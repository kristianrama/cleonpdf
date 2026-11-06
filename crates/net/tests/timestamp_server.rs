//! The timestamp client against a server on the loopback interface: no internet, a real HTTP
//! exchange, and a real RFC 3161 token.
#![cfg(not(target_arch = "wasm32"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use cleonpdf_net::{HttpTimestampAuthority, MAX_RESPONSE};
use cleonpdf_sign::{DigestAlg, SignError, Time, TimestampAuthority, pkcs12, timestamp};

/// What the server saw of one request.
struct Seen {
    request_line: String,
    headers: String,
    body: Vec<u8>,
}

/// Read one HTTP request (headers, then `Content-Length` bytes of body).
fn read_request(stream: &mut TcpStream) -> Seen {
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "the client closed before finishing its request");
        data.extend_from_slice(&chunk[..n]);
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
    let length =
        head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
    while data.len() < head_end + length {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "the client closed in the middle of its body");
        data.extend_from_slice(&chunk[..n]);
    }
    let mut lines = head.lines();
    Seen {
        request_line: lines.next().unwrap_or_default().to_string(),
        headers: lines.collect::<Vec<_>>().join("\n"),
        body: data[head_end..head_end + length].to_vec(),
    }
}

fn respond(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let head =
        format!("HTTP/1.1 {status}\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    // The client may give up early on an oversized answer: a broken pipe is fine.
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

/// A server that answers exactly one request with `reply(request) -> (status, body)`, and tells
/// the test what it saw.
fn serve_once(reply: impl FnOnce(&Seen) -> (&'static str, Vec<u8>) + Send + 'static) -> (String, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/tsa?token=secret", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let seen = read_request(&mut stream);
        let (status, body) = reply(&seen);
        respond(&mut stream, status, &body);
        let _ = tx.send(seen);
    });
    (url, rx)
}

fn tsa_identity() -> pkcs12::DigitalId {
    let path = format!("{}/../sign/tests/data/rsa-aes.p12", env!("CARGO_MANIFEST_DIR"));
    pkcs12::open(&std::fs::read(path).unwrap(), "test").unwrap()
}

/// A query for a digest of the given bytes, as the signer would send it.
fn query_bytes() -> Vec<u8> {
    let mut q = timestamp::TimestampQuery::new(DigestAlg::Sha256, vec![7u8; 32]).unwrap();
    q.nonce = Some(99);
    q.encode().unwrap()
}

#[test]
fn the_query_is_posted_and_the_token_comes_back_untouched() {
    let (url, seen) = serve_once(|req| {
        let q = timestamp::parse_request(&req.body).expect("the server got a well-formed RFC 3161 query");
        let id = tsa_identity();
        let time = Time { year: 2026, month: 11, day: 6, hour: 9, minute: 0, second: 0 };
        let token = timestamp::respond(&id.key, &id.certificate, &id.chain, DigestAlg::Sha256, &q, "1.2.3.4", time, 5).unwrap();
        ("200 OK", token)
    });
    let got = HttpTimestampAuthority::new(&url).unwrap().timestamp(&query_bytes()).unwrap();
    let seen = seen.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(seen.request_line.starts_with("POST /tsa?token=secret "), "{}", seen.request_line);
    let headers = seen.headers.to_ascii_lowercase();
    assert!(headers.contains("content-type: application/timestamp-query"), "{headers}");
    assert!(headers.contains("accept: application/timestamp-reply"), "{headers}");
    assert_eq!(seen.body, query_bytes());
    // What came back is a complete RFC 3161 response to *our* query, with the TSA's certificate.
    let mut sent = timestamp::TimestampQuery::new(DigestAlg::Sha256, vec![7u8; 32]).unwrap();
    sent.nonce = Some(99);
    let token = timestamp::parse_response(&got, &sent).expect("the answer is a valid response to the query that was sent");
    assert!(token.signer_certificate().is_some());
}

#[test]
fn a_server_error_is_reported_with_its_status_and_without_the_path() {
    let (url, _seen) = serve_once(|_| ("503 Service Unavailable", b"busy".to_vec()));
    let err = HttpTimestampAuthority::new(&url).unwrap().timestamp(&query_bytes()).unwrap_err();
    let SignError::Transport(message) = &err else { panic!("{err:?}") };
    assert!(message.contains("503"), "{message}");
    assert!(message.contains("127.0.0.1"), "{message}");
    assert!(!message.contains("secret") && !message.contains("/tsa"), "the path and query stay out of messages: {message}");
}

#[test]
fn an_empty_answer_is_refused() {
    let (url, _seen) = serve_once(|_| ("200 OK", Vec::new()));
    let err = HttpTimestampAuthority::new(&url).unwrap().timestamp(&query_bytes()).unwrap_err();
    assert!(matches!(&err, SignError::Transport(m) if m.contains("empty")), "{err:?}");
}

#[test]
fn an_oversized_answer_is_cut_off_and_refused() {
    let big = vec![0x30u8; MAX_RESPONSE as usize + 4096];
    let (url, _seen) = serve_once(move |_| ("200 OK", big));
    let err = HttpTimestampAuthority::new(&url).unwrap().timestamp(&query_bytes()).unwrap_err();
    assert!(matches!(&err, SignError::Transport(m) if m.contains("oversized")), "{err:?}");
}

#[test]
fn a_server_that_never_answers_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    // Accept and hold the connection open without a word.
    let _hold = std::thread::spawn(move || {
        let held = listener.accept();
        std::thread::sleep(Duration::from_secs(8));
        drop(held);
    });
    let started = Instant::now();
    let tsa = HttpTimestampAuthority::new(&url).unwrap().with_timeout(Duration::from_millis(700));
    let err = tsa.timestamp(&query_bytes()).unwrap_err();
    assert!(matches!(err, SignError::Transport(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(6), "gave up after {:?}", started.elapsed());
}

#[test]
fn a_closed_port_is_an_error_not_a_hang() {
    // Bind, note the port, and close: nothing listens there any more.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let tsa = HttpTimestampAuthority::new(&format!("http://127.0.0.1:{port}/")).unwrap();
    let err = tsa.timestamp(&query_bytes()).unwrap_err();
    assert!(matches!(&err, SignError::Transport(m) if m.contains("couldn't be reached")), "{err:?}");
}
