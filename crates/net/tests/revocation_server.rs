//! The revocation fetcher against a server on the loopback interface: a real HTTP exchange,
//! with the checks that keep a crafted address from reaching it.
#![cfg(not(target_arch = "wasm32"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use cleonpdf_net::{HttpRevocationFetcher, MAX_EVIDENCE};
use cleonpdf_sign::ltv::RevocationFetcher;

struct Seen {
    request_line: String,
    headers: String,
    body: Vec<u8>,
}

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

/// A server that answers `n` requests, each with `reply(request) -> (status line, extra headers,
/// body)`, and reports what it saw.
fn serve(n: usize, reply: impl Fn(&Seen) -> (&'static str, String, Vec<u8>) + Send + 'static) -> (String, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for _ in 0..n {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let seen = read_request(&mut stream);
            let (status, extra, body) = reply(&seen);
            let head = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = tx.send(seen);
        }
    });
    (base, rx)
}

fn local() -> HttpRevocationFetcher {
    HttpRevocationFetcher::new().allow_private_hosts(true).with_timeout(Duration::from_secs(5))
}

#[test]
fn an_ocsp_request_is_posted_as_ocsp_and_the_answer_comes_back_untouched() {
    let (base, seen) = serve(1, |_| ("200 OK", "Content-Type: application/ocsp-response\r\n".into(), b"the answer".to_vec()));
    let got = local().ocsp(&format!("{base}/ocsp?token=secret"), b"the request").unwrap();
    assert_eq!(got, b"the answer");
    let seen = seen.recv().unwrap();
    assert!(seen.request_line.starts_with("POST /ocsp?token=secret "), "{}", seen.request_line);
    assert!(seen.headers.to_ascii_lowercase().contains("content-type: application/ocsp-request"), "{}", seen.headers);
    assert_eq!(seen.body, b"the request");
}

#[test]
fn a_crl_is_fetched_with_get_and_sends_no_body() {
    let (base, seen) = serve(1, |_| ("200 OK", String::new(), vec![0x30, 0x03, 1, 2, 3]));
    assert_eq!(local().crl(&format!("{base}/ca.crl")).unwrap(), [0x30, 0x03, 1, 2, 3]);
    let seen = seen.recv().unwrap();
    assert!(seen.request_line.starts_with("GET /ca.crl "), "{}", seen.request_line);
    assert!(seen.body.is_empty());
}

#[test]
fn an_issuer_certificate_is_fetched_with_get_and_comes_back_untouched() {
    let (base, seen) = serve(1, |_| ("200 OK", "Content-Type: application/pkix-cert\r\n".into(), vec![0x30, 0x03, 1, 2, 3]));
    assert_eq!(local().issuer(&format!("{base}/ca.crt")).unwrap(), [0x30, 0x03, 1, 2, 3]);
    let seen = seen.recv().unwrap();
    assert!(seen.request_line.starts_with("GET /ca.crt "), "{}", seen.request_line);
    assert!(seen.body.is_empty());
    // A missing file is an error naming the host, not an empty certificate.
    let (base, _seen) = serve(1, |_| ("404 Not Found", String::new(), Vec::new()));
    let err = local().issuer(&format!("{base}/gone.crt")).unwrap_err().to_string();
    assert!(err.contains("http status 404") && !err.contains("gone.crt"), "{err}");
}

#[test]
fn a_redirect_is_followed_for_a_crl_and_only_a_few_times() {
    let (base, seen) = serve(2, |req| {
        if req.request_line.starts_with("GET /old ") {
            ("302 Found", "Location: /new\r\n".into(), Vec::new())
        } else {
            ("200 OK", String::new(), b"moved".to_vec())
        }
    });
    assert_eq!(local().crl(&format!("{base}/old")).unwrap(), b"moved");
    assert_eq!(seen.iter().take(2).count(), 2);
    // A loop is cut off.
    let (base, _seen) = serve(8, |_| ("302 Found", "Location: /again\r\n".into(), Vec::new()));
    let err = local().crl(&format!("{base}/start")).unwrap_err().to_string();
    assert!(err.contains("too many redirects"), "{err}");
}

#[test]
fn a_redirect_to_a_non_web_address_is_refused() {
    let (base, _seen) = serve(1, |_| ("302 Found", "Location: file:///etc/passwd\r\n".into(), Vec::new()));
    let err = local().crl(&format!("{base}/x")).unwrap_err().to_string();
    assert!(err.contains("http:// or https://"), "{err}");
}

#[test]
fn a_post_is_not_replayed_after_a_302() {
    let (base, seen) = serve(2, |_| ("302 Found", "Location: /elsewhere\r\n".into(), Vec::new()));
    let err = local().ocsp(&format!("{base}/ocsp"), b"req").unwrap_err().to_string();
    assert!(err.contains("not followed"), "{err}");
    let _ = seen.recv().unwrap();
    assert!(seen.recv_timeout(Duration::from_millis(300)).is_err(), "no second request was made");
}

#[test]
fn bad_answers_are_errors_that_name_the_host_and_not_the_path() {
    let (base, _s) = serve(1, |_| ("404 Not Found", String::new(), b"nope".to_vec()));
    let err = local().crl(&format!("{base}/secret/path?token=SECRET")).unwrap_err().to_string();
    assert!(err.contains("http status 404") && err.contains("127.0.0.1") && !err.contains("SECRET"), "{err}");
    let (base, _s) = serve(1, |_| ("200 OK", String::new(), Vec::new()));
    assert!(local().crl(&format!("{base}/x")).unwrap_err().to_string().contains("empty"));
    let (base, _s) = serve(1, |_| ("200 OK", String::new(), vec![0u8; MAX_EVIDENCE as usize + 1]));
    assert!(local().crl(&format!("{base}/x")).unwrap_err().to_string().contains("oversized"));
}

#[test]
fn a_closed_port_is_an_error_not_a_hang() {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let started = std::time::Instant::now();
    assert!(local().ocsp(&format!("http://127.0.0.1:{port}/"), b"x").is_err());
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn the_default_fetcher_does_not_reach_the_loopback_server_at_all() {
    let (base, seen) = serve(1, |_| ("200 OK", String::new(), b"should not be sent".to_vec()));
    for result in [
        HttpRevocationFetcher::new().crl(&format!("{base}/ca.crl")),
        HttpRevocationFetcher::new().ocsp(&format!("{base}/ocsp"), b"x"),
        HttpRevocationFetcher::new().issuer(&format!("{base}/ca.crt")),
    ] {
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not a public address"), "{err}");
    }
    assert!(seen.recv_timeout(Duration::from_millis(300)).is_err(), "nothing connected");
}
