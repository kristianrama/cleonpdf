//! The Trusted List fetcher against a server on the loopback interface.
#![cfg(not(target_arch = "wasm32"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use cleonpdf_net::HttpListFetcher;
use cleonpdf_sign::trusted_lists::ListFetcher;

fn request_line(stream: &mut TcpStream) -> String {
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    while !data.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&data).lines().next().unwrap_or_default().to_string()
}

/// A server answering `n` requests with `reply(request line) -> (status, extra headers, body)`.
fn serve(n: usize, reply: impl Fn(&str) -> (&'static str, String, Vec<u8>) + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for _ in 0..n {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let line = request_line(&mut stream);
            let (status, extra, body) = reply(&line);
            let head = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    base
}

fn local() -> HttpListFetcher {
    HttpListFetcher::new().allow_private_hosts(true).with_timeout(Duration::from_secs(5))
}

#[test]
fn a_list_is_fetched_as_text_within_the_limit() {
    let base = serve(4, |line| {
        if line.starts_with("GET /moved ") {
            ("301 Moved Permanently", "Location: /list.xml\r\n".into(), Vec::new())
        } else {
            ("200 OK", String::new(), "<a>é</a>".as_bytes().to_vec())
        }
    });
    assert_eq!(local().fetch(&format!("{base}/list.xml"), 1024).unwrap(), "<a>é</a>");
    assert_eq!(local().fetch(&format!("{base}/moved"), 1024).unwrap(), "<a>é</a>");
    // Over the limit the caller set, not the 2 MiB of revocation evidence.
    let err = local().fetch(&format!("{base}/list.xml"), 4).unwrap_err().to_string();
    assert!(err.contains("oversized"), "{err}");
}

#[test]
fn a_list_larger_than_revocation_evidence_is_allowed() {
    let big = vec![b'a'; 3 * 1024 * 1024];
    let base = serve(1, move |_| ("200 OK", String::new(), big.clone()));
    assert_eq!(local().fetch(&format!("{base}/big.xml"), 8 * 1024 * 1024).unwrap().len(), 3 * 1024 * 1024);
}

#[test]
fn bad_answers_are_errors_that_name_the_host() {
    let base = serve(2, |line| {
        if line.contains("/bin") { ("200 OK", String::new(), vec![0xff, 0xfe, 0xfd]) } else { ("404 Not Found", String::new(), b"no".to_vec()) }
    });
    let err = local().fetch(&format!("{base}/missing?token=SECRET"), 1024).unwrap_err().to_string();
    assert!(err.contains("http status 404") && err.contains("127.0.0.1") && !err.contains("SECRET"), "{err}");
    let err = local().fetch(&format!("{base}/bin"), 1024).unwrap_err().to_string();
    assert!(err.contains("not UTF-8"), "{err}");
}

#[test]
fn the_default_fetcher_does_not_reach_the_loopback_server_at_all() {
    let base = serve(1, |_| ("200 OK", String::new(), b"should not be sent".to_vec()));
    let err = HttpListFetcher::new().fetch(&format!("{base}/l.xml"), 1024).unwrap_err().to_string();
    assert!(err.contains("not a public address"), "{err}");
}
