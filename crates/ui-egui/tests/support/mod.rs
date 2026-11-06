//! State-based waits for native preparation, which completes between UI frames.
use cleonpdf_ui_egui::CleonPdfApp;
use egui_kittest::Harness;

pub fn wait_until(h: &mut Harness<'static, CleonPdfApp>, what: &str, ready: impl Fn(&CleonPdfApp) -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        h.step();
        if ready(h.state()) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}: views={}, active={:?}, password={:?}, toast={:?}",
            h.state().views.len(),
            h.state().active,
            h.state().password_prompt.as_ref().map(|p| (&p.name, &p.error)),
            h.state().toast
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// A timestamp server on the loopback interface for one request. It answers with a token signed
/// by `tsa` (an RFC 3161 response at a fixed time), after `hold` (if given) is released: a test
/// can change the document while the server "thinks". Returns the server's address.
#[allow(dead_code)]
pub fn loopback_tsa(tsa: cleonpdf_engine::sign::DigitalId, hold: Option<std::sync::mpsc::Receiver<()>>) -> String {
    use cleonpdf_engine::sign::{DigestAlg, Time, timestamp};
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let url = format!("http://{}/", listener.local_addr().expect("its address"));
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let mut data = Vec::new();
        let mut chunk = [0u8; 4096];
        let (head_end, length) = loop {
            let Ok(n) = stream.read(&mut chunk) else { return };
            if n == 0 {
                return;
            }
            data.extend_from_slice(&chunk[..n]);
            if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&data[..i]).to_ascii_lowercase();
                let length = head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                break (i + 4, length);
            }
        };
        while data.len() < head_end + length {
            let Ok(n) = stream.read(&mut chunk) else { return };
            if n == 0 {
                return;
            }
            data.extend_from_slice(&chunk[..n]);
        }
        let Ok(query) = timestamp::parse_request(&data[head_end..head_end + length]) else { return };
        if let Some(hold) = hold {
            let _ = hold.recv_timeout(std::time::Duration::from_secs(30));
        }
        let time = Time { year: 2026, month: 11, day: 6, hour: 9, minute: 0, second: 0 };
        let Ok(token) = timestamp::respond(&tsa.key, &tsa.certificate, &tsa.chain, DigestAlg::Sha256, &query, "1.2.3.4", time, 1) else { return };
        let _ = stream.write_all(
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", token.len())
                .as_bytes(),
        );
        let _ = stream.write_all(&token);
    });
    url
}
