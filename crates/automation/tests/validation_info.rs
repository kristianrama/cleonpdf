//! `sign_add_validation_info` end to end: a document signed by a certificate whose OCSP responder
//! is a server on the loopback interface. The CA, its responses and its CRLs are made in-process
//! (`sign/tests/support/pki.rs`), so the test needs no network and no OpenSSL.
#![cfg(not(target_arch = "wasm32"))]

#[path = "../../sign/tests/support/pki.rs"]
mod pki;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cleonpdf_automation::{Automation, Content, ToolError};
use cleonpdf_sign::{Time, pkcs12};
use pki::{Answer, Party, aia_ocsp, crl, crl_point, end_entity, ocsp_response, root};
use serde_json::{Value, json};

/// The session clock of these tests; the evidence is current at that moment.
const NOW: i64 = 1_700_000_000;

fn fixture() -> Vec<u8> {
    let objs: [&str; 4] = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 200 300] >>",
        "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << >> >>",
        "<< /Length 0 >>\nstream\n\nendstream",
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

fn workdir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cleonpdf-validation-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.pdf"), fixture()).unwrap();
    dir
}

fn auto(dir: &Path) -> Automation {
    Automation::new().with_root(dir).unwrap().with_clock(|| NOW)
}

fn ok(a: &mut Automation, tool: &str, args: Value) -> Value {
    match a.call(tool, &args) {
        Ok(mut c) => match c.remove(0) {
            Content::Json(v) => v,
            other => panic!("{tool}: expected JSON, got {other:?}"),
        },
        Err(e) => panic!("{tool} {args}: {e}"),
    }
}

/// Serves `POST /ocsp` and `GET /ca.crl` on `listener` with fixed answers (404 for `None`),
/// counting the requests it gets.
fn serve(listener: TcpListener, ocsp: Option<Vec<u8>>, crl: Option<Vec<u8>>) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let mut data = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&chunk[..n]);
                if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&data[..i]).to_ascii_lowercase();
                    let length =
                        head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                    if data.len() >= i + 4 + length {
                        break;
                    }
                }
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let answer = if data.starts_with(b"POST /ocsp") { &ocsp } else { &crl };
            let (status, body) = match answer {
                Some(b) => ("200 OK", b.as_slice()),
                None => ("404 Not Found", b"".as_slice()),
            };
            let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    hits
}

/// A listener on the loopback interface and its base address.
fn bind() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    (listener, base)
}

/// A CA and a leaf whose certificate names `base` as its OCSP responder and CRL address, with
/// the leaf saved as `<file>` (password `secret1`). Returns the CA, the leaf's certificate and
/// the window the CA's answers are valid in (around the session clock).
fn issue(dir: &Path, file: &str, name: &str, base: &str) -> (Party, cleonpdf_sign::Certificate, Time, Time) {
    let ca = root("Test CA");
    let leaf = end_entity(name, &ca, &[aia_ocsp(&format!("{base}/ocsp")), crl_point(&format!("{base}/ca.crl"))]);
    let cert = leaf.cert.clone();
    std::fs::write(dir.join(file), pkcs12::write(&leaf.into_id(&[&ca]), "secret1").unwrap()).unwrap();
    (ca, cert, Time::from_unix(NOW - 3600), Time::from_unix(NOW + 7 * 86400))
}

fn sign(a: &mut Automation, dir: &Path, id: &str) -> u64 {
    let _ = dir;
    let doc = ok(a, "doc_open", json!({ "path": "a.pdf" }))["doc"].as_u64().unwrap();
    ok(a, "sign_document", json!({ "doc": doc, "id": id, "password": "secret1", "page": 1, "rect": [20, 200, 180, 250], "out": "signed.pdf" }));
    doc
}

#[test]
fn a_signed_document_gets_its_ocsp_response_and_chain_embedded() {
    let dir = workdir("ok");
    let (listener, base) = bind();
    let (ca, leaf, this, next) = issue(&dir, "ada.p12", "Ada Lovelace", &base);
    let hits = serve(listener, Some(ocsp_response(&ca, &leaf, &ca.cert, Answer::Good, this, next)), Some(crl(&ca, &[], this, next)));

    let mut a = auto(&dir);
    let doc = sign(&mut a, &dir, "ada.p12");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "signing alone asks no revocation server");

    // Private hosts are refused unless the caller opts in; nothing is requested or saved.
    let r = a.call("sign_add_validation_info", &json!({ "doc": doc, "out": "refused.pdf" }));
    assert!(matches!(&r, Err(ToolError::Failed(m)) if m.contains("not a public address")), "{r:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "a loopback address is never connected to by default");
    assert!(!dir.join("refused.pdf").exists());

    let done = ok(&mut a, "sign_add_validation_info", json!({ "doc": doc, "out": "ltv.pdf", "allow_private_hosts": true }));
    assert_eq!(done["embedded"], json!({ "certificates": 2, "ocsp_responses": 1, "crls": 0 }), "{done}");
    assert_eq!(done["certificates"].as_array().unwrap().len(), 1, "the root needs no evidence: {done}");
    assert_eq!(done["certificates"][0]["evidence"], json!("ocsp"), "{done}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // An incremental update: the signed bytes are untouched, and the DSS is there.
    let before = std::fs::read(dir.join("signed.pdf")).unwrap();
    let after = std::fs::read(dir.join("ltv.pdf")).unwrap();
    assert!(after.starts_with(&before));
    assert!(after.windows(4).any(|w| w == b"/DSS") && after.windows(4).any(|w| w == b"/VRI"), "no DSS in the update");
    // The document now shows the new file, and the signature is not broken by it.
    let listed = ok(&mut a, "sign_list", json!({ "doc": doc }));
    assert_ne!(listed["signatures"][0]["status"], json!("invalid"), "{listed}");
}

#[test]
fn a_crl_is_embedded_when_the_responder_has_nothing() {
    let dir = workdir("crl");
    let (listener, base) = bind();
    let (ca, _leaf, this, next) = issue(&dir, "ada.p12", "Ada Lovelace", &base);
    let hits = serve(listener, None, Some(crl(&ca, &[], this, next)));
    let mut a = auto(&dir);
    let doc = sign(&mut a, &dir, "ada.p12");
    let done = ok(&mut a, "sign_add_validation_info", json!({ "doc": doc, "out": "ltv.pdf", "allow_private_hosts": true }));
    assert_eq!(done["embedded"], json!({ "certificates": 2, "ocsp_responses": 0, "crls": 1 }), "{done}");
    assert_eq!(done["certificates"][0]["evidence"], json!("crl"), "{done}");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "the responder first, then the CRL");
}

#[test]
fn a_revoked_certificate_and_an_empty_handed_run_save_nothing() {
    let dir = workdir("revoked");
    let (listener, base) = bind();
    let (ca, leaf, this, next) = issue(&dir, "ada.p12", "Ada Lovelace", &base);
    let revoked = ocsp_response(&ca, &leaf, &ca.cert, Answer::Revoked(Time::from_unix(NOW - 86400)), this, next);
    serve(listener, Some(revoked), None);
    let mut a = auto(&dir);
    let doc = sign(&mut a, &dir, "ada.p12");
    let r = a.call("sign_add_validation_info", &json!({ "doc": doc, "out": "ltv.pdf", "allow_private_hosts": true }));
    assert!(matches!(&r, Err(ToolError::Failed(m)) if m.contains("was revoked") && m.contains("nothing was added")), "{r:?}");
    assert!(!dir.join("ltv.pdf").exists());

    // A server with nothing: no evidence at all is an error that says why, not an empty store.
    let dir = workdir("nothing");
    let (listener, base) = bind();
    issue(&dir, "ada.p12", "Ada Lovelace", &base);
    serve(listener, None, None);
    let mut a = auto(&dir);
    let doc = sign(&mut a, &dir, "ada.p12");
    let r = a.call("sign_add_validation_info", &json!({ "doc": doc, "out": "ltv.pdf", "allow_private_hosts": true }));
    assert!(matches!(&r, Err(ToolError::Failed(m)) if m.contains("no revocation information could be fetched") && m.contains("404")), "{r:?}");
    assert!(!dir.join("ltv.pdf").exists());
}

#[test]
fn a_document_with_no_signature_has_nothing_to_add_to() {
    let dir = workdir("unsigned");
    let mut a = auto(&dir);
    let doc = ok(&mut a, "doc_open", json!({ "path": "a.pdf" }))["doc"].as_u64().unwrap();
    let r = a.call("sign_add_validation_info", &json!({ "doc": doc, "out": "ltv.pdf" }));
    assert!(matches!(&r, Err(ToolError::Failed(m)) if m.contains("no signature")), "{r:?}");
}
