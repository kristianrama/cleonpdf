//! Add validation information (OCSP and CRL answers, PAdES B-LT) in the real shell: the button in
//! the Signatures panel, the request off the UI thread, private hosts refused unless allowed, and
//! an edit made meanwhile never lost. The CA and its responder are made in-process and served on
//! the loopback interface; nothing touches the internet.

mod support;

#[path = "../../sign/tests/support/pki.rs"]
mod pki;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use cleonpdf_sign::Time;
use cleonpdf_ui_egui::CleonPdfApp;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const FIXTURE: &[u8] = b"%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length 45 >> stream
BT /F1 14 Tf 20 150 Td (Please sign below) Tj ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
trailer << /Root 1 0 R >>
%%EOF";

fn dir() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("cleonpdf-validation-ui-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// A responder on the loopback interface answering every request with `answer`, after `hold` is
/// released (if given). Counts the requests it gets.
fn responder(listener: TcpListener, answer: Vec<u8>, hold: Option<mpsc::Receiver<()>>) -> Arc<AtomicUsize> {
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
            if let Some(hold) = &hold {
                let _ = hold.recv();
            }
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", answer.len());
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&answer);
        }
    });
    hits
}

/// A signed document whose signer's certificate names a responder on the loopback interface,
/// and that responder. Returns the signed bytes and the request counter.
fn signed_with_responder(hold: Option<mpsc::Receiver<()>>) -> (Vec<u8>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let ca = pki::root("Test CA");
    let leaf = pki::end_entity("Ada Lovelace", &ca, &[pki::aia_ocsp(&format!("{base}/ocsp"))]);
    let (this, next) = (Time::from_unix(now() - 3600), Time::from_unix(now() + 7 * 86400));
    let answer = pki::ocsp_response(&ca, &leaf.cert, &ca.cert, pki::Answer::Good, this, next);
    let hits = responder(listener, answer, hold);
    let id = leaf.into_id(&[&ca]);
    let doc = cleonpdf_cos::Document::open(Arc::new(FIXTURE.to_vec())).unwrap();
    let opts = cleonpdf_sign::SignOptions { date: Time::from_unix(now()).to_pdf(), ..Default::default() };
    (cleonpdf_sign::sign(&doc, &id, &opts).unwrap(), hits)
}

fn harness(dir: &std::path::Path, bytes: Vec<u8>, private_hosts: bool) -> Harness<'static, CleonPdfApp> {
    let out = dir.join("validated.pdf").to_string_lossy().into_owned();
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |_cc| {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        app.open_bytes("signed.pdf", None, bytes.clone()).expect("opens");
        app.set_option("left", "closed").unwrap();
        app.set_option("panel", "signatures").unwrap();
        app.set_option("validation-private-hosts", if private_hosts { "on" } else { "off" }).unwrap();
        app.save_override = Some(out.clone());
        app
    });
    h.run_steps(4);
    h
}

fn toast(h: &Harness<'static, CleonPdfApp>) -> String {
    h.state().toast.as_ref().map(|(m, _)| m.clone()).unwrap_or_default()
}

#[test]
fn the_button_fetches_the_answers_and_saves_a_file_with_a_dss() {
    let dir = dir();
    let (signed, hits) = signed_with_responder(None);
    let mut h = harness(&dir, signed.clone(), true);
    h.get_by_label("Add validation information").click();
    support::wait_until(&mut h, "the saved file", |app| !app.validation_in_progress() && dir.join("validated.pdf").exists());
    h.run_steps(2);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let saved = std::fs::read(dir.join("validated.pdf")).unwrap();
    assert!(saved.starts_with(&signed), "an incremental update: the signed bytes are untouched");
    assert!(saved.windows(4).any(|w| w == b"/DSS") && saved.windows(4).any(|w| w == b"/VRI"));
    assert!(toast(&h).contains("Validation information added and saved to"), "{:?}", toast(&h));
    // The document now is the saved file, and its signature is not broken by the new store.
    let s = h.state();
    let doc = s.session.get(s.views[0].id).unwrap();
    assert!(doc.signatures.iter().any(|x| x.signed && x.status != cleonpdf_engine::SignatureStatus::Invalid));
    assert!(!doc.dirty);
}

#[test]
fn a_private_address_in_a_certificate_is_not_contacted_unless_allowed() {
    let dir = dir();
    let (signed, hits) = signed_with_responder(None);
    let mut h = harness(&dir, signed, false);
    h.state_mut().execute("sign.add_validation_info");
    support::wait_until(&mut h, "the refusal", |app| !app.validation_in_progress() && app.toast.is_some());
    assert!(toast(&h).contains("not a public address"), "{:?}", toast(&h));
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no connection was made");
    assert!(!dir.join("validated.pdf").exists());
    // The choice survives a restart (and defaults to off).
    assert!(h.state().persist().contains("\"validation_private_hosts\":false"));
}

#[test]
fn an_edit_made_while_the_servers_answer_is_not_lost() {
    let dir = dir();
    let (release, hold) = mpsc::channel();
    let (signed, hits) = signed_with_responder(Some(hold));
    let mut h = harness(&dir, signed, true);
    h.state_mut().execute("sign.add_validation_info");
    h.run_steps(4);
    assert!(h.state().validation_in_progress(), "the request is in flight");
    // The button is greyed out meanwhile, and the interface is not stuck: the user edits.
    assert!(h.state_mut().apply_edit(cleonpdf_engine::Edit::SetInfo { key: "Title".into(), value: "Edited meanwhile".into() }));
    release.send(()).unwrap();
    support::wait_until(&mut h, "the refusal", |app| !app.validation_in_progress());
    h.run_steps(2);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(!dir.join("validated.pdf").exists(), "nothing was saved");
    assert!(toast(&h).contains("changed while the validation information"), "{:?}", toast(&h));
    let s = h.state();
    assert!(s.session.get(s.views[0].id).unwrap().dirty, "the edit is still in the document");
}

#[test]
fn nothing_is_asked_of_a_document_without_signatures_or_with_unsaved_changes() {
    let dir = dir();
    let mut h = harness(&dir, FIXTURE.to_vec(), true);
    h.state_mut().execute("sign.add_validation_info");
    h.run_steps(2);
    assert!(!h.state().validation_in_progress());
    assert!(toast(&h).contains("no signature"), "{:?}", toast(&h));
    // There is no button either: nothing is signed.
    assert!(h.query_by_label("Add validation information").is_none());

    let (signed, hits) = signed_with_responder(None);
    let mut h = harness(&dir, signed, true);
    assert!(h.state_mut().apply_edit(cleonpdf_engine::Edit::SetInfo { key: "Title".into(), value: "Unsaved".into() }));
    h.state_mut().execute("sign.add_validation_info");
    h.run_steps(2);
    assert!(!h.state().validation_in_progress());
    assert!(toast(&h).contains("save the document first"), "{:?}", toast(&h));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}
