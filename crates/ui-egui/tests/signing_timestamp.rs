//! Sign with a timestamp server in the real shell: the request leaves the UI thread, a bad address
//! keeps the dialog open, an edit made while the server is asked is never lost, and the server is
//! remembered. The server is on the loopback interface; nothing touches the internet.

mod support;

use std::sync::mpsc;

use cleonpdf_engine::sign::pkcs12;
use cleonpdf_ui_egui::{CleonPdfApp, Dialog, DigitalIdEntry, SignStep};
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

/// The `signatureTimeStampToken` attribute's object identifier (1.2.840.113549.1.9.16.2.14), DER.
const TIMESTAMP_TOKEN_OID: [u8; 13] = [0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E];

fn dir() -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("cleonpdf-signing-ts-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn p12(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../sign/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// The shell with a signer's ID known and the Sign as dialog open on it, pointing at `url`.
fn harness(dir: &std::path::Path, url: &str) -> Harness<'static, CleonPdfApp> {
    let id_path = dir.join("signer.p12");
    std::fs::write(&id_path, p12("ec-p256.p12")).unwrap();
    let out = dir.join("signed.pdf");
    let id_path = id_path.to_string_lossy().into_owned();
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |_cc| {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        app.open_bytes("contract.pdf", None, FIXTURE.to_vec()).expect("opens");
        app.set_option("left", "closed").unwrap();
        app.save_override = Some(out.to_string_lossy().into_owned());
        app.digital_ids.push(DigitalIdEntry {
            path: id_path.clone(),
            name: "Signer".into(),
            issuer: "Signer".into(),
            email: String::new(),
            expires: String::new(),
            unusable: None,
        });
        app
    });
    h.run_steps(4);
    h.state_mut().start_signing(0, Some([40.0, 40.0, 200.0, 90.0]), None, None);
    h.run_steps(2);
    let d = h.state_mut().sign_draft.as_mut().unwrap();
    d.selected = Some(0);
    d.step = SignStep::SignAs;
    d.password = "test".into();
    d.timestamp_url = url.into();
    h.run_steps(2);
    h
}

/// The signature value sits in the file as hex, so look for the attribute's identifier in hex.
fn has_token(bytes: &[u8]) -> bool {
    let wanted: String = TIMESTAMP_TOKEN_OID.iter().map(|b| format!("{b:02X}")).collect();
    String::from_utf8_lossy(bytes).to_ascii_uppercase().contains(&wanted)
}

#[test]
fn signing_with_a_timestamp_server_saves_a_b_t_signature_and_remembers_the_server() {
    let dir = dir();
    let url = support::loopback_tsa(pkcs12::open(&p12("rsa-aes.p12"), "test").unwrap(), None);
    let mut h = harness(&dir, &url);
    h.get_by_label("Sign").click();
    support::wait_until(&mut h, "the signed file", |app| {
        app.signing_task_idle() && std::path::Path::new(&app.save_override.clone().unwrap_or_default()).exists()
    });
    let bytes = std::fs::read(dir.join("signed.pdf")).unwrap();
    assert!(has_token(&bytes), "the signature carries the server's timestamp token");
    assert_eq!(h.state().dialog, None);
    assert_eq!(h.state().timestamp_server, url, "the server is remembered");
    // ... and survives a restart.
    let saved = h.state().persist();
    let mut again = CleonPdfApp::new();
    again.restore(&saved);
    assert_eq!(again.timestamp_server, url);
}

#[test]
fn without_a_server_nothing_is_requested_and_the_signature_has_no_token() {
    let dir = dir();
    let mut h = harness(&dir, "");
    h.get_by_label("Sign").click();
    support::wait_until(&mut h, "the signed file", |app| std::path::Path::new(&app.save_override.clone().unwrap_or_default()).exists());
    assert!(!has_token(&std::fs::read(dir.join("signed.pdf")).unwrap()));
    assert_eq!(h.state().timestamp_server, "");
}

#[test]
fn a_bad_server_address_keeps_the_dialog_open_and_says_why() {
    let dir = dir();
    for bad in ["ftp://tsa.example.com", "tsa.example.com", "http://user:pw@tsa.example.com/"] {
        let mut h = harness(&dir, bad);
        h.get_by_label("Sign").click();
        h.run_steps(4);
        assert_eq!(h.state().dialog, Some(Dialog::Sign), "{bad}: the dialog stays open");
        assert!(
            h.state().sign_draft.as_ref().and_then(|d| d.error.clone()).is_some_and(|e| e.contains("timestamp server")),
            "{bad}: {:?}",
            h.state().sign_draft.as_ref().map(|d| d.error.clone())
        );
        assert!(!dir.join("signed.pdf").exists());
    }
}

#[test]
fn an_edit_made_while_the_server_is_asked_is_not_lost() {
    let dir = dir();
    let (release, hold) = mpsc::channel();
    let url = support::loopback_tsa(pkcs12::open(&p12("rsa-aes.p12"), "test").unwrap(), Some(hold));
    let mut h = harness(&dir, &url);
    h.get_by_label("Sign").click();
    // The server is thinking; the interface is not stuck, and the user edits the document.
    h.run_steps(4);
    assert!(h.state().signing_in_progress(), "the request is in flight");
    assert!(h.state_mut().apply_edit(cleonpdf_engine::Edit::SetInfo { key: "Title".into(), value: "Edited meanwhile".into() }));
    release.send(()).unwrap();
    support::wait_until(&mut h, "the refusal", |app| !app.signing_in_progress());
    h.run_steps(2);
    assert!(!dir.join("signed.pdf").exists(), "nothing was saved");
    let toast = h.state().toast.as_ref().map(|(m, _)| m.clone()).unwrap_or_default();
    assert!(toast.contains("changed while the timestamp"), "{toast:?}");
    // The edit is still in the document.
    let s = h.state();
    assert!(s.session.get(s.views[0].id).unwrap().dirty);
}
