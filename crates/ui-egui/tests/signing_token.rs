//! Sign with a key on a smart card or token in the real shell: the card's certificates are
//! listed off the UI thread, the PIN is asked where the password was, the key stays on the token.
//! Needs SoftHSM like `crates/sign/tests/pkcs11.rs` (see `softhsm.rs`); without it the tests say
//! so and pass.
#![cfg(not(target_arch = "wasm32"))]

mod support;

#[path = "../../sign/tests/support/pki.rs"]
mod pki;
#[path = "../../sign/tests/support/softhsm.rs"]
mod softhsm;

use std::sync::Mutex;

use cleonpdf_engine::SignatureStatus;
use cleonpdf_ui_egui::{CleonPdfApp, SignStep};
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

/// The tests share one token and one library; run them one at a time.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn harness(dir: &std::path::Path, module: &std::path::Path) -> Harness<'static, CleonPdfApp> {
    let (dir, module) = (dir.to_path_buf(), module.to_string_lossy().into_owned());
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |_cc| {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        app.open_bytes("contract.pdf", None, FIXTURE.to_vec()).expect("opens");
        app.set_option("left", "closed").unwrap();
        app.export_dir_override = Some(dir.to_string_lossy().into_owned());
        app.save_override = Some(dir.join("contract_signed.pdf").to_string_lossy().into_owned());
        // The module a user would add with "Add smart card module…".
        app.set_option("pkcs11-module", &module).unwrap();
        app
    });
    h.run_steps(6);
    h
}

fn wait_for_cards(h: &mut Harness<'static, CleonPdfApp>) {
    support::wait_until(h, "the smart card scan to finish", |app| !app.token_scan_in_progress());
    h.run_steps(2);
}

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("cleonpdf-token-ui-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_document_is_signed_with_the_key_on_a_smart_card() {
    let _one = serial();
    let Some(f) = softhsm::fixture() else { return };
    let dir = dir("sign");
    let mut h = harness(&dir, &f.module);
    h.state_mut().start_signing(0, None, None, None);
    wait_for_cards(&mut h);

    // The cards' end-entity certificates are in the list; the CA is not.
    let names: Vec<String> = h.state().digital_ids.iter().filter(|e| e.path.starts_with("pkcs11:")).map(|e| e.name.clone()).collect();
    for expected in ["Token EC Signer", "Token RSA Signer"] {
        assert!(names.iter().any(|n| n == expected), "{names:?}");
    }
    assert!(!names.iter().any(|n| n.contains("CA")), "{names:?}");
    // A key type CleonPDF can't sign with is listed greyed, with the reason.
    let p521 = h.state().digital_ids.iter().find(|e| e.name == "Token P-521 Signer").expect("listed");
    assert!(p521.unusable.as_deref().is_some_and(|r| r.contains("can't sign")), "{:?}", p521.unusable);
    // (An earlier run's token with the same names may be on the token directory too.)
    let listed: Vec<_> = h.state().digital_ids.iter().filter(|e| e.name == "Token EC Signer").map(|e| e.path.clone()).collect();
    assert!(!listed.is_empty());
    assert!(!h.get_all_by_label("Token EC Signer").collect::<Vec<_>>().is_empty());

    // Choose the EC one and ask for a PIN, not a password.
    let ec = h.state().digital_ids.iter().position(|e| e.name == "Token EC Signer").unwrap();
    h.state_mut().sign_draft.as_mut().unwrap().selected = Some(ec);
    h.get_by_label("Continue").click();
    h.run_steps(3);
    h.get_by_label("Sign as \"Token EC Signer\"");
    h.get_by_label("PIN");
    h.get_by_label("The key stays on the smart card or token.");
    assert!(h.query_by_label("Digital ID password").is_none());

    // A wrong PIN is refused in the dialog and does not print the PIN.
    h.state_mut().sign_draft.as_mut().unwrap().password = "not-the-pin-4321".into();
    h.run_steps(2);
    h.get_by_label("Sign").click();
    h.run_steps(4);
    let error = h.state().sign_draft.as_ref().and_then(|d| d.error.clone()).expect("an error");
    assert!(error.contains("PIN is not correct") && !error.contains("not-the-pin-4321"), "{error}");
    assert!(!dir.join("contract_signed.pdf").exists());

    // The right one signs; the signature is the card's.
    h.state_mut().sign_draft.as_mut().unwrap().password = softhsm::USER_PIN.into();
    h.run_steps(2);
    h.get_by_label("Sign").click();
    h.run_steps(8);
    let s = h.state();
    assert_eq!(s.sign_draft.as_ref().and_then(|d| d.error.clone()), None);
    assert!(dir.join("contract_signed.pdf").exists());
    let doc = s.session.get(s.views[0].id).unwrap();
    let sig = doc.signatures.iter().find(|x| x.signed).expect("signed");
    assert_eq!(sig.signer.as_deref(), Some("Token EC Signer"));
    // The test CA isn't trusted here: unknown, and not tampered with.
    assert_eq!(sig.status, SignatureStatus::Unknown);
}

#[test]
fn smart_cards_are_listed_again_each_time_and_never_saved() {
    let _one = serial();
    let Some(f) = softhsm::fixture() else { return };
    let mut h = harness(&dir("saved"), &f.module);
    h.state_mut().start_signing(0, None, None, None);
    wait_for_cards(&mut h);
    assert!(h.state().digital_ids.iter().any(|e| e.path.starts_with("pkcs11:")));
    assert_eq!(h.state().sign_draft.as_ref().map(|d| d.step), Some(SignStep::Choose));
    // Not in the saved settings: the card is read when it is there, not remembered.
    let saved = h.state().persist();
    assert!(!saved.contains("\"path\":\"pkcs11:"), "a card identity was saved");
    // …but the module the user added is, and a settings file can't smuggle in more than a few.
    assert!(saved.contains("pkcs11_modules"));
    let mut fresh = CleonPdfApp::new();
    let many: Vec<String> = (0..50).map(|i| format!("/x/lib{i}.so")).collect();
    fresh.restore(&serde_json::json!({ "pkcs11_modules": many }).to_string());
    assert_eq!(fresh.pkcs11_modules.len(), 8);
    // Not a file: refused with the file's name, not remembered.
    let err = fresh.set_option("pkcs11-module", "/nonexistent/dir/libfoo.so").unwrap_err();
    assert!(err.contains("libfoo.so") && !err.contains("/nonexistent"), "{err}");
}
