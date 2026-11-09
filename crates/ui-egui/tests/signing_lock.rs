//! Choosing form fields to lock in the Sign dialog (FieldMDP): the choice reaches the signature,
//! a list with nothing ticked is refused, and a form without fields offers nothing to lock.

use cleonpdf_engine::sign::FieldLock;
use cleonpdf_ui_egui::CleonPdfApp;
use egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};

const FORM: &[u8] = b"%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R 6 0 R] /DA (/Helv 0 Tf 0 g) >> >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Annots [5 0 R 6 0 R] >> endobj
5 0 obj << /Type /Annot /Subtype /Widget /FT /Tx /T (name) /V (Alice) /Rect [20 150 200 170] /P 3 0 R /F 4 >> endobj
6 0 obj << /Type /Annot /Subtype /Widget /FT /Tx /T (amount) /V (100) /Rect [20 110 200 130] /P 3 0 R /F 4 >> endobj
trailer << /Root 1 0 R >>
%%EOF";

const PLAIN: &[u8] = b"%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >> endobj
trailer << /Root 1 0 R >>
%%EOF";

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("cleonpdf-signing-lock-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Open the lock choice (a combo box showing what is chosen now) and pick `what`.
fn choose(h: &mut Harness<'static, CleonPdfApp>, now: &str, what: &str) {
    let combo = h.get_all_by_role(Role::ComboBox).into_iter().find(|n| n.accesskit_node().value().as_deref() == Some(now)).expect("the lock choice");
    combo.click();
    h.run_steps(3);
    h.get_by_label(what).click();
    h.run_steps(3);
}

/// The Sign dialog open at its last step with a digital ID from a file chosen.
fn at_sign_step(pdf: &'static [u8], dir: &std::path::Path) -> Harness<'static, CleonPdfApp> {
    let save = dir.join("signed.pdf").to_string_lossy().into_owned();
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |_cc| {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        app.open_bytes("form.pdf", None, pdf.to_vec()).expect("opens");
        app.set_option("left", "closed").unwrap();
        app.save_override = Some(save);
        app
    });
    h.run_steps(6);
    h.state_mut().start_signing(0, None, None, None);
    h.run_steps(2);
    {
        let d = h.state_mut().sign_draft.as_mut().unwrap();
        d.new_id.create = false;
        d.new_id.file = concat!(env!("CARGO_MANIFEST_DIR"), "/../sign/tests/data/ec-p256.p12").into();
        d.new_id.file_password = "test".into();
    }
    h.run_steps(1);
    h.get_by_label("Continue").click();
    h.run_steps(4);
    h.get_by_label("Continue").click();
    h.run_steps(4);
    h.state_mut().sign_draft.as_mut().unwrap().password = "test".into();
    h.run_steps(2);
    h
}

#[test]
fn the_fields_chosen_in_the_dialog_are_locked_by_the_signature() {
    let dir = dir("choose");
    let mut h = at_sign_step(FORM, &dir);
    // The default locks nothing.
    h.get_by_label("Lock form fields");
    choose(&mut h, "Don't lock", "Only the fields chosen");
    h.get_by_label("name").click();
    h.run_steps(3);
    h.get_by_label("Sign").click();
    h.run_steps(8);
    let s = h.state();
    assert_eq!(s.sign_draft.as_ref().and_then(|d| d.error.clone()), None);
    let doc = s.session.get(s.views[0].id).unwrap();
    let sig = doc.signatures.iter().find(|x| x.signed).unwrap();
    assert_eq!(sig.field_locks, vec![FieldLock::Include(vec!["name".to_string()])]);
}

#[test]
fn a_list_with_nothing_ticked_is_refused_and_nothing_is_signed() {
    let dir = dir("empty");
    let mut h = at_sign_step(FORM, &dir);
    choose(&mut h, "Don't lock", "All fields except the ones chosen");
    h.get_by_label("Sign").click();
    h.run_steps(6);
    let s = h.state();
    assert_eq!(s.sign_draft.as_ref().and_then(|d| d.error.clone()).as_deref(), Some("Choose the fields to lock."));
    assert!(s.session.get(s.views[0].id).unwrap().signatures.iter().all(|x| !x.signed));
    assert!(!dir.join("signed.pdf").exists());
}

#[test]
fn a_form_without_fields_offers_nothing_to_lock() {
    let dir = dir("plain");
    let h = at_sign_step(PLAIN, &dir);
    assert!(h.query_by_label("Lock form fields").is_none());
    assert!(h.query_all_by_role(Role::ComboBox).all(|n| n.accesskit_node().value().as_deref() != Some("Don't lock")));
    // The same dialog on a form does offer it.
    let form = at_sign_step(FORM, &dir);
    form.get_by_label("Lock form fields");
}
