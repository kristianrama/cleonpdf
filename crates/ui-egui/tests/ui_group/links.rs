//! Links: the Help menu and the About dialog open CleonPDF's GitHub page. There is no
//! community button in the top bar and no community card on the home screen.

use cleonpdf_engine::links;
use cleonpdf_ui_egui::{CleonPdfApp, Dialog};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn harness(setup: impl FnOnce(&mut CleonPdfApp) + 'static) -> Harness<'static, CleonPdfApp> {
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |_cc| {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        setup(&mut app);
        app
    });
    h.run_steps(4);
    h
}

#[test]
fn no_third_party_community_links() {
    let h = harness(|_| {});
    assert_eq!(h.query_all_by_label("Discord").count(), 0);
    assert_eq!(h.query_all_by_label("ArtCraft").count(), 0);
    assert_eq!(links::LINKS.len(), 1);
    assert_eq!(links::GITHUB, "https://github.com/kristianrama/cleonpdf");
}

#[test]
fn about_dialog_shows_the_app_icon_and_links() {
    let pdf = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF";
    let mut h = harness(move |app| {
        app.open_bytes("one.pdf", None, pdf.to_vec()).unwrap();
        app.dialog = Some(Dialog::About);
    });
    assert!(h.query_all_by_label("CleonPDF").count() >= 1, "the app icon (alt text) and the name");
    h.get_by_label("CleonPDF on GitHub").click();
    h.run_steps(2);
    assert_eq!(h.state().last_opened_url.as_deref(), Some(links::GITHUB));
}

#[test]
fn help_commands_open_each_link() {
    for l in links::LINKS {
        let mut h = harness(|_| {});
        assert!(h.state_mut().execute(l.command), "{}", l.command);
        assert_eq!(h.state().last_opened_url.as_deref(), Some(l.url));
        assert_eq!(cleonpdf_engine::commands::command(l.command).unwrap().menu, Some("Help"));
    }
}

/// Runs frames until the node labelled `label` exists and has stopped moving, then returns it.
///
/// The About dialog is a modal centred on its own size, so for a few frames after it opens it
/// recentres and every control in it moves. A fixed number of frames is a guess at how long that
/// takes (#671).
fn settled<'a>(h: &'a mut Harness<'static, CleonPdfApp>, label: &'a str) -> egui_kittest::Node<'a> {
    let mut last = None;
    for _ in 0..60 {
        h.run_steps(1);
        let now = h.query_by_label(label).map(|n| n.rect());
        if now.is_some() && now == last {
            return h.get_by_label(label);
        }
        last = now;
    }
    panic!("{label:?} never appeared or never stopped moving");
}

#[test]
fn about_dialog_names_its_author_and_credits_pdfcraft() {
    let mut h = harness(|app| app.dialog = Some(Dialog::About));
    settled(&mut h, "By Kristian Rama");
    // The inherited copyright notice (LICENSE-MIT) is shown, not only kept in the files.
    settled(&mut h, "Based on PdfCraft 0.8.0 by the ArtCraft Team and the PdfCraft contributors (MIT OR Apache-2.0).");
    // No Contributors or Models tabs any more.
    assert!(h.query_by_label("Contributors").is_none());
    assert!(h.query_by_label("Models").is_none());
}
