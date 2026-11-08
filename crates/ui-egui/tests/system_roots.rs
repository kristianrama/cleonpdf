//! Trusting the operating system's root certificates: off until asked, read from the system only
//! then, remembered across restarts, and never part of the user's own trusted list.
#![cfg(not(target_arch = "wasm32"))]

use cleonpdf_ui_egui::CleonPdfApp;

fn app() -> CleonPdfApp {
    let mut app = CleonPdfApp::new();
    app.set_option("language", "en").unwrap();
    app
}

/// Whether this machine has a store of trusted roots to read (a bare container may not).
fn system_has_roots() -> bool {
    cleonpdf_net::system_certificates().is_ok()
}

#[test]
fn the_systems_roots_count_only_after_the_user_turns_them_on() {
    let mut a = app();
    assert!(!a.trust_system_roots && a.session.system_certificates().is_empty(), "off by default, and nothing is read");
    assert!(a.set_option("trust-system-roots", "sometimes").is_err());
    if system_has_roots() {
        a.set_option("trust-system-roots", "on").unwrap();
        assert!(a.trust_system_roots && !a.session.system_certificates().is_empty());
        assert!(a.session.trusted_certificates().is_empty(), "they are not added to the user's own list");
    } else {
        assert!(a.set_option("trust-system-roots", "on").is_err());
        assert!(!a.trust_system_roots && a.session.system_certificates().is_empty(), "a failed read changes nothing");
    }
    a.set_option("trust-system-roots", "off").unwrap();
    assert!(!a.trust_system_roots && a.session.system_certificates().is_empty());
}

#[test]
fn the_choice_survives_a_restart_and_a_default_install_reads_nothing() {
    let mut a = app();
    let untouched = a.persist();
    assert!(untouched.contains("\"trust_system_roots\":false"), "{untouched}");
    let mut fresh = app();
    fresh.restore(&untouched);
    assert!(!fresh.trust_system_roots && fresh.session.system_certificates().is_empty());
    if system_has_roots() {
        a.set_option("trust-system-roots", "on").unwrap();
        let mut b = app();
        b.restore(&a.persist());
        assert!(b.trust_system_roots && !b.session.system_certificates().is_empty());
    }
    // A settings file that holds something else than a boolean leaves it off.
    let mut c = app();
    c.restore(&serde_json::json!({ "trust_system_roots": "yes" }).to_string());
    assert!(!c.trust_system_roots && c.session.system_certificates().is_empty());
}
