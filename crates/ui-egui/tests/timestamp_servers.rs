//! The timestamp servers saved in Preferences: validated, bounded, remembered, picked in the
//! Sign dialog. None is asked unless a signature uses it.
#![cfg(not(target_arch = "wasm32"))]

use cleonpdf_ui_egui::CleonPdfApp;

fn app() -> CleonPdfApp {
    let mut app = CleonPdfApp::new();
    app.set_option("language", "en").unwrap();
    app
}

#[test]
fn only_a_usable_address_is_saved_once_and_the_list_is_bounded() {
    let mut a = app();
    assert!(a.timestamp_servers.is_empty(), "no server is chosen for the user");
    a.set_option("timestamp-server", "  https://tsa.example.org/tsr ").unwrap();
    a.set_option("timestamp-server", "https://tsa.example.org/tsr").unwrap();
    assert_eq!(a.timestamp_servers, ["https://tsa.example.org/tsr"]);
    for bad in ["", "ftp://tsa.example.org", "https://user:pw@tsa.example.org", "https://tsa example.org", "tsa.example.org"] {
        assert!(a.set_option("timestamp-server", bad).is_err(), "{bad:?} was accepted");
    }
    for i in 0..30 {
        let _ = a.set_option("timestamp-server", &format!("https://tsa{i}.example.org"));
    }
    assert_eq!(a.timestamp_servers.len(), 16);
    assert!(a.set_option("timestamp-server", "https://one-more.example.org").is_err());
    a.set_option("timestamp-server-remove", "https://tsa.example.org/tsr").unwrap();
    assert!(!a.timestamp_servers.iter().any(|u| u.contains("tsr")));
}

#[test]
fn the_saved_list_survives_a_restart_and_a_hand_edited_settings_file_cannot_overfill_it() {
    let mut a = app();
    a.set_option("timestamp-server", "https://tsa.example.org/tsr").unwrap();
    let saved = a.persist();
    let mut b = app();
    b.restore(&saved);
    assert_eq!(b.timestamp_servers, ["https://tsa.example.org/tsr"]);

    let mut hostile = vec!["javascript:alert(1)".to_string(), "file:///etc/passwd".into(), "https://u:p@x.example".into()];
    hostile.extend((0..100).map(|i| format!("https://tsa{i}.example.org")));
    hostile.push("https://tsa0.example.org".into());
    let mut c = app();
    c.restore(&serde_json::json!({ "timestamp_servers": hostile, "timestamp_server": 7 }).to_string());
    assert_eq!(c.timestamp_servers.len(), 16);
    assert!(c.timestamp_servers.iter().all(|u| u.starts_with("https://tsa")));
    assert_eq!(c.timestamp_servers.iter().filter(|u| *u == "https://tsa0.example.org").count(), 1);
}
