//! Help ▸ Check for updates (issue #28), with stand-in release sources (no network).

use std::sync::Arc;

use cleonpdf_ui_egui::CleonPdfApp;
use cleonpdf_ui_egui::updates::{Release, UpdateSource, is_newer};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn source(answer: Result<&str, &str>) -> UpdateSource {
    let answer = answer.map(str::to_string).map_err(str::to_string);
    Arc::new(move || answer.clone().map(|v| Release { url: format!("https://github.com/kristianrama/cleonpdf/releases/tag/{v}"), version: v }))
}

fn harness(answer: Result<&str, &str>) -> Harness<'static, CleonPdfApp> {
    Harness::builder().with_size(egui::vec2(1200.0, 800.0)).build_eframe(move |_cc| {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        app.update_source = Some(source(answer));
        app
    })
}

/// Run frames until the background check has reported (or give up).
fn settle(h: &mut Harness<'static, CleonPdfApp>) {
    for _ in 0..200 {
        h.run_steps(2);
        if h.query_by_label_contains("Checking for a newer version").is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    h.run_steps(2);
}

#[test]
fn versions_compare_by_number() {
    assert!(is_newer("v0.2.0", "0.1.1"));
    assert!(is_newer("v0.1.10", "0.1.9"));
    assert!(is_newer("1", "0.9.9"));
    assert!(!is_newer("v0.1.1", "0.1.1"));
    assert!(!is_newer("v0.1.0", "0.1.1"));
    assert!(!is_newer("v0.1.1-beta.2", "0.1.1"), "suffixes are ignored");
    assert!(!is_newer("nightly", "0.1.1"), "a tag that isn't a version is never newer");
    assert!(!is_newer("v1.2.3.4", "0.1.1"));
    assert!(!is_newer("v99999999999999999999.0.0", "0.1.1"), "out of range");
}

#[test]
fn a_newer_release_is_offered_for_download() {
    let mut h = harness(Ok("v99.0.0"));
    h.state_mut().execute("help.check_updates");
    settle(&mut h);
    h.get_by_label_contains("CleonPDF 99.0.0 is available");
    h.get_by_label("Download");
    h.get_by_label("Later").click();
    h.run_steps(3);
    assert!(h.query_by_label_contains("is available").is_none(), "Later closes the dialog");
}

#[test]
fn an_up_to_date_or_failed_check_says_so() {
    let mut h = harness(Ok(concat!("v", env!("CARGO_PKG_VERSION"))));
    h.state_mut().execute("help.check_updates");
    settle(&mut h);
    h.get_by_label_contains("is up to date");
    assert!(h.query_by_label("Download").is_none());

    let mut h = harness(Err("couldn't reach GitHub"));
    h.state_mut().execute("help.check_updates");
    settle(&mut h);
    h.get_by_label_contains("Couldn't check for updates: couldn't reach GitHub");
}

#[test]
fn nothing_is_asked_until_the_user_checks() {
    // Without the host's say-so (tests, embedders, a script on the control channel) there is no
    // check at start: the source is only called from the command.
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();
    let mut h = Harness::builder().with_size(egui::vec2(1200.0, 800.0)).build_eframe(move |_cc| {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        // Settings from a build that had the startup option are ignored.
        app.restore(r#"{"check_updates_at_start": true}"#);
        let counted = counted.clone();
        app.update_source = Some(Arc::new(move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Release { version: "v99.0.0".into(), url: "https://github.com/kristianrama/cleonpdf/releases/tag/v99.0.0".into() })
        }));
        app
    });
    settle(&mut h);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(h.query_by_label_contains("is available").is_none());
    h.state_mut().execute("help.check_updates");
    settle(&mut h);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    h.get_by_label_contains("CleonPDF 99.0.0 is available");
}

/// A harness whose source answers `version` (or fails when it is `None`) and counts its calls,
/// with the automatic check allowed and settings `json` restored.
fn counted(version: Option<&'static str>, json: &str) -> (Harness<'static, CleonPdfApp>, Arc<std::sync::atomic::AtomicUsize>) {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = calls.clone();
    let json = json.to_string();
    let h = Harness::builder().with_size(egui::vec2(1200.0, 800.0)).build_eframe(move |_cc| {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        app.restore(&json);
        app.automatic_update_checks = true;
        let counter = counter.clone();
        app.update_source = Some(Arc::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            version
                .map(|v| Release { version: v.into(), url: format!("https://github.com/kristianrama/cleonpdf/releases/tag/{v}") })
                .ok_or_else(|| "couldn't reach GitHub".to_string())
        }));
        app
    });
    (h, calls)
}

fn calls(c: &std::sync::atomic::AtomicUsize) -> usize {
    c.load(std::sync::atomic::Ordering::SeqCst)
}

#[test]
fn a_newer_release_is_offered_by_itself_once_a_day() {
    let (mut h, c) = counted(Some("v99.0.0"), "{}");
    settle(&mut h);
    settle(&mut h);
    assert_eq!(calls(&c), 1, "one check at start");
    h.get_by_label_contains("CleonPDF 99.0.0 is available");
    h.get_by_label("Later").click();
    h.run_steps(3);
    settle(&mut h);
    assert_eq!(calls(&c), 1, "not again in the same run");
    // The next start, within the day, doesn't ask again.
    let saved = h.state().persist();
    let (mut h, c) = counted(Some("v99.0.0"), &saved);
    settle(&mut h);
    assert_eq!(calls(&c), 0);
    assert!(h.query_by_label_contains("is available").is_none());
    // A day later it does.
    let mut v: serde_json::Value = serde_json::from_str(&saved).unwrap();
    v["update_last_check"] = serde_json::json!(v["update_last_check"].as_u64().unwrap() - cleonpdf_ui_egui::updates::CHECK_INTERVAL_SECS);
    let (mut h, c) = counted(Some("v99.0.0"), &v.to_string());
    settle(&mut h);
    settle(&mut h);
    assert_eq!(calls(&c), 1);
    h.get_by_label_contains("CleonPDF 99.0.0 is available");
}

#[test]
fn an_automatic_check_without_news_says_nothing() {
    let (mut h, c) = counted(Some(concat!("v", env!("CARGO_PKG_VERSION"))), "{}");
    settle(&mut h);
    settle(&mut h);
    assert_eq!(calls(&c), 1);
    assert!(h.query_by_label_contains("is up to date").is_none(), "no dialog when there is nothing new");

    // A failed one says nothing either, and the next start tries again.
    let (mut h, c) = counted(None, "{}");
    settle(&mut h);
    settle(&mut h);
    assert_eq!(calls(&c), 1);
    assert!(h.query_by_label_contains("Couldn't check").is_none());
    let (mut h, c) = counted(None, &h.state().persist());
    settle(&mut h);
    settle(&mut h);
    assert_eq!(calls(&c), 1, "a failure isn't an answer: the next start asks again");
}

#[test]
fn a_skipped_version_is_not_offered_again_by_itself() {
    let (mut h, _) = counted(Some("v99.0.0"), "{}");
    settle(&mut h);
    settle(&mut h);
    h.get_by_label("Skip this version").click();
    h.run_steps(3);
    assert!(h.query_by_label_contains("is available").is_none(), "Skip closes the dialog");
    let mut v: serde_json::Value = serde_json::from_str(&h.state().persist()).unwrap();
    assert_eq!(v["update_skipped"], "v99.0.0");
    v["update_last_check"] = serde_json::json!(0);
    let (mut h, c) = counted(Some("v99.0.0"), &v.to_string());
    settle(&mut h);
    settle(&mut h);
    assert_eq!(calls(&c), 1);
    assert!(h.query_by_label_contains("is available").is_none(), "the skipped version isn't offered again");
    // Asking still shows it, and a later version is offered by itself.
    h.state_mut().execute("help.check_updates");
    settle(&mut h);
    h.get_by_label_contains("CleonPDF 99.0.0 is available");
    let (mut h, _) = counted(Some("v100.0.0"), &v.to_string());
    settle(&mut h);
    settle(&mut h);
    h.get_by_label_contains("CleonPDF 100.0.0 is available");
}

#[test]
fn the_automatic_check_can_be_turned_off() {
    let (mut h, c) = counted(Some("v99.0.0"), r#"{"check_updates_automatically": false}"#);
    settle(&mut h);
    settle(&mut h);
    assert_eq!(calls(&c), 0);
    assert!(h.query_by_label_contains("is available").is_none());
    assert_eq!(serde_json::from_str::<serde_json::Value>(&h.state().persist()).unwrap()["check_updates_automatically"], false);
}
