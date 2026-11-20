//! Help ▸ Check for updates (issue #28), with stand-in release sources (no network).

use std::sync::Arc;

use cleonpdf_ui_egui::CleonPdfApp;
use cleonpdf_ui_egui::updates::{Release, StagedUpdate, UpdateInstaller, UpdateSource, is_newer};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// A stand-in installer: reports 40 of 100 MB, waits for `go` (or Cancel), then answers `ok`
/// (staged, recording what `schedule` was asked) or fails.
struct Stand {
    go: Arc<AtomicBool>,
    scheduled: Arc<Mutex<Vec<bool>>>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

fn stand_in(ok: bool, relaunches: bool) -> (UpdateInstaller, Stand) {
    let stand = Stand { go: Arc::default(), scheduled: Arc::default(), calls: Arc::default() };
    let (go, scheduled, calls) = (stand.go.clone(), stand.scheduled.clone(), stand.calls.clone());
    let installer: UpdateInstaller = Arc::new(move |release: &Release, progress| {
        calls.fetch_add(1, Ordering::SeqCst);
        progress.total.store(100 << 20, Ordering::Relaxed);
        progress.received.store(40 << 20, Ordering::Relaxed);
        while !go.load(Ordering::SeqCst) {
            if progress.cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        if !ok {
            return Err("the release isn't signed with CleonPDF's release key".into());
        }
        let scheduled = scheduled.clone();
        Ok(StagedUpdate {
            version: release.version.clone(),
            relaunches,
            schedule: Box::new(move |relaunch| scheduled.lock().unwrap().push(relaunch)),
        })
    });
    (installer, stand)
}

fn installing(ok: bool, relaunches: bool) -> (Harness<'static, CleonPdfApp>, Stand) {
    let (installer, stand) = stand_in(ok, relaunches);
    let mut h = Harness::builder().with_size(egui::vec2(1200.0, 800.0)).build_eframe(move |_cc| {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        app.update_source = Some(source(Ok("v99.0.0")));
        app.update_installer = Some(installer.clone());
        app
    });
    h.state_mut().execute("help.check_updates");
    settle(&mut h);
    (h, stand)
}

/// Run frames until `label` shows (or give up).
fn until(h: &mut Harness<'static, CleonPdfApp>, label: &str) {
    for _ in 0..500 {
        h.run_steps(1);
        if h.query_by_label_contains(label).is_some() {
            // A widget can be clicked from the frame after it first shows.
            h.run_steps(1);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let labels: Vec<String> = h.query_all_by_label_contains("").map(|n| format!("{n:?}").chars().take(120).collect::<String>()).collect();
    panic!("{label:?} never showed; showing: {labels:?}");
}

fn closes(h: &Harness<'static, CleonPdfApp>) -> bool {
    h.output().viewport_output.values().any(|v| v.commands.iter().any(|c| matches!(c, egui::ViewportCommand::Close)))
}

#[test]
fn update_downloads_in_the_dialog_then_restarts_into_the_new_version() {
    let (mut h, stand) = installing(true, true);
    h.get_by_label_contains("CleonPDF 99.0.0 is available");
    h.get_by_label_contains("signed with CleonPDF's release key");
    assert!(h.query_by_label("Download").is_none(), "an installable update is installed, not downloaded by hand");
    h.get_by_label("Update").click();
    until(&mut h, "Downloading CleonPDF 99.0.0");
    until(&mut h, "40 MB of 100 MB");
    stand.go.store(true, Ordering::SeqCst);
    until(&mut h, "CleonPDF 99.0.0 is ready. It is installed when you quit CleonPDF.");
    assert_eq!(*stand.scheduled.lock().unwrap(), [false], "once ready, it goes in whenever CleonPDF quits");
    assert!(!closes(&h));
    h.get_by_label("Restart now").click();
    h.step();
    assert_eq!(*stand.scheduled.lock().unwrap(), [false, true], "Restart now also starts the new version");
    assert!(closes(&h), "and quits");
}

#[test]
fn later_installs_at_quit_and_the_msi_says_its_installer_runs() {
    let (mut h, stand) = installing(true, false);
    h.get_by_label("Update").click();
    stand.go.store(true, Ordering::SeqCst);
    until(&mut h, "Its installer runs when you quit CleonPDF.");
    h.get_by_label("Install now");
    h.get_by_label("Later").click();
    h.run_steps(3);
    assert!(h.query_by_label_contains("is ready").is_none(), "Later closes the dialog");
    assert_eq!(*stand.scheduled.lock().unwrap(), [false]);
    assert!(!closes(&h));
}

#[test]
fn a_download_can_be_hidden_or_cancelled() {
    let (mut h, stand) = installing(true, true);
    h.get_by_label("Update").click();
    until(&mut h, "40 MB of 100 MB");
    // Later hides it; it comes back when the download is done.
    h.get_by_label("Later").click();
    h.run_steps(3);
    assert!(h.query_by_label_contains("Downloading").is_none());
    stand.go.store(true, Ordering::SeqCst);
    until(&mut h, "is ready");

    let (mut h, stand) = installing(true, true);
    h.get_by_label("Update").click();
    until(&mut h, "40 MB of 100 MB");
    h.get_by_label("Cancel").click();
    until(&mut h, "CleonPDF 99.0.0 is available");
    assert!(stand.scheduled.lock().unwrap().is_empty(), "nothing goes in");
    assert!(h.query_by_label_contains("Couldn't update").is_none(), "a cancel isn't a failure");
    // Update again starts a new download.
    h.get_by_label("Update").click();
    until(&mut h, "40 MB of 100 MB");
    for _ in 0..500 {
        if stand.calls.load(Ordering::SeqCst) == 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert_eq!(stand.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn a_failed_update_offers_the_release_page() {
    let (mut h, stand) = installing(false, true);
    h.get_by_label("Update").click();
    stand.go.store(true, Ordering::SeqCst);
    until(&mut h, "Couldn't update: the release isn't signed with CleonPDF's release key");
    h.get_by_label_contains("download it from its release page");
    h.get_by_label("Download");
    h.get_by_label("Close").click();
    h.run_steps(3);
    assert!(stand.scheduled.lock().unwrap().is_empty());
    // The next check offers Update again.
    h.state_mut().execute("help.check_updates");
    settle(&mut h);
    h.get_by_label("Update");
}
