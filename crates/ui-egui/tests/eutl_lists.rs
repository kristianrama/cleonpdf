//! The European Union Trusted Lists preference: off until asked, never on the network unless
//! Update now is pressed, kept on disk and verified again whenever they are read.
#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cleonpdf_engine::Session;
use cleonpdf_engine::sign::SignError;
use cleonpdf_engine::sign::trusted_lists::{LOTL_URL, ListFetcher, Outcome};
use cleonpdf_ui_egui::CleonPdfApp;

const IT: &str = "https://example.invalid/tl-it.xml";
const DE: &str = "https://example.invalid/tl-de.xml";

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../sign/tests/data/xml/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// A server holding the files named, and a record of what was asked of it.
#[derive(Default)]
struct Server {
    files: HashMap<String, String>,
    asked: Mutex<Vec<String>>,
}
impl Server {
    fn up() -> Arc<Server> {
        let files = [(LOTL_URL, "lotl.xml"), (IT, "tl-it.xml"), (DE, "tl-de.xml")]
            .iter()
            .map(|(u, f)| ((*u).to_string(), String::from_utf8(data(f)).unwrap()))
            .collect();
        Arc::new(Server { files, asked: Mutex::default() })
    }
    fn down() -> Arc<Server> {
        Arc::new(Server::default())
    }
    fn asked(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}
impl ListFetcher for Server {
    fn fetch(&self, url: &str, _max: u64) -> Result<String, SignError> {
        self.asked.lock().unwrap().push(url.to_string());
        self.files.get(url).cloned().ok_or_else(|| SignError::Transport(format!("{url}: could not be reached")))
    }
}

/// A folder of its own for the kept lists.
fn folder(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cleonpdf-eutl-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// 2026-11-18, when the fixtures' lists are in force.
fn app(dir: &Path, server: &Arc<Server>) -> CleonPdfApp {
    let mut app = CleonPdfApp::new();
    app.set_option("language", "en").unwrap();
    app.session = Session::new().with_clock(|| 1_795_000_000);
    app.eutl.cache_dir = Some(dir.to_path_buf());
    let server: Arc<Server> = server.clone();
    app.eutl.source = Some(server);
    app
}

fn signer_file(tag: &str, name: &str) -> String {
    let path = std::env::temp_dir().join(format!("cleonpdf-eutl-{tag}-{}-{name}", std::process::id()));
    std::fs::write(&path, data(name)).unwrap();
    path.to_string_lossy().into_owned()
}

fn finish(app: &mut CleonPdfApp) {
    for _ in 0..2000 {
        app.poll_eutl();
        if !app.eutl.updating() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("the update did not finish");
}

/// An app that has the Commission's certificate, the preference on and the lists fetched.
fn updated(dir: &Path, server: &Arc<Server>, tag: &str) -> CleonPdfApp {
    let mut a = app(dir, server);
    a.set_option("eutl-signer", &signer_file(tag, "tsl-signer-eu.der")).unwrap();
    a.set_option("eutl-lists", "on").unwrap();
    a.set_option("eutl-lists-update", "").unwrap();
    finish(&mut a);
    a
}

#[test]
fn nothing_counts_or_is_fetched_until_the_person_asks() {
    let (dir, server) = (folder("off"), Server::up());
    let mut a = app(&dir, &server);
    assert!(!a.eutl.on && a.eutl.signers.is_empty() && a.session.eutl_anchors().is_empty());
    // Without a certificate to verify the list of lists with, the lists cannot be turned on.
    assert!(a.set_option("eutl-lists", "on").is_err() && !a.eutl.on);
    assert!(a.set_option("eutl-lists", "maybe").is_err());
    assert!(a.set_option("eutl-lists-update", "").is_err(), "off: nothing to update");
    // With one, turning on reads the disk only; nothing has been downloaded yet.
    a.set_option("eutl-signer", &signer_file("off", "tsl-signer-eu.der")).unwrap();
    a.set_option("eutl-lists", "on").unwrap();
    assert!(a.eutl.on && a.eutl.summary.is_none() && a.session.eutl_anchors().is_empty());
    assert!(a.eutl.problem.as_deref().is_some_and(|p| p.contains("downloaded")), "{:?}", a.eutl.problem);
    assert_eq!(server.asked(), 0);
    assert!(!dir.exists(), "nothing was written either");
}

#[test]
fn update_now_fetches_verifies_keeps_and_uses_the_lists() {
    let (dir, server) = (folder("update"), Server::up());
    let a = updated(&dir, &server, "update");
    assert_eq!(server.asked.lock().unwrap().as_slice(), [LOTL_URL, IT, DE]);
    let s = a.eutl.summary.as_ref().expect("lists in force");
    assert!(s.fetched && s.authorities > 0 && s.countries.len() == 2, "{s:?}");
    assert!(s.countries.iter().all(|c| c.outcome == Outcome::Updated));
    assert_eq!(a.session.eutl_anchors().len(), s.authorities);
    assert!(a.eutl.problem.is_none());
    for f in ["lotl.xml", "list-0.xml", "list-1.xml", "locations.txt"] {
        assert!(dir.join(f).is_file(), "{f}");
    }
}

#[test]
fn a_restart_reads_the_kept_lists_and_never_the_network() {
    let (dir, server) = (folder("restart"), Server::up());
    let a = updated(&dir, &server, "restart");
    let saved = a.persist();
    let before = server.asked();
    let quiet = Server::down();
    let mut b = app(&dir, &quiet);
    b.restore(&saved);
    assert!(b.eutl.on && b.eutl.signers.len() == 1);
    assert_eq!(b.session.eutl_anchors().len(), a.session.eutl_anchors().len());
    assert!(b.eutl.summary.as_ref().is_some_and(|s| !s.fetched), "read from disk, not fetched");
    assert_eq!((quiet.asked(), server.asked()), (0, before));
    // A default install remembers nothing.
    let mut fresh = app(&dir, &quiet);
    fresh.restore(&CleonPdfApp::new().persist());
    assert!(!fresh.eutl.on && fresh.session.eutl_anchors().is_empty());
    // A settings file that holds something else than a boolean leaves it off, even with the
    // certificates there, and something else than a list of certificates leaves none.
    let mut odd = app(&dir, &quiet);
    let mut settings: serde_json::Value = serde_json::from_str(&saved).unwrap();
    settings["eutl_lists"] = serde_json::json!("yes");
    odd.restore(&settings.to_string());
    assert!(!odd.eutl.on && odd.eutl.signers.len() == 1 && odd.session.eutl_anchors().is_empty());
    let mut worse = app(&dir, &quiet);
    worse.restore(&serde_json::json!({ "eutl_lists": true, "eutl_signers": 3 }).to_string());
    assert!(!worse.eutl.on && worse.eutl.signers.is_empty());
}

#[test]
fn a_kept_list_that_was_changed_on_disk_is_not_believed() {
    let (dir, server) = (folder("tamper"), Server::up());
    let a = updated(&dir, &server, "tamper");
    let saved = a.persist();
    let it = dir.join("list-0.xml");
    let other = dir.join("list-1.xml");
    // Whichever file is Italy's, granting a withdrawn service must not survive a reload.
    for f in [&it, &other] {
        let text = std::fs::read_to_string(f).unwrap();
        std::fs::write(f, text.replace("Svcstatus/withdrawn", "Svcstatus/granted")).unwrap();
    }
    let mut b = app(&dir, &Server::down());
    b.restore(&saved);
    let s = b.eutl.summary.as_ref();
    assert!(s.is_none_or(|s| s.countries.iter().any(|c| matches!(c.outcome, Outcome::Unusable(_)))), "a changed list must be refused: {s:?}");
    assert!(b.session.eutl_anchors().len() < a.session.eutl_anchors().len());
    // The list of lists itself changed: nothing is used and the reason is shown.
    let lotl = dir.join("lotl.xml");
    let text = std::fs::read_to_string(&lotl).unwrap();
    std::fs::write(&lotl, text.replacen("<", "<!-- x --><", 2)).unwrap();
    let mut c = app(&dir, &Server::down());
    c.restore(&saved);
    assert!(c.session.eutl_anchors().is_empty() && c.eutl.summary.is_none() && c.eutl.problem.is_some());
}

#[test]
fn when_the_lists_cannot_be_reached_the_kept_ones_stay_in_use_and_say_so() {
    let (dir, server) = (folder("offline"), Server::up());
    let mut a = updated(&dir, &server, "offline");
    let anchors = a.session.eutl_anchors().len();
    let down = Server::down();
    let source: Arc<Server> = down.clone();
    a.eutl.source = Some(source);
    a.set_option("eutl-lists-update", "").unwrap();
    finish(&mut a);
    assert_eq!(down.asked(), 1, "only the list of lists was asked for");
    let s = a.eutl.summary.as_ref().unwrap();
    assert!(!s.fetched && s.countries.iter().all(|c| matches!(c.outcome, Outcome::KeptPrevious(_))), "{s:?}");
    assert_eq!(a.session.eutl_anchors().len(), anchors);
    // With nothing kept, a failed update leaves nothing in force and says why.
    let mut b = app(&folder("offline-empty"), &Server::down());
    b.set_option("eutl-signer", &signer_file("offline", "tsl-signer-eu.der")).unwrap();
    b.set_option("eutl-lists", "on").unwrap();
    b.set_option("eutl-lists-update", "").unwrap();
    finish(&mut b);
    assert!(b.session.eutl_anchors().is_empty() && b.eutl.summary.is_none());
    assert!(b.eutl.problem.as_deref().is_some_and(|p| p.contains("could not be fetched")), "{:?}", b.eutl.problem);
}

#[test]
fn a_list_of_lists_signed_by_someone_else_is_refused() {
    let (dir, server) = (folder("other"), Server::up());
    let mut a = app(&dir, &server);
    a.set_option("eutl-signer", &signer_file("other", "other.der")).unwrap();
    a.set_option("eutl-lists", "on").unwrap();
    a.set_option("eutl-lists-update", "").unwrap();
    finish(&mut a);
    assert!(a.session.eutl_anchors().is_empty() && a.eutl.summary.is_none() && a.eutl.problem.is_some());
    assert!(!dir.join("lotl.xml").exists(), "a refused list is not kept");
}

#[test]
fn an_answer_that_arrives_after_the_preference_changed_is_dropped() {
    let (dir, server) = (folder("late"), Server::up());
    let mut a = app(&dir, &server);
    a.set_option("eutl-signer", &signer_file("late", "tsl-signer-eu.der")).unwrap();
    a.set_option("eutl-lists", "on").unwrap();
    a.set_option("eutl-lists-update", "").unwrap();
    assert!(a.eutl.updating());
    a.set_option("eutl-lists", "off").unwrap();
    finish(&mut a);
    assert!(!a.eutl.on && a.session.eutl_anchors().is_empty() && a.eutl.summary.is_none());
    // The same when the certificate it was verified against is taken away.
    let mut b = app(&folder("late2"), &server);
    b.set_option("eutl-signer", &signer_file("late", "tsl-signer-eu.der")).unwrap();
    b.set_option("eutl-lists", "on").unwrap();
    b.set_option("eutl-lists-update", "").unwrap();
    b.remove_eutl_signer(0);
    finish(&mut b);
    assert!(!b.eutl.on && b.session.eutl_anchors().is_empty() && b.eutl.summary.is_none());
}

#[test]
fn removing_the_last_certificate_turns_the_lists_off() {
    let (dir, server) = (folder("remove"), Server::up());
    let mut a = updated(&dir, &server, "remove");
    assert!(!a.session.eutl_anchors().is_empty());
    a.remove_eutl_signer(7);
    assert!(a.eutl.on, "an index past the end changes nothing");
    a.remove_eutl_signer(0);
    assert!(!a.eutl.on && a.eutl.signers.is_empty() && a.session.eutl_anchors().is_empty() && a.eutl.summary.is_none());
    // The same certificate twice is kept once, and a file with none is refused.
    let file = signer_file("remove", "tsl-signer-eu.der");
    a.set_option("eutl-signer", &file).unwrap();
    a.set_option("eutl-signer", &file).unwrap();
    assert_eq!(a.eutl.signers.len(), 1);
    assert!(a.add_eutl_signers(b"not a certificate").is_err());
    assert_eq!(a.eutl.signers.len(), 1);
}
