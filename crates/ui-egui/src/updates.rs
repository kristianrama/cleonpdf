//! Help ▸ Check for updates (issue #28): ask for the latest release and offer it.
//!
//! The desktop app supplies how to ask ([`CleonPdfApp::update_source`]) and, where this copy
//! can update itself, how to install ([`CleonPdfApp::update_installer`]), so this crate has no
//! network code; without a source (the web build, tests) the command opens the releases page.
//! Without an installer the dialog offers the release page; with one, Update downloads the new
//! version in the background (checked against the release key by the installer), and it goes in
//! when CleonPDF quits: right away with Restart now, or whenever the user quits.
//! It asks when the user does, and by itself at most once a day when CleonPDF starts
//! ([`CleonPdfApp::check_updates_automatically`], on unless turned off in Preferences, and only
//! where the host allows it). An automatic check that finds nothing new, or fails, says nothing;
//! one that finds a version the user hasn't skipped opens the Updates dialog.

use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicU64};

use egui::{Align, Layout};

use crate::{CleonPdfApp, theme, widgets};

/// Where every CleonPDF release is listed.
pub const RELEASES_PAGE: &str = "https://github.com/kristianrama/cleonpdf/releases";

/// The latest published release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// Its version tag, such as `v0.2.0`.
    pub version: String,
    /// Its page on [`RELEASES_PAGE`], where the downloads are.
    pub url: String,
}

/// Asks for the latest release (blocking; it runs on its own thread).
pub type UpdateSource = Arc<dyn Fn() -> Result<Release, String> + Send + Sync>;

/// A download's progress, shared between the installer's thread and the dialog.
#[derive(Debug, Default)]
pub struct UpdateProgress {
    /// Bytes received so far.
    pub received: AtomicU64,
    /// The download's size, once known (0 until then).
    pub total: AtomicU64,
    /// Set by Cancel: the installer stops at its next chunk.
    pub cancel: AtomicBool,
}

/// A downloaded and verified update, ready to go in when CleonPDF closes.
pub struct StagedUpdate {
    /// Its version tag, such as `v0.2.7`.
    pub version: String,
    /// Whether it starts again after going in (the Windows installer doesn't).
    pub relaunches: bool,
    /// Arrange for it to go in once CleonPDF has closed; `true` also starts the new version.
    pub schedule: Box<dyn Fn(bool) + Send + Sync>,
}

/// Downloads, verifies and stages a release (blocking; it runs on its own thread).
pub type UpdateInstaller = Arc<dyn Fn(&Release, &UpdateProgress) -> Result<StagedUpdate, String> + Send + Sync>;

/// Where an Update is.
#[derive(Default)]
pub(crate) enum Install {
    #[default]
    Idle,
    #[cfg(not(target_arch = "wasm32"))]
    Running {
        rx: std::sync::mpsc::Receiver<Result<StagedUpdate, String>>,
        progress: Arc<UpdateProgress>,
        version: String,
    },
    Ready(StagedUpdate),
    /// It failed: why, and the release page to download it from instead.
    Failed(String, String),
}

/// Whether release `latest` (a tag such as `v0.2.0`) is newer than version `current` (`0.1.1`).
/// Pre-release and build suffixes are ignored; a version that doesn't parse is never newer.
pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse(latest), parse(current)), (Some(l), Some(c)) if l > c)
}

fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let core = v.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let mut next = |required: bool| match parts.next() {
        Some(p) => p.parse::<u64>().ok(),
        None if required => None,
        None => Some(0),
    };
    let version = (next(true)?, next(false)?, next(false)?);
    parts.next().is_none().then_some(version)
}

/// Where a check is.
#[derive(Default)]
pub(crate) enum Check {
    #[default]
    Idle,
    #[cfg(not(target_arch = "wasm32"))]
    Running(std::sync::mpsc::Receiver<Result<Release, String>>),
    Done(Result<Release, String>),
}

/// How long an automatic check waits after the last one that got an answer: a day.
pub const CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;

#[derive(Default)]
pub(crate) struct Updates {
    pub(crate) check: Check,
    /// The Updates dialog is showing.
    pub(crate) open: bool,
    /// The running check started by itself: it opens the dialog only for news.
    automatic: bool,
    /// This run has already considered an automatic check.
    considered: bool,
    /// When an automatic or manual check last got an answer (Unix seconds; 0: never).
    pub(crate) last_check: u64,
    /// The release the user chose to skip (its tag): automatic checks don't offer it again.
    pub(crate) skipped: Option<String>,
    /// Downloading and installing the new version.
    pub(crate) install: Install,
}

impl CleonPdfApp {
    /// Help ▸ Check for updates: ask for the latest release and show the outcome.
    pub fn check_for_updates(&mut self) {
        self.start_check(false);
    }

    /// Ask for the latest release by itself when a check is due: the preference is on, the host
    /// allows it, this run hasn't considered one yet and the last answer is a day old (or from a
    /// clock that has since gone back). Called each frame; `now` is Unix seconds.
    pub fn automatic_update_check(&mut self, now: u64) {
        if self.updates.considered || !self.check_updates_automatically || !self.automatic_update_checks || self.update_source.is_none() {
            return;
        }
        self.updates.considered = true;
        let last = self.updates.last_check;
        if now >= last && now - last < CHECK_INTERVAL_SECS {
            return;
        }
        self.start_check(true);
    }

    /// An update check is under way (started by the user or by itself), its answer not yet
    /// picked up. Lets tests wait for a silent automatic check.
    #[doc(hidden)]
    pub fn update_check_running(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        {
            matches!(self.updates.check, Check::Running(_))
        }
        #[cfg(target_arch = "wasm32")]
        {
            false
        }
    }

    fn start_check(&mut self, automatic: bool) {
        let Some(source) = self.update_source.clone() else {
            if !automatic {
                self.open_url(RELEASES_PAGE);
            }
            return;
        };
        #[cfg(not(target_arch = "wasm32"))]
        {
            if !automatic {
                // Asking while an automatic check runs makes that one the user's.
                self.updates.open = true;
                self.updates.automatic = false;
            }
            if matches!(self.updates.check, Check::Running(_)) {
                return;
            }
            self.updates.automatic = automatic;
            let (tx, rx) = std::sync::mpsc::channel();
            let ctx = self.ctx.clone();
            std::thread::spawn(move || {
                // The receiver may be gone (the app quit): nothing to report to then.
                let _ = tx.send(source());
                if let Some(ctx) = ctx {
                    ctx.request_repaint();
                }
            });
            self.updates.check = Check::Running(rx);
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = source;
            if !automatic {
                self.open_url(RELEASES_PAGE);
            }
        }
    }

    /// Pick up a finished check (each frame).
    pub(crate) fn poll_updates(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            self.automatic_update_check(now);
            if let Check::Running(rx) = &self.updates.check {
                let result = match rx.try_recv() {
                    Ok(r) => r,
                    Err(std::sync::mpsc::TryRecvError::Empty) => return,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => Err("the update check stopped unexpectedly".into()),
                };
                if result.is_ok() {
                    self.updates.last_check = now;
                }
                if std::mem::take(&mut self.updates.automatic) {
                    let news = result.as_ref().is_ok_and(|r| {
                        is_newer(&r.version, env!("CARGO_PKG_VERSION")) && self.updates.skipped.as_deref() != Some(r.version.as_str())
                    });
                    self.updates.open |= news;
                }
                self.updates.check = Check::Done(result);
            }
            if let Install::Running { rx, .. } = &self.updates.install {
                let result = match rx.try_recv() {
                    Ok(r) => r,
                    Err(std::sync::mpsc::TryRecvError::Empty) => return,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => Err("the update stopped unexpectedly".into()),
                };
                let url = match &self.updates.check {
                    Check::Done(Ok(r)) => r.url.clone(),
                    _ => RELEASES_PAGE.to_string(),
                };
                let cancelled = matches!(&self.updates.install, Install::Running { progress, .. } if progress.cancel.load(Ordering::Relaxed));
                self.updates.install = match result {
                    // Cancel goes back to the offer.
                    Err(_) if cancelled => Install::Idle,
                    Ok(staged) => {
                        // It goes in whenever CleonPDF quits from now on.
                        (staged.schedule)(false);
                        Install::Ready(staged)
                    }
                    Err(e) => Install::Failed(e, url),
                };
                self.updates.open = true;
            }
        }
    }

    /// Update: download, verify and stage `release` in the background.
    fn start_install(&mut self, release: Release) {
        let Some(installer) = self.update_installer.clone() else { return };
        #[cfg(not(target_arch = "wasm32"))]
        {
            if matches!(self.updates.install, Install::Running { .. } | Install::Ready(_)) {
                return;
            }
            let progress = Arc::new(UpdateProgress::default());
            let (tx, rx) = std::sync::mpsc::channel();
            let ctx = self.ctx.clone();
            let shared = progress.clone();
            let version = release.version.clone();
            std::thread::spawn(move || {
                // Repaint as the download moves, at most ten times a second.
                let done = Arc::new(AtomicBool::new(false));
                if let Some(ctx) = ctx.clone() {
                    let done = done.clone();
                    std::thread::spawn(move || {
                        while !done.load(Ordering::Relaxed) {
                            ctx.request_repaint();
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                    });
                }
                // The receiver may be gone (the app quit): nothing to report to then.
                let _ = tx.send(installer(&release, &shared));
                done.store(true, Ordering::Relaxed);
                if let Some(ctx) = ctx {
                    ctx.request_repaint();
                }
            });
            self.updates.install = Install::Running { rx, progress, version };
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (installer, release);
        }
    }
}

/// What the Updates dialog's user chose this frame.
// The web build has no downloads, so it never cancels one.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
enum Act {
    None,
    /// Close the dialog (a download in progress goes on).
    Close,
    /// Open this release page.
    Download(String),
    /// Don't offer this version (a tag) again by itself.
    Skip(String),
    /// Download and stage this release.
    Install(Release),
    /// Stop the download.
    Cancel,
    /// Quit now so the staged update goes in (and starts, where it can).
    Restart,
}

/// Megabytes, one decimal under ten.
#[cfg(not(target_arch = "wasm32"))]
fn megabytes(bytes: u64) -> String {
    let mb = bytes as f64 / (1024.0 * 1024.0);
    if mb < 10.0 { format!("{mb:.1}") } else { format!("{mb:.0}") }
}

/// The Updates dialog.
pub(crate) fn dialog(app: &mut CleonPdfApp, ctx: &egui::Context) {
    if !app.updates.open {
        return;
    }
    let t = theme::Tokens::get(ctx);
    let current = env!("CARGO_PKG_VERSION");
    let can_install = app.update_installer.is_some();
    let mut act = Act::None;
    let modal = crate::widgets::show_modal(ctx, "updates", |ui| {
        ui.set_width(420.0);
        ui.horizontal(|ui| {
            ui.add(crate::icons::image("cloud", 22.0, t.accent));
            ui.label(egui::RichText::new(tl!("Check for updates")).font(theme::semibold(16.0)));
        });
        ui.add_space(8.0);
        let mut buttons: Vec<(&str, bool, Act)> = Vec::new();
        match &app.updates.install {
            #[cfg(not(target_arch = "wasm32"))]
            Install::Running { progress, version, .. } => {
                let version = version.trim_start_matches(['v', 'V']);
                ui.label(egui::RichText::new(crate::i18n::fmt(tl!("Downloading CleonPDF {v}…"), &[("v", version)])).strong());
                ui.add_space(6.0);
                let received = progress.received.load(Ordering::Relaxed);
                let total = progress.total.load(Ordering::Relaxed);
                let fraction = if total > 0 { (received as f64 / total as f64).clamp(0.0, 1.0) as f32 } else { 0.0 };
                // The theme's own bar: egui's default fill is lost against the dialog's colours.
                let (rect, _) = ui.allocate_exact_size(egui::vec2(420.0, 8.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 4.0, t.accent_soft);
                let done = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width() * fraction, rect.height()));
                ui.painter().rect_filled(done, 4.0, t.accent);
                ui.add_space(4.0);
                if total > 0 {
                    let text = crate::i18n::fmt(tl!("{done} MB of {total} MB"), &[("done", &megabytes(received)), ("total", &megabytes(total))]);
                    ui.label(egui::RichText::new(text).color(t.text_muted));
                }
                buttons.push((tl!("Later"), true, Act::Close));
                buttons.push((tl!("Cancel"), false, Act::Cancel));
            }
            Install::Ready(staged) => {
                let version = staged.version.trim_start_matches(['v', 'V']);
                let text = if staged.relaunches {
                    tl!("CleonPDF {v} is ready. It is installed when you quit CleonPDF.")
                } else {
                    tl!("CleonPDF {v} is ready. Its installer runs when you quit CleonPDF.")
                };
                ui.label(egui::RichText::new(crate::i18n::fmt(text, &[("v", version)])).strong());
                let now = if staged.relaunches { tl!("Restart now") } else { tl!("Install now") };
                buttons.push((now, true, Act::Restart));
                buttons.push((tl!("Later"), false, Act::Close));
            }
            Install::Failed(e, url) => {
                ui.label(crate::i18n::fmt(tl!("Couldn't update: {e}"), &[("e", e)]));
                ui.label(egui::RichText::new(tl!("You can still download it from its release page.")).color(t.text_muted));
                buttons.push((tl!("Download"), true, Act::Download(url.clone())));
                buttons.push((tl!("Close"), false, Act::Close));
            }
            Install::Idle => match &app.updates.check {
                Check::Idle => {
                    ui.label(tl!("No check has run yet."));
                }
                #[cfg(not(target_arch = "wasm32"))]
                Check::Running(_) => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(tl!("Checking for a newer version…"));
                    });
                }
                Check::Done(Ok(r)) if is_newer(&r.version, current) => {
                    let version = r.version.trim_start_matches(['v', 'V']);
                    ui.label(egui::RichText::new(crate::i18n::fmt(tl!("CleonPDF {v} is available."), &[("v", version)])).strong());
                    let you_have = if can_install {
                        tl!("You have version {c}.")
                    } else {
                        tl!("You have version {c}. Download the new version from its release page.")
                    };
                    ui.label(egui::RichText::new(crate::i18n::fmt(you_have, &[("c", current)])).color(t.text_muted));
                    if can_install {
                        buttons.push((tl!("Update"), true, Act::Install(r.clone())));
                    } else {
                        buttons.push((tl!("Download"), true, Act::Download(r.url.clone())));
                    }
                    buttons.push((tl!("Later"), false, Act::Close));
                    buttons.push((tl!("Skip this version"), false, Act::Skip(r.version.clone())));
                }
                Check::Done(Ok(_)) => {
                    ui.label(crate::i18n::fmt(tl!("CleonPDF {c} is up to date."), &[("c", current)]));
                }
                Check::Done(Err(e)) => {
                    ui.label(crate::i18n::fmt(tl!("Couldn't check for updates: {e}"), &[("e", &e.to_string())]));
                    ui.label(
                        egui::RichText::new(crate::i18n::fmt(
                            tl!("You have version {c}. All releases are listed at {page}."),
                            &[("c", current), ("page", RELEASES_PAGE)],
                        ))
                        .color(t.text_muted),
                    );
                }
            },
        }
        ui.add_space(10.0);
        let footer = if can_install {
            tl!("Asks GitHub for the latest release. An update is installed only if it is signed with CleonPDF's release key.")
        } else {
            tl!("Asks GitHub for the latest release. Nothing is downloaded or installed automatically.")
        };
        ui.label(egui::RichText::new(footer).color(t.text_muted).small());
        ui.add_space(12.0);
        if buttons.is_empty() {
            buttons.push((tl!("Close"), true, Act::Close));
        }
        // One row's height: a right-to-left layout would take all the height there is, and the
        // dialog would never shrink back after a taller step (the download's progress).
        ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), 32.0), Layout::right_to_left(Align::Center), |ui| {
            // Ids from the labels: the lines above change as a download moves.
            for (label, primary, choice) in buttons {
                if ui.push_id(label, |ui| widgets::pill_button(ui, label, primary).clicked()).inner {
                    act = choice;
                }
            }
        });
    });
    if modal.should_close() && matches!(act, Act::None) {
        act = Act::Close;
    }
    match act {
        Act::None => {}
        Act::Close => {
            app.updates.open = false;
            // A failure is forgotten, so the next Update tries again.
            if matches!(app.updates.install, Install::Failed(..)) {
                app.updates.install = Install::Idle;
            }
        }
        Act::Download(url) => {
            app.updates.open = false;
            app.updates.install = Install::Idle;
            app.open_url(&url);
        }
        Act::Skip(version) => {
            app.updates.open = false;
            app.updates.skipped = Some(version);
        }
        Act::Install(release) => app.start_install(release),
        Act::Cancel =>
        {
            #[cfg(not(target_arch = "wasm32"))]
            if let Install::Running { progress, .. } = &app.updates.install {
                progress.cancel.store(true, Ordering::Relaxed);
            }
        }
        Act::Restart => {
            if let Install::Ready(staged) = &app.updates.install {
                (staged.schedule)(true);
            }
            app.updates.open = false;
            app.request_quit(ctx);
        }
    }
}
