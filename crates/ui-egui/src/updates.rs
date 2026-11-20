//! Help ▸ Check for updates (issue #28): ask for the latest release and offer its download page.
//!
//! The desktop app supplies how to ask ([`CleonPdfApp::update_source`]), so this crate has no
//! network code; without a source (the web build, tests) the command opens the releases page.
//! CleonPDF never downloads or installs anything itself: the user downloads the new version.
//! It asks when the user does, and by itself at most once a day when CleonPDF starts
//! ([`CleonPdfApp::check_updates_automatically`], on unless turned off in Preferences, and only
//! where the host allows it). An automatic check that finds nothing new, or fails, says nothing;
//! one that finds a version the user hasn't skipped opens the Updates dialog.

use std::sync::Arc;

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
        }
    }
}

/// The Updates dialog.
pub(crate) fn dialog(app: &mut CleonPdfApp, ctx: &egui::Context) {
    if !app.updates.open {
        return;
    }
    let t = theme::Tokens::get(ctx);
    let current = env!("CARGO_PKG_VERSION");
    let mut close = false;
    let mut download: Option<String> = None;
    let mut skip: Option<String> = None;
    let modal = crate::widgets::show_modal(ctx, "updates", |ui| {
        ui.set_width(420.0);
        ui.horizontal(|ui| {
            ui.add(crate::icons::image("cloud", 22.0, t.accent));
            ui.label(egui::RichText::new(tl!("Check for updates")).font(theme::semibold(16.0)));
        });
        ui.add_space(8.0);
        match &app.updates.check {
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
                ui.label(
                    egui::RichText::new(crate::i18n::fmt(
                        tl!("You have version {c}. Download the new version from its release page."),
                        &[("c", current)],
                    ))
                    .color(t.text_muted),
                );
                download = Some(r.url.clone());
                skip = Some(r.version.clone());
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
        }
        ui.add_space(10.0);
        ui.label(
            egui::RichText::new(tl!("Asks GitHub for the latest release. Nothing is downloaded or installed automatically."))
                .color(t.text_muted)
                .small(),
        );
        ui.add_space(12.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(url) = download.take() {
                let get = widgets::pill_button(ui, tl!("Download"), true).clicked();
                let later = widgets::pill_button(ui, tl!("Later"), false).clicked();
                let skipped = widgets::pill_button(ui, tl!("Skip this version"), false).clicked();
                close = get || later || skipped;
                download = get.then_some(url);
                skip = skip.take().filter(|_| skipped);
            } else if widgets::pill_button(ui, tl!("Close"), true).clicked() {
                close = true;
            }
        });
    });
    if modal.should_close() {
        close = true;
        download = None;
        skip = None;
    }
    if close {
        app.updates.open = false;
        if skip.is_some() {
            app.updates.skipped = skip;
        }
        if let Some(url) = download {
            app.open_url(&url);
        }
    }
}
