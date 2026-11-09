//! Preferences ▸ Signatures ▸ European Union Trusted Lists: the opt-in switch, the certificates
//! the list of lists is verified against, the lists kept on disk and the update that fetches them.
//!
//! Nothing here runs on its own. Turning the lists on, and starting the app with them on, read
//! only the copy kept on disk (verified again every time); the network is used when the person
//! presses Update now, on a worker thread, and only for the Commission's list of lists and the
//! national lists it points to.
#![cfg(not(target_arch = "wasm32"))]

use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};

use cleonpdf_engine::sign::trusted_lists::{Documents, LOTL_URL, ListFetcher, ListReport, MAX_LIST_BYTES, RefreshError, Snapshot};
use cleonpdf_engine::sign::{Certificate, EutlAnchor, Time};

use crate::CleonPdfApp;

/// A fetcher the update can use from its worker thread.
pub type SharedFetcher = Arc<dyn ListFetcher + Send + Sync>;

/// What the lists in force look like: shown under the Update now button.
#[derive(Clone, Debug, PartialEq)]
pub struct EutlSummary {
    /// The sequence number of the list of lists.
    pub sequence: u64,
    /// When the list of lists says the next one is due.
    pub next_update: Option<Time>,
    /// How many certification authorities the lists name as trusted.
    pub authorities: usize,
    /// One entry per national list the list of lists points to.
    pub countries: Vec<ListReport>,
    /// The lists were fetched just now (false: read from the copy kept on disk).
    pub fetched: bool,
}

/// A finished update, on its way from the worker thread.
struct Done {
    anchors: Vec<EutlAnchor>,
    summary: EutlSummary,
}

struct Job {
    rx: mpsc::Receiver<Result<Done, String>>,
    /// The certificates the update verifies against; its answer is dropped if they changed.
    signers: Vec<Vec<u8>>,
}

/// The state of the Trusted Lists preference.
#[derive(Default)]
pub struct EutlState {
    /// Preferences ▸ Use the European Union Trusted Lists. Off until the person turns it on.
    pub on: bool,
    /// The certificates the Commission signs the list of lists with, as the person verified and
    /// imported them. None is built in.
    pub signers: Vec<Certificate>,
    /// The lists in force, when there are some.
    pub summary: Option<EutlSummary>,
    /// Why the last update, or the last read of the kept lists, did not give lists.
    pub problem: Option<String>,
    job: Option<Job>,
    /// Another folder for the kept lists (tests).
    pub cache_dir: Option<PathBuf>,
    /// Another way to fetch the lists (tests).
    pub source: Option<SharedFetcher>,
}

impl std::fmt::Debug for EutlState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EutlState").field("on", &self.on).field("signers", &self.signers.len()).field("summary", &self.summary).finish()
    }
}

impl EutlState {
    /// An update is running.
    pub fn updating(&self) -> bool {
        self.job.is_some()
    }

    /// Where the lists are kept: next to the recovery folder (`…/CleonPDF/Trusted Lists`, or
    /// `CleonPdfData/Trusted Lists` in portable mode).
    pub fn folder(&self) -> Option<PathBuf> {
        self.cache_dir.clone().or_else(|| crate::recovery::RecoveryStore::default_dir().and_then(|d| d.parent().map(|p| p.join("Trusted Lists"))))
    }
}

fn raw_of(certs: &[Certificate]) -> Vec<Vec<u8>> {
    certs.iter().map(|c| c.raw.clone()).collect()
}

/// The lists kept in `dir`, as `Documents::to_files` laid them out.
fn read_kept(dir: &Path) -> Option<Documents> {
    Documents::from_files(|name| {
        let path = dir.join(name);
        // The files are ours, but a folder can be filled by anyone: no list is read past the cap.
        let len = std::fs::metadata(&path).ok()?.len();
        if len > MAX_LIST_BYTES {
            return None;
        }
        std::fs::read_to_string(path).ok()
    })
}

/// Keep `documents` in `dir`: every file atomically, the file naming the others last, and the
/// files of lists that are gone removed.
fn write_kept(dir: &Path, documents: &Documents) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let existing: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()?.file_name().into_string().ok()).collect(),
        Err(_) => Vec::new(),
    };
    for (name, text) in documents.to_files() {
        let path = dir.join(&name);
        let path = path.to_str().ok_or_else(|| format!("{}: not a usable path", path.display()))?;
        crate::editing::write_atomically(path, text.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
    }
    for name in documents.stale_files(&existing) {
        let _ = std::fs::remove_file(dir.join(name));
    }
    Ok(())
}

fn summarize(snapshot: &Snapshot, fetched: bool) -> EutlSummary {
    EutlSummary {
        sequence: snapshot.lotl.scheme.sequence_number,
        next_update: snapshot.lotl.scheme.next_update,
        authorities: snapshot.anchors().len(),
        countries: snapshot.reports.clone(),
        fetched,
    }
}

/// The lists kept in `dir`, verified again against `signers` as of `now`.
fn load_kept(dir: &Path, signers: &[Certificate], now: Time) -> Result<Snapshot, String> {
    let documents = read_kept(dir).ok_or_else(|| "no Trusted Lists have been downloaded yet".to_string())?;
    Snapshot::load(&documents, signers, now).map_err(|e| e.to_string())
}

/// Fetch the lists, keeping `dir` up to date. When the lists cannot be reached the copy in `dir`
/// is used, if it still verifies. Returns the snapshot and whether it is new.
fn update(fetcher: &dyn ListFetcher, dir: &Path, signers: &[Certificate], now: Time) -> Result<(Snapshot, bool), String> {
    let previous = load_kept(dir, signers, now).ok();
    match Snapshot::refresh(fetcher, LOTL_URL, signers, now, previous.as_ref()) {
        Ok(snapshot) => {
            write_kept(dir, &snapshot.documents)?;
            Ok((snapshot, true))
        }
        Err(RefreshError::Fetch(why)) => match previous {
            Some(held) => Ok((held.kept_offline(&why), false)),
            None => Err(RefreshError::Fetch(why).to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

impl CleonPdfApp {
    /// Use the lists in `snapshot` for validation, or none.
    fn apply_eutl(&mut self, found: Option<(Vec<EutlAnchor>, EutlSummary)>) {
        match found {
            Some((anchors, summary)) => {
                self.session.set_eutl_anchors(anchors);
                self.eutl.summary = Some(summary);
                self.eutl.problem = None;
            }
            None => {
                self.session.set_eutl_anchors(Vec::new());
                self.eutl.summary = None;
            }
        }
    }

    /// Read the lists kept on disk and use them: no network. Used when the preference is turned
    /// on, when its certificates change and when the app starts. Whatever does not verify is not
    /// used, and the reason is kept for the preference to show.
    pub fn reload_eutl_lists(&mut self) {
        if !self.eutl.on || self.eutl.signers.is_empty() {
            self.apply_eutl(None);
            return;
        }
        let loaded = match (self.session.trust_time(), self.eutl.folder()) {
            (None, _) => Err("the Trusted Lists need today's date and this system gives none".to_string()),
            (_, None) => Err("there is no folder to keep the Trusted Lists in".to_string()),
            (Some(now), Some(dir)) => load_kept(&dir, &self.eutl.signers, now),
        };
        match loaded {
            Ok(snapshot) => self.apply_eutl(Some((snapshot.anchors(), summarize(&snapshot, false)))),
            Err(why) => {
                self.apply_eutl(None);
                self.eutl.problem = Some(why);
            }
        }
    }

    /// Preferences ▸ Use the European Union Trusted Lists. Needs the certificates the list of
    /// lists is verified against; reads only the lists already kept.
    ///
    /// # Errors
    /// When turned on without a certificate to verify the list of lists with.
    pub fn set_use_eutl_lists(&mut self, on: bool) -> Result<(), String> {
        if on && self.eutl.signers.is_empty() {
            return Err("Add the certificates that sign the list of lists first".into());
        }
        self.eutl.on = on;
        self.eutl.problem = None;
        self.reload_eutl_lists();
        Ok(())
    }

    /// Verify the list of lists against these certificates from now on (the Commission's, which
    /// the person has checked against the Official Journal).
    ///
    /// # Errors
    /// When the bytes hold no certificate.
    pub fn add_eutl_signers(&mut self, bytes: &[u8]) -> Result<usize, String> {
        let certs = cleonpdf_engine::sign::x509::load_certificates(bytes).map_err(|e| e.to_string())?;
        if certs.is_empty() {
            return Err("That file holds no certificate".into());
        }
        let mut added = 0;
        for c in certs {
            if !self.eutl.signers.iter().any(|s| s.raw == c.raw) {
                self.eutl.signers.push(c);
                added += 1;
            }
        }
        self.reload_eutl_lists();
        Ok(added)
    }

    /// Stop verifying the list of lists against the certificate at `index`. With none left the
    /// lists stop counting and the preference goes off.
    pub fn remove_eutl_signer(&mut self, index: usize) {
        if index < self.eutl.signers.len() {
            self.eutl.signers.remove(index);
        }
        if self.eutl.signers.is_empty() {
            self.eutl.on = false;
        }
        self.reload_eutl_lists();
    }

    /// Preferences ▸ Update now: fetch the list of lists and the national lists on a worker
    /// thread. The answer is picked up by [`CleonPdfApp::poll_eutl`].
    ///
    /// # Errors
    /// When the preference is off, has no certificate, or there is no date or folder to use.
    pub fn update_eutl_lists(&mut self) -> Result<(), String> {
        if self.eutl.job.is_some() {
            return Ok(());
        }
        if !self.eutl.on || self.eutl.signers.is_empty() {
            return Err("Turn on the European Union Trusted Lists first".into());
        }
        let now = self.session.trust_time().ok_or("The Trusted Lists need today's date and this system gives none")?;
        let dir = self.eutl.folder().ok_or("There is no folder to keep the Trusted Lists in")?;
        let signers = self.eutl.signers.clone();
        let source = self.eutl.source.clone();
        let (tx, rx) = mpsc::channel();
        let ctx = self.ctx.clone();
        let spawned = std::thread::Builder::new().name("trusted-lists".into()).spawn(move || {
            let fetcher: SharedFetcher = source.unwrap_or_else(|| Arc::new(cleonpdf_net::HttpListFetcher::new()));
            let answer = update(&*fetcher, &dir, &signers, now)
                .map(|(snapshot, fetched)| Done { anchors: snapshot.anchors(), summary: summarize(&snapshot, fetched) });
            // The receiver may be gone (the app quit): nothing to report to then.
            let _ = tx.send(answer);
            if let Some(ctx) = ctx {
                ctx.request_repaint();
            }
        });
        if spawned.is_err() {
            return Err("The update could not be started".into());
        }
        self.eutl.job = Some(Job { rx, signers: raw_of(&self.eutl.signers) });
        self.eutl.problem = None;
        Ok(())
    }

    /// Pick up a finished update. The app calls it every frame; a headless driver can too.
    pub fn poll_eutl(&mut self) {
        let Some(job) = &self.eutl.job else { return };
        let answer = match job.rx.try_recv() {
            Ok(a) => a,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err("the update stopped unexpectedly".into()),
        };
        let same_signers = raw_of(&self.eutl.signers) == job.signers;
        self.eutl.job = None;
        // The preference was turned off, or its certificates changed, while the update ran: what
        // it brought was verified against something else.
        if !self.eutl.on || !same_signers {
            return;
        }
        match answer {
            Ok(Done { anchors, summary }) => {
                let (fetched, countries) = (summary.fetched, summary.countries.len().to_string());
                self.apply_eutl(Some((anchors, summary)));
                if fetched {
                    self.notify_fmt("Trusted Lists updated: {n} national lists", &[("n", &countries)]);
                } else {
                    self.notify_tr("The Trusted Lists could not be fetched; the lists already kept are used");
                }
            }
            Err(why) => {
                self.eutl.problem = Some(why.clone());
                self.notify_fmt("Couldn't update the Trusted Lists: {e}", &[("e", &why)]);
            }
        }
    }

    /// Preferences ▸ Add certificate…: choose a file holding the certificates that sign the list
    /// of lists (.cer, .crt, .pem or .der).
    pub(crate) fn pick_eutl_signers(&mut self) {
        let dialog = rfd::AsyncFileDialog::new().add_filter(tl!("Certificate"), &["cer", "crt", "pem", "der"]);
        self.ask_one(crate::pickers::Ask::File(dialog), None, |app, path| {
            let read = std::fs::metadata(&path).map_err(|e| e.to_string()).and_then(|m| {
                if m.len() > 1 << 20 {
                    Err("That file is too large to be a certificate".to_string())
                } else {
                    std::fs::read(&path).map_err(|e| e.to_string())
                }
            });
            match read.and_then(|bytes| app.add_eutl_signers(&bytes)) {
                Ok(0) => app.notify_tr("That certificate is already in the list"),
                Ok(_) => {}
                Err(e) => app.notify_fmt("Couldn't read the certificate: {e}", &[("e", &e)]),
            }
        });
    }
}
