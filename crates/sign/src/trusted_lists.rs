//! Keeping the EU Trusted Lists up to date: fetch the list of lists, then each national list it
//! points to, believing nothing that is not signed by a certificate the caller named.
//!
//! This module never opens a socket and never touches a disk: a [`ListFetcher`] brings documents
//! in (`cleonpdf-net` is the HTTP one), and the caller keeps the [`Snapshot`] between runs. What
//! it decides is what a list must satisfy to be used:
//!
//! - its XML signature verifies against a certificate the caller named (for the list of lists) or
//!   the one the verified list of lists names for it (for a national list);
//! - it has not passed its `NextUpdate`;
//! - its sequence number is not lower than that of the copy already held (a rollback to an older
//!   list could bring back a service that was withdrawn);
//! - a national list is for the territory the list of lists says it is for.
//!
//! One national list failing does not stop the others, and a list that cannot be refreshed is
//! kept from the previous snapshot only while that copy still verifies and has not expired. The
//! outcome of every list is recorded, so a country whose list could not be used is visible.

use std::collections::BTreeSet;

use crate::der::Time;
use crate::pdf::EutlAnchor;
use crate::tl::{CA_QC, QualifiedRoot, TrustedList, TrustedListError};
use crate::x509::Certificate;
use crate::{SignError, tl::ListPointer};

/// The address of the European Commission's list of lists.
pub const LOTL_URL: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
/// The media type of a Trusted List in XML form (the other pointers are human-readable renderings).
pub const XML_MIME: &str = "application/vnd.etsi.tsl+xml";
/// Most bytes read for one list.
pub const MAX_LIST_BYTES: u64 = 48 * 1024 * 1024;
/// Most national lists followed from one list of lists.
pub const MAX_NATIONAL_LISTS: usize = 64;

/// How lists are brought in. Implemented over HTTP by `cleonpdf-net`; tests use fakes.
pub trait ListFetcher {
    /// The document published at `url`, at most `max_bytes` long.
    ///
    /// # Errors
    /// [`SignError::Transport`] when it cannot be reached or answers with something unusable.
    fn fetch(&self, url: &str, max_bytes: u64) -> Result<String, SignError>;
}

/// The documents of one verified state: what the caller keeps between runs. They are kept as
/// the signed text, and [`Snapshot::load`] verifies them again, so a changed copy on disk is
/// found out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Documents {
    /// The list of lists.
    pub lotl: String,
    /// The national lists with the address each was fetched from.
    pub lists: Vec<(String, String)>,
}

/// The file that holds the list of lists, in the layout [`Documents::to_files`] gives.
pub const LOTL_FILE: &str = "lotl.xml";
/// The file that says which address each `list-N.xml` came from.
pub const LOCATIONS_FILE: &str = "locations.txt";

fn list_file_name(n: usize) -> String {
    format!("list-{n}.xml")
}

/// Whether `name` is a name `to_files` gives a national list.
fn is_list_file(name: &str) -> bool {
    name.strip_prefix("list-").and_then(|r| r.strip_suffix(".xml")).is_some_and(|d| !d.is_empty() && d.len() <= 4 && d.bytes().all(|b| b.is_ascii_digit()))
}

impl Documents {
    /// The files to keep these documents in, as (name, content) pairs: the list of lists, each
    /// national list as `list-N.xml`, and last the file that says where each came from. Writing
    /// them in this order means a half-written set never names a list it lacks.
    #[must_use]
    pub fn to_files(&self) -> Vec<(String, String)> {
        let mut files = vec![(LOTL_FILE.to_string(), self.lotl.clone())];
        let mut index = String::new();
        for (n, (location, xml)) in self.lists.iter().enumerate() {
            let name = list_file_name(n);
            // An address has no tab or line break: the fetcher refuses those.
            index.push_str(&format!("{name}\t{}\n", location.replace(['\t', '\n', '\r'], "")));
            files.push((name, xml.clone()));
        }
        files.push((LOCATIONS_FILE.to_string(), index));
        files
    }

    /// The names of files a previous `to_files` may have left that the current set no longer
    /// uses: `list-N.xml` for an N past the lists held.
    #[must_use]
    pub fn stale_files(&self, existing: &[String]) -> Vec<String> {
        let keep: std::collections::BTreeSet<String> = (0..self.lists.len()).map(list_file_name).collect();
        existing.iter().filter(|n| is_list_file(n) && !keep.contains(*n)).cloned().collect()
    }

    /// Read documents kept by [`Documents::to_files`], with `read` giving a file's text by name.
    /// `None` when there is no list of lists; a national list whose file is missing is left out.
    pub fn from_files(read: impl Fn(&str) -> Option<String>) -> Option<Documents> {
        let lotl = read(LOTL_FILE)?;
        let mut lists = Vec::new();
        for line in read(LOCATIONS_FILE).unwrap_or_default().lines().take(MAX_NATIONAL_LISTS) {
            let Some((name, location)) = line.split_once('\t') else { continue };
            if !is_list_file(name) {
                continue;
            }
            if let Some(xml) = read(name) {
                lists.push((location.to_string(), xml));
            }
        }
        Some(Documents { lotl, lists })
    }
}

/// What became of one national list in a refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A newer list was fetched and verified.
    Updated,
    /// The list fetched is the one already held.
    Unchanged,
    /// The list could not be refreshed and the copy already held is still good.
    KeptPrevious(String),
    /// The list is not used, and why.
    Unusable(String),
}

/// A national list's place in a refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListReport {
    pub territory: String,
    pub location: String,
    pub outcome: Outcome,
}

/// The lists in force: the list of lists and the national lists that could be used.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub lotl: TrustedList,
    /// Each national list with the address it came from.
    pub lists: Vec<(String, TrustedList)>,
    /// One entry per pointer in the list of lists.
    pub reports: Vec<ListReport>,
    /// The signed text of all of it, to be kept.
    pub documents: Documents,
}

/// Why a refresh produced nothing new.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefreshError {
    #[error("the list of lists could not be fetched: {0}")]
    Fetch(String),
    #[error("the list of lists was refused: {0}")]
    Refused(TrustedListError),
    #[error("the list of lists is older (sequence {fetched}) than the one already held (sequence {held})")]
    Rollback { fetched: u64, held: u64 },
    #[error("the list of lists is out of date since {0}")]
    Expired(Time),
    #[error("no signing certificate for the list of lists was given")]
    NoAnchors,
}

fn usable(list: &TrustedList, now: Time) -> Result<(), String> {
    if list.is_expired(now) {
        let since = list.scheme.next_update.map(|t| t.to_string()).unwrap_or_default();
        return Err(format!("out of date since {since}"));
    }
    Ok(())
}

/// Whether a pointer is for a Trusted List in XML that this module follows.
fn followed(p: &ListPointer, own_territory: &str) -> bool {
    p.mime_type.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(XML_MIME))
        && p.territory.as_deref().is_some_and(|t| !t.is_empty() && !t.eq_ignore_ascii_case(own_territory))
}

impl Snapshot {
    /// Verify documents the caller kept and make a snapshot of them. A list that no longer
    /// verifies, or is out of date, is left out and reported; the list of lists must be good.
    ///
    /// # Errors
    /// [`RefreshError`] when the list of lists does not verify against `anchors` or is out of date.
    pub fn load(documents: &Documents, anchors: &[Certificate], now: Time) -> Result<Snapshot, RefreshError> {
        if anchors.is_empty() {
            return Err(RefreshError::NoAnchors);
        }
        let lotl = TrustedList::parse(&documents.lotl, anchors, now).map_err(RefreshError::Refused)?;
        if let Err(_why) = usable(&lotl, now) {
            return Err(RefreshError::Expired(lotl.scheme.next_update.unwrap_or(now)));
        }
        let mut lists = Vec::new();
        let mut reports = Vec::new();
        let mut kept = Documents { lotl: documents.lotl.clone(), lists: Vec::new() };
        for p in lotl.pointers.iter().filter(|p| followed(p, &lotl.scheme.territory)).take(MAX_NATIONAL_LISTS) {
            let territory = p.territory.clone().unwrap_or_default();
            let held = documents.lists.iter().find(|(loc, _)| *loc == p.location);
            let outcome = match held {
                None => Outcome::Unusable("not held".into()),
                Some((loc, xml)) => match check_national(xml, p, now) {
                    Ok(list) => {
                        lists.push((loc.clone(), list));
                        kept.lists.push((loc.clone(), xml.clone()));
                        Outcome::Unchanged
                    }
                    Err(why) => Outcome::Unusable(why),
                },
            };
            reports.push(ListReport { territory, location: p.location.clone(), outcome });
        }
        Ok(Snapshot { lotl, lists, reports, documents: kept })
    }

    /// Fetch the list of lists and the national lists it points to, keeping from `previous`
    /// what could not be refreshed. Nothing is changed in `previous`.
    ///
    /// # Errors
    /// [`RefreshError`] when the list of lists cannot be had, does not verify, is out of date or is
    /// older than the one in `previous`: the caller then keeps using `previous`.
    pub fn refresh(
        fetcher: &dyn ListFetcher,
        lotl_url: &str,
        anchors: &[Certificate],
        now: Time,
        previous: Option<&Snapshot>,
    ) -> Result<Snapshot, RefreshError> {
        if anchors.is_empty() {
            return Err(RefreshError::NoAnchors);
        }
        let xml = fetcher.fetch(lotl_url, MAX_LIST_BYTES).map_err(|e| RefreshError::Fetch(e.to_string()))?;
        let lotl = TrustedList::parse(&xml, anchors, now).map_err(RefreshError::Refused)?;
        if lotl.is_expired(now) {
            return Err(RefreshError::Expired(lotl.scheme.next_update.unwrap_or(now)));
        }
        if let Some(held) = previous.map(|p| p.lotl.scheme.sequence_number).filter(|h| lotl.scheme.sequence_number < *h) {
            return Err(RefreshError::Rollback { fetched: lotl.scheme.sequence_number, held });
        }
        let mut lists = Vec::new();
        let mut reports = Vec::new();
        let mut kept = Documents { lotl: xml, lists: Vec::new() };
        let mut seen = BTreeSet::new();
        for p in lotl.pointers.iter().filter(|p| followed(p, &lotl.scheme.territory)) {
            let territory = p.territory.clone().unwrap_or_default();
            let report = |outcome| ListReport { territory: territory.clone(), location: p.location.clone(), outcome };
            if reports.len() >= MAX_NATIONAL_LISTS {
                reports.push(report(Outcome::Unusable("more national lists than are followed".into())));
                continue;
            }
            // A second pointer for a territory would let one list shadow another.
            if !seen.insert(territory.to_ascii_uppercase()) {
                reports.push(report(Outcome::Unusable("the list of lists points to this territory twice".into())));
                continue;
            }
            let held = previous.and_then(|s| s.held(&p.location));
            let fetched = fetcher.fetch(&p.location, MAX_LIST_BYTES).map_err(|e| e.to_string()).and_then(|xml| {
                let list = check_national(&xml, p, now)?;
                match held {
                    Some((old, _)) if list.scheme.sequence_number < old.scheme.sequence_number => Err(format!(
                        "older (sequence {}) than the one already held (sequence {})",
                        list.scheme.sequence_number, old.scheme.sequence_number
                    )),
                    _ => Ok((xml, list)),
                }
            });
            match fetched {
                Ok((xml, list)) => {
                    let same = held.is_some_and(|(old, _)| old.scheme == list.scheme);
                    kept.lists.push((p.location.clone(), xml));
                    reports.push(report(if same { Outcome::Unchanged } else { Outcome::Updated }));
                    lists.push((p.location.clone(), list));
                }
                Err(why) => {
                    // The copy held is used only if it is still good under today's list of lists.
                    let still = held.and_then(|(_, xml)| check_national(xml, p, now).ok().map(|l| (xml.to_string(), l)));
                    match still {
                        Some((xml, list)) => {
                            kept.lists.push((p.location.clone(), xml));
                            lists.push((p.location.clone(), list));
                            reports.push(report(Outcome::KeptPrevious(why)));
                        }
                        None => reports.push(report(Outcome::Unusable(why))),
                    }
                }
            }
        }
        Ok(Snapshot { lotl, lists, reports, documents: kept })
    }

    /// The list held from `location` and its signed text.
    fn held(&self, location: &str) -> Option<(&TrustedList, &str)> {
        let list = self.lists.iter().find(|(loc, _)| loc == location).map(|(_, l)| l)?;
        let xml = self.documents.lists.iter().find(|(loc, _)| loc == location).map(|(_, x)| x.as_str())?;
        Some((list, xml))
    }

    /// The certificates that anchor trust in qualified certificates at `t` across all the lists
    /// in force, each with the territory of the list that names it.
    #[must_use]
    pub fn qualified_roots_at(&self, t: Time) -> Vec<(String, QualifiedRoot<'_>)> {
        let mut out = Vec::new();
        for (_, list) in &self.lists {
            for root in list.qualified_roots_at(t) {
                out.push((list.scheme.territory.clone(), root));
            }
        }
        out
    }

    /// The certification authorities of qualified services, as trust anchors for validation: each
    /// certificate with the times its service was granted (from the state's start to the next
    /// state's, or without end for the current one).
    #[must_use]
    pub fn anchors(&self) -> Vec<EutlAnchor> {
        let mut out = Vec::new();
        for (_, list) in &self.lists {
            for provider in &list.providers {
                for service in &provider.services {
                    for (i, state) in service.states.iter().enumerate() {
                        if state.service_type != CA_QC || !state.is_granted() {
                            continue;
                        }
                        let until = service.states.get(i.saturating_add(1)).map(|next| next.from);
                        for certificate in &state.certificates {
                            out.push(EutlAnchor {
                                certificate: certificate.clone(),
                                territory: list.scheme.territory.clone(),
                                provider: provider.name.clone(),
                                service: service.name.clone(),
                                granted: vec![(state.from, until)],
                            });
                        }
                    }
                }
            }
        }
        out
    }

    /// The national lists that are not in use, with the reason.
    #[must_use]
    pub fn unusable(&self) -> Vec<&ListReport> {
        self.reports.iter().filter(|r| matches!(r.outcome, Outcome::Unusable(_))).collect()
    }
}

/// Verify a national list against the signers its pointer names, and the other rules.
fn check_national(xml: &str, pointer: &ListPointer, now: Time) -> Result<TrustedList, String> {
    let list = TrustedList::parse(xml, &pointer.signers, now).map_err(|e| e.to_string())?;
    usable(&list, now)?;
    let want = pointer.territory.as_deref().unwrap_or_default();
    if !list.scheme.territory.eq_ignore_ascii_case(want) {
        return Err(format!("the list is for {} and not for {want}", list.scheme.territory));
    }
    Ok(list)
}
