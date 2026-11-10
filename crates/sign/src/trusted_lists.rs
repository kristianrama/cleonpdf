//! Keeping the EU Trusted Lists up to date: fetch the list of lists, then each national list it
//! points to, believing nothing that is not signed by a certificate the caller named.
//!
//! This module never opens a socket and never touches a disk: a [`ListFetcher`] brings documents
//! in (`cleonpdf-net` is the HTTP one), and the caller keeps the [`Snapshot`] between runs. What
//! it decides is what a list must satisfy to be used:
//!
//! - its XML signature verifies against a certificate the caller named (for the list of lists) or
//!   the one the verified list of lists names for it (for a national list);
//! - when the Commission has changed the certificates it signs the list of lists with since the
//!   ones the caller named were published, the list of lists says where its *pivots* are: older
//!   issues of itself, each signed with the certificates of the one before and naming the
//!   certificates of the next. They are followed from the caller's certificates to today's, every
//!   link verified, and a chain with a link missing or out of order is refused (see
//!   [`MAX_PIVOTS`]);
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
use crate::tl::{CA_QC, QualifiedRoot, TrustedList, TrustedListError, unverified_information_uris};
use crate::x509::Certificate;
use crate::xmldsig::XmlSignatureError;
use crate::{SignError, tl::ListPointer};

/// The address of the European Commission's list of lists.
pub const LOTL_URL: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
/// The media type of a Trusted List in XML form (the other pointers are human-readable renderings).
pub const XML_MIME: &str = "application/vnd.etsi.tsl+xml";
/// Most bytes read for one list.
pub const MAX_LIST_BYTES: u64 = 48 * 1024 * 1024;
/// Most national lists followed from one list of lists.
pub const MAX_NATIONAL_LISTS: usize = 64;
/// Most pivots of the list of lists followed. The Commission has published a handful since 2019.
pub const MAX_PIVOTS: usize = 32;
/// Most chains of pivots tried: one per publication in the Official Journal the list of lists
/// still names (two while the Commission moves from one to the next).
const MAX_PIVOT_CHAINS: usize = 4;
/// Most bytes read for one pivot. A pivot is an issue of the list of lists, which has no
/// providers in it.
pub const MAX_PIVOT_BYTES: u64 = 8 * 1024 * 1024;

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
    /// The pivots that led from the caller's certificates to the signer of the list of lists,
    /// oldest first, with the address each was fetched from. Empty when none were needed.
    pub pivots: Vec<(String, String)>,
}

/// The file that holds the list of lists, in the layout [`Documents::to_files`] gives.
pub const LOTL_FILE: &str = "lotl.xml";
/// The file that says which address each `list-N.xml` came from.
pub const LOCATIONS_FILE: &str = "locations.txt";

fn list_file_name(n: usize) -> String {
    format!("list-{n}.xml")
}

fn pivot_file_name(n: usize) -> String {
    format!("pivot-{n}.xml")
}

/// Whether `name` is `<prefix>N.xml` with a short number.
fn is_numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|r| r.strip_suffix(".xml"))
        .is_some_and(|d| !d.is_empty() && d.len() <= 4 && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `name` is a name `to_files` gives a national list.
fn is_list_file(name: &str) -> bool {
    is_numbered(name, "list-")
}

/// Whether `name` is a name `to_files` gives a pivot of the list of lists.
fn is_pivot_file(name: &str) -> bool {
    is_numbered(name, "pivot-")
}

impl Documents {
    /// The files to keep these documents in, as (name, content) pairs: the list of lists, each
    /// pivot as `pivot-N.xml`, each national list as `list-N.xml`, and last the file that says
    /// where each came from. Writing them in this order means a half-written set never names a
    /// list it lacks.
    #[must_use]
    pub fn to_files(&self) -> Vec<(String, String)> {
        let mut files = vec![(LOTL_FILE.to_string(), self.lotl.clone())];
        let mut index = String::new();
        let pivots = self.pivots.iter().enumerate().map(|(n, d)| (pivot_file_name(n), d));
        let lists = self.lists.iter().enumerate().map(|(n, d)| (list_file_name(n), d));
        for (name, (location, xml)) in pivots.chain(lists) {
            // An address has no tab or line break: the fetcher refuses those.
            index.push_str(&format!("{name}\t{}\n", location.replace(['\t', '\n', '\r'], "")));
            files.push((name, xml.clone()));
        }
        files.push((LOCATIONS_FILE.to_string(), index));
        files
    }

    /// The names of files a previous `to_files` may have left that the current set no longer
    /// uses: `list-N.xml` and `pivot-N.xml` for an N past the documents held.
    #[must_use]
    pub fn stale_files(&self, existing: &[String]) -> Vec<String> {
        let keep: std::collections::BTreeSet<String> =
            (0..self.lists.len()).map(list_file_name).chain((0..self.pivots.len()).map(pivot_file_name)).collect();
        existing.iter().filter(|n| (is_list_file(n) || is_pivot_file(n)) && !keep.contains(*n)).cloned().collect()
    }

    /// Read documents kept by [`Documents::to_files`], with `read` giving a file's text by name.
    /// `None` when there is no list of lists; a list or pivot whose file is missing is left out
    /// (a chain of pivots with one missing then fails to verify).
    pub fn from_files(read: impl Fn(&str) -> Option<String>) -> Option<Documents> {
        let lotl = read(LOTL_FILE)?;
        let mut lists = Vec::new();
        let mut pivots = Vec::new();
        for line in read(LOCATIONS_FILE).unwrap_or_default().lines().take(MAX_NATIONAL_LISTS.saturating_add(MAX_PIVOTS)) {
            let Some((name, location)) = line.split_once('\t') else { continue };
            let into = if is_list_file(name) {
                &mut lists
            } else if is_pivot_file(name) {
                &mut pivots
            } else {
                continue;
            };
            if let Some(xml) = read(name) {
                into.push((location.to_string(), xml));
            }
        }
        Some(Documents { lotl, lists, pivots })
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
    #[error("the list of lists is signed with a certificate that its pivots do not lead to from the ones given: {0}")]
    Pivots(String),
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

/// The pivots named in `uris` (the `SchemeInformationURI` entries, newest first), as the chains
/// a caller may have to follow, each oldest first.
///
/// A pivot is an entry whose path ends in `.xml`; anything else is a publication in the Official
/// Journal. The pivots above the first publication are the ones made since it: the chain for a
/// caller holding that publication's certificates. While the Commission moves from one
/// publication to the next both are listed, and a caller holding the older one's certificates
/// follows the pivots between the two and then the newer ones; and so on down the list.
fn pivot_chains(uris: &[String]) -> Vec<Vec<&str>> {
    let is_pivot = |u: &str| {
        let path = u.split(['?', '#']).next().unwrap_or(u);
        path.len() >= 4 && path.get(path.len().saturating_sub(4)..).is_some_and(|end| end.eq_ignore_ascii_case(".xml"))
    };
    // The runs of pivots between publications, newest run first, each newest first.
    let mut runs: Vec<Vec<&str>> = vec![Vec::new()];
    let mut total = 0usize;
    for u in uris {
        if !is_pivot(u) {
            runs.push(Vec::new());
        } else if total < MAX_PIVOTS
            && let Some(run) = runs.last_mut()
        {
            run.push(u.as_str());
            total = total.saturating_add(1);
        }
    }
    let mut chains: Vec<Vec<&str>> = Vec::new();
    let mut newer: Vec<&str> = Vec::new();
    for run in runs {
        if run.is_empty() {
            continue;
        }
        if chains.len() >= MAX_PIVOT_CHAINS {
            break;
        }
        // Oldest first: this run reversed, then everything newer.
        let mut chain: Vec<&str> = run.iter().rev().copied().collect();
        chain.extend(newer.iter().copied());
        newer = chain.clone();
        chains.push(chain);
    }
    chains
}

/// What became of looking a pivot up.
enum PivotText {
    Found(String),
    /// It could not be fetched: the chain may be good, there is just no saying now.
    Unreachable(String),
    /// It is not among the documents held, or not where a pivot may be fetched from.
    Refused(String),
}

/// The scheme and host of `url` (`https://host`), lower-cased.
fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!scheme.is_empty() && !host.is_empty()).then(|| format!("{}://{}", scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

/// The certificates the pivot `list` says sign the list of lists from then on: those of its
/// pointer to its own territory's list in XML.
fn next_signers(list: &TrustedList) -> Vec<Certificate> {
    let own = list.scheme.territory.as_str();
    list.pointers
        .iter()
        .filter(|p| p.mime_type.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(XML_MIME)))
        .filter(|p| p.territory.as_deref().is_some_and(|t| !own.is_empty() && t.eq_ignore_ascii_case(own)))
        .flat_map(|p| p.signers.iter().cloned())
        .collect()
}

/// Why a chain of pivots did not lead to the list of lists, and whether only because a pivot
/// could not be fetched.
type ChainBreak = (String, bool);

/// Follow one chain of pivots from `anchors` and verify the list of lists `xml` at its end.
/// Every pivot must be signed by a certificate of the set before it (valid when the pivot was
/// issued), name the next set, be for the same territory and have a higher sequence number than
/// the one before; the list of lists must then verify against the last set, today, and be no
/// older than the last pivot.
fn follow(
    xml: &str,
    anchors: &[Certificate],
    now: Time,
    chain: &[&str],
    pivot: &mut dyn FnMut(&str) -> PivotText,
) -> Result<(TrustedList, Vec<(String, String)>), ChainBreak> {
    let mut signers: Vec<Certificate> = anchors.to_vec();
    let mut last: Option<(u64, String)> = None;
    let mut used = Vec::new();
    for url in chain {
        let text = match pivot(url) {
            PivotText::Found(t) => t,
            PivotText::Unreachable(why) => return Err((format!("{url}: {why}"), true)),
            PivotText::Refused(why) => return Err((format!("{url}: {why}"), false)),
        };
        let list = TrustedList::parse_as_issued(&text, &signers).map_err(|e| (format!("{url}: {e}"), false))?;
        if let Some((sequence, territory)) = &last {
            if list.scheme.sequence_number <= *sequence {
                return Err((format!("{url}: sequence {} does not follow {sequence}", list.scheme.sequence_number), false));
            }
            if !list.scheme.territory.eq_ignore_ascii_case(territory) {
                return Err((format!("{url}: for {} and not for {territory}", list.scheme.territory), false));
            }
        }
        signers = next_signers(&list);
        if signers.is_empty() {
            return Err((format!("{url}: names no certificate for the list of lists"), false));
        }
        last = Some((list.scheme.sequence_number, list.scheme.territory.clone()));
        used.push(((*url).to_string(), text));
    }
    let lotl = TrustedList::parse(xml, &signers, now).map_err(|e| (e.to_string(), false))?;
    if let Some((sequence, territory)) = &last {
        if lotl.scheme.sequence_number < *sequence {
            return Err((format!("sequence {} is older than its pivot's {sequence}", lotl.scheme.sequence_number), false));
        }
        if !lotl.scheme.territory.eq_ignore_ascii_case(territory) {
            return Err((format!("for {} while its pivots are for {territory}", lotl.scheme.territory), false));
        }
    }
    Ok((lotl, used))
}

/// Verify the list of lists `xml`: against `anchors` directly, or, when it is signed with a
/// certificate that is not one of them, through the pivots it names. Returns the list and the
/// pivots that were needed, oldest first.
fn verify_lotl(
    xml: &str,
    anchors: &[Certificate],
    now: Time,
    pivot: &mut dyn FnMut(&str) -> PivotText,
) -> Result<(TrustedList, Vec<(String, String)>), RefreshError> {
    let direct = match TrustedList::parse(xml, anchors, now) {
        Ok(lotl) => return Ok((lotl, Vec::new())),
        Err(e) => e,
    };
    if direct != TrustedListError::Signature(XmlSignatureError::UntrustedSigner) {
        return Err(RefreshError::Refused(direct));
    }
    // What the unverified list says is only where to look: every pivot is verified in `follow`.
    let uris = unverified_information_uris(xml);
    let chains = pivot_chains(&uris);
    if chains.is_empty() {
        return Err(RefreshError::Refused(direct));
    }
    let mut first_why = None;
    let mut unreachable = None;
    for chain in &chains {
        match follow(xml, anchors, now, chain, pivot) {
            Ok(found) => return Ok(found),
            Err((why, true)) => {
                unreachable.get_or_insert(why);
            }
            Err((why, false)) => {
                first_why.get_or_insert(why);
            }
        }
    }
    // A pivot that could not be fetched may be the one that was needed: that is a failure to
    // fetch, and the lists already held stay in use.
    match (unreachable, first_why) {
        (Some(why), _) => Err(RefreshError::Fetch(why)),
        (None, why) => Err(RefreshError::Pivots(why.unwrap_or_default())),
    }
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
        let mut held_pivot = |url: &str| match documents.pivots.iter().find(|(loc, _)| loc == url) {
            Some((_, xml)) => PivotText::Found(xml.clone()),
            None => PivotText::Refused("not held".into()),
        };
        let (lotl, pivots) = verify_lotl(&documents.lotl, anchors, now, &mut held_pivot)?;
        if let Err(_why) = usable(&lotl, now) {
            return Err(RefreshError::Expired(lotl.scheme.next_update.unwrap_or(now)));
        }
        let mut lists = Vec::new();
        let mut reports = Vec::new();
        let mut kept = Documents { lotl: documents.lotl.clone(), lists: Vec::new(), pivots };
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
        // A pivot never changes once published: one already held is not fetched again (it is
        // verified again all the same), and one is fetched at most once however many chains
        // name it.
        let mut fetched: Vec<(String, Result<String, String>)> = Vec::new();
        let mut pivot = |url: &str| {
            // The unverified list of lists names these addresses: nothing is asked of a host
            // other than the one the list of lists itself came from.
            if origin(url).is_none() || origin(url) != origin(lotl_url) {
                return PivotText::Refused("not at the address of the list of lists".into());
            }
            if let Some((_, held)) = previous.and_then(|p| p.documents.pivots.iter().find(|(loc, _)| loc == url)) {
                return PivotText::Found(held.clone());
            }
            let known = fetched.iter().find(|(loc, _)| loc == url).map(|(_, r)| r.clone());
            let result = known.unwrap_or_else(|| {
                let r = fetcher.fetch(url, MAX_PIVOT_BYTES).map_err(|e| e.to_string());
                fetched.push((url.to_string(), r.clone()));
                r
            });
            match result {
                Ok(text) => PivotText::Found(text),
                Err(why) => PivotText::Unreachable(why),
            }
        };
        let (lotl, pivots) = verify_lotl(&xml, anchors, now, &mut pivot)?;
        if lotl.is_expired(now) {
            return Err(RefreshError::Expired(lotl.scheme.next_update.unwrap_or(now)));
        }
        if let Some(held) = previous.map(|p| p.lotl.scheme.sequence_number).filter(|h| lotl.scheme.sequence_number < *h) {
            return Err(RefreshError::Rollback { fetched: lotl.scheme.sequence_number, held });
        }
        let mut lists = Vec::new();
        let mut reports = Vec::new();
        let mut kept = Documents { lotl: xml, lists: Vec::new(), pivots };
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

    /// This snapshot used again because the lists could not be fetched: every list it still
    /// holds is reported as kept, with `why`.
    #[must_use]
    pub fn kept_offline(mut self, why: &str) -> Snapshot {
        for r in &mut self.reports {
            if r.outcome == Outcome::Unchanged {
                r.outcome = Outcome::KeptPrevious(format!("the list of lists could not be fetched ({why})"));
            }
        }
        self
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn chains(uris: &[&str]) -> Vec<Vec<String>> {
        let owned: Vec<String> = uris.iter().map(|u| (*u).to_string()).collect();
        pivot_chains(&owned).into_iter().map(|c| c.into_iter().map(str::to_string).collect()).collect()
    }

    #[test]
    fn pivots_are_grouped_by_the_publication_they_follow_oldest_first() {
        // No pivots: nothing to follow.
        assert!(chains(&[]).is_empty());
        assert!(chains(&["https://eur-lex.europa.eu/oj-1"]).is_empty());
        // The pivots since the one publication, newest listed first.
        assert_eq!(
            chains(&["h://x/p3.xml", "h://x/p2.XML", "h://x/p1.xml?v=1#f", "https://eur-lex.europa.eu/oj-1"]),
            [["h://x/p1.xml?v=1#f", "h://x/p2.XML", "h://x/p3.xml"]]
        );
        // Two publications: the newer one's holders follow p4; the older one's p1, p2, then p4.
        assert_eq!(
            chains(&["h://x/p4.xml", "oj-2", "h://x/p2.xml", "h://x/p1.xml", "oj-1"]),
            [vec!["h://x/p4.xml"], vec!["h://x/p1.xml", "h://x/p2.xml", "h://x/p4.xml"]]
        );
        // A publication with no pivot since: its holders verify directly, the older one's follow theirs.
        assert_eq!(chains(&["oj-2", "h://x/p2.xml", "h://x/p1.xml", "oj-1"]), [["h://x/p1.xml", "h://x/p2.xml"]]);
        // Pivots listed under the oldest publication still make a chain (no publication is known for them).
        assert_eq!(chains(&["h://x/p2.xml", "oj-1", "h://x/p1.xml"]), [vec!["h://x/p2.xml"], vec!["h://x/p1.xml", "h://x/p2.xml"]]);
        // What only looks like a pivot.
        assert!(chains(&["xml", ".xm", "h://x/p.xml.html", "h://x/?u=p.xml"]).is_empty());
    }

    #[test]
    fn a_list_cannot_make_the_reader_follow_pivots_without_end() {
        let many: Vec<String> = (0..500).map(|n| format!("h://x/p{n}.xml")).collect();
        let found = pivot_chains(&many);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].len(), MAX_PIVOTS);
        // Alternating pivots and publications: no more chains than are tried.
        let alternating: Vec<String> = (0..500).map(|n| if n % 2 == 0 { format!("h://x/p{n}.xml") } else { format!("oj-{n}") }).collect();
        let found = pivot_chains(&alternating);
        assert_eq!(found.len(), MAX_PIVOT_CHAINS);
        assert!(found.iter().all(|c| c.len() <= MAX_PIVOTS));
    }

    #[test]
    fn an_origin_is_the_scheme_and_host() {
        assert_eq!(origin("https://EC.europa.eu/tools/lotl/eu-lotl.xml").as_deref(), Some("https://ec.europa.eu"));
        assert_eq!(origin("HTTPS://ec.europa.eu?x").as_deref(), Some("https://ec.europa.eu"));
        assert_ne!(origin("http://ec.europa.eu/a"), origin("https://ec.europa.eu/a"));
        assert_ne!(origin("https://ec.europa.eu.example/a"), origin("https://ec.europa.eu/a"));
        assert_ne!(origin("https://ec.europa.eu:8443/a"), origin("https://ec.europa.eu/a"));
        for bad in ["", "ec.europa.eu/a", "://host/a", "https:///a", "https://"] {
            assert_eq!(origin(bad), None, "{bad:?}");
        }
    }
}
