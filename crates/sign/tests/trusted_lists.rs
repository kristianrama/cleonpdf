//! Keeping the Trusted Lists up to date: what is believed, kept and refused on a refresh.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::cell::RefCell;
use std::collections::HashMap;

use cleonpdf_sign::tl::TrustedListError;
use cleonpdf_sign::trusted_lists::{Documents, LOTL_URL, ListFetcher, Outcome, RefreshError, Snapshot};
use cleonpdf_sign::xmldsig::XmlSignatureError;
use cleonpdf_sign::{Certificate, SignError, Time};

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/xml/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}
fn text(name: &str) -> String {
    String::from_utf8(data(name)).unwrap()
}
fn cert(name: &str) -> Certificate {
    Certificate::parse(&data(name)).unwrap()
}
fn t(year: u32, month: u32, day: u32) -> Time {
    Time { year, month, day, hour: 12, minute: 0, second: 0 }
}
fn now() -> Time {
    t(2026, 11, 20)
}
fn anchors() -> Vec<Certificate> {
    vec![cert("tsl-signer-eu.der")]
}

const IT: &str = "https://example.invalid/tl-it.xml";
const DE: &str = "https://example.invalid/tl-de.xml";

/// A server holding the files named, and a record of what was asked of it.
#[derive(Default)]
struct Server {
    files: HashMap<String, String>,
    asked: RefCell<Vec<String>>,
}
impl Server {
    fn with(files: &[(&str, &str)]) -> Server {
        Server { files: files.iter().map(|(u, f)| ((*u).to_string(), text(f))).collect(), asked: RefCell::default() }
    }
}
impl ListFetcher for Server {
    fn fetch(&self, url: &str, _max: u64) -> Result<String, SignError> {
        self.asked.borrow_mut().push(url.to_string());
        self.files.get(url).cloned().ok_or_else(|| SignError::Transport(format!("{url}: could not be reached")))
    }
}

fn refresh(files: &[(&str, &str)], previous: Option<&Snapshot>, at: Time) -> Result<Snapshot, RefreshError> {
    Snapshot::refresh(&Server::with(files), LOTL_URL, &anchors(), at, previous)
}
fn good() -> Snapshot {
    refresh(&[(LOTL_URL, "lotl.xml"), (IT, "tl-it.xml"), (DE, "tl-de.xml")], None, now()).unwrap()
}
fn outcome<'a>(s: &'a Snapshot, territory: &str) -> &'a Outcome {
    &s.reports.iter().find(|r| r.territory == territory).unwrap_or_else(|| panic!("no report for {territory}")).outcome
}
fn roots(s: &Snapshot, at: Time) -> Vec<String> {
    let mut v: Vec<String> = s.qualified_roots_at(at).iter().map(|(c, r)| format!("{c}:{}", r.service.name)).collect();
    v.sort();
    v
}

#[test]
fn a_refresh_fetches_the_list_of_lists_then_each_xml_list_it_points_to() {
    let server = Server::with(&[(LOTL_URL, "lotl.xml"), (IT, "tl-it.xml"), (DE, "tl-de.xml")]);
    let s = Snapshot::refresh(&server, LOTL_URL, &anchors(), now(), None).unwrap();
    // The PDF rendering is not a list, and nothing else is asked for.
    assert_eq!(*server.asked.borrow(), [LOTL_URL, IT, DE]);
    assert_eq!(s.lists.len(), 2);
    assert_eq!(*outcome(&s, "IT"), Outcome::Updated);
    assert_eq!(*outcome(&s, "DE"), Outcome::Updated);
    assert_eq!(roots(&s, now()), ["DE:DE one CA", "IT:Qualified CA One", "IT:Qualified CA Three"]);
    assert!(s.unusable().is_empty());
}

#[test]
fn what_is_kept_is_verified_again_when_it_is_loaded() {
    let s = good();
    let again = Snapshot::load(&s.documents, &anchors(), now()).unwrap();
    assert_eq!(roots(&again, now()), roots(&s, now()));
    assert_eq!(*outcome(&again, "IT"), Outcome::Unchanged);
    // A copy that was changed on disk is not believed; the others still are.
    let mut docs: Documents = s.documents.clone();
    for (loc, xml) in &mut docs.lists {
        if loc == IT {
            *xml = xml.replace("Svcstatus/withdrawn", "Svcstatus/granted");
        }
    }
    let loaded = Snapshot::load(&docs, &anchors(), now()).unwrap();
    assert!(matches!(outcome(&loaded, "IT"), Outcome::Unusable(_)));
    assert_eq!(*outcome(&loaded, "DE"), Outcome::Unchanged);
    assert_eq!(loaded.lists.len(), 1);
    // A list that is missing from what was kept.
    docs.lists.retain(|(loc, _)| loc != DE);
    assert_eq!(*outcome(&Snapshot::load(&docs, &anchors(), now()).unwrap(), "DE"), Outcome::Unusable("not held".into()));
    // The list of lists must be good: changed, or signed by someone else, or out of date.
    let mut bad = s.documents.clone();
    bad.lotl = bad.lotl.replace("example.invalid/tl-it", "example.invalid/evil");
    assert!(matches!(
        Snapshot::load(&bad, &anchors(), now()),
        Err(RefreshError::Refused(TrustedListError::Signature(XmlSignatureError::DigestMismatch)))
    ));
    assert!(matches!(Snapshot::load(&s.documents, &[cert("tsl-signer-it.der")], now()), Err(RefreshError::Refused(_))));
    assert!(matches!(Snapshot::load(&s.documents, &anchors(), t(2027, 5, 1)), Err(RefreshError::Expired(_))));
    assert_eq!(Snapshot::load(&s.documents, &[], now()).unwrap_err(), RefreshError::NoAnchors);
}

#[test]
fn nothing_is_believed_without_the_anchors_the_caller_names() {
    let files = [(LOTL_URL, "lotl.xml"), (IT, "tl-it.xml")];
    assert_eq!(Snapshot::refresh(&Server::with(&files), LOTL_URL, &[], now(), None).unwrap_err(), RefreshError::NoAnchors);
    let other = [cert("tsl-signer-it.der")];
    let err = Snapshot::refresh(&Server::with(&files), LOTL_URL, &other, now(), None).unwrap_err();
    assert!(matches!(err, RefreshError::Refused(TrustedListError::Signature(XmlSignatureError::UntrustedSigner))), "{err:?}");
    // A list of lists that cannot be fetched is an error and no snapshot.
    assert!(matches!(refresh(&[], None, now()), Err(RefreshError::Fetch(_))));
}

#[test]
fn one_list_failing_does_not_stop_the_others_and_a_good_copy_is_kept() {
    // No Germany this time.
    let s = refresh(&[(LOTL_URL, "lotl.xml"), (IT, "tl-it.xml")], None, now()).unwrap();
    assert_eq!(*outcome(&s, "IT"), Outcome::Updated);
    assert!(matches!(outcome(&s, "DE"), Outcome::Unusable(why) if why.contains("could not be reached")));
    assert_eq!(s.lists.len(), 1);
    // With a previous snapshot, Germany's copy is used and says why.
    let prev = good();
    let s = refresh(&[(LOTL_URL, "lotl.xml"), (IT, "tl-it.xml")], Some(&prev), now()).unwrap();
    assert!(matches!(outcome(&s, "DE"), Outcome::KeptPrevious(why) if why.contains("could not be reached")));
    assert_eq!(*outcome(&s, "IT"), Outcome::Unchanged);
    assert_eq!(roots(&s, now()), roots(&prev, now()));
    assert_eq!(s.documents.lists.len(), 2);
    // A copy that has expired meanwhile is not kept.
    let s = refresh(&[(LOTL_URL, "lotl-372.xml")], Some(&prev), t(2027, 4, 10)).unwrap();
    assert!(matches!(outcome(&s, "DE"), Outcome::Unusable(_)) && matches!(outcome(&s, "IT"), Outcome::Unusable(_)));
    assert!(s.lists.is_empty());
}

#[test]
fn an_older_list_never_replaces_a_newer_one() {
    let prev = good();
    // The list of lists.
    let err = refresh(&[(LOTL_URL, "lotl-370.xml"), (IT, "tl-it.xml")], Some(&prev), now()).unwrap_err();
    assert_eq!(err, RefreshError::Rollback { fetched: 370, held: 371 });
    assert!(refresh(&[(LOTL_URL, "lotl-372.xml"), (IT, "tl-it.xml"), (DE, "tl-de.xml")], Some(&prev), now()).is_ok());
    // A national list: 28 is held, 27 is offered.
    let newer = refresh(&[(LOTL_URL, "lotl.xml"), (IT, "tl-it-28.xml")], Some(&prev), now()).unwrap();
    assert_eq!(*outcome(&newer, "IT"), Outcome::Updated);
    assert_eq!(roots(&newer, now()).iter().filter(|r| r.starts_with("IT:")).collect::<Vec<_>>(), ["IT:IT newer CA"]);
    let back = refresh(&[(LOTL_URL, "lotl.xml"), (IT, "tl-it.xml")], Some(&newer), now()).unwrap();
    assert!(matches!(outcome(&back, "IT"), Outcome::KeptPrevious(why) if why.contains("older")), "{:?}", back.reports);
    assert_eq!(roots(&back, now()).iter().filter(|r| r.starts_with("IT:")).collect::<Vec<_>>(), ["IT:IT newer CA"]);
    // Without a snapshot there is nothing to roll back from.
    assert!(refresh(&[(LOTL_URL, "lotl-370.xml"), (IT, "tl-it-26.xml")], None, now()).is_ok());
}

#[test]
fn lists_past_their_next_update_are_not_used() {
    let err = refresh(&[(LOTL_URL, "lotl-expired.xml")], None, now()).unwrap_err();
    assert!(matches!(err, RefreshError::Expired(_)), "{err:?}");
    let s = refresh(&[(LOTL_URL, "lotl.xml"), (IT, "tl-it-expired.xml"), (DE, "tl-de.xml")], None, now()).unwrap();
    assert!(matches!(outcome(&s, "IT"), Outcome::Unusable(why) if why.contains("out of date")));
    assert_eq!(*outcome(&s, "DE"), Outcome::Updated);
    // A good copy held is used rather than the stale list.
    let s = refresh(&[(LOTL_URL, "lotl.xml"), (IT, "tl-it-expired.xml"), (DE, "tl-de.xml")], Some(&good()), now()).unwrap();
    assert!(matches!(outcome(&s, "IT"), Outcome::KeptPrevious(why) if why.contains("out of date")));
}

#[test]
fn a_national_list_must_be_signed_by_its_own_signer_and_be_for_its_own_territory() {
    // Signed with a certificate the list of lists names for Italy, not for Germany.
    let s = refresh(&[(LOTL_URL, "lotl.xml"), (DE, "tl-de-wrong-signer.xml")], None, now()).unwrap();
    assert!(matches!(outcome(&s, "DE"), Outcome::Unusable(why) if why.contains("not")), "{:?}", s.reports);
    // Validly signed by Germany's signer, but a list for France.
    let s = refresh(&[(LOTL_URL, "lotl.xml"), (DE, "tl-de-wrong-territory.xml")], None, now()).unwrap();
    assert!(matches!(outcome(&s, "DE"), Outcome::Unusable(why) if why.contains("for FR")), "{:?}", s.reports);
    assert!(s.lists.is_empty());
}

#[test]
fn a_territory_has_one_list_and_the_list_of_lists_is_not_followed_again() {
    let server =
        Server::with(&[(LOTL_URL, "lotl-twice.xml"), (IT, "tl-it.xml"), ("https://example.invalid/tl-it-b.xml", "tl-it-28.xml"), (DE, "tl-de.xml")]);
    let s = Snapshot::refresh(&server, LOTL_URL, &anchors(), now(), None).unwrap();
    let it: Vec<_> = s.reports.iter().filter(|r| r.territory == "IT").collect();
    assert_eq!((it.len(), &it[0].outcome), (2, &Outcome::Updated));
    assert!(matches!(&it[1].outcome, Outcome::Unusable(why) if why.contains("twice")));
    assert!(!server.asked.borrow().contains(&"https://example.invalid/tl-it-b.xml".to_string()));
    // A pointer for the list of lists' own territory is skipped, and so is one with no signer.
    let server = Server::with(&[(LOTL_URL, "lotl-self.xml"), (IT, "tl-it.xml")]);
    let s = Snapshot::refresh(&server, LOTL_URL, &anchors(), now(), None).unwrap();
    assert_eq!(*server.asked.borrow(), [LOTL_URL, IT]);
    assert_eq!(s.reports.len(), 1);
}
