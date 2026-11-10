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
fn a_snapshot_used_offline_says_its_lists_were_kept_and_why() {
    let s = Snapshot::load(&good().documents, &anchors(), now()).unwrap().kept_offline("no route");
    match outcome(&s, "IT") {
        Outcome::KeptPrevious(why) => assert!(why.contains("no route"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(outcome(&s, "DE"), Outcome::KeptPrevious(_)));
    // A list that was not usable stays what it was.
    let mut docs = good().documents;
    docs.lists.retain(|(loc, _)| loc != DE);
    let s = Snapshot::load(&docs, &anchors(), now()).unwrap().kept_offline("x");
    assert_eq!(*outcome(&s, "DE"), Outcome::Unusable("not held".into()));
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

#[test]
fn the_snapshot_hands_validation_its_anchors_with_the_times_they_were_granted() {
    let anchors = good().anchors();
    let find = |name: &str| anchors.iter().filter(|a| a.service == name).collect::<Vec<_>>();
    // Qualified CA One: granted since 2016 and still.
    let one = find("Qualified CA One");
    assert_eq!(one.len(), 1);
    assert_eq!((one[0].territory.as_str(), one[0].provider.as_str()), ("IT", "Test Qualified Provider"));
    assert!(one[0].granted_at(t(2016, 7, 2)) && one[0].granted_at(now()) && !one[0].granted_at(t(2016, 6, 30)));
    // Qualified CA Two: granted until it was withdrawn on 2022-03-01 09:00 UTC.
    let two = find("Qualified CA Two");
    assert_eq!(two.len(), 1);
    assert!(two[0].granted_at(t(2020, 1, 1)) && !two[0].granted_at(t(2022, 3, 2)) && !two[0].granted_at(now()));
    // Not certification authorities for qualified certificates, or not granted ever, or unreadable.
    for none in ["Qualified TSA", "Non-qualified CA", "Broken"] {
        assert!(find(none).is_empty(), "{none}");
    }
    // The ceased service was granted before it ceased.
    let old = find("Old CA");
    assert!(old.len() == 1 && old[0].granted_at(t(2018, 1, 1)) && !old[0].granted_at(now()));
}

#[test]
fn documents_round_trip_through_files_and_a_damaged_set_is_read_as_far_as_it_goes() {
    let docs = good().documents;
    let files = docs.to_files();
    // The index comes last, and only names that are our own are ever written.
    assert_eq!(files.last().unwrap().0, "locations.txt");
    assert!(files.iter().all(|(n, _)| n == "lotl.xml" || n == "locations.txt" || (n.starts_with("list-") && n.ends_with(".xml"))));
    let by_name: HashMap<String, String> = files.iter().cloned().collect();
    let back = Documents::from_files(|n| by_name.get(n).cloned()).unwrap();
    assert_eq!(back, docs);
    // It still loads and verifies.
    assert_eq!(Snapshot::load(&back, &anchors(), now()).unwrap().lists.len(), 2);
    // No list of lists, no documents; a missing national list or index leaves the rest.
    assert!(Documents::from_files(|_| None).is_none());
    let without = Documents::from_files(|n| if n == "list-0.xml" { None } else { by_name.get(n).cloned() }).unwrap();
    assert_eq!(without.lists.len(), docs.lists.len() - 1);
    assert!(Documents::from_files(|n| if n == "locations.txt" { None } else { by_name.get(n).cloned() }).unwrap().lists.is_empty());
    // An index that names other files is not followed to them.
    let evil = "../../etc/passwd\thttps://x.invalid/a.xml\nlist-0.xml\thttps://example.invalid/tl-it.xml\nlist-99999.xml\thttps://x.invalid/b.xml\n";
    let asked = RefCell::new(Vec::new());
    let read = |n: &str| {
        asked.borrow_mut().push(n.to_string());
        if n == "locations.txt" { Some(evil.to_string()) } else { by_name.get(n).cloned() }
    };
    let got = Documents::from_files(read).unwrap();
    assert_eq!(got.lists.len(), 1);
    assert_eq!(*asked.borrow(), ["lotl.xml", "locations.txt", "list-0.xml"]);
    // Files a smaller set no longer uses.
    let one = Documents { lotl: docs.lotl.clone(), lists: docs.lists[..1].to_vec(), pivots: Vec::new() };
    let names: Vec<String> = ["lotl.xml", "list-0.xml", "list-1.xml", "list-7.xml", "notes.txt", "list-x.xml"].map(String::from).to_vec();
    assert_eq!(one.stale_files(&names), ["list-1.xml", "list-7.xml"]);
}

// ---- Pivots: the list of lists signed with certificates newer than the ones the caller has ----

const P300: &str = "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-300.xml";
const P320: &str = "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-320.xml";
const P380: &str = "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-380.xml";

/// The chain of the fixtures: `a` was published in the Official Journal; pivot 300 (signed by
/// `a`) names `a` and `b`; pivot 320 (signed by `b`) names `c`, which signs `lotl-pivoted.xml`.
/// Later `c` is published too, pivot 380 (signed by `c`) names `d`, which signs
/// `lotl-transition.xml`.
fn pivoted(lotl: &'static str, p320: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![(LOTL_URL, lotl), (P300, "pivot-300.xml"), (P320, p320), (P380, "pivot-380.xml"), (IT, "tl-it.xml"), (DE, "tl-de.xml")]
}
fn through(files: &[(&str, &str)], anchor: &str) -> (Result<Snapshot, RefreshError>, Vec<String>) {
    let server = Server::with(files);
    let s = Snapshot::refresh(&server, LOTL_URL, &[cert(anchor)], now(), None);
    (s, server.asked.into_inner())
}
fn pivot_addresses(s: &Snapshot) -> Vec<&str> {
    s.documents.pivots.iter().map(|(loc, _)| loc.as_str()).collect()
}

#[test]
fn a_list_signed_with_newer_certificates_is_reached_through_its_pivots() {
    let files = pivoted("lotl-pivoted.xml", "pivot-320.xml");
    // `a` expired in 2022: it is judged when each pivot was issued, and the list itself today.
    let (s, asked) = through(&files, "tsl-pivot-a.der");
    let s = s.unwrap();
    assert_eq!(asked, [LOTL_URL, P300, P320, IT, DE], "oldest pivot first, none twice, nothing else");
    assert_eq!(pivot_addresses(&s), [P300, P320]);
    assert_eq!(s.lotl.signer.raw, cert("tsl-pivot-c.der").raw);
    assert_eq!(s.lotl.scheme.sequence_number, 371);
    assert_eq!(roots(&s, now()), ["DE:DE one CA", "IT:Qualified CA One", "IT:Qualified CA Three"]);
    // Whoever already has today's certificate needs no pivot and asks for none.
    let (s, asked) = through(&files, "tsl-pivot-c.der");
    assert_eq!(asked, [LOTL_URL, IT, DE]);
    assert!(s.unwrap().documents.pivots.is_empty());
}

#[test]
fn every_link_of_the_chain_must_hold() {
    let refused = |files: &[(&str, &str)], anchor: &str, say: &str| match through(files, anchor).0 {
        Err(RefreshError::Pivots(why)) => assert!(why.contains(say), "{why:?} does not say {say:?}"),
        other => panic!("{say}: {:?}", other.map(|s| s.lotl.scheme.sequence_number)),
    };
    // A pivot signed by someone the chain does not name.
    refused(&pivoted("lotl-pivoted.xml", "pivot-320-stranger.xml"), "tsl-pivot-a.der", "not made by a certificate that is trusted");
    // A pivot issued after its signer's certificate had expired.
    refused(&pivoted("lotl-pivoted.xml", "pivot-320-late.xml"), "tsl-pivot-a.der", "not valid at this time");
    // A pivot that names no certificate for what comes next.
    refused(&pivoted("lotl-pivoted.xml", "pivot-320-nosigners.xml"), "tsl-pivot-a.der", "names no certificate");
    // A pivot older than the one before it, and one for another territory.
    refused(&pivoted("lotl-pivoted.xml", "pivot-320-sequence.xml"), "tsl-pivot-a.der", "does not follow 300");
    refused(&pivoted("lotl-pivoted.xml", "pivot-320-it.xml"), "tsl-pivot-a.der", "for IT and not for EU");
    // A list of lists older than its own last pivot.
    refused(&pivoted("lotl-pivoted-low.xml", "pivot-320.xml"), "tsl-pivot-a.der", "older than its pivot's 320");
    // A chain is followed from its start: `b` is named by pivot 300, but who holds only `b`
    // cannot verify pivot 300 and does not get to skip it.
    refused(&pivoted("lotl-pivoted.xml", "pivot-320.xml"), "tsl-pivot-b.der", P300);
    refused(&pivoted("lotl-pivoted.xml", "pivot-320.xml"), "tsl-pivot-stranger.der", P300);
    // The same pivot served at both addresses is not a chain.
    refused(&[(LOTL_URL, "lotl-pivoted.xml"), (P300, "pivot-300.xml"), (P320, "pivot-300.xml")], "tsl-pivot-a.der", "does not follow 300");
    // A list of lists that was changed is refused for that, whatever pivots it names.
    let mut server = Server::with(&pivoted("lotl-pivoted.xml", "pivot-320.xml"));
    let changed = text("lotl-pivoted.xml").replace("<TSLSequenceNumber>371<", "<TSLSequenceNumber>999<");
    server.files.insert(LOTL_URL.to_string(), changed);
    assert_eq!(
        Snapshot::refresh(&server, LOTL_URL, &[cert("tsl-pivot-a.der")], now(), None).unwrap_err(),
        RefreshError::Refused(TrustedListError::Signature(XmlSignatureError::DigestMismatch))
    );
    assert_eq!(*server.asked.borrow(), [LOTL_URL], "and no pivot is asked for");
    // Without pivots the refusal is the plain one.
    assert_eq!(
        through(&[(LOTL_URL, "lotl.xml")], "tsl-pivot-a.der").0.unwrap_err(),
        RefreshError::Refused(TrustedListError::Signature(XmlSignatureError::UntrustedSigner))
    );
}

#[test]
fn a_pivot_that_cannot_be_fetched_is_a_failure_to_fetch_and_only_the_lists_host_is_asked() {
    // Unreachable: the caller keeps what it holds, as when the list of lists is unreachable.
    let (s, asked) = through(&[(LOTL_URL, "lotl-pivoted.xml"), (P300, "pivot-300.xml")], "tsl-pivot-a.der");
    assert!(matches!(s, Err(RefreshError::Fetch(ref why)) if why.contains(P320)), "{:?}", s.err());
    assert_eq!(asked, [LOTL_URL, P300, P320]);
    // A pivot named at another host is not asked for at all.
    let elsewhere = "https://example.invalid/eu-lotl-pivot-320.xml";
    let files = [(LOTL_URL, "lotl-pivoted-elsewhere.xml"), (P300, "pivot-300.xml"), (elsewhere, "pivot-320.xml")];
    let (s, asked) = through(&files, "tsl-pivot-a.der");
    assert!(matches!(s, Err(RefreshError::Pivots(ref why)) if why.contains("not at the address")), "{:?}", s.err());
    assert_eq!(asked, [LOTL_URL, P300]);
}

#[test]
fn while_two_publications_are_listed_each_ones_holders_follow_their_own_pivots() {
    let files = pivoted("lotl-transition.xml", "pivot-320.xml");
    // The newer publication's certificate: only the pivot made since.
    let (s, asked) = through(&files, "tsl-pivot-c.der");
    let s = s.unwrap();
    assert_eq!(asked, [LOTL_URL, P380, IT, DE]);
    assert_eq!(pivot_addresses(&s), [P380]);
    assert_eq!(s.lotl.signer.raw, cert("tsl-pivot-d.der").raw);
    // The older publication's: the pivots between the two, then the newer ones.
    let (s, asked) = through(&files, "tsl-pivot-a.der");
    let s = s.unwrap();
    assert_eq!(asked, [LOTL_URL, P380, P300, P320, IT, DE], "pivot 380 is tried first and fetched once");
    assert_eq!(pivot_addresses(&s), [P300, P320, P380]);
    assert_eq!(s.lotl.signer.raw, cert("tsl-pivot-d.der").raw);
    // A certificate from the middle of a chain starts nothing.
    assert!(matches!(through(&files, "tsl-pivot-b.der").0, Err(RefreshError::Pivots(_))));
}

#[test]
fn the_pivots_are_kept_verified_again_and_not_fetched_twice() {
    let files = pivoted("lotl-pivoted.xml", "pivot-320.xml");
    let a = [cert("tsl-pivot-a.der")];
    let s = through(&files, "tsl-pivot-a.der").0.unwrap();
    // On disk: one file per pivot, named in the file that says where each came from.
    let kept: HashMap<String, String> = s.documents.to_files().into_iter().collect();
    assert!(kept.contains_key("pivot-0.xml") && kept.contains_key("pivot-1.xml") && !kept.contains_key("pivot-2.xml"));
    assert!(kept["locations.txt"].contains(&format!("pivot-0.xml\t{P300}\n")) && kept["locations.txt"].contains(&format!("pivot-1.xml\t{P320}\n")));
    let back = Documents::from_files(|n| kept.get(n).cloned()).unwrap();
    assert_eq!(back, s.documents);
    let names = ["pivot-0.xml", "pivot-1.xml", "pivot-2.xml", "pivot-x.xml", "list-0.xml"].map(String::from);
    assert_eq!(s.documents.stale_files(&names), ["pivot-2.xml"]);
    // Loaded again with no network: the same chain, from the same certificate.
    let loaded = Snapshot::load(&back, &a, now()).unwrap();
    assert_eq!(pivot_addresses(&loaded), [P300, P320]);
    assert_eq!(loaded.anchors().len(), s.anchors().len());
    // A pivot missing or changed on disk breaks the chain, and nothing is believed.
    let mut missing = back.clone();
    missing.pivots.remove(0);
    assert!(matches!(Snapshot::load(&missing, &a, now()), Err(RefreshError::Pivots(ref why)) if why.contains("not held")));
    let mut changed = back.clone();
    changed.pivots[1].1 = changed.pivots[1].1.replace("<TSLSequenceNumber>320<", "<TSLSequenceNumber>321<");
    assert!(matches!(Snapshot::load(&changed, &a, now()), Err(RefreshError::Pivots(_))));
    let mut swapped = back.clone();
    swapped.pivots[1].1 = text("pivot-320-stranger.xml");
    assert!(matches!(Snapshot::load(&swapped, &a, now()), Err(RefreshError::Pivots(_))));
    // The next refresh has the pivots already: it asks for the lists only.
    let server = Server::with(&files);
    let again = Snapshot::refresh(&server, LOTL_URL, &a, now(), Some(&loaded)).unwrap();
    assert_eq!(*server.asked.borrow(), [LOTL_URL, IT, DE]);
    assert_eq!(pivot_addresses(&again), [P300, P320]);
    assert_eq!(*outcome(&again, "IT"), Outcome::Unchanged);
}
