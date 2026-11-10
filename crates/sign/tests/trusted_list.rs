//! Trusted Lists (ETSI TS 119 612): signed lists in, qualified trust anchors out.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use cleonpdf_sign::tl::{TrustedList, TrustedListError};
use cleonpdf_sign::xmldsig::XmlSignatureError;
use cleonpdf_sign::{Certificate, Time};

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/xml/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}
fn text(name: &str) -> String {
    String::from_utf8(data(name)).unwrap()
}
fn cert(name: &str) -> Certificate {
    Certificate::parse(&data(name)).unwrap()
}
fn t(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Time {
    Time { year, month, day, hour, minute, second }
}
fn now() -> Time {
    t(2026, 11, 20, 12, 0, 0)
}
fn lotl() -> TrustedList {
    TrustedList::parse(&text("lotl.xml"), &[cert("tsl-signer-eu.der")], now()).unwrap()
}
fn national() -> TrustedList {
    TrustedList::parse(&text("tl-it.xml"), &[cert("tsl-signer-it.der")], now()).unwrap()
}
fn names(l: &TrustedList, at: Time) -> Vec<String> {
    let mut v: Vec<String> = l.qualified_roots_at(at).iter().map(|r| r.service.name.clone()).collect();
    v.sort();
    v
}

#[test]
fn the_list_of_lists_says_who_signs_each_national_list() {
    let l = lotl();
    assert_eq!(l.scheme.territory, "EU");
    assert_eq!(l.scheme.sequence_number, 371);
    assert_eq!(l.scheme.version, 5);
    assert_eq!(l.scheme.operator, "Test European Commission");
    assert!(l.scheme.list_type.ends_with("/EUlistofthelists"));
    assert_eq!(l.scheme.issued, Some(t(2026, 10, 15, 0, 0, 0)));
    assert_eq!(l.scheme.next_update, Some(t(2027, 4, 15, 0, 0, 0)));
    assert_eq!(l.signer.raw, cert("tsl-signer-eu.der").raw);
    assert_eq!(l.pointers.len(), 3);
    let it = &l.pointers[0];
    assert_eq!((it.territory.as_deref(), it.mime_type.as_deref()), (Some("IT"), Some("application/vnd.etsi.tsl+xml")));
    assert_eq!(it.location, "https://example.invalid/tl-it.xml");
    assert_eq!(it.signers.iter().map(|c| c.raw.clone()).collect::<Vec<_>>(), vec![cert("tsl-signer-it.der").raw]);
    assert_eq!(l.pointers[1].signers.len(), 2);
    assert_eq!(l.pointers[2].mime_type.as_deref(), Some("application/pdf"));
    assert!(l.pointers[2].signers.is_empty());
    assert!(l.providers.is_empty());
}

#[test]
fn a_national_list_is_trusted_through_the_signers_the_list_of_lists_names() {
    let signers = lotl().pointers.remove(0).signers;
    let l = TrustedList::parse(&text("tl-it.xml"), &signers, now()).unwrap();
    assert_eq!((l.scheme.territory.as_str(), l.scheme.sequence_number), ("IT", 27));
    assert_eq!(l.providers.len(), 2);
    // The English name is preferred.
    assert_eq!(l.providers[0].name, "Test Qualified Provider");
    assert_eq!(l.providers[0].services.len(), 5);
    // A certificate that is not a certificate counts as such; a subject name alone anchors nothing.
    assert_eq!(l.unreadable_certificates, 1);
    // The same list without the XAdES properties.
    assert!(TrustedList::parse(&text("tl-it-plain.xml"), &signers, now()).is_ok());
}

#[test]
fn qualified_roots_follow_each_services_status_through_time() {
    let l = national();
    // Now: two granted qualified CAs. The withdrawn one, the ceased one, the time stamping
    // service and the non-qualified CA are not qualified roots, nor is the one with no certificate.
    assert_eq!(names(&l, now()), ["Qualified CA One", "Qualified CA Three"]);
    let roots = l.qualified_roots_at(now());
    assert_eq!(roots[0].certificate.raw, cert("qca1.der").raw);
    assert_eq!(roots[0].provider.name, "Test Qualified Provider");
    // Before the third existed, while the second was granted and the old one not yet ceased.
    assert_eq!(names(&l, t(2018, 6, 1, 0, 0, 0)), ["Old CA", "Qualified CA One", "Qualified CA Two"]);
    assert_eq!(names(&l, t(2020, 6, 1, 0, 0, 0)), ["Qualified CA One", "Qualified CA Two"]);
    assert!(names(&l, t(2016, 6, 30, 23, 59, 59)).is_empty());
    // The second was withdrawn at 2022-03-01 10:00 +01:00, which is 09:00 UTC.
    assert!(names(&l, t(2022, 3, 1, 8, 59, 59)).contains(&"Qualified CA Two".to_string()));
    assert!(!names(&l, t(2022, 3, 1, 9, 0, 0)).contains(&"Qualified CA Two".to_string()));
    // Services that are not certification authorities for qualified certificates carry no weight.
    let all: Vec<_> = l.providers.iter().flat_map(|p| &p.services).map(|s| s.name.as_str()).collect();
    assert!(all.contains(&"Qualified TSA") && all.contains(&"Non-qualified CA"));
}

#[test]
fn a_list_knows_when_it_runs_out() {
    let l = national();
    assert!(!l.is_expired(t(2027, 4, 1, 8, 0, 0)));
    assert!(l.is_expired(t(2027, 4, 1, 8, 0, 1)));
    assert!(!lotl().is_expired(now()));
}

fn signature_error(r: Result<TrustedList, TrustedListError>) -> XmlSignatureError {
    match r {
        Err(TrustedListError::Signature(e)) => e,
        other => panic!("expected a signature error, got {other:?}"),
    }
}

#[test]
fn only_the_signers_the_caller_names_are_believed() {
    let it = text("tl-it.xml");
    // The list's own embedded certificate is not a reason to trust it.
    assert_eq!(signature_error(TrustedList::parse(&it, &[], now())), XmlSignatureError::UntrustedSigner);
    assert_eq!(signature_error(TrustedList::parse(&it, &[cert("tsl-signer-eu.der")], now())), XmlSignatureError::UntrustedSigner);
    assert_eq!(signature_error(TrustedList::parse(&text("lotl.xml"), &[cert("tsl-signer-it.der")], now())), XmlSignatureError::UntrustedSigner);
    // And a signer is believed only while its certificate is valid.
    assert_eq!(signature_error(TrustedList::parse(&it, &[cert("tsl-signer-it.der")], t(2040, 1, 1, 0, 0, 0))), XmlSignatureError::SignerNotValid);
}

#[test]
fn a_list_that_was_changed_is_refused() {
    let it = text("tl-it.xml");
    let signers = [cert("tsl-signer-it.der")];
    let refused = |xml: String| signature_error(TrustedList::parse(&xml, &signers, now()));
    // Granting what was withdrawn, adding a trusted certificate, and backdating a status.
    assert_eq!(refused(it.replace("Svcstatus/withdrawn", "Svcstatus/granted")), XmlSignatureError::DigestMismatch);
    let qca1 = data("qca1.der");
    let b64 = base64_of(&data("qca2.der"));
    assert!(it.contains(&b64[..60]));
    assert_eq!(refused(it.replacen(&base64_of(&qca1)[..60], &b64[..60], 1)), XmlSignatureError::DigestMismatch);
    assert_eq!(refused(it.replace("2024-01-01T00:00:00Z", "2010-01-01T00:00:00Z")), XmlSignatureError::DigestMismatch);
    // The signed properties are covered too.
    assert_eq!(
        refused(it.replace("2026-10-01T08:00:00Z</xades:SigningTime>", "2026-10-02T08:00:00Z</xades:SigningTime>")),
        XmlSignatureError::DigestMismatch
    );
    // A list with its signature removed is never taken as a list.
    let start = it.find("<ds:Signature").unwrap();
    let end = it.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    assert_eq!(refused(format!("{}{}", &it[..start], &it[end..])), XmlSignatureError::Unsigned);
}

fn base64_of(der: &[u8]) -> String {
    use base64::Engine as _;
    let s = base64::engine::general_purpose::STANDARD.encode(der);
    s.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n")
}

#[test]
fn a_signed_document_that_is_not_a_list_is_refused() {
    let r = TrustedList::parse(&text("rsa-sha256-exc.xml"), &[cert("rsa.der")], now());
    assert_eq!(r.unwrap_err(), TrustedListError::NotATrustedList);
    assert!(matches!(TrustedList::parse("not xml", &[cert("rsa.der")], now()), Err(TrustedListError::Signature(XmlSignatureError::NotXml(_)))));
}

#[test]
fn damaged_lists_never_panic_and_are_never_believed_by_accident() {
    let it = data("tl-it.xml");
    let signers = [cert("tsl-signer-it.der")];
    // A list cut short is not a list.
    for cut in (0..it.len()).step_by(97) {
        if let Ok(s) = std::str::from_utf8(&it[..cut]) {
            assert!(TrustedList::parse(s, &signers, now()).is_err(), "cut at {cut}");
        }
    }
    // One byte changed anywhere: whatever happens, it must not panic, and a list that still
    // verifies must read as the original does (only insignificant bytes can change).
    let original = national();
    for i in (0..it.len()).step_by(13) {
        let mut b = it.clone();
        b[i] = b[i].wrapping_add(1);
        let Ok(s) = String::from_utf8(b) else { continue };
        if let Ok(l) = TrustedList::parse(&s, &signers, now()) {
            assert_eq!(names(&l, now()), names(&original, now()), "byte {i}");
            assert_eq!(l.scheme, original.scheme, "byte {i}");
        }
    }
}

#[test]
fn the_addresses_a_list_gives_about_itself_are_read_without_believing_it() {
    use cleonpdf_sign::tl::unverified_information_uris;
    // Each address once, however many languages it is given in, in the list's order.
    let uris = unverified_information_uris(&text("lotl-pivoted.xml"));
    assert_eq!(uris.len(), 3, "{uris:?}");
    assert!(uris[0].ends_with("eu-lotl-pivot-320.xml") && uris[1].ends_with("eu-lotl-pivot-300.xml") && uris[2].contains("eur-lex.europa.eu"));
    // A list without the element, something that is not a list, and something that is not XML.
    assert!(unverified_information_uris(&text("lotl.xml")).is_empty());
    assert!(unverified_information_uris(&text("rsa-sha256-exc.xml")).is_empty());
    assert!(unverified_information_uris("<<<").is_empty());
    assert!(unverified_information_uris("").is_empty());
}

#[test]
fn a_past_list_is_judged_when_it_was_issued_and_must_say_when_that_was() {
    let a = [Certificate::parse(&data("tsl-pivot-a.der")).unwrap()];
    // Signed in 2021 by a certificate that expired in 2022.
    let today = Time { year: 2026, month: 11, day: 20, hour: 12, minute: 0, second: 0 };
    assert_eq!(TrustedList::parse(&text("pivot-300.xml"), &a, today).unwrap_err(), TrustedListError::Signature(XmlSignatureError::SignerNotValid));
    let list = TrustedList::parse_as_issued(&text("pivot-300.xml"), &a).unwrap();
    assert_eq!(list.scheme.sequence_number, 300);
    // Its signer is still checked: someone else's certificate does not do.
    let b = [Certificate::parse(&data("tsl-pivot-b.der")).unwrap()];
    assert_eq!(
        TrustedList::parse_as_issued(&text("pivot-300.xml"), &b).unwrap_err(),
        TrustedListError::Signature(XmlSignatureError::UntrustedSigner)
    );
    // A signed document that gives no issue time cannot be placed in time.
    let rsa = [Certificate::parse(&data("rsa.der")).unwrap()];
    assert!(matches!(TrustedList::parse_as_issued(&text("rsa-sha256-exc.xml"), &rsa), Err(TrustedListError::Malformed(_))));
}
