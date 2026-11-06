//! Gathering long-term validation evidence: which answers are kept, which are refused and why.
//! Servers are scripted fakes; the CA, its OCSP responses and CRLs come from `support/pki.rs`.

#[path = "support/pki.rs"]
mod pki;

use std::cell::RefCell;

use cleonpdf_sign::SignError;
use cleonpdf_sign::der::{Time, Tlv, tag};
use cleonpdf_sign::ltv::{Outcome, RevocationFetcher, Source, gather};
use cleonpdf_sign::revocation::ocsp_request;
use pki::{Answer, Party, aia_ocsp, crl, crl_point, end_entity, ocsp_response, root, time};

/// Asked on this date; the answers below are valid around it.
fn now() -> Time {
    time(2026, 6, 15)
}
fn window() -> (Time, Time) {
    (time(2026, 6, 14), time(2026, 6, 21))
}

type OcspFn<'a> = Box<dyn Fn(&str, &[u8]) -> Result<Vec<u8>, SignError> + 'a>;
type CrlFn<'a> = Box<dyn Fn(&str) -> Result<Vec<u8>, SignError> + 'a>;

/// A scripted pair of servers that logs every address it is asked for.
struct Servers<'a> {
    ocsp: OcspFn<'a>,
    crl: CrlFn<'a>,
    asked: RefCell<Vec<String>>,
}

impl<'a> Servers<'a> {
    fn new(ocsp: impl Fn(&str, &[u8]) -> Result<Vec<u8>, SignError> + 'a, crl: impl Fn(&str) -> Result<Vec<u8>, SignError> + 'a) -> Self {
        Servers { ocsp: Box::new(ocsp), crl: Box::new(crl), asked: RefCell::default() }
    }
    fn silent() -> Servers<'static> {
        Servers::new(|u, _| Err(pki::unreachable(u)), |u| Err(pki::unreachable(u)))
    }
}

impl RevocationFetcher for Servers<'_> {
    fn crl(&self, url: &str) -> Result<Vec<u8>, SignError> {
        self.asked.borrow_mut().push(url.to_string());
        (self.crl)(url)
    }
    fn ocsp(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, SignError> {
        self.asked.borrow_mut().push(url.to_string());
        (self.ocsp)(url, request)
    }
}

fn chain(leaf: &Party, above: &[&Party]) -> Vec<cleonpdf_sign::Certificate> {
    std::iter::once(leaf).chain(above.iter().copied()).map(|p| p.cert.clone()).collect()
}

#[test]
fn a_good_ocsp_answer_is_kept_with_the_chain_and_asks_only_the_issuer_and_serial() {
    let ca = root("Root");
    let leaf = end_entity("Leaf", &ca, &[aia_ocsp("http://ocsp.example/x")]);
    let (this, next) = window();
    let seen = RefCell::new(Vec::new());
    let servers = Servers::new(
        |_, req| {
            seen.borrow_mut().push(req.to_vec());
            Ok(ocsp_response(&ca, &leaf.cert, &ca.cert, Answer::Good, this, next))
        },
        |u| Err(pki::unreachable(u)),
    );
    let got = gather(&[chain(&leaf, &[&ca])], now(), &servers);
    assert_eq!(got.evidence.ocsps.len(), 1);
    assert!(got.evidence.crls.is_empty());
    assert_eq!(got.evidence.certs.len(), 2, "the chain goes in too");
    assert_eq!(got.notes.len(), 1, "a self-signed root needs no evidence");
    assert_eq!(got.notes[0].outcome, Outcome::Fetched(Source::Ocsp));
    assert!(!got.any_revoked() && got.has_revocation_evidence());
    // The request is exactly the CertID of the leaf under its issuer, and nothing else.
    let requests = seen.borrow();
    assert_eq!(requests.as_slice(), [ocsp_request(&leaf.cert, &ca.cert)]);
    let parsed = Tlv::parse_all(&requests[0]).unwrap().children().unwrap();
    assert_eq!(parsed.len(), 1, "no signature, no extensions");
    let tbs = parsed[0].children().unwrap();
    assert_eq!(tbs.len(), 1, "no requestor name or extensions");
    let cert_id = tbs[0].children().unwrap()[0].children().unwrap()[0].children().unwrap();
    assert_eq!(cert_id[3].tag, tag::INTEGER);
    assert_eq!(cert_id[3].uint_bytes(), leaf.cert.serial.as_slice());
}

#[test]
fn a_crl_is_used_when_the_responder_cannot_be_reached() {
    let ca = root("Root");
    let leaf = end_entity("Leaf", &ca, &[aia_ocsp("http://ocsp.example/"), crl_point("http://crl.example/ca.crl")]);
    let (this, next) = window();
    let list = crl(&ca, &[], this, next);
    let servers = Servers::new(|u, _| Err(pki::unreachable(u)), |_| Ok(list.clone()));
    let got = gather(&[chain(&leaf, &[&ca])], now(), &servers);
    assert_eq!(got.notes[0].outcome, Outcome::Fetched(Source::Crl));
    assert_eq!((got.evidence.ocsps.len(), got.evidence.crls.len()), (0, 1));
    assert_eq!(*servers.asked.borrow(), ["http://ocsp.example/", "http://crl.example/ca.crl"]);
}

#[test]
fn a_revoked_answer_is_reported_as_revoked() {
    let ca = root("Root");
    let leaf = end_entity("Leaf", &ca, &[aia_ocsp("http://ocsp.example/")]);
    let (this, next) = window();
    let at = time(2026, 6, 1);
    let servers = Servers::new(|_, _| Ok(ocsp_response(&ca, &leaf.cert, &ca.cert, Answer::Revoked(at), this, next)), |u| Err(pki::unreachable(u)));
    let got = gather(&[chain(&leaf, &[&ca])], now(), &servers);
    assert_eq!(got.notes[0].outcome, Outcome::Revoked { source: Source::Ocsp, at });
    assert!(got.any_revoked());
    // A CRL that lists the serial says the same.
    let leaf = end_entity("Leaf2", &ca, &[crl_point("http://crl.example/")]);
    let list = crl(&ca, &[(leaf.cert.serial.as_slice(), at)], this, next);
    let got = gather(&[chain(&leaf, &[&ca])], now(), &Servers::new(|u, _| Err(pki::unreachable(u)), |_| Ok(list.clone())));
    assert_eq!(got.notes[0].outcome, Outcome::Revoked { source: Source::Crl, at });
}

#[test]
fn answers_that_do_not_check_out_are_not_kept() {
    let ca = root("Root");
    let leaf = end_entity("Leaf", &ca, &[aia_ocsp("http://ocsp.example/"), crl_point("http://crl.example/")]);
    let other = end_entity("Other", &ca, &[]);
    let impostor = root("Root");
    let (this, next) = window();
    let none = |u: &str| -> Result<Vec<u8>, SignError> { Err(pki::unreachable(u)) };
    let stale = (time(2026, 5, 1), time(2026, 5, 8));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // Signed by a key that is not the issuer's, though it carries the issuer's name.
        ("an OCSP answer signed by an impostor", ocsp_response(&impostor, &leaf.cert, &ca.cert, Answer::Good, this, next)),
        // A good answer about another certificate, replayed.
        ("an OCSP answer about another certificate", ocsp_response(&ca, &other.cert, &ca.cert, Answer::Good, this, next)),
        // Valid, but not when we asked.
        ("an OCSP answer from last month", ocsp_response(&ca, &leaf.cert, &ca.cert, Answer::Good, stale.0, stale.1)),
        ("garbage", b"<html>404</html>".to_vec()),
    ];
    for (what, answer) in cases {
        let servers = Servers::new(|_, _| Ok(answer.clone()), none);
        let got = gather(&[chain(&leaf, &[&ca])], now(), &servers);
        assert!(matches!(got.notes[0].outcome, Outcome::Missing(_)), "{what}: {:?}", got.notes);
        assert!(!got.has_revocation_evidence(), "{what}");
    }
    // The same for CRLs: forged, someone else's, and out of date.
    let bad_crls = [("a CRL signed by an impostor", crl(&impostor, &[], this, next)), ("an out-of-date CRL", crl(&ca, &[], stale.0, stale.1))];
    for (what, list) in bad_crls {
        let servers = Servers::new(|u, _| Err(pki::unreachable(u)), |_| Ok(list.clone()));
        let got = gather(&[chain(&leaf, &[&ca])], now(), &servers);
        assert!(matches!(got.notes[0].outcome, Outcome::Missing(_)), "{what}: {:?}", got.notes);
        assert!(!got.has_revocation_evidence(), "{what}");
    }
}

#[test]
fn a_delegated_responders_certificate_is_kept_with_its_answer() {
    let ca = root("Root");
    let leaf = end_entity("Leaf", &ca, &[aia_ocsp("http://ocsp.example/")]);
    let responder =
        pki::issue("Responder", Some(&ca), &[pki::basic_constraints(false), pki::key_usage(pki::DIGITAL_SIGNATURE), pki::eku_ocsp_signing()]);
    let (this, next) = window();
    let servers = Servers::new(|_, _| Ok(ocsp_response(&responder, &leaf.cert, &ca.cert, Answer::Good, this, next)), |u| Err(pki::unreachable(u)));
    let got = gather(&[chain(&leaf, &[&ca])], now(), &servers);
    assert_eq!(got.notes[0].outcome, Outcome::Fetched(Source::Ocsp));
    assert!(got.evidence.certs.contains(&responder.cert.raw), "the responder's certificate is in the store");
    // A responder without the OCSP-signing usage is refused.
    let plain = pki::issue("Plain", Some(&ca), &[pki::basic_constraints(false), pki::key_usage(pki::DIGITAL_SIGNATURE)]);
    let servers = Servers::new(|_, _| Ok(ocsp_response(&plain, &leaf.cert, &ca.cert, Answer::Good, this, next)), |u| Err(pki::unreachable(u)));
    let got = gather(&[chain(&leaf, &[&ca])], now(), &servers);
    assert!(matches!(got.notes[0].outcome, Outcome::Missing(_)), "{:?}", got.notes);
}

#[test]
fn every_certificate_below_the_root_is_asked_once_however_many_signatures_share_it() {
    let top = root("Root");
    let mid = pki::ca("Intermediate", &top, &[aia_ocsp("http://ocsp.example/top")]);
    let a = end_entity("Alice", &mid, &[aia_ocsp("http://ocsp.example/mid")]);
    let b = end_entity("Bob", &mid, &[aia_ocsp("http://ocsp.example/mid")]);
    let (this, next) = window();
    let servers = Servers::new(
        |url, req| {
            let (cert, issuer) = match url {
                "http://ocsp.example/top" => (&mid, &top),
                _ if req == ocsp_request(&a.cert, &mid.cert) => (&a, &mid),
                _ => (&b, &mid),
            };
            Ok(ocsp_response(issuer, &cert.cert, &issuer.cert, Answer::Good, this, next))
        },
        |u| Err(pki::unreachable(u)),
    );
    let chains = [chain(&a, &[&mid, &top]), chain(&b, &[&mid, &top]), chain(&a, &[&mid, &top])];
    let got = gather(&chains, now(), &servers);
    // Intermediate once, A once, B once; the root never.
    assert_eq!(servers.asked.borrow().len(), 3, "{:?}", servers.asked.borrow());
    assert_eq!(got.evidence.ocsps.len(), 3);
    assert_eq!(got.evidence.certs.len(), 4, "four certificates, none twice");
    assert!(got.notes.iter().all(|n| n.outcome == Outcome::Fetched(Source::Ocsp)));
}

#[test]
fn a_certificate_with_nowhere_to_ask_is_missing_not_an_error() {
    let ca = root("Root");
    let none = end_entity("None", &ca, &[]);
    let servers = Servers::silent();
    let got = gather(&[chain(&none, &[&ca])], now(), &servers);
    assert!(matches!(&got.notes[0].outcome, Outcome::Missing(m) if m.contains("names no OCSP responder or CRL address")), "{:?}", got.notes);
    assert!(servers.asked.borrow().is_empty());
    // Only http and https are tried: an ldap:// address is never handed to the fetcher.
    let ldap = end_entity("Ldap", &ca, &[aia_ocsp("ldap://dir.example/cn=x"), crl_point("ftp://files.example/ca.crl")]);
    let got = gather(&[chain(&ldap, &[&ca])], now(), &servers);
    assert!(matches!(got.notes[0].outcome, Outcome::Missing(_)));
    assert!(servers.asked.borrow().is_empty());
    // A chain that stops before a root says so.
    let leaf = end_entity("Orphan", &ca, &[aia_ocsp("http://ocsp.example/")]);
    let got = gather(&[vec![leaf.cert.clone()]], now(), &servers);
    assert!(matches!(&got.notes[0].outcome, Outcome::Missing(m) if m.contains("issuer")), "{:?}", got.notes);
    assert!(servers.asked.borrow().is_empty());
    // The failure reason names the host and never the path (which may carry a token).
    let secret = end_entity("Secret", &ca, &[aia_ocsp("http://ocsp.example/path?token=SECRET")]);
    let got = gather(
        &[chain(&secret, &[&ca])],
        now(),
        &Servers::new(|_, _| Err(SignError::Transport("ocsp.example: couldn't be reached".into())), |u| Err(pki::unreachable(u))),
    );
    let Outcome::Missing(m) = &got.notes[0].outcome else { panic!("{:?}", got.notes) };
    assert!(m.contains("ocsp.example") && !m.contains("SECRET"), "{m}");
}
