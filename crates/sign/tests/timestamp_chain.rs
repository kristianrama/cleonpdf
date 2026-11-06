//! The timestamp authority's chain, as validation reports it, and long-term validation evidence
//! gathered for it as for the signer's own: a timestamp can only be checked offline if the
//! authority's certificates were not revoked, and the file keeps the proof.

#[path = "support/pki.rs"]
mod pki;

use std::cell::RefCell;
use std::sync::Arc;

use cleonpdf_cos::Document;
use cleonpdf_sign::ltv::{Outcome, RevocationFetcher, gather};
use cleonpdf_sign::{DigestAlg, SignError, SignOptions, TimestampAuthority, TrustStore, signatures};
use pki::{Answer, Party, aia_ocsp, end_entity, ocsp_response, root, time};

/// A one-page document with a real cross-reference table.
fn fixture() -> Vec<u8> {
    let objs: [&str; 3] = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 200 300] >>",
        "<< /Type /Page /Parent 2 0 R /Resources << >> >>",
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

/// A TSA that signs with `party`'s key and certificate, at 2026-06-15.
struct Tsa {
    party: Party,
    chain: Vec<cleonpdf_sign::Certificate>,
}

impl TimestampAuthority for Tsa {
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, SignError> {
        let q = cleonpdf_sign::timestamp::parse_request(request)?;
        cleonpdf_sign::timestamp::respond(&self.party.key, &self.party.cert, &self.chain, DigestAlg::Sha256, &q, "1.2.3.4", time(2026, 6, 15), 9)
    }
}

/// OCSP answers from the CA for whichever certificate is asked about, and a log of the addresses.
struct Servers<'a> {
    ca: &'a Party,
    certs: Vec<cleonpdf_sign::Certificate>,
    asked: RefCell<Vec<String>>,
}

impl RevocationFetcher for Servers<'_> {
    fn crl(&self, url: &str) -> Result<Vec<u8>, SignError> {
        Err(pki::unreachable(url))
    }
    fn ocsp(&self, url: &str, _request: &[u8]) -> Result<Vec<u8>, SignError> {
        self.asked.borrow_mut().push(url.to_string());
        let cert = self.certs.iter().find(|c| c.ocsp_urls.iter().any(|u| u == url)).ok_or_else(|| pki::unreachable(url))?;
        Ok(ocsp_response(self.ca, cert, &self.ca.cert, Answer::Good, time(2026, 6, 14), time(2026, 6, 21)))
    }
}

struct Made {
    ca: Party,
    signer: cleonpdf_sign::Certificate,
    tsa: cleonpdf_sign::Certificate,
    signed: Vec<u8>,
    stamped: Vec<u8>,
}

/// A document signed with a timestamp, and the same document with a document timestamp, both
/// from one CA whose certificates name their own OCSP responders.
fn made() -> Made {
    let ca = root("Test CA");
    let signer = end_entity("Signer", &ca, &[aia_ocsp("http://ca.test/signer")]);
    let tsa = end_entity("Stamping Authority", &ca, &[aia_ocsp("http://ca.test/tsa")]);
    let (signer_cert, tsa_cert) = (signer.cert.clone(), tsa.cert.clone());
    let tsa = Tsa { party: tsa, chain: vec![ca.cert.clone()] };
    let id = signer.into_id(&[&ca]);
    let doc = Document::open(Arc::new(fixture())).unwrap();
    let opts = SignOptions { date: "D:20260615120000Z".into(), ..SignOptions::default() };
    let signed = cleonpdf_sign::sign_with_timestamp(&doc, &id, &opts, &tsa).unwrap();
    let stamped = cleonpdf_sign::timestamp_document(&Document::open(Arc::new(fixture())).unwrap(), &tsa, "D:20260615120000Z").unwrap();
    Made { ca, signer: signer_cert, tsa: tsa_cert, signed, stamped }
}

fn read(bytes: &[u8], trust: &TrustStore) -> Vec<cleonpdf_sign::SignatureInfo> {
    signatures(&Document::open(Arc::new(bytes.to_vec())).unwrap(), bytes, trust)
}

#[test]
fn a_signatures_timestamp_chain_is_reported_trusted_or_not() {
    let m = made();
    for trust in [TrustStore { certs: vec![m.ca.cert.clone()] }, TrustStore::default()] {
        let s = read(&m.signed, &trust).into_iter().find(|s| s.signed).unwrap();
        assert!(s.timestamp);
        let subjects: Vec<_> = s.timestamp_chain.iter().map(|c| c.display_name()).collect();
        assert_eq!(subjects, ["Stamping Authority", "Test CA"], "the authority first, then its issuer");
        assert_eq!(s.chain.first().map(|c| c.display_name()).as_deref(), Some("Signer"), "the signer's own chain is separate");
    }
}

#[test]
fn a_document_timestamps_chain_is_reported() {
    let m = made();
    let s = read(&m.stamped, &TrustStore::default()).into_iter().find(|s| s.doc_timestamp).unwrap();
    let subjects: Vec<_> = s.timestamp_chain.iter().map(|c| c.display_name()).collect();
    assert_eq!(subjects, ["Stamping Authority", "Test CA"]);
}

#[test]
fn a_document_without_a_timestamp_has_no_timestamp_chain() {
    let ca = root("Test CA");
    let signer = end_entity("Signer", &ca, &[]);
    let id = signer.into_id(&[&ca]);
    let doc = Document::open(Arc::new(fixture())).unwrap();
    let signed = cleonpdf_sign::sign(&doc, &id, &SignOptions { date: "D:20260615120000Z".into(), ..SignOptions::default() }).unwrap();
    let s = read(&signed, &TrustStore::default()).into_iter().find(|s| s.signed).unwrap();
    assert!(!s.timestamp && s.timestamp_chain.is_empty());
}

#[test]
fn evidence_is_gathered_for_the_timestamp_authority_as_for_the_signer() {
    let m = made();
    let s = read(&m.signed, &TrustStore::default()).into_iter().find(|s| s.signed).unwrap();
    let chains = vec![s.chain.clone(), s.timestamp_chain.clone()];
    let servers = Servers { ca: &m.ca, certs: vec![m.signer.clone(), m.tsa.clone()], asked: RefCell::default() };
    let got = gather(&chains, time(2026, 6, 15), &servers);
    assert_eq!(*servers.asked.borrow(), ["http://ca.test/signer", "http://ca.test/tsa"]);
    assert_eq!(got.evidence.ocsps.len(), 2, "an answer for the signer and one for the authority");
    assert!(got.notes.iter().all(|n| matches!(n.outcome, Outcome::Fetched(_))), "{:?}", got.notes);
    assert!(got.evidence.certs.iter().any(|c| c.as_slice() == m.tsa.raw.as_slice()), "the authority's certificate is kept");
}
