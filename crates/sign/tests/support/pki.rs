//! A small certificate authority for tests: certificates issued in-process with chosen
//! extensions, and the CRLs and OCSP responses a CA would publish for them. Shared by the sign
//! and automation tests (`#[path]`), so a test can run a whole chain without OpenSSL.
#![allow(dead_code)]

use cleonpdf_sign::DigestAlg;
use cleonpdf_sign::der::{self, Time, tag};
use cleonpdf_sign::pkcs12::DigitalId;
use cleonpdf_sign::x509::{Certificate, Name};
use cleonpdf_sign::{PrivateKey, SignError};

pub fn time(year: u32, month: u32, day: u32) -> Time {
    Time { year, month, day, hour: 12, minute: 0, second: 0 }
}

pub struct Party {
    pub name: Name,
    pub key: PrivateKey,
    pub cert: Certificate,
}

impl Party {
    /// The party as a digital ID with `chain` (nearest issuer first) behind it.
    pub fn into_id(self, chain: &[&Party]) -> DigitalId {
        DigitalId { key: self.key, certificate: self.cert, chain: chain.iter().map(|p| p.cert.clone()).collect(), friendly_name: None }
    }
}

pub fn ext(oid: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    if critical { der::seq(&[&der::oid(oid), &der::boolean(true), &der::octets(value)]) } else { der::seq(&[&der::oid(oid), &der::octets(value)]) }
}

pub fn basic_constraints(ca: bool) -> Vec<u8> {
    let body = if ca { der::seq(&[&der::boolean(true)]) } else { der::seq(&[]) };
    ext("2.5.29.19", true, &body)
}

pub fn key_usage(bits: u8) -> Vec<u8> {
    ext("2.5.29.15", true, &der::tlv(tag::BIT_STRING, &[1, bits]))
}

pub const DIGITAL_SIGNATURE: u8 = 0x80;
pub const KEY_CERT_SIGN: u8 = 0x04;

/// Authority Information Access naming an OCSP responder.
pub fn aia_ocsp(url: &str) -> Vec<u8> {
    ext("1.3.6.1.5.5.7.1.1", false, &der::seq(&[&der::seq(&[&der::oid("1.3.6.1.5.5.7.48.1"), &der::tlv(tag::ctx_prim(6), url.as_bytes())])]))
}

/// Authority Information Access naming an OCSP responder and/or where the issuer's certificate
/// is published (`caIssuers`).
pub fn aia(ocsp: Option<&str>, ca_issuers: Option<&str>) -> Vec<u8> {
    let access = |method: &str, url: &str| der::seq(&[&der::oid(method), &der::tlv(tag::ctx_prim(6), url.as_bytes())]);
    let entries: Vec<Vec<u8>> =
        [ocsp.map(|u| access("1.3.6.1.5.5.7.48.1", u)), ca_issuers.map(|u| access("1.3.6.1.5.5.7.48.2", u))].into_iter().flatten().collect();
    let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
    ext("1.3.6.1.5.5.7.1.1", false, &der::seq(&refs))
}

/// A certificates-only CMS bundle (`.p7c`), as some CAs publish their issuer certificates.
pub fn p7c(certs: &[&Certificate]) -> Vec<u8> {
    let joined: Vec<u8> = certs.iter().flat_map(|c| c.raw.iter().copied()).collect();
    let signed = der::seq(&[
        &der::int(1),
        &der::tlv(tag::SET, &[]),
        &der::seq(&[&der::oid("1.2.840.113549.1.7.1")]),
        &der::tlv(tag::ctx(0), &joined),
        &der::tlv(tag::SET, &[]),
    ]);
    der::seq(&[&der::oid("1.2.840.113549.1.7.2"), &der::explicit(0, &signed)])
}

/// A CRL distribution point with one full-name URI.
pub fn crl_point(url: &str) -> Vec<u8> {
    let name = der::tlv(tag::ctx(0), &der::tlv(tag::ctx_prim(6), url.as_bytes()));
    ext("2.5.29.31", false, &der::seq(&[&der::seq(&[&der::tlv(tag::ctx(0), &name)])]))
}

/// The OCSP-signing extended key usage.
pub fn eku_ocsp_signing() -> Vec<u8> {
    ext("2.5.29.37", false, &der::seq(&[&der::oid("1.3.6.1.5.5.7.3.9")]))
}

/// A certificate for a fresh P-256 key, signed by `issuer` (or by itself).
pub fn issue(cn: &str, issuer: Option<&Party>, extensions: &[Vec<u8>]) -> Party {
    let key = PrivateKey::generate_p256().unwrap();
    let name = Name::build(cn, "", "PKI Tests", "", "US");
    let signer = issuer.map_or(&key, |i| &i.key);
    let issuer_name = issuer.map_or(&name, |i| &i.name);
    let alg = signer.preferred_digest();
    let sig_alg = signer.signature_algorithm(alg);
    let exts: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
    let mut fields: Vec<Vec<u8>> = vec![der::explicit(0, &der::int(2))];
    fields.extend([
        der::uint(&[1 + cn.len() as u8]),
        sig_alg.clone(),
        issuer_name.raw.clone(),
        der::seq(&[&time(2020, 1, 1).encode(), &time(2040, 1, 1).encode()]),
        name.raw.clone(),
        key.public_key().spki(),
    ]);
    fields.push(der::explicit(3, &der::seq(&exts)));
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let tbs = der::seq(&refs);
    let signature = signer.sign(alg, &tbs).unwrap();
    let cert = Certificate::parse(&der::seq(&[&tbs, &sig_alg, &der::bit_string(&signature)])).unwrap();
    Party { name, key, cert }
}

/// A leaf certificate for a public key someone else holds (a token generated it), issued by
/// `under`. `spki` is the DER `SubjectPublicKeyInfo`.
pub fn end_entity_for_key(cn: &str, under: &Party, spki: Vec<u8>, extensions: &[Vec<u8>]) -> Certificate {
    let mut all = vec![basic_constraints(false), key_usage(DIGITAL_SIGNATURE)];
    all.extend_from_slice(extensions);
    let exts: Vec<&[u8]> = all.iter().map(Vec::as_slice).collect();
    let name = Name::build(cn, "", "PKI Tests", "", "US");
    let alg = under.key.preferred_digest();
    let sig_alg = under.key.signature_algorithm(alg);
    let mut fields: Vec<Vec<u8>> = vec![der::explicit(0, &der::int(2))];
    fields.extend([
        der::uint(&[0x40 + cn.len() as u8]),
        sig_alg.clone(),
        under.name.raw.clone(),
        der::seq(&[&time(2020, 1, 1).encode(), &time(2040, 1, 1).encode()]),
        name.raw,
        spki,
    ]);
    fields.push(der::explicit(3, &der::seq(&exts)));
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let tbs = der::seq(&refs);
    let signature = under.key.sign(alg, &tbs).unwrap();
    Certificate::parse(&der::seq(&[&tbs, &sig_alg, &der::bit_string(&signature)])).unwrap()
}

pub fn root(cn: &str) -> Party {
    issue(cn, None, &[basic_constraints(true), key_usage(KEY_CERT_SIGN)])
}

pub fn ca(cn: &str, under: &Party, extensions: &[Vec<u8>]) -> Party {
    let mut all = vec![basic_constraints(true), key_usage(KEY_CERT_SIGN)];
    all.extend_from_slice(extensions);
    issue(cn, Some(under), &all)
}

pub fn end_entity(cn: &str, under: &Party, extensions: &[Vec<u8>]) -> Party {
    let mut all = vec![basic_constraints(false), key_usage(DIGITAL_SIGNATURE)];
    all.extend_from_slice(extensions);
    issue(cn, Some(under), &all)
}

/// How an OCSP response answers.
#[derive(Clone, Copy)]
pub enum Answer {
    Good,
    Revoked(Time),
}

/// An OCSP response from `responder` about `cert` (issued by `issuer`) valid `this`..`next`.
/// When `responder` is not the issuer, its certificate travels with the response.
pub fn ocsp_response(responder: &Party, cert: &Certificate, issuer: &Certificate, answer: Answer, this: Time, next: Time) -> Vec<u8> {
    let cert_id = der::seq(&[
        &DigestAlg::Sha1.algorithm(),
        &der::octets(&DigestAlg::Sha1.digest(&[&cert.issuer.raw])),
        &der::octets(&DigestAlg::Sha1.digest(&[&issuer.public_key.key_bits()])),
        &der::uint(&cert.serial),
    ]);
    let status = match answer {
        Answer::Good => der::tlv(tag::ctx_prim(0), &[]),
        Answer::Revoked(at) => der::tlv(tag::ctx(1), &at.encode()),
    };
    let single = der::seq(&[&cert_id, &status, &this.encode(), &der::tlv(tag::ctx(0), &next.encode())]);
    let responder_id = der::tlv(tag::ctx(1), &responder.cert.subject.raw);
    let tbs = der::seq(&[&responder_id, &this.encode(), &der::seq(&[&single])]);
    let alg = responder.key.signature_algorithm(DigestAlg::Sha256);
    let sig = responder.key.sign(DigestAlg::Sha256, &tbs).unwrap();
    let mut basic = vec![tbs, alg, der::bit_string(&sig)];
    if responder.cert.raw != issuer.raw {
        basic.push(der::explicit(0, &der::seq(&[&responder.cert.raw])));
    }
    let refs: Vec<&[u8]> = basic.iter().map(Vec::as_slice).collect();
    let basic = der::seq(&refs);
    // responseStatus is an ENUMERATED, as responders send it.
    der::seq(&[&der::tlv(tag::ENUMERATED, &[0]), &der::explicit(0, &der::seq(&[&der::oid("1.3.6.1.5.5.7.48.1.1"), &der::octets(&basic)]))])
}

/// A CRL from `issuer`, listing `revoked` serials.
pub fn crl(issuer: &Party, revoked: &[(&[u8], Time)], this: Time, next: Time) -> Vec<u8> {
    let alg = issuer.key.signature_algorithm(DigestAlg::Sha256);
    let mut tbs = vec![der::int(1), alg.clone(), issuer.cert.subject.raw.clone(), this.encode(), next.encode()];
    if !revoked.is_empty() {
        let entries: Vec<Vec<u8>> = revoked.iter().map(|(serial, at)| der::seq(&[&der::uint(serial), &at.encode()])).collect();
        let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
        tbs.push(der::seq(&refs));
    }
    let refs: Vec<&[u8]> = tbs.iter().map(Vec::as_slice).collect();
    let tbs = der::seq(&refs);
    let sig = issuer.key.sign(DigestAlg::Sha256, &tbs).unwrap();
    der::seq(&[&tbs, &alg, &der::bit_string(&sig)])
}

pub fn unreachable(host: &str) -> SignError {
    SignError::Transport(format!("{host}: couldn't be reached"))
}
