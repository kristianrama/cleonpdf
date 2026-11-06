//! Long-term validation evidence, gathered: for each certificate in a signature's chain, ask the
//! issuer's OCSP responder (RFC 6960) or read its CRL (RFC 5280), check the answer, and collect
//! what verified for [`crate::dss::embed`] (PAdES B-LT).
//!
//! This module never opens a socket. The addresses come from the certificates, which means from
//! whoever made them, so the caller supplies the transport ([`RevocationFetcher`]) and decides
//! which hosts it will talk to. What a server answers is checked here before it is kept: the
//! answer must be signed by the certificate's issuer (or a responder it delegated to), name the
//! certificate, and be current.

use crate::dss::Evidence;
use crate::revocation::{CertificateList, OcspResponse, RevocationStatus, ocsp_request};
use crate::x509::Certificate;
use crate::{SignError, Time};

/// How revocation evidence is fetched. Implemented over HTTP by `cleonpdf-net`; tests use fakes.
pub trait RevocationFetcher {
    /// The CRL (DER) published at `url`.
    fn crl(&self, url: &str) -> Result<Vec<u8>, SignError>;
    /// The OCSP response (DER) a responder at `url` gives to `request` (DER).
    fn ocsp(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, SignError>;
    /// What is published at `url` as a certificate's issuer (`caIssuers`): a DER certificate, or
    /// a certificates-only CMS bundle. A transport that cannot fetch these keeps this default, and
    /// chains that lack their issuer are then reported, not completed.
    fn issuer(&self, url: &str) -> Result<Vec<u8>, SignError> {
        Err(SignError::Transport(format!("{}: fetching issuer certificates is not supported here", host(url))))
    }
}

/// Where a certificate's evidence came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Ocsp,
    Crl,
}

/// What happened for one certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Verified evidence that the certificate is not revoked was collected.
    Fetched(Source),
    /// Verified evidence says the certificate is revoked (it is collected too).
    Revoked { source: Source, at: Time },
    /// No usable evidence; the reason names the host, never the path of the address.
    Missing(String),
}

/// One certificate and what was found for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub subject: String,
    pub outcome: Outcome,
}

/// The evidence collected and a note per certificate that needed it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gathered {
    pub evidence: Evidence,
    pub notes: Vec<Note>,
    /// Issuer certificates downloaded to complete chains that lacked them.
    pub issuers_fetched: usize,
}

impl Gathered {
    /// True when any certificate was found revoked.
    pub fn any_revoked(&self) -> bool {
        self.notes.iter().any(|n| matches!(n.outcome, Outcome::Revoked { .. }))
    }

    /// True when some revocation evidence (an OCSP response or a CRL) was collected.
    pub fn has_revocation_evidence(&self) -> bool {
        !self.evidence.ocsps.is_empty() || !self.evidence.crls.is_empty()
    }
}

/// The longest chain looked at and the most addresses tried per certificate.
const MAX_CHAIN: usize = 10;
const MAX_URLS: usize = 3;

/// Collect evidence for `chains` (each signer first, as `SignatureInfo::chain`) as of `at`.
///
/// A chain that stops at a certificate whose issuer is not in it is completed first, from the
/// address the certificate names for its issuer (`caIssuers`): the download is kept only if it is
/// the issuer's certificate (its name, and its key verifies the signature), and the chain then
/// continues from it, up to a self-signed root or the length limit.
///
/// Every certificate that has an issuer in its chain gets one OCSP query (its responders in order)
/// and, failing that, one CRL download. A self-signed root needs none. A certificate whose issuer
/// could not be had, or whose servers could not be reached or gave nothing usable, is noted
/// as missing; the rest still go in. The chain's certificates are collected too (a delegated
/// responder's certificate with its response), so the store can be checked offline.
pub fn gather(chains: &[Vec<Certificate>], at: Time, fetcher: &dyn RevocationFetcher) -> Gathered {
    let mut out = Gathered::default();
    let mut fetched = Fetched::default();
    let completed: Vec<(Vec<Certificate>, Option<String>)> = chains.iter().map(|chain| complete(chain, fetcher, &mut fetched)).collect();
    out.issuers_fetched = fetched.certs.len();
    let mut done: Vec<&[u8]> = Vec::new();
    for (chain, why_not) in &completed {
        for (i, cert) in chain.iter().take(MAX_CHAIN).enumerate() {
            add_unique(&mut out.evidence.certs, &cert.raw);
            if cert.is_self_signed() || done.contains(&cert.raw.as_slice()) {
                continue;
            }
            done.push(&cert.raw);
            let subject = cert.display_name();
            let outcome = match chain.get(i + 1).filter(|_| i + 1 < MAX_CHAIN) {
                Some(issuer) => one(cert, issuer, at, fetcher, &mut out.evidence),
                None => Outcome::Missing(match why_not {
                    Some(why) => format!("the issuer's certificate is not in the chain and could not be fetched ({why})"),
                    None => "the issuer's certificate is not in the chain".into(),
                }),
            };
            out.notes.push(Note { subject, outcome });
        }
    }
    out
}

/// Issuer certificates already downloaded in this run, by the certificate they were fetched for
/// (several chains often stop at the same one). `None` records a failed attempt with its reason.
#[derive(Default)]
struct Fetched {
    certs: Vec<Certificate>,
    tried: Vec<(Vec<u8>, Result<Certificate, String>)>,
}

/// `chain`, extended upward from its last certificate while that one is not self-signed and names
/// where its issuer can be had. The second value says why the chain still stops short, if a
/// download was attempted and failed.
fn complete(chain: &[Certificate], fetcher: &dyn RevocationFetcher, fetched: &mut Fetched) -> (Vec<Certificate>, Option<String>) {
    let mut chain: Vec<Certificate> = chain.iter().take(MAX_CHAIN).cloned().collect();
    while chain.len() < MAX_CHAIN {
        let Some(last) = chain.last() else { break };
        if last.is_self_signed() || chain.iter().any(|c| c.subject.raw == last.issuer.raw) {
            // A chain whose issuer is already in it was built in order; one that is not is the
            // caller's business, not something to fetch around.
            break;
        }
        if last.ca_issuer_urls.is_empty() {
            return (chain, None);
        }
        let key = last.raw.clone();
        let result = match fetched.tried.iter().find(|(k, _)| *k == key) {
            Some((_, r)) => r.clone(),
            None => {
                let r = fetch_issuer(last, &chain, fetcher);
                if let Ok(c) = &r {
                    fetched.certs.push(c.clone());
                }
                fetched.tried.push((key, r.clone()));
                r
            }
        };
        match result {
            Ok(issuer) => chain.push(issuer),
            Err(why) => return (chain, Some(why)),
        }
    }
    (chain, None)
}

/// Download `cert`'s issuer from the first address that gives it.
fn fetch_issuer(cert: &Certificate, chain: &[Certificate], fetcher: &dyn RevocationFetcher) -> Result<Certificate, String> {
    let mut why: Vec<String> = Vec::new();
    for url in cert.ca_issuer_urls.iter().filter(|u| is_web(u)).take(MAX_URLS) {
        match fetcher.issuer(url) {
            Ok(bytes) => {
                let candidates = Certificate::parse(&bytes).map(|c| vec![c]).or_else(|_| crate::cms::certificates_only(&bytes));
                match candidates {
                    Ok(list) => {
                        match list.into_iter().find(|c| c.subject.raw == cert.issuer.raw && cert.signed_by(&c.public_key) && !chain.contains(c)) {
                            Some(found) => return Ok(found),
                            None => why.push(format!("{}: the download is not this certificate's issuer", host(url))),
                        }
                    }
                    Err(_) => why.push(format!("{}: the download is neither a certificate nor a certificate bundle", host(url))),
                }
            }
            Err(e) => why.push(e.to_string()),
        }
    }
    if why.is_empty() {
        why.push("the certificate names no issuer address (http or https)".into());
    }
    Err(why.join("; "))
}

fn add_unique(list: &mut Vec<Vec<u8>>, blob: &[u8]) {
    if !list.iter().any(|b| b.as_slice() == blob) {
        list.push(blob.to_vec());
    }
}

/// Plain `http://` and `https://` addresses; `ldap://` and the rest are not tried.
fn is_web(url: &str) -> bool {
    let lower = |n: usize| url.get(..n).map(str::to_ascii_lowercase);
    lower(7).as_deref() == Some("http://") || lower(8).as_deref() == Some("https://")
}

fn one(cert: &Certificate, issuer: &Certificate, at: Time, fetcher: &dyn RevocationFetcher, evidence: &mut Evidence) -> Outcome {
    let mut why: Vec<String> = Vec::new();
    let request = ocsp_request(cert, issuer);
    for url in cert.ocsp_urls.iter().filter(|u| is_web(u)).take(MAX_URLS) {
        let asked = fetcher.ocsp(url, &request).and_then(|bytes| {
            let response = OcspResponse::parse(&bytes)?;
            Ok((bytes, response))
        });
        match asked {
            Ok((bytes, response)) => match response.check(cert, issuer, at) {
                status @ (RevocationStatus::Good | RevocationStatus::Revoked { .. }) => {
                    add_unique(&mut evidence.ocsps, &bytes);
                    if let Some(responder) = response.responder_certificate() {
                        add_unique(&mut evidence.certs, &responder.raw);
                    }
                    return match status {
                        RevocationStatus::Revoked { at } => Outcome::Revoked { source: Source::Ocsp, at },
                        _ => Outcome::Fetched(Source::Ocsp),
                    };
                }
                RevocationStatus::Unknown => {
                    why.push(format!("{}: the OCSP answer is not current, not signed by the issuer, or not about this certificate", host(url)))
                }
            },
            Err(e) => why.push(e.to_string()),
        }
    }
    for url in cert.crl_urls.iter().filter(|u| is_web(u)).take(MAX_URLS) {
        let read = fetcher.crl(url).and_then(|bytes| {
            let list = CertificateList::parse(&bytes)?;
            Ok((bytes, list))
        });
        match read {
            Ok((bytes, list)) => match list.check(cert, issuer, at) {
                status @ (RevocationStatus::Good | RevocationStatus::Revoked { .. }) => {
                    add_unique(&mut evidence.crls, &bytes);
                    return match status {
                        RevocationStatus::Revoked { at } => Outcome::Revoked { source: Source::Crl, at },
                        _ => Outcome::Fetched(Source::Crl),
                    };
                }
                RevocationStatus::Unknown => {
                    why.push(format!("{}: the CRL is out of date, not signed by the issuer, or not this issuer's", host(url)))
                }
            },
            Err(e) => why.push(e.to_string()),
        }
    }
    if why.is_empty() {
        why.push("the certificate names no OCSP responder or CRL address (http or https)".into());
    }
    Outcome::Missing(why.join("; "))
}

/// The host (and port) of an address, for messages: a path or query may carry a token.
fn host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or_default()
}
