//! Trusted Lists (ETSI TS 119 612): the signed XML lists in which each EU/EEA member state
//! publishes its qualified trust service providers, and the European Commission's list of those
//! lists (the LOTL).
//!
//! This reads a list that is already in hand; it fetches nothing. A list is trusted only when its
//! XML signature (see [`crate::xmldsig`]) verifies against a signing certificate the caller
//! supplies: for the LOTL, the certificates the Commission publishes in the Official Journal of
//! the European Union; for a national list, the ones the LOTL points to ([`ListPointer::signers`]).
//! Nothing here decides what to do with a list that is out of date: see
//! [`TrustedList::is_expired`].

use crate::der::Time;
use crate::x509::Certificate;
use crate::xmldsig::{self, XmlSignatureError};
use base64::Engine as _;
use roxmltree::Node;

const TSL: &str = "http://uri.etsi.org/02231/v2#";

/// The service status values that mean "granted", the current one and the one used before
/// ETSI TS 119 612 v2.1.1.
const GRANTED: [&str; 2] = ["http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted", "http://uri.etsi.org/TrstSvc/Svcstatus/granted"];
/// The service type of a certification authority issuing qualified certificates.
pub const CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";

/// Most providers, services, states, pointers and certificates read from one list; a list with
/// more is refused rather than cut, as a cut list would silently lose trust anchors.
const MAX_ITEMS: usize = 200_000;
/// Most certificates one service or pointer may carry.
const MAX_CERTS_PER_ITEM: usize = 64;
/// Most `SchemeInformationURI` entries read, and the longest one.
const MAX_INFORMATION_URIS: usize = 64;
const MAX_URI_LEN: usize = 2048;

/// Why a Trusted List was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustedListError {
    #[error("{0}")]
    Signature(#[from] XmlSignatureError),
    #[error("the document is not a Trusted List")]
    NotATrustedList,
    #[error("the Trusted List is malformed: {0}")]
    Malformed(String),
}

/// The list's own details (TS 119 612 §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeInfo {
    /// `TSLVersionIdentifier`.
    pub version: u32,
    /// `TSLSequenceNumber`: grows with every issue of the list.
    pub sequence_number: u64,
    /// `TSLType`, a URI (for example `.../TSLType/EUgeneric`).
    pub list_type: String,
    /// `SchemeOperatorName`, in English if there is one.
    pub operator: String,
    /// `SchemeTerritory`, a country code (`EU` for the LOTL).
    pub territory: String,
    /// `ListIssueDateTime`.
    pub issued: Option<Time>,
    /// `NextUpdate`: the list is not to be relied on after this.
    pub next_update: Option<Time>,
}

/// Where another list is, and who signs it (an entry of the LOTL).
#[derive(Debug, Clone)]
pub struct ListPointer {
    pub location: String,
    pub territory: Option<String>,
    pub mime_type: Option<String>,
    /// The certificates that sign the list at `location`.
    pub signers: Vec<Certificate>,
}

/// A service's status from a point in time on.
#[derive(Debug, Clone)]
pub struct ServiceState {
    /// `ServiceTypeIdentifier`, a URI.
    pub service_type: String,
    /// `ServiceStatus`, a URI.
    pub status: String,
    /// `StatusStartingTime`.
    pub from: Time,
    /// The certificates that identify the service in this state.
    pub certificates: Vec<Certificate>,
}

impl ServiceState {
    /// Whether the status is "granted".
    #[must_use]
    pub fn is_granted(&self) -> bool {
        GRANTED.contains(&self.status.as_str())
    }
}

/// A trust service of a provider, with its history.
#[derive(Debug, Clone)]
pub struct TrustService {
    pub name: String,
    /// Every state the list records, oldest first; the last is the current one.
    pub states: Vec<ServiceState>,
}

impl TrustService {
    /// The state in force at `t`: the latest that started at or before it.
    #[must_use]
    pub fn state_at(&self, t: Time) -> Option<&ServiceState> {
        self.states.iter().rev().find(|s| s.from <= t)
    }
}

/// A trust service provider.
#[derive(Debug, Clone)]
pub struct TrustServiceProvider {
    pub name: String,
    pub services: Vec<TrustService>,
}

/// A certificate that anchors trust for a qualified service at some time, and who vouches for it.
#[derive(Debug, Clone, Copy)]
pub struct QualifiedRoot<'a> {
    pub certificate: &'a Certificate,
    pub provider: &'a TrustServiceProvider,
    pub service: &'a TrustService,
}

/// A Trusted List whose signature has been verified.
#[derive(Debug, Clone)]
pub struct TrustedList {
    pub scheme: SchemeInfo,
    pub pointers: Vec<ListPointer>,
    pub providers: Vec<TrustServiceProvider>,
    /// The certificate that signed the list.
    pub signer: Certificate,
    /// Certificates in the list that could not be read; they anchor nothing.
    pub unreadable_certificates: usize,
}

fn is_tsl(n: Node<'_, '_>, local: &str) -> bool {
    n.is_element() && n.tag_name().name() == local && n.tag_name().namespace() == Some(TSL)
}

fn child<'a, 'i>(n: Node<'a, 'i>, local: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| is_tsl(*c, local))
}

fn children<'a, 'i>(n: Node<'a, 'i>, local: &'a str) -> impl Iterator<Item = Node<'a, 'i>> {
    n.children().filter(move |c| is_tsl(*c, local))
}

fn text(n: Node<'_, '_>) -> String {
    n.descendants().filter(|d| d.is_text()).filter_map(|d| d.text()).collect::<String>().trim().to_string()
}

fn child_text(n: Node<'_, '_>, local: &str) -> Option<String> {
    child(n, local).map(text)
}

/// The text of the multilingual `Name` or `Value`-like children of `n`: English if there is one,
/// else the first.
fn localized(n: Node<'_, '_>, local: &str) -> String {
    let mut first = None;
    for c in children(n, local) {
        let lang = c.attribute(("http://www.w3.org/XML/1998/namespace", "lang")).unwrap_or("");
        if lang.to_ascii_lowercase().starts_with("en") {
            return text(c);
        }
        first.get_or_insert_with(|| text(c));
    }
    first.unwrap_or_default()
}

/// An `xs:dateTime` as UTC: `2026-04-01T00:00:00Z`, with fractions of a second and an offset
/// allowed.
fn datetime(s: &str) -> Option<Time> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-');
    let (year, month, day) = (d.next()?.parse::<u32>().ok()?, d.next()?.parse::<u32>().ok()?, d.next()?.parse::<u32>().ok()?);
    if d.next().is_some() || year == 0 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let split = rest.find(['Z', '+', '-']).unwrap_or(rest.len());
    let (clock, zone) = rest.split_at(split);
    let mut c = clock.split(':');
    let hour = c.next()?.parse::<u32>().ok()?;
    let minute = c.next()?.parse::<u32>().ok()?;
    let second = c.next()?.split('.').next()?.parse::<u32>().ok()?;
    if c.next().is_some() || hour > 24 || minute > 59 || second > 60 {
        return None;
    }
    let t = Time { year, month, day, hour: hour.min(23), minute, second: second.min(59) };
    let offset = match zone {
        "" | "Z" => 0,
        z => {
            let sign = if z.starts_with('-') { -1i64 } else { 1 };
            let (h, m) = z.get(1..)?.split_once(':')?;
            sign * (i64::from(h.parse::<u32>().ok()?) * 3600 + i64::from(m.parse::<u32>().ok()?) * 60)
        }
    };
    Some(t.add_seconds(offset.checked_neg()?))
}

/// Read every `X509Certificate` under the `DigitalId`s of `n`, counting those that cannot be read.
fn certificates(n: Node<'_, '_>, unreadable: &mut usize) -> Result<Vec<Certificate>, TrustedListError> {
    let mut out = Vec::new();
    for id in n.descendants().filter(|d| is_tsl(*d, "DigitalId")) {
        for c in children(id, "X509Certificate") {
            if out.len() >= MAX_CERTS_PER_ITEM {
                return Err(TrustedListError::Malformed("too many certificates in one entry".into()));
            }
            let clean: String = text(c).chars().filter(|c| !c.is_whitespace()).collect();
            match base64::engine::general_purpose::STANDARD.decode(clean).ok().and_then(|raw| Certificate::parse(&raw).ok()) {
                Some(cert) => out.push(cert),
                None => *unreadable += 1,
            }
        }
    }
    Ok(out)
}

fn state(n: Node<'_, '_>, unreadable: &mut usize) -> Result<Option<ServiceState>, TrustedListError> {
    let (Some(service_type), Some(status), Some(from)) =
        (child_text(n, "ServiceTypeIdentifier"), child_text(n, "ServiceStatus"), child_text(n, "StatusStartingTime").and_then(|t| datetime(&t)))
    else {
        return Ok(None);
    };
    let certificates = child(n, "ServiceDigitalIdentity").map_or(Ok(Vec::new()), |id| certificates(id, unreadable))?;
    Ok(Some(ServiceState { service_type, status, from, certificates }))
}

fn pointer(n: Node<'_, '_>, unreadable: &mut usize) -> Result<Option<ListPointer>, TrustedListError> {
    let Some(location) = child_text(n, "TSLLocation") else { return Ok(None) };
    let mut p = ListPointer { location, territory: None, mime_type: None, signers: Vec::new() };
    if let Some(ids) = child(n, "ServiceDigitalIdentities") {
        p.signers = certificates(ids, unreadable)?;
    }
    if let Some(info) = child(n, "AdditionalInformation") {
        for other in children(info, "OtherInformation") {
            for c in other.children().filter(|c| c.is_element()) {
                match c.tag_name().name() {
                    "SchemeTerritory" => p.territory = Some(text(c)),
                    "MimeType" => p.mime_type = Some(text(c)),
                    _ => {}
                }
            }
        }
    }
    Ok(Some(p))
}

/// The `SchemeInformationURI` entries of `xml`, in document order, **without any check of its
/// signature**: addresses to look at, never something to believe. The list of lists names its
/// pivots here (see [`crate::trusted_lists`]), and they have to be read before the list itself can
/// be verified; each pivot is then verified on its own.
///
/// Empty when the document is not a Trusted List or cannot be read. Entries that are too long
/// are left out, and no more than a fixed number are returned.
#[must_use]
pub fn unverified_information_uris(xml: &str) -> Vec<String> {
    let Ok(doc) = xmldsig::parse(xml) else { return Vec::new() };
    let root = doc.root_element();
    if !is_tsl(root, "TrustServiceStatusList") {
        return Vec::new();
    }
    let Some(uris) = child(root, "SchemeInformation").and_then(|info| child(info, "SchemeInformationURI")) else { return Vec::new() };
    let mut out: Vec<String> = Vec::new();
    for uri in children(uris, "URI").map(text) {
        if out.len() >= MAX_INFORMATION_URIS {
            break;
        }
        // The same address is given once per language.
        if !uri.is_empty() && uri.len() <= MAX_URI_LEN && !out.contains(&uri) {
            out.push(uri);
        }
    }
    out
}

impl TrustedList {
    /// Verify `xml` as a Trusted List signed by one of `signers` (valid at `now`) and read it.
    ///
    /// # Errors
    /// [`TrustedListError`]: the signature does not verify, the document is not a Trusted List, or
    /// it is too large or too broken to read.
    pub fn parse(xml: &str, signers: &[Certificate], now: Time) -> Result<TrustedList, TrustedListError> {
        Self::read(xml, signers, Some(now))
    }

    /// Verify `xml` as a Trusted List signed by one of `signers`, with the signer's certificate
    /// judged at the time the list says it was issued, and read it. This is for a list from the
    /// past that is one link of a chain (a pivot of the list of lists): its signer may have
    /// expired since, and what it says is believed only as far as the chain goes. A list that
    /// gives no issue time is refused.
    ///
    /// # Errors
    /// [`TrustedListError`], as [`TrustedList::parse`].
    pub fn parse_as_issued(xml: &str, signers: &[Certificate]) -> Result<TrustedList, TrustedListError> {
        Self::read(xml, signers, None)
    }

    /// `at`: when the signer must have been valid, or `None` for the list's own issue time.
    fn read(xml: &str, signers: &[Certificate], at: Option<Time>) -> Result<TrustedList, TrustedListError> {
        let doc = xmldsig::parse(xml)?;
        let root = doc.root_element();
        let at = match at {
            Some(t) => t,
            // Read before the signature is checked, and covered by it once it is.
            None => child(root, "SchemeInformation")
                .filter(|_| is_tsl(root, "TrustServiceStatusList"))
                .and_then(|info| child_text(info, "ListIssueDateTime"))
                .and_then(|t| datetime(&t))
                .ok_or_else(|| TrustedListError::Malformed("no issue time".into()))?,
        };
        let signer = xmldsig::verify_enveloped(&doc, xml, signers, at)?;
        if !is_tsl(root, "TrustServiceStatusList") {
            return Err(TrustedListError::NotATrustedList);
        }
        let info = child(root, "SchemeInformation").ok_or_else(|| TrustedListError::Malformed("no SchemeInformation".into()))?;
        let number = |name: &str| child_text(info, name).and_then(|t| t.parse::<u64>().ok());
        let scheme = SchemeInfo {
            version: number("TSLVersionIdentifier")
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| TrustedListError::Malformed("no version".into()))?,
            sequence_number: number("TSLSequenceNumber").ok_or_else(|| TrustedListError::Malformed("no sequence number".into()))?,
            list_type: child_text(info, "TSLType").unwrap_or_default(),
            operator: child(info, "SchemeOperatorName").map(|n| localized(n, "Name")).unwrap_or_default(),
            territory: child_text(info, "SchemeTerritory").unwrap_or_default(),
            issued: child_text(info, "ListIssueDateTime").and_then(|t| datetime(&t)),
            next_update: child(info, "NextUpdate").and_then(|n| child_text(n, "dateTime")).and_then(|t| datetime(&t)),
        };
        let mut unreadable = 0usize;
        let mut pointers = Vec::new();
        if let Some(list) = child(info, "PointersToOtherTSL") {
            for p in children(list, "OtherTSLPointer") {
                if pointers.len() >= MAX_ITEMS {
                    return Err(TrustedListError::Malformed("too many pointers".into()));
                }
                pointers.extend(pointer(p, &mut unreadable)?);
            }
        }
        let mut providers = Vec::new();
        let mut items = 0usize;
        if let Some(list) = child(root, "TrustServiceProviderList") {
            for p in children(list, "TrustServiceProvider") {
                let name = child(p, "TSPInformation").and_then(|i| child(i, "TSPName")).map(|n| localized(n, "Name")).unwrap_or_default();
                let mut services = Vec::new();
                for s in child(p, "TSPServices").into_iter().flat_map(|l| children(l, "TSPService")) {
                    items += 1;
                    if items > MAX_ITEMS {
                        return Err(TrustedListError::Malformed("too many services".into()));
                    }
                    let Some(current) = child(s, "ServiceInformation") else { continue };
                    let service_name = child(current, "ServiceName").map(|n| localized(n, "Name")).unwrap_or_default();
                    let mut states = Vec::new();
                    for h in child(s, "ServiceHistory").into_iter().flat_map(|l| children(l, "ServiceHistoryInstance")) {
                        states.extend(state(h, &mut unreadable)?);
                    }
                    states.extend(state(current, &mut unreadable)?);
                    states.sort_by_key(|s| s.from);
                    if states.len() > MAX_CERTS_PER_ITEM * 16 {
                        return Err(TrustedListError::Malformed("too many states in one service".into()));
                    }
                    services.push(TrustService { name: service_name, states });
                }
                providers.push(TrustServiceProvider { name, services });
            }
        }
        Ok(TrustedList { scheme, pointers, providers, signer, unreadable_certificates: unreadable })
    }

    /// Whether `now` is past the list's `NextUpdate`. A list with no `NextUpdate` never is.
    #[must_use]
    pub fn is_expired(&self, now: Time) -> bool {
        self.scheme.next_update.is_some_and(|n| n < now)
    }

    /// The certificates that anchor trust in qualified certificates at time `t`: those of the
    /// certification authority services of type [`CA_QC`] whose status was "granted" then.
    #[must_use]
    pub fn qualified_roots_at(&self, t: Time) -> Vec<QualifiedRoot<'_>> {
        let mut out = Vec::new();
        for provider in &self.providers {
            for service in &provider.services {
                if let Some(s) = service.state_at(t).filter(|s| s.service_type == CA_QC && s.is_granted()) {
                    out.extend(s.certificates.iter().map(|certificate| QualifiedRoot { certificate, provider, service }));
                }
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn datetimes_are_read_as_utc() {
        let t = |y, mo, d, h, mi, s| Time { year: y, month: mo, day: d, hour: h, minute: mi, second: s };
        assert_eq!(datetime("2026-04-01T00:00:00Z"), Some(t(2026, 4, 1, 0, 0, 0)));
        assert_eq!(datetime(" 2026-04-01T10:20:30.987Z "), Some(t(2026, 4, 1, 10, 20, 30)));
        assert_eq!(datetime("2026-04-01T10:00:00"), Some(t(2026, 4, 1, 10, 0, 0)));
        assert_eq!(datetime("2026-04-01T10:00:00+02:00"), Some(t(2026, 4, 1, 8, 0, 0)));
        assert_eq!(datetime("2026-01-01T01:00:00+02:30"), Some(t(2025, 12, 31, 22, 30, 0)));
        assert_eq!(datetime("2026-04-01T10:00:00-05:00"), Some(t(2026, 4, 1, 15, 0, 0)));
        for bad in [
            "",
            "2026-04-01",
            "T",
            "2026-13-01T00:00:00Z",
            "2026-04-32T00:00:00Z",
            "0000-01-01T00:00:00Z",
            "2026-04-01T25:00:00Z",
            "2026-04-01T00:00Z",
            "x-y-zT0:0:0Z",
            "2026-04-01T00:00:00+2",
        ] {
            assert_eq!(datetime(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_service_is_judged_by_the_state_in_force_then() {
        let st = |status: &str, y| ServiceState {
            service_type: CA_QC.into(),
            status: status.into(),
            from: Time { year: y, month: 1, day: 1, hour: 0, minute: 0, second: 0 },
            certificates: Vec::new(),
        };
        let service = TrustService { name: "s".into(), states: vec![st(GRANTED[0], 2016), st("withdrawn", 2020), st(GRANTED[1], 2024)] };
        let at = |y| Time { year: y, month: 6, day: 1, hour: 0, minute: 0, second: 0 };
        assert!(service.state_at(at(2015)).is_none());
        assert!(service.state_at(at(2017)).unwrap().is_granted());
        assert!(!service.state_at(at(2021)).unwrap().is_granted());
        assert!(service.state_at(at(2030)).unwrap().is_granted());
    }
}
