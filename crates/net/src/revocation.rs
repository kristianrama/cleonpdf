//! OCSP and CRL downloads for [`cleonpdf_sign::ltv`].
//!
//! The addresses are written into certificates, so whoever made a certificate chooses where the
//! request goes. A document with a crafted signature could point it at `localhost`, a router or
//! a cloud metadata service. So by default a host that is, or resolves to, a loopback, private,
//! link-local, shared (CGNAT) or otherwise non-public address is refused, in every redirect
//! too. A private PKI whose responders live on the company network opts in with
//! [`HttpRevocationFetcher::allow_private_hosts`].
//!
//! The check is made on the addresses this process resolves, just before the request. Behind a
//! proxy the proxy resolves the name itself, so the check is a guard against crafted addresses,
//! not a firewall: a host this process cannot resolve is left to the proxy.

// The browser build has no sockets: the checks below are only exercised by tests there.
#![cfg_attr(target_arch = "wasm32", allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::time::Duration;

use cleonpdf_sign::SignError;
use cleonpdf_sign::ltv::RevocationFetcher;

#[cfg(not(target_arch = "wasm32"))]
use crate::check_address;
use crate::{TIMEOUT, host_of};

/// The most bytes read from one answer. The signer's parsers refuse anything larger.
pub const MAX_EVIDENCE: u64 = 2 * 1024 * 1024;
/// How many redirects one request follows.
const MAX_HOPS: u32 = 3;

/// Whether `ip` is an address a request from a user's machine may reasonably go to.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => public_v4(v4),
            None => public_v6(v6),
        },
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        // 100.64.0.0/10 shared address space (carrier-grade NAT).
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24 IETF protocol assignments, 198.18.0.0/15 benchmarking, 240/4 reserved.
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fc00::/7 unique local, fe80::/10 link-local.
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        // 2001:db8::/32 documentation.
        || (first == 0x2001 && ip.segments()[1] == 0x0db8))
}

/// A host written as an IPv4 address in one of the old `inet_aton` forms: `2130706433`,
/// `0x7f.1`, `0177.0.0.1`, `127.1`. Some resolvers read these as addresses and some do not, so the
/// guard reads them itself instead of depending on the platform. `None` for anything that is not
/// all numbers (a name).
fn legacy_ipv4(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut numbers = Vec::with_capacity(parts.len());
    for part in &parts {
        if part.is_empty() {
            return None;
        }
        let (digits, radix) = match part.get(..2) {
            Some("0x" | "0X") => (part.get(2..)?, 16),
            _ if part.len() > 1 && part.starts_with('0') => (part.get(1..)?, 8),
            _ => (*part, 10),
        };
        // "0x" alone is zero for inet_aton; keep that reading.
        let digits = if digits.is_empty() { "0" } else { digits };
        numbers.push(u64::from_str_radix(digits, radix).ok()?);
    }
    // All but the last part are one byte; the last fills the rest.
    let (last, head) = numbers.split_last()?;
    let mut value: u64 = 0;
    for n in head {
        if *n > 0xff {
            return None;
        }
        value = (value << 8) | n;
    }
    let free_bits = 8 * (4 - head.len() as u32);
    if free_bits < 64 && *last >> free_bits != 0 {
        return None;
    }
    value = value.checked_shl(free_bits).unwrap_or(0) | last;
    u32::try_from(value).ok().map(Ipv4Addr::from)
}

/// The host and port of an address that passed `check_address`.
fn host_port(url: &str) -> Option<(String, u16)> {
    let authority = host_of(url)?;
    let default = if url.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("https")) { 443 } else { 80 };
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((authority.to_string(), default)),
    }
}

/// Fetches OCSP responses (POST) and CRLs (GET) over HTTP(S).
#[derive(Clone, Debug)]
pub struct HttpRevocationFetcher {
    timeout: Duration,
    allow_private: bool,
}

impl Default for HttpRevocationFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpRevocationFetcher {
    /// A fetcher that goes only to public hosts, with the usual time limit per request.
    pub fn new() -> Self {
        Self { timeout: TIMEOUT, allow_private: false }
    }

    /// Allow hosts on private, loopback and link-local addresses (a company's own responders).
    #[must_use]
    pub fn allow_private_hosts(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }

    /// The same fetcher with another time limit per request.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Refuse an address that is, or resolves to, a non-public host.
    fn guard(&self, url: &str) -> Result<(), String> {
        if self.allow_private {
            return Ok(());
        }
        let (host, port) = host_port(url).ok_or("the address has no usable host")?;
        let refused = || "is not a public address (loopback, private or link-local hosts are refused)".to_string();
        if let Some(ip) = host.parse::<IpAddr>().ok().or_else(|| legacy_ipv4(&host).map(IpAddr::V4)) {
            return if is_public(ip) { Ok(()) } else { Err(refused()) };
        }
        if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
            return Err(refused());
        }
        // A name this process cannot resolve is left to the proxy (if any) or fails to connect.
        if let Ok(addrs) = (host.as_str(), port).to_socket_addrs()
            && addrs.into_iter().any(|a| !is_public(a.ip()))
        {
            return Err(refused());
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn fetch(&self, what: &str, url: &str, post: Option<&[u8]>, limit: u64) -> Result<Vec<u8>, SignError> {
        let mut url = check_address(what, url).map_err(SignError::Transport)?;
        let client = crate::client(self.timeout, 0, false).map_err(|e| SignError::Transport(format!("{what}: {e}")))?;
        for _ in 0..=MAX_HOPS {
            // Messages name the host, never the path or query (which may carry a token).
            let host = host_of(&url).unwrap_or("the server").to_string();
            let fail = |what: String| SignError::Transport(format!("{host}: {what}"));
            self.guard(&url).map_err(fail)?;
            let mut response = match post {
                Some(body) => client
                    .post(&url)
                    .header("Content-Type", "application/ocsp-request")
                    .header("Accept", "application/ocsp-response")
                    .header("User-Agent", concat!("CleonPDF/", env!("CARGO_PKG_VERSION")))
                    .config()
                    .http_status_as_error(false)
                    .build()
                    .send(body),
                None => client
                    .get(&url)
                    .header("User-Agent", concat!("CleonPDF/", env!("CARGO_PKG_VERSION")))
                    .config()
                    .http_status_as_error(false)
                    .build()
                    .call(),
            }
            .map_err(|e| fail(format!("couldn't be reached ({e})")))?;
            let status = response.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                // A POST is repeated as a POST only on 307 and 308, which keep the method.
                if post.is_some() && !matches!(status, 307 | 308) {
                    return Err(fail(format!("answered a request with a redirect (http status {status}) that is not followed")));
                }
                let location =
                    response.headers().get("location").and_then(|v| v.to_str().ok()).ok_or_else(|| fail("redirected without saying where".into()))?;
                let next = if location.starts_with('/') {
                    // A path on the same server.
                    let scheme = if url.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("https")) { "https" } else { "http" };
                    format!("{scheme}://{}{location}", host_of(&url).unwrap_or_default())
                } else {
                    location.to_string()
                };
                url = check_address(what, &next).map_err(SignError::Transport)?;
                continue;
            }
            if status != 200 {
                return Err(fail(format!("answered with http status {status}")));
            }
            let body = response
                .body_mut()
                .with_config()
                .limit(limit)
                .read_to_vec()
                .map_err(|e| fail(format!("sent an unreadable or oversized answer ({e})")))?;
            if body.is_empty() {
                return Err(fail("sent an empty answer".into()));
            }
            return Ok(body);
        }
        Err(SignError::Transport(format!("{}: too many redirects", host_of(&url).unwrap_or("the server"))))
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn fetch(&self, _what: &str, _url: &str, _post: Option<&[u8]>, _limit: u64) -> Result<Vec<u8>, SignError> {
        Err(SignError::Transport("revocation servers can't be reached from the browser".into()))
    }
}

impl RevocationFetcher for HttpRevocationFetcher {
    fn crl(&self, url: &str) -> Result<Vec<u8>, SignError> {
        self.fetch("the CRL address", url, None, MAX_EVIDENCE)
    }

    fn ocsp(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, SignError> {
        self.fetch("the OCSP address", url, Some(request), MAX_EVIDENCE)
    }

    fn issuer(&self, url: &str) -> Result<Vec<u8>, SignError> {
        self.fetch("the issuer certificate address", url, None, MAX_EVIDENCE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_are_public() {
        for ok in ["8.8.8.8", "93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public(ok.parse().unwrap_or_else(|e| panic!("{ok}: {e}"))), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "0.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "198.18.0.1",
            "192.0.0.8",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public(bad.parse().unwrap_or_else(|e| panic!("{bad}: {e}"))), "{bad}");
        }
        // The neighbours of the shared range are public.
        assert!(is_public("100.63.255.255".parse().unwrap_or_else(|e| panic!("{e}"))));
        assert!(is_public("100.128.0.1".parse().unwrap_or_else(|e| panic!("{e}"))));
        assert!(is_public("172.32.0.1".parse().unwrap_or_else(|e| panic!("{e}"))));
    }

    #[test]
    fn old_style_ipv4_spellings_are_read_the_way_resolvers_read_them() {
        let ip = |s: &str| legacy_ipv4(s);
        assert_eq!(ip("2130706433"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(ip("0x7f000001"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(ip("0x7f.1"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(ip("127.1"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(ip("0177.0.0.1"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(ip("10.0.1"), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(ip("169.254.43518"), Some(Ipv4Addr::new(169, 254, 169, 254)));
        assert_eq!(ip("8.8.8.8"), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(ip("0"), Some(Ipv4Addr::UNSPECIFIED));
        // Not numbers, or out of range: not an address.
        for not in ["ocsp.example", "1.2.3.4.5", "256.1.1.1", "4294967296", "1.2.3.", "", "a.b", "08", "0xzz", "1..2"] {
            assert_eq!(ip(not), None, "{not}");
        }
    }

    #[test]
    fn host_and_port_are_read_from_the_address() {
        assert_eq!(host_port("http://ocsp.example/x"), Some(("ocsp.example".into(), 80)));
        assert_eq!(host_port("HTTPS://ocsp.example/x"), Some(("ocsp.example".into(), 443)));
        assert_eq!(host_port("http://ocsp.example:8080/x?y"), Some(("ocsp.example".into(), 8080)));
        assert_eq!(host_port("http://[::1]:9000/x"), Some(("::1".into(), 9000)));
        assert_eq!(host_port("https://[2606:4700::1]/"), Some(("2606:4700::1".into(), 443)));
        assert_eq!(host_port("http://host:notaport/"), None);
    }

    #[test]
    fn crafted_addresses_are_refused_before_any_request() {
        let strict = HttpRevocationFetcher::new();
        for url in [
            "http://127.0.0.1/ocsp",
            "http://localhost:8080/",
            "http://LOCALHOST/",
            "http://foo.localhost/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.0.1/",
            "http://10.1.2.3:5000/",
            "http://[::ffff:127.0.0.1]/",
            // 127.0.0.1 written as one decimal number: the resolver reads it, so the guard does too.
            "http://2130706433/",
            "http://0x7f.1/",
            "http://0177.0.0.1:8080/",
            "http://0/",
        ] {
            assert!(strict.guard(url).is_err(), "{url}");
            let err = strict.ocsp(url, b"x").expect_err("refused").to_string();
            assert!(err.contains("not a public address"), "{url}: {err}");
            assert!(strict.crl(url).is_err(), "{url}");
        }
        assert!(strict.guard("http://8.8.8.8/").is_ok());
        assert!(HttpRevocationFetcher::new().allow_private_hosts(true).guard("http://127.0.0.1/").is_ok());
        // Not web addresses at all.
        for url in ["ldap://dir.example/cn=x", "file:///etc/passwd", "http://user:pw@8.8.8.8/", ""] {
            assert!(strict.crl(url).is_err(), "{url}");
        }
    }
}
