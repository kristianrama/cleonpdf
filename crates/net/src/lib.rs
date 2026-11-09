//! Outbound network requests, in one place.
//!
//! This is the only crate that opens sockets. Nothing here runs on its own: a request is made
//! when the user asks for something that needs one (checking for updates, signing with a
//! timestamp server) and never in the background. There is no built-in server address: a
//! timestamp server is whatever the user types.
//!
//! - [`agent`]: the HTTPS client, over rustls with the operating system's trusted roots.
//! - [`HttpTimestampAuthority`]: an RFC 3161 client for [`cleonpdf_sign::TimestampAuthority`].
//! - [`HttpRevocationFetcher`]: OCSP and CRL downloads for [`cleonpdf_sign::ltv`]. Unlike a
//!   timestamp server, these addresses come from certificates (so from whoever made them), and
//!   the fetcher refuses loopback, private and link-local hosts unless told otherwise.
//!
//! Everything a server answers is untrusted: bodies are size-capped, requests time out, and
//! errors name the host but never the path or query (which may carry a token).
//!
//! The browser build has no sockets, so the client is absent there and
//! [`HttpTimestampAuthority::new`] says so.

use std::time::Duration;

use cleonpdf_sign::{SignError, TimestampAuthority};

mod lists;
mod revocation;
pub use lists::HttpListFetcher;
pub use revocation::{HttpRevocationFetcher, MAX_EVIDENCE, is_public};

/// The most bytes read from a timestamp server's answer. A token with its certificate chain is a
/// few kilobytes.
pub const MAX_RESPONSE: u64 = 1 << 20;
/// How long one request may take, from connecting to the last byte.
pub const TIMEOUT: Duration = Duration::from_secs(20);
/// The longest server address accepted.
const MAX_URL: usize = 2048;
/// How many redirects a request follows.
const MAX_REDIRECTS: u32 = 3;

/// The server address checked and ready to use: `http://` or `https://`, a host, no user name
/// or password in it, no spaces or control characters, at most 2,048 bytes. Returned without
/// surrounding whitespace.
pub fn check_url(url: &str) -> Result<String, String> {
    check_address("the timestamp server address", url)
}

/// [`check_url`] for any kind of server; `what` starts the messages ("the OCSP address").
pub(crate) fn check_address(what: &str, url: &str) -> Result<String, String> {
    let url = url.trim();
    if url.is_empty() {
        return Err(format!("{what} is empty"));
    }
    if url.len() > MAX_URL {
        return Err(format!("{what} is longer than {MAX_URL} bytes"));
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!("{what} has spaces or control characters"));
    }
    let rest = ["http://", "https://"]
        .iter()
        .find_map(|scheme| {
            let head = url.get(..scheme.len())?;
            head.eq_ignore_ascii_case(scheme).then(|| url.get(scheme.len()..))?
        })
        .ok_or_else(|| format!("{what} must start with http:// or https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(format!("{what} can't carry a user name or password"));
    }
    if host_of(url).is_none() {
        return Err(format!("{what} has no host"));
    }
    Ok(url.to_string())
}

/// The host (and port) of an address that passed [`check_url`], for messages.
pub(crate) fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    (!authority.is_empty() && !authority.starts_with(':')).then_some(authority)
}

/// The HTTPS client: rustls with the certificate authorities the operating system trusts, a
/// global timeout, and a short redirect limit. There is no bundled root list.
#[cfg(not(target_arch = "wasm32"))]
pub fn agent(timeout: Duration) -> Result<ureq::Agent, String> {
    client(timeout, MAX_REDIRECTS, true)
}

/// The same client with `redirects` followed by it (0: the caller reads a 3xx itself, so it can
/// check where it points before going there).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn client(timeout: Duration, redirects: u32, redirects_error: bool) -> Result<ureq::Agent, String> {
    Ok(ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(redirects)
        .max_redirects_will_error(redirects_error)
        .tls_config(ureq::tls::TlsConfig::builder().root_certs(os_roots()?).build())
        .build()
        .new_agent())
}

/// The certificate authorities the operating system trusts.
#[cfg(not(target_arch = "wasm32"))]
fn os_roots() -> Result<ureq::tls::RootCerts, String> {
    let found = rustls_native_certs::load_native_certs();
    let certs: Vec<ureq::tls::Certificate<'static>> = found.certs.iter().map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned()).collect();
    if certs.is_empty() {
        return Err("no trusted certificates found on this system".into());
    }
    Ok(ureq::tls::RootCerts::new_with_certs(&certs))
}

/// Most certificates read from the system's store. Real stores hold a few hundred; a store with
/// more than this is cut here rather than loaded without bound.
pub const MAX_SYSTEM_ROOTS: usize = 5_000;

/// The root certificates the operating system trusts, for validating signatures when the user
/// asks to trust them (Acrobat: Windows Integration), and how many entries of the store could
/// not be read as certificates. Nothing is requested from the network. The store is the one the
/// platform keeps for TLS, so the caller decides whether that is what it wants to trust
/// documents' signers with.
///
/// # Errors
/// A system with no store, or an empty one, and the browser, which has none to read.
pub fn system_certificates() -> Result<(Vec<cleonpdf_sign::Certificate>, usize), String> {
    let der = system_roots()?;
    let total = der.len();
    let certs: Vec<cleonpdf_sign::Certificate> = der.iter().filter_map(|d| cleonpdf_sign::Certificate::parse(d).ok()).collect();
    if certs.is_empty() {
        return Err("none of the system's trusted certificates could be read".into());
    }
    let unreadable = total - certs.len();
    Ok((certs, unreadable))
}

fn system_roots() -> Result<Vec<Vec<u8>>, String> {
    #[cfg(target_arch = "wasm32")]
    {
        Err("the browser has no list of trusted certificates to read".into())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let found = rustls_native_certs::load_native_certs();
        let certs: Vec<Vec<u8>> = found.certs.iter().take(MAX_SYSTEM_ROOTS).map(|c| c.as_ref().to_vec()).collect();
        if certs.is_empty() {
            return Err("no trusted certificates found on this system".into());
        }
        Ok(certs)
    }
}

/// An RFC 3161 timestamp server reached over HTTP(S): the request is POSTed as
/// `application/timestamp-query` and the answer read as `application/timestamp-reply`.
///
/// The answer is only bytes here; the signer checks the token (imprint, the TSA's signature)
/// before it is embedded, so a server that lies is refused there.
#[derive(Clone, Debug)]
pub struct HttpTimestampAuthority {
    url: String,
    timeout: Duration,
}

impl HttpTimestampAuthority {
    /// A client for the server at `url` (see [`check_url`] for what is accepted).
    pub fn new(url: &str) -> Result<Self, String> {
        if cfg!(target_arch = "wasm32") {
            return Err("timestamp servers can't be reached from the browser".into());
        }
        Ok(Self { url: check_url(url)?, timeout: TIMEOUT })
    }

    /// The time limit of one request.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The same client with another time limit per request.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The server's host (and port), for messages.
    pub fn host(&self) -> &str {
        host_of(&self.url).unwrap_or("the timestamp server")
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TimestampAuthority for HttpTimestampAuthority {
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, SignError> {
        let host = self.host();
        let fail = |what: String| SignError::Transport(format!("timestamp server {host}: {what}"));
        let agent = agent(self.timeout).map_err(fail)?;
        let mut response = agent
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .header("User-Agent", concat!("CleonPDF/", env!("CARGO_PKG_VERSION")))
            // Read the status ourselves: the message should say what the server answered.
            .config()
            .http_status_as_error(false)
            .build()
            .send(request)
            .map_err(|e| fail(format!("couldn't be reached ({e})")))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(fail(format!("answered with http status {status}")));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE)
            .read_to_vec()
            .map_err(|e| fail(format!("sent an unreadable or oversized answer ({e})")))?;
        if body.is_empty() {
            return Err(fail("sent an empty answer".into()));
        }
        Ok(body)
    }
}

#[cfg(target_arch = "wasm32")]
impl TimestampAuthority for HttpTimestampAuthority {
    fn timestamp(&self, _request: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError::Transport("timestamp servers can't be reached from the browser".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_http_and_https_server_addresses_are_accepted() {
        for ok in
            ["http://timestamp.example.com", "https://tsa.example.org/tsr", "HTTPS://TSA.Example.org:8443/a?b=c", "  http://localhost:3000/ts  "]
        {
            assert!(check_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "   ",
            "timestamp.example.com",
            "ftp://tsa.example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "http://",
            "https:///path",
            "http://:80/x",
            "http://user:secret@tsa.example.com/",
            "http://tsa.example.com@evil.example.org/",
            "http://tsa .example.com/",
            "http://tsa.example.com/\nx",
            "http://tsa.example.com/\u{0}x",
        ] {
            assert!(check_url(bad).is_err(), "{bad:?}");
        }
        assert!(check_url(&format!("http://h/{}", "a".repeat(MAX_URL))).is_err());
        // Multi-byte text where the scheme should be never splits a character.
        assert!(check_url("h\u{e9}ttp://x").is_err());
        assert!(check_url("\u{1F600}\u{1F600}\u{1F600}").is_err());
    }

    #[test]
    fn messages_name_the_host_and_never_the_path_or_query() {
        let tsa = HttpTimestampAuthority::new("https://tsa.example.com:8443/secret/path?token=abc").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(tsa.host(), "tsa.example.com:8443");
    }
}
