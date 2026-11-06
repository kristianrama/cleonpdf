//! Outbound network requests, in one place.
//!
//! This is the only crate that opens sockets. Nothing here runs on its own: a request is made
//! when the user asks for something that needs one (checking for updates, signing with a
//! timestamp server) and never in the background. There is no built-in server address: a
//! timestamp server is whatever the user types.
//!
//! - [`agent`]: the HTTPS client, over rustls with the operating system's trusted roots.
//! - [`HttpTimestampAuthority`]: an RFC 3161 client for [`cleonpdf_sign::TimestampAuthority`].
//!
//! Everything a server answers is untrusted: bodies are size-capped, requests time out, and
//! errors name the host but never the path or query (which may carry a token).
//!
//! The browser build has no sockets, so the client is absent there and
//! [`HttpTimestampAuthority::new`] says so.

use std::time::Duration;

use cleonpdf_sign::{SignError, TimestampAuthority};

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
    let url = url.trim();
    if url.is_empty() {
        return Err("the timestamp server address is empty".into());
    }
    if url.len() > MAX_URL {
        return Err(format!("the timestamp server address is longer than {MAX_URL} bytes"));
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("the timestamp server address has spaces or control characters".into());
    }
    let rest = ["http://", "https://"]
        .iter()
        .find_map(|scheme| {
            let head = url.get(..scheme.len())?;
            head.eq_ignore_ascii_case(scheme).then(|| url.get(scheme.len()..))?
        })
        .ok_or("the timestamp server address must start with http:// or https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err("the timestamp server address can't carry a user name or password".into());
    }
    if host_of(url).is_none() {
        return Err("the timestamp server address has no host".into());
    }
    Ok(url.to_string())
}

/// The host (and port) of an address that passed [`check_url`], for messages.
fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    (!authority.is_empty() && !authority.starts_with(':')).then_some(authority)
}

/// The HTTPS client: rustls with the certificate authorities the operating system trusts, a
/// global timeout, and a short redirect limit. There is no bundled root list.
#[cfg(not(target_arch = "wasm32"))]
pub fn agent(timeout: Duration) -> Result<ureq::Agent, String> {
    Ok(ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(MAX_REDIRECTS)
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
        let fail = |what: String| SignError::Transport(format!("{host}: {what}"));
        let agent = agent(self.timeout).map_err(&fail)?;
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
