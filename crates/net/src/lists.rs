//! Trusted List downloads for [`cleonpdf_sign::trusted_lists`].
//!
//! The addresses come from the list of lists, and the lists are signed, so what a server sends is
//! believed only if its signature verifies; the transport still treats the addresses as untrusted
//! (the same host checks as [`HttpRevocationFetcher`]: no loopback, private or link-local
//! hosts, on every redirect too) and reads at most the size the caller allows.

use std::time::Duration;

use cleonpdf_sign::SignError;
use cleonpdf_sign::trusted_lists::ListFetcher;

use crate::HttpRevocationFetcher;

/// Fetches Trusted Lists (GET) over HTTP(S). A list is a few megabytes, and the whole refresh
/// takes one request for the list of lists and one for each country, so the time limit per
/// request is longer than for revocation evidence.
#[derive(Clone, Debug)]
pub struct HttpListFetcher {
    inner: HttpRevocationFetcher,
}

impl Default for HttpListFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpListFetcher {
    /// A fetcher that goes only to public hosts.
    pub fn new() -> Self {
        Self { inner: HttpRevocationFetcher::new().with_timeout(Duration::from_secs(60)) }
    }

    /// Allow hosts on private, loopback and link-local addresses (for tests and a mirror kept
    /// on the company network).
    #[must_use]
    pub fn allow_private_hosts(mut self, allow: bool) -> Self {
        self.inner = self.inner.allow_private_hosts(allow);
        self
    }

    /// The same fetcher with another time limit per request.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.with_timeout(timeout);
        self
    }
}

impl ListFetcher for HttpListFetcher {
    fn fetch(&self, url: &str, max_bytes: u64) -> Result<String, SignError> {
        let bytes = self.inner.fetch("the Trusted List address", url, None, max_bytes)?;
        String::from_utf8(bytes)
            .map_err(|_| SignError::Transport(format!("{}: the list is not UTF-8 text", crate::host_of(url).unwrap_or("the server"))))
    }
}
