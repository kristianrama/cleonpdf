# cleonpdf-net

Layer L5: outbound network requests, in one crate. It is the only crate that opens sockets, so
"what does this app send over the network?" has one place to look.

- `agent(timeout)`: the HTTPS client, rustls with the operating system's trusted roots (no
  bundled root list). Used by Help ▸ Check for updates.
- `HttpTimestampAuthority::new(url)`: an RFC 3161 timestamp client for
  `cleonpdf_sign::TimestampAuthority`. The query is POSTed as `application/timestamp-query`; the
  answer is only bytes here, and the signer checks the token (imprint, the TSA's signature)
  before embedding it, so a server that lies is refused there.

- `HttpRevocationFetcher`: OCSP (POST, `application/ocsp-request`) and CRL (GET) downloads, and the issuer certificate a `caIssuers` address names (GET), for
  `cleonpdf_sign::ltv`. Their addresses are written in certificates, so whoever made a
  certificate chooses where the request goes. By default a host that is, or resolves to, a
  loopback, private, link-local, shared (CGNAT) or other non-public address is refused, on every
  redirect too; `allow_private_hosts(true)` is for a company's own PKI. Redirects are read and
  checked one by one (three at most; a POST is not replayed after a 301/302/303). Behind a proxy
  the proxy resolves the name, so this guards against crafted addresses and is not a firewall.

- `HttpListFetcher`: Trusted List downloads (GET, up to the size the caller allows, 48 MiB for the
  EU lists) for `cleonpdf_sign::trusted_lists`. The same host checks and redirect handling as the
  revocation fetcher. What it brings is believed only if its XML signature verifies, which
  `cleonpdf_sign` checks; a request is made only when the user asks to update the lists.

Rules:

- **Nothing runs on its own.** A request is made when the user asks for something that needs one
  (check for updates, sign with a timestamp server, add validation information). No background
  polling, no telemetry; opening or validating a document never makes a request.
- **No built-in server.** A timestamp server is whatever the user types; the address must be
  `http://` or `https://`, with a host, no user name or password, no spaces or control characters,
  at most 2,048 bytes (`check_url`).
- **Answers are untrusted.** 20 s limit per request, three redirects, the body capped at 1 MiB,
  an empty answer refused (revocation answers: 2 MiB). Messages name the host, never the path or query (which may carry a
  token).
- **Not in the browser.** A page can't open sockets; on `wasm32` the client is absent and
  `HttpTimestampAuthority::new` says so.

Tests (`tests/timestamp_server.rs`) run a real HTTP exchange against a server on the loopback
interface that answers with a real RFC 3161 token: the request's method, headers and body, the
token round trip, a 503, an empty answer, an oversized answer, a server that never answers, and a
closed port. `tests/revocation_server.rs` does the same for OCSP and CRL requests (method,
content type, redirects, status codes, size cap) and checks that the default fetcher never connects
to a loopback server. No test touches the internet; a check against a real public TSA is still to do.
