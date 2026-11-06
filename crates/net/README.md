# cleonpdf-net

Layer L5: outbound network requests, in one crate. It is the only crate that opens sockets, so
"what does this app send over the network?" has one place to look.

- `agent(timeout)`: the HTTPS client, rustls with the operating system's trusted roots (no
  bundled root list). Used by Help ▸ Check for updates.
- `HttpTimestampAuthority::new(url)`: an RFC 3161 timestamp client for
  `cleonpdf_sign::TimestampAuthority`. The query is POSTed as `application/timestamp-query`; the
  answer is only bytes here, and the signer checks the token (imprint, the TSA's signature)
  before embedding it, so a server that lies is refused there.

Rules:

- **Nothing runs on its own.** A request is made when the user asks for something that needs one
  (check for updates, sign with a timestamp server). No background polling, no telemetry.
- **No built-in server.** A timestamp server is whatever the user types; the address must be
  `http://` or `https://`, with a host, no user name or password, no spaces or control characters,
  at most 2,048 bytes (`check_url`).
- **Answers are untrusted.** 20 s limit per request, three redirects, the body capped at 1 MiB,
  an empty answer refused. Messages name the host, never the path or query (which may carry a
  token).
- **Not in the browser.** A page can't open sockets; on `wasm32` the client is absent and
  `HttpTimestampAuthority::new` says so.

Tests (`tests/timestamp_server.rs`) run a real HTTP exchange against a server on the loopback
interface that answers with a real RFC 3161 token: the request's method, headers and body, the
token round trip, a 503, an empty answer, an oversized answer, a server that never answers, and a
closed port. No test touches the internet; a check against a real public TSA is still to do.
