# TLS certificate chains

Made for `src/tls.rs`'s tests with Python `cryptography` (the keys are thrown away; regenerate the
whole set together). Each leaf is a server certificate for `tl.example.test`, valid 2026–2036.

| File | What |
|---|---|
| `root-p384.der`, `root-p521.der`, `root-p256.der` | self-signed ECDSA authorities on P-384, P-521 and P-256 |
| `leaf-p384-sha512.der` | issued by `root-p384` with ECDSA and SHA-512, as Hungary's Trusted List host is |
| `leaf-p384-sha384.der` | the same with SHA-384, which `ring` checks on its own |
| `leaf-p521-sha256.der`, `leaf-p521-sha384.der`, `leaf-p521-sha512.der` | issued by `root-p521` with each hash |
| `leaf-p256-sha512.der` | issued by `root-p256` with SHA-512 |
| `leaf-p384-sha512-impostor.der` | names `root-p384` as its issuer but is signed by another P-384 key |
