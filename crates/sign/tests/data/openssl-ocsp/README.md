# OCSP responses made by OpenSSL

An independent encoder for `revocation::OcspResponse`: the helpers in `tests/support/pki.rs` are
written alongside the parser, and once agreed with it on an INTEGER where RFC 6960 has an
ENUMERATED (`responseStatus`). Real responders (ArubaPEC's) send the ENUMERATED.

Made with OpenSSL 3.0 on 2026-11-12 (keys thrown away):

- `ca.pem`: a self-signed RSA 2048 CA, which also signs the responses.
- `leaf-good.pem` (serial 0x1001), `leaf-revoked.pem` (serial 0x1002): issued by `ca.pem`.
- `good.ocsp`, `revoked.ocsp`: `openssl ocsp -index index.txt -rsigner ca.pem -rkey ca.key -CA ca.pem
  -reqin <request> -respout <file> -ndays 3650`, for requests made with `openssl ocsp -issuer ca.pem
  -cert <leaf> -no_nonce`. The index lists 0x1001 as valid and 0x1002 as revoked on
  2026-11-01 12:00 UTC for keyCompromise (so `revoked.ocsp` carries a `revocationReason`).
  Both: thisUpdate 2026-11-12, nextUpdate 2036-11-09.
