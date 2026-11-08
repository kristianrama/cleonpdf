# cleonpdf-sign

Layer L4: digital signatures (execution plan M9; ISO 32000-2 §12.8; PAdES, ETSI EN 319 142).

```rust
let id = pkcs12::open(&std::fs::read("me.p12")?, "password")?;          // a digital ID
let signed = sign(&doc, &id, &SignOptions { page: 0, rect: Some(r), date, ..Default::default() })?;
for s in signatures(&doc, &bytes, &trust) {                                // list + validate
    println!("{}: {} — {:?}", s.field, s.summary(), s.details);
}
```

- **Formats, on RustCrypto primitives:** a small DER reader and writer (`der`), X.509
  certificates (`x509`), CMS SignedData (`cms`), and PKCS #12 digital ID files (`pkcs12`):
  PBES2 (PBKDF2 + AES/3DES), the legacy SHA-1 3DES/RC2 schemes, and MAC checks. Writing uses
  OpenSSL 3's defaults (AES-256-CBC, HMAC-SHA-256).
- **Keys:** RSA, ECDSA P-256 and P-384. Verification uses RustCrypto everywhere. RSA
  private-key operations (signing, key generation) use `aws-lc-rs` on native targets and are
  refused in the browser (ADR-0009: the `rsa` crate's Marvin advisory, RUSTSEC-2023-0071, has
  no fix, so `rsa` is only used to verify). ECDSA signs with deterministic nonces (RFC 6979).
- **Signing:** PAdES B-B (`ETSI.CAdES.detached`, signing-certificate-v2, SHA-256/384, no SHA-1).
  An existing unsigned field or a new one (visible with Acrobat's name-and-details appearance,
  or invisible); certification with DocMDP P=1/2/3. A visible signature can show a `Graphic`
  where the large name would be: drawn strokes, filled outlines (a typed signature) or RGBA
  pixels (an image XObject with a soft mask), checked and size-capped first. The document is written incrementally
  with a zero-filled `/Contents` and fixed-width `/ByteRange`, which are then patched in
  place. Encrypted documents are refused for now.
- **Timestamps (PAdES B-T):** the `timestamp` module builds and parses RFC 3161 requests,
  responses and TSTInfo tokens (size-capped, imprint- and signature-checked). `sign_with_timestamp`
  attaches the TSA's token as an unsigned attribute over the signature value; the transport is
  the caller's (`TimestampAuthority` — this crate never opens a socket). Validation verifies
  embedded tokens; `TrustStore::system` holds root certificates the operating system trusts (the
  caller reads them; `cleonpdf-net::system_certificates`), kept apart from the user's `certs`: a signer
  chaining to one is valid, and the signature says which system root vouched for it. When the TSA chains to the trust store it reports the trusted time in
  `SignatureInfo::timestamp_time`, which then anchors certificate-validity and revocation
  checks. An untrusted TSA's time is reported as an unverified timestamp and never used as the
  validation time (the signer's claimed time is). `timestamp::respond` is the TSA-side signer behind the
  deterministic test authority.
- **Document timestamps and LTV:** `timestamp_document` appends a standalone RFC 3161
  document timestamp (`/ETSI.RFC3161`) covering the whole file; validation discovers and
  verifies these dictionaries (imprint over the signed bytes, token signature, TSA cert
  validity). `dss::embed` merges revocation evidence into the catalog's `/DSS` with `/VRI`
  entries keyed per signature (uppercase-hex SHA-1 of `/Contents`), deduplicating
  byte-identical blobs — sign → DSS → timestamp makes a B-LTA file, and the change classifier
  treats the store as a permitted change: only objects reached through `/Certs`, `/CRLs`,
  `/OCSPs` and `/VRI` with the shape of their role, and new or only grown since the signature,
  count (a `/DSS` entry naming a page's contents, or a `/Type /DSS` label, does not).
  `revocation` parses and verifies RFC 5280 CRLs and
  RFC 6960 OCSP responses (responder identity, OCSP-signing EKU for delegated responders,
  CertID hash matching, validity windows); validation checks embedded evidence against the
  signer's chain and a verified revocation invalidates the signature.

- **Gathering evidence (PAdES B-LT):** `ltv::gather` takes the signers' chains and a
  `RevocationFetcher` (this crate never opens a socket; `cleonpdf-net` is the HTTP one). For
  each certificate below a root it asks the OCSP responders the certificate names, then its CRL
  addresses (http and https only, three each), and keeps an answer only if `revocation` verifies
  it and it is current. The result is `Evidence` for `dss::embed`, with a note per certificate:
  fetched (OCSP or CRL), revoked, or missing with the reason. The OCSP request carries only the
  issuer hash and serial number. The addresses come from the certificates, which is why the
  transport, not this crate, decides which hosts to talk to.

`SignatureInfo::timestamp_chain` is the timestamp authority's chain (of a signature's token or of a
document timestamp), built at validation time whether or not it is trusted; hand it to `ltv::gather`
beside the signer's `chain`, so the file also carries proof that the authority was not revoked.

`ltv::gather` also completes a chain that stops short of its issuer: it asks the certificate's
`caIssuers` address (`RevocationFetcher::issuer`; a DER certificate or a certificates-only CMS bundle),
keeps a download only if its name matches and its key verifies the certificate below, and stops at a
self-signed root or ten certificates.

`pkcs11` (not on wasm) loads a PKCS #11 module with `cryptoki` and lists the tokens it shows and the
certificates on them, with no PIN, and `Module::identity` / `pkcs11::find` open a token certificate as a
`DigitalId`: the PIN logs in, the private key stays on the token (`ExternalKey`: RSA PKCS #1 over the
DigestInfo, ECDSA over the digest; tested with RSA-2048 and P-256) and the token's answer is checked against the
certificate's key before it is used. `pkcs11::list(extra)` gives the end-entity certificates of every
candidate module (`candidates(extra)`: the user's, the configured and the known ones, each once) for the
app's Sign dialog, and `find_in(extra, …)` is `find` over the same set. A module is code that runs in the process, so its path comes only
from the user or from the system's known locations (`is_allowed`, `known_modules`,
`configured_modules` / `CLEONPDF_PKCS11_MODULES`), never from a document. Tested against SoftHSM
(`tests/pkcs11.rs`, which runs when `CLEONPDF_TEST_PKCS11_MODULE` and `SOFTHSM2_CONF` are set; CI sets them).

Form-field locks (FieldMDP): `SignOptions::lock` (a `FieldLock`: all, include or exclude fields by full name) or the signature field's own `/Lock` writes a `/Reference` with `/TransformMethod /FieldMDP` and, on a field signed with a caller's list, the field's `/Lock`. A caller's list must name fields the form has and can't replace a field's own lock. Validation reads `SignatureInfo::field_locks` and reports `kind::LOCKED_FIELDS` when a locked field (or a widget, or a value it inherits from a parent) differs from the signed revision, goes missing, or, under all/exclude, a field is added. Names are matched exactly; a parent's name covers the fields below it. Tested in `tests/field_lock.rs`.

Not yet: certificate security.
macOS Keychain and Windows Current User Personal (My) store identities sign through
`ExternalKey` without exporting private keys. Windows CNG supports RSA PKCS #1 v1.5 and
ECDSA P-256/P-384; the store integration is tested with software-backed keys. A smart card
or token whose driver registers a CNG key storage provider is such an identity too: the key
is opened for signing without the silent flag, so the provider shows its own PIN dialog
(checked by hand with a SafeNet token; CI has no hardware). A store identity signs with the
issuers Windows chains its certificate to, without the root. Store certificates that can't
sign (no private key, another key type, a key CNG can't open) are returned by
`windows::list` as `unusable` with the reason and the Windows error code, shown greyed in
the Sign dialog and by `sign_windows_ids`, instead of being left out silently; a key that
needs a prompt to open is listed and asks at signing (issue #179).
- **Validation:** `/ByteRange` and the CMS are read from the file's own bytes; the digest,
  the signature value and the signer's chain (against a `TrustStore`) are checked. Later
  revisions are diffed against the signed one, and the changes are classified (signing, form
  fill, comments, metadata, page content, document structure) under the DocMDP permissions.
  The verdict follows Acrobat: valid, unknown (intact but the identity isn't trusted) or invalid.
- **Chains are checked, not just linked.** `x509::build_chain` only takes an issuer whose key
  verifies the certificate below it *and* that may issue: `basicConstraints` CA:TRUE (an old v1
  self-signed root without constraints counts), `keyCertSign` when it has a key usage, a
  `pathLenConstraint` that allows the CAs below it, and, given the signing time, validity then.
  Certificates embedded in a document are in the pool too, so an ordinary subscriber certificate
  can never vouch for another one; when an issuer is refused, the signature's details say why.
- **The signer's certificate must allow signing documents** (`Certificate::signing_problem`): a
  key usage needs digitalSignature or nonRepudiation, an extended key usage needs a
  document-signing purpose (any, emailProtection, codeSigning, RFC 9336 documentSigning, Adobe
  Authentic Documents, Microsoft document signing), and no critical extension may be one CleonPDF
  doesn't process. Otherwise the verdict is unknown, never valid, and the details say why.
- **BER as well as DER.** The CMS is read with `der::Tlv::parse_ber`, as Windows CryptoAPI, Adobe
  PPKMS, DocuSign, Documenso and `openssl cms -stream` write it: indefinite lengths and an
  OCTET STRING split into segments. Only the structure is read that way; certificates and signed
  attributes are still verified over their own exact bytes (signed attributes written with an
  indefinite length are re-encoded as DER first, as RFC 5652 §5.4 has them signed). Nesting is
  bounded, and the details say that the signature was BER. High tag numbers are not read.
- **Later changes are classified narrowly.** Only the catalog's own `/Metadata` stream is the
  document's XMP, and only objects reached through the `/DSS` keys above are the security store. A
  `/Type /Metadata` or `/Type /DSS` *label* on any other dictionary or stream (a page's Form
  XObject, say) makes nothing permitted, at every DocMDP level.
- **Strict in what it checks, tolerant where signers differ.** RSA PKCS #1 signatures are checked
  against the one encoding the digest should have, built here and compared byte for byte; the
  `DigestInfo` may omit its NULL parameter, as older signers write it (RFC 8017 App. B.1), but a
  signature over the bare digest, which doesn't say which hash it uses, is refused. A signature
  value must be below the modulus (RFC 8017 §5.2.2). RSA-PSS uses the salt length it declares.
  ECDSA is read as DER, non-minimal DER or raw `r ‖ s`. `adbe.x509.rsa_sha1` is validated. What the
  check tolerated is listed in the signature's details: a DigestInfo without its NULL, an RSA value
  that isn't modulus-length, ECDSA that isn't canonical DER, a SignerInfo whose digest algorithm
  differs from the one the signature algorithm names. What CleonPDF can't check (an unknown
  algorithm or curve) is *unknown*, never *invalid*.
- **Weak algorithms still validate, and say so.** SHA-1 and RIPEMD-160 signatures are common in
  documents signed years ago, so they validate (new signatures never use SHA-1), but the signature's
  details say that the algorithm is weak and shouldn't be relied on.
- **Validation algorithms:** digests SHA-1, SHA-224/256/384/512, SHA-512/224, SHA-512/256,
  SHA3-224/256/384/512 and RIPEMD-160. RSA PKCS #1 v1.5 and RSASSA-PSS (the hash, MGF1 hash and
  salt length the signature declares), ECDSA on P-256, P-384, P-521, brainpoolP256r1, P384r1 and
  P512r1 (also BSI "plain" ECDSA), and Ed25519 (RFC 8419, over the signed attributes).
  Signing: RSA, P-256, P-384 with SHA-256/384/512. The RSA padding checks and brainpoolP512r1 are
  written here (`rsa_pad`, `ec512`) on `crypto-bigint`, because the typed APIs of the `rsa` crate
  and RustCrypto don't cover them.

Oracles: poppler's `pdfsig` reports our signatures valid; OpenSSL reads our `.p12` files and
verifies our CMS; `tests/data/openssl-signed.pdf` is a signature OpenSSL made, which we validate.
