# XML signature test data

Made for these tests with OpenSSL 3, Python `lxml` 6 and `signxml` 5 (an implementation unrelated to the
code under test) and `cryptography` for the two hand-built signatures. The keys protect nothing. Regenerate
any file and its certificate together: each run creates new keys.

| File | What |
|---|---|
| `doc.xml` | the unsigned document: prefixes, an unused namespace, a re-declared prefix, a comment, a CDATA section, entities, a processing instruction, `xml:lang` |
| `doc.exc.c14n`, `doc.inc.c14n` | its canonical form (exclusive and inclusive), from libxml2 |
| `inner.exc.c14n`, `inner.inc.c14n` | the canonical form of the inner `ns:Inner` element on its own |
| `rsa.der`, `ec.der`, `other.der`, `old.der` | the signers' certificates (`old.der` is valid for one day only) |
| `rsa-sha256-exc.xml`, `rsa-sha256-inc.xml`, `rsa-sha512-exc.xml` | `doc.xml` with an enveloped RSA signature by `rsa.der` (exclusive or inclusive canonicalization, SHA-256 or SHA-512), by `#root` |
| `ec-sha256-exc.xml`, `ec-sha256-inc.xml` | the same, ECDSA P-256 by `ec.der` |
| `other-signer.xml` | signed by `other.der` |
| `rsa-sha256-emptyuri.xml` | signed with `URI=""` |
| `rsa-sha256-partial.xml` | a valid signature that covers only the `i1` element |
