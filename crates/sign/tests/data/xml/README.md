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
| `rsa-pss.der` | an RSA 3072 signer for the RSA-PSS files |
| `rsa-pss-sha256-exc.xml`, `rsa-pss-sha384-exc.xml`, `rsa-pss-sha512-exc.xml`, `rsa-pss-sha3-256-exc.xml` | `doc.xml` signed by signxml with RFC 6931's `#<hash>-rsa-MGF1` (RSASSA-PSS, MGF1 with the same hash, salt as long as the hash), as the German Trusted List is |
| `rsa-pss-sha256-salt20.xml` | the SHA-256 one with its value re-made by `cryptography` with a 20-byte salt |

## Trusted Lists

Synthetic lists in the shape of ETSI TS 119 612 (the names, locations and certificates are invented),
signed with XAdES-style enveloped signatures (a reference to the whole document and one to the
`SignedProperties`) by a script on `lxml` and `cryptography`.

| File | What |
|---|---|
| `lotl.xml` | a list of lists (`EU`, sequence 371), signed by `tsl-signer-eu.der` (RSA); points to an `IT` list (signer `tsl-signer-it.der`), a `DE` list (two signers) and a PDF rendering (no signer) |
| `tl-it.xml` | the `IT` list, signed by `tsl-signer-it.der` (ECDSA P-256): two providers; granted, withdrawn-with-history, ceased-with-history and unreadable-certificate services; a qualified time stamping service and a non-qualified CA |
| `tl-it-plain.xml` | the same without the XAdES properties |
| `qca1.der`, `qca2.der`, `qca3.der`, `qca-old.der`, `qtsa.der`, `pkc.der` | the certificates the `IT` list names |

### Pivots of the list of lists

Invented signers `tsl-pivot-a.der` (RSA, 2019–2022), `-b` (P-256, 2020–2024), `-c` (RSA, 2023–2030),
`-d` (P-256, 2025–2032) and `-stranger.der`, made with `cryptography`; the lists are signed like the ones
above. The pivot addresses are `https://ec.europa.eu/tools/lotl/eu-lotl-pivot-N.xml` (served by the tests'
fake fetcher, never fetched), each address given twice in `SchemeInformationURI` (two languages).

| File | What |
|---|---|
| `pivot-300.xml` | sequence 300, issued 2021, signed by `a`, names `a` and `b` |
| `pivot-320.xml` | sequence 320, issued 2023, signed by `b`, names `c` |
| `lotl-pivoted.xml` | sequence 371, signed by `c`; lists pivots 320, 300, then the Official Journal; points to the `IT` and `DE` lists |
| `pivot-380.xml` | sequence 380, signed by `c`, names `d`; lists a second Official Journal publication above 320 and 300 |
| `lotl-transition.xml` | sequence 381, signed by `d`, with pivot 380's addresses (two publications listed) |
| `pivot-320-stranger.xml`, `-late.xml`, `-nosigners.xml`, `-sequence.xml`, `-it.xml` | pivot 320 signed by `stranger`, issued in 2025 (after `b` expired), naming no signer, with sequence 290, for `IT` |
| `lotl-pivoted-low.xml` | sequence 310, lower than its pivot's |
| `lotl-pivoted-elsewhere.xml` | names pivot 320 at another host |
