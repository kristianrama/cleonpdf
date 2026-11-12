//! XML signatures (W3C XMLDSig, enveloped) for the documents that carry them in this crate: the
//! EU Trusted Lists (ETSI TS 119 612), signed with XAdES.
//!
//! Only what those lists use is read, and anything else is refused rather than guessed at:
//! exclusive or inclusive canonical XML 1.0 without comments, the enveloped-signature transform,
//! references by `""` or by `#id`, SHA-2 digests, and RSA PKCS #1, RSA-PSS (RFC 6931's
//! `#<hash>-rsa-MGF1`, with SHA-2 or SHA-3) or ECDSA signatures. The signer
//! is never taken from the document: its certificate has to be one the caller already trusts, and
//! the signature has to cover the whole document element, so that what is read afterwards is what
//! was signed.

use std::collections::{BTreeMap, HashSet};

use base64::Engine as _;
use roxmltree::{Document, Node, NodeId};

use crate::der::Time;
use crate::keys::{DigestAlg, PssParams, Scheme};
use crate::x509::Certificate;

const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const C14N_INCLUSIVE: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const C14N_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Why an XML signature was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmlSignatureError {
    #[error("the document is not well-formed XML: {0}")]
    NotXml(String),
    #[error("the document has no XML signature")]
    Unsigned,
    #[error("the XML signature is not one this reader accepts: {0}")]
    Unsupported(String),
    #[error("the XML signature is malformed: {0}")]
    Malformed(String),
    #[error("a digest in the XML signature does not match the document")]
    DigestMismatch,
    #[error("the XML signature value does not match")]
    BadSignature,
    #[error("the XML signature was not made by a certificate that is trusted for it")]
    UntrustedSigner,
    #[error("the signer's certificate is not valid at this time")]
    SignerNotValid,
}

/// Longest XML document read: far above the largest national list.
pub const MAX_XML_BYTES: usize = 64 * 1024 * 1024;
/// Most XML nodes read from one document.
const MAX_NODES: u32 = 4_000_000;
/// Most references one signature may hold.
const MAX_REFERENCES: usize = 16;
/// Deepest element nesting canonicalized.
const MAX_DEPTH: usize = 256;

/// Parse an XML document, refusing DTDs (and so entity tricks) and bounding its size.
pub fn parse(xml: &str) -> Result<Document<'_>, XmlSignatureError> {
    if xml.len() > MAX_XML_BYTES {
        return Err(XmlSignatureError::NotXml("too large".into()));
    }
    // roxmltree recurses on nesting without a limit of its own, so a document nested thousands of
    // levels deep overflows the stack: measure the nesting first, without recursion.
    if nesting(xml.as_bytes()) > MAX_DEPTH {
        return Err(XmlSignatureError::NotXml("elements nested too deeply".into()));
    }
    let options = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: MAX_NODES };
    Document::parse_with_options(xml, options).map_err(|e| XmlSignatureError::NotXml(e.to_string()))
}

/// The deepest element nesting of `xml` by a scan that does not build anything. For a document
/// that is well-formed it is exact; for one that is not, the parser rejects it anyway.
fn nesting(xml: &[u8]) -> usize {
    let (mut depth, mut deepest, mut i) = (0usize, 0usize, 0usize);
    let find = |from: usize, pat: &[u8]| -> usize {
        xml.get(from..)
            .and_then(|rest| rest.windows(pat.len()).position(|w| w == pat))
            .map_or(xml.len(), |p| from.saturating_add(p).saturating_add(pat.len()))
    };
    while i < xml.len() {
        let Some(&b) = xml.get(i) else { break };
        if b != b'<' {
            i += 1;
            continue;
        }
        let rest = xml.get(i..).unwrap_or(&[]);
        if rest.starts_with(b"<!--") {
            i = find(i.saturating_add(4), b"-->");
        } else if rest.starts_with(b"<![CDATA[") {
            i = find(i.saturating_add(9), b"]]>");
        } else if rest.starts_with(b"<?") {
            i = find(i.saturating_add(2), b"?>");
        } else if rest.starts_with(b"<!") {
            i = find(i.saturating_add(2), b">");
        } else {
            let closing = rest.get(1) == Some(&b'/');
            // To the end of the tag, over quoted attribute values (which may hold a `>`).
            let (mut j, mut quote) = (i.saturating_add(1), 0u8);
            let mut last = 0u8;
            while let Some(&c) = xml.get(j) {
                if quote != 0 {
                    if c == quote {
                        quote = 0;
                    }
                } else if c == b'"' || c == b'\'' {
                    quote = c;
                } else if c == b'>' {
                    break;
                }
                last = c;
                j += 1;
            }
            i = j.saturating_add(1);
            if closing {
                depth = depth.saturating_sub(1);
            } else if last != b'/' {
                depth = depth.saturating_add(1);
                deepest = deepest.max(depth);
            } else {
                deepest = deepest.max(depth.saturating_add(1));
            }
        }
    }
    deepest
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Inclusive,
    Exclusive,
}

fn escape_text(s: &str, out: &mut Vec<u8>) {
    for c in s.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            c => push_char(c, out),
        }
    }
}

fn escape_attr(s: &str, out: &mut Vec<u8>) {
    for c in s.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            c => push_char(c, out),
        }
    }
}

fn push_char(c: char, out: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

/// The qualified name an element or attribute was written with, read from the source: the parser
/// keeps the namespace but not the prefix, and two prefixes may name the same namespace.
fn written_name(src: &str, start: usize) -> &str {
    let rest = src.get(start..).unwrap_or("");
    let end = rest.find(|c: char| c.is_whitespace() || matches!(c, '/' | '>' | '=')).unwrap_or(rest.len());
    rest.get(..end).unwrap_or("")
}

fn prefix_of(qname: &str) -> &str {
    qname.split_once(':').map_or("", |(p, _)| p)
}

struct Canon<'a> {
    src: &'a str,
    mode: Mode,
    /// An element left out with everything below it (the enveloped signature).
    skip: Option<NodeId>,
    out: Vec<u8>,
    depth: usize,
}

impl Canon<'_> {
    fn element(&mut self, n: Node<'_, '_>, rendered: &BTreeMap<String, String>) -> Result<(), XmlSignatureError> {
        if self.depth >= MAX_DEPTH {
            return Err(XmlSignatureError::Unsupported("elements nested too deeply".into()));
        }
        self.depth += 1;
        let qname = written_name(self.src, n.range().start.saturating_add(1));
        let prefix = prefix_of(qname);
        // The namespaces in scope, by prefix ("" is the default namespace).
        let scope: BTreeMap<String, String> =
            n.namespaces().filter(|ns| ns.name() != Some("xml")).map(|ns| (ns.name().unwrap_or("").to_string(), ns.uri().to_string())).collect();
        struct Attr<'x> {
            ns: &'x str,
            local: &'x str,
            qname: &'x str,
            value: &'x str,
        }
        let mut attrs: Vec<Attr<'_>> = n
            .attributes()
            .map(|a| Attr { ns: a.namespace().unwrap_or(""), local: a.name(), qname: written_name(self.src, a.range().start), value: a.value() })
            .collect();
        attrs.sort_by(|a, b| (a.ns, a.local).cmp(&(b.ns, b.local)));
        // The namespace declarations to write: what is in scope and not yet written by an
        // ancestor (inclusive), or what the element and its attributes use (exclusive).
        let mut declare: BTreeMap<String, String> = BTreeMap::new();
        match self.mode {
            Mode::Inclusive => {
                for (p, u) in &scope {
                    if rendered.get(p) != Some(u) {
                        declare.insert(p.clone(), u.clone());
                    }
                }
                if !scope.contains_key("") && rendered.get("").is_some_and(|u| !u.is_empty()) {
                    declare.insert(String::new(), String::new());
                }
            }
            Mode::Exclusive => {
                let mut used: Vec<&str> = vec![prefix];
                used.extend(attrs.iter().map(|a| prefix_of(a.qname)).filter(|p| !p.is_empty() && *p != "xml"));
                for p in used {
                    let u = scope.get(p).map_or("", String::as_str);
                    if p.is_empty() {
                        if u != rendered.get("").map_or("", String::as_str) {
                            declare.insert(String::new(), u.to_string());
                        }
                    } else if scope.contains_key(p) && rendered.get(p).map(String::as_str) != Some(u) {
                        declare.insert(p.to_string(), u.to_string());
                    }
                }
            }
        }
        let mut here = rendered.clone();
        self.out.push(b'<');
        self.out.extend_from_slice(qname.as_bytes());
        // BTreeMap order puts the default namespace ("") first, then the prefixes in order.
        for (p, u) in &declare {
            self.out.extend_from_slice(b" xmlns");
            if !p.is_empty() {
                self.out.push(b':');
                self.out.extend_from_slice(p.as_bytes());
            }
            self.out.extend_from_slice(b"=\"");
            escape_attr(u, &mut self.out);
            self.out.push(b'"');
            here.insert(p.clone(), u.clone());
        }
        for a in &attrs {
            self.out.push(b' ');
            self.out.extend_from_slice(a.qname.as_bytes());
            self.out.extend_from_slice(b"=\"");
            escape_attr(a.value, &mut self.out);
            self.out.push(b'"');
        }
        self.out.push(b'>');
        for c in n.children() {
            if c.is_element() {
                if Some(c.id()) != self.skip {
                    self.element(c, &here)?;
                }
            } else if c.is_text() {
                escape_text(c.text().unwrap_or(""), &mut self.out);
            } else if let Some(pi) = c.pi() {
                self.out.extend_from_slice(b"<?");
                self.out.extend_from_slice(pi.target.as_bytes());
                if let Some(v) = pi.value.filter(|v| !v.is_empty()) {
                    self.out.push(b' ');
                    self.out.extend_from_slice(v.as_bytes());
                }
                self.out.extend_from_slice(b"?>");
            }
        }
        self.out.extend_from_slice(b"</");
        self.out.extend_from_slice(qname.as_bytes());
        self.out.push(b'>');
        self.depth = self.depth.saturating_sub(1);
        Ok(())
    }
}

/// Canonical XML (without comments) of `node` and what is below it, leaving out `skip`.
fn canonicalize(src: &str, node: Node<'_, '_>, mode: Mode, skip: Option<NodeId>) -> Result<Vec<u8>, XmlSignatureError> {
    if !node.is_element() {
        return Err(XmlSignatureError::Malformed("only elements are canonicalized".into()));
    }
    let mut c = Canon { src, mode, skip, out: Vec::new(), depth: 0 };
    c.element(node, &BTreeMap::new())?;
    Ok(c.out)
}

/// Canonical XML 1.0 (without comments) of an element, for callers and tests that need the bytes.
pub fn canonical_xml(src: &str, node: Node<'_, '_>, exclusive: bool) -> Result<Vec<u8>, XmlSignatureError> {
    canonicalize(src, node, if exclusive { Mode::Exclusive } else { Mode::Inclusive }, None)
}

fn is_dsig(n: Node<'_, '_>, local: &str) -> bool {
    n.is_element() && n.tag_name().name() == local && n.tag_name().namespace() == Some(DSIG)
}

fn child<'a, 'i>(n: Node<'a, 'i>, local: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| is_dsig(*c, local))
}

fn algorithm<'a>(n: Node<'a, '_>) -> Result<&'a str, XmlSignatureError> {
    n.attribute("Algorithm").ok_or_else(|| XmlSignatureError::Malformed("an element has no Algorithm".into()))
}

fn mode_of(uri: &str) -> Result<Mode, XmlSignatureError> {
    match uri {
        C14N_EXCLUSIVE => Ok(Mode::Exclusive),
        C14N_INCLUSIVE => Ok(Mode::Inclusive),
        other => Err(XmlSignatureError::Unsupported(format!("canonicalization {other}"))),
    }
}

fn digest_of(uri: &str) -> Result<DigestAlg, XmlSignatureError> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(DigestAlg::Sha256),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Ok(DigestAlg::Sha384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(DigestAlg::Sha512),
        other => Err(XmlSignatureError::Unsupported(format!("digest {other}"))),
    }
}

/// RSASSA-PSS "without parameters" (RFC 6931 §2.3.10): the hash is also MGF1's, the salt is as long
/// as its output and the trailer is 0xBC. The SHA-1 and MD variants are left out, as for PKCS #1.
fn pss(alg: DigestAlg) -> (Scheme, DigestAlg) {
    (Scheme::RsaPss(PssParams { mgf: alg, salt_len: Some(alg.output_len()) }), alg)
}

fn signature_method(uri: &str) -> Result<(Scheme, DigestAlg), XmlSignatureError> {
    match uri {
        "http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1" => Ok(pss(DigestAlg::Sha224)),
        "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" => Ok(pss(DigestAlg::Sha256)),
        "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1" => Ok(pss(DigestAlg::Sha384)),
        "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1" => Ok(pss(DigestAlg::Sha512)),
        "http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1" => Ok(pss(DigestAlg::Sha3_224)),
        "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1" => Ok(pss(DigestAlg::Sha3_256)),
        "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1" => Ok(pss(DigestAlg::Sha3_384)),
        "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1" => Ok(pss(DigestAlg::Sha3_512)),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Ok((Scheme::RsaPkcs1, DigestAlg::Sha256)),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Ok((Scheme::RsaPkcs1, DigestAlg::Sha384)),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Ok((Scheme::RsaPkcs1, DigestAlg::Sha512)),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Ok((Scheme::Ecdsa, DigestAlg::Sha256)),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => Ok((Scheme::Ecdsa, DigestAlg::Sha384)),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" => Ok((Scheme::Ecdsa, DigestAlg::Sha512)),
        other => Err(XmlSignatureError::Unsupported(format!("signature method {other}"))),
    }
}

fn b64(text: &str) -> Result<Vec<u8>, XmlSignatureError> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(clean).map_err(|_| XmlSignatureError::Malformed("bad base64".into()))
}

fn text_of(n: Node<'_, '_>) -> String {
    n.descendants().filter(|d| d.is_text()).filter_map(|d| d.text()).collect()
}

/// The element a same-document reference points at: `""` is the document element, `#id` the one
/// element whose `Id`, `ID` or `id` is that. An id that names two elements is refused: that is how
/// a signed element is swapped for another.
fn resolve<'a, 'i>(doc: &'a Document<'i>, uri: &str) -> Result<Node<'a, 'i>, XmlSignatureError> {
    if uri.is_empty() {
        return Ok(doc.root_element());
    }
    let Some(id) = uri.strip_prefix('#') else {
        return Err(XmlSignatureError::Unsupported(format!("reference to {uri}")));
    };
    let mut found = doc.descendants().filter(|n| n.is_element() && ["Id", "ID", "id"].iter().any(|k| n.attribute(*k) == Some(id)));
    let first = found.next().ok_or_else(|| XmlSignatureError::Malformed(format!("no element with the id {id}")))?;
    if found.next().is_some() {
        return Err(XmlSignatureError::Malformed(format!("the id {id} names more than one element")));
    }
    Ok(first)
}

/// Check the one enveloped XML signature of `doc` (read from `src`) against `signers`, the
/// certificates the caller trusts to sign this kind of document, as of `at`. Returns the signer.
///
/// # Errors
/// [`XmlSignatureError`] says what was wrong; nothing is returned for a document that cannot be
/// shown to have been signed by one of `signers`.
pub fn verify_enveloped(doc: &Document<'_>, src: &str, signers: &[Certificate], at: Time) -> Result<Certificate, XmlSignatureError> {
    let root = doc.root_element();
    let mut signatures = root.children().filter(|c| is_dsig(*c, "Signature"));
    let sig = signatures.next().ok_or(XmlSignatureError::Unsigned)?;
    if signatures.next().is_some() {
        return Err(XmlSignatureError::Unsupported("more than one signature on the document element".into()));
    }
    let info = child(sig, "SignedInfo").ok_or_else(|| XmlSignatureError::Malformed("no SignedInfo".into()))?;
    let info_mode =
        mode_of(algorithm(child(info, "CanonicalizationMethod").ok_or_else(|| XmlSignatureError::Malformed("no CanonicalizationMethod".into()))?)?)?;
    let (scheme, alg) =
        signature_method(algorithm(child(info, "SignatureMethod").ok_or_else(|| XmlSignatureError::Malformed("no SignatureMethod".into()))?)?)?;
    // Every reference must digest to what it says, and one of them must be the whole document.
    let mut covers_document = false;
    let mut seen = 0usize;
    for r in info.children().filter(|c| is_dsig(*c, "Reference")) {
        seen += 1;
        if seen > MAX_REFERENCES {
            return Err(XmlSignatureError::Unsupported("too many references".into()));
        }
        let target = resolve(doc, r.attribute("URI").ok_or_else(|| XmlSignatureError::Malformed("a reference has no URI".into()))?)?;
        let mut mode = Mode::Inclusive;
        let mut skip = None;
        if let Some(ts) = child(r, "Transforms") {
            for t in ts.children().filter(|c| is_dsig(*c, "Transform")) {
                if t.children().any(|c| c.is_element()) {
                    return Err(XmlSignatureError::Unsupported("a transform with parameters".into()));
                }
                match algorithm(t)? {
                    ENVELOPED => skip = Some(sig.id()),
                    other => mode = mode_of(other)?,
                }
            }
        }
        let dm = digest_of(algorithm(child(r, "DigestMethod").ok_or_else(|| XmlSignatureError::Malformed("no DigestMethod".into()))?)?)?;
        let want = b64(&text_of(child(r, "DigestValue").ok_or_else(|| XmlSignatureError::Malformed("no DigestValue".into()))?))?;
        let bytes = canonicalize(src, target, mode, skip)?;
        if dm.digest(&[&bytes]) != want {
            return Err(XmlSignatureError::DigestMismatch);
        }
        if target.id() == root.id() {
            // The signature itself is part of the document element: it counts as covering it only
            // when the enveloped-signature transform leaves it out.
            covers_document |= skip == Some(sig.id());
        }
    }
    if seen == 0 {
        return Err(XmlSignatureError::Malformed("the signature signs nothing".into()));
    }
    if !covers_document {
        return Err(XmlSignatureError::Unsupported("the signature does not cover the whole document".into()));
    }
    let signed = canonicalize(src, info, info_mode, None)?;
    let value = b64(&text_of(child(sig, "SignatureValue").ok_or_else(|| XmlSignatureError::Malformed("no SignatureValue".into()))?))?;
    // Who signed: the certificates the signature carries that the caller trusts; or, with none
    // carried, each of the caller's.
    let mut carried: Vec<Certificate> = Vec::new();
    if let Some(ki) = child(sig, "KeyInfo") {
        for d in ki.descendants().filter(|d| is_dsig(*d, "X509Certificate")).take(16) {
            if let Ok(c) = Certificate::parse(&b64(&text_of(d))?) {
                carried.push(c);
            }
        }
    }
    let trusted: HashSet<&[u8]> = signers.iter().map(|c| c.raw.as_slice()).collect();
    let candidates: Vec<&Certificate> =
        if carried.is_empty() { signers.iter().collect() } else { carried.iter().filter(|c| trusted.contains(c.raw.as_slice())).collect() };
    if candidates.is_empty() {
        return Err(XmlSignatureError::UntrustedSigner);
    }
    let digest = alg.digest(&[&signed]);
    let mut valid_now = false;
    for c in candidates {
        if !c.valid_at(at) {
            continue;
        }
        valid_now = true;
        if c.public_key.verify(scheme, alg, &digest, &value).unwrap_or(false) {
            return Ok(c.clone());
        }
    }
    Err(if valid_now { XmlSignatureError::BadSignature } else { XmlSignatureError::SignerNotValid })
}
