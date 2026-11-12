//! XML signatures against files made by lxml and signxml, which share no code with this crate.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use cleonpdf_sign::xmldsig::{XmlSignatureError, canonical_xml, parse, verify_enveloped};
use cleonpdf_sign::{Certificate, PublicKey, Time};

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/xml/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}
fn text(name: &str) -> String {
    String::from_utf8(data(name)).unwrap()
}
fn cert(name: &str) -> Certificate {
    Certificate::parse(&data(name)).unwrap()
}
fn at(year: u32) -> Time {
    Time { year, month: 6, day: 1, hour: 12, minute: 0, second: 0 }
}
fn check(xml: &str, signers: &[&str], year: u32) -> Result<Certificate, XmlSignatureError> {
    let doc = parse(xml)?;
    let certs: Vec<Certificate> = signers.iter().map(|s| cert(s)).collect();
    verify_enveloped(&doc, xml, &certs, at(year))
}

#[test]
fn canonical_forms_match_libxml2() {
    let src = text("doc.xml");
    let doc = parse(&src).unwrap();
    assert_eq!(String::from_utf8(canonical_xml(&src, doc.root_element(), true).unwrap()).unwrap(), text("doc.exc.c14n"));
    assert_eq!(String::from_utf8(canonical_xml(&src, doc.root_element(), false).unwrap()).unwrap(), text("doc.inc.c14n"));
    let inner = doc.descendants().find(|n| n.tag_name().name() == "Inner").unwrap();
    assert_eq!(String::from_utf8(canonical_xml(&src, inner, true).unwrap()).unwrap(), text("inner.exc.c14n"));
    assert_eq!(String::from_utf8(canonical_xml(&src, inner, false).unwrap()).unwrap(), text("inner.inc.c14n"));
}

#[test]
fn signatures_by_another_implementation_verify() {
    for (file, signer) in [
        ("rsa-sha256-exc.xml", "rsa.der"),
        ("rsa-sha256-inc.xml", "rsa.der"),
        ("rsa-sha512-exc.xml", "rsa.der"),
        ("ec-sha256-exc.xml", "ec.der"),
        ("ec-sha256-inc.xml", "ec.der"),
        ("rsa-sha256-emptyuri.xml", "rsa.der"),
    ] {
        let got = check(&text(file), &[signer], 2027).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(got.raw, cert(signer).raw, "{file}");
    }
}

#[test]
fn rsa_pss_signatures_verify_with_the_salt_rfc_6931_fixes() {
    // As the German Trusted List is signed: RSASSA-PSS "without parameters", by signxml.
    for file in ["rsa-pss-sha256-exc.xml", "rsa-pss-sha384-exc.xml", "rsa-pss-sha512-exc.xml", "rsa-pss-sha3-256-exc.xml"] {
        let got = check(&text(file), &["rsa-pss.der"], 2027).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(got.raw, cert("rsa-pss.der").raw, "{file}");
        // Any change still breaks it, and so does another signer.
        let changed = text(file).replace("<ns:Inner", "<ns:Inner extra=\"1\"");
        assert_ne!(changed, text(file));
        assert_eq!(check(&changed, &["rsa-pss.der"], 2027), Err(XmlSignatureError::DigestMismatch), "{file}");
        assert_eq!(check(&text(file), &["rsa.der"], 2027), Err(XmlSignatureError::UntrustedSigner), "{file}");
    }
    // A PSS value with a salt shorter than the hash is not what the method names.
    assert_eq!(check(&text("rsa-pss-sha256-salt20.xml"), &["rsa-pss.der"], 2027), Err(XmlSignatureError::BadSignature));
    // A PSS value under the PKCS #1 method, and the other way round, does not verify.
    let as_pkcs1 = text("rsa-pss-sha256-exc.xml").replace("2007/05/xmldsig-more#sha256-rsa-MGF1", "2001/04/xmldsig-more#rsa-sha256");
    assert_eq!(check(&as_pkcs1, &["rsa-pss.der"], 2027), Err(XmlSignatureError::BadSignature));
    let as_pss = text("rsa-sha256-exc.xml").replace("2001/04/xmldsig-more#rsa-sha256", "2007/05/xmldsig-more#sha256-rsa-MGF1");
    assert_eq!(check(&as_pss, &["rsa.der"], 2027), Err(XmlSignatureError::BadSignature));
    // The SHA-1 variant stays outside the list.
    let sha1 = text("rsa-pss-sha256-exc.xml").replace("#sha256-rsa-MGF1", "#sha1-rsa-MGF1");
    assert!(matches!(check(&sha1, &["rsa-pss.der"], 2027), Err(XmlSignatureError::Unsupported(_))));
}

#[test]
fn keys_marked_for_rsa_pss_only_verify_pss_within_their_restrictions() {
    // As Germany's Trusted List signer: SubjectPublicKeyInfo `id-RSASSA-PSS`, made by OpenSSL.
    let restricted = cert("rsa-pss-key-restricted.der");
    let open = cert("rsa-pss-key-open.der");
    assert!(matches!(restricted.public_key, PublicKey::RsaPss { only: Some(_), .. }), "{:?}", restricted.public_key.describe());
    assert!(matches!(open.public_key, PublicKey::RsaPss { only: None, .. }));
    assert_eq!(open.public_key.describe(), "RSA-PSS 3072-bit");
    // The key keeps its own SubjectPublicKeyInfo, parameters and all.
    let spki = PublicKey::from_spki(&cleonpdf_sign::der::Tlv::parse_all(&restricted.public_key.spki()).unwrap()).unwrap();
    assert_eq!(spki, restricted.public_key);
    for file in ["rsa-pss-key-restricted-sha256.xml", "rsa-pss-key-open-sha256.xml", "rsa-pss-key-open-sha512.xml"] {
        let signer = if file.contains("restricted") { "rsa-pss-key-restricted.der" } else { "rsa-pss-key-open.der" };
        check(&text(file), &[signer], 2027).unwrap_or_else(|e| panic!("{file}: {e}"));
    }
    // The restricted key names SHA-256: a SHA-512 signature by it is refused.
    assert_eq!(check(&text("rsa-pss-key-restricted-sha512.xml"), &["rsa-pss-key-restricted.der"], 2027), Err(XmlSignatureError::BadSignature));
    // A PKCS #1 v1.5 signature by a PSS-only key is refused, though the arithmetic would check.
    assert_eq!(check(&text("rsa-pss-key-open-pkcs1.xml"), &["rsa-pss-key-open.der"], 2027), Err(XmlSignatureError::BadSignature));
}

#[test]
fn the_signer_must_be_one_the_caller_trusts() {
    let xml = text("other-signer.xml");
    // Validly signed, but by a certificate that is not on the caller's list.
    assert_eq!(check(&xml, &["rsa.der", "ec.der"], 2027), Err(XmlSignatureError::UntrustedSigner));
    assert!(check(&xml, &["other.der"], 2027).is_ok());
    assert_eq!(check(&xml, &[], 2027), Err(XmlSignatureError::UntrustedSigner));
}

#[test]
fn the_signer_must_be_valid_at_that_time() {
    let xml = text("rsa-sha256-exc.xml");
    assert_eq!(check(&xml, &["rsa.der"], 2050), Err(XmlSignatureError::SignerNotValid));
    assert_eq!(check(&xml, &["rsa.der"], 2020), Err(XmlSignatureError::SignerNotValid));
}

#[test]
fn any_change_to_the_document_or_the_signature_is_caught() {
    let xml = text("rsa-sha256-exc.xml");
    let ok = |s: &str| check(s, &["rsa.der"], 2027);
    assert!(ok(&xml).is_ok());
    // Content.
    assert_eq!(ok(&xml.replace("text with", "text WITH")), Err(XmlSignatureError::DigestMismatch));
    // An attribute, and a namespace URI.
    assert_eq!(ok(&xml.replace("b=\"2\"", "b=\"3\"")), Err(XmlSignatureError::DigestMismatch));
    assert_eq!(ok(&xml.replace("urn:example:other", "urn:example:evil")), Err(XmlSignatureError::DigestMismatch));
    // The digest and the signed information it sits in.
    let digest = xml.split("<ds:DigestValue>").nth(1).unwrap().split('<').next().unwrap();
    let mut other = digest.to_string();
    other.replace_range(0..1, if digest.starts_with('A') { "B" } else { "A" });
    assert_eq!(ok(&xml.replace(digest, &other)), Err(XmlSignatureError::DigestMismatch));
    assert_eq!(ok(&xml.replace("xmldsig-more#rsa-sha256", "xmldsig-more#rsa-sha384")), Err(XmlSignatureError::BadSignature));
    // The signature value.
    let value = xml.split("<ds:SignatureValue>").nth(1).unwrap().split('<').next().unwrap();
    let mut forged = value.to_string();
    forged.replace_range(10..11, if &value[10..11] == "A" { "B" } else { "A" });
    assert_eq!(ok(&xml.replace(value, &forged)), Err(XmlSignatureError::BadSignature));
}

#[test]
fn what_is_not_signed_is_not_accepted() {
    // A correct signature over one element only does not vouch for the document.
    let partial = text("rsa-sha256-partial.xml");
    assert!(matches!(check(&partial, &["rsa.der"], 2027), Err(XmlSignatureError::Unsupported(_))), "{:?}", check(&partial, &["rsa.der"], 2027));
    // No signature at all, or one that is not a direct child of the document element.
    assert_eq!(check(&text("doc.xml"), &["rsa.der"], 2027), Err(XmlSignatureError::Unsigned));
    let xml = text("rsa-sha256-exc.xml");
    let start = xml.find("<ds:Signature").unwrap();
    let end = xml.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    let sig = &xml[start..end];
    let moved = format!("{}{}", xml.replace(sig, ""), "").replace("</ns:Empty>", &format!("{sig}</ns:Empty>"));
    assert_eq!(check(&moved, &["rsa.der"], 2027), Err(XmlSignatureError::Unsigned));
    // Two signatures are refused outright.
    let doubled = xml.replace("</ns:Doc>", &format!("{sig}</ns:Doc>"));
    assert!(matches!(check(&doubled, &["rsa.der"], 2027), Err(XmlSignatureError::Unsupported(_))));
}

#[test]
fn a_duplicate_id_cannot_swap_the_signed_element() {
    let xml = text("rsa-sha256-exc.xml");
    // A second element with the signed id, placed ahead of the real one (signature wrapping).
    let wrapped = xml.replacen("<ns:Empty/>", "<ns:Empty Id=\"root\"/>", 1);
    assert!(matches!(check(&wrapped, &["rsa.der"], 2027), Err(XmlSignatureError::Malformed(_))));
}

#[test]
fn algorithms_outside_the_list_are_refused() {
    let xml = text("rsa-sha256-exc.xml");
    for (from, to) in [
        ("xmldsig-more#rsa-sha256", "xmldsig#rsa-sha1"),
        ("xmlenc#sha256", "xmldsig#sha1"),
        ("xml-exc-c14n#\"/><ds:SignatureMethod", "REC-xml-c14n11-20080502\"/><ds:SignatureMethod"),
    ] {
        assert!(matches!(check(&xml.replace(from, to), &["rsa.der"], 2027), Err(XmlSignatureError::Unsupported(_))), "{from}");
    }
}

#[test]
fn hostile_xml_is_refused_without_trouble() {
    // A DTD, so no entity tricks.
    let bomb = "<?xml version=\"1.0\"?><!DOCTYPE d [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><d>&b;&b;&b;</d>";
    assert!(matches!(parse(bomb), Err(XmlSignatureError::NotXml(_))));
    // Not XML, and nothing.
    for junk in ["", "<a>", "<a></b>", "\u{0}", "<a b=1/>"] {
        assert!(parse(junk).is_err(), "{junk:?}");
    }
    // Deep nesting is bounded rather than blowing the stack.
    for depth in [300, 5_000, 200_000] {
        let deep = format!("{}{}", "<a>".repeat(depth), "</a>".repeat(depth));
        assert!(matches!(parse(&deep), Err(XmlSignatureError::NotXml(_))), "{depth}");
        // Self-closing and quoted `>` do not hide the nesting.
        let tricky = format!("{}<b x=\">\"/>{}", "<a y='>'>".repeat(depth), "</a>".repeat(depth));
        assert!(parse(&tricky).is_err(), "{depth}");
    }
    // Real documents are nowhere near the limit, and what is in comments or CDATA does not count.
    let fine = format!("{}<!-- <x><x><x> --><![CDATA[<x><x>]]>{}", "<a>".repeat(200), "</a>".repeat(200));
    assert!(parse(&fine).is_ok());
    // The canonicalizer has its own bound, for a tree built some other way.
    let nested = format!("{}{}", "<a>".repeat(300), "</a>".repeat(300));
    let doc = roxmltree::Document::parse(&nested).unwrap();
    assert!(matches!(canonical_xml(&nested, doc.root_element(), true), Err(XmlSignatureError::Unsupported(_))));
}
