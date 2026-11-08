//! PKCS #11 against SoftHSM, a software token: the real module interface, a real token with
//! certificates on it, and no hardware. The test builds its own token.
//!
//! It needs a SoftHSM library and a configuration of its own, so it runs only when
//! `CLEONPDF_TEST_PKCS11_MODULE` names `libsofthsm2.so` and `SOFTHSM2_CONF` points at a
//! configuration with a scratch token directory (CI sets both). Without them the tests say so
//! and pass, unless `CLEONPDF_REQUIRE_PKCS11` is set, which makes a missing token an error.
#![cfg(not(target_arch = "wasm32"))]

#[path = "support/pki.rs"]
mod pki;
#[path = "support/softhsm.rs"]
mod softhsm;

use std::sync::{Arc, Mutex};

use cleonpdf_cos::Document;
use cleonpdf_sign::pkcs11::{self, Module, TokenInfo};
use cleonpdf_sign::{DigitalId, SignOptions, Status, TrustStore, signatures};
use softhsm::{EC_ID, KEYS_LABEL, MISMATCH_ID, P521_ID, RSA_ID, USER_PIN, fixture};

/// The tests share one token and one library; run them one at a time.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn the_token_and_its_certificates_are_listed_without_a_pin() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let module = Module::load(&f.module).unwrap();
    let tokens = module.tokens().unwrap();
    let token = tokens.iter().find(|t| t.label == "CleonPDF Test").unwrap_or_else(|| panic!("{tokens:?}"));
    assert!(token.login_required, "a PIN is needed to use the keys, not to read the certificates");
    assert!(!token.manufacturer.is_empty() && !token.serial.is_empty(), "{token:?}");

    let found = module.certificates(token.slot).unwrap();
    let mut got: Vec<(&str, &[u8], &[u8])> =
        found.certificates.iter().map(|c| (c.label.as_str(), c.id.as_slice(), c.certificate.raw.as_slice())).collect();
    got.sort();
    assert_eq!(got, [("Ada's certificate", [1u8].as_slice(), f.leaf.as_slice()), ("Test CA", [2u8].as_slice(), f.ca.as_slice())]);
    assert!(!found.certificates[0].certificate.display_name().is_empty());
    assert_eq!(found.skipped, 1, "the object that is not a certificate is counted, not trusted");
}

#[test]
fn loading_a_library_twice_returns_the_same_module() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let (a, b) = (Module::load(&f.module).unwrap(), Module::load(&f.module).unwrap());
    assert!(std::sync::Arc::ptr_eq(&a, &b));
    assert_eq!(a.path(), std::fs::canonicalize(&f.module).unwrap());
}

#[test]
fn a_slot_that_does_not_exist_is_an_error_not_a_panic() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let module = Module::load(&f.module).unwrap();
    for slot in [u64::MAX, 0xdead_beef, 987_654_321] {
        let err = module.certificates(slot).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.starts_with("PKCS #11 module libsofthsm2.so"), "slot {slot}: {err:?}");
    }
}

#[test]
fn a_module_is_allowed_only_when_listed() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    // SoftHSM is where a system package puts it, or the process was told: either way listed
    // only by one of the two ways, and a copy elsewhere is not.
    let copy = std::env::temp_dir().join(format!("cleonpdf-copy-{}.so", std::process::id()));
    std::fs::copy(&f.module, &copy).unwrap();
    assert!(!pkcs11::is_allowed(&copy), "a module nobody listed is not loaded just because it exists");
    let _ = std::fs::remove_file(&copy);
    // The places a system package uses are allowed (when SoftHSM is installed there).
    for known in pkcs11::known_modules() {
        assert!(pkcs11::is_allowed(&known), "{}", known.display());
    }
}

fn keys_token(module: &Module) -> TokenInfo {
    module.tokens().unwrap().into_iter().find(|t| t.label == KEYS_LABEL).expect("the keys token is listed")
}

/// A one-page document with a real cross-reference table.
fn document() -> Document {
    let objs: [&str; 3] = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 200 300] >>",
        "<< /Type /Page /Parent 2 0 R /Resources << >> >>",
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    Document::open(Arc::new(out)).unwrap()
}

fn sign_with(id: &DigitalId) -> Result<Vec<u8>, cleonpdf_sign::SignError> {
    cleonpdf_sign::sign(&document(), id, &SignOptions { date: "D:20261106120000Z".into(), ..SignOptions::default() })
}

#[test]
fn a_key_on_the_token_signs_and_the_signature_validates() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let module = Module::load(&f.module).unwrap();
    let token = keys_token(&module);
    for (id, signer) in [(EC_ID, "Token EC Signer"), (RSA_ID, "Token RSA Signer")] {
        let identity = module.identity(token.slot, &id, Some(USER_PIN)).unwrap();
        assert!(identity.key.is_external(), "the key stays on the token");
        assert_eq!(identity.chain.len(), 0, "the CA on the token is the root, which a chain leaves out");
        let signed = sign_with(&identity).unwrap();
        let ca = cleonpdf_sign::Certificate::parse(&f.ca).unwrap();
        let doc = Document::open(Arc::new(signed.clone())).unwrap();
        let found = signatures(&doc, &signed, &TrustStore { certs: vec![ca] }).into_iter().find(|s| s.signed).unwrap();
        assert_eq!(found.status, Status::Valid, "{signer}: {:?}", found.details);
        assert_eq!(found.signer.as_deref(), Some(signer));
    }
}

#[test]
fn a_wrong_pin_is_refused_without_putting_the_pin_in_the_message() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let module = Module::load(&f.module).unwrap();
    let token = keys_token(&module);
    let wrong = "not-the-pin-4321";
    let err = module.identity(token.slot, &EC_ID, Some(wrong)).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("PIN is not correct") && !err.contains(wrong), "{err:?}");
    // One wrong try does not lock the token: the right PIN still works (and resets the count).
    assert!(module.identity(token.slot, &EC_ID, Some(USER_PIN)).is_ok());
    // The PIN is not in what a key or an identity prints either.
    let identity = module.identity(token.slot, &EC_ID, Some(USER_PIN)).unwrap();
    assert!(!format!("{:?} {:?}", identity.key, identity.certificate.subject).contains(USER_PIN));
}

#[test]
fn a_token_that_needs_a_pin_is_not_asked_to_sign_without_one() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let module = Module::load(&f.module).unwrap();
    let token = keys_token(&module);
    assert!(token.login_required && !token.protected_authentication_path);
    let err = module.identity(token.slot, &EC_ID, None).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("needs a PIN"), "{err:?}");
}

#[test]
fn a_certificate_without_a_private_key_or_an_unknown_identifier_is_an_error() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let module = Module::load(&f.module).unwrap();
    let token = keys_token(&module);
    // The CA's certificate is on the token (id 2) but no private key goes with it.
    let err = module.identity(token.slot, &[2], Some(USER_PIN)).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("holds no private key"), "{err:?}");
    let err = module.identity(token.slot, &[0x77], Some(USER_PIN)).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("no certificate with that identifier"), "{err:?}");
}

#[test]
fn a_signature_that_does_not_match_the_certificate_is_never_used() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let module = Module::load(&f.module).unwrap();
    let token = keys_token(&module);
    // The token signs with the key it holds under this identifier; the certificate is for another.
    let identity = module.identity(token.slot, &MISMATCH_ID, Some(USER_PIN)).unwrap();
    let err = sign_with(&identity).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("doesn't match the certificate's key"), "{err:?}");
}

#[test]
fn an_identity_is_found_by_reference_or_name_among_the_modules_the_user_listed() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    assert!(pkcs11::is_allowed(&f.module), "{} is not a known location: list it in CLEONPDF_PKCS11_MODULES", f.module.display());
    let module = Module::load(&f.module).unwrap();
    let token = keys_token(&module);
    let found = module.certificates(token.slot).unwrap();
    let ec = found.certificates.iter().find(|c| c.id == EC_ID).unwrap();
    let by_reference = pkcs11::find(&pkcs11::reference(&ec.certificate), Some(USER_PIN)).unwrap();
    assert_eq!(by_reference.certificate.raw, ec.certificate.raw);
    assert!(pkcs11::find("Token RSA Signer", Some(USER_PIN)).is_ok(), "by common name");
    let err = pkcs11::find("pkcs11:00", Some(USER_PIN)).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("no PKCS #11 identity"), "{err:?}");
}

#[test]
fn a_key_type_cleonpdf_does_not_sign_with_is_refused_before_the_token_is_asked() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let module = Module::load(&f.module).unwrap();
    let token = keys_token(&module);
    // The key is on the token and the PIN is right; the refusal does not depend on either.
    for pin in [Some(USER_PIN), Some("not-the-pin-4321")] {
        let err = module.identity(token.slot, &P521_ID, pin).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("signing with") && err.contains("on a token"), "{err:?}");
    }
}

#[test]
fn the_listing_for_the_app_has_the_end_entity_certificates_and_not_the_roots() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let listing = pkcs11::list(std::slice::from_ref(&f.module));
    let names: Vec<_> =
        listing.identities.iter().filter(|i| i.token == KEYS_LABEL).map(|i| i.certificate.subject.common_name().unwrap_or("")).collect();
    for expected in ["Token EC Signer", "Token RSA Signer"] {
        assert!(names.contains(&expected), "{names:?}");
    }
    // The token's own CA certificate is self-signed: a root is not something to sign as.
    assert!(listing.identities.iter().all(|i| !i.certificate.is_self_signed()));
    // The module was named twice (by the user and as a known location) and read once.
    let again = pkcs11::candidates(&[f.module.clone(), f.module.clone()]);
    let real = std::fs::canonicalize(&f.module).unwrap();
    assert_eq!(again.iter().filter(|p| std::fs::canonicalize(p).ok().as_ref() == Some(&real)).count(), 1);
}

#[test]
fn a_module_the_user_chose_is_searched_and_a_broken_one_is_only_a_note() {
    let _one = serial();
    let Some(f) = fixture() else { return };
    let broken = std::env::temp_dir().join("cleonpdf-not-a-module.so");
    std::fs::write(&broken, b"not a shared library").unwrap();
    let extra = [broken.clone(), f.module.clone()];
    let listing = pkcs11::list(&extra);
    assert!(
        listing.notes.iter().any(|n| n.contains("cleonpdf-not-a-module.so") && !n.contains(&*std::env::temp_dir().to_string_lossy())),
        "{:?}",
        listing.notes
    );
    assert!(!listing.identities.is_empty());
    assert!(pkcs11::find_in(&extra, "Token EC Signer", Some(USER_PIN)).is_ok());
    let _ = std::fs::remove_file(broken);
}
