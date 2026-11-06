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

use std::sync::Mutex;

use cleonpdf_sign::pkcs11::{self, Module};
use softhsm::fixture;

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
