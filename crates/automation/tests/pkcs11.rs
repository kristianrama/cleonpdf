//! `sign_pkcs11_tokens` against SoftHSM: the tool lists a token and its certificates, and loads
//! only modules the system or the user listed. Needs SoftHSM like `crates/sign/tests/pkcs11.rs`
//! (see `softhsm.rs` for the environment); without it the tests say so and pass.
#![cfg(not(target_arch = "wasm32"))]

#[path = "../../sign/tests/support/pki.rs"]
mod pki;
#[path = "../../sign/tests/support/softhsm.rs"]
mod softhsm;

use std::sync::Mutex;

use cleonpdf_automation::{Automation, Content, ToolError};
use serde_json::{Value, json};

/// The tests share one token and one library; run them one at a time.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn auto() -> Automation {
    let dir = std::env::temp_dir().join(format!("cleonpdf-pkcs11-tool-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Automation::new().with_root(&dir).unwrap()
}

fn call(a: &mut Automation, args: Value) -> Result<Value, ToolError> {
    a.call("sign_pkcs11_tokens", &args).map(|mut c| match c.remove(0) {
        Content::Json(v) => v,
        other => panic!("expected JSON, got {other:?}"),
    })
}

fn our_token(listing: &Value) -> Value {
    listing["modules"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|m| m["tokens"].as_array().unwrap().iter())
        .find(|t| t["label"] == json!("CleonPDF Test"))
        .unwrap_or_else(|| panic!("no test token in {listing}"))
        .clone()
}

#[test]
fn the_tool_lists_the_token_and_its_certificates_for_a_named_module_and_for_all() {
    let _one = serial();
    let Some(f) = softhsm::fixture() else { return };
    assert!(
        cleonpdf_sign::pkcs11::is_allowed(&f.module),
        "{} is not a known location: list it in CLEONPDF_PKCS11_MODULES for this test",
        f.module.display()
    );
    let mut a = auto();
    for args in [json!({ "module": f.module.to_string_lossy() }), json!({})] {
        let listing = call(&mut a, args).unwrap();
        let token = our_token(&listing);
        assert_eq!(token["login_required"], json!(true));
        assert_eq!(token["unusable_certificates"], json!(1), "{token}");
        let mut names: Vec<&str> = token["certificates"].as_array().unwrap().iter().map(|c| c["certificate"]["name"].as_str().unwrap()).collect();
        names.sort();
        assert_eq!(names, ["Ada Lovelace", "Test CA"], "{token}");
        assert_eq!(token["certificates"][0]["key_id"].as_str().map(str::len), Some(2));
    }
}

#[test]
fn a_module_nobody_listed_is_never_loaded() {
    let _one = serial();
    let Some(f) = softhsm::fixture() else { return };
    let mut a = auto();
    // The same library under another path, a file that is not a library, and a path that is not there:
    // none is on the list, so none is opened.
    let copy = std::env::temp_dir().join(format!("cleonpdf-unlisted-{}.so", std::process::id()));
    std::fs::copy(&f.module, &copy).unwrap();
    let junk = std::env::temp_dir().join(format!("cleonpdf-junk-{}.so", std::process::id()));
    std::fs::write(&junk, b"not a library").unwrap();
    for path in [copy.to_string_lossy().into_owned(), junk.to_string_lossy().into_owned(), "/nowhere/libx.so".to_string()] {
        let r = call(&mut a, json!({ "module": path }));
        assert!(matches!(&r, Err(ToolError::Failed(m)) if m.contains("not a PKCS #11 module CleonPDF was told to use")), "{path}: {r:?}");
    }
    let _ = std::fs::remove_file(copy);
    let _ = std::fs::remove_file(junk);
}
