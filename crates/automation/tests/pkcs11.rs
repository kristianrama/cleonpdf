//! `sign_hardware_tokens` against SoftHSM: the tool lists a token and its certificates, and loads
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
    a.call("sign_hardware_tokens", &args).map(|mut c| match c.remove(0) {
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

/// A one-page document with a real cross-reference table.
fn minimal_pdf() -> Vec<u8> {
    let objs = [
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
    out
}

#[test]
fn a_document_is_signed_with_a_key_that_stays_on_the_token() {
    let _one = serial();
    let Some(f) = softhsm::fixture() else { return };
    let mut a = auto();
    let root = std::env::temp_dir().join(format!("cleonpdf-pkcs11-tool-{}", std::process::id()));
    std::fs::write(root.join("in.pdf"), minimal_pdf()).unwrap();
    std::fs::write(root.join("ca.cer"), &f.ca).unwrap();
    let listing = call(&mut a, json!({})).unwrap();
    let keys = listing["modules"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|m| m["tokens"].as_array().unwrap().iter())
        .find(|t| t["label"] == json!(softhsm::KEYS_LABEL))
        .unwrap_or_else(|| panic!("no keys token in {listing}"))
        .clone();
    let id_of = |name: &str| -> String {
        let c = keys["certificates"].as_array().unwrap().iter().find(|c| c["certificate"]["name"] == json!(name)).unwrap();
        c["id"].as_str().unwrap().to_string()
    };
    let doc = |a: &mut Automation| match a.call("doc_open", &json!({ "path": "in.pdf" })).unwrap().remove(0) {
        Content::Json(v) => v["doc"].as_u64().unwrap(),
        other => panic!("{other:?}"),
    };
    // Signing shows the signed file afterwards, so every signature starts from a fresh copy.
    let sign = |a: &mut Automation, id: &str, pin: Option<&str>, out: &str| {
        let mut args = json!({ "doc": doc(a), "id": id, "out": out });
        if let Some(pin) = pin {
            args["password"] = json!(pin);
        }
        a.call("sign_document", &args)
    };
    // A wrong PIN and a missing PIN are refused, and nothing is written.
    let reference = id_of("Token EC Signer");
    for (pin, expect) in [(Some("not-the-pin-4321"), "PIN is not correct"), (None, "needs a PIN")] {
        match sign(&mut a, &reference, pin, "bad.pdf") {
            Err(ToolError::Failed(m)) => assert!(m.contains(expect) && !m.contains("not-the-pin-4321"), "{m}"),
            other => panic!("expected a refusal: {other:?}"),
        }
        assert!(!root.join("bad.pdf").exists());
    }
    // By fingerprint (EC) and by common name (RSA).
    sign(&mut a, &reference, Some(softhsm::USER_PIN), "ec.pdf").unwrap();
    sign(&mut a, "pkcs11:Token RSA Signer", Some(softhsm::USER_PIN), "rsa.pdf").unwrap();
    a.call("sign_trust", &json!({ "paths": ["ca.cer"] })).unwrap();
    for (file, signer) in [("ec.pdf", "Token EC Signer"), ("rsa.pdf", "Token RSA Signer")] {
        let mut b = auto();
        let re = match b.call("doc_open", &json!({ "path": file })).unwrap().remove(0) {
            Content::Json(v) => v["doc"].as_u64().unwrap(),
            other => panic!("{other:?}"),
        };
        b.call("sign_trust", &json!({ "paths": ["ca.cer"] })).unwrap();
        let Content::Json(list) = b.call("sign_list", &json!({ "doc": re })).unwrap().remove(0) else { panic!("expected JSON") };
        assert_eq!((list["signatures"][0]["signer"].as_str(), list["signatures"][0]["status"].as_str()), (Some(signer), Some("valid")), "{list}");
    }
    // A reference nobody holds.
    match sign(&mut a, "pkcs11:00", Some(softhsm::USER_PIN), "none.pdf") {
        Err(ToolError::Failed(m)) => assert!(m.contains("no PKCS #11 identity"), "{m}"),
        other => panic!("{other:?}"),
    }
}
