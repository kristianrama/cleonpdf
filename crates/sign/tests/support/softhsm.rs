//! A SoftHSM token for tests: the real PKCS #11 interface with a software token and no hardware.
//! Shared by the sign and automation tests (`#[path]`); the test crate declares `mod pki;` too.
//!
//! It needs a SoftHSM library and a configuration of its own, so it works only when
//! `CLEONPDF_TEST_PKCS11_MODULE` names `libsofthsm2.so` and `SOFTHSM2_CONF` points at a
//! configuration with a scratch token directory (CI sets both). Without them [`fixture`] says so
//! and returns `None`, unless `CLEONPDF_REQUIRE_PKCS11` is set, which makes a missing token an error.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, CertificateType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use secrecy::SecretString;

const SO_PIN: &str = "so-pin-1234";
const USER_PIN: &str = "user-pin-1234";

/// What the fixture put on the token.
pub struct Fixture {
    pub module: PathBuf,
    /// Kept alive: the library is initialised through it.
    _context: Pkcs11,
    pub leaf: Vec<u8>,
    pub ca: Vec<u8>,
}

pub fn module_path() -> Option<PathBuf> {
    let path = std::env::var_os("CLEONPDF_TEST_PKCS11_MODULE").map(PathBuf::from).filter(|p| p.is_file());
    if path.is_none() || std::env::var_os("SOFTHSM2_CONF").is_none() {
        assert!(
            std::env::var_os("CLEONPDF_REQUIRE_PKCS11").is_none(),
            "CLEONPDF_TEST_PKCS11_MODULE and SOFTHSM2_CONF must be set when CLEONPDF_REQUIRE_PKCS11 is"
        );
        eprintln!("skipped: no SoftHSM (set CLEONPDF_TEST_PKCS11_MODULE and SOFTHSM2_CONF)");
        return None;
    }
    path
}

fn secret(pin: &str) -> AuthPin {
    SecretString::from(pin)
}

/// One token with two certificates and one object that claims to be a certificate and isn't,
/// built once; the tests only read it.
pub fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let module = module_path()?;
            let context = Pkcs11::new(&module).expect("SoftHSM loads");
            // The tests below load the same library through `Module::load` afterwards: it must
            // cope with a library that something else in the process initialised.
            context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).expect("SoftHSM starts");
            let free = context
                .get_all_slots()
                .unwrap()
                .into_iter()
                .find(|s| context.get_token_info(*s).is_ok_and(|t| !t.token_initialized()))
                .expect("SoftHSM offers a free slot");
            context.init_token(free, &secret(SO_PIN), "CleonPDF Test").expect("token initialises");
            // SoftHSM renumbers the slot once the token exists.
            let slot = context
                .get_slots_with_initialized_token()
                .unwrap()
                .into_iter()
                .find(|s| context.get_token_info(*s).is_ok_and(|t| t.label() == "CleonPDF Test"))
                .expect("the new token is listed");
            let session = context.open_rw_session(slot).unwrap();
            session.login(UserType::So, Some(&secret(SO_PIN))).unwrap();
            session.init_pin(&secret(USER_PIN)).unwrap();
            session.logout().unwrap();
            session.login(UserType::User, Some(&secret(USER_PIN))).unwrap();

            let ca = crate::pki::root("Test CA");
            let leaf = crate::pki::end_entity("Ada Lovelace", &ca, &[]);
            let object = |label: &str, id: u8, subject: Vec<u8>, value: Vec<u8>| {
                vec![
                    Attribute::Class(ObjectClass::CERTIFICATE),
                    Attribute::CertificateType(CertificateType::X_509),
                    Attribute::Token(true),
                    Attribute::Label(label.as_bytes().to_vec()),
                    Attribute::Id(vec![id]),
                    Attribute::Subject(subject),
                    Attribute::Value(value),
                ]
            };
            session.create_object(&object("Ada's certificate", 1, leaf.cert.subject.raw.clone(), leaf.cert.raw.clone())).unwrap();
            session.create_object(&object("Test CA", 2, ca.cert.subject.raw.clone(), ca.cert.raw.clone())).unwrap();
            session.create_object(&object("not a certificate", 3, ca.cert.subject.raw.clone(), b"definitely not DER".to_vec())).unwrap();
            Some(Fixture { module, _context: context, leaf: leaf.cert.raw.clone(), ca: ca.cert.raw.clone() })
        })
        .as_ref()
}
