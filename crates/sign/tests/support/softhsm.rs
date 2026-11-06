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
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use cryptoki::types::Ulong;
use secrecy::SecretString;

pub const SO_PIN: &str = "so-pin-1234";
pub const USER_PIN: &str = "user-pin-1234";

/// What the fixture put on the token.
pub struct Fixture {
    pub module: PathBuf,
    /// Kept alive: the library is initialised through it.
    _context: Pkcs11,
    pub leaf: Vec<u8>,
    pub ca: Vec<u8>,
}

/// The token with signing keys: label, and the identifiers of its two key pairs (each shared by
/// the key pair's certificate). The CA that issued their certificates is `Fixture::ca`.
pub const KEYS_LABEL: &str = "CleonPDF Keys";
pub const EC_ID: [u8; 1] = [0x10];
pub const RSA_ID: [u8; 1] = [0x11];
/// A private key of its own whose certificate carries *another* key's public half: a token that
/// signs with the wrong key.
pub const MISMATCH_ID: [u8; 1] = [0x12];
/// A P-521 key pair and its certificate: a key type CleonPDF verifies but does not sign with.
pub const P521_ID: [u8; 1] = [0x13];

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
            let session = new_token(&context, "CleonPDF Test");
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

            // A second token holds two key pairs generated on it, with certificates the CA issued.
            let keys = new_token(&context, KEYS_LABEL);
            keys.create_object(&object("Test CA", 2, ca.cert.subject.raw.clone(), ca.cert.raw.clone())).unwrap();
            let public_id = |id: &[u8], label: &str| {
                vec![Attribute::Token(true), Attribute::Verify(true), Attribute::Id(id.to_vec()), Attribute::Label(label.as_bytes().to_vec())]
            };
            let private = |id: &[u8], label: &str| {
                vec![
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Sign(true),
                    Attribute::Id(id.to_vec()),
                    Attribute::Label(label.as_bytes().to_vec()),
                ]
            };
            // P-256 (the curve's OID, DER-encoded, is the key's parameters).
            let mut ec_public = public_id(&EC_ID, "EC signer");
            ec_public.push(Attribute::EcParams(vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]));
            let (public, _) = keys.generate_key_pair(&Mechanism::EccKeyPairGen, &ec_public, &private(&EC_ID, "EC signer")).unwrap();
            let Attribute::EcPoint(wrapped) = keys.get_attributes(public, &[AttributeType::EcPoint]).unwrap().remove(0) else {
                panic!("no EC point")
            };
            // The point comes as a DER OCTET STRING around the uncompressed point.
            let is_wrapped = wrapped.first() == Some(&0x04) && wrapped.get(1).map(|l| *l as usize + 2) == Some(wrapped.len());
            let point = if is_wrapped { wrapped.get(2..).unwrap_or_default().to_vec() } else { wrapped.clone() };
            let spki = cleonpdf_sign::keys::PublicKey::P256(point).spki();
            let cert = crate::pki::end_entity_for_key("Token EC Signer", &ca, spki.clone(), &[]);
            keys.create_object(&object("EC signer", EC_ID[0], cert.subject.raw.clone(), cert.raw.clone())).unwrap();
            // Another P-256 key pair on the token, under a certificate for the key above.
            let mut other_public = public_id(&MISMATCH_ID, "mismatched");
            other_public.push(Attribute::EcParams(vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]));
            keys.generate_key_pair(&Mechanism::EccKeyPairGen, &other_public, &private(&MISMATCH_ID, "mismatched")).unwrap();
            let cert = crate::pki::end_entity_for_key("Token Mismatched Signer", &ca, spki, &[]);
            keys.create_object(&object("mismatched", MISMATCH_ID[0], cert.subject.raw.clone(), cert.raw.clone())).unwrap();
            let mut p521_public = public_id(&P521_ID, "P-521");
            p521_public.push(Attribute::EcParams(vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]));
            let (public, _) = keys.generate_key_pair(&Mechanism::EccKeyPairGen, &p521_public, &private(&P521_ID, "P-521")).unwrap();
            let Attribute::EcPoint(wrapped) = keys.get_attributes(public, &[AttributeType::EcPoint]).unwrap().remove(0) else {
                panic!("no EC point")
            };
            // DER OCTET STRING with a long-form length (0x81 0x85) around the 133-byte point.
            let point = wrapped.get(3..).unwrap_or_default().to_vec();
            let cert = crate::pki::end_entity_for_key("Token P-521 Signer", &ca, cleonpdf_sign::keys::PublicKey::P521(point).spki(), &[]);
            keys.create_object(&object("P-521", P521_ID[0], cert.subject.raw.clone(), cert.raw.clone())).unwrap();
            // RSA 2048.
            let mut rsa_public = public_id(&RSA_ID, "RSA signer");
            rsa_public.extend([Attribute::ModulusBits(Ulong::try_from(2048usize).unwrap()), Attribute::PublicExponent(vec![1, 0, 1])]);
            let (public, _) = keys.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &rsa_public, &private(&RSA_ID, "RSA signer")).unwrap();
            let got = keys.get_attributes(public, &[AttributeType::Modulus, AttributeType::PublicExponent]).unwrap();
            let (mut n, mut e) = (Vec::new(), Vec::new());
            for a in got {
                match a {
                    Attribute::Modulus(v) => n = v,
                    Attribute::PublicExponent(v) => e = v,
                    _ => {}
                }
            }
            let spki = cleonpdf_sign::keys::PublicKey::Rsa { n, e }.spki();
            let cert = crate::pki::end_entity_for_key("Token RSA Signer", &ca, spki, &[]);
            keys.create_object(&object("RSA signer", RSA_ID[0], cert.subject.raw.clone(), cert.raw.clone())).unwrap();
            Some(Fixture { module, _context: context, leaf: leaf.cert.raw.clone(), ca: ca.cert.raw.clone() })
        })
        .as_ref()
}

/// Initialise the next free token with `label`, give it the test PIN and return a session logged
/// in as its user (the session keeps the login for creating objects).
fn new_token(context: &Pkcs11, label: &str) -> cryptoki::session::Session {
    let free = context
        .get_all_slots()
        .unwrap()
        .into_iter()
        .find(|s| context.get_token_info(*s).is_ok_and(|t| !t.token_initialized()))
        .expect("SoftHSM offers a free slot");
    context.init_token(free, &secret(SO_PIN), label).expect("token initialises");
    // SoftHSM renumbers the slot once the token exists.
    let slot = context
        .get_slots_with_initialized_token()
        .unwrap()
        .into_iter()
        .find(|s| context.get_token_info(*s).is_ok_and(|t| t.label() == label))
        .expect("the new token is listed");
    let session = context.open_rw_session(slot).unwrap();
    session.login(UserType::So, Some(&secret(SO_PIN))).unwrap();
    session.init_pin(&secret(USER_PIN)).unwrap();
    session.logout().unwrap();
    session.login(UserType::User, Some(&secret(USER_PIN))).unwrap();
    session
}
