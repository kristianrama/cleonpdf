//! PKCS #11 tokens: smart cards, USB tokens and HSMs, reached through the vendor's library
//! (`opensc-pkcs11.so`, a CA's middleware, SoftHSM…).
//!
//! **A PKCS #11 module is code that runs inside this process.** Loading one is as trusted as
//! installing a program, so a module path comes only from the user (a setting, the file they
//! picked, an environment variable of the process that started us) or from the fixed list of
//! places a system package puts one ([`known_modules`]); never from a document and never from a
//! tool argument that is not checked against those ([`is_allowed`]).
//!
//! It lists the tokens a module shows and the certificates on them (no PIN needed), and signs
//! with a token's key: [`Module::identity`] logs in with the PIN, finds the private key that
//! shares a certificate's identifier and returns a [`DigitalId`] whose key signs on the token.
//! The key never leaves it. What a token or module says about itself is untrusted text and is
//! cleaned and capped before it is returned.
//!
//! A PIN is held only to log in: it is wrapped in a secret string that is wiped when dropped,
//! never stored, never put in a message. The session stays logged in for as long as the
//! identity lives and ends with it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as P11Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::keys::{DigestAlg, ExternalKey, PrivateKey, PublicKey, Scheme};
use crate::pkcs12::DigitalId;
use crate::{Certificate, SignError};

/// The most slots, certificates per token and bytes per certificate looked at; a module that
/// returns more is read up to these and no further.
const MAX_SLOTS: usize = 64;
const MAX_CERTIFICATES: usize = 128;
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
/// The longest label, manufacturer, model or serial number kept, in characters.
const MAX_TEXT: usize = 64;

/// A loaded and initialised PKCS #11 module. One per library file for the life of the process:
/// a library may be initialised only once, so loading the same file again returns this one.
#[derive(Debug)]
pub struct Module {
    path: PathBuf,
    context: Pkcs11,
}

/// One token (a card in a reader, a USB token, an HSM partition).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    /// The slot it is in; only meaningful to the module that gave it.
    pub slot: u64,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    /// True when the user has to enter a PIN before the token's private keys can be used.
    pub login_required: bool,
    /// True when the token takes the PIN itself (a reader with a PIN pad): none is passed to it.
    pub protected_authentication_path: bool,
}

/// A certificate on a token, with the identifier its private key shares.
#[derive(Clone, Debug)]
pub struct TokenCertificate {
    pub label: String,
    /// `CKA_ID`: the private key that goes with this certificate has the same one.
    pub id: Vec<u8>,
    pub certificate: Certificate,
}

/// What reading one token's certificates gave.
#[derive(Clone, Debug, Default)]
pub struct TokenCertificates {
    pub certificates: Vec<TokenCertificate>,
    /// Certificate objects that could not be used: not X.509, unreadable, too large or too many.
    pub skipped: usize,
}

fn registry() -> &'static Mutex<HashMap<PathBuf, Arc<Module>>> {
    static LOADED: OnceLock<Mutex<HashMap<PathBuf, Arc<Module>>>> = OnceLock::new();
    LOADED.get_or_init(Mutex::default)
}

/// A message that names the module by file name only: the full path is the user's business.
fn describe(path: &Path, what: impl std::fmt::Display) -> SignError {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    SignError::Crypto(format!("PKCS #11 module {name}: {what}"))
}

/// Text from a token or module made safe to show: control characters become spaces, the ends
/// are trimmed and the length is capped.
fn clean(text: &str) -> String {
    let spaced: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    spaced.trim().chars().take(MAX_TEXT).collect()
}

impl Module {
    /// Load and initialise the module at `path`. The same file is loaded once per process.
    ///
    /// The caller decides that `path` may be loaded (see the module documentation); this runs
    /// the library's code.
    pub fn load(path: &Path) -> Result<Arc<Module>, SignError> {
        let key = std::fs::canonicalize(path).map_err(|e| describe(path, format!("can't be opened ({e})")))?;
        if !key.is_file() {
            return Err(describe(path, "is not a file"));
        }
        let mut loaded = registry().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(module) = loaded.get(&key) {
            return Ok(module.clone());
        }
        let context = Pkcs11::new(&key).map_err(|e| describe(path, format!("can't be loaded ({e})")))?;
        match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) => {}
            // Something else in this process already initialised the library; the context is
            // usable all the same.
            Err(P11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(describe(path, format!("didn't start ({e})"))),
        }
        let module = Arc::new(Module { path: key.clone(), context });
        loaded.insert(key, module.clone());
        Ok(module)
    }

    /// The file this module was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The tokens present now.
    pub fn tokens(&self) -> Result<Vec<TokenInfo>, SignError> {
        let slots = self.context.get_slots_with_token().map_err(|e| describe(&self.path, format!("couldn't list its tokens ({e})")))?;
        let mut tokens = Vec::new();
        for slot in slots.into_iter().take(MAX_SLOTS) {
            // A slot whose token can't be read (just removed, or not initialised) is not listed.
            let Ok(info) = self.context.get_token_info(slot) else { continue };
            if !info.token_initialized() {
                continue;
            }
            tokens.push(TokenInfo {
                slot: slot.id(),
                label: clean(info.label()),
                manufacturer: clean(info.manufacturer_id()),
                model: clean(info.model()),
                serial: clean(info.serial_number()),
                login_required: info.login_required(),
                protected_authentication_path: info.protected_authentication_path(),
            });
        }
        Ok(tokens)
    }

    /// The X.509 certificates on the token in `slot`. Certificates are public objects: no PIN.
    pub fn certificates(&self, slot: u64) -> Result<TokenCertificates, SignError> {
        let slot = Slot::try_from(slot).map_err(|_| describe(&self.path, "no such slot"))?;
        let session = self.context.open_ro_session(slot).map_err(|e| describe(&self.path, format!("couldn't open the token ({e})")))?;
        let template = [Attribute::Class(ObjectClass::CERTIFICATE), Attribute::CertificateType(CertificateType::X_509)];
        let objects = session.find_objects(&template).map_err(|e| describe(&self.path, format!("couldn't list the certificates ({e})")))?;
        let mut out = TokenCertificates::default();
        for (i, object) in objects.into_iter().enumerate() {
            if i >= MAX_CERTIFICATES {
                out.skipped += 1;
                continue;
            }
            let Ok(attributes) = session.get_attributes(object, &[AttributeType::Value, AttributeType::Label, AttributeType::Id]) else {
                out.skipped += 1;
                continue;
            };
            let (mut value, mut label, mut id) = (None, String::new(), Vec::new());
            for attribute in attributes {
                match attribute {
                    Attribute::Value(v) => value = Some(v),
                    Attribute::Label(l) => label = clean(&String::from_utf8_lossy(&l)),
                    Attribute::Id(v) => id = v.into_iter().take(MAX_CERTIFICATE_BYTES).collect(),
                    _ => {}
                }
            }
            match value.filter(|v| v.len() <= MAX_CERTIFICATE_BYTES).map(|v| Certificate::parse(&v)) {
                Some(Ok(certificate)) => out.certificates.push(TokenCertificate { label, id, certificate }),
                _ => out.skipped += 1,
            }
        }
        Ok(out)
    }
}

/// A private key on a token. It signs there; the PIN is not kept, only the logged-in session.
struct TokenKey {
    /// The session is `Send` but not `Sync`: one signature at a time.
    session: Mutex<Session>,
    key: ObjectHandle,
    public: PublicKey,
    module: PathBuf,
}

impl ExternalKey for TokenKey {
    fn sign(&self, alg: DigestAlg, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        let digest = alg.digest(&[msg]);
        // RSA: the token pads (PKCS #1 v1.5) what it is given, so it is given the DigestInfo.
        // ECDSA: the token signs the hash as it is.
        let (mechanism, data, scheme) = match &self.public {
            PublicKey::Rsa { .. } => (Mechanism::RsaPkcs, crate::rsa_pad::digest_info(alg, &digest, true), Scheme::RsaPkcs1),
            _ => (Mechanism::Ecdsa, digest.clone(), Scheme::Ecdsa),
        };
        let raw = {
            let session = self.session.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            session
                .sign(&mechanism, self.key, &data)
                .map_err(|e| describe(&self.module, format!("didn't sign (is the token still connected?) ({e})")))?
        };
        let signature = self.public.store_signature_der(&raw)?;
        // What comes back from a token is checked against the certificate's key before it goes
        // into a file: a token that signs with another key, or badly, is caught here.
        match self.public.verify(scheme, alg, &digest, &signature) {
            Ok(true) => Ok(signature),
            _ => Err(describe(&self.module, "returned a signature that doesn't match the certificate's key")),
        }
    }
}

/// The PIN problems a user can act on, said plainly; anything else is the module's own error.
fn login_error(path: &Path, e: P11Error) -> SignError {
    match e {
        P11Error::Pkcs11(RvError::PinIncorrect, _) => describe(path, "the PIN is not correct (a token locks after a few wrong tries)"),
        P11Error::Pkcs11(RvError::PinLocked, _) => describe(path, "the PIN is locked; the token's issuer has to unlock it"),
        P11Error::Pkcs11(RvError::PinLenRange, _) => describe(path, "the PIN has a length this token doesn't accept"),
        P11Error::Pkcs11(RvError::PinExpired, _) => describe(path, "the PIN has expired; change it with the token's own software"),
        other => describe(path, format!("couldn't log in ({other})")),
    }
}

impl Module {
    /// The identity on the token in `slot` whose certificate has `key_id`: log in with `pin`,
    /// find the private key with the same identifier and return a [`DigitalId`] that signs on
    /// the token. `chain` holds the issuers found among the token's other certificates.
    ///
    /// `pin` is needed when the token [`TokenInfo::login_required`] and has no
    /// [`TokenInfo::protected_authentication_path`]. It is used to log in and not kept; callers
    /// should wipe their own copy. RSA, P-256 and P-384 keys sign; other key types are refused.
    pub fn identity(&self, slot: u64, key_id: &[u8], pin: Option<&str>) -> Result<DigitalId, SignError> {
        let slot_handle = Slot::try_from(slot).map_err(|_| describe(&self.path, "no such slot"))?;
        let info = self.context.get_token_info(slot_handle).map_err(|e| describe(&self.path, format!("couldn't read the token ({e})")))?;
        let pin: Option<AuthPin> = match pin {
            Some(p) => Some(AuthPin::from(p)),
            None if info.login_required() && !info.protected_authentication_path() => {
                return Err(describe(&self.path, "this token needs a PIN to sign"));
            }
            None => None,
        };
        let found = self.certificates(slot)?;
        let certificate = found
            .certificates
            .iter()
            .find(|c| c.id == key_id)
            .ok_or_else(|| describe(&self.path, "the token has no certificate with that identifier"))?
            .certificate
            .clone();
        // Refuse a key type that can't sign before asking the token anything.
        if certificate.public_key.store_signing_key().is_none() {
            return Err(SignError::Unsupported(format!("signing with {} keys on a token", certificate.public_key.describe())));
        }
        let session = self.context.open_ro_session(slot_handle).map_err(|e| describe(&self.path, format!("couldn't open the token ({e})")))?;
        if info.login_required() {
            match session.login(UserType::User, pin.as_ref()) {
                Ok(()) => {}
                // Another session of this process logged in already: the login holds token-wide.
                Err(P11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                Err(e) => return Err(login_error(&self.path, e)),
            }
        }
        let template = [Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(key_id.to_vec())];
        let key = session
            .find_objects(&template)
            .map_err(|e| describe(&self.path, format!("couldn't look for the private key ({e})")))?
            .into_iter()
            .next()
            .ok_or_else(|| describe(&self.path, "the token holds no private key for that certificate"))?;
        let pool: Vec<Certificate> = found.certificates.iter().map(|c| c.certificate.clone()).collect();
        let chain: Vec<Certificate> =
            crate::x509::build_chain(&certificate, &pool, None).into_iter().skip(1).filter(|c| !c.is_self_signed()).cloned().collect();
        let label = found.certificates.iter().find(|c| c.id == key_id).map(|c| c.label.clone()).filter(|l| !l.is_empty());
        let token_key = TokenKey { session: Mutex::new(session), key, public: certificate.public_key.clone(), module: self.path.clone() };
        Ok(DigitalId { key: PrivateKey::external(certificate.public_key.clone(), Arc::new(token_key)), certificate, chain, friendly_name: label })
    }
}

/// The `pkcs11:<SHA-256 of the certificate>` reference CleonPDF keeps for a token identity.
pub fn reference(c: &Certificate) -> String {
    let d = DigestAlg::Sha256.digest(&[&c.raw]);
    format!("pkcs11:{}", d.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// The token identity a reference (or a certificate common name) names, searched in the modules
/// [`configured_modules`] and [`known_modules`] give, and opened with `pin`. A module that fails
/// to load is skipped; if nothing matches, the error says which could not be read.
pub fn find(reference_or_name: &str, pin: Option<&str>) -> Result<DigitalId, SignError> {
    let name = reference_or_name.strip_prefix("pkcs11:").unwrap_or(reference_or_name);
    let mut seen = Vec::new();
    let mut unreadable = Vec::new();
    for path in configured_modules().into_iter().chain(known_modules()) {
        let real = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.contains(&real) {
            continue;
        }
        seen.push(real);
        let module = match Module::load(&path) {
            Ok(m) => m,
            Err(e) => {
                unreadable.push(e.to_string());
                continue;
            }
        };
        let Ok(tokens) = module.tokens() else { continue };
        for token in tokens {
            let Ok(found) = module.certificates(token.slot) else { continue };
            if let Some(c) = found
                .certificates
                .iter()
                .find(|c| reference(&c.certificate) == reference_or_name || c.certificate.subject.common_name() == Some(name))
            {
                return module.identity(token.slot, &c.id, pin);
            }
        }
    }
    let note = if unreadable.is_empty() { String::new() } else { format!(" ({})", unreadable.join("; ")) };
    Err(SignError::Crypto(format!("no PKCS #11 identity {reference_or_name} on the tokens of the modules CleonPDF may use{note}")))
}

/// Where system packages put PKCS #11 modules, that exist on this machine. These are the only
/// modules a tool may name without the user having configured them.
pub fn known_modules() -> Vec<PathBuf> {
    const CANDIDATES: &[&str] = &[
        // OpenSC (smart cards and PIV/CAC/national ID cards).
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib64/opensc-pkcs11.so",
        "/usr/lib/opensc-pkcs11.so",
        "/usr/local/lib/opensc-pkcs11.so",
        "/opt/homebrew/lib/opensc-pkcs11.so",
        "/Library/OpenSC/lib/opensc-pkcs11.so",
        "/usr/local/lib/pkcs11/opensc-pkcs11.so",
        // SoftHSM (software tokens, for testing).
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        // Windows OpenSC installs here.
        "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",
    ];
    CANDIDATES.iter().map(PathBuf::from).filter(|p| p.is_file()).collect()
}

/// The modules the process that started us was told about: the paths in the environment
/// variable `CLEONPDF_PKCS11_MODULES` (separated like `PATH`), that exist.
pub fn configured_modules() -> Vec<PathBuf> {
    std::env::var_os("CLEONPDF_PKCS11_MODULES")
        .map(|value| std::env::split_paths(&value).filter(|p| !p.as_os_str().is_empty() && p.is_file()).collect())
        .unwrap_or_default()
}

/// Whether `path` is one of [`configured_modules`] or [`known_modules`] (compared by real path,
/// so a link or `..` does not get around it). Tools check this before [`Module::load`].
pub fn is_allowed(path: &Path) -> bool {
    let Ok(wanted) = std::fs::canonicalize(path) else { return false };
    configured_modules().into_iter().chain(known_modules()).filter_map(|p| std::fs::canonicalize(p).ok()).any(|p| p == wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_from_a_token_is_made_safe_to_show() {
        assert_eq!(clean("  My\u{0}Token\u{1b}[31m \n"), "My Token [31m");
        assert_eq!(clean(&"x".repeat(500)).chars().count(), MAX_TEXT);
        assert_eq!(clean(""), "");
    }

    #[test]
    fn a_path_is_allowed_only_if_it_names_a_known_or_configured_module() {
        assert!(!is_allowed(Path::new("/definitely/not/here.so")));
        // A real file that no one listed is refused: being a file is not enough.
        let me = std::env::current_exe().unwrap();
        assert!(!is_allowed(&me));
    }

    #[test]
    fn a_missing_file_or_a_directory_is_an_error_that_names_the_file_only() {
        let err = Module::load(Path::new("/nonexistent/dir/libfoo.so")).unwrap_err().to_string();
        assert!(err.contains("libfoo.so") && !err.contains("/nonexistent"), "{err}");
        let err = Module::load(&std::env::temp_dir()).unwrap_err().to_string();
        assert!(err.contains("is not a file"), "{err}");
        // A file that is not a library is refused by the loader, not run.
        let junk = std::env::temp_dir().join(format!("cleonpdf-not-a-module-{}.so", std::process::id()));
        std::fs::write(&junk, b"not a library").unwrap();
        let err = Module::load(&junk).unwrap_err().to_string();
        assert!(err.contains("can't be loaded"), "{err}");
        let _ = std::fs::remove_file(&junk);
    }
}
