//! The TLS crypto provider: rustls's `ring` provider, with the ECDSA certificate signatures it
//! lacks verified by this product's own ECDSA code (RustCrypto's `p256`/`p384`/`p521`, through
//! `cleonpdf-sign`).
//!
//! `ring` verifies ECDSA P-256 and P-384 with SHA-256 or SHA-384 only. Certification authorities
//! also sign with SHA-512, and with P-521 keys: Hungary's Trusted List is served by a host whose
//! certificate chain uses ECDSA with SHA-512, so it could not be fetched at all. Those
//! combinations are added here, for certificate chains and for the TLS handshake's own signature
//! (`ecdsa_secp521r1_sha512`). Nothing else changes: the same roots, the same rules, and a
//! signature is accepted only in canonical DER, as `ring` requires.

use std::sync::{Arc, OnceLock};

use cleonpdf_sign::DigestAlg;
use cleonpdf_sign::PublicKey;
use cleonpdf_sign::keys::Scheme;
use rustls::SignatureScheme;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::alg_id;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Curve {
    P256,
    P384,
    P521,
}

/// ECDSA on `curve` over a digest made with `hash`.
#[derive(Debug)]
struct Ecdsa {
    curve: Curve,
    hash: DigestAlg,
    key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for Ecdsa {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        let key = match self.curve {
            Curve::P256 => PublicKey::P256(public_key.to_vec()),
            Curve::P384 => PublicKey::P384(public_key.to_vec()),
            Curve::P521 => PublicKey::P521(public_key.to_vec()),
        };
        let digest = self.hash.digest(&[message]);
        // A note means the signature was read leniently (raw r ‖ s, padding, trailing bytes):
        // fine in a PDF, not in TLS.
        let mut notes = Vec::new();
        match key.verify_noting(Scheme::Ecdsa, self.hash, &digest, signature, &mut notes) {
            Ok(true) if notes.is_empty() => Ok(()),
            _ => Err(InvalidSignature),
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

static P256_SHA512: Ecdsa = Ecdsa { curve: Curve::P256, hash: DigestAlg::Sha512, key: alg_id::ECDSA_P256, signature: alg_id::ECDSA_SHA512 };
static P384_SHA512: Ecdsa = Ecdsa { curve: Curve::P384, hash: DigestAlg::Sha512, key: alg_id::ECDSA_P384, signature: alg_id::ECDSA_SHA512 };
static P521_SHA256: Ecdsa = Ecdsa { curve: Curve::P521, hash: DigestAlg::Sha256, key: alg_id::ECDSA_P521, signature: alg_id::ECDSA_SHA256 };
static P521_SHA384: Ecdsa = Ecdsa { curve: Curve::P521, hash: DigestAlg::Sha384, key: alg_id::ECDSA_P521, signature: alg_id::ECDSA_SHA384 };
static P521_SHA512: Ecdsa = Ecdsa { curve: Curve::P521, hash: DigestAlg::Sha512, key: alg_id::ECDSA_P521, signature: alg_id::ECDSA_SHA512 };

/// What is added to `ring`'s set, for certificate chains.
static ADDED: [&dyn SignatureVerificationAlgorithm; 5] = [&P256_SHA512, &P384_SHA512, &P521_SHA256, &P521_SHA384, &P521_SHA512];
/// The handshake signature scheme `ring` lacks: TLS 1.3 ties ECDSA SHA-512 to P-521.
static P521_HANDSHAKE: [&dyn SignatureVerificationAlgorithm; 1] = [&P521_SHA512];

/// `ring`'s provider with [`ADDED`]. Built once: the algorithm lists rustls takes are `'static`.
pub(crate) fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let mut p = rustls::crypto::ring::default_provider();
            p.signature_verification_algorithms = with_added(p.signature_verification_algorithms);
            Arc::new(p)
        })
        .clone()
}

fn with_added(base: WebPkiSupportedAlgorithms) -> WebPkiSupportedAlgorithms {
    let all: Vec<&'static dyn SignatureVerificationAlgorithm> = base.all.iter().copied().chain(ADDED.iter().copied()).collect();
    let mut mapping: Vec<(SignatureScheme, &'static [&'static dyn SignatureVerificationAlgorithm])> = base.mapping.to_vec();
    if !mapping.iter().any(|(s, _)| *s == SignatureScheme::ECDSA_NISTP521_SHA512) {
        mapping.push((SignatureScheme::ECDSA_NISTP521_SHA512, &P521_HANDSHAKE));
    }
    // Leaked once per process (see `provider`): rustls keeps these lists for its lifetime.
    WebPkiSupportedAlgorithms { all: Vec::leak(all), mapping: Vec::leak(mapping) }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_added_algorithms_are_the_ones_ring_lacks_and_nothing_is_dropped() {
        let ring = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        let ours = provider().signature_verification_algorithms;
        let ids = |a: &[&dyn SignatureVerificationAlgorithm]| -> Vec<(AlgorithmIdentifier, AlgorithmIdentifier)> {
            a.iter().map(|x| (x.public_key_alg_id(), x.signature_alg_id())).collect()
        };
        for added in ids(&ADDED) {
            assert!(!ids(ring.all).contains(&added), "ring already has {added:?}");
        }
        assert_eq!(ours.all.len(), ring.all.len() + ADDED.len());
        assert!(ids(ring.all).iter().all(|id| ids(ours.all).contains(id)));
        assert_eq!(ours.mapping.len(), ring.mapping.len() + 1);
        assert!(ours.mapping.iter().any(|(s, _)| *s == SignatureScheme::ECDSA_NISTP521_SHA512));
        // Built once.
        assert!(Arc::ptr_eq(&provider(), &provider()));
    }

    #[test]
    fn every_client_uses_this_provider() {
        // Where the system has trusted roots to load (CI and desktops do).
        for redirects in [0, crate::MAX_REDIRECTS] {
            let Ok(agent) = crate::client(std::time::Duration::from_secs(5), redirects, true) else { return };
            let used = agent.config().tls_config().unversioned_rustls_crypto_provider().clone();
            assert!(used.is_some_and(|p| Arc::ptr_eq(&p, &provider())), "redirects {redirects}");
        }
    }

    fn der(name: &str) -> rustls::pki_types::CertificateDer<'static> {
        let path = format!("{}/tests/data/tls/{name}", env!("CARGO_MANIFEST_DIR"));
        rustls::pki_types::CertificateDer::from(std::fs::read(&path).unwrap())
    }

    /// Verify the server certificate `leaf` for `tl.example.test`, trusting only `root`, in 2027.
    fn chain(leaf: &str, root: &str, with: Arc<CryptoProvider>) -> Result<(), rustls::Error> {
        use rustls::client::danger::ServerCertVerifier as _;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der(root)).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), with).build().unwrap();
        let name = rustls::pki_types::ServerName::try_from("tl.example.test").unwrap();
        let now = rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000));
        verifier.verify_server_cert(&der(leaf), &[], &name, &[], now).map(|_| ())
    }

    #[test]
    fn chains_signed_with_ecdsa_and_sha512_or_p521_verify() {
        let ring = || Arc::new(rustls::crypto::ring::default_provider());
        // As Hungary's Trusted List host: a P-384 authority that signs with SHA-512. `ring` alone
        // cannot check it; with the additions it is checked and accepted.
        assert!(chain("leaf-p384-sha512.der", "root-p384.der", ring()).is_err());
        chain("leaf-p384-sha512.der", "root-p384.der", provider()).unwrap();
        for (leaf, root) in [
            ("leaf-p256-sha512.der", "root-p256.der"),
            ("leaf-p521-sha256.der", "root-p521.der"),
            ("leaf-p521-sha384.der", "root-p521.der"),
            ("leaf-p521-sha512.der", "root-p521.der"),
        ] {
            assert!(chain(leaf, root, ring()).is_err(), "{leaf}");
            chain(leaf, root, provider()).unwrap_or_else(|e| panic!("{leaf}: {e}"));
        }
        // What `ring` checks itself is unchanged.
        chain("leaf-p384-sha384.der", "root-p384.der", ring()).unwrap();
        chain("leaf-p384-sha384.der", "root-p384.der", provider()).unwrap();
    }

    #[test]
    fn a_sha512_signature_by_another_key_or_another_root_is_refused() {
        // Under the trusted root's name, signed by another P-384 key.
        assert!(matches!(
            chain("leaf-p384-sha512-impostor.der", "root-p384.der", provider()),
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))
        ));
        // Signed by a root that is not the one trusted.
        assert!(chain("leaf-p384-sha512.der", "root-p521.der", provider()).is_err());
        assert!(chain("leaf-p521-sha512.der", "root-p384.der", provider()).is_err());
    }

    #[test]
    fn only_canonical_der_signatures_on_the_right_curve_verify() {
        let message = b"tbsCertificate";
        let key = p384::ecdsa::SigningKey::from_slice(&[7u8; 48]).unwrap();
        let point = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let digest = DigestAlg::Sha512.digest(&[message]);
        let sig: p384::ecdsa::Signature = {
            use p384::ecdsa::signature::hazmat::PrehashSigner;
            key.sign_prehash(&digest).unwrap()
        };
        let der = sig.to_der().as_bytes().to_vec();
        assert!(P384_SHA512.verify_signature(&point, message, &der).is_ok());
        // The raw r ‖ s form, which a PDF reader tolerates, is not DER.
        assert!(P384_SHA512.verify_signature(&point, message, &sig.to_bytes()).is_err());
        // Trailing bytes, another message, another hash, a key for another curve, garbage.
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(P384_SHA512.verify_signature(&point, message, &trailing).is_err());
        assert!(P384_SHA512.verify_signature(&point, b"something else", &der).is_err());
        assert!(P521_SHA384.verify_signature(&point, message, &der).is_err());
        assert!(P256_SHA512.verify_signature(&point, message, &der).is_err());
        assert!(P384_SHA512.verify_signature(&[], message, &der).is_err());
        assert!(P384_SHA512.verify_signature(&point, message, &[]).is_err());
        assert!(P384_SHA512.verify_signature(&[0xFF; 97], message, &der).is_err());
    }
}
