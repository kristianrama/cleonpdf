//! Updating CleonPDF in place from a GitHub release, without network code or UI.
//!
//! Every release carries `SHA256SUMS.txt` (the SHA-256 of each file) and `SHA256SUMS.txt.sig`,
//! an Ed25519 signature over it made in CI with the release key. The app holds the public half
//! (`packaging/update-key.pub`), so it installs a download only when:
//!
//! 1. the checksums verify against that key ([`verify_sums`]), and
//! 2. the download hashes to the checksum listed for its name ([`copy_checked`]).
//!
//! A release without a signature, or one made with another key, is never installed: the user
//! downloads it from the release page as before. [`install`] finds which release file fits the
//! running copy (a macOS app bundle, the Windows MSI install, a Linux AppImage), stages it and
//! swaps it in once CleonPDF has closed.
//!
//! The caller downloads ([`cleonpdf-net`'s client](https://docs.rs/ureq)) and shows progress;
//! everything a server sends is untrusted, so sizes are capped ([`MAX_SUMS`], [`MAX_SIG`],
//! [`MAX_ASSET`]).

use std::fmt;
use std::io::{Read, Write};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

pub mod install;

/// The checksums file every release carries.
pub const SUMS: &str = "SHA256SUMS.txt";
/// Its signature, made with the release key.
pub const SUMS_SIG: &str = "SHA256SUMS.txt.sig";
/// The most bytes read for [`SUMS`]: a line per release file, a few dozen files.
pub const MAX_SUMS: u64 = 64 * 1024;
/// The most bytes read for [`SUMS_SIG`]: one base64 signature.
pub const MAX_SIG: u64 = 1024;
/// The largest release file downloaded (they are about 100 MB).
pub const MAX_ASSET: u64 = 1 << 30;

/// Signed ahead of the checksums, so that a signature made with the release key over anything
/// else can't be passed off as one over a release's checksums.
const CONTEXT: &[u8] = b"CleonPDF release checksums v1\n";

/// Why an update can't go ahead.
#[derive(Debug)]
pub enum UpdateError {
    /// A key that isn't one (`what` says which and why).
    Key(&'static str),
    /// The checksums aren't signed with the release key, or the signature is malformed.
    Signature,
    /// The checksums don't list this file.
    NotListed(String),
    /// The download doesn't match its listed checksum.
    Checksum,
    /// The download is larger than allowed.
    TooLarge(u64),
    /// The user cancelled.
    Cancelled,
    /// This copy of CleonPDF can't update itself (how it was installed).
    Unsupported(String),
    /// A file operation failed.
    Io(std::io::Error),
    /// A system tool (`hdiutil`, `ditto`, `msiexec`) failed.
    Tool { tool: &'static str, detail: String },
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(what) => write!(f, "invalid key: {what}"),
            Self::Signature => f.write_str("the release isn't signed with CleonPDF's release key"),
            Self::NotListed(name) => write!(f, "the release doesn't list {name}"),
            Self::Checksum => f.write_str("the download doesn't match the release's checksum"),
            Self::TooLarge(max) => write!(f, "the download is larger than {} MB", max / (1024 * 1024)),
            Self::Cancelled => f.write_str("cancelled"),
            Self::Unsupported(why) => f.write_str(why),
            Self::Io(e) => write!(f, "{e}"),
            Self::Tool { tool, detail } => write!(f, "{tool} failed: {detail}"),
        }
    }
}

impl std::error::Error for UpdateError {}

impl From<std::io::Error> for UpdateError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The first line of `text` that isn't blank or a `#` comment, trimmed.
fn key_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))
}

/// 32 bytes from one line of base64.
fn key_bytes(text: &str) -> Result<[u8; 32], UpdateError> {
    let line = key_line(text).ok_or(UpdateError::Key("empty"))?;
    // A 32-byte key is 44 base64 characters; refuse anything much longer before decoding it.
    if line.len() > 64 {
        return Err(UpdateError::Key("too long"));
    }
    let bytes = B64.decode(line).map_err(|_| UpdateError::Key("not base64"))?;
    bytes.try_into().map_err(|_| UpdateError::Key("not 32 bytes"))
}

/// The release key's public half, which the app checks releases against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Read `packaging/update-key.pub`: one line of base64 (32 bytes); blank lines and `#`
    /// comments are skipped.
    pub fn parse(text: &str) -> Result<Self, UpdateError> {
        VerifyingKey::from_bytes(&key_bytes(text)?).map(Self).map_err(|_| UpdateError::Key("not an Ed25519 public key"))
    }

    /// One line of base64, as [`PublicKey::parse`] reads it.
    pub fn to_text(&self) -> String {
        B64.encode(self.0.as_bytes())
    }
}

/// The release key's private half. It lives only in the owner's keeping and in CI's secrets.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// A new random key.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn generate() -> Result<Self, UpdateError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| UpdateError::Key("no randomness from the system"))?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    /// Read a key written by [`SecretKey::to_text`] (one line of base64, 32 bytes).
    pub fn parse(text: &str) -> Result<Self, UpdateError> {
        Ok(Self(SigningKey::from_bytes(&key_bytes(text)?)))
    }

    /// One line of base64: the key's 32-byte seed.
    pub fn to_text(&self) -> String {
        B64.encode(self.0.to_bytes())
    }

    /// The public half.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// The signature file for checksums `sums`: one line of base64 and a newline.
    pub fn sign_sums(&self, sums: &[u8]) -> String {
        let mut message = CONTEXT.to_vec();
        message.extend_from_slice(sums);
        format!("{}\n", B64.encode(self.0.sign(&message).to_bytes()))
    }
}

/// Whether `sig` (a [`SUMS_SIG`] file) is `key`'s signature over checksums `sums`.
pub fn verify_sums(key: &PublicKey, sums: &[u8], sig: &str) -> Result<(), UpdateError> {
    let line = key_line(sig).filter(|l| l.len() <= 128).ok_or(UpdateError::Signature)?;
    let bytes: [u8; 64] = B64.decode(line).ok().and_then(|b| b.try_into().ok()).ok_or(UpdateError::Signature)?;
    let mut message = CONTEXT.to_vec();
    message.extend_from_slice(sums);
    key.0.verify_strict(&message, &Signature::from_bytes(&bytes)).map_err(|_| UpdateError::Signature)
}

/// The SHA-256 that checksums `sums` (as `sha256sum` writes them: `<hex>  <name>`, or
/// `<hex> *<name>`) list for file `name`, matched exactly.
pub fn listed_sha256(sums: &str, name: &str) -> Option<[u8; 32]> {
    sums.lines().find_map(|line| {
        let (hex, rest) = line.split_once(char::is_whitespace)?;
        let listed = rest.trim_start().trim_start_matches('*').trim_end_matches('\r');
        (listed == name).then(|| hex_32(hex)).flatten()
    })
}

fn hex_32(hex: &str) -> Option<[u8; 32]> {
    let digits = hex.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        let value = |c: u8| (c as char).to_digit(16);
        *byte = u8::try_from(value(*pair.first()?)? * 16 + value(*pair.get(1)?)?).ok()?;
    }
    Some(out)
}

/// The version in release tag `tag` (`v0.2.7` → `0.2.7`): digits and single dots only, so it
/// can go into a file name and a URL as it is. `None` for anything else.
pub fn version_of_tag(tag: &str) -> Option<&str> {
    let v = tag.strip_prefix(['v', 'V'])?;
    let ok = !v.is_empty() && v.len() <= 32 && v.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    ok.then_some(v)
}

/// Copy a download from `from` to `to`, hashing it on the way, and fail unless it hashes to
/// `expected`. At most `max` bytes are read. `progress` gets the bytes copied so far after each
/// chunk and returns false to cancel.
pub fn copy_checked(
    from: &mut dyn Read,
    to: &mut dyn Write,
    expected: &[u8; 32],
    max: u64,
    progress: &mut dyn FnMut(u64) -> bool,
) -> Result<u64, UpdateError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        total = total.saturating_add(n as u64);
        if total > max {
            return Err(UpdateError::TooLarge(max));
        }
        let chunk = buf.get(..n).ok_or(UpdateError::Checksum)?;
        hasher.update(chunk);
        to.write_all(chunk)?;
        if !progress(total) {
            return Err(UpdateError::Cancelled);
        }
    }
    to.flush()?;
    if hasher.finalize().as_slice() == expected.as_slice() { Ok(total) } else { Err(UpdateError::Checksum) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn keys_round_trip_through_text() {
        let secret = SecretKey::generate().unwrap();
        let again = SecretKey::parse(&secret.to_text()).unwrap();
        assert_eq!(again.public(), secret.public());
        let public = PublicKey::parse(&format!("# CleonPDF release key\n\n{}\n", secret.public().to_text())).unwrap();
        assert_eq!(public, secret.public());
        assert_ne!(SecretKey::generate().unwrap().public(), secret.public(), "keys are random");
        for bad in ["", "# only a comment\n", "not base64!", "AAAA", &"A".repeat(200)] {
            assert!(PublicKey::parse(bad).is_err(), "{bad:?}");
            assert!(SecretKey::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_the_release_key_s_signature_over_these_checksums_verifies() {
        let key = SecretKey::generate().unwrap();
        let sums = b"0123  cleonpdf-0.2.7-macos-universal.dmg\n";
        let sig = key.sign_sums(sums);
        verify_sums(&key.public(), sums, &sig).unwrap();
        // Other checksums, another key, a signature over the bare checksums (no context), junk.
        assert!(verify_sums(&key.public(), b"0124  cleonpdf-0.2.7-macos-universal.dmg\n", &sig).is_err());
        assert!(verify_sums(&SecretKey::generate().unwrap().public(), sums, &sig).is_err());
        let bare = format!("{}\n", B64.encode(key.0.sign(sums).to_bytes()));
        assert!(verify_sums(&key.public(), sums, &bare).is_err(), "the context is part of what is signed");
        for junk in ["", "\n", "AAAA", "!!!", &"A".repeat(400)] {
            assert!(matches!(verify_sums(&key.public(), sums, junk), Err(UpdateError::Signature)), "{junk:?}");
        }
    }

    #[test]
    fn checksums_are_found_by_exact_name() {
        let a = sha(b"a");
        let b = sha(b"b");
        let sums =
            format!("{}  cleonpdf-0.2.7-linux-x86_64.AppImage\n{} *cleonpdf-0.2.7-linux-x86_64.AppImage.zsync\r\nshort  x\n", hex(&a), hex(&b));
        assert_eq!(listed_sha256(&sums, "cleonpdf-0.2.7-linux-x86_64.AppImage"), Some(a));
        assert_eq!(listed_sha256(&sums, "cleonpdf-0.2.7-linux-x86_64.AppImage.zsync"), Some(b));
        assert_eq!(listed_sha256(&sums, "cleonpdf-0.2.7-linux-x86_64"), None, "no prefix matches");
        assert_eq!(listed_sha256(&sums, "x"), None, "a malformed hash is no hash");
        assert_eq!(listed_sha256("", "x"), None);
    }

    #[test]
    fn versions_come_only_from_plain_tags() {
        assert_eq!(version_of_tag("v0.2.7"), Some("0.2.7"));
        assert_eq!(version_of_tag("V1.0.0"), Some("1.0.0"));
        for bad in ["0.2.7", "v", "v0.2.7-rc.1", "v0..7", "v.1", "v1.", "v0.2.7/../../x", "v0.2.7?x", &format!("v{}", "1.".repeat(20))] {
            assert_eq!(version_of_tag(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn downloads_are_checked_capped_and_cancellable() {
        let data = vec![7u8; 200_000];
        let mut out = Vec::new();
        let mut seen = Vec::new();
        let n = copy_checked(&mut data.as_slice(), &mut out, &sha(&data), MAX_ASSET, &mut |n| {
            seen.push(n);
            true
        })
        .unwrap();
        assert_eq!((n, out.len()), (200_000, 200_000));
        assert_eq!(seen.last(), Some(&200_000), "progress reaches the end");
        assert!(matches!(copy_checked(&mut data.as_slice(), &mut Vec::new(), &sha(b"other"), MAX_ASSET, &mut |_| true), Err(UpdateError::Checksum)));
        assert!(matches!(
            copy_checked(&mut data.as_slice(), &mut Vec::new(), &sha(&data), 100_000, &mut |_| true),
            Err(UpdateError::TooLarge(100_000))
        ));
        assert!(matches!(
            copy_checked(&mut data.as_slice(), &mut Vec::new(), &sha(&data), MAX_ASSET, &mut |n| n < 100_000),
            Err(UpdateError::Cancelled)
        ));
        assert!(
            copy_checked(&mut [].as_slice(), &mut Vec::new(), &sha(b""), MAX_ASSET, &mut |_| true).is_ok(),
            "empty is fine if it is what's listed"
        );
    }
}
