//! `cargo xtask update-key`: the release key that in-app updates are checked against.
//!
//! - `new [--out FILE]` makes a key: its private half goes to FILE (default
//!   `~/.cleonpdf-release-key`, readable only by you; never committed), its public half into
//!   `packaging/update-key.pub`, which the app is built with.
//! - `sign FILE` signs a release's `SHA256SUMS.txt` with the private key in the
//!   `CLEONPDF_RELEASE_KEY` environment variable (CI's secret) and writes `FILE.sig`. It refuses
//!   a key whose public half isn't the one in `packaging/update-key.pub`, so a release is never
//!   signed with a key the app doesn't know.
//! - `verify FILE` checks `FILE.sig` against `packaging/update-key.pub`.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use cleonpdf_update::{PublicKey, SecretKey, verify_sums};

use crate::gates;

/// The environment variable (and GitHub secret) holding the private key.
pub const SECRET_ENV: &str = "CLEONPDF_RELEASE_KEY";
const PUBLIC_FILE: &str = "packaging/update-key.pub";

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let root = gates::root();
    let public_file = root.join(PUBLIC_FILE);
    match args.first().map(String::as_str) {
        Some("new") => {
            let out = match args.get(1).map(String::as_str) {
                Some("--out") => PathBuf::from(args.get(2).context("--out needs a file")?),
                Some(other) => bail!("unknown argument {other}"),
                None => default_secret_file()?,
            };
            new_key(&out, &public_file)
        }
        Some("sign") => {
            let file = PathBuf::from(args.get(1).context("sign needs the SHA256SUMS.txt to sign")?);
            let secret = std::env::var(SECRET_ENV).with_context(|| format!("{SECRET_ENV} isn't set"))?;
            let public = std::fs::read_to_string(&public_file).with_context(|| format!("reading {PUBLIC_FILE}"))?;
            let sig = sign(&secret, &public, &std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?)?;
            let out = sig_path(&file);
            std::fs::write(&out, sig).with_context(|| format!("writing {}", out.display()))?;
            println!("signed: {}", out.display());
            Ok(())
        }
        Some("verify") => {
            let file = PathBuf::from(args.get(1).context("verify needs the SHA256SUMS.txt to check")?);
            let key = PublicKey::parse(&std::fs::read_to_string(&public_file)?).map_err(anyhow::Error::msg).context(PUBLIC_FILE)?;
            let sig = std::fs::read_to_string(sig_path(&file)).with_context(|| format!("reading {}", sig_path(&file).display()))?;
            verify_sums(&key, &std::fs::read(&file)?, &sig).map_err(anyhow::Error::msg)?;
            println!("good signature: {}", file.display());
            Ok(())
        }
        _ => bail!("usage: cargo xtask update-key new [--out FILE] | sign SHA256SUMS.txt | verify SHA256SUMS.txt"),
    }
}

fn default_secret_file() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).context("no home folder: pass --out FILE")?;
    Ok(PathBuf::from(home).join(".cleonpdf-release-key"))
}

fn sig_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

fn new_key(out: &Path, public_file: &Path) -> anyhow::Result<()> {
    if out.exists() {
        bail!(
            "{} already exists: a second key would leave every release signed with the first unable to install. Move it away first if you really mean to replace it.",
            out.display()
        );
    }
    let key = SecretKey::generate().map_err(anyhow::Error::msg)?;
    write_private(out, &format!("{}\n", key.to_text()))?;
    let current = std::fs::read_to_string(public_file).unwrap_or_default();
    std::fs::write(public_file, with_key(&current, &key.public())).with_context(|| format!("writing {}", public_file.display()))?;
    println!("Private key: {} (keep it safe and never commit it)", out.display());
    println!("Public key:  {} → {PUBLIC_FILE}", key.public().to_text());
    println!();
    println!("Next:");
    println!("  1. GitHub ▸ the repository ▸ Settings ▸ Secrets and variables ▸ Actions ▸ New repository secret:");
    println!("     name {SECRET_ENV}, value the one line in {}.", out.display());
    println!("  2. Commit {PUBLIC_FILE} (a pull request into main).");
    println!("  3. Keep a copy of {} somewhere safe (a password manager): without it, a later", out.display());
    println!("     release can't be installed from inside the app by the versions that know this key.");
    Ok(())
}

/// Write the private key readable only by its owner.
fn write_private(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| format!("creating {}", path.display()))?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

/// `pub_file` (the current `packaging/update-key.pub`) with its key line set to `key`: comment
/// lines are kept, any other line is replaced.
fn with_key(pub_file: &str, key: &PublicKey) -> String {
    let mut out: String = pub_file.lines().filter(|l| l.trim_start().starts_with('#')).map(|l| format!("{l}\n")).collect();
    out.push_str(&key.to_text());
    out.push('\n');
    out
}

/// The signature file for `sums`, made with the private key `secret`, whose public half must be
/// the one in `public` (the contents of `packaging/update-key.pub`).
fn sign(secret: &str, public: &str, sums: &[u8]) -> anyhow::Result<String> {
    let key = SecretKey::parse(secret).map_err(anyhow::Error::msg).context(SECRET_ENV)?;
    let expected = PublicKey::parse(public).map_err(anyhow::Error::msg).context(PUBLIC_FILE)?;
    if key.public() != expected {
        bail!("{SECRET_ENV} isn't the private half of the key in {PUBLIC_FILE}: the app would refuse this release");
    }
    let sig = key.sign_sums(sums);
    verify_sums(&expected, sums, &sig).map_err(anyhow::Error::msg)?;
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_file_keeps_its_comments_and_gets_one_key() {
        let key = SecretKey::generate().unwrap();
        let file = with_key("# about the key\n#  more\nOLDKEY\n\n", &key.public());
        assert_eq!(file, format!("# about the key\n#  more\n{}\n", key.public().to_text()));
        assert_eq!(PublicKey::parse(&file).unwrap(), key.public());
        assert_eq!(with_key("", &key.public()), format!("{}\n", key.public().to_text()));
    }

    #[test]
    fn signing_needs_the_private_half_of_the_committed_key() {
        let key = SecretKey::generate().unwrap();
        let public = with_key("# k\n", &key.public());
        let sig = sign(&key.to_text(), &public, b"sums").unwrap();
        verify_sums(&key.public(), b"sums", &sig).unwrap();
        let other = SecretKey::generate().unwrap();
        let e = sign(&other.to_text(), &public, b"sums").unwrap_err().to_string();
        assert!(e.contains("isn't the private half"), "{e}");
        assert!(sign("junk", &public, b"sums").is_err());
        assert!(sign(&key.to_text(), "# no key yet\n", b"sums").is_err(), "nothing is signed before the key is committed");
    }

    #[test]
    fn a_new_key_is_private_and_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("xtask-update-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("key");
        let public = dir.join("update-key.pub");
        std::fs::write(&public, "# comment\n").unwrap();
        new_key(&secret, &public).unwrap();
        let key = SecretKey::parse(&std::fs::read_to_string(&secret).unwrap()).unwrap();
        assert_eq!(PublicKey::parse(&std::fs::read_to_string(&public).unwrap()).unwrap(), key.public());
        assert!(std::fs::read_to_string(&public).unwrap().starts_with("# comment\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(new_key(&secret, &public).is_err(), "an existing key file is never replaced");
        assert_eq!(SecretKey::parse(&std::fs::read_to_string(&secret).unwrap()).unwrap().public(), key.public());
        let _ = std::fs::remove_dir_all(dir);
    }
}
