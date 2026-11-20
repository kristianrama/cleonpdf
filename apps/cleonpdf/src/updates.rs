//! Asks GitHub for the latest CleonPDF release (Help ▸ Check for updates, issue #28), and
//! installs it in place where this copy can update itself ([`installer`]).
//!
//! An update is installed only when the release's `SHA256SUMS.txt` is signed with the release
//! key this build carries (`packaging/update-key.pub`) and the download hashes to the checksum
//! listed for it (`cleonpdf-update`). A build without a key, or a copy that can't update itself
//! (a package, a portable copy, a translocated app), offers the release page instead.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use cleonpdf_ui_egui::updates::{RELEASES_PAGE, Release, StagedUpdate, UpdateInstaller, UpdateProgress};
use cleonpdf_update::{self as update, UpdateError, install};

const LATEST: &str = "https://api.github.com/repos/kristianrama/cleonpdf/releases/latest";
/// Where a release's files are, under `v<version>/`.
const DOWNLOADS: &str = "https://github.com/kristianrama/cleonpdf/releases/download";
/// The release key's public half (empty or only comments: in-app updates are off).
const RELEASE_KEY: &str = include_str!("../../../packaging/update-key.pub");
/// How long a download may take in all.
const DOWNLOAD_TIME: Duration = Duration::from_secs(30 * 60);

/// The update to swap in once the window has closed, and whether to start it afterwards.
static PENDING: Mutex<Option<(install::Staged, bool)>> = Mutex::new(None);

/// How to install updates, where this build has a release key and this copy can update itself.
pub fn installer() -> Option<UpdateInstaller> {
    let key = match update::PublicKey::parse(RELEASE_KEY) {
        Ok(key) => key,
        Err(e) => {
            log::info!("updates install from the release page: this build has no release key ({e})");
            return None;
        }
    };
    let target = match install::detect_current() {
        Ok(target) => {
            install::clean_leftovers(&target);
            target
        }
        Err(e) => {
            log::info!("updates install from the release page: {e}");
            return None;
        }
    };
    Some(Arc::new(move |release: &Release, progress: &UpdateProgress| install_release(DOWNLOADS, &key, &target, release, progress)))
}

/// Download, verify and stage `release` for `target`, from `downloads/v<version>/`.
fn install_release(
    downloads: &str,
    key: &update::PublicKey,
    target: &install::Target,
    release: &Release,
    progress: &UpdateProgress,
) -> Result<StagedUpdate, String> {
    let version = update::version_of_tag(&release.version).ok_or("the release's version isn't one CleonPDF can install")?;
    let name = target.asset(version).ok_or("the release has no download for this system")?;
    target.check_writable().map_err(|e| e.to_string())?;
    let base = format!("{downloads}/v{version}");
    let agent = cleonpdf_net::agent_without_redirects(DOWNLOAD_TIME)?;
    let sums = fetch_text(&agent, &format!("{base}/{}", update::SUMS), update::MAX_SUMS)?;
    let sig = match fetch_text(&agent, &format!("{base}/{}", update::SUMS_SIG), update::MAX_SIG) {
        Ok(sig) => sig,
        Err(Fetch::NotFound) => return Err("this release isn't signed for installing from CleonPDF".into()),
        Err(e) => return Err(e.into()),
    };
    update::verify_sums(key, sums.as_bytes(), &sig).map_err(|e| e.to_string())?;
    let expected = update::listed_sha256(&sums, &name).ok_or_else(|| UpdateError::NotListed(name.clone()).to_string())?;
    let dest = target.download_path(&name).map_err(|e| e.to_string())?;
    let staged = download(&agent, &format!("{base}/{name}"), &dest, &expected, progress)
        .and_then(|()| install::stage(target, &dest, version).map_err(|e| e.to_string()));
    // The disk image is spent once its bundle is copied out; a failed download is removed.
    if staged.is_err() || target.kind == install::Kind::MacApp {
        let _ = std::fs::remove_file(&dest);
    }
    let staged = staged?;
    log::info!("update {} downloaded, verified and staged", release.version);
    Ok(StagedUpdate {
        version: release.version.clone(),
        relaunches: target.relaunches(),
        schedule: Box::new(move |relaunch| match PENDING.lock() {
            Ok(mut pending) => *pending = Some((staged.clone(), relaunch)),
            Err(poisoned) => *poisoned.into_inner() = Some((staged.clone(), relaunch)),
        }),
    })
}

/// Why a small file couldn't be fetched.
enum Fetch {
    NotFound,
    Failed(String),
}

impl From<Fetch> for String {
    fn from(f: Fetch) -> Self {
        match f {
            Fetch::NotFound => "the release is missing a file".into(),
            Fetch::Failed(e) => e,
        }
    }
}

/// A small text file, at most `max` bytes.
fn fetch_text(agent: &ureq::Agent, url: &str, max: u64) -> Result<String, Fetch> {
    let mut response = get(agent, url).map_err(Fetch::Failed)?;
    if response.status().as_u16() == 404 {
        return Err(Fetch::NotFound);
    }
    check_status(response.status().as_u16()).map_err(Fetch::Failed)?;
    response.body_mut().with_config().limit(max).read_to_string().map_err(|e| Fetch::Failed(format!("unreadable download ({e})")))
}

/// GET `url`, following up to three redirects to GitHub's own hosts. A redirect's body is never
/// read, and one elsewhere is refused.
fn get(agent: &ureq::Agent, url: &str) -> Result<ureq::http::Response<ureq::Body>, String> {
    let mut url = url.to_string();
    for _ in 0..=3 {
        let response = agent
            .get(&url)
            .header("User-Agent", concat!("CleonPDF/", env!("CARGO_PKG_VERSION")))
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| format!("couldn't reach GitHub ({e})"))?;
        if !response.status().is_redirection() {
            return Ok(response);
        }
        let location = response.headers().get("location").and_then(|v| v.to_str().ok()).ok_or("GitHub redirected nowhere")?;
        url = redirect_target(&url, location).ok_or("GitHub redirected to a host that isn't GitHub's")?;
    }
    Err("too many redirects".into())
}

/// Where redirect `location` (from a response to `from`) points, if it is HTTPS on GitHub's own
/// hosts (`github.com`, `*.githubusercontent.com`), or a path on the same host.
fn redirect_target(from: &str, location: &str) -> Option<String> {
    if location.len() > 8192 || location.chars().any(|c| c.is_control() || c == ' ') {
        return None;
    }
    if location.starts_with('/') && !location.starts_with("//") {
        let (scheme, rest) = from.split_once("://")?;
        let host = rest.split('/').next()?;
        return Some(format!("{scheme}://{host}{location}"));
    }
    let rest = location.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    let github = host == "github.com" || host.strip_suffix(".githubusercontent.com").is_some_and(|sub| !sub.is_empty() && !sub.contains(['@', ':']));
    github.then(|| location.to_string())
}

fn check_status(status: u16) -> Result<(), String> {
    if (200..300).contains(&status) { Ok(()) } else { Err(format!("couldn't download the update (http status: {status})")) }
}

/// Download `url` to `dest`, checking it against `expected` and reporting to `progress`.
fn download(agent: &ureq::Agent, url: &str, dest: &std::path::Path, expected: &[u8; 32], progress: &UpdateProgress) -> Result<(), String> {
    use std::sync::atomic::Ordering;
    let response = get(agent, url)?;
    check_status(response.status().as_u16())?;
    if let Some(total) = response.body().content_length() {
        progress.total.store(total, Ordering::Relaxed);
    }
    let mut reader = response.into_body().into_with_config().limit(update::MAX_ASSET).reader();
    let file = std::fs::File::create(dest).map_err(|e| format!("couldn't save the update ({e})"))?;
    let mut out = std::io::BufWriter::new(file);
    update::copy_checked(&mut reader, &mut out, expected, update::MAX_ASSET, &mut |n| {
        progress.received.store(n, Ordering::Relaxed);
        !progress.cancel.load(Ordering::Relaxed)
    })
    .map_err(|e| e.to_string())?;
    out.into_inner().map_err(|e| e.error().to_string())?.sync_all().map_err(|e| e.to_string())
}

/// Swap in the update staged with Restart now or Later, now that the window has closed.
pub fn apply_pending() {
    let pending = match PENDING.lock() {
        Ok(mut pending) => pending.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    if let Some((staged, relaunch)) = pending {
        match install::apply(&staged, relaunch) {
            Ok(()) => log::info!("update installed{}", if relaunch { "; starting it" } else { "" }),
            Err(e) => {
                log::error!("the update couldn't be installed: {e}");
                install::discard(&staged);
            }
        }
    }
}

/// The latest release. The answer is untrusted: its size is capped, and only a page under
/// [`RELEASES_PAGE`] is ever offered for download (anything else falls back to that list).
pub fn latest_release() -> Result<Release, String> {
    let agent = cleonpdf_net::agent(Duration::from_secs(10))?;
    let mut response = agent
        .get(LATEST)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", concat!("CleonPDF/", env!("CARGO_PKG_VERSION")))
        // Read error statuses ourselves: a 403 from GitHub usually means its anonymous
        // rate limit ran out, and the retry time rides along in a response header.
        .config()
        .http_status_as_error(false)
        .build()
        .call()
        .map_err(|e| format!("couldn't reach GitHub ({e})"))?;
    let status = response.status().as_u16();
    if status == 403 {
        let reset = response.headers().get("x-ratelimit-reset").and_then(|v| v.to_str().ok());
        return Err(rate_limited(reset, now_unix()));
    }
    if !(200..300).contains(&status) {
        return Err(format!("couldn't reach GitHub (http status: {status})"));
    }
    let body = response.body_mut().with_config().limit(1 << 20).read_to_string().map_err(|e| format!("unreadable answer ({e})"))?;
    parse(&body)
}

/// The current Unix time in seconds (0 when the clock gives nothing usable).
fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What to tell the user when GitHub answers 403: its anonymous quota (60 checks an hour,
/// shared by everyone behind the same address) ran out. `reset` is the `x-ratelimit-reset`
/// header, the Unix time the quota refills; `now` is the current Unix time. Anything
/// surprising (no header, not a number, already past) falls back to asking for patience.
fn rate_limited(reset: Option<&str>, now: u64) -> String {
    const FALLBACK: &str = "GitHub is limiting update checks for now (shared hourly quota); try again later";
    let wait = reset.and_then(|r| r.trim().parse::<u64>().ok()).and_then(|reset| reset.checked_sub(now)).filter(|&wait| wait > 0);
    match wait {
        Some(wait) => {
            let minutes = wait.div_ceil(60).max(1);
            let plural = if minutes == 1 { "" } else { "s" };
            format!("GitHub is limiting update checks for now (shared hourly quota); try again in about {minutes} minute{plural}")
        }
        None => FALLBACK.into(),
    }
}

fn parse(body: &str) -> Result<Release, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| format!("unreadable answer ({e})"))?;
    let version = v["tag_name"].as_str().filter(|t| !t.is_empty() && t.len() <= 64).ok_or("no release found")?.to_string();
    let url = v["html_url"]
        .as_str()
        .filter(|u| u.strip_prefix(RELEASES_PAGE).is_some_and(|rest| rest.starts_with('/') && !rest.contains(['?', '#', '\\'])))
        .unwrap_or(RELEASES_PAGE)
        .to_string();
    Ok(Release { version, url })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_read_and_only_our_release_pages_are_offered() {
        let r = parse(r#"{"tag_name":"v0.2.0","html_url":"https://github.com/kristianrama/cleonpdf/releases/tag/v0.2.0"}"#).unwrap();
        assert_eq!(r, Release { version: "v0.2.0".into(), url: "https://github.com/kristianrama/cleonpdf/releases/tag/v0.2.0".into() });
        for elsewhere in ["https://example.com/cleonpdf.exe", "https://github.com/kristianrama/cleonpdf/releases.evil/x", "javascript:alert(1)"] {
            let r = parse(&format!(r#"{{"tag_name":"v9.9.9","html_url":"{elsewhere}"}}"#)).unwrap();
            assert_eq!(r.url, RELEASES_PAGE, "{elsewhere}");
        }
        assert!(parse(r#"{"message":"Not Found"}"#).is_err());
        assert!(parse("<html>").is_err());
    }

    #[test]
    fn rate_limit_messages_name_the_wait() {
        let limited = "GitHub is limiting update checks for now (shared hourly quota); try again in about 20 minutes";
        assert_eq!(rate_limited(Some("1800001200"), 1800000000), limited);
        // Rounds up: 61 seconds out reads as 2 minutes.
        assert_eq!(
            rate_limited(Some("1800000061"), 1800000000),
            "GitHub is limiting update checks for now (shared hourly quota); try again in about 2 minutes"
        );
        assert_eq!(
            rate_limited(Some("1800000060"), 1800000000),
            "GitHub is limiting update checks for now (shared hourly quota); try again in about 1 minute"
        );
        // No header, not a number, or already past: ask for patience instead of a time.
        let later = "GitHub is limiting update checks for now (shared hourly quota); try again later";
        for bad in [None, Some(""), Some("soon"), Some("1799999999"), Some("1800000000")] {
            assert_eq!(rate_limited(bad, 1800000000), later);
        }
    }

    /// A release served over plain HTTP from this machine: `files` by name under `/v0.2.7/`;
    /// anything else is a 404. Serves `requests` requests, then stops.
    fn serve(files: Files, requests: usize) -> String {
        use std::io::{BufRead as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(requests) {
                let Ok(mut stream) = stream else { continue };
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                // The rest of the request's head.
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                }
                let body = files.iter().find(|(n, _)| path == format!("/v0.2.7/{n}")).map(|(_, b)| b.clone());
                let (status, body) = match body {
                    Some(b) => ("200 OK", b),
                    None => ("404 Not Found", b"missing".to_vec()),
                };
                let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        format!("http://{addr}")
    }

    fn sha_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
    }

    /// An AppImage in a fresh folder, and the release file that replaces it.
    fn appimage(name: &str) -> (std::path::PathBuf, install::Target) {
        let dir = std::env::temp_dir().join(format!("cleonpdf-app-update-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let current = dir.join("CleonPDF.AppImage");
        std::fs::write(&current, "old").unwrap();
        (dir, install::Target { kind: install::Kind::AppImage, path: current, arch: "x86_64".into() })
    }

    const ASSET: &str = "cleonpdf-0.2.7-linux-x86_64.AppImage";

    /// A stand-in release's files: name and contents.
    type Files = Vec<(String, Vec<u8>)>;

    fn release() -> Release {
        Release { version: "v0.2.7".into(), url: format!("{RELEASES_PAGE}/tag/v0.2.7") }
    }

    #[test]
    fn a_signed_release_is_downloaded_verified_staged_and_swapped_in() {
        let key = update::SecretKey::generate().unwrap();
        let new = b"new AppImage".repeat(10_000);
        let sums = format!("{}  {ASSET}\n{}  other.dmg\n", sha_hex(&new), sha_hex(b"x"));
        let base = serve(
            vec![
                (update::SUMS.into(), sums.clone().into_bytes()),
                (update::SUMS_SIG.into(), key.sign_sums(sums.as_bytes()).into_bytes()),
                (ASSET.into(), new.clone()),
            ],
            3,
        );
        let (dir, target) = appimage("ok");
        let progress = UpdateProgress::default();
        let staged = install_release(&base, &key.public(), &target, &release(), &progress).unwrap();
        assert_eq!(staged.version, "v0.2.7");
        assert!(staged.relaunches);
        assert_eq!(progress.received.load(std::sync::atomic::Ordering::Relaxed), new.len() as u64);
        assert_eq!(progress.total.load(std::sync::atomic::Ordering::Relaxed), new.len() as u64);
        assert_eq!(std::fs::read(&target.path).unwrap(), b"old", "nothing changes until CleonPDF has closed");
        (staged.schedule)(false);
        apply_pending();
        assert_eq!(std::fs::read(&target.path).unwrap(), new);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no download left behind");
        apply_pending();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn anything_but_the_release_key_s_checksums_and_the_listed_file_is_refused() {
        let key = update::SecretKey::generate().unwrap();
        let new = b"new AppImage".to_vec();
        let sums = format!("{}  {ASSET}\n", sha_hex(&new));
        let sig = key.sign_sums(sums.as_bytes());
        let cases: Vec<(&str, Files, usize, &str)> = vec![
            ("unsigned", vec![(update::SUMS.into(), sums.clone().into_bytes()), (ASSET.into(), new.clone())], 2, "isn't signed for installing"),
            (
                "another key",
                vec![
                    (update::SUMS.into(), sums.clone().into_bytes()),
                    (update::SUMS_SIG.into(), update::SecretKey::generate().unwrap().sign_sums(sums.as_bytes()).into_bytes()),
                    (ASSET.into(), new.clone()),
                ],
                2,
                "isn't signed with CleonPDF's release key",
            ),
            (
                "tampered",
                vec![
                    (update::SUMS.into(), sums.clone().into_bytes()),
                    (update::SUMS_SIG.into(), sig.clone().into_bytes()),
                    (ASSET.into(), b"evil AppImage".to_vec()),
                ],
                3,
                "doesn't match the release's checksum",
            ),
            (
                "unlisted",
                vec![
                    (update::SUMS.into(), b"00  other\n".to_vec()),
                    (update::SUMS_SIG.into(), key.sign_sums(b"00  other\n").into_bytes()),
                    (ASSET.into(), new.clone()),
                ],
                2,
                "doesn't list cleonpdf-0.2.7-linux-x86_64.AppImage",
            ),
            ("no checksums", vec![], 1, "missing a file"),
        ];
        for (case, files, requests, expect) in cases {
            let base = serve(files, requests);
            let (dir, target) = appimage(case);
            let e = install_release(&base, &key.public(), &target, &release(), &UpdateProgress::default()).err().unwrap_or_default();
            assert!(e.contains(expect), "{case}: {e}");
            assert_eq!(std::fs::read(&target.path).unwrap(), b"old", "{case}");
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "{case}: no download left behind");
            let _ = std::fs::remove_dir_all(dir);
        }
        let bad = Release { version: "v0.2.7/../x".into(), url: RELEASES_PAGE.into() };
        let (dir, target) = appimage("tag");
        assert!(install_release("http://127.0.0.1:9", &key.public(), &target, &bad, &UpdateProgress::default()).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_cancelled_download_leaves_nothing_behind() {
        let key = update::SecretKey::generate().unwrap();
        let new = vec![1u8; 4 << 20];
        let sums = format!("{}  {ASSET}\n", sha_hex(&new));
        let base = serve(
            vec![
                (update::SUMS.into(), sums.clone().into_bytes()),
                (update::SUMS_SIG.into(), key.sign_sums(sums.as_bytes()).into_bytes()),
                (ASSET.into(), new),
            ],
            3,
        );
        let (dir, target) = appimage("cancel");
        let progress = UpdateProgress::default();
        progress.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let e = install_release(&base, &key.public(), &target, &release(), &progress).err().unwrap_or_default();
        assert_eq!(e, "cancelled");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn redirects_go_only_to_github_s_hosts() {
        let from = "https://github.com/kristianrama/cleonpdf/releases/download/v0.2.7/SHA256SUMS.txt";
        let to = "https://objects.githubusercontent.com/github-production-release-asset/1?X-Amz-Signature=abc";
        assert_eq!(redirect_target(from, to).as_deref(), Some(to));
        assert_eq!(
            redirect_target(from, "https://release-assets.githubusercontent.com/x").as_deref(),
            Some("https://release-assets.githubusercontent.com/x")
        );
        assert_eq!(redirect_target(from, "/kristianrama/cleonpdf/x").as_deref(), Some("https://github.com/kristianrama/cleonpdf/x"));
        for elsewhere in [
            "http://objects.githubusercontent.com/x",
            "https://evil.example/x",
            "https://githubusercontent.com/x",
            "https://objects.githubusercontent.com.evil.example/x",
            "https://user@evil.example/.githubusercontent.com/x",
            "https://x.githubusercontent.com:443@evil.example/",
            "//evil.example/x",
            "https://github.com/x y",
            "javascript:alert(1)",
        ] {
            assert_eq!(redirect_target(from, elsewhere), None, "{elsewhere}");
        }
    }

    #[test]
    fn a_redirect_elsewhere_is_refused() {
        use std::io::{BufRead as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Some(Ok(mut stream)) = listener.incoming().next() {
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 && !line.ends_with("\r\n\r\n") {}
                let _ = stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        });
        let agent = cleonpdf_net::agent_without_redirects(Duration::from_secs(10)).unwrap();
        let e = get(&agent, &format!("http://{addr}/v0.2.7/SHA256SUMS.txt")).err().unwrap_or_default();
        assert!(e.contains("isn't GitHub's"), "{e}");
    }

    #[test]
    fn this_build_s_release_key_file_reads() {
        // Empty (only its comments) until the owner makes the key; then one valid key.
        match update::PublicKey::parse(RELEASE_KEY) {
            Ok(_) => {}
            Err(UpdateError::Key("empty")) => assert!(RELEASE_KEY.lines().all(|l| l.trim().is_empty() || l.starts_with('#'))),
            Err(e) => panic!("packaging/update-key.pub: {e}"),
        }
    }

    /// Live, by hand: `CLEONPDF_ASSET_URL` (a release file's address on GitHub's file host, as
    /// GitHub's redirect gives it) downloads and verifies through the update's download path.
    #[test]
    #[ignore = "needs network access and CLEONPDF_ASSET_URL"]
    fn a_release_file_downloads_from_github_s_file_host() {
        let url = std::env::var("CLEONPDF_ASSET_URL").unwrap();
        let expected: [u8; 32] = std::env::var("CLEONPDF_ASSET_SHA256").ok().and_then(|h| update::listed_sha256(&format!("{h}  f"), "f")).unwrap();
        let agent = cleonpdf_net::agent_without_redirects(Duration::from_secs(600)).unwrap();
        let dest = std::env::temp_dir().join(format!("cleonpdf-live-{}", std::process::id()));
        let progress = UpdateProgress::default();
        download(&agent, &url, &dest, &expected, &progress).unwrap();
        eprintln!("downloaded {} bytes", progress.received.load(std::sync::atomic::Ordering::Relaxed));
        let _ = std::fs::remove_file(dest);
    }

    /// Live: a published release's checksums come through GitHub's redirect to its file host.
    #[test]
    #[ignore = "needs network access"]
    fn a_published_release_s_checksums_download() {
        let agent = cleonpdf_net::agent(Duration::from_secs(60)).unwrap();
        let sums = fetch_text(&agent, &format!("{DOWNLOADS}/v0.2.6/{}", update::SUMS), update::MAX_SUMS).map_err(String::from).unwrap();
        assert!(update::listed_sha256(&sums, "cleonpdf-0.2.6-macos-universal.dmg").is_some(), "{sums}");
        assert!(
            matches!(fetch_text(&agent, &format!("{DOWNLOADS}/v0.2.6/{}", update::SUMS_SIG), update::MAX_SIG), Err(Fetch::NotFound)),
            "0.2.6 is unsigned"
        );
    }

    /// Live: asks GitHub over TLS with the OS's roots (`cargo test -p cleonpdf -- --ignored`).
    #[test]
    #[ignore = "needs network access"]
    fn github_answers_with_the_latest_release() {
        let r = latest_release().unwrap();
        assert!(cleonpdf_ui_egui::updates::is_newer(&r.version, "0.0.0"), "{r:?}");
        assert!(r.url.starts_with(RELEASES_PAGE), "{r:?}");
    }
}
