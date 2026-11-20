//! Which release file fits the running copy of CleonPDF, staging it, and swapping it in.
//!
//! - **macOS**: the app bundle (`CleonPDF.app`, wherever it is). The disk image is mounted
//!   read-only, the bundle in it is copied beside the running one (`.CleonPDF-<version>.app`),
//!   and once CleonPDF has closed the two are swapped by renaming, then the new one is opened.
//!   Not from a translocated copy (macOS runs an app it hasn't moved from the download folder
//!   from a read-only mount) or a folder CleonPDF can't write.
//! - **Windows**: the MSI install (under Program Files, no portable marker). Once CleonPDF has
//!   closed, the new MSI runs (`msiexec /passive`), which upgrades it in place.
//! - **Linux**: the AppImage (`$APPIMAGE`). The new one is downloaded beside it and renamed over
//!   it once CleonPDF has closed, then started. Packages (.deb, .rpm, Flatpak) and the archive
//!   are updated the way they were installed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::UpdateError;

/// The files beside a Windows executable that mark a portable copy (as `cleonpdf_ui_egui::portable`).
const PORTABLE_MARKERS: [&str; 2] = ["portable.txt", "CleonPDF.portable"];

/// How this copy of CleonPDF was installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An app bundle on macOS.
    MacApp,
    /// The Windows MSI.
    WindowsMsi,
    /// A Linux AppImage.
    AppImage,
}

/// The running copy, as far as updating it goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub kind: Kind,
    /// The app bundle (macOS), the install folder (Windows) or the AppImage file (Linux).
    pub path: PathBuf,
    /// The processor architecture (`std::env::consts::ARCH`).
    pub arch: String,
}

/// What [`detect`] looks at; [`detect_current`] fills it in for the running process.
pub struct Running<'a> {
    /// `std::env::consts::OS`.
    pub os: &'a str,
    /// `std::env::consts::ARCH`.
    pub arch: &'a str,
    /// The running executable.
    pub exe: &'a Path,
    /// `$APPIMAGE`, which an AppImage's runtime sets to the AppImage's own path.
    pub appimage: Option<&'a Path>,
    /// The Program Files folders (Windows).
    pub program_files: &'a [PathBuf],
}

/// Whether, and how, this copy can update itself; [`UpdateError::Unsupported`] says why not.
pub fn detect(r: &Running<'_>) -> Result<Target, UpdateError> {
    let unsupported = |why: &str| Err(UpdateError::Unsupported(why.into()));
    let target = |kind, path: &Path| Ok(Target { kind, path: path.to_path_buf(), arch: r.arch.to_string() });
    match r.os {
        "macos" => {
            let contents = r.exe.parent().filter(|p| p.file_name().is_some_and(|n| n == "MacOS")).and_then(Path::parent);
            let bundle = contents.filter(|p| p.file_name().is_some_and(|n| n == "Contents")).and_then(Path::parent);
            let Some(bundle) = bundle.filter(|b| b.extension().is_some_and(|e| e == "app") && b.parent().is_some()) else {
                return unsupported("CleonPDF isn't running from an app bundle");
            };
            if bundle.components().any(|c| c.as_os_str() == "AppTranslocation") {
                return unsupported(
                    "macOS is running CleonPDF from a read-only copy: move CleonPDF to the Applications folder, open it from there and update again",
                );
            }
            target(Kind::MacApp, bundle)
        }
        "windows" => {
            let Some(dir) = r.exe.parent() else { return unsupported("CleonPDF's folder is unknown") };
            if PORTABLE_MARKERS.iter().any(|m| dir.join(m).exists()) {
                return unsupported("this is the portable copy: unzip the new one over it");
            }
            if r.arch != "x86_64" {
                return unsupported("there is no installer for this processor");
            }
            let lower = |p: &Path| p.to_string_lossy().to_lowercase().replace('/', "\\");
            let installed = r.program_files.iter().filter(|pf| !pf.as_os_str().is_empty()).any(|pf| {
                let (dir, pf) = (lower(dir), lower(pf));
                dir.strip_prefix(pf.trim_end_matches('\\')).is_some_and(|rest| rest.starts_with('\\'))
            });
            if !installed {
                return unsupported("this copy wasn't installed with CleonPDF's installer");
            }
            target(Kind::WindowsMsi, dir)
        }
        "linux" => match r.appimage {
            Some(p) if p.is_absolute() && p.is_file() && matches!(r.arch, "x86_64" | "aarch64") => target(Kind::AppImage, p),
            Some(_) => unsupported("there is no AppImage for this processor"),
            None => unsupported("CleonPDF was installed from a package or an archive: update it the same way"),
        },
        _ => unsupported("CleonPDF can't update itself on this system"),
    }
}

/// [`detect`] for the running process.
pub fn detect_current() -> Result<Target, UpdateError> {
    let exe = std::env::current_exe()?;
    let appimage = std::env::var_os("APPIMAGE").map(PathBuf::from);
    let program_files: Vec<PathBuf> =
        ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"].iter().filter_map(std::env::var_os).map(PathBuf::from).collect();
    detect(&Running {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        exe: &exe,
        appimage: appimage.as_deref(),
        program_files: &program_files,
    })
}

impl Target {
    /// The release file for version `version` (from [`crate::version_of_tag`]) that fits this
    /// copy, as the release workflow names it.
    pub fn asset(&self, version: &str) -> Option<String> {
        match self.kind {
            Kind::MacApp => Some(format!("cleonpdf-{version}-macos-universal.dmg")),
            Kind::WindowsMsi => (self.arch == "x86_64").then(|| format!("cleonpdf-{version}-windows-x64.msi")),
            Kind::AppImage => matches!(self.arch.as_str(), "x86_64" | "aarch64").then(|| format!("cleonpdf-{version}-linux-{}.AppImage", self.arch)),
        }
    }

    /// Where to download release file `name` (from [`Target::asset`]). An AppImage is
    /// downloaded beside the running one, so it can be renamed over it; the others go to a
    /// folder of their own in the temporary folder, which this creates.
    pub fn download_path(&self, name: &str) -> Result<PathBuf, UpdateError> {
        match (self.kind, self.path.parent()) {
            (Kind::AppImage, Some(dir)) => Ok(dir.join(format!(".{name}.part"))),
            (Kind::AppImage, None) => Err(UpdateError::Unsupported("the AppImage's folder is unknown".into())),
            _ => {
                let dir = std::env::temp_dir().join("cleonpdf-update");
                std::fs::create_dir_all(&dir)?;
                Ok(dir.join(name))
            }
        }
    }

    /// Fail early, before anything is downloaded, if the update can't go in: the folder holding
    /// the app bundle or the AppImage must be writable (not a mounted disk image, not a folder
    /// of another user's). The Windows installer asks for permission itself.
    pub fn check_writable(&self) -> Result<(), UpdateError> {
        let dir = match self.kind {
            Kind::WindowsMsi => return Ok(()),
            Kind::MacApp | Kind::AppImage => self.path.parent().ok_or_else(|| UpdateError::Unsupported("CleonPDF's folder is unknown".into()))?,
        };
        let probe = dir.join(format!(".cleonpdf-update-probe-{}", std::process::id()));
        std::fs::create_dir(&probe)
            .and_then(|()| std::fs::remove_dir(&probe))
            .map_err(|e| UpdateError::Unsupported(format!("CleonPDF can't write to {} ({e}): download the new version instead", dir.display())))
    }

    /// Whether applying the update starts the new version (the Windows installer doesn't).
    pub fn relaunches(&self) -> bool {
        self.kind != Kind::WindowsMsi
    }
}

/// A verified download made ready to swap in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    kind: Kind,
    /// The new bundle, installer or AppImage.
    from: PathBuf,
    /// What it replaces (for the MSI, the install folder, which it doesn't touch).
    to: PathBuf,
}

/// Make the verified download `downloaded` (of version `version`) ready to swap in for `target`.
pub fn stage(target: &Target, downloaded: &Path, version: &str) -> Result<Staged, UpdateError> {
    match target.kind {
        Kind::AppImage => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(downloaded, std::fs::Permissions::from_mode(0o755))?;
            }
            Ok(Staged { kind: Kind::AppImage, from: downloaded.to_path_buf(), to: target.path.clone() })
        }
        Kind::MacApp => stage_mac(downloaded, &target.path, version),
        Kind::WindowsMsi => Ok(Staged { kind: Kind::WindowsMsi, from: downloaded.to_path_buf(), to: target.path.clone() }),
    }
}

/// Copy the bundle out of disk image `dmg` to `.CleonPDF-<version>.app` beside `bundle`.
fn stage_mac(dmg: &Path, bundle: &Path, version: &str) -> Result<Staged, UpdateError> {
    let parent = bundle.parent().ok_or_else(|| UpdateError::Unsupported("the app's folder is unknown".into()))?;
    let staged = parent.join(format!(".CleonPDF-{version}.app"));
    if staged.exists() {
        std::fs::remove_dir_all(&staged)?;
    }
    // Can the bundle's folder be written? (Applications is, for an administrator.)
    std::fs::create_dir(&staged)
        .and_then(|()| std::fs::remove_dir(&staged))
        .map_err(|e| UpdateError::Unsupported(format!("CleonPDF can't write to {} ({e}): download the new version instead", parent.display())))?;
    let mount = std::env::temp_dir().join(format!("cleonpdf-update-mount-{}", std::process::id()));
    std::fs::create_dir_all(&mount)?;
    let mut attach = Command::new("/usr/bin/hdiutil");
    attach.arg("attach").args(["-nobrowse", "-readonly", "-noautoopen", "-noverify", "-mountpoint"]).arg(&mount).arg(dmg);
    let copied = run("hdiutil", &mut attach).and_then(|()| {
        let app = mount.join("CleonPDF.app");
        if !app.join("Contents").join("Info.plist").is_file() {
            return Err(UpdateError::Tool { tool: "hdiutil", detail: "the disk image holds no CleonPDF.app".into() });
        }
        run("ditto", Command::new("/usr/bin/ditto").arg(&app).arg(&staged))
    });
    // Always detach, even when the copy failed; force it if something still holds the volume.
    if run("hdiutil", Command::new("/usr/bin/hdiutil").arg("detach").arg(&mount).arg("-quiet")).is_err() {
        let _ = run("hdiutil", Command::new("/usr/bin/hdiutil").arg("detach").arg(&mount).args(["-quiet", "-force"]));
    }
    let _ = std::fs::remove_dir(&mount);
    if let Err(e) = copied {
        let _ = std::fs::remove_dir_all(&staged);
        return Err(e);
    }
    Ok(Staged { kind: Kind::MacApp, from: staged, to: bundle.to_path_buf() })
}

/// Run `cmd` to completion; a failure carries the end of its error output.
fn run(tool: &'static str, cmd: &mut Command) -> Result<(), UpdateError> {
    let out = cmd.stdin(Stdio::null()).output().map_err(|e| UpdateError::Tool { tool, detail: e.to_string() })?;
    if out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&out.stderr);
    let text = text.trim();
    // The last 300 characters, cut at a character boundary.
    let start = text.char_indices().rev().nth(299).map_or(0, |(i, _)| i);
    let detail = text.get(start..).filter(|t| !t.is_empty()).map_or_else(|| out.status.to_string(), str::to_string);
    Err(UpdateError::Tool { tool, detail })
}

/// Swap the staged update in, now that CleonPDF has closed; with `relaunch`, start the new
/// version (where [`Target::relaunches`]).
pub fn apply(staged: &Staged, relaunch: bool) -> Result<(), UpdateError> {
    match staged.kind {
        Kind::AppImage => {
            std::fs::rename(&staged.from, &staged.to)?;
            if relaunch {
                Command::new(&staged.to).stdin(Stdio::null()).spawn()?;
            }
        }
        Kind::MacApp => {
            swap_bundle(&staged.from, &staged.to)?;
            if relaunch {
                // A new instance: this one may not have quit yet.
                Command::new("/usr/bin/open").arg("-n").arg(&staged.to).stdin(Stdio::null()).spawn()?;
            }
        }
        Kind::WindowsMsi => {
            Command::new("msiexec").args(msiexec_args(&staged.from)).stdin(Stdio::null()).spawn()?;
        }
    }
    Ok(())
}

/// Remove what an update interrupted before it went in left behind (CleonPDF closed in the middle
/// of a download, or crashed with an update staged): a partial AppImage beside the running one, a
/// staged or old app bundle beside the running one, and the temporary download folder. Only names
/// this module makes are removed. Call it when CleonPDF starts, before any update is staged.
pub fn clean_leftovers(target: &Target) {
    let ours = |name: &str| match target.kind {
        Kind::AppImage => name.starts_with(".cleonpdf-") && name.ends_with(".AppImage.part"),
        Kind::MacApp => (name.starts_with(".CleonPDF-") && name.ends_with(".app")) || (name.starts_with('.') && name.contains(".app-old-")),
        Kind::WindowsMsi => false,
    };
    if let Some(entries) = target.path.parent().and_then(|dir| std::fs::read_dir(dir).ok()) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path == target.path || !entry.file_name().to_str().is_some_and(ours) {
                continue;
            }
            let _ = if path.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
        }
    }
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join("cleonpdf-update"));
}

/// Remove a staged update that won't be applied.
pub fn discard(staged: &Staged) {
    let _ = if staged.from.is_dir() { std::fs::remove_dir_all(&staged.from) } else { std::fs::remove_file(&staged.from) };
}

/// `msiexec`'s arguments for installing `msi` with a progress bar and no questions.
fn msiexec_args(msi: &Path) -> Vec<std::ffi::OsString> {
    vec!["/i".into(), msi.as_os_str().to_owned(), "/passive".into(), "/norestart".into()]
}

/// Replace bundle `current` with `new` by renaming: the old one is moved aside first and put
/// back if the new one can't take its place, then removed.
fn swap_bundle(new: &Path, current: &Path) -> Result<(), UpdateError> {
    let name = current.file_name().ok_or_else(|| UpdateError::Unsupported("the app bundle has no name".into()))?;
    let old = current.with_file_name(format!(".{}-old-{}", name.to_string_lossy(), std::process::id()));
    std::fs::rename(current, &old)?;
    if let Err(e) = std::fs::rename(new, current) {
        let _ = std::fs::rename(&old, current);
        return Err(e.into());
    }
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cleonpdf-update-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn running<'a>(os: &'a str, arch: &'a str, exe: &'a Path, appimage: Option<&'a Path>, program_files: &'a [PathBuf]) -> Running<'a> {
        Running { os, arch, exe, appimage, program_files }
    }

    #[test]
    fn a_mac_app_bundle_updates_unless_translocated() {
        let exe = Path::new("/Applications/CleonPDF.app/Contents/MacOS/CleonPDF");
        let t = detect(&running("macos", "aarch64", exe, None, &[])).unwrap();
        assert_eq!((t.kind, t.path.as_path()), (Kind::MacApp, Path::new("/Applications/CleonPDF.app")));
        assert_eq!(t.asset("0.2.7").as_deref(), Some("cleonpdf-0.2.7-macos-universal.dmg"));
        assert!(t.relaunches());
        let moved = Path::new("/Users/k/Desktop/CleonPDF copy.app/Contents/MacOS/CleonPDF");
        assert_eq!(detect(&running("macos", "x86_64", moved, None, &[])).unwrap().path, Path::new("/Users/k/Desktop/CleonPDF copy.app"));
        for not_bundled in ["/usr/local/bin/cleonpdf", "/x/Contents/MacOS/CleonPDF", "/x/CleonPDF.app/MacOS/CleonPDF", "CleonPDF"] {
            assert!(
                matches!(detect(&running("macos", "aarch64", Path::new(not_bundled), None, &[])), Err(UpdateError::Unsupported(_))),
                "{not_bundled}"
            );
        }
        let translocated = Path::new("/private/var/folders/x/T/AppTranslocation/ABC/d/CleonPDF.app/Contents/MacOS/CleonPDF");
        let e = detect(&running("macos", "aarch64", translocated, None, &[])).unwrap_err().to_string();
        assert!(e.contains("Applications folder"), "{e}");
    }

    #[test]
    fn the_windows_msi_install_updates_but_a_portable_copy_does_not() {
        let pf = [PathBuf::from("C:\\Program Files"), PathBuf::from("C:\\Program Files (x86)")];
        let exe = Path::new("C:/Program Files/CleonPDF/cleonpdf.exe");
        let t = detect(&running("windows", "x86_64", exe, None, &pf)).unwrap();
        assert_eq!(t.kind, Kind::WindowsMsi);
        assert_eq!(t.asset("0.2.7").as_deref(), Some("cleonpdf-0.2.7-windows-x64.msi"));
        assert!(!t.relaunches());
        // Case and slashes don't matter; a folder that only starts like Program Files does.
        assert!(detect(&running("windows", "x86_64", Path::new("c:/program files/CleonPDF/cleonpdf.exe"), None, &pf)).is_ok());
        for elsewhere in ["C:/Program Files2/CleonPDF/cleonpdf.exe", "D:/Tools/CleonPDF/cleonpdf.exe"] {
            assert!(detect(&running("windows", "x86_64", Path::new(elsewhere), None, &pf)).is_err(), "{elsewhere}");
        }
        assert!(detect(&running("windows", "aarch64", exe, None, &pf)).is_err(), "no ARM installer");
        assert!(detect(&running("windows", "x86_64", exe, None, &[PathBuf::new()])).is_err(), "an empty Program Files matches nothing");
        // A portable marker beside the executable wins.
        let dir = temp("portable");
        std::fs::write(dir.join("portable.txt"), "").unwrap();
        let exe = dir.join("cleonpdf.exe");
        let e = detect(&running("windows", "x86_64", &exe, None, &[dir.parent().unwrap().to_path_buf()])).unwrap_err().to_string();
        assert!(e.contains("portable"), "{e}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn only_an_appimage_updates_on_linux() {
        let dir = temp("appimage-detect");
        let file = dir.join("CleonPDF.AppImage");
        std::fs::write(&file, "x").unwrap();
        let exe = Path::new("/tmp/.mount_Cleon/usr/bin/cleonpdf");
        let t = detect(&running("linux", "x86_64", exe, Some(&file), &[])).unwrap();
        assert_eq!((t.kind, t.path.as_path()), (Kind::AppImage, file.as_path()));
        assert_eq!(t.asset("0.2.7").as_deref(), Some("cleonpdf-0.2.7-linux-x86_64.AppImage"));
        assert_eq!(t.download_path("cleonpdf-0.2.7-linux-x86_64.AppImage").unwrap(), dir.join(".cleonpdf-0.2.7-linux-x86_64.AppImage.part"));
        assert_eq!(
            detect(&running("linux", "aarch64", exe, Some(&file), &[])).unwrap().asset("1.0.0").as_deref(),
            Some("cleonpdf-1.0.0-linux-aarch64.AppImage")
        );
        assert!(detect(&running("linux", "riscv64", exe, Some(&file), &[])).is_err());
        assert!(detect(&running("linux", "x86_64", Path::new("/usr/bin/cleonpdf"), None, &[])).is_err(), "a package");
        assert!(detect(&running("linux", "x86_64", exe, Some(Path::new("relative.AppImage")), &[])).is_err());
        assert!(detect(&running("linux", "x86_64", exe, Some(&dir.join("gone.AppImage")), &[])).is_err());
        assert!(detect(&running("freebsd", "x86_64", exe, Some(&file), &[])).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_appimage_is_renamed_over_the_running_one() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp("appimage-apply");
        let current = dir.join("CleonPDF.AppImage");
        std::fs::write(&current, "old").unwrap();
        let target = Target { kind: Kind::AppImage, path: current.clone(), arch: "x86_64".into() };
        let part = target.download_path("cleonpdf-0.2.7-linux-x86_64.AppImage").unwrap();
        std::fs::write(&part, "new").unwrap();
        let staged = stage(&target, &part, "0.2.7").unwrap();
        assert_eq!(std::fs::metadata(&part).unwrap().permissions().mode() & 0o777, 0o755, "executable");
        apply(&staged, false).unwrap();
        assert_eq!(std::fs::read_to_string(&current).unwrap(), "new");
        assert!(!part.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_that_cannot_be_written_is_found_before_downloading() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp("writable");
        let target = Target { kind: Kind::MacApp, path: dir.join("CleonPDF.app"), arch: "aarch64".into() };
        target.check_writable().unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "the probe is removed");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root can write anywhere, so this half only means something for other users.
        let root = std::fs::create_dir(dir.join("x")).is_ok();
        if !root {
            let e = target.check_writable().unwrap_err().to_string();
            assert!(e.contains("can't write to"), "{e}");
            let appimage = Target { kind: Kind::AppImage, path: dir.join("CleonPDF.AppImage"), arch: "x86_64".into() };
            assert!(appimage.check_writable().is_err());
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Target { kind: Kind::WindowsMsi, path: dir.join("nowhere/at/all"), arch: "x86_64".into() }.check_writable().is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bundle_swap_puts_the_old_one_back_when_the_new_one_cannot_go_in() {
        let dir = temp("swap");
        let current = dir.join("CleonPDF.app");
        let new = dir.join(".CleonPDF-0.2.7.app");
        std::fs::create_dir_all(current.join("Contents")).unwrap();
        std::fs::write(current.join("Contents/version"), "old").unwrap();
        std::fs::create_dir_all(new.join("Contents")).unwrap();
        std::fs::write(new.join("Contents/version"), "new").unwrap();
        let staged = Staged { kind: Kind::MacApp, from: new.clone(), to: current.clone() };
        apply(&staged, false).unwrap();
        assert_eq!(std::fs::read_to_string(current.join("Contents/version")).unwrap(), "new");
        assert!(!new.exists());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "the old bundle is gone");
        // The staged bundle has vanished: the running one stays where it was.
        let e = apply(&staged, false);
        assert!(e.is_err());
        assert_eq!(std::fs::read_to_string(current.join("Contents/version")).unwrap(), "new");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn leftovers_of_an_interrupted_update_are_cleaned_and_nothing_else() {
        let dir = temp("leftovers");
        let make_dir = |n: &str| std::fs::create_dir_all(dir.join(n).join("Contents")).unwrap();
        let make_file = |n: &str| std::fs::write(dir.join(n), "x").unwrap();
        make_dir("CleonPDF.app");
        make_dir(".CleonPDF-0.2.7.app");
        make_dir(".CleonPDF.app-old-4242");
        make_dir("Other.app");
        make_dir(".Other-0.2.7.app");
        make_file(".cleonpdf-0.2.7-linux-x86_64.AppImage.part");
        make_file("notes.txt");
        clean_leftovers(&Target { kind: Kind::MacApp, path: dir.join("CleonPDF.app"), arch: "aarch64".into() });
        let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, [".Other-0.2.7.app", ".cleonpdf-0.2.7-linux-x86_64.AppImage.part", "CleonPDF.app", "Other.app", "notes.txt"]);
        make_file("CleonPDF.AppImage");
        clean_leftovers(&Target { kind: Kind::AppImage, path: dir.join("CleonPDF.AppImage"), arch: "x86_64".into() });
        assert!(!dir.join(".cleonpdf-0.2.7-linux-x86_64.AppImage.part").exists());
        assert!(dir.join("CleonPDF.AppImage").exists() && dir.join("notes.txt").exists() && dir.join(".Other-0.2.7.app").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_msi_runs_passively_without_restarting_windows() {
        let args = msiexec_args(Path::new("C:\\Temp\\cleonpdf-update\\cleonpdf-0.2.7-windows-x64.msi"));
        assert_eq!(args, ["/i", "C:\\Temp\\cleonpdf-update\\cleonpdf-0.2.7-windows-x64.msi", "/passive", "/norestart"]);
    }

    #[test]
    fn tool_failures_keep_the_end_of_their_message() {
        #[cfg(unix)]
        let mut cmd = {
            let mut c = Command::new("sh");
            c.args(["-c", "printf 'first line\\n%0400d\\nlast words' 0 >&2; exit 3"]);
            c
        };
        #[cfg(windows)]
        let mut cmd = {
            let mut c = Command::new("cmd");
            c.args(["/C", "echo last words 1>&2 & exit 3"]);
            c
        };
        let e = run("tool", &mut cmd).unwrap_err().to_string();
        assert!(e.starts_with("tool failed: ") && e.trim_end().ends_with("last words"), "{e}");
        assert!(e.chars().count() <= 320, "{e}");
        assert!(matches!(run("missing", &mut Command::new("cleonpdf-no-such-tool")), Err(UpdateError::Tool { tool: "missing", .. })));
    }

    /// The real thing on macOS: a disk image made with `hdiutil` like the release's, staged and
    /// swapped in for a bundle in a temporary folder.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_disk_image_s_bundle_is_staged_and_swapped_in() {
        let dir = temp("dmg");
        let src = dir.join("src");
        let app = src.join("CleonPDF.app/Contents");
        std::fs::create_dir_all(app.join("MacOS")).unwrap();
        std::fs::write(app.join("Info.plist"), "<plist/>").unwrap();
        std::fs::write(app.join("MacOS/CleonPDF"), "new").unwrap();
        let dmg = dir.join("cleonpdf-0.2.7-macos-universal.dmg");
        run(
            "hdiutil",
            Command::new("/usr/bin/hdiutil")
                .args(["create", "-srcfolder"])
                .arg(&src)
                .args(["-volname", "CleonPDF", "-fs", "HFS+", "-format", "UDZO", "-ov"])
                .arg(&dmg),
        )
        .unwrap();
        let installed = dir.join("Applications/CleonPDF.app");
        std::fs::create_dir_all(installed.join("Contents/MacOS")).unwrap();
        std::fs::write(installed.join("Contents/MacOS/CleonPDF"), "old").unwrap();
        let target = Target { kind: Kind::MacApp, path: installed.clone(), arch: "aarch64".into() };
        let staged = stage(&target, &dmg, "0.2.7").unwrap();
        assert!(dir.join("Applications/.CleonPDF-0.2.7.app/Contents/Info.plist").is_file());
        apply(&staged, false).unwrap();
        assert_eq!(std::fs::read_to_string(installed.join("Contents/MacOS/CleonPDF")).unwrap(), "new");
        assert_eq!(std::fs::read_dir(dir.join("Applications")).unwrap().count(), 1);
        // A disk image without the bundle stages nothing.
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::write(empty.join("readme"), "x").unwrap();
        let bad = dir.join("bad.dmg");
        run(
            "hdiutil",
            Command::new("/usr/bin/hdiutil")
                .args(["create", "-srcfolder"])
                .arg(&empty)
                .args(["-volname", "X", "-fs", "HFS+", "-format", "UDZO", "-ov"])
                .arg(&bad),
        )
        .unwrap();
        assert!(matches!(stage(&target, &bad, "0.2.8"), Err(UpdateError::Tool { .. })));
        assert!(!dir.join("Applications/.CleonPDF-0.2.8.app").exists(), "a failed staging leaves nothing behind");
        let _ = std::fs::remove_dir_all(dir);
    }
}
