# Releasing CleonPDF

Every push to the `release` branch runs `.github/workflows/release.yml`. It builds installers for
macOS, Windows, Linux and the web, signs the ones it has certificates for, and creates or updates a
**draft** GitHub Release named `CleonPDF v<version>`. Nobody sees a draft until it is published by
hand.

The workflow is self-contained. Every action is pinned to a commit, and every tool it downloads
(nfpm, appimagetool, the AppImage runtime) is pinned to a version and checked against its SHA-256.
PdfCraft's release pipeline called reusable workflows in `storytold/craft-common-actions` at `@main`;
that repository has no licence, so nothing was copied from it, and calling it would have run code
someone else controls with this repository's write access and signing secrets.

User-facing names say **CleonPDF**; files, binaries and ids stay lowercase
(`cleonpdf-<version>-<platform>-<arch>.<ext>`, `io.github.kristianrama.cleonpdf`).

## Cutting a release

1. **Bump the version** on `main`. It lives only in `[workspace.package] version` in the root
   `Cargo.toml`:

   ```sh
   cargo xtask version                 # prints the current version
   cargo xtask version set 0.9.0       # or 0.9.0-rc.1; updates Cargo.toml and Cargo.lock
   ```

   Commit it through the normal flow (a PR into `main`, merged when CI is green).
2. **Update `release`** to that commit and push it. The workflow starts by itself:

   ```sh
   git push origin main:release
   ```

3. **Wait for the draft.** When every job has finished, the Releases page has a draft
   `CleonPDF v0.9.0` targeting the pushed commit, with every artifact and `SHA256SUMS.txt`. The notes
   are generated from the merged PRs.
4. **Check it.** Download an installer or two and read the job summaries. A `::warning::` there
   means a signing secret was missing and that artifact is unsigned.
5. **Publish** the draft in the GitHub UI. Publishing creates the `v0.9.0` tag. Versions with a
   pre-release suffix (`-rc.1`) are marked as pre-releases.

Pushing to `release` again before you publish rebuilds the same draft, replaces its assets and moves
its target to the new commit, so the tag lands on what was built last.
Once the draft is published, the workflow refuses to touch that version again, so bump it first.

**Test runs:** *Actions ▸ Release ▸ Run workflow* runs the whole pipeline by hand, on any branch, and
also makes a draft. The optional `version` input (such as `0.9.0-rc.1`) renames that run's files and
its draft; the binaries still report the version in `Cargo.toml`. Delete the draft afterwards.

**Cost.** GitHub Actions is free on public repositories. On a private one, GitHub Free includes
2,000 minutes a month, and macOS minutes are billed at about ten times the Linux rate, so one release
run uses a large share of them. A private repository builds Linux for x86_64 only.

## What gets built

| Platform | Artifacts | Built on |
|---|---|---|
| macOS 11+ (universal: Apple silicon + Intel) | `cleonpdf-<v>-macos-universal.dmg`, `cleonpdf-cli-<v>-macos-universal.zip` | `macos-15` |
| Windows 10+ x64 | `cleonpdf-<v>-windows-x64.msi`, `cleonpdf-<v>-windows-x64-portable.zip` | `windows-latest` |
| Linux x86_64 | `cleonpdf-<v>-linux-x86_64.{AppImage,AppImage.zsync,deb,rpm,tar.gz}`, `cleonpdf-cli-<v>-linux-x86_64.tar.gz` | `ubuntu-22.04` |
| Linux aarch64 (public repository only) | `cleonpdf-<v>-linux-aarch64.{AppImage,AppImage.zsync,deb,rpm,tar.gz}`, `cleonpdf-cli-<v>-linux-aarch64.tar.gz` | `ubuntu-22.04-arm` |
| Web | `cleonpdf-web-<v>.zip` (a static site; see [`packaging/web/README.md`](../packaging/web/README.md)) | `ubuntu-latest` |

**Not built yet**, although the scripts are here: Windows x86 and ARM64 (`package.ps1 -Arch x86|arm64`),
Linux riscv64 (cross-compiled tarballs), the Flatpak bundles (`packaging/linux/flatpak-bundle.sh`) and
FreeBSD (`packaging/freebsd/package.sh`, which needs a FreeBSD VM). PdfCraft's pipeline built them;
each is a job to add to `release.yml`.

Every binary reports its version (`cleonpdf --version`, `cleonpdf-cli --version`, *Help ▸ About*).
The workflow sets `CLEONPDF_BUILD_SHA` and `CLEONPDF_BUILD_DATE` (`packaging/env.sh` fills them in
for local builds): the commit is recorded in the macOS `Info.plist` (`CleonPdfBuildCommit`) and the
date in the AppStream metadata. The binaries don't embed the commit yet.

**Fonts:** every job checks out [craft-fonts](https://github.com/storytold/craft-fonts) at the commit
pinned in `release.yml` (`CRAFT_FONTS_REF`) and builds with `CRAFT_FONTS_DIR` and
`CRAFT_FONTS_REQUIRED=1`, so releases embed its Japanese fonts and fail rather than ship without them
(`AGENTS.md` §1.4). Bump the pin deliberately.

**OCR models:** every desktop package ships the Scan & OCR models (#103). The packaging scripts call
`stage_models` (`packaging/env.sh`; `package.ps1` on Windows), which runs `cargo xtask models` to
fetch every `kind = "model"` file in `ATTRIBUTION.toml` (verified by SHA-256) with its licence text
and an `ATTRIBUTION.txt`, straight into the package, so packaging needs the network. They go where
`cleonpdf_ocr::Models::dirs_beside_exe` looks: `models\` beside `cleonpdf.exe` (MSI, portable zip),
`CleonPDF.app/Contents/Resources/models` (macOS), and `share/cleonpdf/models` beside `bin/`
(deb, rpm, tar.gz, AppImage, Flatpak, FreeBSD). The web build doesn't include them yet.

### macOS

`packaging/macos/package.sh` builds both architectures, joins them with `lipo`, and assembles
`CleonPDF.app` from `Info.plist.in` (bundle id `io.github.kristianrama.cleonpdf`, macOS 11+, PDF declared
as a document type with rank Alternate, so CleonPDF is offered under Open With without taking over
from Preview). Files opened from Finder arrive as Apple events, which
`apps/cleonpdf/src/apple_events.rs` receives.

- **Signing** uses the hardened runtime and a secure timestamp, executable first, then the bundle.
  `packaging/macos/import-cert.sh` puts the certificate in a temporary keychain, deleted at the end
  of the job.
- **Notarization:** the app is zipped and sent with `xcrun notarytool submit --wait`, the ticket is
  stapled, and the result is checked with `codesign --verify`, `stapler validate` and `spctl`. The
  app ships on a drag-to-Applications DMG, which is signed and notarized too.
  Its Finder window (background, icon size and positions) comes from
  [`packaging/macos/dmg/`](../packaging/macos/dmg/README.md), and its volume is named `CleonPDF`
  without the version, which the window's background needs; the DMG file name keeps the version.
- **CLI:** `cleonpdf-cli` is signed and notarized as a zip. A bare executable can't hold a stapled
  ticket, so Gatekeeper looks it up online the first time a downloaded copy runs.

Without certificates (locally) the script signs ad-hoc and skips notarization:

```sh
packaging/macos/package.sh --arch aarch64     # quicker, host-only; --arch universal needs both targets
```

### Windows

`packaging/windows/package.ps1 -Arch x64|x86|arm64` builds with `-C target-feature=+crt-static`, so
neither the MSI nor the portable zip needs the Visual C++ redistributable.

- Before packaging, it reads both executables' PE headers: the machine type must match `-Arch`, and
  `cleonpdf.exe` must be a GUI-subsystem program (no console window, #57) while `cleonpdf-cli.exe`
  stays a console program.
- `cleonpdf.wxs` (WiX v5) installs per machine into Program Files with a Start Menu shortcut, a
  desktop shortcut (on by default) and an App Paths entry. Both shortcuts are plain links to
  `cleonpdf.exe`, not advertised MSI shortcuts (#107, #143). The MSI version is the numeric `X.Y.Z`
  (MSI has no pre-release field), and same-version upgrades are allowed so release candidates replace
  each other. Icon ids end in `.ico` or `.exe` (Windows Installer requires it).
- `installer-ui.wxs` supplies native welcome, maintenance, progress, files-in-use and outcome
  dialogs. Full UI confirms success with Finish; failures and cancellations have distinct messages.
  The welcome dialog has a "Create a desktop shortcut" checkbox and an "Edit with CleonPDF"
  right-click menu checkbox, both ticked by default. `/qn` and `/qb` stay unattended and create
  both unless `INSTALLDESKTOPSHORTCUT=0` or `INSTALLPDFCONTEXTMENU=0` is passed. An update (the
  launcher runs `msiexec /passive` with no properties) keeps the desktop shortcut only if
  `CleonPDF.lnk` is still on the all-users desktop, so deleting it once keeps it away (#1058); a
  value given on the command line wins.
- The PDF right-click entry (#682) is a classic verb under
  `HKLM\Software\Classes\SystemFileAssociations\.pdf\shell\CleonPDF.Edit`, so it shows whichever app
  is the default for `.pdf` and never changes that default. Several selected PDFs (up to 15, the
  limit for a `Document` verb) start one `cleonpdf.exe "<file>"` each, and the single-instance
  hand-off opens them as tabs. On Windows 11 it is under "Show more options"; a first-level entry
  needs an `IExplorerCommand` handler and package identity (a sparse MSIX package), which the MSI
  doesn't have.
- `test-msi.ps1 <file.msi>` checks the compiled shortcut, context-menu and dialog tables, and
  evaluates the desktop shortcut's first-install and update conditions. Packaging
  runs it in a child process before signing, so the MSI isn't held open when signtool runs.
- The portable zip holds both executables, the README, the licences, the OFL licence of each
  embedded craft-fonts family, and `portable.txt`. That marker beside `cleonpdf.exe` keeps the
  settings, logs, crash recovery and new digital IDs in `CleonPdfData\` next to the exe instead of
  `%APPDATA%` and `%LOCALAPPDATA%` (`crates/ui-egui/src/portable.rs`).
- **Signing:** `packaging/windows/sign.ps1` signs both executables and the MSI with `signtool`
  (SHA-256, RFC 3161 timestamp), from a `.pfx` (`WINDOWS_CERTIFICATE`) or Azure Trusted Signing
  (`AZURE_*`), whichever is configured. It is the one place to change when signing changes.

Locally: `dotnet tool install -g wix --version 5.0.2`, then `pwsh packaging/windows/package.ps1 -Arch x64`.

### Linux

`packaging/linux/package.sh` stages one FHS tree (both binaries, the desktop entry, hicolor icons,
AppStream metainfo) and makes every format from it: an **AppImage** (any distribution, nothing to
install), a **.deb** and an **.rpm** (built with [nfpm](https://nfpm.goreleaser.com) from
`nfpm.yaml`; they integrate with the menu, MIME and icon caches), a **.tar.gz**, and a CLI-only
**`cleonpdf-cli-<v>-linux-<arch>.tar.gz`** (the stripped `cleonpdf-cli` plus the licences and
README, for servers, CI and agent sandboxes). `--formats` picks a subset (`appimage deb rpm tar cli`).

The binaries are built on Ubuntu 22.04, the oldest GitHub-hosted image, so they need only
**glibc ≥ 2.35**: Ubuntu 22.04+, Debian 12+, Fedora 36+, RHEL 10. Windowing (X11, Wayland,
xkbcommon) and the GPU (Vulkan, EGL) are loaded at runtime from the system; the .deb and .rpm declare
them as dependencies (see `nfpm.yaml`).

Each AppImage embeds update information
(`gh-releases-zsync|kristianrama|cleonpdf|latest|cleonpdf-*-linux-<arch>.AppImage.zsync`), and its
`.zsync` is published beside it, so AppImageUpdate and AppImageLauncher can update it in place,
downloading only the changed blocks. `latest` is the newest published, non-pre-release version.
`package.sh` writes the `.zsync` when `zsyncmake` (the `zsync` package) is installed and warns
otherwise. The release job installs zsync, and runs a pinned appimagetool with a pinned runtime
(`APPIMAGETOOL`, `APPIMAGE_RUNTIME`).

**Flatpak:** `packaging/linux/flatpak-bundle.sh` turns a tarball into a single-file bundle with
`flatpak/io.github.kristianrama.cleonpdf.bundle.yml` (no Rust build; the same binaries), then installs
it and runs `cleonpdf-cli --version` in the sandbox. The release workflow doesn't run it yet.
`flatpak/io.github.kristianrama.cleonpdf.yml` is the from-source manifest for a later Flathub
submission. Printing is not available in the Flatpak yet: it runs `lp`, which the freedesktop runtime
lacks; it needs the print portal.

Locally (on Linux, with nfpm): `packaging/linux/package.sh` or `--formats "deb tar"`; then
`packaging/linux/flatpak-bundle.sh` for the Flatpak.

### FreeBSD

GitHub has no FreeBSD runners, so a FreeBSD build needs a FreeBSD VM (PdfCraft used one on
`ubuntu-latest`) running `packaging/freebsd/package.sh`. The tarball is a `/usr/local`-style tree with
the same desktop entry, metainfo and icons as Linux. The release workflow doesn't build it yet.

### Web

`packaging/web/package.sh` runs `trunk build --release` in `apps/cleonpdf-web` and zips the site
with sample `_headers` and `.htaccess` files. Hosting (MIME types, compression, caching, iframes) is
covered in [`packaging/web/README.md`](../packaging/web/README.md).

## Secrets

The signing secrets are repository secrets (*Settings ▸ Secrets and variables ▸ Actions*). Each is
optional: without them, the Windows files are unsigned and the macOS ones are ad-hoc signed and not
notarized, and the run shows a warning. For more protection, move them into an environment limited to
the `release` branch and add `environment: <name>` to the macOS and Windows jobs.

| Secret | Used for |
|---|---|
| `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD` | base64 Developer ID Application `.p12` and its password |
| `KEYCHAIN_PASSWORD` | the temporary CI keychain (random if unset) |
| `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` | `notarytool` (an app-specific password) |
| `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD` | base64 `.pfx` code-signing certificate and its password |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | service principal for Azure Trusted Signing (instead of a `.pfx`) |
| `AZURE_SIGNING_ENDPOINT`, `AZURE_SIGNING_ACCOUNT`, `AZURE_CERT_PROFILE` | Trusted Signing endpoint, account and certificate profile |
| `SIGNPATH_API_TOKEN` | SignPath API token of a user who may submit signing requests (below) |

### Windows signing through SignPath

CleonPDF's Windows files are signed through [SignPath](https://about.signpath.io/), free for open
source, with SignPath Foundation's certificate ([code signing policy](code-signing.md)). The
`windows (SignPath)` job runs when the repository **variable** `SIGNPATH_ORGANIZATION_ID` is set
(*Settings ▸ Secrets and variables ▸ Actions ▸ Variables*); `SIGNPATH_PROJECT_SLUG` and
`SIGNPATH_POLICY_SLUG` default to `cleonpdf` and `release-signing`. In the SignPath project:

- the artifact configuration is
  [`packaging/windows/signpath-artifact-configuration.xml`](../packaging/windows/signpath-artifact-configuration.xml),
  set as the project's default;
- the *GitHub.com* trusted build system is linked, and the SignPath GitHub app can read this
  repository.

The job sends the unsigned MSI and portable zip, then waits up to four hours for an approver to
approve the request in SignPath (SignPath emails the approvers). Approved, the signed files replace
the unsigned ones and the draft is made as usual. Rejected, failed or timed out, there is no draft;
re-run the failed jobs to ask again. SignPath checks that the programs' product version is the
release's version, so a test run with a `version` override can't be signed.

`GITHUB_TOKEN` creates the release; only the final job gets `contents: write`.

## Checks

There is no packaging-lint workflow yet. Before changing `packaging/` or the workflows, run locally:

```sh
actionlint .github/workflows/*.yml          # with shellcheck on PATH, it checks the run: scripts too
shellcheck packaging/*.sh packaging/*/*.sh
desktop-file-validate packaging/linux/io.github.kristianrama.cleonpdf.desktop
```

## Scanner detections

Antivirus and reputation scanners sometimes flag a released file. Check the facts before you change
code or answer publicly. The first report was [issue #747](https://github.com/storytold/pdfcraft/issues/747),
a match of the `CobaltStrikeBeacon` family rule.

1. **Confirm the file is the release.** Compare its SHA-256 with `SHA256SUMS.txt` on the GitHub
   Release. Only a file whose hash matches the release says anything about that release.
2. **Record the signature.** `packaging/windows/security-audit.ps1` prints the Authenticode status:
   - `Valid`: the signature verifies.
   - `NotSigned`: no signature, as in developer and test builds. Not evidence of compromise by itself.
   - `HashMismatch`: the file changed after it was signed. Investigate.
   - `NotTrusted` or `UnknownError`: a signature exists but did not validate on this machine. Compare
     the signer and the hash with the release.
3. **Extract the payloads without running them.** Scan the executables inside the MSI and the
   portable zip, not only the outer installer. `7z x -oDIR cleonpdf-<version>-windows-x64.msi`
   extracts them. The payload names are WiX-internal, so tell the executables apart by their file
   type. Don't install or run the MSI or the extracted files.
4. **Scan with YARA and keep every match.** Use your own copies of YARA and the rule. CleonPDF
   bundles neither, and the helper never runs in the app, the installer or CI:

   ```powershell
   pwsh packaging/windows/security-audit.ps1 -Path .\cleonpdf.exe, .\cleonpdf-cli.exe -YaraExe C:\tools\yara64.exe -YaraRule C:\rules\CobaltStrikeBeacon.yar
   ```

   The output lists each matched identifier with its offset, and the SHA-256 of the rule file.
   Record where the rule came from and its revision. For CAPEv2's `CobaltStrikeBeacon` rule, that is
   the commit that last changed `data/yara/CAPE/CobaltStrikeBeacon.yar`.
5. **Find the condition branch.** Family rules usually have alternative branches, such as
   `all of ($x*) or 2 of ($a*) or ...`. Copy the rule, make one rule per branch with only the strings
   it uses, and scan again to see which branch fired.
6. **Interpret with care.** A match on generic repeated-byte patterns says much less than a match on
   distinctive code or strings, and it does not show that the software belongs to the family. Rules
   change too: CAPEv2 commit `9b599185` (2024-12-05) lengthened this rule's two repeated-byte patterns
   from 4 to 16 bytes to reduce false positives, so an older rule revision can match files that the
   current one does not. Don't alter CleonPDF's binaries to change a scanner's result. That changes
   nothing about the software.
7. **Report.** To the scanner, send the file's SHA-256, the release URL, the rule name and revision,
   and the matched identifiers and offsets. Report CleonPDF problems at
   <https://github.com/kristianrama/cleonpdf/issues> with the same facts.
