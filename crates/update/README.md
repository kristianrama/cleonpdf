# cleonpdf-update

Layer L5: installing a new CleonPDF from inside the app (*Help ▸ Check for updates ▸ Update*),
without network code or UI. The desktop app (`apps/cleonpdf/src/updates.rs`) downloads through
`cleonpdf-net` and shows progress; this crate decides what is safe to install and puts it in.

- **The release key** (`PublicKey`, `SecretKey`): Ed25519. The public half is built into the app
  from `packaging/update-key.pub`; the private half lives with the owner and in the release
  workflow's `CLEONPDF_RELEASE_KEY` secret. `cargo xtask update-key` makes one and signs with it.
- **Signed checksums** (`verify_sums`, `listed_sha256`, `copy_checked`): a release's
  `SHA256SUMS.txt` must be signed with the release key (`SHA256SUMS.txt.sig`, over a fixed context
  line and the file), and a download must hash to the checksum listed for its exact name. Sizes
  are capped (`MAX_SUMS`, `MAX_SIG`, `MAX_ASSET`); a download can be cancelled between chunks.
- **What fits this copy** (`install::detect`): a macOS app bundle (not translocated), the Windows
  MSI install (under Program Files, no portable marker, x64), a Linux AppImage (`$APPIMAGE`,
  x86_64 or aarch64). Anything else says why and gets the release page.
- **Putting it in** (`install::stage`, `install::apply`): the disk image is mounted read-only and
  its bundle copied beside the running one; once CleonPDF has closed, the bundles are swapped by
  renaming (the old one is put back if the new one can't go in) and the new one opened. The MSI is
  run with `msiexec /passive /norestart`. The AppImage is renamed over the running one and started.
  `Target::check_writable` fails before any download when the folder can't be written.

Release file names follow `.github/workflows/release.yml` (`cleonpdf-<version>-macos-universal.dmg`,
`-windows-x64.msi`, `-linux-<arch>.AppImage`). The macOS test builds a real disk image with
`hdiutil`, so it runs on the macOS CI runner.
