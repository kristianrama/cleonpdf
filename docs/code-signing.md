# Code signing policy

CleonPDF's release files are built from this repository's source code by GitHub Actions on
GitHub-hosted runners ([`.github/workflows/release.yml`](../.github/workflows/release.yml)), from
the `release` branch. Nothing is built or signed on a personal machine. Each release lists the
SHA-256 of every file in `SHA256SUMS.txt`.

## Windows

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by
[SignPath Foundation](https://signpath.org/).

- **What is signed:** `cleonpdf.exe` and `cleonpdf-cli.exe`, inside both the MSI installer and the
  portable zip, and the MSI itself.
- **How:** the release workflow sends the unsigned MSI and portable zip to SignPath, which signs them
  as set out in
  [`packaging/windows/signpath-artifact-configuration.xml`](../packaging/windows/signpath-artifact-configuration.xml).
  It checks that every signed program carries the product name `CleonPDF` and the release's version.
- **Approval:** every signing request is approved by hand by an approver (below) before anything is
  signed.

## macOS

The app and the command-line tool are signed with a Developer ID Application certificate of
Kristian Rama and notarized by Apple ([`packaging/macos/`](../packaging/macos/)).

## Status

Version 0.1.0 was released unsigned. Signing starts with the first release after it is set up:
Windows once SignPath Foundation has accepted the project, macOS once the Apple Developer ID is in
place. The release notes say whether a release is signed.

## Team roles

- **Committers and reviewers:** [Kristian Rama](https://github.com/kristianrama). Changes proposed by
  anyone else (pull requests) are reviewed by a committer before they are merged.
- **Approvers:** [Kristian Rama](https://github.com/kristianrama).

Every team member uses multi-factor authentication for GitHub and SignPath.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically
requested by the user or the person installing or operating it.

The only network request CleonPDF makes itself is *Help ▸ Check for updates*, which asks GitHub
for the latest release when you choose it. Nothing is downloaded or installed automatically. Links
in documents open in your browser only when you click them and confirm.
