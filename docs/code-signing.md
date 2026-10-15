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

The macOS files are not signed with an Apple Developer ID or notarized: they carry an ad-hoc
signature only ([`packaging/macos/`](../packaging/macos/)). The first time a new version opens,
macOS refuses it; *System Settings ▸ Privacy & Security ▸ Open Anyway* opens it.

## Status

Releases so far are unsigned. Windows signing starts with the first release after SignPath
Foundation accepts the project; until then Windows asks, the first time a new version opens, to
choose *More info ▸ Run anyway*.

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
