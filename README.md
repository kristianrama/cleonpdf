<p align="center">
  <img src="assets/app-icon/cleonpdf.svg" alt="CleonPDF app icon: a page with an amber folded corner and a bold C on a navy tile" width="112">
</p>

<h1 align="center">CleonPDF</h1>

<p align="center">
  <b>An open-source PDF workbench written in Rust.</b><br>
  Read, organize, combine, split, comment on, fill in and protect PDFs in a fast native app that runs
  on your machine, with no account, no telemetry and no cloud.<br>
  macOS · Windows · Linux · FreeBSD · the web
</p>

<p align="center">
  <img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-1d3461">
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-1d3461">
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-f2a93b">
</p>

> [!NOTE]
> CleonPDF is based on [PdfCraft](https://github.com/storytold/pdfcraft) 0.8.0 by the ArtCraft team and
> the PdfCraft contributors, under the same MIT OR Apache-2.0 license. It is an independent project, not
> made, sponsored or endorsed by the ArtCraft team. What changed is listed in
> [What CleonPDF changes](#what-cleonpdf-changes).

[Status](#status) · [What it does](#what-it-does) · [Command line and agents](#command-line-and-agents) · [Build from source](#build-from-source) · [How it's built](#how-its-built) · [What CleonPDF changes](#what-cleonpdf-changes) · [License](#license-and-credits)

---

## Status

**CleonPDF is alpha.** It starts from PdfCraft 0.8.0 (October 2026). The PdfCraft team measured that
release against Acrobat Pro: most offline features exist in some form (57% of all tracked features, 94%
of the must-haves), and every everyday workflow can be completed. Those numbers are theirs and have not
been re-measured for CleonPDF; [docs/target-app-parity.md](docs/target-app-parity.md) explains how they
were taken.

- **Good today:** viewing and search; organizing, combining and splitting; most kinds of comment; filling
  and authoring forms (with sandboxed JavaScript); passwords, redaction and sanitizing; basic digital
  signatures; printing; the Accessibility Checker; agent control through the CLI and MCP.
- **Still borrowed:** pages are drawn by the `hayro` crate.
- **Thin or missing:** reliable editing of existing text (especially CJK and right-to-left), OCR beyond
  Latin script, Office import and export, Preflight and PDF/X/UA, full XFA forms.
- **Hardening:** fuzzing still finds crashes and hangs on hostile files. Each one gets fixed with a
  regression test.

**There are no CleonPDF releases yet.** Build it from source (below). Releases will appear on the
[releases page](https://github.com/kristianrama/cleonpdf/releases), which is also where the app looks
for updates.

## What it does

- **Reads faithfully.** It handles kerning and ligatures, right-to-left and complex scripts, vertical
  CJK, colour emoji, shadings, blend modes, soft masks and optional content. Large pages render in tiles,
  so text stays sharp at any zoom. It has continuous, single-page, two-up, full-screen and Read layouts,
  in light and dark themes.
- **Survives bad files.** Every page renders in isolation and damaged documents are repaired.
- **Finds, selects and copies text** in reading order, across columns, right-to-left runs and CJK.
- **Organizes pages like cards on a table.** Rotate, delete, insert and reorder pages, with undo that
  still works after you save.
- **Combines, extracts and splits** without losing links, form fields, layers or attachments.
- **Saves safely.** Saves are incremental, so the original bytes stay intact. Writes are atomic. Work
  is autosaved every minute and offered back after a crash.
- **Opens protected documents.** The full standard security handler is implemented, from 40-bit RC4 to
  AES-256, and the author's permissions are honoured.
- **Covers the rest of a PDF.** Comments in threads, forms, layers, attachments and Document Properties.
- **Finds every tool from one place.** Press <kbd>⌘K</kbd> (<kbd>Ctrl K</kbd>) to search every tool
  and command.

## Command line and agents

Every engine feature is reachable without the GUI, through one table of JSON-Schema-described tools.

```sh
cleonpdf-cli info    form.pdf                                  # structure as JSON
cleonpdf-cli text    paper.pdf --page 3                        # reading-order text
cleonpdf-cli edit    in.pdf --rotate 1,2:90 --delete 5 --title "Q3" --out out.pdf
cleonpdf-cli combine report.pdf appendix.pdf --out combined.pdf
cleonpdf-cli split   report.pdf --every 10 --out-dir parts/
cleonpdf-cli tools                                             # every tool and its JSON Schema
cleonpdf-cli run --script steps.json --root ./work             # several steps in one session
```

With `--root`, every file a script reads or writes stays inside that directory.

**MCP server, for AI agents.** It is opt-in: CleonPDF never starts it on its own, and it opens no
network port. It runs only while an agent launches `cleonpdf-cli mcp`, and talks over stdin/stdout:

```json
{ "mcpServers": { "cleonpdf": { "command": "cleonpdf-cli", "args": ["mcp", "--root", "/path/to/your/pdfs"] } } }
```

`--compact` shrinks the tool list the agent has to read. To build the CLI without the server, use
`cargo build -p cleonpdf-cli --no-default-features`.

**Driving the app.** Start the desktop app with `cleonpdf --control ~/.cleonpdf-control.json` and an
agent can inspect and operate the real interface through `cleonpdf-cli ui --control …`: clicks, typing,
commands, panels and screenshots. It is off by default and listens only on loopback. Every connection
must present the random token written to that file. Keep the file in a folder only you can write.

## Build from source

You need Rust 1.95 or later.

```sh
git clone https://github.com/kristianrama/cleonpdf
cd cleonpdf
cargo xtask models                                 # fetch the OCR models Scan & OCR needs
cargo run --release -p cleonpdf -- some.pdf        # desktop app
cargo run --release -p cleonpdf-cli -- --help      # command-line tool
```

Japanese interface text, and Japanese text in edited PDFs, need the fonts from
[craft-fonts](https://github.com/storytold/craft-fonts), an optional build input:

```sh
git clone https://github.com/storytold/craft-fonts ../craft-fonts
CRAFT_FONTS_DIR=../craft-fonts cargo run --release -p cleonpdf -- some.pdf
```

Packaging scripts for every platform are in [`packaging/`](packaging/). Logs, environment variables and
other development notes are in [docs/development.md](docs/development.md).

## How it's built

CleonPDF is a Cargo workspace of focused crates, layered so the core never depends on the UI:

| Crate | What it does |
|---|---|
| `cleonpdf-filters` | Every PDF stream filter (Flate, LZW, ASCII85, RunLength, predictors), encode and decode |
| `cleonpdf-crypt` | The standard security handler: RC4, AES-128/256, revisions 2–6, permissions |
| `cleonpdf-cos` | The PDF object layer: tolerant parsing, repair, copy-on-write edits, incremental and full writing |
| `cleonpdf-organize` | Page operations, combine, extract and split, bookmarks, page labels, document information |
| `cleonpdf-annot` | Comments: notes, text markup, shapes, ink and text boxes, with replies and appearances |
| `cleonpdf-forms` | Interactive forms: the field model, filling with regenerated appearances |
| `cleonpdf-render` | Rendering, inspection and text extraction in reading order |
| `cleonpdf-engine` | The façade every frontend uses: sessions, edits, undo, saving, the tool catalogue |
| `cleonpdf-automation` | Agent control: the headless tool table, `cleonpdf-cli run` and the opt-in MCP server |
| `cleonpdf-ui-egui` | The desktop and web interface |

Every change has to pass the same checks: `cargo fmt --check`, Clippy with warnings as errors, the
tests, `cargo xtask layers` (crate layering) and `cargo xtask assets` (asset licences).

Behaviour comes from the ISO 32000 specification and black-box observation, never from anyone else's
code. Every icon, font and image is openly licensed and listed in [ATTRIBUTION.md](ATTRIBUTION.md).

## What CleonPDF changes

Compared with PdfCraft 0.8.0:

- **Name.** The app, binaries (`cleonpdf`, `cleonpdf-cli`), crates (`cleonpdf-*`) and identifiers
  (`io.github.kristianrama.cleonpdf`) are renamed. The Windows installer has its own upgrade code, so it
  never replaces a PdfCraft installation.
- **Branding.** The ArtCraft name and logos, the Discord links and the ArtCraft web pages are removed.
  The app links to this repository instead. CleonPDF has a new app icon.
- **Updates.** The app checks this repository's releases, not PdfCraft's.
- **A parser fix.** The number parser in `cleonpdf-cos` ran in quadratic time on long malformed numbers:
  a 4 KB compressed content stream could stall it for about half an hour. It now runs in linear time,
  and it no longer produces infinite or NaN reals from input such as `-inf` or `1e999`.

Issue and pull request numbers in `docs/` and in code comments (such as #90) refer to
[PdfCraft's tracker](https://github.com/storytold/pdfcraft/issues), where that history lives.

## License and credits

CleonPDF is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Required notices, including PdfCraft's copyright, are in [NOTICE](NOTICE).

CleonPDF is built on the work of the PdfCraft contributors, who are credited in the app's About dialog
(Contributors tab) and in [contributors/](contributors/).

Bundled fonts, icons, images and other assets keep their own open licences. Each one is listed with its
author, source and licence in [ATTRIBUTION.md](ATTRIBUTION.md).

<sub>Adobe and Acrobat are trademarks or registered trademarks of Adobe Inc. in the United States and/or
other countries. CleonPDF is an independent, open-source project and is not affiliated with, sponsored by
or endorsed by Adobe Inc.; these names are used only to describe the workflows it is compatible with.</sub>
