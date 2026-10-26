# CleonPDF — instructions for agents

CleonPDF is a clean-room, open-source, Rust-native PDF application targeting Adobe Acrobat Pro parity. It runs natively on macOS, Windows, Linux and FreeBSD, and on the web via WASM. It is a fork of PdfCraft 0.8.0 (https://github.com/storytold/pdfcraft), renamed and maintained by Kristian Rama; `NOTICE` records what it inherits.

## Start every session here
1. Read `ROADMAP.md` (the one-page summary: stage, numbers, progress log), `docs/roadmap.md` (the milestone table), `docs/gaps.md` (the ranked gaps) and `docs/target-app-parity.md` (the numbers and how they are measured) before choosing work. Prefer the gaps over new P2/P3 features, and keep these documents true when things change. At the end of a session, add a line to the ROADMAP.md progress log.
   - Entries before the fork (2026-10-14) describe PdfCraft's history. Issue and PR numbers in `docs/` and code comments refer to PdfCraft's tracker.
   - "Shipped" in `parity/` means "exists and tested", not "as good as Acrobat". Don't mark a feature shipped on a generic test, and say in its notes what is still missing.
2. Read the README of the crate you're touching.
3. PdfCraft's local planning folder (`plan/`: STATUS.md, execution plan, architecture, ADRs, Acrobat observations) was never published, so it is not here. References to it in comments and docs are historical.

## Non-negotiables
- **Assets: read `AGENTS.md` §1 before adding or showing any icon, image, font or document.** No assets from Adobe products, ever. Only openly licensed or contributor-original assets are allowed, each with an entry in `ATTRIBUTION.toml`. `cargo xtask assets` enforces this. `AGENTS.md` overrides this file.
- **Fonts live in [storytold/craft-fonts](https://github.com/storytold/craft-fonts)**, an openly licensed font repository shared with PdfCraft. Never commit font files here (`AGENTS.md` §1.4). It is the optional build input `CRAFT_FONTS_DIR`: `git clone https://github.com/storytold/craft-fonts ../craft-fonts && CRAFT_FONTS_DIR=../craft-fonts cargo test --workspace` embeds the Japanese fonts (UI fallback, Japanese text in edited PDFs) and runs their tests, which otherwise skip. Code using `cleonpdf_fonts::CRAFT_FONTS` must work when it is empty.
- **Clean-room.**
  - Never read, disassemble or copy anything inside the Acrobat bundle (names and listings only). **Never open `Contents/Resources/JavaScripts/`.**
  - Behaviour comes from public docs, specs (ISO 32000-2, the Arlington model) and black-box observation.
  - Never copy GPL/AGPL code. MuPDF, Ghostscript, Poppler, veraPDF and DSS run only as external oracle processes.
- **Privacy.** When observing Acrobat, use synthetic fixtures only. Never capture the Home view, recent files or account info. Never commit Acrobat outputs, corpus files or personal data.
- **Layering.** Nothing below L7 depends on egui/winit/eframe/rfd (`cargo xtask layers` enforces it). `cos`/`filters`/`crypt`/`arlington` stay standalone.
- **Fidelity.** The PDF object graph is the model. Preserve unknown data. Saves are incremental unless a full rewrite is required. Never silently drop or repair data without recording it.
- **Never panic.** Every PDF, script, MCP call, settings file and keystroke is untrusted input, and none of it may crash the app or lose the user's work. This outranks feature work. Return `Result` (the crate's error enum) and propagate with `?`, or fall back leniently and record it. In non-test code:
  - No `unwrap`/`expect`/`panic!`/`unreachable!`/`todo!` unless it is provably infallible, with a comment saying why.
  - No indexing or slicing with input-derived positions (use `get`, and slice strings only at char boundaries).
  - Use checked or saturating arithmetic on input-derived numbers, and guard against division by zero and NaN/inf casts.
  - Cap allocations sized by input, and bound recursion with depth limits or seen-sets.
  - Handle lock poisoning.
  - No `unsafe` (`unsafe_code = "forbid"`).
  - Every crash fix gets a synthetic regression test. See `AGENTS.md` §4.
- **Rust only** in the product and build (`xtask`). No handwritten JS/TS.
- **Review every update as you make it, at four zooms.** Not an end-of-task pass — a per-update habit, so a defect never gets built on. **Clause:** checked arithmetic, `get()` not `[i]`, char-boundary slicing, the right error through `?`, `<` against `<=`, the 1-based/0-based seam, capped allocations. **Function:** is it total — name an input that panics; walk empty, zero, max, malformed, cyclic; is the return type honest. **File/module:** two sources of truth, dead or duplicated code, is the public surface still smallest and the doc comment still true. **Project:** layering, wasm, undo/redo, save fidelity, encryption and permissions, a matching `automation` tool or registry entry, and whether a `parity/` status or note just became untrue. Scale the zoom to the change, and fix what a level turns up before widening.
  - Tests mirror the zooms: property → unit → crate integration → end-to-end.
  - **Prove a test fails before the fix by actually reverting the fix.** A test nobody has seen fail is not evidence. This has caught two worthless tests in this repo: one confinement test passed with path resolution switched off entirely, because the tools failed on a nonexistent document id before reaching the path.
  - **Rebasing is a review step, not a mechanical one.** Read every hunk you resolve, and the auto-merged hunks in the files you touched too — `main` moves fast enough that a file can change by hundreds of lines under a branch.
- **External PRs are held to safety, security and completeness before style.** Provenance first (no Adobe-derived asset, no committed font, no copied GPL/AGPL code, behaviour from the spec and not from reading another implementation), then no new panic path or `unsafe`, then `--root` confinement on every path including ones reached by nested dispatch, opt-in-only MCP and control channel, no new outbound network, then a headless `automation` tool, tests at the right zoom and an honest `parity/` entry. Provenance is the part a contributor cannot be expected to know, and the only part that cannot be undone after merge.
- **Quality gates** before every commit: `cargo fmt --check`, clippy with `-D warnings`, the tests, `cargo xtask layers`, `cargo xtask assets`, and the wasm check once `xtask ci` exists (M0).
  - **Scope builds and tests to the crates you touched** — `cargo clippy -p <crate> -j 2 --all-targets` and `cargo test -p <crate> -j 2`, under a `timeout`. A full `--workspace` build has locked up a development machine's CPU; it is CI's job and CI runs it on every PR. Run the workspace sweep locally only when you have a reason to and the machine is free.
- **Version numbers** follow the owner's official scheme in `docs/releasing.md` §Version numbers: 0.x until stable, the stage stated in the docs and the release title (never a `-beta` suffix, which the update check and the AppImage updater skip), minor for a beta requirement or another capability users notice, patch for fixes in between, 1.0.0 when stable.
- **Commits and PRs:** `main` is the integration branch. Branch from an up-to-date `main` as `<type>/<slug>` (`feat/`, `fix/`, `docs/`, `chore/`, `refactor/`), commit only green states, and open a PR into `main` using `.github/pull_request_template.md`. Merge only when CI is green.
- **Taking fixes from PdfCraft.** CleonPDF renamed every crate and identifier, so upstream commits don't apply as they are. To port one, apply its diff with the same renames (`pdfcraft` → `cleonpdf`, `PdfCraft` → `CleonPDF`, `PdfCraftApp` → `CleonPdfApp`, `PDFCRAFT` → `CLEONPDF`), then review it like any other change. Never add back ArtCraft branding.

## Running and looking at the app
- `cargo run -p cleonpdf -- <file.pdf>` opens the desktop app.
- `cargo run -p cleonpdf-cli -- run --script steps.json --root DIR` drives the engine headlessly through the automation tools (`cleonpdf-cli tools` lists them). Use it, together with `page_render`, to check engine changes. `cleonpdf-cli mcp` is the opt-in MCP server (AGENTS.md §3).
- `cargo xtask fuzz --time 300` mutation-fuzzes open/render/edit/save in child processes. Findings land in `fuzz-out/findings/` (git-ignored; never commit corpus-derived files). Turn every real finding into a small synthetic regression test before fixing it.
- `cargo xtask interop` opens every kind of PDF we write in qpdf, Poppler, MuPDF and Ghostscript (install them; CI runs it with `--require-all`). A new way of writing or saving PDFs gets a case in `xtask/src/interop.rs`.
- `cargo xtask parity [--partial]` reports Acrobat-parity progress from `parity/acrobat-features.toml`. Update the entry when a feature ships.
- `cargo xtask demo-pdf` builds `dist/demo/cleonpdf-showcase.pdf` (needs Chrome) for visual checks.
- For UI work, **look at the result**. Either launch `cleonpdf --control FILE doc.pdf` and use `cleonpdf-cli ui --control FILE screenshot --out x.png` (plus `inspect`, `click`, `key`, `type`, `command`, `set`), or take a headless shot with `cargo run -p cleonpdf-ui-egui --example shot`. Control-channel tests use kittest (`crates/ui-egui/tests/control.rs`).
- Parallel agents: use a separate `CARGO_TARGET_DIR` per agent and separate git worktrees.

## Current bootstrap debt
- `cleonpdf-render` renders through the `hayro` crate directly and inspects documents through `lopdf`. Both are meant to be replaced by `cos` / `model` / the DisplayList device (M1–M2).
