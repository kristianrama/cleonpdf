# CleonPDF app icon

<img src="cleonpdf.svg" alt="CleonPDF app icon: a glowing C around an open book marked PDF, on a dark blue tile" width="128">

**Design:** a glowing C with a geometric lattice in its band, around a globe and an open book marked
"PDF", above the "Cleon PDF" wordmark, on a dark blue-to-violet tile with a light rim. It follows the
artwork the project owner, Kristian Rama, supplied on 2026-10-14 (a 1408 × 768 mockup whose icon is
about 474 px wide), redrawn as vectors so every size is sharp.

**Two vector masters**, written by [`packaging/app-icon-svg.py`](../../packaging/app-icon-svg.py) (edit its
geometry and colours there, not the SVGs):

- `cleonpdf.svg`: the whole tile, for every size from 64 px up.
- `cleonpdf-small.svg`: the emblem alone on the same tile, for sizes below 64 px, where the wordmark
  would only be a smudge.

The tile is a superellipse |x|ⁿ + |y|ⁿ = 1 with n = 4.9, the corner shape of the supplied artwork. The
glow is SVG blur filters; the wordmark and the "PDF" on the book are Inter, outlined by usvg, so the
SVGs need no fonts.

**Tile:** Windows and Linux icons use the full-bleed tile. macOS icons put it on Apple's grid (an
824 px body centred on a transparent 1024 px canvas).

Licence: [LICENSE.txt](LICENSE.txt) (`MIT OR Apache-2.0`, like the repo).

## Files

| File | What it is |
|---|---|
| `cleonpdf.svg` | vector master: the full tile; every icon of 64 px and up is rendered from it |
| `cleonpdf-small.svg` | vector master: the emblem alone; every icon below 64 px is rendered from it |
| `cleonpdf-1024.png` | 1024 px on Apple's grid; also the runtime Dock icon on macOS |
| `cleonpdf.icns` | macOS icon (16–1024 px) |
| `cleonpdf.ico` | Windows icon (16–256 px), embedded in `cleonpdf.exe` by `apps/cleonpdf/build.rs` |
| `cleonpdf-document.svg` | Windows PDF file icon master: a Lucide document outline, navy badge and outlined PDF lettering (vector, unchanged by the raster artwork); no font dependency |
| `cleonpdf-document.ico` | Windows PDF file icon (16–256 px), embedded as resource 2 in `cleonpdf.exe` |
| `hicolor/<n>x<n>/apps/io.github.kristianrama.cleonpdf.png` | Linux hicolor theme, 16–512 px; the 256 px one is the runtime icon on Windows and Linux |
| `hicolor/scalable/apps/io.github.kristianrama.cleonpdf.svg` | Linux scalable icon (copy of `cleonpdf.svg`) |

Where it shows: `apps/cleonpdf/src/main.rs` sets the window icon (Dock, taskbar, Alt-Tab, launcher) and the
Wayland app id `io.github.kristianrama.cleonpdf`; `packaging/linux/io.github.kristianrama.cleonpdf.desktop` names the
hicolor icon.

Windows PDF files use resource 2 (`"cleonpdf.exe",-2`) when CleonPDF is chosen as the default
reader; the app keeps resource 1. The document outline is adapted from Lucide `file-text`
1.49.0 (ISC); its badge and outlined lettering are original (`MIT OR Apache-2.0`), covered by
[LICENSE-document.txt](LICENSE-document.txt). Both icons are embedded, requiring no runtime
sidecar. This provides a file type icon; first-page thumbnails still need a thumbnail provider.

## Regenerate

```sh
python3 packaging/app-icon-svg.py   # only after changing the design; needs usvg
packaging/icons.sh                  # needs resvg and python3
cargo xtask assets        # then update the sha256 values in ATTRIBUTION.toml and run with --write
```
