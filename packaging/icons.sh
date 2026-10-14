#!/usr/bin/env bash
# Regenerate the app icons from the two raster masters in assets/app-icon/, and the Windows PDF
# file icon from assets/app-icon/cleonpdf-document.svg:
#
#   cleonpdf.png        1024 px, the full tile (the emblem and the "Cleon PDF" wordmark): 64 px and up
#   cleonpdf-small.png  1024 px, the emblem alone on the same tile: below 64 px, where the wordmark
#                       would only be a smudge
#
# Needs: python3 with Pillow (pip install 'pillow>=12'), and resvg (cargo install resvg) for the
# document icon. The outputs are committed, so building and packaging never need these tools.
# After running it, update the sha256 values in ATTRIBUTION.toml, then `cargo xtask assets --write`.
#
#   packaging/icons.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$ROOT/assets/app-icon"
ID="io.github.kristianrama.cleonpdf"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

command -v resvg >/dev/null || { echo "error: resvg not found (cargo install resvg)" >&2; exit 1; }
python3 -c 'import PIL' 2>/dev/null || { echo "error: Pillow not found (pip install pillow)" >&2; exit 1; }

# The app icon: hicolor PNGs, the macOS 1024 px PNG and .icns, and the Windows .ico.
python3 - "$DIR" "$ID" <<'PY'
import io, struct, sys
from PIL import Image

out, app_id = sys.argv[1], sys.argv[2]
full = Image.open(f"{out}/cleonpdf.png").convert("RGBA")
small = Image.open(f"{out}/cleonpdf-small.png").convert("RGBA")
SMALL_BELOW = 64  # sizes under this use the emblem without the wordmark

def tile(size):
    return (small if size < SMALL_BELOW else full).resize((size, size), Image.LANCZOS)

def apple(size):
    # Apple's icon grid: an 824/1024 body centred on a transparent canvas.
    body = round(size * 824 / 1024)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    off = (size - body) // 2
    canvas.alpha_composite(tile(body), (off, off))
    return canvas

def png(im):
    b = io.BytesIO()
    im.save(b, format="PNG", optimize=True)
    return b.getvalue()

# 1024 px on Apple's grid (also the runtime Dock icon on macOS, see apps/cleonpdf/src/main.rs).
open(f"{out}/cleonpdf-1024.png", "wb").write(png(apple(1024)))

# Linux hicolor theme (full bleed; hicolor/256x256 is also the runtime icon on Windows and Linux).
import os
for s in (16, 24, 32, 48, 64, 128, 256, 512):
    d = f"{out}/hicolor/{s}x{s}/apps"
    os.makedirs(d, exist_ok=True)
    open(f"{d}/{app_id}.png", "wb").write(png(tile(s)))

# Windows .ico: PNG-compressed entries, 16-256 px.
blobs = [png(tile(s)) for s in (16, 20, 24, 32, 40, 48, 64, 128, 256)]
head = struct.pack("<HHH", 0, 1, len(blobs))
entries, data, offset = b"", b"", 6 + 16 * len(blobs)
for b in blobs:
    w, h = struct.unpack(">II", b[16:24])  # IHDR
    entries += struct.pack("<BBBBHHII", w % 256, h % 256, 0, 0, 1, 32, len(b), offset)
    data += b
    offset += len(b)
open(f"{out}/cleonpdf.ico", "wb").write(head + entries + data)

# macOS .icns: every entry a PNG on Apple's grid, which macOS reads for all of these since 10.7.
body = b""
for kind, size in (("icp4", 16), ("icp5", 32), ("icp6", 64), ("ic07", 128), ("ic08", 256), ("ic09", 512),
                   ("ic10", 1024), ("ic11", 32), ("ic12", 64), ("ic13", 256), ("ic14", 512)):
    p = png(apple(size))
    body += kind.encode("ascii") + struct.pack(">I", 8 + len(p)) + p
open(f"{out}/cleonpdf.icns", "wb").write(b"icns" + struct.pack(">I", 8 + len(body)) + body)
PY

# The Windows PDF document icon: its own resource in cleonpdf.exe; the app icon stays the first one.
render() { resvg -w "$2" -h "$2" "$1" "$3" </dev/null; }
ICO_PNGS=()
for s in 16 20 24 32 40 48 64 128 256; do
  render "$DIR/cleonpdf-document.svg" "$s" "$TMP/document-$s.png"
  ICO_PNGS+=("$TMP/document-$s.png")
done
python3 - "$DIR/cleonpdf-document.ico" "${ICO_PNGS[@]}" <<'PY'
import struct, sys
out, pngs = sys.argv[1], sys.argv[2:]
blobs = [open(p, "rb").read() for p in pngs]
head = struct.pack("<HHH", 0, 1, len(blobs))
entries, data, offset = b"", b"", 6 + 16 * len(blobs)
for b in blobs:
    w, h = struct.unpack(">II", b[16:24])  # IHDR
    entries += struct.pack("<BBBBHHII", w % 256, h % 256, 0, 0, 1, 32, len(b), offset)
    data += b
    offset += len(b)
open(out, "wb").write(head + entries + data)
PY
echo "icons written to $DIR"
