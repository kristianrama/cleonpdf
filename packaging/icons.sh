#!/usr/bin/env bash
# Regenerate every app icon from the two vector masters in assets/app-icon/, and the Windows PDF
# file icon from assets/app-icon/cleonpdf-document.svg:
#
#   cleonpdf.svg        the full tile, with the "Cleon PDF" wordmark: icons of 64 px and up
#   cleonpdf-small.svg  the emblem alone on the same tile: icons below 64 px, where the wordmark
#                       would only be a smudge
#
# The masters come from packaging/app-icon-svg.py. Needs: resvg (cargo install resvg) and python3
# (stdlib only, for the .ico and .icns containers). The outputs are committed, so building and
# packaging never need these tools. After running it, update the sha256 values in
# ATTRIBUTION.toml, then `cargo xtask assets --write`.
#
#   packaging/icons.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$ROOT/assets/app-icon"
FULL="$DIR/cleonpdf.svg"
SMALL="$DIR/cleonpdf-small.svg"
ID="io.github.kristianrama.cleonpdf"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

command -v resvg >/dev/null || { echo "error: resvg not found (cargo install resvg)" >&2; exit 1; }

render() { resvg -w "$2" -h "$2" "$1" "$3" </dev/null; }
# The master for a body of $1 px: the emblem alone below 64 px.
master() { if [ "$1" -lt 64 ]; then echo "$SMALL"; else echo "$FULL"; fi; }

# macOS icons follow Apple's grid: an 824 px body centred on a transparent 1024 canvas.
for which in full small; do
  src="$FULL"; [ "$which" = small ] && src="$SMALL"
  {
    echo '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1024 1024">'
    echo '<image x="100" y="100" width="824" height="824" xlink:href="'"$src"'"/>'
    echo '</svg>'
  } >"$TMP/mac-$which.svg"
done
mac() { # size -> the grid wrapper whose body suits that size
  if [ $(($1 * 824 / 1024)) -lt 64 ]; then echo "$TMP/mac-small.svg"; else echo "$TMP/mac-full.svg"; fi
}

# 1024 px on Apple's grid (also the runtime Dock icon on macOS, see apps/cleonpdf/src/main.rs).
render "$(mac 1024)" 1024 "$DIR/cleonpdf-1024.png"

# Linux hicolor theme (full bleed; hicolor/256x256 is also the runtime icon on Windows and Linux).
for s in 16 24 32 48 64 128 256 512; do
  mkdir -p "$DIR/hicolor/${s}x${s}/apps"
  render "$(master "$s")" "$s" "$DIR/hicolor/${s}x${s}/apps/$ID.png"
done
mkdir -p "$DIR/hicolor/scalable/apps"
cp "$FULL" "$DIR/hicolor/scalable/apps/$ID.svg"

# Windows .ico files: PNG-compressed entries, 16-256 px. The document icon has its own resource
# in cleonpdf.exe; the app icon remains the first/default icon.
ico() { # out.ico png...
  python3 - "$@" <<'PY'
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
}
APP_PNGS=() DOC_PNGS=()
for s in 16 20 24 32 40 48 64 128 256; do
  render "$(master "$s")" "$s" "$TMP/app-$s.png"
  render "$DIR/cleonpdf-document.svg" "$s" "$TMP/document-$s.png"
  APP_PNGS+=("$TMP/app-$s.png")
  DOC_PNGS+=("$TMP/document-$s.png")
done
ico "$DIR/cleonpdf.ico" "${APP_PNGS[@]}"
ico "$DIR/cleonpdf-document.ico" "${DOC_PNGS[@]}"

# macOS .icns: every entry a PNG, which macOS reads for all of these types since 10.7.
ICNS_ARGS=()
for entry in icp4:16 icp5:32 icp6:64 ic07:128 ic08:256 ic09:512 ic10:1024 ic11:32 ic12:64 ic13:256 ic14:512; do
  size="${entry#*:}"
  [ -f "$TMP/mac-$size.png" ] || render "$(mac "$size")" "$size" "$TMP/mac-$size.png"
  ICNS_ARGS+=("${entry%%:*}" "$TMP/mac-$size.png")
done
python3 - "$DIR/cleonpdf.icns" "${ICNS_ARGS[@]}" <<'PY'
import struct, sys
out, rest = sys.argv[1], sys.argv[2:]
body = b""
for kind, path in zip(rest[::2], rest[1::2]):
    png = open(path, "rb").read()
    body += kind.encode("ascii") + struct.pack(">I", 8 + len(png)) + png
open(out, "wb").write(b"icns" + struct.pack(">I", 8 + len(body)) + body)
PY
echo "icons written to $DIR"
