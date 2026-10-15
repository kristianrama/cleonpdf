#!/usr/bin/env bash
# glass-compare.sh <cleonpdf binary> <out dir> <label>: CleonPDF with the glass window over a colourful
# picture, light and dark theme, one screenshot each.
set -u
APP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUT="$(mkdir -p "$2" && cd "$2" && pwd)"
L="$3"
LOG="$OUT/$L-steps.log"
log() { echo "$(date +%T) $*" | tee -a "$LOG"; }
defaults write com.apple.universalaccess reduceTransparency -bool false >>"$LOG" 2>&1
if ! pgrep -x Preview >/dev/null; then
  open -a Preview "$PWD/smoke/wallpaper.png"
  sleep 6
  osascript -e 'tell application "Preview" to set bounds of front window to {0, 25, 1024, 768}' >>"$LOG" 2>&1
fi
cp "smoke/Esempio CleonPDF.pdf" "$OUT/doc.pdf"
scene() {
  local name="$1"; shift
  "$APP" "$@" >"$OUT/$L-$name.out" 2>&1 &
  local pid=$!
  sleep 25
  screencapture -x "$OUT/$L-$name.png" && log "shot $name"
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  sleep 3
}
scene light --glass on --language it --theme light --new-window "$OUT/doc.pdf"
scene dark --glass on --language it --theme dark --new-window "$OUT/doc.pdf"
log done
