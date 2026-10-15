#!/usr/bin/env bash
# glass.sh <cleonpdf binary> <out dir> <label>: open a colourful picture, then CleonPDF over it with
# the glass window on and off, and take screenshots.
set -u
APP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUT="$(mkdir -p "$2" && cd "$2" && pwd)"
L="$3"
LOG="$OUT/$L-steps.log"
log() { echo "$(date +%T) $*" | tee -a "$LOG"; }
sw_vers >>"$LOG"
log "reduceTransparency before: $(defaults read com.apple.universalaccess reduceTransparency 2>&1)"
defaults write com.apple.universalaccess reduceTransparency -bool false >>"$LOG" 2>&1 || log "defaults write failed"
log "reduceTransparency after: $(defaults read com.apple.universalaccess reduceTransparency 2>&1)"
open -a Preview "$PWD/smoke/wallpaper.png"
sleep 6
osascript -e 'tell application "Preview" to set bounds of front window to {0, 25, 1024, 768}' >>"$LOG" 2>&1
cp "smoke/Esempio CleonPDF.pdf" "$OUT/doc.pdf"
scene() {
  local name="$1"; shift
  "$APP" "$@" >"$OUT/$L-$name.out" 2>&1 &
  local pid=$!
  sleep 25
  screencapture -x "$OUT/$L-$name.png" && log "shot $name"
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  log "scene $name exit $?"
  sleep 3
}
scene glass-light --glass on --language it --theme light --new-window "$OUT/doc.pdf"
scene glass-dark --glass on --language it --theme dark --new-window "$OUT/doc.pdf"
scene glass-home --glass on --language it --theme light --new-window
scene opaque --glass off --language it --theme light --new-window "$OUT/doc.pdf"
grep -h 'backdrop\|renderer' "$HOME/Library/Application Support/CleonPDF/logs/"*.log >>"$LOG" 2>/dev/null
log done
