#!/usr/bin/env bash
# Smoke test on a macOS runner: mac.sh release <app.dmg> <cleonpdf-cli> <out>
#                                mac.sh main <cleonpdf binary> <cleonpdf-cli> <out>
set -u
MODE="$1"; SRC="$2"; CLI="$3"; OUT="$4"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
LOG="$OUT/$MODE-steps.log"
log() { echo "$(date +%T) $*" | tee -a "$LOG"; }
shot() { if screencapture -x "$OUT/$MODE-$1.png"; then log "shot $1"; else log "screencapture failed: $1"; fi; }

log "screen: $(system_profiler SPDisplaysDataType 2>/dev/null | grep -i resolution | head -1 | xargs)"
if [ "$MODE" = release ]; then
  open "$SRC"
  sleep 10
  shot dmg-window
  ls -la /Volumes/CleonPDF >>"$LOG" 2>&1
  cp -R /Volumes/CleonPDF/CleonPDF.app /Applications/ && log "copied to /Applications"
  osascript -e 'tell application "Finder" to close every window' >/dev/null 2>&1
  hdiutil detach /Volumes/CleonPDF -quiet || log "detach failed"
  APP=/Applications/CleonPDF.app/Contents/MacOS/CleonPDF
  { codesign -dv /Applications/CleonPDF.app 2>&1; spctl -a -vv /Applications/CleonPDF.app 2>&1; } >>"$LOG"
else
  APP="$SRC"
fi
"$APP" --version >>"$LOG" 2>&1

work="$HOME/Documenti"
mkdir -p "$work"
cp "smoke/Esempio CleonPDF.pdf" "$work/"
cd "$work" || exit 1
scene() {
  local name="$1"; shift
  local ctrl="$RUNNER_TEMP/$MODE-$name.control"
  rm -f "$ctrl"
  "$APP" --control "$ctrl" "$@" >"$OUT/$MODE-$name.out" 2>&1 &
  local pid=$!
  for _ in $(seq 60); do [ -s "$ctrl" ] && break; sleep 1; done
  [ -s "$ctrl" ] || log "scene $name: no control file"
  sleep 10
  [ "$MODE" = release ] && osascript -e 'tell application "CleonPDF" to activate' >/dev/null 2>&1
  sleep 2
  shot "$name"
  "$CLI" ui --control "$ctrl" screenshot --out "$OUT/$MODE-$name-app.png" >>"$LOG" 2>&1 || log "scene $name: control screenshot failed"
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  log "scene $name: exit $?"
  sleep 2
}
scene 05-home --language it --theme light
scene 06-viewer --language it --theme light --panel comments --zoom 72 "Esempio CleonPDF.pdf"
scene 07-dark --language it --theme dark --panel comments --page 11 --zoom 80 "Esempio CleonPDF.pdf"
scene 10-about --language it --theme light --dialog about "Esempio CleonPDF.pdf"
ls -la "$HOME/Library/Application Support/CleonPDF" >>"$LOG" 2>&1
cp "$HOME/Library/Application Support/CleonPDF/logs/cleonpdf.log" "$OUT/$MODE-app.log" 2>/dev/null
log done
