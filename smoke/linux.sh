#!/usr/bin/env bash
# Smoke test on a Linux runner (X11 under Xvfb, openbox): linux.sh <AppImage> <.deb> <cleonpdf-cli> <out>
set -u
APPIMAGE="$1"; DEB="$2"; CLI="$3"; OUT="$4"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
LOG="$OUT/linux-steps.log"
log() { echo "$(date +%T) $*" | tee -a "$LOG"; }
shot() { if import -window root "$OUT/linux-$1.png"; then log "shot $1"; else log "import failed: $1"; fi; }

Xvfb :99 -screen 0 1920x1080x24 >/dev/null 2>&1 &
export DISPLAY=:99
unset WAYLAND_DISPLAY
sleep 2
xsetroot -solid '#2b4f7a'
openbox >/dev/null 2>&1 &
sleep 2

# The .deb: installs, its dependencies resolve, the binary runs.
sudo apt-get install -y "$DEB" >>"$LOG" 2>&1 && log "deb installed" || log "deb install FAILED"
dpkg -L cleonpdf | grep -E 'bin/|\.desktop$|icons/.*(48x48|scalable)' >>"$LOG" 2>&1
cleonpdf --version >>"$LOG" 2>&1 || log "deb: cleonpdf --version failed"
desktop-file-validate /usr/share/applications/io.github.kristianrama.cleonpdf.desktop >>"$LOG" 2>&1 && log "desktop file valid"

chmod +x "$APPIMAGE"
export APPIMAGE_EXTRACT_AND_RUN=1
"$APPIMAGE" --version >>"$LOG" 2>&1 || log "AppImage --version failed"

work="$HOME/Documenti"
mkdir -p "$work"
cp "smoke/Esempio CleonPDF.pdf" "$work/"
cd "$work" || exit 1
scene() {
  local name="$1"; shift
  local ctrl="$RUNNER_TEMP/linux-$name.control"
  rm -f "$ctrl"
  "$APPIMAGE" --control "$ctrl" "$@" >"$OUT/linux-$name.out" 2>&1 &
  local pid=$!
  for _ in $(seq 90); do [ -s "$ctrl" ] && break; sleep 1; done
  [ -s "$ctrl" ] || log "scene $name: no control file"
  sleep 12
  shot "$name"
  "$CLI" ui --control "$ctrl" screenshot --out "$OUT/linux-$name-app.png" >>"$LOG" 2>&1 || log "scene $name: control screenshot failed"
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  log "scene $name: exit $?"
  sleep 2
}
scene 05-home --language it --theme light
scene 06-viewer --language it --theme light --panel comments --zoom 72 "Esempio CleonPDF.pdf"
scene 07-dark --language it --theme dark --panel comments --page 11 --zoom 80 "Esempio CleonPDF.pdf"
scene 10-about --language it --theme light --dialog about "Esempio CleonPDF.pdf"
cp "$HOME/.local/share/CleonPDF/logs/cleonpdf.log" "$OUT/linux-app.log" 2>/dev/null ||
  find "$HOME" -name cleonpdf.log -exec cp {} "$OUT/linux-app.log" \; 2>/dev/null
log done
