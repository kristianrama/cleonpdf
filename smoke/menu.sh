#!/usr/bin/env bash
# menu.sh <cleonpdf> <cleonpdf-cli> <out dir> <label>: the macOS menu bar. Reads it back through the
# control channel, opens each menu with System Events (needs Accessibility) and screenshots it, then
# chooses items with the pointer and by key and checks the effect in ui.state.
set -u
APP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CLI="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
OUT="$(mkdir -p "$3" && cd "$3" && pwd)"
L="$4"
LOG="$OUT/$L-steps.log"
log() { echo "$(date +%T) $*" | tee -a "$LOG"; }
sw_vers >>"$LOG"
cp "smoke/Esempio CleonPDF.pdf" "$OUT/doc.pdf"
ctrl="$RUNNER_TEMP/menu.control"
rm -f "$ctrl"
"$APP" --control "$ctrl" --language it --theme light --new-window "$OUT/doc.pdf" >"$OUT/$L-app.out" 2>&1 &
pid=$!
for _ in $(seq 120); do [ -s "$ctrl" ] && break; sleep 1; done
[ -s "$ctrl" ] || log "no control file"
sleep 10
ui() { "$CLI" ui --control "$ctrl" "$@"; }
state() { ui state >"$OUT/$L-state-$1.json" 2>>"$LOG" || log "state $1 failed"; python3 - "$OUT/$L-state-$1.json" <<'PY' | tee -a "$LOG"
import json, sys
s = json.load(open(sys.argv[1]))
a = s.get("active") or {}
print(sys.argv[1].rsplit("-", 1)[-1], "dirty:", [d["dirty"] for d in s.get("documents", [])], "zoom:", a.get("zoom_percent"), "find_open:", a.get("find_open"), "close_prompt:", s.get("close_prompt"))
PY
}
ui menu_bar >"$OUT/$L-menu_bar.json" 2>>"$LOG" || log "menu_bar failed"
python3 - "$OUT/$L-menu_bar.json" <<'PY' | tee -a "$LOG"
import json, sys
m = json.load(open(sys.argv[1]))
print("system:", m.get("system"))
rb = m.get("read_back") or []
print("read back:", [i.get("title") for i in rb])
for menu in rb:
    keys = [f'{i["title"]} {i.get("key", "")}'.strip() for i in menu.get("items", []) if "title" in i]
    print("  ", menu.get("title"), "|", " · ".join(keys))
PY
state 0
screencapture -x "$OUT/$L-01-window.png" && log "shot window"
se() { osascript -e "tell application \"System Events\" to tell (first process whose unix id is $pid) to $1" 2>&1; }
log "frontmost: $(se 'set frontmost to true')"
sleep 1
log "menu bar items: $(se 'get name of every menu bar item of menu bar 1')"
for i in 2 3 4 5 6 7 8; do
  r=$(se "click menu bar item $i of menu bar 1")
  [ -n "$r" ] && log "click menu $i: $r"
  sleep 1.5
  screencapture -x "$OUT/$L-menu-$i.png" && log "shot menu $i"
  osascript -e 'tell application "System Events" to key code 53' >>"$LOG" 2>&1
  sleep 1
done
# With the pointer: Pagine ▸ Ruota pagine in senso orario.
log "rotate: $(se 'click menu item "Ruota pagine in senso orario" of menu 1 of menu bar item "Pagine" of menu bar 1')"
sleep 2
state 1-rotated
# By key, through the items' key equivalents.
key() { osascript -e "tell application \"System Events\" to keystroke \"$1\" using {$2}" 2>&1; }
log "cmd-1: $(key 1 'command down')"
sleep 2
state 2-actual-size
log "cmd-f: $(key f 'command down')"
sleep 2
state 3-find
key abc '' >/dev/null
sleep 1
screencapture -x "$OUT/$L-02-find-typed.png"
log "cmd-a, cmd-x in the find field: $(key a 'command down') $(key x 'command down')"
sleep 1
screencapture -x "$OUT/$L-03-find-cut.png"
log "cmd-z in the find field: $(key z 'command down')"
sleep 2
state 4-undo-in-field
osascript -e 'tell application "System Events" to key code 53' >>"$LOG" 2>&1
sleep 1
log "cmd-z: $(key z 'command down')"
sleep 2
state 5-undone
log "rotate again: $(se 'click menu item "Ruota pagine in senso orario" of menu 1 of menu bar item "Pagine" of menu bar 1')"
sleep 2
log "cmd-q: $(key q 'command down')"
sleep 3
state 6-quit
screencapture -x "$OUT/$L-04-quit.png"
kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
grep -h 'menu bar\|glass\|panicked' "$HOME/Library/Application Support/CleonPDF/logs/"*.log >>"$LOG" 2>/dev/null
log done
