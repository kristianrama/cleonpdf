#!/usr/bin/env bash
# radio.sh <cleonpdf> <cleonpdf-cli> <out dir> <label>: click View ▸ Single page while it is already
# chosen, and Continuous scrolling twice, then read the marks back from the system menu bar.
set -u
APP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CLI="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
OUT="$(mkdir -p "$3" && cd "$3" && pwd)"
L="$4"
LOG="$OUT/$L-radio.log"
log() { echo "$(date +%T) $*" | tee -a "$LOG"; }
cp "smoke/Esempio CleonPDF.pdf" "$OUT/doc.pdf"
ctrl="$RUNNER_TEMP/radio-$L.control"
rm -f "$ctrl"
"$APP" --control "$ctrl" --language it --theme light --new-window "$OUT/doc.pdf" >"$OUT/$L-radio-app.out" 2>&1 &
pid=$!
for _ in $(seq 120); do [ -s "$ctrl" ] && break; sleep 1; done
sleep 10
marks() {
  "$CLI" ui --control "$ctrl" menu_bar >"$OUT/$L-radio-$1.json" 2>>"$LOG"
  python3 - "$OUT/$L-radio-$1.json" "$1" <<'PY' | tee -a "$LOG"
import json, sys
m = json.load(open(sys.argv[1]))
view = next(x for x in m["read_back"] if x.get("title") == "Visualizza")
want = ["Pagina singola", "Visualizzazione doppia", "Scorrimento continuo"]
marks = {i["title"]: bool(i.get("checked")) for i in view["items"] if i.get("title") in want}
model = next(x for x in m["menus"] if x["title"] == "Visualizza")
app = {i["label"]: i.get("checked") for i in model["items"] if i.get("label") in want}
print(sys.argv[2], "system:", marks, "app:", app, "AGREE" if marks == app else "DISAGREE")
PY
}
se() { osascript -e "tell application \"System Events\" to tell (first process whose unix id is $pid) to $1" 2>&1; }
se 'set frontmost to true' >/dev/null
sleep 1
marks 0-start
se 'click menu item "Pagina singola" of menu 1 of menu bar item "Visualizza" of menu bar 1' >>"$LOG"
sleep 2
marks 1-single-again
se 'click menu item "Scorrimento continuo" of menu 1 of menu bar item "Visualizza" of menu bar 1' >>"$LOG"
sleep 2
marks 2-continuous-off
se 'click menu item "Visualizzazione doppia" of menu 1 of menu bar item "Visualizza" of menu bar 1' >>"$LOG"
sleep 2
marks 3-two-up
kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
log done
