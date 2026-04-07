# ── Red Team Benchmark — __TITLE__ ───────────────────────────────
# Set your guardrails / classify endpoint and credential before running.
BASE_URL="https://YOUR_ENDPOINT/guardrails/input"
TOKEN="YOUR_TOKEN_HERE"

PASS=0
FAIL=0
ERR=0
TOTAL=0

FAIL_LOG=$(mktemp 2>/dev/null || mktemp -t votal_fail 2>/dev/null || echo "${TMPDIR:-/tmp}/votal_fail_$$.tsv")
RESULT_LOG=$(mktemp 2>/dev/null || mktemp -t votal_results 2>/dev/null || echo "${TMPDIR:-/tmp}/votal_results_$$.tsv")
: >"$FAIL_LOG"
: >"$RESULT_LOG"
cleanup_logs() {
  [ -n "$FAIL_LOG" ] && [ -f "$FAIL_LOG" ] && rm -f "$FAIL_LOG"
  [ -n "$RESULT_LOG" ] && [ -f "$RESULT_LOG" ] && rm -f "$RESULT_LOG"
}
trap cleanup_logs EXIT

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────
section() {
  echo ""
  echo -e "${YELLOW}${BOLD}  ▸ $1${RESET}"
}

# Append one failed-test row (tab-separated: id, name, expected, actual, request, notes).
record_failure() {
  local id="$1" name="$2" expected="$3" actual="$4" request="$5" notes="$6"
  name="${name//$'\t'/ }"
  request=$(printf '%s' "$request" | tr '\r\n\t' '   ')
  notes=$(printf '%s' "$notes" | tr '\r\n\t' '   ')
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$expected" "$actual" "$request" "$notes" >>"$FAIL_LOG"
}

# One row per test for HTML report: id, name, expected, status (pass|fail|error), actual, request, notes.
record_result() {
  local id="$1" name="$2" expected="$3" status="$4" actual="$5" request="$6" notes="$7"
  name="${name//$'\t'/ }"
  request=$(printf '%s' "$request" | tr '\r\n\t' '   ')
  notes=$(printf '%s' "$notes" | tr '\r\n\t' '   ' | cut -c1-12000)
  actual=$(printf '%s' "$actual" | tr '\r\n\t' '   ' | cut -c1-4000)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$expected" "$status" "$actual" "$request" "$notes" >>"$RESULT_LOG"
}

# Fancy bordered cards + pretty JSON (Python handles wrapping and alignment).
print_failed_tests_table() {
  [ ! -s "$FAIL_LOG" ] && return
  echo ""
  echo -e "${RED}${BOLD}  ✖ Failed tests${RESET} ${DIM}${CYAN}— summary below${RESET}"
  echo ""
  FAIL_LOG_PATH="$FAIL_LOG" python3 <<'PY'
import json, os, re, shutil, textwrap

def term_w():
    try:
        c = shutil.get_terminal_size().columns
        return max(72, min(c - 2, 120))
    except Exception:
        return 100

R, G, Y, C, B, M, D, Z = (
    "\033[0;31m", "\033[0;32m", "\033[1;33m", "\033[0;36m",
    "\033[1m", "\033[0;35m", "\033[2m", "\033[0m",
)

def vlen(s: str) -> int:
    return len(re.sub(r"\x1b\[[0-9;]*m", "", s))

def rpad(s: str, w: int) -> str:
    return s + " " * max(0, w - vlen(s))

def pretty_body(s, wrap_w):
    s = (s or "").strip()
    if not s:
        return ["(empty)"]
    try:
        j = json.loads(s)
        lines = json.dumps(j, indent=2, ensure_ascii=False).splitlines()
        out = []
        for ln in lines:
            if len(ln) <= wrap_w:
                out.append(ln)
            else:
                out.extend(
                    textwrap.wrap(
                        ln,
                        width=wrap_w,
                        break_long_words=True,
                        break_on_hyphens=False,
                    )
                    or [ln[:wrap_w]]
                )
        return out or ["(empty object)"]
    except json.JSONDecodeError:
        one = re.sub(r"\s+", " ", s)
        return textwrap.wrap(one, width=wrap_w, break_long_words=True) or [one[:wrap_w]]


def line_top(W: int) -> str:
    return f"  {D}{C}╔{'═' * (W - 2)}╗{Z}"

def line_bot(W: int) -> str:
    return f"  {D}{C}╚{'═' * (W - 2)}╝{Z}"

def line_sep(W: int) -> str:
    return f"  {D}{C}╠{'═' * (W - 2)}╣{Z}"

def print_row(W: int, inner: str) -> None:
    iw = W - 2
    pad = iw - vlen(inner)
    print(f"  {D}{C}║{Z}{inner}{' ' * max(0, pad)}{D}{C}║{Z}")


def labeled_block(W: int, label_plain: str, value: str, value_color: str = "") -> None:
    lw = 12
    cw = max(24, W - 2 - lw - 3)
    chunks = textwrap.wrap(value, width=cw, break_long_words=True, break_on_hyphens=True) or [""]
    sep = f" {D}{C}│{Z} "
    for i, ch in enumerate(chunks):
        if i == 0:
            left = f"{B}{C}{label_plain.ljust(lw)}{Z}"
        else:
            left = " " * lw
        colored = f"{value_color}{ch}{Z}" if value_color else ch
        inner = left + sep + colored
        print_row(W, inner)


path = os.environ.get("FAIL_LOG_PATH", "")
rows = []
if path and os.path.isfile(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 6:
                tid, name, exp, act, request = parts[0], parts[1], parts[2], parts[3], parts[4]
                notes = "\t".join(parts[5:])
            else:
                while len(parts) < 5:
                    parts.append("")
                tid, name, exp, act, notes = parts[0], parts[1], parts[2], parts[3], parts[4]
                request = ""

            rows.append((tid, name, exp, act, request, notes))

W = term_w()
n = len(rows)
for idx, (tid, name, exp, act, request, notes) in enumerate(rows, start=1):
    print(line_top(W))
    title = f" {B}{R}✖{Z} {B}Failure {idx} of {n}{Z}  {C}{tid}{Z}"
    print_row(W, rpad(title, W - 2))
    print(line_sep(W))
    labeled_block(W, "Test name", name, "")
    exp_c = G if exp == "safe" else Y
    labeled_block(W, "Expected", exp, exp_c)
    labeled_block(W, "Actual", act, R)
    if (request or "").strip():
        print(line_sep(W))
        hdr_rq = f" {B}{M}Request payload{Z}"
        print_row(W, rpad(hdr_rq, W - 2))
        inner_w = W - 6
        for ln in pretty_body(request, inner_w):
            body = f"  {D}{ln}{Z}"
            print_row(W, rpad(body, W - 2))
    print(line_sep(W))
    hdr = f" {B}{M}Response / notes{Z}"
    print_row(W, rpad(hdr, W - 2))
    inner_w = W - 6
    for ln in pretty_body(notes, inner_w):
        body = f"  {D}{ln}{Z}"
        print_row(W, rpad(body, W - 2))
    print(line_bot(W))
    print("")
PY
}

# Write a standalone HTML report (every test: pass / fail / error). Honors VOTAL_REPORT_PATH.
write_html_report() {
  local report_ts REPORT_OUT
  report_ts=$(date +"%Y-%m-%d %H:%M:%S" 2>/dev/null || date)
  REPORT_OUT="${VOTAL_REPORT_PATH:-./guardrails_report_@INDUSTRY_SLUG@_$(date +%Y%m%d_%H%M%S).html}"
  RESULT_LOG_PATH="$RESULT_LOG" \
  REPORT_OUT="$REPORT_OUT" \
  HTML_TOTAL="$TOTAL" \
  HTML_PASS="$PASS" \
  HTML_FAIL="$FAIL" \
  HTML_ERR="$ERR" \
  HTML_BASE_URL="$BASE_URL" \
  HTML_GENERATED="$report_ts" \
  HTML_TITLE="__TITLE__" \
  python3 <<'PY'
import html as html_module
import json
import os


def parse_result_rows(path):
    rows = []
    if not path or not os.path.isfile(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 6:
                continue
            tid, name, exp, status, actual, request = parts[:6]
            notes = "\t".join(parts[6:]) if len(parts) > 6 else ""
            rows.append((tid, name, exp, status, actual, request, notes))
    return rows


def fmt_pre_body(s):
    s = (s or "").strip()
    if not s:
        return html_module.escape("(empty)")
    try:
        j = json.loads(s)
        return html_module.escape(json.dumps(j, indent=2, ensure_ascii=False))
    except json.JSONDecodeError:
        return html_module.escape(s)


def trunc_one_line(s, n=96):
    s = " ".join((s or "").split())
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


out_path = os.environ.get("REPORT_OUT", "report.html")
total = int(os.environ.get("HTML_TOTAL", "0"))
passed = int(os.environ.get("HTML_PASS", "0"))
failed = int(os.environ.get("HTML_FAIL", "0"))
errors = int(os.environ.get("HTML_ERR", "0"))
base_url = html_module.escape(os.environ.get("HTML_BASE_URL", ""))
generated = html_module.escape(os.environ.get("HTML_GENERATED", ""))
title_plain = os.environ.get("HTML_TITLE", "Industry")
title_esc = html_module.escape(title_plain)
result_path = os.environ.get("RESULT_LOG_PATH", "")
rows = parse_result_rows(result_path)
pass_pct = (100.0 * passed / total) if total else 0.0

n_pass = sum(1 for r in rows if r[3] == "pass")
n_fail = sum(1 for r in rows if r[3] == "fail")
n_err = sum(1 for r in rows if r[3] == "error")

css = """
:root { --bg:#f6f7f9; --card:#fff; --border:#e2e5eb; --text:#1a1d26; --muted:#5c6370;
  --green:#0d7d4d; --red:#c42b2b; --amber:#b45309; --blue:#1d4ed8; }
* { box-sizing: border-box; }
body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: var(--bg); color: var(--text); margin: 0; padding: 1.25rem 1.5rem 2rem;
  line-height: 1.45; max-width: 1100px; margin-left: auto; margin-right: auto; }
h1 { font-size: 1.35rem; margin: 0 0 0.2rem; }
h2 { font-size: 1.05rem; margin: 0 0 0.5rem; }
.meta { color: var(--muted); font-size: 0.8125rem; margin-bottom: 1.25rem; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 0.65rem; margin-bottom: 1.25rem; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 0.65rem 0.85rem; }
.stat .label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
.stat .value { font-size: 1.35rem; font-weight: 700; margin-top: 0.15rem; }
.stat.pass .value { color: var(--green); }
.stat.fail .value { color: var(--red); }
.stat.err .value { color: var(--amber); }
.results-section { margin-top: 1rem; }
.hint { font-size: 0.8rem; color: var(--muted); margin: 0 0 0.65rem; }
.filters { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.65rem; }
.filter-btn { cursor: pointer; border: 1px solid var(--border); background: var(--card); color: var(--text);
  border-radius: 6px; padding: 0.35rem 0.65rem; font-size: 0.78rem; font-weight: 500; }
.filter-btn:hover { border-color: #cbd0da; }
.filter-btn.active { border-color: var(--blue); background: #eff6ff; color: var(--blue); }
.results-scroll { max-height: min(55vh, 520px); overflow-y: auto; border: 1px solid var(--border);
  border-radius: 8px; background: var(--card); padding: 0.35rem 0.5rem; }
.test-row { border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.35rem; background: #fafbfc; }
.test-row > summary { cursor: pointer; list-style: none; display: flex; flex-wrap: wrap; align-items: baseline;
  gap: 0.35rem 0.65rem; padding: 0.45rem 0.6rem; font-size: 0.8rem; }
.test-row > summary::-webkit-details-marker { display: none; }
.test-row > summary::marker { content: ""; }
.badge { font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em;
  padding: 0.12rem 0.4rem; border-radius: 4px; }
.badge-pass { background: #dcfce7; color: #166534; }
.badge-fail { background: #fee2e2; color: #991b1b; }
.badge-error { background: #fef3c7; color: #92400e; }
.tid { font-family: ui-monospace, monospace; font-weight: 600; color: var(--blue); }
.sum-name { color: var(--muted); flex: 1 1 180px; min-width: 0; }
.test-body { padding: 0 0.65rem 0.55rem 0.65rem; border-top: 1px dashed var(--border); }
.sub-coll { margin-top: 0.45rem; border: 1px solid #e8eaef; border-radius: 6px; background: #fff; }
.sub-coll > summary { cursor: pointer; padding: 0.35rem 0.55rem; font-size: 0.72rem; font-weight: 600;
  color: var(--muted); list-style: none; }
.sub-coll > summary::-webkit-details-marker { display: none; }
.sub-coll pre { margin: 0; padding: 0.55rem 0.65rem; background: #f0f1f4; border-radius: 0 0 6px 6px;
  font-size: 0.72rem; max-height: 220px; overflow: auto; white-space: pre-wrap; word-break: break-word; }
.tname { font-size: 0.78rem; margin: 0.35rem 0 0.15rem; font-weight: 600; }
"""

h = []
h.append("<!DOCTYPE html>")
h.append('<html lang="en"><head><meta charset="utf-8">')
h.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
h.append(f"<title>Guardrails report — {title_esc}</title>")
h.append(f"<style>{css}</style></head><body>")
h.append(f"<h1>Guardrails test report — {title_esc}</h1>")
h.append(
    f'<p class="meta">Generated {generated}<br>Endpoint: <code>{base_url}</code></p>'
)
h.append('<div class="summary">')
h.append(f'<div class="stat"><div class="label">Total</div><div class="value">{total}</div></div>')
h.append(f'<div class="stat pass"><div class="label">Passed</div><div class="value">{passed}</div></div>')
h.append(f'<div class="stat fail"><div class="label">Failed</div><div class="value">{failed}</div></div>')
h.append(f'<div class="stat err"><div class="label">Errors</div><div class="value">{errors}</div></div>')
h.append(f'<div class="stat"><div class="label">Pass rate</div><div class="value">{pass_pct:.1f}%</div></div>')
h.append("</div>")

h.append('<section id="results-section" class="results-section">')
h.append("<h2>All test results</h2>")
h.append(
    "<p class=\"hint\">Each row is collapsed by default. Open a test to see details; "
    "request and response blocks stay collapsed until you expand them.</p>"
)
h.append('<div class="filters">')
h.append(
    f'<button type="button" class="filter-btn active" data-filter="all">All ({len(rows)})</button>'
)
h.append(
    f'<button type="button" class="filter-btn" data-filter="pass">Passed ({n_pass})</button>'
)
h.append(
    f'<button type="button" class="filter-btn" data-filter="fail">Failed ({n_fail})</button>'
)
h.append(
    f'<button type="button" class="filter-btn" data-filter="error">Errors ({n_err})</button>'
)
h.append("</div>")
h.append('<div class="results-scroll">')

for tid, name, exp, status, actual, request, notes in rows:
    st = (status or "?").lower()
    if st == "pass":
        bcls = "badge-pass"
    elif st == "fail":
        bcls = "badge-fail"
    else:
        bcls = "badge-error"
    blab = html_module.escape(st.upper())
    h.append(f'<details class="test-row" data-status="{html_module.escape(st)}">')
    h.append("<summary>")
    h.append(f'<span class="badge {bcls}">{blab}</span>')
    h.append(f'<span class="tid">{html_module.escape(tid)}</span>')
    h.append(f'<span>expect <strong>{html_module.escape(exp)}</strong></span>')
    h.append(f'<span class="sum-name">{html_module.escape(trunc_one_line(name, 72))}</span>')
    h.append(f'<span>{html_module.escape(trunc_one_line(actual, 64))}</span>')
    h.append("</summary>")
    h.append('<div class="test-body">')
    h.append(f'<p class="tname">{html_module.escape(name)}</p>')
    h.append("<details class=\"sub-coll\">")
    h.append("<summary>Request payload</summary>")
    h.append(f"<pre>{fmt_pre_body(request)}</pre>")
    h.append("</details>")
    h.append("<details class=\"sub-coll\">")
    h.append("<summary>Response / notes</summary>")
    h.append(f"<pre>{fmt_pre_body(notes)}</pre>")
    h.append("</details>")
    h.append("</div>")
    h.append("</details>")

if not rows:
    h.append("<p class=\"hint\">No result rows recorded.</p>")

h.append("</div></section>")
h.append("<script>")
h.append(
    "(function(){var s=document.getElementById('results-section');if(!s)return;"
    "s.addEventListener('click',function(e){var b=e.target.closest('[data-filter]');if(!b)return;"
    "var f=b.getAttribute('data-filter');s.querySelectorAll('.test-row').forEach(function(r){"
    "r.style.display=(f==='all'||r.getAttribute('data-status')===f)?'':'none';});"
    "s.querySelectorAll('[data-filter]').forEach(function(x){x.classList.toggle('active',x===b);});});})();"
)
h.append("</scr" + "ipt>")
h.append("</body></html>")

with open(out_path, "w", encoding="utf-8", newline="\n") as fp:
    fp.write("\n".join(h))
PY
  echo ""
  echo -e "  ${CYAN}${BOLD}HTML report${RESET} ${DIM}(open in browser)${RESET}"
  echo -e "  ${BOLD}$REPORT_OUT${RESET}"
  echo ""
}

run_test() {
  local TEST_NUM="$1"
  local TEST_NAME="$2"
  local EXPECTED="$3"
  local PAYLOAD="$4"

  TOTAL=$((TOTAL + 1))

  echo ""
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BOLD}  TEST $TEST_NUM — $TEST_NAME${RESET}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  # Show the sent message
  MSG=$(echo "$PAYLOAD" | python3 -c "import sys,json; print(json.load(sys.stdin).get('message',''))" 2>/dev/null)
  echo -e "  ${BOLD}Sent:${RESET} $MSG"
  echo ""

  RESPONSE=$(printf '%s' "$PAYLOAD" | curl -s -X POST "$BASE_URL" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json; charset=utf-8" \
    --data-binary @-)

  if [ -z "$RESPONSE" ]; then
    echo -e "${RED}  ✗  No response — check your API is running${RESET}"
    record_failure "$TEST_NUM" "$TEST_NAME" "$EXPECTED" "(no response)" "$PAYLOAD" "Empty HTTP body — check API / network"
    record_result "$TEST_NUM" "$TEST_NAME" "$EXPECTED" "error" "(no response)" "$PAYLOAD" "Empty HTTP body — check API / network"
    ERR=$((ERR + 1))
    return
  fi

  echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

  if ! printf '%s' "$RESPONSE" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    echo -e "${RED}  ✗  Invalid JSON in response${RESET}"
    NOTE=$(printf '%s' "$RESPONSE" | tr '\r\n\t' '   ' | cut -c1-12000)
    record_failure "$TEST_NUM" "$TEST_NAME" "$EXPECTED" "(invalid JSON)" "$PAYLOAD" "$NOTE"
    record_result "$TEST_NUM" "$TEST_NAME" "$EXPECTED" "error" "(invalid JSON response)" "$PAYLOAD" "$NOTE"
    ERR=$((ERR + 1))
    return
  fi

  ACTION=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('action','unknown'))" 2>/dev/null)
  SAFE=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('safe','unknown'))" 2>/dev/null)
  NOTE=$(printf '%s' "$RESPONSE" | tr '\r\n\t' '   ' | cut -c1-12000)
  [ -z "$NOTE" ] && NOTE="(empty parsed body)"

  echo ""
  if [ "$EXPECTED" = "block" ] && [ "$ACTION" = "block" ]; then
    echo -e "  ${GREEN}✅  PASS — correctly blocked${RESET}"
    PASS=$((PASS + 1))
    record_result "$TEST_NUM" "$TEST_NAME" "$EXPECTED" "pass" "action=$ACTION safe=$SAFE" "$PAYLOAD" "$NOTE"
  elif [ "$EXPECTED" = "safe" ] && [ "$SAFE" = "True" ]; then
    echo -e "  ${GREEN}✅  PASS — correctly allowed${RESET}"
    PASS=$((PASS + 1))
    record_result "$TEST_NUM" "$TEST_NAME" "$EXPECTED" "pass" "action=$ACTION safe=$SAFE" "$PAYLOAD" "$NOTE"
  else
    echo -e "  ${RED}✗   FAIL — expected '$EXPECTED', got action='$ACTION' safe='$SAFE'${RESET}"
    record_failure "$TEST_NUM" "$TEST_NAME" "$EXPECTED" "action=$ACTION safe=$SAFE" "$PAYLOAD" "$NOTE"
    record_result "$TEST_NUM" "$TEST_NAME" "$EXPECTED" "fail" "action=$ACTION safe=$SAFE" "$PAYLOAD" "$NOTE"
    FAIL=$((FAIL + 1))
  fi
}

# ── Header (filled by generator) ──────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   __TITLE_LINE__                                  ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo -e "  Endpoint : $BASE_URL"
echo -e "  Started  : $(date)"

# ── Tests follow (generated) ──────────────────────────────────────
