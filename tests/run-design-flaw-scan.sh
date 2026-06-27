#!/usr/bin/env bash
# AntiBot/WAF GW HTML/JS design-flaw scanner
# Combines: semgrep (custom rules) + retire.js (known-vuln libs) + CSP audit
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
RULES="$SCRIPT_DIR/semgrep-design-flaws.yml"
DASHBOARDS="$REPO_ROOT/dashboards"
BOLD=$'\e[1m'; RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; DIM=$'\e[2m'; RST=$'\e[0m'

npass=0; nwarn=0; nfail=0

header(){ echo; echo "${BOLD}━━━ $* ━━━${RST}"; }
ok()  { echo "  ${GRN}✔${RST}  $*"; npass=$((npass+1)); }
bad() { echo "  ${RED}✘${RST}  $*"; nfail=$((nfail+1)); }
warn(){ echo "  ${YEL}⚠${RST}  $*"; nwarn=$((nwarn+1)); }

# ── 1. Semgrep custom design-flaw rules ───────────────────────────────────
header "Semgrep — custom design-flaw rules"
TMPDIR_SCRIPTS=$(mktemp -d)
trap 'rm -rf "$TMPDIR_SCRIPTS"' EXIT

# Extract inline <script> blocks preserving original HTML line numbers so
# Semgrep findings map directly back to the HTML file at the right line.
python3 - "$DASHBOARDS" "$TMPDIR_SCRIPTS" << 'PYEOF'
import re, sys, pathlib
src_dir, out_dir = sys.argv[1], sys.argv[2]
OPEN_RE  = re.compile(r'<script(?:\s[^>]*)?>',  re.IGNORECASE)
CLOSE_RE = re.compile(r'</script\s*>',            re.IGNORECASE)
for html_file in pathlib.Path(src_dir).glob('*.html'):
    lines, out, in_script = html_file.read_text(errors='replace').splitlines(), [], False
    for ln in lines:
        if not in_script:
            if OPEN_RE.search(ln):
                in_script = True
                after = OPEN_RE.split(ln, maxsplit=1)[-1]
                out.append(after if after.strip() else '')
            else:
                out.append('')
        else:
            if CLOSE_RE.search(ln):
                in_script = False
                before = CLOSE_RE.split(ln, maxsplit=1)[0]
                out.append(before if before.strip() else '')
            else:
                out.append(ln)
    pathlib.Path(out_dir, html_file.stem + '.js').write_text('\n'.join(out))
PYEOF

# Run Semgrep on extracted JS (line numbers match original HTML)
SEMGREP_TEXT=$(semgrep --config "$RULES" "$TMPDIR_SCRIPTS/" \
  --no-git-ignore --quiet --text 2>/dev/null) || true

SEMGREP_COUNT=$(echo "$SEMGREP_TEXT" | grep -c "^    ❯❱" 2>/dev/null || echo 0)

if [ "$SEMGREP_COUNT" -eq 0 ]; then
  ok "No design-flaw rule hits"
else
  warn "${SEMGREP_COUNT} finding(s) — line numbers match original HTML files:"
  # Rewrite /tmp/xxx/foo.js → dashboards/foo.html in output
  # Note: array-join-to-innerHTML findings need manual review — check that all
  # string fields inside the map() are wrapped in escapeHtml() before marking OK.
  { echo "$SEMGREP_TEXT" \
    | sed "s|${TMPDIR_SCRIPTS}/||g; s|\.js\b|.html|g" \
    | grep -Ev "^[┌└│]|Code Findings" || true; } | head -80
fi

# ── 2. retire.js — known-vulnerable JS libraries ─────────────────────────
header "retire.js — known-vulnerable JS libraries"
if command -v retire &>/dev/null; then
  RETIRE_OUT=$(retire --path "$DASHBOARDS" --outputformat json 2>/dev/null || true)
  RETIRE_COUNT=$(echo "$RETIRE_OUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin) if sys.stdin.read().strip() else []; print(len(d))" 2>/dev/null || echo 0)
  if [ "$RETIRE_COUNT" -eq 0 ]; then
    ok "No known-vulnerable libraries detected"
  else
    warn "${RETIRE_COUNT} file(s) with known-vulnerable libraries"
    echo "$RETIRE_OUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for item in data:
        f = item.get('file','?').split('dashboards/')[-1]
        for r in item.get('results', []):
            print(f\"    \033[33mWARNING  \033[0m  {f}  [{r.get('component','')} {r.get('version','')}]\")
            for v in r.get('vulnerabilities',[]):
                ids = ', '.join(v.get('identifiers',{}).get('CVE',[]) or
                               v.get('identifiers',{}).get('bug',[]) or ['?'])
                print(f\"             {ids}: {v.get('severity','?')}\")
except: pass
" 2>/dev/null
  fi
else
  warn "retire.js not found — skipping (install: npm install -g retire)"
fi

# ── 3. CSP audit — check response headers from running gateway ────────────
header "CSP audit — live gateway headers"
GW_URL="${GW_URL:-http://localhost:8443}"
ADMIN_PATH="/antibot-appsec-gateway/secured/controls"

HEADERS=$(curl -sI --max-time 5 "$GW_URL$ADMIN_PATH" 2>/dev/null || true)
HTTP_STATUS=$(echo "$HEADERS" | grep -oP "HTTP/[0-9.]+ \K[0-9]+" | tail -1 || echo "")
if [ -z "$HEADERS" ]; then
  warn "Could not reach gateway at $GW_URL — skipping CSP check (set GW_URL env var)"
elif [ "$HTTP_STATUS" = "404" ] || [ "$HTTP_STATUS" = "403" ]; then
  warn "Admin path returned HTTP $HTTP_STATUS — gateway running but admin access denied from this IP (expected if ADMIN_ALLOWED_IPS doesn't include localhost). Pass a reachable URL via GW_URL env var."
else
  # Extract CSP
  CSP=$(echo "$HEADERS" | grep -i "content-security-policy:" | sed 's/.*: //' | tr -d '\r')
  if [ -z "$CSP" ]; then
    bad "No Content-Security-Policy header on admin endpoints"
  else
    ok "CSP header present"
    echo "  ${DIM}${CSP}${RST}" | fold -w 100 -s | sed '2,$s/^/       /'
    # Flag dangerous CSP directives
    echo "$CSP" | grep -qi "unsafe-inline" && warn "CSP contains 'unsafe-inline' (script-src or style-src)" || true
    echo "$CSP" | grep -qi "unsafe-eval"   && warn "CSP contains 'unsafe-eval'" || true
    echo "$CSP" | grep -qi "\*"            && warn "CSP contains wildcard (*) source" || true
    echo "$CSP" | grep -qi "data:"         && warn "CSP allows 'data:' URIs (XSS vector)" || true
    echo "$CSP" | grep -qi "http:"         && warn "CSP allows plain http: sources" || true
    [[ "$CSP" =~ frame-ancestors ]] || bad "CSP missing 'frame-ancestors' directive (clickjacking)"
    [[ "$CSP" =~ default-src|script-src ]] || bad "CSP missing script-src / default-src"
  fi

  # Check other security headers
  echo "$HEADERS" | grep -qi "x-frame-options:"           && ok "X-Frame-Options present"     || bad "X-Frame-Options missing"
  echo "$HEADERS" | grep -qi "x-content-type-options:"    && ok "X-Content-Type-Options present" || bad "X-Content-Type-Options missing"
  echo "$HEADERS" | grep -qi "referrer-policy:"           && ok "Referrer-Policy present"      || warn "Referrer-Policy missing (nice-to-have)"
  echo "$HEADERS" | grep -qi "strict-transport-security:" && ok "HSTS present"                 || warn "HSTS missing (expected if TLS_ENABLED=0)"
  echo "$HEADERS" | grep -qi "permissions-policy:"        && ok "Permissions-Policy present"   || warn "Permissions-Policy missing (nice-to-have)"
fi

# ── 4. Hardcoded secrets scan ─────────────────────────────────────────────
header "Hardcoded secrets / credentials in dashboard JS"
SECRET_HITS=$(grep -rn \
  -E "(api[_-]?key|apikey|secret|password|token|passwd|credential)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{8,}" \
  "$DASHBOARDS" --include="*.html" -i \
  | grep -iv "placeholder\|comment\|label\|desc\|example\|e\.g\.\|sample\|test\|dummy\|fake\|your-\|<.*>\|token.*cookie\|token.*header\|type=.password" \
  | grep -v "^\s*//" \
  | wc -l)
if [ "$SECRET_HITS" -eq 0 ]; then
  ok "No hardcoded credentials detected"
else
  bad "${SECRET_HITS} potential hardcoded secret(s)"
  grep -rn \
    -E "(api[_-]?key|apikey|secret|password|token|passwd|credential)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{8,}" \
    "$DASHBOARDS" --include="*.html" -i \
    | grep -iv "placeholder\|comment\|label\|desc\|example\|e\.g\.\|sample\|test\|dummy\|fake\|your-\|<.*>\|token.*cookie\|token.*header\|type=.password" \
    | grep -v "^\s*//" \
    | sed "s|$DASHBOARDS/||g" \
    | head -10 | sed 's/^/    /'
fi

# ── 5. Internal URL leakage in shipped HTML ───────────────────────────────
header "Internal URL leakage in shipped HTML"
INTERNAL_HITS=$(grep -rn \
  -E "https?://(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|host\.docker\.internal)" \
  "$DASHBOARDS" --include="*.html" \
  | grep -v "^\s*//" \
  | wc -l)
if [ "$INTERNAL_HITS" -eq 0 ]; then
  ok "No internal URLs embedded in shipped HTML"
else
  warn "${INTERNAL_HITS} internal URL(s) in HTML (review — may be legit examples)"
  grep -rn \
    -E "https?://(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|host\.docker\.internal)" \
    "$DASHBOARDS" --include="*.html" \
    | grep -v "^\s*//" \
    | sed "s|$DASHBOARDS/||g" \
    | head -10 | sed 's/^/    /'
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo
echo "${BOLD}━━━ Summary ━━━${RST}"
echo "  ${GRN}Pass: ${npass}${RST}   ${YEL}Warn: ${nwarn}${RST}   ${RED}Fail: ${nfail}${RST}"
echo

if [ "$nfail" -gt 0 ]; then
  exit 1
else
  exit 0
fi
