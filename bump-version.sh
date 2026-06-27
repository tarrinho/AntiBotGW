#!/usr/bin/env bash
# bump-version.sh OLD NEW
# Updates every canonical version location in the repo.
# Usage: ./bump-version.sh 1.7.10 1.7.11
set -euo pipefail

OLD="${1:?Usage: $0 OLD NEW  e.g. $0 1.7.10 1.7.11}"
NEW="${2:?Usage: $0 OLD NEW  e.g. $0 1.7.10 1.7.11}"
ROOT="$(cd "$(dirname "$0")" && pwd)"

# Replace $1 with $2 in a file, print what changed
replace() {
    local file="$ROOT/$1" pattern="$2" replacement="$3"
    if grep -qF "$pattern" "$file"; then
        sed -i "s|$(echo "$pattern" | sed 's/[[\.*^$()+?{|]/\\&/g')|$(echo "$replacement" | sed 's/[[\.*^$()+?{|]/\\&/g')|g" "$file"
        echo "  updated: $1"
    else
        echo "  WARN: pattern not found in $1 — skipping: $pattern"
    fi
}

echo "Bumping $OLD → $NEW"

# ── Code version constant ──────────────────────────────────────────────────────
replace config.py                    "AntiBotWaf_GW_${OLD}"          "AntiBotWaf_GW_${NEW}"

# ── Test version constant + stale-string guard ─────────────────────────────────
replace tests/test_pure.py           "_EXPECTED_VERSION = \"AntiBotWaf_GW_${OLD}\"" "_EXPECTED_VERSION = \"AntiBotWaf_GW_${NEW}\""
replace tests/test_pure.py           "AntiBotWaf_GW_(?!${OLD//./\\.}\\b)"           "AntiBotWaf_GW_(?!${NEW//./\\.}\\b)"
replace tests/test_pure.py           "if found != \"${OLD}\""                  "if found != \"${NEW}\""

# ── Entry-point module docstring ───────────────────────────────────────────────
replace proxy.py                     "Anti-bot reverse proxy v${OLD}"           "Anti-bot reverse proxy v${NEW}"

# ── Docker Compose ─────────────────────────────────────────────────────────────
replace docker-compose.yml           "image: appsec-antibot-gw:${OLD}"          "image: appsec-antibot-gw:${NEW}"
replace docker-compose.yml           "container_name: appsec-antibot-gw${OLD}"  "container_name: appsec-antibot-gw${NEW}"

# ── Dashboard HTML files ───────────────────────────────────────────────────────
for f in dashboards/*.html; do
    replace "$f" "AntiBotWaf_GW_${OLD}"  "AntiBotWaf_GW_${NEW}"
    replace "$f" "sidebar-brand-ver\">${OLD}<" "sidebar-brand-ver\">${NEW}<"
done

# ── manual/README.md version ───────────────────────────────────────────────────
replace manual/README.md  "AntiBotWaf_GW/${OLD}"  "AntiBotWaf_GW/${NEW}"
replace manual/README.md  "appsec-antibot-gw:${OLD}"        "appsec-antibot-gw:${NEW}"
replace manual/README.md  "trivy image appsec-antibot-gw:${OLD}"  "trivy image appsec-antibot-gw:${NEW}"

# ── MANUAL.md header + image refs + expected-banner sample ─────────────────────
replace MANUAL.md  "**Version**: ${OLD}"                    "**Version**: ${NEW}"
replace MANUAL.md  "appsec-antibot-gw:${OLD}"               "appsec-antibot-gw:${NEW}"
replace MANUAL.md  "AntiBotWaf_GW_${OLD} listening"              "AntiBotWaf_GW_${NEW} listening"

# ── README.md expected-startup banner + docker-run container-name ──────────────
replace README.md  "AntiBotWaf_GW_${OLD} listening"              "AntiBotWaf_GW_${NEW} listening"
replace README.md  "--name appsec-antibot-gw${OLD}"         "--name appsec-antibot-gw${NEW}"

# ── README quickstart image references (not version-history rows) ──────────────
replace README.md  "appsec-antibot-gw:${OLD} (~ "          "appsec-antibot-gw:${NEW} (~ "
replace README.md  "appsec-antibot-gw:${OLD} \\"            "appsec-antibot-gw:${NEW} \\"
replace README.md  "appsec-antibot-gw:${OLD}\`"             "appsec-antibot-gw:${NEW}\`"
replace README.md  "appsec-antibot-gw:${OLD}
echo"                                               "appsec-antibot-gw:${NEW}
echo"
replace README.md  "appsec-antibot-gw:${OLD} ."             "appsec-antibot-gw:${NEW} ."
replace README.md  "trivy image appsec-antibot-gw:${OLD}"   "trivy image appsec-antibot-gw:${NEW}"

# ── geo-dashboard test version assertion ───────────────────────────────────────
replace tests/test_geo_dashboard.py  "AntiBotWaf_GW_${OLD}"  "AntiBotWaf_GW_${NEW}"

echo "Done. Verify with: grep -rn 'AntiBotWaf_GW_${OLD}\\|appsec-antibot-gw:${OLD}' --include='*.py' --include='*.html' --include='*.yml' --include='*.md'"

# ── Build-gate (1.9.0): refuse to consider the bump complete if the v18*/v19*
# regression suites have any failures. Catches the "edits got reverted by an
# external git op between editing and tagging" class of regression — the exact
# failure mode that nearly shipped 1.8.15 minus all its claimed features.
# Skip with BUMP_SKIP_TESTS=1 (only when tests will be re-run separately).
if [ "${BUMP_SKIP_TESTS:-0}" = "1" ]; then
    echo "BUMP_SKIP_TESTS=1 → skipping pytest gate (use with care)"
    exit 0
fi
echo
echo "── Build-gate: running v18*/v19* regression suites ─────────────────"
echo "    (set BUMP_SKIP_TESTS=1 to skip — only when running tests separately)"
GATE_OUT=$(python -m pytest tests/test_v18*.py tests/test_v19*.py \
                  --timeout=60 -q --tb=no 2>&1 | tail -5)
echo "$GATE_OUT"
if echo "$GATE_OUT" | grep -qE '[0-9]+ failed'; then
    echo
    echo "✗ Build-gate FAILED — regression suite has failures."
    echo "  Do NOT build images / tag / push until these are resolved."
    echo "  Re-run: python -m pytest tests/test_v18*.py tests/test_v19*.py -v"
    exit 2
fi
echo "✓ Build-gate passed — safe to build."
