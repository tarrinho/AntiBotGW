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
replace config.py                    "AppSecGW_${OLD}"          "AppSecGW_${NEW}"

# ── Test version constant + stale-string guard ─────────────────────────────────
replace tests/test_pure.py           "_EXPECTED_VERSION = \"AppSecGW_${OLD}\"" "_EXPECTED_VERSION = \"AppSecGW_${NEW}\""
replace tests/test_pure.py           "AppSecGW_(?!${OLD//./\\.}\\b)"           "AppSecGW_(?!${NEW//./\\.}\\b)"

# ── Entry-point module docstring ───────────────────────────────────────────────
replace proxy.py                     "Anti-bot reverse proxy v${OLD}"           "Anti-bot reverse proxy v${NEW}"

# ── Docker Compose ─────────────────────────────────────────────────────────────
replace docker-compose.yml           "image: appsec-antibot-gw:${OLD}"          "image: appsec-antibot-gw:${NEW}"
replace docker-compose.yml           "container_name: appsec-antibot-gw${OLD}"  "container_name: appsec-antibot-gw${NEW}"

# ── Dashboard HTML files ───────────────────────────────────────────────────────
for f in dashboards/*.html; do
    replace "$f" "AppSecGW_${OLD}"  "AppSecGW_${NEW}"
done

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
replace tests/test_geo_dashboard.py  "AppSecGW_${OLD}"  "AppSecGW_${NEW}"

echo "Done. Verify with: grep -rn 'AppSecGW_${OLD}\\|appsec-antibot-gw:${OLD}' --include='*.py' --include='*.html' --include='*.yml' --include='*.md'"
