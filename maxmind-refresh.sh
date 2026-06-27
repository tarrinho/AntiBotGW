#!/bin/bash
# AntiBot/WAF GW — monthly refresh of MaxMind GeoLite2-ASN database.
# Install in cron:   0 5 1 * *   /path/to/maxmind-refresh.sh >> /var/log/maxmind-refresh.log 2>&1
#
# Reads MAXMIND_LICENSE_KEY from /etc/appsecgw/maxmind.env (mode 0600) so
# the key never leaks into ps/cron logs:
#   echo 'MAXMIND_LICENSE_KEY=<your-key>' > /etc/appsecgw/maxmind.env
#   chmod 600 /etc/appsecgw/maxmind.env
set -euo pipefail

ENV_FILE="${MAXMIND_ENV_FILE:-/etc/appsecgw/maxmind.env}"
VOLUME="${ANTIBOT_VOLUME:-antibot-data}"
CONTAINER="${ANTIBOT_CONTAINER:-appsec-antibot-gw1.6.5}"

# Prefer an already-exported MAXMIND_LICENSE_KEY (e.g. from systemd
# EnvironmentFile= / shell rc / docker --env-file). Fall back to the canonical
# /etc/appsecgw/maxmind.env file so cron continues to work without further setup.
if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
  if [[ -r "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
  fi
fi
: "${MAXMIND_LICENSE_KEY:?MAXMIND_LICENSE_KEY env var must be set, or $ENV_FILE must contain it}"

TMPDIR=$(mktemp -d -t maxmind-XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR"

fetch_db() {
  local edition="$1" outfile="$2"
  echo "[$(date -u +%FT%TZ)] downloading ${edition}…"
  HTTP_CODE=$(curl -L -sS -o "${outfile}.tar.gz" -w '%{http_code}' \
    "https://download.maxmind.com/app/geoip_download?edition_id=${edition}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz")
  if [[ "$HTTP_CODE" != "200" ]]; then
    echo "[$(date -u +%FT%TZ)] ERROR: ${edition} returned HTTP $HTTP_CODE" >&2
    head -c 500 "${outfile}.tar.gz" >&2; echo >&2
    return 3
  fi
  tar xzf "${outfile}.tar.gz"
  local mmdb
  mmdb=$(find . -name "${edition}.mmdb" | head -1)
  [[ -n "$mmdb" ]] || { echo "[$(date -u +%FT%TZ)] ERROR: ${edition}.mmdb not in archive" >&2; return 4; }
  local size; size=$(stat -c%s "$mmdb")
  echo "[$(date -u +%FT%TZ)] extracted ${size} bytes from $mmdb"
  docker run --rm \
    -v "${VOLUME}":/data \
    -v "${TMPDIR}/${mmdb#./}":/in/db.mmdb:ro \
    --user root \
    busybox sh -c "cp /in/db.mmdb /data/${edition}.mmdb && chown 65532:65532 /data/${edition}.mmdb"
}

# 1.5.4: refresh both ASN (used for hosting-provider tagging) and City
# (used for the geo-map dashboard). City DB is only ~65 MB.
fetch_db GeoLite2-ASN  asn  || exit $?
fetch_db GeoLite2-City city || exit $?

# Restart container so the new mmdbs are reloaded by _init_maxmind()
docker restart "${CONTAINER}" > /dev/null
echo "[$(date -u +%FT%TZ)] DONE — ${CONTAINER} restarted"
