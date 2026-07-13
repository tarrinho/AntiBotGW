#!/bin/sh
# cscli-shim.sh — wraps the official `cscli` binary so that hub update /
# hub upgrade calls are run at most once per UTC day. Subsequent calls in the
# same day exit 0 immediately without downloading anything.
#
# Persists the day-stamp under /var/lib/crowdsec/data/.hub_update_stamp.
# That dir is the named volume `crowdsec-data` in docker-compose.yml, so the
# stamp survives container restarts and only "yesterday" triggers a fresh
# download on tomorrow's first start.
#
# Why this exists: the official crowdsecurity/crowdsec entrypoint runs
# `cscli hub update` on every container start. Each restart re-downloaded
# `rdns_seo_bots.txt`, `ip_seo_bots.txt`, `rnds_seo_bots.regex` from
# https://hub-data.crowdsec.net/whitelists/... — wasting bandwidth and
# polluting the container's first 10s of logs. This shim turns the per-start
# cost into a per-day cost.
#
# To force a refresh (e.g. after a manual collection install): delete the
# stamp file:   rm /var/lib/crowdsec/data/.hub_update_stamp

set -eu

# Real cscli (moved aside by the Dockerfile during image build).
: "${CSCLI_REAL:=/usr/local/bin/cscli.real}"
STAMP=/var/lib/crowdsec/data/.hub_update_stamp
TODAY="$(date -u +%Y-%m-%d)"

# Only intercept `hub update` / `hub upgrade`. Every other subcommand
# (status, decisions, lapi, collections, …) passes through unchanged.
if [ "${1:-}" = "hub" ] && { [ "${2:-}" = "update" ] || [ "${2:-}" = "upgrade" ]; }; then
    LAST=""
    if [ -f "$STAMP" ]; then
        LAST="$(cat "$STAMP" 2>/dev/null || echo "")"
    fi

    if [ "$LAST" = "$TODAY" ]; then
        echo "[cscli-shim] skip 'cscli $1 $2' — already done today ($TODAY)" >&2
        exit 0
    fi

    echo "[cscli-shim] running 'cscli $1 $2' (last=${LAST:-never}, today=$TODAY)" >&2
    if "$CSCLI_REAL" "$@"; then
        # Stamp ONLY after a successful update — a failed download must not
        # poison the stamp and cause us to skip retry on the next restart.
        mkdir -p "$(dirname "$STAMP")"
        printf '%s\n' "$TODAY" > "$STAMP"
        echo "[cscli-shim] stamped $TODAY" >&2
        exit 0
    else
        rc=$?
        echo "[cscli-shim] 'cscli $1 $2' failed rc=$rc — stamp NOT updated" >&2
        exit "$rc"
    fi
fi

# Default path: invoke the real cscli verbatim.
exec "$CSCLI_REAL" "$@"
