#!/usr/bin/env bash
# myip.sh — detect operator public IP and (re)launch the gateway with
# ADMIN_ALLOWED_IPS pinned to that IP. Preserves UPSTREAM, ALLOWED_HOSTS,
# the named volume, and all hardening flags.
#
# Usage:
#   ./myip.sh                                # show detected IP only
#   ./myip.sh --apply                        # recreate the container
#   ./myip.sh --apply --extra "10.0.0.0/8"   # add extra CIDRs to the allowlist
#
# Env overrides:
#   IMAGE          = full image reference  (default: appsec-antibot-gw:1.2)
#   CONTAINER      = container name        (default: appsec-antibot-gw1.2)
#   PORT           = host port to bind     (default: 8443)
#   VOLUME         = named volume          (default: antibot-data)
#   UPSTREAM       = upstream URL          (REQUIRED on --apply)
#   ALLOWED_HOSTS  = Host header allowlist (REQUIRED on --apply)
#   ADMIN_KEY      = admin key (set if you don't want one auto-generated)

set -euo pipefail

IMAGE="${IMAGE:-appsec-antibot-gw:1.2}"
CONTAINER="${CONTAINER:-appsec-antibot-gw1.2}"
PORT="${PORT:-8443}"
VOLUME="${VOLUME:-antibot-data}"
EXTRA_IPS=""
APPLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)  APPLY=1; shift ;;
    --extra)  EXTRA_IPS="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

# ── 1. Detect public IP — multi-provider fallback, fail closed ────────────
detect_public_ip() {
  local ip
  for url in \
      "https://api.ipify.org" \
      "https://ifconfig.me/ip" \
      "https://ipinfo.io/ip" \
      "https://icanhazip.com" ; do
    ip="$(curl -s --max-time 4 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    # Validate IPv4 / IPv6 syntactically
    if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] \
        || [[ "$ip" =~ ^[0-9a-fA-F:]+$ && "$ip" == *:* ]]; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

MY_IP="$(detect_public_ip)" || { echo "ERROR: could not detect public IP from any provider"; exit 3; }

# ── 2. Build the allowlist string ─────────────────────────────────────────
# / format: single IPs become /32 (IPv4) or /128 (IPv6) automatically inside
# the gateway, but listing them explicitly is fine.
ADMIN_ALLOWED_IPS="${MY_IP},127.0.0.1"
if [[ -n "$EXTRA_IPS" ]]; then
  ADMIN_ALLOWED_IPS="${ADMIN_ALLOWED_IPS},${EXTRA_IPS}"
fi

echo "Detected public IP : $MY_IP"
echo "Admin allowlist    : $ADMIN_ALLOWED_IPS"
echo "Container          : $CONTAINER"
echo "Image              : $IMAGE"

if [[ "$APPLY" -eq 0 ]]; then
  echo
  echo "(dry-run — pass --apply to (re)launch the container)"
  exit 0
fi

# ── 3. Validate required env for --apply ──────────────────────────────────
: "${UPSTREAM:?UPSTREAM env var must be set when --apply is used}"
: "${ALLOWED_HOSTS:?ALLOWED_HOSTS env var must be set when --apply is used}"

# Auto-generate ADMIN_KEY if operator did not supply one.
if [[ -z "${ADMIN_KEY:-}" ]]; then
  ADMIN_KEY="$(openssl rand -base64 24)"
  echo "ADMIN_KEY (generated): $ADMIN_KEY"
fi

# ── 4. Recreate the container ─────────────────────────────────────────────
if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "stopping + removing existing $CONTAINER..."
  docker stop "$CONTAINER" >/dev/null
  docker rm   "$CONTAINER" >/dev/null
fi

docker volume create "$VOLUME" >/dev/null

docker run -d --name "$CONTAINER" \
  --restart unless-stopped \
  --read-only --tmpfs /tmp:size=16m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 200 --memory 256m --cpus 1.0 \
  -p "${PORT}:8443" \
  -e UPSTREAM="$UPSTREAM" \
  -e ALLOWED_HOSTS="$ALLOWED_HOSTS" \
  -e ADMIN_ALLOWED_IPS="$ADMIN_ALLOWED_IPS" \
  -e ADMIN_KEY="$ADMIN_KEY" \
  -e TRUST_XFF=last \
  -v "${VOLUME}:/data" \
  "$IMAGE" >/dev/null

sleep 2
echo
docker ps --filter "name=^${CONTAINER}\$" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo
echo "Live probe:"
curl -s --max-time 4 "http://127.0.0.1:${PORT}/__live" || echo "(no response on /__live)"
echo
echo "Dashboard URL:"
echo "  http://127.0.0.1:${PORT}/__dashboard?key=${ADMIN_KEY}"
