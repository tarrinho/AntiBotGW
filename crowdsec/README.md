# CrowdSec daily-cache wrapper

A thin Docker image derived from `crowdsecurity/crowdsec:latest` that turns
`cscli hub update` / `cscli hub upgrade` from a *per-start* network operation
into a *per-day* one.

> **Attribution / licensing.** This image is a derivative work around the
> official `crowdsecurity/crowdsec` image, which is licensed under the
> [MIT License](https://github.com/crowdsecurity/crowdsec/blob/master/LICENSE).
> The `cscli-shim.sh` script bundled here is original and distributed under
> the AntiBotGW project's Apache-2.0 licence. This is **NOT an official
> CrowdSec release** and is not affiliated with or endorsed by CrowdSec SAS.
> Upstream project: <https://github.com/crowdsecurity/crowdsec>.

## Why

The official CrowdSec entrypoint runs `cscli hub update` on every container
start. With the named-volume mounts already in `docker-compose.yml`, the data
is on disk — but `cscli` still re-fetches the hub index plus any
recently-touched whitelist / blocklist files (e.g.
`whitelists/benign_bots/search_engine_crawlers/rdns_seo_bots.txt`) from
`https://hub-data.crowdsec.net/...` on every restart.

For an SEO-bot whitelist that changes at most weekly, this is wasted
bandwidth and slows container startup by 5–10 s.

## How it works

The shim intercepts only `cscli hub update` and `cscli hub upgrade`. Every
other subcommand passes through to the real binary unchanged.

1. Stamp file: `/var/lib/crowdsec/data/.hub_update_stamp`. Contains
   a single line — today's UTC date (`YYYY-MM-DD`).
2. On `cscli hub update|upgrade`:
   - If stamp's content equals today's date → log `[cscli-shim] skip …`
     and exit 0 without touching the network.
   - Otherwise run the real `cscli`. On success, update the stamp.
3. Background: no daemon. The official entrypoint naturally calls
   `cscli hub update` on every start; the shim is what decides whether that
   call hits the network or no-ops.
4. After midnight UTC, the next container start (or any internal `cscli hub
   update` invocation) sees a stale stamp → fresh fetch → new stamp.

## Files

- `cscli-shim.sh` — POSIX shell, ≤60 LOC, vendored into the image.
- `Dockerfile.crowdsec-cached` — single-stage derive-and-shim build.

## Build

```bash
# Local single-arch build (used by docker-compose):
docker build -f Dockerfile.crowdsec-cached -t crowdsec-cached:latest .

# Multi-arch matching upstream CrowdSec tags:
docker buildx build \
    --platform linux/amd64,linux/arm64,linux/arm/v7 \
    -f Dockerfile.crowdsec-cached \
    -t harbor.example.com/crowdsec-cached:1.0 --push .
```

## Use in docker-compose.yml

```yaml
crowdsec:
  build:
    context: ./crowdsec
    dockerfile: Dockerfile.crowdsec-cached
  image: crowdsec-cached:latest
  # … the rest of the service block stays identical to upstream …
  volumes:
    - crowdsec-data:/var/lib/crowdsec/data    # MUST be persistent for the stamp
    - crowdsec-config:/etc/crowdsec
```

The persistent `crowdsec-data` volume is required — without it the stamp
file lives in tmpfs and is destroyed by every `docker compose down`.

## Forcing a refresh

To force the next start to re-download (e.g. after manually installing a
new collection):

```bash
docker exec crowdsec rm -f /var/lib/crowdsec/data/.hub_update_stamp
docker compose restart crowdsec
```

## Verifying the shim is active

```bash
# Inside the container — the shim writes its own log lines to stderr:
docker exec crowdsec cscli hub update
# First call:  [cscli-shim] running 'cscli hub update' (last=…, today=…)
#              [cscli-shim] stamped 2026-06-02
# Second call: [cscli-shim] skip 'cscli hub update' — already done today (2026-06-02)

# Confirm the real binary is reachable:
docker exec crowdsec cscli version    # passthrough — runs real cscli
```

## Limitations / non-goals

- **Does not** schedule its own daily refresh. Relies on container restarts
  (most CrowdSec deployments restart on host reboot, or via the daily
  `cscli hub update` triggered by the agent itself).
- **Does not** rate-limit non-hub subcommands. `cscli decisions list`,
  `cscli bouncers add`, etc. pass through unchanged.
- **Does not** validate stamp content beyond exact date string match.
  Tampering with the stamp file is trivial — this is a cache, not a
  security control.
