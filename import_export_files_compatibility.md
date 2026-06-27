# Import / Export & Configuration Files — Compatibility Table

**Current release:** 1.7.12  
**Last updated:** 2026-05-11

---

## 1. Settings Export/Import (ZIP + XML)

### Format

| Item | Value |
|------|-------|
| Endpoint (export) | `GET /__settings-export?include_secrets=0\|1` |
| Endpoint (import) | `POST /__settings-import?dry_run=0\|1&overwrite_secrets=0\|1` |
| Container format | `.zip` (single entry: `appsecgw-config.xml`) |
| Filename pattern | `appsecgw-config-{host}-{timestamp}.zip` |
| Max inflated size | 4 MiB (ZIP-bomb protection) |
| Introduced | 1.6.5 |

### XML Schema (`appsecgw-config.xml`)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<appsecgw-config version="1.6.5" exported_at="{unix_ts}">
  <knobs>
    <knob name="KEY" type="TYPE">JSON_ENCODED_VALUE</knob>
  </knobs>
  <admin_ips>
    <admin_ip cidr="CIDR" note="STR" source="manual" description="STR" added_ts="TS"/>
  </admin_ips>
  <secrets>                      <!-- only present if include_secrets=1 -->
    <secret name="ABUSEIPDB_KEY">VALUE</secret>
  </secrets>
</appsecgw-config>
```

### Version Compatibility

| Exported from | Import into 1.6.5 | Import into 1.6.6 | Import into 1.6.7 | Import into 1.7.x |
|---------------|:-----------------:|:-----------------:|:-----------------:|:-----------------:|
| 1.6.5         | ✓ native          | ✓ full            | ✓ full            | ✓ full            |
| 1.6.6         | ✓ (skips unknown knobs) | ✓ native   | ✓ full            | ✓ full            |
| 1.6.7         | ✓ (skips unknown knobs) | ✓ (skips unknown knobs) | ✓ native | ✓ full   |
| 1.7.x         | ✓ (skips unknown knobs) | ✓ (skips unknown knobs) | ✓ (skips unknown knobs) | ✓ native |

> **Rule:** Unknown `<knob>` names are rejected (counted in `knobs_rejected`), not fatal. Older releases accept exports from newer ones with partial application.

### Import Response Schema

```json
{
  "dry_run": false,
  "overwrite_secrets": false,
  "knobs_applied": 12,
  "knobs_rejected": 0,
  "admin_ips_added": 2,
  "secrets_applied": 0,
  "applied": ["RISK_BAN_THRESHOLD", "..."],
  "rejected": {},
  "errors": []
}
```

---

## 2. Logs Export (CSV)

| Item | Value |
|------|-------|
| Endpoint | `GET /__logs-export` |
| Format | RFC 4180 CSV (quoted, comma-separated) |
| Filename | `appsecgw_events.csv` |
| Row cap | 100 000 rows |
| Introduced | 1.5.4 |

### Columns

| # | Column | Type | Notes |
|---|--------|------|-------|
| 1 | `id` | INTEGER | SQLite rowid |
| 2 | `ts` | REAL | Unix epoch (float) |
| 3 | `iso_ts` | TEXT | ISO 8601 UTC |
| 4 | `ip` | TEXT | Client IP |
| 5 | `ua` | TEXT | User-Agent |
| 6 | `path` | TEXT | Request path |
| 7 | `status` | INTEGER | HTTP response code |
| 8 | `reason` | TEXT | Block/allow reason |
| 9 | `method` | TEXT | HTTP method — **added 1.6.0** |
| 10 | `ip_type` | TEXT | `residential`/`datacenter`/`tor` — **added 1.6.2** |

### Query Parameters

| Param | Values | Default |
|-------|--------|---------|
| `level` | `debug`, `info`, `warn`, `error` | all |
| `method` | `all`, `POST`, `GET`, … | `all` |
| `ip_type` | `all`, `residential`, `dc`, `tor` | `all` |
| `q` | free-text search (ip / ua / path) | — |
| `limit` | integer (max 100 000) | 10 000 |

### Column Availability by Release

| Column | ≤1.5.x | 1.6.0 | 1.6.2+ |
|--------|:------:|:-----:|:------:|
| id, ts, iso_ts, ip, ua, path, status, reason | ✓ | ✓ | ✓ |
| method | — | ✓ | ✓ |
| ip_type | — | — | ✓ |

---

## 3. Environment Variables (`.env` / `.env.example`)

### Compatibility by Feature Tier

| Env Var Group | Format | Introduced | Required |
|---------------|--------|-----------|----------|
| `UPSTREAM` | URL string | 1.4.x | Yes |
| `AUTHORIZED_BOT_UAS` | JSON array **or** legacy CSV `UA:path` pairs | 1.4.x (CSV) / 1.5.5 (JSON) | No |
| `ENDPOINT_POLICIES` | JSON array of `{path, policy, rps, burst}` | 1.6.0 | No |
| `CUSTOM_RULES` | JSON array of `{if, then}` objects | 1.6.1 | No |
| `JWT_VALIDATE_PATHS` / `JWT_HMAC_SECRET` | CSV paths + string | 1.6.1 | No |
| `COUNTRY_BLOCK_ENABLED` / `COUNTRY_DENYLIST` | `0`/`1` + CSV ISO-3166-1 alpha-2 | 1.6.0 | No |
| `DLP_ENABLED` / `DLP_GROUP_*` | `0`/`1` + CSV regex groups | 1.6.2 | No |
| `WEBHOOK_URL` / `WEBHOOK_SECRET` / `WEBHOOK_EVENT_FILTER` | URL + secret + CSV glob patterns | 1.6.2 | No |
| `DB_BACKEND` / `POSTGRES_*` | `sqlite`\|`postgres` + credentials | 1.6.4 | No |
| `REDIS_URL` / `REDIS_PASSWORD` | URL + string | 1.6.8 | No |
| `CROWDSEC_LAPI_KEY` / `CROWDSEC_LAPI_URL` | string + URL | 1.6.8 | No |
| `AI_UA_*_ENABLED` | `0`/`1` per crawler | 1.6.0 | No |
| `APPSECGW_KEY_DIR` | path | 1.6.7 | No |

### `AUTHORIZED_BOT_UAS` Migration

Both formats are accepted indefinitely; the parser auto-detects on load.

```bash
# Legacy CSV (≤1.5.4)
AUTHORIZED_BOT_UAS=Googlebot:robots.txt,Bingbot:robots.txt

# Current JSON (1.5.5+)
AUTHORIZED_BOT_UAS=["Googlebot", "Bingbot"]
```

---

## 4. Hot-Reload Knobs (`config_kv` table / `POST /__config`)

| Item | Value |
|------|-------|
| Storage | `config_kv` SQLite table (persists across restarts) |
| Introduced | 1.5.5 |
| Precedence | Env var overrides `config_kv` at boot (env wins) |
| Transport | JSON (`{KEY: VALUE}` — value is JSON-encoded) |

Knob names are stable across releases. Unknown knobs are rejected. Knobs added in newer releases are silently absent from older config_kv tables and fall back to their coded defaults.

---

## 5. SQLite Database Schema

### Schema Evolution

| Migration | Column Added | Table | Introduced |
|-----------|-------------|-------|-----------|
| 001 | `description` | `admin_ips` | 1.5.3 |
| 002 | `missed` | `timeline` | 1.5.4 |
| 003 | `config_kv` table (new) | — | 1.5.5 |
| 004 | `secrets_kv` table (new) | — | 1.5.5 |
| 005 | `abuseipdb_cache` table (new) | — | 1.5.5 |
| 006 | `svc_metrics` table (new) | — | 1.6.5 |
| 007 | `pg_*` columns | `svc_metrics` | 1.6.5 |
| 008 | `gw_registry` table (new) | — | 1.6.7 |
| 009 | `domain`, `auto_apply` | `gw_registry` | 1.6.7 |

All migrations are idempotent (`ALTER TABLE … ADD COLUMN IF NOT EXISTS`) and applied at boot. Never remove entries from `_SCHEMA_MIGRATIONS`.

### Backend Compatibility

| Feature | SQLite | PostgreSQL (TimescaleDB) |
|---------|:------:|:------------------------:|
| `events` table | ✓ | ✓ (hypertable) |
| `admin_ips` | ✓ | ✓ |
| `config_kv` | ✓ | ✓ |
| `secrets_kv` | ✓ | ✓ |
| `gw_registry` | ✓ | ✓ |
| `timeline` | ✓ | — (SQLite only) |
| `svc_metrics` | ✓ | — (SQLite only) |
| `abuseipdb_cache` | ✓ | — (SQLite only) |

> **No automatic data migration** when switching `DB_BACKEND`. Old events remain in the previous store.

---

## 6. Cryptographic Key Files

| File | Format | Location | Rotation |
|------|--------|----------|----------|
| `.admin_key` | Hex string (20 URL-safe chars) | `/data/.admin_key` (or `APPSECGW_KEY_DIR`) | Generated once at first boot |
| `.pow_key` | Hex string (64 chars) | `/data/.pow_key` | Generated once; survives restart (in-flight challenges remain valid) |
| `.session_key` | Hex string (64 chars) | `/data/.session_key` | Generated once; survives restart (active sessions remain valid) |

Mount `/data` as a persistent volume. Deleting key files forces regeneration and **invalidates all active sessions and in-flight PoW challenges**.

---

## 7. MaxMind GeoLite2 Data Files

| File | Format | Location | Update Cadence |
|------|--------|----------|---------------|
| `GeoLite2-ASN.mmdb` | MaxMind MMDB binary | `/data/GeoLite2-ASN.mmdb` | Weekly auto-fetch when `MAXMIND_LICENSE_KEY` set |
| `GeoLite2-City.mmdb` | MaxMind MMDB binary | `/data/GeoLite2-City.mmdb` | Weekly auto-fetch |

Bundled snapshots shipped in image at `/usr/local/share/maxmind/` — copied to `/data` on first boot. No license key required for bundled snapshots.

---

## 8. SBOM Files

| File | Format | Scope |
|------|--------|-------|
| `sbom/sbom-1.5.5.cdx.json` | CycloneDX 1.6 JSON | Container image 1.5.5 |
| `sbom/sbom-1.5.4.cdx.json` | CycloneDX 1.6 JSON | Container image 1.5.4 |

---

## 9. Webhook Event Payload

**Content-Type:** `application/json`  
**Introduced:** 1.6.0  
**Signature header:** `X-AntiBot/WAF GW-Signature: <HMAC-SHA256 hex>` (when `WEBHOOK_SECRET` set)

```json
{
  "ts":          1234567890.123,
  "ip":          "1.2.3.4",
  "reason":      "honeypot",
  "risk_score":  87.5,
  "session":     "abc123...",
  "fingerprint": "xyz789...",
  "status":      403,
  "path":        "/admin",
  "ua":          "Mozilla/5.0...",
  "method":      "POST"
}
```

---

## 10. Summary: Introduced-In Reference

| Format / File | Introduced | Still supported |
|---------------|-----------|:---------------:|
| SQLite `events` schema (base) | 1.4.x | ✓ |
| `.env` / env-var config | 1.4.x | ✓ |
| AUTHORIZED_BOT_UAS CSV | 1.4.x | ✓ (auto-migrated) |
| AUTHORIZED_BOT_UAS JSON | 1.5.5 | ✓ |
| `timeline.missed` column | 1.5.4 | ✓ |
| Logs CSV export | 1.5.4 | ✓ |
| `config_kv` / `secrets_kv` tables | 1.5.5 | ✓ |
| Settings ZIP+XML export/import | 1.6.5 | ✓ |
| Settings import dry-run | 1.6.6 | ✓ |
| PostgreSQL backend | 1.6.4 | ✓ |
| `svc_metrics` table | 1.6.5 | ✓ |
| `gw_registry` table | 1.6.7 | ✓ |
| Redis mesh-sync | 1.6.8 | ✓ |
| CrowdSec LAPI bouncer | 1.6.8 | ✓ |
| MaxMind MMDB (bundled) | 1.5.5 | ✓ |
| GeoLite2 auto-fetch | 1.6.5 | ✓ |
| SBOM (CycloneDX) | 1.5.4 | ✓ |
| Webhook JSON events | 1.6.0 | ✓ |
