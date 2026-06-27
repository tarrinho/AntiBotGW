"""
tests/test_v190_pg_only_banner.py — guard the one-shot operator banner
that fires when POSTGRES_DSN is freshly set on a deployment that still
has data in the local SQLite file.

The banner explains the new PG-only contract:
  • PG is now the sole backend
  • Local SQLite at DB_PATH is preserved but unused
  • `python -m db.import`  → migrate SQLite data into PG
  • `python -m db.export`  → back up PG into SQLite

After the banner has been shown once, a marker file is dropped so
restarts stay quiet. These tests anchor:
  • Banner is gated on POSTGRES_DSN being set
  • Banner text references both CLI tools (so operators can copy-paste)
  • Banner is gated on local SQLite having data (no spurious banner on
    fresh deploys)
  • Marker file path + suppression on second boot
  • Marker write is wrapped in try/except so read-only /data doesn't
    crash the gateway
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
PROXY = os.path.join(_REPO, "proxy.py")


def _src():
    return open(PROXY, encoding="utf-8").read()


# ── Banner exists + lives behind a POSTGRES_DSN gate ────────────────────

def test_banner_block_present_in_on_startup():
    src = _src()
    assert "[db-upgrade]" in src and "POSTGRES_DSN is now set" in src, (
        "proxy.on_startup must print a one-shot operator banner when "
        "POSTGRES_DSN is freshly set on a populated SQLite deployment"
    )


def test_banner_gated_on_postgres_dsn_set():
    """The block must sit inside the `if POSTGRES_DSN:` gate so empty-DSN
    deployments never see the banner."""
    src = _src()
    pg_gate_idx = src.find("if POSTGRES_DSN:")
    banner_idx  = src.find("[db-upgrade]")
    assert pg_gate_idx != -1, "if POSTGRES_DSN: gate not found"
    assert banner_idx != -1, "banner not found"
    assert pg_gate_idx < banner_idx, (
        "banner must be INSIDE the `if POSTGRES_DSN:` block — otherwise "
        "it fires on SQLite-only deployments"
    )


# ── Banner content ──────────────────────────────────────────────────────

def test_banner_references_db_import_cli():
    src = _src()
    # Match the canonical CLI form so operators can copy-paste.
    assert "python -m db.import" in src, (
        "banner must reference `python -m db.import` so operators know "
        "how to migrate SQLite → PG"
    )


def test_banner_references_db_export_cli():
    src = _src()
    assert "python -m db.export" in src, (
        "banner must reference `python -m db.export` so operators know "
        "how to back PG up to SQLite"
    )


def test_banner_warns_local_sqlite_is_preserved_but_unused():
    """Operator must understand SQLite isn't deleted — it's just dormant
    under PG-only mode. Wording-flexible match on the key concept."""
    src = _src()
    blk_start = src.find("[db-upgrade]")
    block = src[blk_start: blk_start + 1200]
    # Must mention 'preserved' and 'unused' (or 'inactive') in the same
    # block — orders the operator's mental model: PG primary, SQLite idle.
    assert "preserved" in block.lower(), (
        "banner must say the local SQLite is preserved (not deleted)"
    )
    assert "unused" in block.lower() or "inactive" in block.lower(), (
        "banner must say the local SQLite is unused under PG-only mode"
    )


def test_banner_only_fires_when_local_sqlite_has_data():
    """Avoid spurious banners on fresh deploys. The block must condition
    on a non-zero row count from at least one user-data table."""
    src = _src()
    # Quick smell test: SELECT COUNT(*) from a real table appears near the
    # banner gate.
    blk_start = src.find("[db-upgrade]")
    # Look in the ~2KB region BEFORE the print() to find the guard.
    pre_block = src[max(0, blk_start - 2000): blk_start]
    assert "SELECT COUNT(*)" in pre_block, (
        "banner block must inspect SQLite row counts before printing — "
        "no row → no banner"
    )
    # The conditional must check that at least one count is positive.
    assert re.search(r">\s*0", pre_block) or "users > 0" in pre_block.lower() \
        or "events > 0" in pre_block.lower(), (
        "banner gate must require non-zero user-data rows in the local SQLite"
    )


# ── Marker file: one-shot semantics ────────────────────────────────────

def test_marker_file_dropped_to_suppress_future_banners():
    src = _src()
    # Marker write — `with open(_marker, "w")` or similar.
    blk_start = src.find("[db-upgrade]")
    block = src[blk_start: blk_start + 1500]
    assert "open(_marker" in block or "open(marker" in block.lower(), (
        "after printing, the banner block must drop a marker file so "
        "subsequent restarts stay quiet"
    )


def test_marker_check_precedes_banner_print():
    """The marker existence test must run BEFORE the print() — otherwise
    the banner fires every restart even after the marker exists."""
    src = _src()
    # _marker assignment + existence check should both appear before [db-upgrade].
    marker_idx = src.find("_marker")
    banner_idx = src.find("[db-upgrade]")
    assert marker_idx != -1, "_marker not declared"
    assert banner_idx != -1
    assert marker_idx < banner_idx, (
        "_marker variable must be set BEFORE the banner-print branch"
    )


def test_marker_write_is_oserror_safe():
    """The marker write must tolerate OSError (read-only /data, permission
    issue) — otherwise a banner-print path crashes the gateway boot."""
    src = _src()
    blk_start = src.find("[db-upgrade]")
    block = src[blk_start: blk_start + 1500]
    # Either a specific OSError except or a bare 'except Exception' with
    # the # nosec marker (existing pattern in the file).
    assert ("except OSError" in block
            or "except Exception" in block
            or "except:" in block), (
        "marker-write must be wrapped in try/except so an unwritable "
        "/data doesn't crash the gateway"
    )


# ── Banner is suppressed on subsequent boots ───────────────────────────

def test_banner_skipped_when_marker_present():
    """A presence check on _marker MUST gate the entire banner block —
    not just the marker-write. Otherwise the banner re-prints every boot
    even though the marker is already there."""
    src = _src()
    # Find the banner block and look upward for an `os.path.exists(_marker)`
    # or `if not _marker_present:` style guard.
    blk_start = src.find("[db-upgrade]")
    pre_block = src[max(0, blk_start - 3000): blk_start]
    # Must contain a marker existence test before the banner.
    assert ("os.path.exists(_marker)" in pre_block
            or "_marker.exists" in pre_block
            or "Path(_marker).exists()" in pre_block), (
        "banner block must check os.path.exists(_marker) — subsequent boots "
        "with the marker present must NOT re-print"
    )
