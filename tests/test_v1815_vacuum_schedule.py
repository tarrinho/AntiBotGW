"""
1.8.15 — daily scheduled VACUUM.

Behaviour:
  * VACUUM_DAILY_AT config knob ("HH:MM" 24-h, "" disables).
  * Default "05:00" — runs at 5 AM container local time.
  * Hot-reloadable (validated to HH:MM range).
  * Background task spawned at startup.
  * Skips (and slog's) when migration is running, manual VACUUM is in flight,
    or backend != sqlite.
  * Runs through _DB_VACUUM_LOCK (same single-flight gate as manual click).
  * Audit row uses actor='scheduler'.

Coverage:
  TestVacuumScheduleSourceGuards   — config + knob + spawn + loop guards
  TestVacuumScheduleTiming         — _next_vacuum_secs returns sensible values
"""
import pathlib


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_CFG_SRC  = (_ROOT / "config.py").read_text(encoding="utf-8")
_PXY_SRC  = (_ROOT / "proxy.py").read_text(encoding="utf-8")
_CTL_SRC  = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")


# ── 1. Source guards ────────────────────────────────────────────────────────

class TestVacuumScheduleSourceGuards:

    def test_config_knob_defined(self):
        assert 'VACUUM_DAILY_AT = os.environ.get("VACUUM_DAILY_AT"' in _CFG_SRC, (
            "VACUUM_DAILY_AT must be declared in config.py"
        )

    def test_config_default_5am(self):
        idx = _CFG_SRC.find("VACUUM_DAILY_AT")
        block = _CFG_SRC[idx: idx + 200]
        assert '"05:00"' in block, (
            "Default schedule must be 05:00"
        )

    def test_in_hot_reload_knobs(self):
        idx = _PH_SRC.find('"VACUUM_DAILY_AT"')
        assert idx != -1, "VACUUM_DAILY_AT missing from _HOT_RELOAD_KNOBS"
        block = _PH_SRC[idx: idx + 250]
        # Validator must accept empty string AND HH:MM with range checks
        assert 'v == ""' in block or "v=='':\n" in block, (
            "validator must accept empty string (disabled)"
        )
        assert "24" in block and "60" in block, (
            "validator must range-check HH:MM"
        )

    def test_scheduler_loop_exists(self):
        assert "async def _vacuum_scheduler_loop(" in _PH_SRC, (
            "Background loop _vacuum_scheduler_loop must exist"
        )

    def test_scheduler_uses_lock(self):
        idx = _PH_SRC.find("async def _vacuum_scheduler_loop(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_DB_VACUUM_LOCK" in block, (
            "scheduler must use _DB_VACUUM_LOCK (same gate as manual)"
        )

    def test_scheduler_checks_migration(self):
        idx = _PH_SRC.find("async def _vacuum_scheduler_loop(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_BG_MIGRATION" in block, (
            "scheduler must skip when migration is running"
        )

    def test_scheduler_skip_when_not_sqlite(self):
        idx = _PH_SRC.find("async def _vacuum_scheduler_loop(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert 'DB_BACKEND != "sqlite"' in block, (
            "scheduler must skip when active backend is not sqlite"
        )

    def test_scheduler_actor_is_scheduler(self):
        idx = _PH_SRC.find("async def _vacuum_scheduler_loop(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert 'actor="scheduler"' in block, (
            "scheduler must pass actor='scheduler' so audit rows are distinguishable"
        )

    def test_scheduler_spawned_at_startup(self):
        assert "_vacuum_scheduler_loop" in _PXY_SRC, (
            "proxy.py must spawn _vacuum_scheduler_loop in on_startup"
        )
        idx = _PXY_SRC.find("_vacuum_scheduler_loop")
        ctx = _PXY_SRC[max(0, idx - 200): idx + 50]
        assert "asyncio.create_task" in ctx, (
            "scheduler must be spawned via asyncio.create_task"
        )

    def test_ui_knob_registered(self):
        assert "VACUUM_DAILY_AT" in _CTL_SRC, (
            "controls.html knob registry must include VACUUM_DAILY_AT"
        )
        idx = _CTL_SRC.find("VACUUM_DAILY_AT:")
        block = _CTL_SRC[idx: idx + 400]
        assert "kind:'str'" in block or 'kind: "str"' in block, (
            "VACUUM_DAILY_AT must render as a string knob (HH:MM)"
        )


# ── 2. Timing helper ────────────────────────────────────────────────────────

class TestVacuumScheduleTiming:

    def test_disabled_returns_none(self):
        import sys
        sys.path.insert(0, str(_ROOT))
        import core.proxy_handler as _cph
        assert _cph._next_vacuum_secs("") is None
        assert _cph._next_vacuum_secs(None) is None

    def test_malformed_returns_none(self):
        import sys
        sys.path.insert(0, str(_ROOT))
        import core.proxy_handler as _cph
        for bad in ("xx", "25:00", "10:60", "10", "5:5:5", "abc:def"):
            assert _cph._next_vacuum_secs(bad) is None, (
                f"{bad!r} must be rejected"
            )

    def test_valid_returns_positive(self):
        import sys
        sys.path.insert(0, str(_ROOT))
        import core.proxy_handler as _cph
        # Both 05:00 and 23:59 must compute >0 seconds until next occurrence
        for at in ("05:00", "23:59", "00:00", "12:30"):
            secs = _cph._next_vacuum_secs(at)
            assert secs is not None and 0 < secs <= 24 * 3600 + 60, (
                f"{at}: expected 0 < secs <= 86400; got {secs}"
            )

    def test_past_time_rolls_to_next_day(self):
        """If HH:MM has already passed today, secs must be < 24h (next-day occurrence)."""
        import sys, datetime as _dt
        sys.path.insert(0, str(_ROOT))
        import core.proxy_handler as _cph
        now = _dt.datetime.now()
        # Pick an HH:MM that's definitely already passed today (1 minute earlier).
        past = (now - _dt.timedelta(minutes=1))
        at = f"{past.hour:02d}:{past.minute:02d}"
        secs = _cph._next_vacuum_secs(at)
        assert secs is not None, "must return a value for valid HH:MM"
        # Must be tomorrow (>~23.9h) — not today's elapsed window.
        assert secs > 23 * 3600, (
            f"past-time {at} must roll to tomorrow; got {secs}s"
        )
