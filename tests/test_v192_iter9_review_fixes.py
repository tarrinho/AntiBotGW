"""
1.9.1 iter-9 — code-review follow-up fixes.

Full iter-4 → iter-8 functional review surfaced three actionable issues:

  HIGH-1 — TRUSTED_PROXIES / TRUST_XFF / ADMIN_ALLOWED_IPS hot-reloadable
           from config_kv. An attacker with config_kv write access
           (admin auth bypass / SQL injection) could escalate to
           persistent IP spoofing by adding their own /32 to
           TRUSTED_PROXIES or flipping TRUST_XFF to 'last'. The next
           request would land with attacker-controlled `get_ip(request)`
           and EVERY IP-gated check (admin allowlist, country block,
           AbuseIPDB, ban-by-IP) would silently fail open.

           Fix: add `_DB_LOAD_DENY` frozenset to core/proxy_handler.py
           listing the trust-topology knobs; `db_load_config` refuses
           to apply any key in this set + emits
           `config_kv_security_knob_refused` warn. These knobs MUST be
           set via env at deploy time.

  MED-1 — `_to_ip_net_list` (integrations/endpoint_policy.py) silently
          dropped invalid CIDR entries. An operator setting
          `TRUSTED_PROXIES=10.0.0.0/33` (typo: should be /32) got an
          empty list with no log. Fix: emit `ip_net_list_rejected_entry`
          warn per dropped entry with the bad value + parser error.

  MED-2 — legacy DSN lift (iter-7) used `json.loads()` with
          `except: pass` fallback. A partially-corrupted legacy row
          (e.g. unterminated JSON) fell through and got encrypted as
          garbage. Operator's PG-init then failed silently on next
          boot. Fix: validate the lifted value parses as a
          postgres:// URL before encrypting + persisting.

  Verified false positive (no action):
  - HIGH-2 (reviewer's claim) VACUUM_DAILY_AT validator insufficient.
    Empirically `12_34` rejected: `v[2] == ":"` IS already enforced.
"""
import pathlib


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_DBSQ_SRC = (_ROOT / "db" / "sqlite.py").read_text(encoding="utf-8")
_EP_SRC   = (_ROOT / "integrations" / "endpoint_policy.py").read_text(encoding="utf-8")


# HIGH-1 — trust-topology knob denylist

def test_high1_db_load_deny_set_defined():
    """`_DB_LOAD_DENY` must exist as a frozenset and contain the
    trust-topology knobs."""
    assert "_DB_LOAD_DENY = frozenset({" in _PH_SRC, (
        "core/proxy_handler.py must define _DB_LOAD_DENY as a frozenset"
    )
    for knob in ("TRUSTED_PROXIES", "TRUST_XFF", "ADMIN_ALLOWED_IPS"):
        assert f'"{knob}"' in _PH_SRC, (
            f"_DB_LOAD_DENY must include {knob!r} — trust-topology knob "
            f"that must not be hot-reloadable from config_kv"
        )


def test_high1_db_load_config_honours_deny():
    """db_load_config must skip keys in _DB_LOAD_DENY and emit a
    `config_kv_security_knob_refused` slog so operators see when their
    config_kv has a trust-topology row that's being ignored."""
    idx = _DBSQ_SRC.find("def db_load_config")
    end = _DBSQ_SRC.find("\ndef ", idx + 1)
    body = _DBSQ_SRC[idx:end if end > 0 else len(_DBSQ_SRC)]
    assert "_DB_LOAD_DENY" in body, (
        "db_load_config must reference _DB_LOAD_DENY and refuse keys "
        "in that set"
    )
    assert "config_kv_security_knob_refused" in body, (
        "db_load_config must emit a slog when a denied knob is skipped"
    )


def test_high1_runtime_deny_works():
    """Functional: write TRUSTED_PROXIES to config_kv and confirm
    db_load_config refuses to apply it."""
    import os, sqlite3, json, tempfile
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import proxy
    # Use a tmp DB so we don't pollute the real one
    td = tempfile.mkdtemp()
    db = f"{td}/cfg_test.db"
    saved_path = proxy.DB_PATH
    try:
        proxy.DB_PATH = db
        proxy.db_init()
        conn = sqlite3.connect(db)
        # Pre-seed with a malicious trust-topology row
        conn.execute("DELETE FROM config_kv")
        conn.execute(
            "INSERT INTO config_kv (key, value, ts) VALUES (?, ?, ?)",
            ("TRUSTED_PROXIES", json.dumps(["1.2.3.4/32"]), 0.0))
        conn.commit()
        conn.close()
        # Snapshot the in-memory list, reset env-pin set, load
        original = list(getattr(proxy, "TRUSTED_PROXIES", []))
        saved_env = proxy._ENV_PROVIDED_KNOBS
        proxy._ENV_PROVIDED_KNOBS = set()
        try:
            proxy.db_load_config()
        finally:
            proxy._ENV_PROVIDED_KNOBS = saved_env
        # Assertion: the in-memory list MUST NOT contain the malicious
        # entry, regardless of starting state.
        post = list(getattr(proxy, "TRUSTED_PROXIES", []))
        # Compare normalised forms — _to_ip_net_list returns CIDR strings
        assert "1.2.3.4/32" not in post, (
            f"db_load_config applied a denied TRUSTED_PROXIES value; "
            f"original={original!r}, post={post!r}"
        )
    finally:
        proxy.DB_PATH = saved_path


# MED-1 — _to_ip_net_list logs rejected entries

def test_med1_to_ip_net_list_logs_rejections():
    """_to_ip_net_list must log a warn per dropped entry so operators
    see why their CIDR list looks shorter than expected."""
    assert "ip_net_list_rejected_entry" in _EP_SRC, (
        "integrations/endpoint_policy.py:_to_ip_net_list must emit a "
        "slog when it drops an invalid CIDR entry — silent drop was "
        "the root cause of a real operator confusion"
    )


def test_med1_to_ip_net_list_functional_drops_and_keeps_good():
    """Functional: pass a mixed list; valid entries survive, invalid
    ones are dropped + logged."""
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    from integrations.endpoint_policy import _to_ip_net_list
    out = _to_ip_net_list("10.0.0.0/8,10.0.0.0/33,not-an-ip,192.168.0.0/24")
    # /33 invalid, "not-an-ip" invalid; /8 and /24 normalised
    assert "10.0.0.0/8" in out
    assert "192.168.0.0/24" in out
    # The two bad entries must be absent
    assert not any("33" in x for x in out)
    assert "not-an-ip" not in out


# MED-2 — legacy DSN lift validates URL shape

def test_med2_legacy_dsn_lift_validates_url():
    """The iter-7 legacy DSN lift must validate the legacy value
    parses as a postgres:// URL before encrypting + persisting."""
    idx = _DBSQ_SRC.find("def db_load_secrets")
    end = _DBSQ_SRC.find("\ndef ", idx + 1)
    body = _DBSQ_SRC[idx:end if end > 0 else len(_DBSQ_SRC)]
    assert "_looks_valid" in body or "urlparse" in body, (
        "legacy DSN lift must parse the legacy value as a URL and "
        "verify it has a postgres:// scheme + hostname before "
        "encrypting"
    )
    assert "legacy_dsn_lift_skipped_malformed" in body, (
        "must emit an error slog when a malformed legacy DSN is "
        "skipped (so operator sees the problem instead of a silent "
        "PG-init failure on next boot)"
    )


def test_med2_legacy_dsn_lift_doc_marker_present():
    """Doc marker `iter-9 (code-review MED-2)` must appear in the
    validation block so a future reader understands the rationale."""
    assert "iter-9 (code-review MED-2)" in _DBSQ_SRC, (
        "iter-9 fix marker must appear at the validation block in the "
        "legacy DSN lift code"
    )


# Verified false-positive (regression guard)

def test_vacuum_daily_at_validator_rejects_malformed():
    """Reviewer flagged this as HIGH-2; verified false positive
    empirically. Lock down the validator so a future refactor can't
    silently accept malformed input."""
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import proxy
    spec = proxy._HOT_RELOAD_KNOBS["VACUUM_DAILY_AT"]
    validator = spec[1]
    # Good
    for v in ("", "05:00", "23:59", "00:00", "12:30"):
        assert validator(v), f"{v!r} should be accepted"
    # Bad
    for v in ("12_34", "12a34", "24:00", "12:60", "abcde", "5:00",
              "12:5", "1234", "12:345", "12 34"):
        assert not validator(v), f"{v!r} should be rejected"
