"""
tests/test_v1811_service_owner.py — QA for the SERVICE_OWNER feature (1.8.11).

SERVICE_OWNER is an operator-set string, editable in Settings → Config, persisted
to config_kv (SQLite + Postgres via the hot-reload path), and rendered in every
dashboard footer as "Operated by <owner>".
"""
import inspect
import os

os.environ.setdefault("UPSTREAM", "https://example.com")
os.environ.setdefault("ADMIN_KEY", "x" * 16)

import config                                   # noqa: E402
from core import proxy_handler                  # noqa: E402
from core import middleware                     # noqa: E402

_HERE = os.path.dirname(__file__)


def _dash(name):
    with open(os.path.join(_HERE, "..", "dashboards", name), encoding="utf-8") as f:
        return f.read()


class TestServiceOwnerKnob:
    def test_global_exists(self):
        assert hasattr(config, "SERVICE_OWNER")

    def test_hot_reloadable(self):
        """In _HOT_RELOAD_KNOBS → editable via /config AND persisted to config_kv
        (the same path every hot-reload knob uses; mirrored to Postgres)."""
        assert "SERVICE_OWNER" in proxy_handler._HOT_RELOAD_KNOBS
        coerce, validate = proxy_handler._HOT_RELOAD_KNOBS["SERVICE_OWNER"]
        assert coerce is str
        assert validate("Acme Security Team") is True
        assert validate("x" * 200) is False        # 128-char cap

    def test_env_pin_excluded(self):
        """Excluded from env-pinning so the UI/DB value always wins, even when
        SERVICE_OWNER is also set via container env."""
        assert "SERVICE_OWNER" in proxy_handler._ENV_PIN_EXCLUDE

    def test_in_config_state(self):
        """GET /config must expose SERVICE_OWNER so Settings can load it."""
        st = proxy_handler._read_hot_reload_state()
        assert "SERVICE_OWNER" in st


class TestServiceOwnerSettingsUI:
    def test_config_section_has_card(self):
        s = _dash("settings.html")
        assert 'id="card-service-owner"' in s, "Service-owner card missing"
        assert 'id="svc-owner-input"' in s
        assert 'id="btn-svc-owner-save"' in s

    def test_card_mapped_to_config_section(self):
        s = _dash("settings.html")
        assert "'card-service-owner': 'config'" in s, \
            "card must be mapped to the Config submenu section"

    def test_save_posts_service_owner(self):
        s = _dash("settings.html")
        assert "JSON.stringify({SERVICE_OWNER: val})" in s, \
            "Save must POST SERVICE_OWNER to /config"


class TestServiceOwnerFooterInjection:
    def test_middleware_injects_owner_and_renders_footer(self):
        src = inspect.getsource(middleware._inject_csrf_global)
        assert "__AGW_SERVICE_OWNER__" in src, "must inject the owner JS global"
        assert "svc-owner" in src and "portal-footer" in src, \
            "must render the owner into .portal-footer"
        # Value comes from live config (hot-reload propagates there).
        assert "SERVICE_OWNER" in src and "config" in src
        # textContent (not innerHTML) → XSS-safe rendering of operator input.
        assert "textContent" in src and "innerHTML" not in src
