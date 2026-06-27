"""
1.9.3 — the Settings "Database backend" toggle must not flash "SQLite active"
before loadDb() resolves the real backend. It starts in a neutral LOADING state
(grey track, hidden thumb, ⏳ hourglass, both labels dimmed); dbSetTarget() exits
that state once the live DB_BACKEND is known.
"""
import os
import pathlib

os.environ.setdefault("UPSTREAM", "https://example.com")
_ROOT = pathlib.Path(__file__).resolve().parent.parent
_HTML = (_ROOT / "dashboards" / "settings.html").read_text()


def test_loading_hourglass_present():
    assert 'id="db-loading"' in _HTML, "db-backend toggle must have a loading hourglass"
    assert "⏳" in _HTML, "hourglass glyph must be present"


def test_thumb_hidden_by_default():
    # Thumb starts hidden so no side reads as active during load.
    assert "transition:left .2s;display:none" in _HTML, \
        "db-thumb must default to display:none (loading state)"


def test_labels_dimmed_by_default():
    # Neither SQLite nor Postgres label may be highlighted (fg) by default.
    import re
    for lbl in ("db-lbl-sqlite", "db-lbl-pg"):
        m = re.search(rf'id="{lbl}"[^>]*style="([^"]*)"', _HTML)
        assert m, f"{lbl} not found"
        assert "color:var(--dim)" in m.group(1), \
            f"{lbl} must default to dim (not active) until the backend loads"


def test_track_neutral_by_default():
    # Track must NOT default to the green (SQLite-active) colour.
    assert "background:#484f58" in _HTML, "track must default to neutral grey while loading"
    assert "background:#3fb950;" not in _HTML, "track must not default to green-SQLite"


def test_dbsettarget_exits_loading_state():
    # The function that runs with the real backend must hide the hourglass
    # and reveal the thumb.
    import re
    m = re.search(r"function dbSetTarget\(val\)\{(.+?)\n  \}", _HTML, re.S)
    assert m, "dbSetTarget not found"
    body = m.group(1)
    assert "db-loading" in body and "display = 'none'" in body, \
        "dbSetTarget must hide the loading hourglass"
    assert "db-thumb" in body and "display = ''" in body, \
        "dbSetTarget must reveal the thumb"
