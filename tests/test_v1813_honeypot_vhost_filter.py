"""
tests/test_v1813_honeypot_vhost_filter.py — the honeypots dashboard vhost
selector must actually filter the data.

The UI (honeypots.html) appends `&vhost=<host>` to its three fetches
(honeypots-data, attack-playbook, honey-suggest). For the selector to do
anything, each backend endpoint must (a) read the `vhost` query param and
(b) push it into its DB read. They previously read only `mins`, so the
combobox was cosmetic. Guarded here by AST source inspection (no import
side-effects — importing proxy/config writes key files + needs UPSTREAM).
"""
import ast
import os

_REPO = os.path.join(os.path.dirname(__file__), "..")


def _func_src(path, fname):
    src = open(os.path.join(_REPO, path), encoding="utf-8").read()
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fname:
            seg = ast.get_source_segment(src, n)
            assert seg, f"could not extract source of {fname} in {path}"
            return seg
    raise AssertionError(f"{fname} not found in {path}")


def test_honeypots_data_filters_by_vhost():
    s = _func_src("dashboards/honeypots.py", "honeypots_data_endpoint")
    assert 'query.get("vhost"' in s, "honeypots-data never reads the vhost param"
    assert "vhost=_vhost" in s, "honeypots-data doesn't pass vhost to db_read_events_async"


def test_attack_playbook_filters_by_vhost():
    s = _func_src("core/proxy_handler.py", "attack_playbook_endpoint")
    assert 'query.get("vhost"' in s, "attack-playbook never reads the vhost param"
    assert "vhost=_vhost" in s, "attack-playbook doesn't pass vhost to db_read_events_async"


def test_honey_suggest_filters_by_vhost():
    s = _func_src("core/proxy_handler.py", "honey_suggest_endpoint")
    assert 'query.get("vhost"' in s, "honey-suggest never reads the vhost param"
    # honey-suggest uses a raw SQL count; the filter is a parameterised clause.
    assert "vhost = ?" in s, "honey-suggest SQL has no vhost filter clause"
    assert "_vhost" in s and "(start_ts," in s, "honey-suggest vhost param not bound"


def test_vhost_read_is_lowercased_like_other_dashboards():
    # agents/siem store + match vhost lowercase; honeypots must follow or the
    # selector silently matches nothing for mixed-case hosts.
    for path, fn in (("dashboards/honeypots.py", "honeypots_data_endpoint"),
                     ("core/proxy_handler.py", "attack_playbook_endpoint"),
                     ("core/proxy_handler.py", "honey_suggest_endpoint")):
        s = _func_src(path, fn)
        assert '.strip().lower()' in s, f"{fn} must .strip().lower() the vhost param"
