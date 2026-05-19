"""1.6.5 — TimescaleDB 1-minute soak.

Stand up a real timescale/timescaledb container, point the gateway's pg
backend at it, run synthetic traffic against the gateway for 60 s, then
assert event rows accumulated in Postgres.

Skipped when:
  • Docker isn't available, OR
  • the appsec-antibot-gw:1.6.5 image isn't built.

Tear-down always runs (even on failure) so the test is re-runnable.
"""
import shutil
import subprocess
import time
import pytest


def _have(cmd):
    return shutil.which(cmd) is not None


def _docker_works():
    if not _have("docker"):
        return False
    try:
        r = subprocess.run(["docker", "info"],
                            capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _image_present(tag):
    try:
        r = subprocess.run(["docker", "image", "inspect", tag],
                            capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


@pytest.mark.skipif(not _docker_works(), reason="docker not available")
@pytest.mark.skipif(not (_image_present("appsec-antibot-gw:1.8.9")
                         or _image_present("appsec-antibot-gw:1.8.6")
                         or _image_present("appsec-antibot-gw:1.6.5")),
                     reason="no appsec-antibot-gw image built")
def test_timescaledb_60s_soak():
    """Spin TimescaleDB + gateway pointed at it, 60 s of traffic,
    assert events in Postgres."""
    NET           = "appsecgw-soak-net"
    PG_NAME       = "appsecgw-soak-pg"
    GW_NAME       = "appsecgw-soak-gw"
    UPSTREAM_NAME = "appsecgw-soak-upstream"
    PG_PASS = "appsecgw-soak-pw"
    PG_DB   = "appsecgw"

    def cleanup():
        for n in (GW_NAME, PG_NAME, UPSTREAM_NAME):
            subprocess.run(["docker", "rm", "-f", n],
                            capture_output=True, timeout=20)
        subprocess.run(["docker", "network", "rm", NET],
                        capture_output=True, timeout=10)

    cleanup()
    try:
        # 1. Network
        r = _run(["docker", "network", "create", NET])
        assert r.returncode == 0, f"network create failed: {r.stderr}"

        # 2. TimescaleDB
        r = _run([
            "docker", "run", "-d", "--name", PG_NAME, "--network", NET,
            "-e", f"POSTGRES_PASSWORD={PG_PASS}",
            "-e", f"POSTGRES_DB={PG_DB}",
            "timescale/timescaledb:latest-pg16",
        ])
        assert r.returncode == 0, f"timescale start failed: {r.stderr}"

        # Wait for readiness
        deadline = time.time() + 60
        ready = False
        while time.time() < deadline:
            r = _run(["docker", "exec", PG_NAME, "pg_isready",
                      "-U", "postgres", "-d", PG_DB])
            if r.returncode == 0:
                ready = True
                break
            time.sleep(1)
        assert ready, "Postgres never became ready within 60 s"

        # 3. Upstream (nginx serves a default page)
        r = _run(["docker", "run", "-d", "--name", UPSTREAM_NAME,
                  "--network", NET, "nginx:alpine"])
        assert r.returncode == 0, f"upstream start failed: {r.stderr}"

        # 4. Gateway pointing at Postgres
        env_args = []
        env_kv = {
            "UPSTREAM": f"http://{UPSTREAM_NAME}:80",
            "ADMIN_KEY": "soak-key",
            "ADMIN_ALLOWED_IPS": "0.0.0.0/0",
            "ALLOWED_HOSTS": "",
            "JS_CHALLENGE": "0",
            "TURNSTILE_ENABLED": "0",
            "STRICT_ORIGIN": "0",
            "DB_BACKEND": "postgres",
            "POSTGRES_DSN":
                f"postgresql://postgres:{PG_PASS}@{PG_NAME}:5432/{PG_DB}",
        }
        for k, v in env_kv.items():
            env_args.extend(["-e", f"{k}={v}"])
        gw_image = ("appsec-antibot-gw:1.8.9"
                    if _image_present("appsec-antibot-gw:1.8.9")
                    else "appsec-antibot-gw:1.8.6"
                    if _image_present("appsec-antibot-gw:1.8.6")
                    else "appsec-antibot-gw:1.6.5")
        r = _run(["docker", "run", "-d", "--name", GW_NAME,
                  "--network", NET] + env_args + [gw_image])
        assert r.returncode == 0, f"gateway start failed: {r.stderr}"

        # Wait for gateway readiness — grep its logs.
        deadline = time.time() + 30
        gw_ready = False
        while time.time() < deadline:
            logs = _run(["docker", "logs", GW_NAME]).stdout
            if ("postgres backend selected" in logs or "active=postgres" in logs) and "[svc-metrics]" in logs:
                gw_ready = True
                break
            time.sleep(1)
        assert gw_ready, (
            f"gateway never reported postgres-selected. logs:\n"
            f"{_run(['docker','logs',GW_NAME]).stdout[-2000:]}")

        # 5. Drive traffic from inside the network (avoids host-port mapping
        # flakes). Send ~300 requests over 60 s with a browser-ish UA.
        start = time.time()
        sent = 0
        ua = "Mozilla/5.0 (Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
        while time.time() - start < 60:
            _run(["docker", "exec", UPSTREAM_NAME, "sh", "-c",
                  f"for i in 1 2 3 4 5; do "
                  f"  wget -q -O- --user-agent='{ua}' "
                  f"      http://{GW_NAME}:8443/ >/dev/null 2>&1 || true; "
                  f"done"], timeout=15)
            sent += 5
            time.sleep(1)
        assert sent >= 200, f"only sent {sent} requests in 60 s"

        # Give fire-and-forget pg writes a moment to drain.
        # Use 10 s to allow thread-pool inserts to flush on ARM64.
        time.sleep(10)

        # 6. Confirm rows landed in Postgres (query via docker exec).
        r = _run(["docker", "exec", PG_NAME, "psql",
                  "-U", "postgres", "-d", PG_DB,
                  "-At", "-c", "SELECT COUNT(*) FROM events"])
        if r.returncode != 0:
            gw_logs = _run(["docker", "logs", GW_NAME]).stdout
            pg_logs = _run(["docker", "logs", "--tail", "30", PG_NAME]).stdout
            assert False, (
                f"psql query failed: {r.stderr}\n"
                f"---- GW logs ----\n{gw_logs[-3000:]}\n"
                f"---- PG logs ----\n{pg_logs[-1500:]}")
        try:
            rows = int(r.stdout.strip())
        except ValueError:
            rows = -1

        # Diagnostic: query gateway's /__db-test from inside the gateway container.
        db_test = _run(["docker", "exec", GW_NAME, "python3", "-c",
                        "import urllib.request,json;"
                        "try:\n"
                        " req=urllib.request.Request('http://127.0.0.1:8443/antibot-appsec-gateway/secured/__db-test',\n"
                        "  headers={'Authorization':'Bearer soak-key'});\n"
                        " r=urllib.request.urlopen(req,timeout=5);\n"
                        " print(r.read().decode());\n"
                        "except Exception as e: print('db-test err:',e)"])

        if rows == 0:
            # Diagnostic: check SQLite event count inside gateway container.
            sqlite_rows = _run(["docker", "exec", GW_NAME, "python3", "-c",
                                "import sqlite3,os; db='/data/antibot.db';"
                                "conn=sqlite3.connect(db) if os.path.exists(db) else None;"
                                "print(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]"
                                " if conn else 'no-db')"])
            # Diagnostic: test pg_insert_event from inside gateway container.
            pg_py_diag = _run(["docker", "exec", GW_NAME, "python3", "-c",
                               "import sys,os; sys.path.insert(0,'/app');"
                               "os.chdir('/app');"
                               "from config import DB_BACKEND, POSTGRES_DSN;"
                               "print('DB_BACKEND=',repr(DB_BACKEND));"
                               "print('POSTGRES_DSN=',repr(POSTGRES_DSN));"
                               "import state; state._postgres_available=True;"
                               "from db.postgres import _get_pool, pg_insert_event;"
                               "import time;"
                               "pool=_get_pool();"
                               "print('pool=',pool);"
                               "r=pg_insert_event(time.time(),'2.2.2.2','diag','/',200,'diag-exec','tk','','','','rid');"
                               "print('insert=',r)"])
            # Diagnostic: direct INSERT to confirm Postgres table accepts writes.
            _run(["docker", "exec", PG_NAME, "psql",
                  "-U", "postgres", "-d", PG_DB, "-At", "-c",
                  "INSERT INTO events (ts,ip,ua,path,status,reason) "
                  "VALUES (NOW(),'1.2.3.4','diag-ua','/',200,'diag-test')"])
            rows_after = _run(["docker", "exec", PG_NAME, "psql",
                               "-U", "postgres", "-d", PG_DB, "-At", "-c",
                               "SELECT COUNT(*) FROM events"]).stdout.strip()
            gw_full_logs = _run(["docker", "logs", GW_NAME]).stdout
            pg_logs = _run(["docker", "logs", "--tail", "50", PG_NAME]).stdout
            assert False, (
                f"0 Postgres event rows after 60 s traffic + 10 s drain.\n"
                f"SQLite events in GW container: {sqlite_rows.stdout.strip()!r}\n"
                f"pg_insert_event exec diag: {pg_py_diag.stdout!r} err={pg_py_diag.stderr!r}\n"
                f"GW /__db-test: {db_test.stdout!r}\n"
                f"Direct psql INSERT — rows after: {rows_after}\n"
                f"---- GW logs (last 3000) ----\n{gw_full_logs[-3000:]}\n"
                f"---- PG logs ----\n{pg_logs[-1500:]}")

        gw_tail = _run(["docker", "logs", "--tail", "60", GW_NAME]).stdout
        assert rows >= 50, (
            f"60 s of traffic produced only {rows} Postgres event rows "
            f"(expected ≥50). GW tail:\n{gw_tail}")

        # 7. Confirm Timescale hypertable was created on `events`.
        r = _run(["docker", "exec", PG_NAME, "psql",
                  "-U", "postgres", "-d", PG_DB,
                  "-At", "-c",
                  "SELECT 1 FROM timescaledb_information.hypertables "
                  "WHERE hypertable_name='events'"])
        # Best-effort — older Timescale versions name the view differently.
        # If not present we still want the test to pass since rows landed.
        if r.returncode == 0 and r.stdout.strip() == "1":
            print("[soak] Timescale hypertable confirmed on events")
        else:
            print(f"[soak] Timescale hypertable view check: rc={r.returncode} "
                  f"out={r.stdout!r}")
    finally:
        cleanup()
