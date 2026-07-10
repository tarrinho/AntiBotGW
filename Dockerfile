# ─── Stage 1: build deps using Chainguard's Wolfi-based python:latest-dev.
# Same Python interpreter as the runtime stage so wheels match exactly.
# Chainguard ships fixes for OS-level CVEs typically within hours of disclosure.
FROM cgr.dev/chainguard/python:latest-dev@sha256:6dd180984927051df465a1914772a4675119e6a998ab9dcfbb7a9269badad387 AS builder

USER root
WORKDIR /tmp

RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel \
 && python3 -m pip install --no-cache-dir --target /pydeps \
       'aiohttp==3.14.1' \
       'maxminddb==2.8.2' \
       'psycopg[binary]==3.3.4' \
       'redis==5.3.1' \
       'pyotp>=2.9.0' \
       'qrcode>=7.0' \
       'cryptography>=46.0.5' \
       'PyJWT>=2.13.0'

# Pre-stage the rootfs we'll copy into the distroless runtime.  The runtime
# has no shell or coreutils so we can't mkdir/ln there.
RUN mkdir -p /rootfs/app /rootfs/data /rootfs/usr/local/share/maxmind \
 && cp -a /pydeps/. /rootfs/app/pydeps \
 && ln -sf /data/.admin_key   /rootfs/app/.admin_key \
 && ln -sf /data/.session_key /rootfs/app/.session_key \
 && ln -sf /data/.pow_key     /rootfs/app/.pow_key

COPY proxy.py      /rootfs/app/proxy.py
COPY config.py     /rootfs/app/config.py
COPY state.py      /rootfs/app/state.py
COPY helpers.py    /rootfs/app/helpers.py
COPY identity.py   /rootfs/app/identity.py
COPY rate_limit.py /rootfs/app/rate_limit.py
COPY scoring.py    /rootfs/app/scoring.py
COPY vhost.py      /rootfs/app/vhost.py
COPY admin        /rootfs/app/admin
COPY challenge    /rootfs/app/challenge
COPY core         /rootfs/app/core
COPY dashboards   /rootfs/app/dashboards
COPY db           /rootfs/app/db
COPY detection    /rootfs/app/detection
COPY integrations /rootfs/app/integrations
COPY reputation   /rootfs/app/reputation
# 1.5.5 — bundled GeoLite2 mmdbs at a path NOT shadowed by /data volume.
# proxy.py copies these into /data on first boot so the GeoMap dashboard
# works out-of-the-box. Operators may override by dropping fresher mmdbs
# into /data, or set MAXMIND_LICENSE_KEY to auto-refresh inside the container.
COPY _seed/ /rootfs/usr/local/share/maxmind/

USER nonroot

# ─── Stage 2: Chainguard's distroless python runtime (Wolfi). No shell, no
# apt, no systemd, no ncurses, no util-linux, no expat-side-tools. Built
# from upstream sources with continuous security patching. ───
FROM cgr.dev/chainguard/python:latest@sha256:522a5ff629869272271784d864da372e03612822902878ecb20b4afc9e797779

COPY --from=builder --chown=65532:65532 /rootfs /

WORKDIR /app
USER 65532:65532

# 1.5.5 — only deploy-shape envs go in the image. Runtime-tunable knobs
# (BURST/REFILL/IP_BURST/IP_REFILL/ALLOWED_METHODS/ALLOWED_HOSTS/etc.) are
# intentionally NOT set here so they stay hot-reloadable via /__config.
# proxy.py has sensible in-code defaults; operators override per-deploy via
# `docker run -e KEY=VAL` or compose env_file.
ENV LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=8443 \
    TRUST_XFF=last \
    DB_PATH=/data/antibot.db \
    DEBUG=0 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PYTHONPATH=/app/pydeps \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

VOLUME ["/data"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python3","-c","import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8443/antibot-appsec-gateway/live', timeout=3).read()==b'ok' else 1)"]

ENTRYPOINT ["python3", "/app/proxy.py"]
