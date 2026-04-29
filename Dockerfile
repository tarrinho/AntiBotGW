# ─── Stage 1: build deps using Chainguard's Wolfi-based python:latest-dev.
# Same Python interpreter as the runtime stage so wheels match exactly.
# Chainguard ships fixes for OS-level CVEs typically within hours of disclosure.
FROM cgr.dev/chainguard/python:latest-dev AS builder

USER root
WORKDIR /tmp

RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel \
 && python3 -m pip install --no-cache-dir --upgrade --target /pydeps \
       'aiohttp>=3.11.11,<4'

# Pre-stage the rootfs we'll copy into the distroless runtime.  The runtime
# has no shell or coreutils so we can't mkdir/ln there.
RUN mkdir -p /rootfs/app /rootfs/data \
 && cp -a /pydeps/. /rootfs/app/pydeps \
 && ln -sf /data/.admin_key   /rootfs/app/.admin_key \
 && ln -sf /data/.session_key /rootfs/app/.session_key \
 && ln -sf /data/.pow_key     /rootfs/app/.pow_key

COPY proxy.py /rootfs/app/proxy.py
COPY dashboards /rootfs/app/dashboards

# ─── Stage 2: Chainguard's distroless python runtime (Wolfi). No shell, no
# apt, no systemd, no ncurses, no util-linux, no expat-side-tools. Built
# from upstream sources with continuous security patching. ───
FROM cgr.dev/chainguard/python:latest

COPY --from=builder --chown=65532:65532 /rootfs /

WORKDIR /app
USER 65532:65532

ENV LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=8443 \
    BURST=30 \
    REFILL=2.0 \
    IP_BURST=60 \
    IP_REFILL=8.0 \
    ALLOWED_METHODS="GET,HEAD,POST,OPTIONS" \
    ALLOWED_HOSTS="" \
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
    CMD ["python3","-c","import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8443/__live', timeout=3).read()==b'ok' else 1)"]

ENTRYPOINT ["python3", "/app/proxy.py"]
