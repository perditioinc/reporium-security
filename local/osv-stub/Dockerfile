# OSS, $0 local substitute for PyPI (named osv-stub for the OSV advisory data
# it serves). Serves a PEP 503 Simple index + the PyPI JSON advisory API over
# self-signed TLS. Pure stdlib Python + openssl. No paid services.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Wheelhouse: fetched at BUILD time (real index available during docker build)
# so the runtime stub can install fully offline. Holds the build toolchain plus
# the seeded vulnerable package and its deps. No binaries committed to the repo.
ENV WHEELHOUSE=/wheelhouse
ARG VULN_PACKAGE="jinja2==2.11.2"
RUN mkdir -p "$WHEELHOUSE" \
    && pip download --no-cache-dir -d "$WHEELHOUSE" \
        pip setuptools wheel ${VULN_PACKAGE}

WORKDIR /app
COPY osv_stub.py osv_stub_tls.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

EXPOSE 443
ENTRYPOINT ["/app/entrypoint.sh"]
