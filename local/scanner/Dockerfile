# Runs the REAL reporium-security CLI against the local OSS substitutes.
# Source is mounted read-only at /src and installed editable; git + pip-audit
# are the tools the real checks shell out to. $0 / OSS only.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Pre-install (at build time, against the real index) the OSS CVE scanner the
# dependency check invokes, plus reporium-security's own runtime deps. This lets
# the smoke install the app with --no-deps after pypi.org is redirected to the
# local stub, so no smoke-time install touches the real index.
RUN pip install --no-cache-dir \
      "setuptools>=68.0" wheel \
      pip-audit \
      "httpx>=0.27" "pyyaml>=6.0" "python-dotenv>=1.0"

WORKDIR /work
COPY smoke.sh /usr/local/bin/smoke.sh
RUN chmod +x /usr/local/bin/smoke.sh

ENTRYPOINT ["/usr/local/bin/smoke.sh"]
