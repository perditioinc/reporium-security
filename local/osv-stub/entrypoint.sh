#!/bin/sh
# Generate a self-signed cert for pypi.org (so pip-audit's HTTPS client trusts
# the local stub) and start the PyPI JSON stub over TLS on :443.
# Self-signed, local-only, regenerated on each boot. No secrets persisted.
set -e

CERT_DIR=/certs
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/osv.crt" ]; then
  echo "[pypi-stub] generating self-signed cert for pypi.org"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/osv.key" \
    -out "$CERT_DIR/osv.crt" \
    -days 365 \
    -subj "/CN=pypi.org" \
    -addext "subjectAltName=DNS:pypi.org,DNS:www.pypi.org,DNS:localhost" >/dev/null 2>&1
fi

export OSV_CERT="$CERT_DIR/osv.crt"
export OSV_KEY="$CERT_DIR/osv.key"
exec python3 /app/osv_stub_tls.py
