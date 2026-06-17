"""TLS wrapper around osv_stub: serves the OSV API stub over HTTPS on :443.

pip-audit talks to api.osv.dev over HTTPS, so the local substitute must also
speak TLS. The cert is self-signed for CN=api.osv.dev (generated at boot by
entrypoint.sh) and shared with the scanner container as a trusted CA. This is
the OSS, offline, $0 stand-in for the OSV.dev advisory service.
"""

from __future__ import annotations

import os
import ssl
from http.server import ThreadingHTTPServer

from osv_stub import Handler  # reuse the request handler


def main() -> None:
    port = int(os.environ.get("OSV_PORT", "443"))
    host = os.environ.get("OSV_HOST", "0.0.0.0")
    cert = os.environ["OSV_CERT"]
    key = os.environ["OSV_KEY"]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[osv-stub] HTTPS listening on {host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
