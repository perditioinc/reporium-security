"""Local PyPI JSON stub: OSS, offline, $0 substitute for pypi.org.

reporium_security/checks/dependencies.py shells out to `pip-audit --requirement
requirements.txt` with NO --vulnerability-service flag, so pip-audit uses its
default "pypi" service. That service:

  GET https://pypi.org/pypi/<name>/<version>/json   (per pinned requirement)
  GET https://pypi.org/pypi/<name>/json             (metadata / resolution)

and reads the ".vulnerabilities" array plus ".info.requires_dist" for resolution.

This stub serves just enough of that JSON so the REAL dependency check runs
end-to-end with zero network egress:
  * returns an empty requires_dist (no transitive resolution -> no real PyPI),
  * attaches a seeded vulnerability to the pinned vulnerable package so the
    check produces a deterministic finding.

The container's network alias is pypi.org, so pip-audit's HTTPS client reaches
this stub instead of the real index. Pure standard library only.
"""

from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SEED_PATH = Path(os.environ.get("OSV_SEED", "/data/vulns.json"))
WHEELHOUSE = Path(os.environ.get("WHEELHOUSE", "/wheelhouse"))

# /pypi/<name>/<version>/json  and  /pypi/<name>/json
_VER_RE = re.compile(r"^/pypi/(?P<name>[^/]+)/(?P<version>[^/]+)/json/?$")
_PKG_RE = re.compile(r"^/pypi/(?P<name>[^/]+)/json/?$")
# PEP 503 Simple index:  /simple/  and  /simple/<name>/
_SIMPLE_ROOT_RE = re.compile(r"^/simple/?$")
_SIMPLE_PKG_RE = re.compile(r"^/simple/(?P<name>[^/]+)/?$")
# wheel download:  /packages/<filename>
_PKGFILE_RE = re.compile(r"^/packages/(?P<filename>[^/]+)$")


def _canon(name: str) -> str:
    """PEP 503 normalized name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _wheels() -> list[Path]:
    if not WHEELHOUSE.exists():
        return []
    return sorted(WHEELHOUSE.glob("*.whl")) + sorted(WHEELHOUSE.glob("*.tar.gz"))


def _wheel_project(filename: str) -> str:
    """Project name from a wheel/sdist filename, PEP 503 normalized."""
    base = filename
    if base.endswith(".whl"):
        return _canon(base.split("-")[0])
    if base.endswith(".tar.gz"):
        return _canon(base[: -len(".tar.gz")].rsplit("-", 1)[0])
    return _canon(base)


def _load_seed() -> dict:
    if SEED_PATH.exists():
        return json.loads(SEED_PATH.read_text(encoding="utf-8"))
    return {"by_package": {}, "vulns": {}}


SEED = _load_seed()


def _vulns_for(name: str, version: str) -> list[dict]:
    key = f"{(name or '').lower()}=={version or ''}"
    ids = SEED.get("by_package", {}).get(key, [])
    out = []
    for i in ids:
        v = SEED.get("vulns", {}).get(i)
        if not v:
            continue
        # PyPI vulnerability record shape pip-audit consumes.
        out.append(
            {
                "id": v["id"],
                "aliases": v.get("aliases", []),
                "details": v.get("details", v.get("summary", "")),
                "summary": v.get("summary", ""),
                "fixed_in": v.get("fix_versions", []),
                "link": v.get("link", ""),
                "source": "osv",
                "withdrawn": None,
            }
        )
    return out


def _pkg_json(name: str, version: str | None) -> dict:
    """Minimal valid PyPI JSON: empty requires_dist halts resolution."""
    info_version = version or "0.0.0"
    body = {
        "info": {
            "name": name,
            "version": info_version,
            "requires_dist": [],  # no transitive resolution -> no real PyPI
            "yanked": False,
        },
        "releases": {info_version: []},
        "urls": [],
        "vulnerabilities": _vulns_for(name, version or info_version),
    }
    return body


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[pypi-stub] " + (fmt % args))

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path in ("/", "/health"):
            self._send(200, {"status": "ok", "service": "pypi-stub"})
            return

        # --- PEP 503 Simple index (so pip-audit's resolver can install) ----
        if _SIMPLE_ROOT_RE.match(self.path):
            projects = sorted({_wheel_project(w.name) for w in _wheels()})
            links = "".join(f'<a href="/simple/{p}/">{p}</a>\n' for p in projects)
            self._send_html(200, f"<!DOCTYPE html><html><body>\n{links}</body></html>")
            return

        m = _SIMPLE_PKG_RE.match(self.path)
        if m:
            want = _canon(m.group("name"))
            links = ""
            for w in _wheels():
                if _wheel_project(w.name) == want:
                    links += f'<a href="/packages/{w.name}">{w.name}</a>\n'
            self._send_html(200, f"<!DOCTYPE html><html><body>\n{links}</body></html>")
            return

        m = _PKGFILE_RE.match(self.path)
        if m:
            f = WHEELHOUSE / m.group("filename")
            if f.exists():
                self._send_file(f)
            else:
                self._send(404, {"message": "no such file"})
            return

        # --- PyPI JSON API (advisory data the dependency check reads) -------
        m = _VER_RE.match(self.path)
        if m:
            self._send(200, _pkg_json(m.group("name"), m.group("version")))
            return

        m = _PKG_RE.match(self.path)
        if m:
            self._send(200, _pkg_json(m.group("name"), None))
            return

        self._send(404, {"message": "not found"})


def main() -> None:
    port = int(os.environ.get("OSV_PORT", "443"))
    host = os.environ.get("OSV_HOST", "0.0.0.0")
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[pypi-stub] listening on {host}:{port}, seed={SEED_PATH}")
    print(f"[pypi-stub] seeded packages: {list(SEED.get('by_package', {}).keys())}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
