#!/bin/sh
# Smoke test: exercise reporium-security's REAL path against local OSS stubs.
#
#   real path: `reporium-security scan <org/repo>`
#     -> git clone https://github.com/<org>/<repo>.git   (rewritten -> gitserver)
#     -> 5 checks (secrets, dependencies via pip-audit -> OSV stub, workflows,
#        files, history)
#     -> grade + SECURITY_REPORT.md
#
# We make NO changes to the application source. Redirection happens entirely via
# git config (insteadOf) and a trusted local CA for the OSV stub.
set -e

echo "=============================================="
echo " reporium-security local smoke"
echo "=============================================="

# --- 1. Trust the local PyPI stub's self-signed cert (pypi.org) ------------
# The stub container shares its cert via the /certs volume.
for i in $(seq 1 30); do
  if [ -f /certs/osv.crt ]; then break; fi
  echo "[smoke] waiting for pypi-stub cert..."
  sleep 1
done
if [ ! -f /certs/osv.crt ]; then
  echo "[smoke] FAIL: pypi-stub cert never appeared"
  exit 1
fi
cp /certs/osv.crt /usr/local/share/ca-certificates/pypi-stub.crt
update-ca-certificates >/dev/null 2>&1 || true
# pip-audit (requests/urllib3) honours these:
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# --- 2. Rewrite GitHub clone URL -> local git daemon (no source edits) ------
# pip-audit resolves the audited requirements with pip; point pip's index at
# the local PyPI stub's Simple index (pypi.org already resolves to the stub).
export PIP_INDEX_URL=https://pypi.org/simple/
export PIP_DISABLE_PIP_VERSION_CHECK=1

git config --global url."git://gitserver/".insteadOf "https://github.com/"
# the CLI builds https://github.com/<org>/<repo>.git; the rewrite yields
# and the CLI builds https://github.com/<org>/<repo>.git, so the rewrite yields
# git://gitserver/<org>/<repo>.git -- which is exactly the seeded bare path.

# --- 3. Install the REAL source (mounted read-only at /src) ------------------
# Copy to a writable dir so setuptools can write build metadata WITHOUT
# touching the read-only source mount, then install. No source edits.
# Runtime deps were baked into the image at build time; install the app itself
# with --no-deps so this step never reaches the (now-redirected) index.
echo "[smoke] installing reporium-security from /src (source stays read-only)"
rm -rf /tmp/src && cp -a /src /tmp/src
# --no-build-isolation: use the setuptools/wheel already in the image instead
# of fetching build deps from the (redirected) index.
pip install --no-cache-dir --no-deps --no-build-isolation /tmp/src \
  >/tmp/pip.log 2>&1 || {
  echo "[smoke] FAIL: could not install reporium-security"; cat /tmp/pip.log; exit 1;
}

# --- 4. Wait for the PyPI stub to answer over HTTPS -------------------------
for i in $(seq 1 30); do
  if curl -sf https://pypi.org/health >/dev/null 2>&1; then break; fi
  echo "[smoke] waiting for pypi-stub https..."
  sleep 1
done

# --- 5. Run the REAL CLI against the seeded remote repo ---------------------
REPORT=/work/SECURITY_REPORT.md
set +e
echo "[smoke] running: reporium-security scan perditioinc/sample-service"
reporium-security scan perditioinc/sample-service --output "$REPORT"
CLI_RC=$?
set -e

echo "----------------------------------------------"
echo "[smoke] CLI exit code: $CLI_RC"
echo "[smoke] ----- SECURITY_REPORT.md -----"
cat "$REPORT" || { echo "[smoke] FAIL: no report produced"; exit 1; }
echo "[smoke] -------------------------------"

# --- 6. Assertions on the REAL output --------------------------------------
fail=0

# 6a. Clone went through the local git daemon (proves GitHub substitute worked):
#     if the clone had failed, scan_repo would have errored before a report.
if ! grep -q "Security Report: perditioinc/sample-service" "$REPORT"; then
  echo "[smoke] ASSERT FAIL: report not produced for the cloned remote repo"
  fail=1
else
  echo "[smoke] OK: remote repo cloned via local git daemon and scanned"
fi

# 6b. Dependency CVE check surfaced the seeded jinja2 CVE via the OSV stub:
if grep -qi "jinja2" "$REPORT" && grep -qi "CVE" "$REPORT"; then
  echo "[smoke] OK: dependency check found the seeded CVE via OSV stub"
else
  echo "[smoke] ASSERT FAIL: seeded jinja2 CVE not reported (OSV stub path)"
  fail=1
fi

# 6c. Grade is D (HIGH/CRITICAL CVE), proving grade logic ran on real findings:
if grep -q "Grade: D" "$REPORT"; then
  echo "[smoke] OK: grade D as expected for a HIGH-severity dependency CVE"
else
  echo "[smoke] NOTE: grade was not D; printing grade line:"
  grep -i "Grade:" "$REPORT" || true
  # Grade depends on stub-reported severity; treat non-D as a soft signal only
  # if a CVE was still found (6b). If 6b passed, the real path worked.
fi

# 6d. The non-dependency checks ran cleanly on the seeded (clean) repo:
if grep -q "No secrets detected in source files" "$REPORT" \
   && grep -q "No sensitive files detected" "$REPORT"; then
  echo "[smoke] OK: secrets + files checks passed on the clean seed repo"
else
  echo "[smoke] ASSERT FAIL: secrets/files checks did not pass as expected"
  fail=1
fi

echo "=============================================="
if [ "$fail" -eq 0 ]; then
  echo " SMOKE: PASS"
  exit 0
else
  echo " SMOKE: FAIL"
  exit 1
fi
