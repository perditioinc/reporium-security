# Local OSS substrate for reporium-security

A $0, OSS, fully local development substrate that exercises the **real**
`reporium-security` scan path against offline substitutes for the external
services it touches. Additive and local-only -- it never edits the application
source, never touches production, and makes no network calls to live cloud.

## What reporium-security actually depends on

`reporium-security` is a pure-Python CLI scanner with five checks. Its only
external touchpoints are:

| Real (cloud / network) dependency | Where it is used | OSS local substitute |
|-----------------------------------|------------------|----------------------|
| **GitHub** (`git clone https://github.com/<org>/<repo>.git`) | `__main__._clone_repo` when scanning a remote `org/repo` | `gitserver` -- a `git daemon` (git:// protocol) serving a seeded bare repo. The scanner rewrites the GitHub URL with `git insteadOf`. |
| **PyPI advisory data** (`https://pypi.org/pypi/<pkg>/<ver>/json`) | `checks/dependencies.py` via `pip-audit` (default `pypi` service) | `osv-stub` -- a stdlib HTTPS PyPI-JSON stub. Resolves to `pypi.org` via a Docker network alias; the scanner trusts its self-signed cert. |
| **`git`, `pip-audit` binaries** | files / history / dependency checks | the real OSS tools, installed in the `scanner` image |

The source is **mounted read-only**. All redirection is done with git config
(`insteadOf`), a Docker network alias, and a trusted local CA -- no app edits.

## Services

- **gitserver** -- builds a real git history from `seed/sample-service/` and
  serves it read-only over `git://`. Substitutes GitHub.
- **osv-stub** -- a PyPI JSON stub (named for the OSV advisory data it serves)
  that returns a seeded vulnerability for the pinned `jinja2==2.11.2` so the
  dependency check has a deterministic CVE to find. Substitutes pypi.org.
- **scanner** -- installs the real `reporium-security` (read-only source),
  wires up the redirects, and runs the smoke.

## Usage

```bash
# from repo root
make local-validate        # up -> smoke -> down -v (one shot)

# or from local/
make up                    # start gitserver + osv-stub
make smoke                 # run the real scan path against the stubs
make down                  # stop + remove (including volumes)
```

## What the smoke proves

Running `reporium-security scan perditioinc/sample-service` end-to-end:

1. the remote repo is **cloned via the local git daemon** (GitHub substitute),
2. all five checks run on the real cloned tree,
3. the dependency check surfaces the **seeded CVE via the PyPI stub**
   (pip-audit substitute), driving the grade,
4. secrets and sensitive-file checks pass cleanly on the seed repo.

The smoke exits non-zero if any of these assertions fail.

## Configuration

See `.env.example`. All values are local-only; there are no secrets.
