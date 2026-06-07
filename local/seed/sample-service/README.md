# sample-service

Seeded scan target for the reporium-security local substrate. Clean of secrets
and sensitive files; pins one known-vulnerable dependency (jinja2==2.11.2) so
the dependency CVE check has a deterministic finding to surface against the
local OSV stub.
