#!/bin/sh
# OSS, $0 local substitute for GitHub's git transport.
# Seeds a bare repo from the mounted seed tree, then serves it read-only over
# the git:// protocol. The scanner rewrites https://github.com/<org>/<repo>.git
# to git://gitserver/<org>/<repo>.git via git insteadOf (no app edits).
set -e

BASE=/srv/git
SEED_SRC=/seed

mkdir -p "$BASE"

# Build the seeded scan-target repo as a real git history (the history check
# scans the last 20 commits, so we need actual commits, not just a snapshot).
build_repo() {
  org_repo="$1"      # e.g. perditioinc/sample-service
  src="$2"           # working tree to commit
  work="/tmp/build-$(echo "$org_repo" | tr '/' '-')"
  bare="$BASE/${org_repo}.git"

  rm -rf "$work"
  mkdir -p "$work"
  cp -a "$src/." "$work/"

  git -C "$work" init -q -b main
  git -C "$work" config user.email "seed@local"
  git -C "$work" config user.name "Seed Bot"
  git -C "$work" config commit.gpgsign false
  git -C "$work" add -A
  git -C "$work" commit -q -m "seed: initial import of sample-service"

  mkdir -p "$(dirname "$bare")"
  rm -rf "$bare"
  git clone -q --bare "$work" "$bare"
  # Allow git daemon to export this repo.
  touch "$bare/git-daemon-export-ok"
  echo "[gitserver] seeded $bare"
}

if [ -d "$SEED_SRC/sample-service" ]; then
  build_repo "perditioinc/sample-service" "$SEED_SRC/sample-service"
fi

echo "[gitserver] starting git daemon on :9418 (base-path=$BASE)"
exec git daemon \
  --reuseaddr \
  --verbose \
  --export-all \
  --base-path="$BASE" \
  --enable=upload-pack \
  "$BASE"
