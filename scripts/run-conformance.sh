#!/usr/bin/env bash
# Runs the sigstore-conformance verify tests against sigstore-swift-conformance.
#
#   scripts/run-conformance.sh [pytest args...]   e.g. -k happy-path -rA
#
# Env: CONFORMANCE_REF (default: v0.0.29, as pinned in CI),
#      CONFORMANCE_DIR (checkout + venv cache, default .build/sigstore-conformance).
# Requires git and uv (brew install uv). Signing tests are skipped; the
# expected failures in .github/conformance-xfail.txt are strict xfails.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REF="${CONFORMANCE_REF:-21533cde107c734ebc153c3e3a24d75fc9811a36}"
DIR="${CONFORMANCE_DIR:-$ROOT/.build/sigstore-conformance}"
TRACKER_REF="f5ef7e3a49c5b9aa2a5c8f9591e2c9feb1939060" # pinned in the action at v0.0.29

swift build --package-path "$ROOT" --product sigstore-swift-conformance
BIN="$(swift build --package-path "$ROOT" --show-bin-path)/sigstore-swift-conformance"

if [ ! -d "$DIR/suite/.git" ]; then
  git init -q "$DIR/suite"
fi
git -C "$DIR/suite" fetch -q --depth 1 https://github.com/sigstore/sigstore-conformance.git "$REF"
git -C "$DIR/suite" checkout -q FETCH_HEAD

if [ ! -d "$DIR/workspace/cpython-release-tracker/.git" ]; then
  git init -q "$DIR/workspace/cpython-release-tracker"
  git -C "$DIR/workspace/cpython-release-tracker" fetch -q --depth 1 \
    https://github.com/woodruffw/cpython-release-tracker.git "$TRACKER_REF"
  git -C "$DIR/workspace/cpython-release-tracker" checkout -q FETCH_HEAD
fi

if [ ! -x "$DIR/env/bin/python" ]; then
  uv venv -q --clear "$DIR/env"
fi
VIRTUAL_ENV="$DIR/env" uv pip install -q --requirement "$DIR/suite/requirements.txt"

XFAIL="$(sed -e '/^#/d' "$ROOT/.github/conformance-xfail.txt" | xargs)"
cd "$DIR/suite"
GHA_SIGSTORE_CONFORMANCE_XFAIL="$XFAIL" GITHUB_WORKSPACE="$DIR/workspace" \
  "$DIR/env/bin/python" -m pytest test -q -p no:cacheprovider \
  --skip-signing --entrypoint="$BIN" "$@"
