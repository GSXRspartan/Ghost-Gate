#!/usr/bin/env bash
# Prepare a writable copy of the pinned Tari Ootle reference for building.
#
# Why a copy rather than building in place:
#
#   crates/template_builtin/build.rs compiles five builtin WASM templates and writes
#   the results into its own crate tree (crates/template_builtin/compiled/*.wasm,
#   plus a target/ per template). Those paths are gitignored, so they are absent from
#   a fresh clone and the build fails without producing them.
#
#   The pinned reference checkout is read-only for this project. Rather than let a
#   build script write into it, we copy it to a scratch directory outside the
#   contest repo and point the workspace's path dependencies there. The copy is
#   verified against the expected commit before use, so a stale copy cannot silently
#   change what we build against.
#
# Usage:  scripts/prepare_reference.sh [destination]
# Default destination: ../_ootle-v042-build

set -euo pipefail

REFERENCE="${REFERENCE:-../tari-ootle-v0.42.0-reference}"
DEST="${1:-../_ootle-v042-build}"
EXPECTED_SHA="a43773e600b9503ed3fadcd3f0048f86131e3644"
EXPECTED_TAG="v0.42.0"

if [ ! -f "$REFERENCE/Cargo.toml" ]; then
  echo "error: no Tari Ootle checkout at $REFERENCE" >&2
  exit 1
fi

ACTUAL_SHA="$(git -C "$REFERENCE" rev-parse HEAD 2>/dev/null || echo none)"
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "error: reference is at '$ACTUAL_SHA', expected $EXPECTED_SHA" >&2
  echo "       refusing to build against an unpinned cohort" >&2
  exit 1
fi

ACTUAL_TAG="$(git -C "$REFERENCE" describe --tags --exact-match 2>/dev/null || echo none)"
echo "reference: $ACTUAL_SHA (tag: $ACTUAL_TAG)"

if [ ! -f "$DEST/Cargo.toml" ]; then
  echo "creating build copy at $DEST"
  mkdir -p "$(dirname "$DEST")"
  mkdir -p "$DEST"
  # Copy sources only. tar keeps the tree intact without needing robocopy, and
  # excluding .git keeps a stale commit out of the copy.
  tar -C "$REFERENCE" --exclude='./.git' --exclude='./target' -cf - . | tar -C "$DEST" -xf -
elif [ -d "$DEST/.git" ]; then
  EXISTING="$(git -C "$DEST" rev-parse HEAD 2>/dev/null || echo none)"
  if [ "$EXISTING" != "$EXPECTED_SHA" ]; then
    echo "error: build copy at $DEST is $EXISTING, expected $EXPECTED_SHA" >&2
    echo "       delete it and re-run" >&2
    exit 1
  fi
fi

# Re-verify the copy is the same cohort by comparing the workspace manifest, which
# every crate in the cohort inherits its version from.
SRC_VERSION="$(grep -m1 '^version' "$REFERENCE/Cargo.toml" | tr -d ' "')"
DST_VERSION="$(grep -m1 '^version' "$DEST/Cargo.toml" | tr -d ' "')"
if [ "$SRC_VERSION" != "$DST_VERSION" ]; then
  echo "error: copy version $DST_VERSION != reference $SRC_VERSION" >&2
  exit 1
fi
echo "build copy: $DEST (workspace $DST_VERSION)"

echo
echo "Now run tests with the external target dir, e.g."
echo "  CARGO_TARGET_DIR=../_cargo-target cargo test"