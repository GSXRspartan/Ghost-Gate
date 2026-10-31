#!/usr/bin/env bash
# Pre-build the five builtin WASM templates into their expected in-tree locations.
#
# WHY
#   crates/template_builtin/build.rs compiles the builtin templates by shelling out to `cargo build
#   --target wasm32-unknown-unknown --release` inside each template's directory, then copies the
#   artifact from `<template>/target/wasm32-unknown-unknown/release/<name>.wasm` into
#   `crates/template_builtin/compiled/`.
#
#   That nested `cargo build` inherits CARGO_TARGET_DIR from the environment. When a caller sets
#   CARGO_TARGET_DIR (which the workspace recommends, to keep artifacts out of the repo), the nested
#   build writes to the shared directory instead of the template's own `target/`, so the copy source
#   does not exist and the build script fails:
#
#       Error: Copy file to dest / No such file or directory. (os error 2)
#
# FIX
#   Run this script with CARGO_TARGET_DIR unset. That puts the artifacts exactly where the build
#   script looks for them, after which a later build with CARGO_TARGET_DIR set finds them present.
#   Everything stays on the native ext4 volume; scripts/_sync.sh excludes `target/` from the copy
#   back to Windows.
#
# Run once per synced tree. Safe to re-run.

set -euo pipefail

# Invoked as `wsl.exe ... bash script.sh`, which is not a login shell and so has no cargo on PATH.
export PATH="${HOME}/.cargo/bin:${PATH}"

BUILD_COPY="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/_ootle-v042-build}"
BUILTIN_DIR="$BUILD_COPY/crates/template_builtin"

if [ ! -d "$BUILTIN_DIR/templates" ]; then
  echo "error: $BUILTIN_DIR/templates not found" >&2
  echo "       run scripts/prepare_reference.sh first" >&2
  exit 1
fi

# Unset here deliberately: the point of this script is to let cargo use each template's own
# target/ directory, which is where the build script reads the artifact from.
unset CARGO_TARGET_DIR

for template in account nft_faucet faucet liquidity_pool burn_rate_governance; do
  dir="$BUILTIN_DIR/templates/$template"
  if [ ! -d "$dir" ]; then
    echo "skip: $template (not present)"
    continue
  fi
  echo "building builtin template: $template"
  (cd "$dir" && cargo build --target wasm32-unknown-unknown --release >/dev/null)
  wasm="$dir/target/wasm32-unknown-unknown/release/$template.wasm"
  if [ ! -f "$wasm" ]; then
    echo "error: expected $wasm to exist after the build" >&2
    exit 1
  fi
  echo "  ok: $(stat -c%s "$wasm") bytes"
done

echo
echo "all builtin templates built in-tree; a later build with CARGO_TARGET_DIR set will find them"