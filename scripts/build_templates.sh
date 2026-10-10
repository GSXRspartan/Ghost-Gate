#!/usr/bin/env bash
# Builds the Haunted Vault's template WASM artifacts.
#
# The templates live in their own cargo workspaces (excluded from the native workspace because they
# build for wasm32-unknown-unknown with a different feature set). Each is compiled to
#   templates/<name>/target/wasm32-unknown-unknown/release/<name>.wasm
# which is where deploy_vault expects to find them.
#
# Requires the wasm32-unknown-unknown target on the pinned toolchain (already installed on this
# machine). This is a wasm build, not the heavy native build; it is safe to run alongside other
# work, though it does use cargo.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.97.1}"

for name in ghost_gate_faucet ghost_gate; do
  dir="$REPO_ROOT/templates/$name"
  if [ ! -d "$dir" ]; then
    echo "missing template dir: $dir" >&2
    exit 1
  fi
  echo "== building $name (wasm32 release) =="
  (cd "$dir" && cargo build --target wasm32-unknown-unknown --release --quiet)
  # The artifact name follows the PACKAGE name (hyphens to underscores), which is not always the
  # directory name; and some templates pin their own target-dir in .cargo/config.toml (the same
  # build.rs quirk the cohort's template_builtin has), so the artifact can land in target/default/
  # or target/.
  pkg="$(grep -m1 '^name = ' "$dir/Cargo.toml" | sed 's/^name = "//; s/"$//')"
  artifact="$(printf '%s' "$pkg" | tr '-' '_').wasm"
  out=""
  for cand in "$dir/target/default/wasm32-unknown-unknown/release/$artifact" \
              "$dir/target/wasm32-unknown-unknown/release/$artifact"; do
    if [ -f "$cand" ]; then out="$cand"; break; fi
  done
  if [ -z "$out" ]; then
    echo "no .wasm artifact found after building $name (package $pkg, artifact $artifact)" >&2
    exit 1
  fi
  echo "  ok: $out ($(wc -c < "$out") bytes)"
done
echo "all templates built."
