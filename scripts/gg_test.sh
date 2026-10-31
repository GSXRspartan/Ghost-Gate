#!/usr/bin/env bash
# Run a cargo command against the Ghost Gate workspace with this machine's build settings.
#
# The cohort switch lives in the root Cargo.toml's [workspace.dependencies]; nothing here decides it.
#
# Three settings this script exists to get right, each of which cost a build on this project:
#
#   - RUSTUP_TOOLCHAIN. The cohort pins 1.97.1 (tari-ootle-v0.42.0-ghost-gate/rust-toolchain.toml) and
#     the workspace asks for the same rust-version, so the default `stable` toolchain (1.99.0 here) is
#     not what this project is built with. rustup only applies a directory's rust-toolchain.toml to
#     processes started inside that directory, and a build started here is *not* inside the cohort tree,
#     so the pin has to be applied explicitly.
#
#   - The target directory. `.cargo/config.toml` (git-ignored, machine-local) points it at the Linux
#     filesystem rather than the HDD-mounted D: drive. It is deliberately config and not the
#     CARGO_TARGET_DIR environment variable: cargo exports CARGO_TARGET_DIR to build scripts, and
#     `crates/template_builtin/build.rs` shells out to a nested cargo for each builtin template and then
#     reads the .wasm from that template's own target/ directory. Inherit the variable and the nested
#     build writes elsewhere, and the cohort build dies with "Copy file to dest: No such file or
#     directory".
#
#   - One heavy build at a time. This box has ~9.7 GiB of RAM and 8 CPUs; the default here is 3 jobs.
#
# Usage: scripts/gg_test.sh <cargo-subcommand> [args...]
#   scripts/gg_test.sh test -p ghost-gate-tests --test gate_engine -- --test-threads=2
set -uo pipefail

ROOT="${GG_ROOT:-/mnt/d/Codex/ghost-gate-workspace}"
JOBS="${CARGO_BUILD_JOBS:-3}"
LOG="${LOG:-${HOME}/gg-logs/gg_test.log}"

# protoc 21.12, not the distro's 3.12.4: the base-layer protos use proto3 optional fields.
export PROTOC="${PROTOC:-${HOME}/ootle-build/protoc/bin/protoc}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.97.1}"
export CARGO_BUILD_JOBS="$JOBS"
export RUST_BACKTRACE=1

mkdir -p "$(dirname "$LOG")"
cd "$ROOT/ghost-gate" || exit 1

SUB="${1:-test}"
shift || true

{
  echo "=== $(date -Is) cargo $SUB $* (target=$(cargo config get build.target-dir 2>/dev/null | tail -1) jobs=$JOBS toolchain=$RUSTUP_TOOLCHAIN) ==="
} >> "$LOG"

cargo "$SUB" "$@" 2>&1 | tee -a "$LOG"
exit "${PIPESTATUS[0]}"
