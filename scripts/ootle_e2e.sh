#!/usr/bin/env bash
# Run a scenario from the Ootle cohort's own end-to-end harness.
#
# `integration_tests` starts a base node, validator, indexer, miner and wallet daemon in-process, so
# this is a real network exercising the real RPC surface rather than a stand-in. It is the harness the
# cohort uses for its own wallet flows, which is why Gate 3 uses it instead of a hand-rolled localnet.
#
# Debug profile, not the release profile the cohort README suggests. The shared target directory is
# warm in debug from the engine suite, and a release build of the whole node stack on this box is a
# multi-hour rebuild that buys nothing for a correctness run.
#
# The target directory is passed with `--config build.target-dir` rather than CARGO_TARGET_DIR, and the
# reason is the cohort's own `crates/template_builtin/build.rs`: cargo exports CARGO_TARGET_DIR to build
# scripts, that script shells out to a nested cargo for each builtin template and then reads the .wasm
# out of that template's own target/ directory, so an inherited variable makes the cohort build fail
# with "Copy file to dest: No such file or directory". The cohort tree is left untouched, which also
# keeps the patched tree byte-comparable with the pristine reference (docs/wallet-mvp.patch).
#
# Usage: scripts/ootle_e2e.sh [--] [cucumber args...]
#   Everything after `--` goes to the test binary, which is where cucumber's own arguments belong. Passing
#   them straight through does not work: cargo parses `--tags` itself and refuses the command.
#   e.g. scripts/ootle_e2e.sh -- --tags "@transfer"
#        scripts/ootle_e2e.sh -- --name "Stealth transfer to account that does not previously exist"

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export RUST_BACKTRACE=1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
# The cohort pins 1.97.1 and rustup only applies a rust-toolchain.toml to processes started inside that
# tree, so the pin is applied here explicitly rather than inherited from the working directory.
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.97.1}"
# protoc 21.12; the distro's 3.12.4 rejects proto3 optional fields.
export PROTOC="${PROTOC:-${HOME}/ootle-build/protoc/bin/protoc}"

# Two native build dependencies are missing from this image and `sudo` needs a password, so they are
# unpacked from their distribution packages into a user-writable prefix instead:
#   - libudev's development files, for `hidapi`'s C shim (pulled in by the Minotari base-layer wallet)
#   - autoconf/automake/m4/libtool, because `libtor-src` builds Tor from source via `autoreconf`
# scripts/stage_native_deps.sh does the work; the exports below are what its output asks for. Nothing
# outside $HOME is touched.
bash "$SCRIPT_DIR/stage_native_deps.sh" >/dev/null
export PATH="${HOME}/gg-local/usr/bin:$PATH"
export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-${HOME}/gg-local/usr/lib/x86_64-linux-gnu/pkgconfig}"
# hidapi compiles its C shim *before* asking pkg-config anything, so the header has to be findable by the
# C compiler itself. CPATH is gcc/clang's own "additional include search path" variable, which is why it
# is used here instead of CFLAGS: nothing about the compiler invocation changes, only where it looks.
export CPATH="${CPATH:-${HOME}/gg-local/usr/include}${CPATH:+:$CPATH}"

TARGET="${TARGET:-${HOME}/gg-ootle-target}"
STAGED="${STAGED:-/mnt/d/Codex/ghost-gate-workspace/_ootle-v042-ghost-gate}"
LOG="${LOG:-${HOME}/gg-logs/e2e.log}"

[ -f "$STAGED/Cargo.toml" ] || { echo "error: cohort tree missing at $STAGED" >&2; exit 1; }

cd "$STAGED" || exit 1

# `utoipa-swagger-ui` (pulled in by the indexer) downloads a release zip from github.com in its build
# script, and that fetch is the single point where building this harness depends on the network. The
# crate honours SWAGGER_UI_DOWNLOAD_URL when it starts with `file:`, so scripts/stage_swagger_ui.sh
# fetches the archive once and the build reuses it from disk.
SWAGGER_ZIP="${SWAGGER_ZIP:-${HOME}/gg-cache/swagger-ui-v5.17.14.zip}"
if [ -s "$SWAGGER_ZIP" ]; then
  export SWAGGER_UI_DOWNLOAD_URL="file:$SWAGGER_ZIP"
  echo "using local Swagger UI archive: $SWAGGER_ZIP"
else
  echo "warning: $SWAGGER_ZIP absent; the build will try to download from github.com" >&2
  echo "         run scripts/stage_swagger_ui.sh first if that fails" >&2
fi

mkdir -p "$(dirname "$LOG")"
# A fresh log per invocation: a stale tail here is indistinguishable from a current one.
: > "$LOG"
{
  echo "=== $(date -Is) cargo test -p integration_tests --test cucumber $* (target=$TARGET jobs=$CARGO_BUILD_JOBS) ==="
} >> "$LOG"

cargo --config "build.target-dir=\"$TARGET\"" test -p integration_tests --test cucumber "$@" 2>&1 |
  tee -a "$LOG"
exit "${PIPESTATUS[0]}"
