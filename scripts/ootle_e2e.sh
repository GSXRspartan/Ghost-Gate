#!/usr/bin/env bash
# Run a scenario from the Ootle cohort's own end-to-end harness.
#
# `integration_tests` starts a base node, validator, indexer, miner and wallet daemon in-process, so
# this is a real network exercising the real RPC surface rather than a stand-in. It is the harness the
# cohort uses for its own wallet flows, which is why Gate 3 uses it instead of a hand-rolled localnet.
#
# Debug profile, not the release profile the cohort README suggests: the shared target directory is
# warm in debug and cold in release, and at jobs=1 on this box a release rebuild is not affordable.
#
# Jobs default to 1 and the WSL VM is capped at 2800 MB (see ~/.wslconfig): overcommitting the host
# restarts Windows, which costs far more than the recoverable in-VM OOM this avoids.
#
# Usage: scripts/ootle_e2e.sh [cucumber args...]
#   e.g. scripts/ootle_e2e.sh --tags "@transfer"
#        scripts/ootle_e2e.sh --name "Stealth transfer to account that does not previously exist"

set -uo pipefail
export PATH="/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUST_BACKTRACE=1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

TARGET="${TARGET:-/root/gg-ootle-target}"
STAGED="${STAGED:-/root/gg/_ootle-v042-ghost-gate}"
LOG="${LOG:-/root/e2e.log}"

[ -f "$STAGED/Cargo.toml" ] || { echo "error: staged tree missing at $STAGED" >&2; exit 1; }

cd "$STAGED" || exit 1

# `utoipa-swagger-ui` (pulled in by the indexer) downloads a release zip from github.com in its build
# script, and that fetch is the single point where building this harness depends on the network. The
# crate honours SWAGGER_UI_DOWNLOAD_URL when it starts with `file:`, so scripts/stage_swagger_ui.sh
# fetches the archive once and the build reuses it from disk.
SWAGGER_ZIP="${SWAGGER_ZIP:-/root/gg-cache/swagger-ui-v5.17.14.zip}"
if [ -s "$SWAGGER_ZIP" ]; then
  export SWAGGER_UI_DOWNLOAD_URL="file:$SWAGGER_ZIP"
  echo "using local Swagger UI archive: $SWAGGER_ZIP"
else
  echo "warning: $SWAGGER_ZIP absent; the build will try to download from github.com" >&2
  echo "         run scripts/stage_swagger_ui.sh first if that fails" >&2
fi

# A fresh log per invocation: a stale tail here is indistinguishable from a current one.
: > "$LOG"
{
  echo "=== $(date -Is) cargo test -p integration_tests --test cucumber $* ==="
} >> "$LOG"

env CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="$CARGO_BUILD_JOBS" \
  cargo test -p integration_tests --test cucumber "$@" 2>&1 | tee -a "$LOG"
exit "${PIPESTATUS[0]}"