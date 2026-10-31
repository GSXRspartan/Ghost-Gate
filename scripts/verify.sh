#!/usr/bin/env bash
# Full verification sweep.
#
# Runs every suite Ghost Gate has, in the environment each one needs:
#
#   1. non-engine suites on the Windows host  (fast inner loop)
#   2. engine-backed suites under WSL        (Cranelift cannot build on Windows)
#
# Passes if every suite it ran reported zero failures. Suites that could not run
# are reported as SKIPPED with the reason, never as passing.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

TARGET_DIR="${CARGO_TARGET_DIR:-$(cd .. && pwd)/_cargo-target}"
export CARGO_TARGET_DIR="$TARGET_DIR"

FAILED=0
declare -a SUMMARY=()

record() {
  local name="$1" status="$2" detail="$3"
  SUMMARY+=("$(printf '%-34s %-8s %s' "$name" "$status" "$detail")")
  [ "$status" = "FAIL" ] && FAILED=1
  return 0
}

echo "=============================================================="
echo " Ghost Gate verification sweep"
echo " target dir: $CARGO_TARGET_DIR"
echo "=============================================================="
echo

# --- 1. Non-engine suites, Windows host -------------------------------------------------------
echo "--- [1/2] non-engine suites (Windows host) ---"
LOG1="$(mktemp -d)/nonengine.log"
if cargo test -p ghost-gate-core -p ghost-gate-wallet -p ghost-gate-verifier > "$LOG1" 2>&1; then
  PASSED="$(grep -c '^test .* ok$' "$LOG1" || true)"
  FAILED_COUNT="$(grep -c '^test .* FAILED' "$LOG1" || true)"
  record "core + wallet + verifier" "PASS" "${PASSED} tests passed"
else
  record "core + wallet + verifier" "FAIL" "see $LOG1"
  tail -40 "$LOG1"
fi
echo

# --- 2. Engine-backed suites, WSL ------------------------------------------------------------
echo "--- [2/2] engine-backed suites (WSL) ---"
if bash scripts/wsl_run.sh --version >/dev/null 2>&1 || true; then
  LOG2="$(mktemp -d)/engine.log"
  if bash scripts/wsl_run.sh test -p ghost-gate-tests > "$LOG2" 2>&1; then
    PASSED="$(grep -c '^test .* ok$' "$LOG2" || true)"
    record "ghost-gate-tests (engine)" "PASS" "${PASSED} tests passed"
  else
    record "ghost-gate-tests (engine)" "FAIL" "see $LOG2"
    tail -60 "$LOG2"
  fi
else
  record "ghost-gate-tests (engine)" "SKIP" "WSL unavailable"
fi
echo

# --- Summary ---------------------------------------------------------------------------------
echo "=============================================================="
for line in "${SUMMARY[@]}"; do
  echo "$line"
done
echo "=============================================================="

if [ "$FAILED" -ne 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS (every suite that ran had zero failures)"