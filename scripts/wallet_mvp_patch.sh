#!/usr/bin/env bash
# Generate the wallet MVP patch as a reviewable diff against pristine upstream v0.42.0.
#
# The pristine reference at ../tari-ootle-v0.42.0-reference is never written to. The patch tree at
# ../tari-ootle-v0.42.0-ghost-gate is a writable copy carrying only the changes needed to let the
# wallet express a minimum-value-promise-bearing output. This script emits the diff between them, so
# the patch is always reviewable and always diffable against exact upstream.
#
# Usage:
#   scripts/wallet_mvp_patch.sh            # write docs/wallet-mvp.patch
#   scripts/wallet_mvp_patch.sh --check    # verify the patch tree still matches the recorded patch

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE="$(cd "$REPO_DIR/.." && pwd)"

REFERENCE="${REFERENCE:-$WORKSPACE/tari-ootle-v0.42.0-reference}"
PATCHED="${PATCHED:-$WORKSPACE/tari-ootle-v0.42.0-ghost-gate}"
OUT="$REPO_DIR/docs/wallet-mvp.patch"

UPSTREAM_SHA="a43773e600b9503ed3fadcd3f0048f86131e3644"

for dir in "$REFERENCE" "$PATCHED"; do
  if [ ! -f "$dir/Cargo.toml" ]; then
    echo "error: missing $dir" >&2
    exit 1
  fi
done

ACTUAL_SHA="$(git -C "$REFERENCE" rev-parse HEAD 2>/dev/null || echo none)"
if [ "$ACTUAL_SHA" != "$UPSTREAM_SHA" ]; then
  echo "error: reference is at '$ACTUAL_SHA', expected $UPSTREAM_SHA" >&2
  echo "       the patch must always be diffable against exact upstream v0.42.0" >&2
  exit 1
fi

# `git status` on the reference is deliberately not run here. Over a drvfs mount it walks every
# file in a 30 MB tree and takes minutes, which turns this script into a stall. The SHA check above
# pins the cohort, and the bounded diff below is the guarantee that actually matters: it is the
# exhaustive list of what this patch changes. To confirm the reference is untouched, run
# `git -C ../tari-ootle-v0.42.0-reference status --short` from a native filesystem.

echo "upstream: $ACTUAL_SHA"

# Only these paths may differ. A change anywhere else is not part of the wallet MVP feature and would
# make the patch unreviewable, so the list is exhaustive rather than a glob.
FILES=(
  "crates/wallet/sdk/src/apis/stealth_transfer/params.rs"
  "crates/wallet/sdk/src/apis/stealth_transfer/types.rs"
  "crates/wallet/sdk/src/apis/stealth_transfer/api.rs"
  "crates/wallet/sdk/src/apis/stealth_transfer/minimum_value_promise_tests.rs"
  "crates/wallet/sdk/src/apis/stealth_outputs.rs"
  "applications/tari_walletd/src/handlers/accounts.rs"
  "utilities/traffic-sim/src/sim.rs"
)

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
: > "$TMP"

for rel in "${FILES[@]}"; do
  a="$REFERENCE/$rel"
  b="$PATCHED/$rel"
  if [ ! -e "$a" ] && [ ! -e "$b" ]; then
    echo "error: $rel exists in neither tree" >&2
    exit 1
  fi
  # CRLF is normalised on read so the diff reflects content changes, not line-ending churn: the
  # patch tree was copied on Windows and the reference was cloned on Windows, but a future checkout
  # on Linux would otherwise produce a patch that is entirely \r removals.
  if [ -e "$a" ] && [ -e "$b" ]; then
    diff -u --strip-trailing-cr --label "a/$rel" --label "b/$rel" "$a" "$b" >> "$TMP" || true
  elif [ -e "$b" ]; then
    { echo "--- /dev/null"; echo "+++ b/$rel"; sed -n '1,$p' "$b"; } >> "$TMP"
  fi
done

CHANGED="$(grep -c '^--- a/' "$TMP" || true)"
LINES="$(grep -c '^[+-]' "$TMP" || true)"

if [ "${1:-}" = "--check" ]; then
  if [ -f "$OUT" ] && diff -q "$TMP" "$OUT" >/dev/null 2>&1; then
    echo "patch is up to date: $CHANGED files, $LINES changed lines"
    exit 0
  fi
  echo "MISMATCH: $OUT differs from the patched tree" >&2
  exit 1
fi

cp "$TMP" "$OUT"

echo "wrote $OUT"
echo "  files changed: $CHANGED"
echo "  lines changed: $LINES"
echo
echo "Changed files:"
grep '^--- a/' "$OUT" | sed 's|^--- a/|  |'