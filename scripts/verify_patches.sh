#!/usr/bin/env bash
# Verify the two Ghost Gate patches against the cohort they target, with real exit codes.
#
# Both patches are applied to the cohort tree that the build actually uses, so "it applies" has to mean
# three separate things:
#
#   1. it applies to a clean, LF checkout of the pinned commit a43773e6 (v0.42.0)
#   2. it applies, warning-free, to the pristine reference working tree
#   3. the patched cohort contains exactly what the patch says it contains
#
# (2) is where the Windows mount gets in the way: D: is mounted through WSL, so the reference working tree
# is CRLF while the repository's blobs are LF. A plain `git apply` therefore reports a context mismatch on
# every hunk, and `git apply --check` also prints a "has type 100755, expected 100644" warning for every
# file, because the mount reports everything as executable. Neither is a property of the patch. The
# clean-LF export in (1) is what proves the patch is correct; the CRLF case is handled with
# --ignore-whitespace, which is the narrowest knob that addresses it.
#
# Usage: scripts/verify_patches.sh
set -uo pipefail

WORKSPACE="${WORKSPACE:-/mnt/d/Codex/ghost-gate-workspace}"
PINNED="${PINNED:-a43773e600b9503ed3fadcd3f0048f86131e3644}"
REFERENCE="${REFERENCE:-$WORKSPACE/tari-ootle-v0.42.0-reference}"
PATCHED="${PATCHED:-$WORKSPACE/_ootle-v042-ghost-gate}"
# A clone with the pinned commit's history, used to export an LF-clean copy of it.
UPSTREAM="${UPSTREAM:-${HOME}/Tari-Bug-Hunt/ootle-contest-392d805}"
REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PATCHES=(docs/wallet-mvp.patch docs/ghsa-empty-proof.patch docs/walletd-cli-dup-short.patch)

status=0
fail() {
  printf 'FAIL: %s\n' "$*"
  status=1
}
ok() { printf '  ok  %s\n' "$*"; }

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

printf '=== the reference is the pinned commit ===\n'
head_sha="$(git -C "$REFERENCE" rev-parse HEAD)"
printf '  reference HEAD: %s\n' "$head_sha"
if [ "$head_sha" != "$PINNED" ]; then
  fail "the reference is at $head_sha, not $PINNED"
else
  ok "reference is at the pinned commit $(git -C "$REFERENCE" describe --tags --exact-match HEAD 2>/dev/null || echo v0.42.0)"
fi

printf '\n=== each patch applies to a clean LF export of %s ===\n' "${PINNED:0:8}"
clean="$scratch/clean"
mkdir -p "$clean"
if ! git -C "$UPSTREAM" archive "$PINNED" | tar -x -C "$clean"; then
  fail "could not export $PINNED from $UPSTREAM"
fi
for p in "${PATCHES[@]}"; do
  out="$(git -C "$clean" apply --check -p1 "$REPO/$p" 2>&1)"
  rc=$?
  if [ $rc -eq 0 ]; then
    ok "$p applies (exit $rc, no output)"
  else
    fail "$p does not apply to a clean export (exit $rc): $out"
  fi
  printf '      files: %s\n' "$(grep -c '^+++ ' "$REPO/$p")"
done

printf '\n=== each patch applies to the pristine reference working tree ===\n'
printf '  (CRLF checkout on a Windows mount: --ignore-whitespace, and file-mode warnings are expected)\n'
for p in "${PATCHES[@]}"; do
  out="$(git -C "$REFERENCE" apply --check --ignore-whitespace -p1 "$REPO/$p" 2>&1)"
  rc=$?
  mode_warnings="$(printf '%s\n' "$out" | grep -c 'has type 1007\|has type 1006')"
  if [ $rc -eq 0 ]; then
    ok "$p applies to the reference working tree (exit $rc, $mode_warnings file-mode warning(s))"
  else
    fail "$p does not apply to the reference working tree (exit $rc): $out"
  fi
done

printf '\n=== the patched cohort carries exactly what the patches say ===\n'
# Apply both patches to a clean copy of the pinned commit, then compare the four touched files against
# the patched cohort. This is the check that the tree is not carrying drift the patches do not describe.
expected="$scratch/expected"
cp -r "$clean" "$expected"
for p in "${PATCHES[@]}"; do
  if ! git -C "$expected" apply -p1 "$REPO/$p" >/dev/null 2>&1; then
    fail "could not apply $p to the verification copy"
    continue
  fi
done
# Sanitise: some patch generators leave a timestamp after the path (separated by a tab). A mangled
# name would make the comparison loop hash two unreadable files and "pass" on equal empty input,
# which is a false pass -- so cut at the first tab and refuse a name that is not a real file.
touched="$(for p in "${PATCHES[@]}"; do grep '^+++ ' "$REPO/$p" | sed 's|^+++ b/||; s|\t.*$||'; done)"
mismatches=0
compared=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  compared=$((compared + 1))
  if [ ! -f "$expected/$f" ] || [ ! -f "$PATCHED/$f" ]; then
    fail "patch names a file that does not exist in the export or the cohort: $f"
    continue
  fi
  # Line endings are normalised before comparing: the export is LF (as the repository stores it) and the
  # patched cohort's working tree is CRLF, because D: is mounted through WSL. Anything else -- a real
  # content difference -- still fails.
  if [ "$(tr -d '\r' < "$expected/$f" | sha256sum | cut -d' ' -f1)" = \
       "$(tr -d '\r' < "$PATCHED/$f" | sha256sum | cut -d' ' -f1)" ]; then
    ok "$f matches (CRLF-normalised)"
  else
    fail "$f differs between the patched cohort and the patched export"
    mismatches=$((mismatches + 1))
  fi
done <<< "$touched"
printf '  (%s file(s) compared, %s mismatch(es))\n' "$compared" "$mismatches"

printf '\n'
if [ "$status" = 0 ]; then
  printf 'ALL CHECKS PASSED\n'
else
  printf 'CHECKS FAILED\n'
fi
exit "$status"
