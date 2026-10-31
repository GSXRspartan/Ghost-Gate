#!/usr/bin/env bash
# Confirm the machine is idle before starting a heavyweight build.
#
# Two rules this enforces, both learned the hard way on a 5 GB host, and both still true on a bigger one:
#   - exactly one Cargo build at a time. Two at once is what starved WSL of memory and, in one case,
#     restarted Windows outright.
#   - no unrelated work in flight. A stray `cargo test --no-run` linker was once found holding 90% of
#     the only core for 56 minutes while an intended build timed out behind it.
#
# Worth running on a shared machine even when memory looks fine: another WSL user's test run is easy to
# miss and its output goes to their log, not this one.
#
# Usage: scripts/build_preflight.sh

set -uo pipefail

echo "=== cargo / rustc / linker processes ==="
found=0
while read -r pid elapsed args; do
  [ -z "$pid" ] && continue
  found=1
  echo "  pid=$pid elapsed=$elapsed"
  echo "    $args"
done < <(ps -eo pid,etime,args | grep -E 'cargo|rustc|rust-lld|cc1plus' | grep -v grep | cut -c1-150)

if [ "$found" = 0 ]; then
  echo "  none"
fi

echo
echo "=== intended builds running? ==="
if pgrep -f 'cargo test -p ghost-gate-tests' >/dev/null 2>&1; then
  echo "  a Ghost Gate build is already running -- do not start a second"
  exit 1
fi
echo "  no Ghost Gate build running"

echo
echo "=== unrelated cargo work (should be none) ==="
unrelated=$(ps -eo args | grep -E '^\s*/?.*cargo ' | grep -v grep \
  | grep -vE 'cargo test -p ghost-gate-tests|cargo metadata' || true)
if [ -n "$unrelated" ]; then
  echo "$unrelated" | sed 's/^/  /'
  echo "  ^ not ours. Confirm it is safe to leave running before starting a build."
else
  echo "  none"
fi

echo
echo "=== WSL memory ==="
free -m | sed -n '1,3p'

echo
echo "=== target caches (must be preserved) ==="
# One target directory for all Gate 3 work, on the Linux filesystem rather than the HDD-mounted D: drive.
# The cohort crates are only compiled once per target directory, so pointing a command anywhere else
# silently recompiles the whole Ootle layer.
for d in "${HOME}/gg-ootle-target"; do
  if [ -d "$d" ]; then
    echo "  $d  $(du -sh "$d" 2>/dev/null | cut -f1)"
  else
    echo "  $d  (absent)"
  fi
done
