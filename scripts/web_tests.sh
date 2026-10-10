#!/usr/bin/env bash
# Runs the Ghost Gate provider-layer tests with `node --test`.
#
# The web layer has no build step on purpose, so its tests are plain node tests against the pinned
# provider contract. They need a node binary; on this box that lives in the Windows toolchain, so
# the script looks in the usual places rather than assuming `node` is on PATH.
#
# A green run means the adapters behave per the pinned contract and the mode matrix holds. It does
# NOT mean a live wallet was exercised -- see docs/PROVIDER_COMPATIBILITY.md §8 for exactly what was
# and was not tested.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../web"

NODE=""
for candidate in node "/mnt/c/Program Files/nodejs/node.exe"; do
  if command -v "$candidate" >/dev/null 2>&1 || [ -x "$candidate" ]; then
    NODE="$candidate"
    break
  fi
done
if [ -z "$NODE" ]; then
  echo "no node found: install node or point PATH at it" >&2
  exit 1
fi

exec "$NODE" --test js/ghost/test.js "$@"
