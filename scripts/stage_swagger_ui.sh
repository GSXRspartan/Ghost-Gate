#!/usr/bin/env bash
# Diagnose why utoipa-swagger-ui's build script cannot fetch its archive, and stage the archive
# locally so the build stops depending on github.com at build time.
#
# The crate honours SWAGGER_UI_DOWNLOAD_URL when it starts with `file:`, copying from a local path
# instead of downloading. That is the escape hatch: fetch once, build offline forever after.
set -uo pipefail

VERSION=v5.17.14
URL="https://github.com/swagger-api/swagger-ui/archive/refs/tags/${VERSION}.zip"
DEST="${DEST:-/root/gg-cache/swagger-ui-${VERSION}.zip}"
mkdir -p "$(dirname "$DEST")"

echo "=== direct fetch ==="
curl -sSL -o "$DEST" --max-time 120 -w 'http=%{http_code} size=%{size_download}\n' "$URL" 2>&1 | tail -2

if [ ! -s "$DEST" ]; then
  echo "  fetch produced nothing"
  exit 1
fi

echo
echo "=== archive sanity ==="
file "$DEST" 2>/dev/null || true
ls -l "$DEST"
# A valid zip starts with "PK". Anything else means we saved an error page.
magic=$(head -c 2 "$DEST")
if [ "$magic" != "PK" ]; then
  echo "  NOT a zip (starts with '$magic') -- likely an error page:"
  head -c 300 "$DEST"
  echo
  exit 1
fi
echo "  zip header OK"

echo
echo "=== required top-level entry ==="
unzip -l "$DEST" 2>/dev/null | grep -m3 "dist/" || {
  echo "  no dist/ entries found"
  unzip -l "$DEST" 2>/dev/null | head -8
}