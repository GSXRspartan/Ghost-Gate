#!/usr/bin/env bash
# Show how utoipa-swagger-ui's build script obtains the Swagger UI bundle, and whether that can be
# satisfied without reaching github.com.
#
# Its build script downloads a release zip from GitHub at build time. If github.com is unreachable
# from this network, the Ootle integration harness cannot build at all, and the question becomes
# whether the crate honours a pre-supplied archive or an alternate URL.
set -uo pipefail

F=$(ls -d /root/.cargo/registry/src/*/utoipa-swagger-ui-9.0.2 2>/dev/null | head -1)
if [ -z "$F" ]; then
  echo "utoipa-swagger-ui-9.0.2 source not present in the cargo registry"
  exit 1
fi
echo "source: $F"
echo
echo "=== env vars and paths it reads ==="
grep -n "env::var\|OUT_DIR\|CUR_DIR" "$F/build.rs" | head -20
echo
echo "=== archive acquisition ==="
grep -n "fn get_zip_archive" -A 40 "$F/build.rs" | head -50
echo
echo "=== connectivity ==="
for url in https://github.com https://crates.io https://static.crates.io; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 "$url" 2>/dev/null)
  echo "  $url -> ${code:-unreachable}"
done