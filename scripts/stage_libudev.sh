#!/usr/bin/env bash
# Provide libudev's development files without root, for `hidapi`'s build script.
#
# Why this exists: the Minotari base-layer wallet (pulled in by `integration_tests`) depends on
# `hidapi`, whose Linux build script compiles a C shim against libudev. That needs the *dev* files --
# `libudev.h`, `libudev.pc` and a `libudev.so` link name -- and this WSL image ships only the runtime
# `libudev.so.1`. `sudo` requires a password in this environment, so the dev files are unpacked from the
# distribution package into a user-writable prefix and pkg-config is pointed there
# (`PKG_CONFIG_PATH=/home/pdark/gg-local/lib/pkgconfig`, which scripts/ootle_e2e.sh exports).
#
# Idempotent: safe to re-run. Nothing outside $HOME is modified.
#
# Usage: scripts/stage_libudev.sh
set -euo pipefail

DST="${DST:-/home/pdark/gg-local}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if pkg-config --exists libudev 2>/dev/null; then
  echo "libudev is already visible to pkg-config; nothing to do"
  exit 0
fi

echo "=== fetching libudev-dev ==="
cd "$WORK"
apt-get download libudev-dev
deb="$(ls libudev-dev_*.deb | head -1)"
dpkg-deb -x "$deb" extracted

SRC="$WORK/extracted/usr"
echo
echo "=== installing into $DST ==="
mkdir -p "$DST/include" "$DST/lib/pkgconfig"
cp "$SRC/include/libudev.h" "$DST/include/"

# The package ships libudev.so as a symlink into /lib; point ours at the runtime library that is
# actually installed, so -ludev resolves without the dev symlink in the system library directory.
ln -sf /lib/x86_64-linux-gnu/libudev.so.1 "$DST/lib/libudev.so"

# The shipped .pc hardcodes prefix=/usr. Repoint every path at the local prefix.
sed -e "s|^prefix=/usr|prefix=$DST|" \
  -e "s|^exec_prefix=/usr|exec_prefix=$DST|" \
  -e "s|^libdir=/usr/lib/x86_64-linux-gnu|libdir=$DST/lib|" \
  -e "s|^includedir=/usr/include|includedir=$DST/include|" \
  "$SRC/lib/x86_64-linux-gnu/pkgconfig/libudev.pc" > "$DST/lib/pkgconfig/libudev.pc"

echo
echo "=== verify ==="
PKG_CONFIG_PATH="$DST/lib/pkgconfig" pkg-config --exists libudev
echo "  pkg-config sees libudev: $(PKG_CONFIG_PATH="$DST/lib/pkgconfig" pkg-config --modversion libudev)"
echo "  link flags: $(PKG_CONFIG_PATH="$DST/lib/pkgconfig" pkg-config --libs libudev)"
echo
echo "export PKG_CONFIG_PATH=$DST/lib/pkgconfig   # scripts/ootle_e2e.sh already does this"