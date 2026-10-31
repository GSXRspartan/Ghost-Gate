#!/usr/bin/env bash
# Provide the native build dependencies this WSL image lacks, without root.
#
# `sudo` requires a password in this environment, and the end-to-end harness needs two things that are
# not installed:
#
#   libudev-dev              `hidapi` (pulled in by the Minotari base-layer wallet) compiles a C shim
#                            against libudev, so it needs the header, the .pc file and a `libudev.so`
#                            link name. The image ships only the runtime `libudev.so.1`.
#
#   libdbus-1-dev, libsodium-dev
#                            more development files the base-layer node links against; both are resolved
#                            by pkg-config at build time and neither is installed in this image.
#
#   autoconf automake m4 libtool
#                            `libtor-src` builds Tor and a bundled libevent from source, and Tor's
#                            `autogen.sh` runs `autoreconf -i -f -W all,error`. Its tarball is vendored
#                            in the crate, so nothing is downloaded -- but the autotools are not on the
#                            box at all.
#
# The distribution packages are unpacked into a user-writable prefix whose layout mirrors `/usr`, then
# made self-consistent, because Debian's autotools hardcode absolute paths:
#
#   - perl scripts and data files reference /usr/share/{autoconf,automake-1.16,aclocal,libtool} and
#     /usr/bin/{autom4te,autoconf,autoheader,automake,aclocal,m4}. All of those are rewritten to the
#     prefix. (Each script also honours an environment variable for the same thing -- PERL5LIB,
#     ACLOCAL_PATH, AUTOM4TE, AUTOCONF, M4 -- but the data files have no such escape hatch, so the
#     rewrite is the only route that does not need a wrapper for every tool.)
#   - automake installs unversioned `automake`/`aclocal` through update-alternatives, which writes to
#     /etc. Symlinks are created instead.
#   - automake's `config.sub`/`config.guess` are symlinks into /usr/share/misc, which does not exist in
#     this image, so they dangle and `autoreconf` fails with "required file './config.sub' not found".
#     They are replaced with the copies the autoconf package ships in build-aux.
#
# Nothing outside $HOME is modified. Callers need:
#
#   PATH=$PREFIX/usr/bin:$PATH
#   PKG_CONFIG_PATH=$PREFIX/usr/lib/x86_64-linux-gnu/pkgconfig
#   CPATH=$PREFIX/usr/include
#
# `scripts/ootle_e2e.sh` runs this and exports all three. Idempotent; safe to re-run.
#
# Usage: scripts/stage_native_deps.sh
set -euo pipefail

PREFIX="${PREFIX:-${HOME}/gg-local}"
PACKAGES=(libudev-dev autoconf automake m4 libtool libdbus-1-dev libsodium-dev)

log() { printf '%s\n' "$*"; }

# Already staged? Cheap check first, because this runs on every e2e invocation. The stamp lists what was
# unpacked, so adding a package to $PACKAGES re-stages rather than silently doing nothing.
STAMP="$PREFIX/.staged-packages"
need_staging=0
for p in "${PACKAGES[@]}"; do
  if ! grep -qx "$p" "$STAMP" 2>/dev/null; then
    need_staging=1
  fi
done
if [ "$need_staging" = 0 ] && [ -x "$PREFIX/usr/bin/aclocal" ] && [ -x "$PREFIX/usr/bin/automake" ] &&
   [ -f "$PREFIX/usr/share/automake-1.16/config.sub" ] &&
   [ -f "$PREFIX/usr/lib/x86_64-linux-gnu/pkgconfig/libudev.pc" ]; then
  log "native build dependencies already staged in $PREFIX"
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log "=== fetching ${PACKAGES[*]} ==="
cd "$WORK"
apt-get download "${PACKAGES[@]}"

log
log "=== unpacking into $PREFIX (layout mirrors /usr) ==="
for deb in ./*.deb; do
  dpkg-deb -x "$deb" "$PREFIX"
  log "  $(basename "$deb")"
done
: > "$STAMP"
printf '%s\n' "${PACKAGES[@]}" >> "$STAMP"

log
log "=== making the prefix self-consistent ==="

# libudev-dev ships libudev.so as a symlink into /lib, absent here. Point ours at the runtime library
# that is installed so -ludev resolves.
if [ ! -e "$PREFIX/usr/lib/x86_64-linux-gnu/libudev.so" ]; then
  ln -sf /lib/x86_64-linux-gnu/libudev.so.1 "$PREFIX/usr/lib/x86_64-linux-gnu/libudev.so"
fi
# Its .pc hardcodes prefix=/usr.
pc="$PREFIX/usr/lib/x86_64-linux-gnu/pkgconfig/libudev.pc"
if [ -f "$pc" ] && grep -q '^prefix=/usr$' "$pc"; then
  sed -i -e "s|^prefix=/usr|prefix=$PREFIX/usr|" \
    -e "s|^exec_prefix=/usr|exec_prefix=$PREFIX/usr|" \
    -e "s|^libdir=/usr/lib/x86_64-linux-gnu|libdir=$PREFIX/usr/lib/x86_64-linux-gnu|" \
    -e "s|^includedir=/usr/include|includedir=$PREFIX/usr/include|" "$pc"
fi

# Rewrite the autotools' absolute paths. `perl -pi` over the scripts and data files; the pattern is
# anchored on a leading slash so an already-rewritten path cannot match twice.
autotools_files() {
  find "$PREFIX/usr/bin" -maxdepth 1 -type f \( -name 'aclocal*' -o -name 'automake*' -o -name 'auto*' \) 2>/dev/null
  find "$PREFIX/usr/share/autoconf" "$PREFIX/usr/share/automake-1.16" "$PREFIX/usr/share/aclocal" \
    "$PREFIX/usr/share/aclocal-1.16" "$PREFIX/usr/share/libtool" -type f 2>/dev/null
}
mapfile -t files < <(autotools_files)
log "  rewriting hardcoded paths in ${#files[@]} files"
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  grep -q '^#!' "$f" 2>/dev/null || file "$f" 2>/dev/null | grep -qE 'text|script' || continue
  sed -i -e "s|\"/usr/share/autoconf|\"$PREFIX/usr/share/autoconf|g" \
    -e "s|'/usr/share/autoconf|'$PREFIX/usr/share/autoconf|g" \
    -e "s|\"/usr/share/automake-1.16|\"$PREFIX/usr/share/automake-1.16|g" \
    -e "s|'/usr/share/automake-1.16|'$PREFIX/usr/share/automake-1.16|g" \
    -e "s|\"/usr/share/aclocal-1.16|\"$PREFIX/usr/share/aclocal-1.16|g" \
    -e "s|'/usr/share/aclocal-1.16|'$PREFIX/usr/share/aclocal-1.16|g" \
    -e "s|\"/usr/share/aclocal|\"$PREFIX/usr/share/aclocal|g" \
    -e "s|'/usr/share/aclocal|'$PREFIX/usr/share/aclocal|g" \
    -e "s|\"/usr/share/libtool|\"$PREFIX/usr/share/libtool|g" \
    -e "s|'/usr/share/libtool|'$PREFIX/usr/share/libtool|g" \
    -e "s|'/usr/bin/autom4te|'$PREFIX/usr/bin/autom4te|g" \
    -e "s|'/usr/bin/autoconf|'$PREFIX/usr/bin/autoconf|g" \
    -e "s|'/usr/bin/autoheader|'$PREFIX/usr/bin/autoheader|g" \
    -e "s|'/usr/bin/automake|'$PREFIX/usr/bin/automake|g" \
    -e "s|'/usr/bin/aclocal|'$PREFIX/usr/bin/aclocal|g" \
    -e "s|'/usr/bin/m4|'$PREFIX/usr/bin/m4|g" \
    "$f" 2>/dev/null || true
done

# Unversioned names, standing in for update-alternatives.
for tool in automake aclocal; do
  versioned="$(ls "$PREFIX/usr/bin/$tool"-* 2>/dev/null | head -1 || true)"
  if [ -n "$versioned" ] && [ ! -e "$PREFIX/usr/bin/$tool" ]; then
    ln -sf "$(basename "$versioned")" "$PREFIX/usr/bin/$tool"
  fi
done

# Dangling config.sub/config.guess: automake's are symlinks into /usr/share/misc, absent here.
for f in config.sub config.guess; do
  target="$PREFIX/usr/share/automake-1.16/$f"
  if [ ! -e "$target" ] && [ -f "$PREFIX/usr/share/autoconf/build-aux/$f" ]; then
    rm -f "$target"
    cp "$PREFIX/usr/share/autoconf/build-aux/$f" "$target"
    chmod +x "$target"
    log "  replaced dangling $f with autoconf's copy"
  fi
done

log
log "=== verify ==="
export PATH="$PREFIX/usr/bin:$PATH"
export PKG_CONFIG_PATH="$PREFIX/usr/lib/x86_64-linux-gnu/pkgconfig"
for t in aclocal autoconf automake libtoolize m4; do
  printf '  %-12s %s\n' "$t" "$(command -v "$t" || echo MISSING)"
done
printf '  %-12s %s\n' automake "$(automake --version 2>/dev/null | head -1 || echo BROKEN)"
printf '  %-12s %s\n' libudev "$(pkg-config --modversion libudev 2>/dev/null || echo MISSING)"
printf '  %-12s %s\n' config.sub "$( [ -r "$PREFIX/usr/share/automake-1.16/config.sub" ] && echo readable || echo DANGLING)"

log
log "export PATH=$PREFIX/usr/bin:\$PATH"
log "export PKG_CONFIG_PATH=$PREFIX/usr/lib/x86_64-linux-gnu/pkgconfig"
log "export CPATH=$PREFIX/usr/include"
