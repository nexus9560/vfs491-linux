#!/usr/bin/env bash
# Build libfprint 1.94.100 with the VFS491 driver integrated.
#
# Everything the build needs lives under this repository:
#   build/libfprint.tgz            upstream libfprint 1.94.100 tarball
#   build/libfprint-v1.94.100/      patched source tree (extracted on first run)
#   build/lfp-full-build/          meson build directory (default output)
#
# Usage: ./build-libfprint.sh [source-tree]
#        BUILD_DIR=... DRIVERS=... ./build-libfprint.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-$ROOT/build/libfprint-v1.94.100}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build/lfp-full-build}"
DRIVERS="${DRIVERS:-default,vfs491}"
TARBALL="$ROOT/build/libfprint.tgz"
PATCH="$ROOT/libfprint-1.94.100-vfs491.patch"

if [ ! -d "$SRC" ]; then
  if [ ! -f "$TARBALL" ]; then
    echo "Error: $SRC is missing and $TARBALL is not present" >&2
    exit 1
  fi
  echo "Extracting $TARBALL"
  tar -xf "$TARBALL" -C "$ROOT/build"
  echo "Applying $PATCH"
  patch -d "$SRC" -p1 < "$PATCH"
fi

if [ ! -f "$SRC/meson.build" ]; then
  echo "Error: $SRC is not a libfprint source tree" >&2
  exit 1
fi

MESON_ARGS=(
  -Ddrivers="$DRIVERS"
  -Dgtk-examples=false
  -Dintrospection=false
  -Ddoc=false
  -Dinstalled-tests=false
)

if [ -d "$BUILD_DIR" ]; then
  meson setup --reconfigure "$BUILD_DIR" "$SRC" "${MESON_ARGS[@]}"
else
  meson setup "$BUILD_DIR" "$SRC" "${MESON_ARGS[@]}"
fi

ninja -C "$BUILD_DIR"
echo "Built successfully: $BUILD_DIR/libfprint/libfprint-2.so.2.0.0"
