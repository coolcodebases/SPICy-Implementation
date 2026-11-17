#!/usr/bin/env bash
# builds libspicy_ffi.a for macOS and iOS and copies it with the C header into SPICY_DIR
# SPICY_DIR is the spicy folder inside the privatedrop checkout
# usage: SPICY_DIR=/path/to/that/folder ./scripts/build-apple.sh [all|macos|ios]
# deployment targets are macOS 10.15 and iOS 13.0, as in the privatedrop xcode projects
# the macOS library is universal
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SPICY_DIR="${SPICY_DIR:?set SPICY_DIR to the privatedrop folder that receives the library}"
WHAT="${1:-all}"
export MACOSX_DEPLOYMENT_TARGET=10.15
export IPHONEOS_DEPLOYMENT_TARGET=13.0

cd "$HERE"
build() {
  echo "==> cargo build --release --target $1"
  cargo build --release --lib --target "$1"
}
lib() { echo "$HERE/target/$1/release/libspicy_ffi.a"; }

mkdir -p "$SPICY_DIR/lib" "$SPICY_DIR/Sources/CSpicy/include"
cp "$HERE/include/spicy_ffi.h" "$SPICY_DIR/Sources/CSpicy/include/spicy_ffi.h"

if [[ "$WHAT" == all || "$WHAT" == macos ]]; then
  build aarch64-apple-darwin
  build x86_64-apple-darwin
  mkdir -p "$SPICY_DIR/lib/macOS"
  lipo -create "$(lib aarch64-apple-darwin)" "$(lib x86_64-apple-darwin)" -output "$SPICY_DIR/lib/macOS/libspicy_ffi.a"
fi
if [[ "$WHAT" == all || "$WHAT" == ios ]]; then
  build aarch64-apple-ios
  mkdir -p "$SPICY_DIR/lib/iOS"
  cp "$(lib aarch64-apple-ios)" "$SPICY_DIR/lib/iOS/libspicy_ffi.a"
  build aarch64-apple-ios-sim
  mkdir -p "$SPICY_DIR/lib/iOS Simulator"
  cp "$(lib aarch64-apple-ios-sim)" "$SPICY_DIR/lib/iOS Simulator/libspicy_ffi.a"
fi

# folder names match xcode's $(PLATFORM_DISPLAY_NAME)
for f in "$SPICY_DIR"/lib/*/libspicy_ffi.a; do
  printf '%s: ' "${f#$SPICY_DIR/}"; lipo -info "$f" | sed 's/.*: //'
done
