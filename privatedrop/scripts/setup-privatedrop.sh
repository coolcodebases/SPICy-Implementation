#!/usr/bin/env bash
# sets up privatedrop with spicy as its psi
# clones privatedrop and privatedrop-base at the commits the patches apply to and applies the patches
# copies app/ into the checkout as spicy/ and builds libspicy_ffi.a
# creates the test signing authority and the test identities
# usage: ./scripts/setup-privatedrop.sh DEST [macos|ios|all]
# needs git, openssl, python3 and a rust toolchain with the apple targets
# rustup target add x86_64-apple-darwin aarch64-apple-darwin
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:?usage: setup-privatedrop.sh DEST [macos|ios|all]}"
TARGETS="${2:-macos}"
PRIVATEDROP_COMMIT=fb47cb680fcf929b83fe86f619939de1a35bcc19
BASE_COMMIT=43f6bbccba7d78358a673054bbbd0befd0d9ca85

git clone https://github.com/seemoo-lab/privatedrop.git "$DEST"
cd "$DEST"
git checkout -q "$PRIVATEDROP_COMMIT"
git submodule update --init privatedrop-base
git -C privatedrop-base checkout -q "$BASE_COMMIT"

git apply "$HERE/patches/privatedrop.patch"
git -C privatedrop-base apply "$HERE/patches/privatedrop-base.patch"
cp -R "$HERE/app" "$DEST/spicy"

SPICY_DIR="$DEST/spicy" "$HERE/scripts/build-apple.sh" "$TARGETS"

"$DEST/spicy/scripts/make-test-authority.sh"
SPICY_FFI_DIR="$HERE" "$DEST/spicy/scripts/make-identity-resources.sh"
SPICY_FFI_DIR="$HERE" LEVEL=wic "$DEST/spicy/scripts/make-identity-resources.sh"

echo "privatedrop with spicy is in $DEST"
