#!/usr/bin/env bash
# signs a spicy registration with the test authority as der cms with the content attached.
# usage: scripts/sign-registration.sh in.bin out.cms
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)/TestAuthority"
openssl cms -sign -binary -nodetach -md sha256 -outform DER \
  -signer "$DIR/spicy-test-authority.pem" -inkey "$DIR/spicy-test-authority.key.pem" \
  -in "$1" -out "$2"
# verify the signature as privatedrop does
openssl smime -verify -inform DER -in "$2" -CAfile "$DIR/spicy-test-authority.pem" -out /dev/null 2>/dev/null \
  || { echo "verification of $2 failed" >&2; exit 1; }
