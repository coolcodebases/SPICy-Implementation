#!/usr/bin/env bash
# creates the test signing authority for spicy identity registrations in TestAuthority.
# it is a self-signed certificate with the profile of privatedrop's original psi signing certificate.
# usage: scripts/make-test-authority.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)/TestAuthority"
mkdir -p "$DIR"
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$DIR/spicy-test-authority.key.pem" -out "$DIR/spicy-test-authority.pem" \
  -subj "/CN=PrivateDrop SPICy Test Authority/O=PrivateDrop Test/C=DE" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=critical,emailProtection"
chmod 600 "$DIR/spicy-test-authority.key.pem"
openssl x509 -in "$DIR/spicy-test-authority.pem" -noout -subject -dates
