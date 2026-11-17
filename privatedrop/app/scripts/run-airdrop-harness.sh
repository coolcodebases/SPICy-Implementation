#!/usr/bin/env bash
# builds and runs AirDropHarness for x86_64, under rosetta on apple silicon.
# e2e runs AirDropE2E, the privatedrop psi flow with the spicy backend and the signed identity resources.
# compare runs LegacyVsSpicy, the original psi and spicy on identical inputs.
# usage: scripts/run-airdrop-harness.sh [e2e|compare|build] [args...]
# it needs the rust library in lib/macOS and rosetta 2.
set -euo pipefail
SPICY="$(cd "$(dirname "$0")/.." && pwd)"
H="$SPICY/AirDropHarness"
B="$SPICY/../privatedrop-base/Sources"
S="$H/Sources"
ln -sfn "$B/PSI/Relic" "$S/Relic"
ln -sfn "$B/OpenSSL/OpenSSLLib" "$S/OpenSSLLib"
ln -sfn "$B/libarchive/LibArc" "$S/LibArc"
ln -sfn "$SPICY/Sources/CSpicy" "$S/CSpicy"
ln -sfn "$SPICY/Sources/SpicyPSI" "$S/SpicyPSI"
rm -rf "$S/RelicImpl" "$S/OpenSSLImpl" "$S/PSI" "$S/OpenSSL" "$S/Libarchive" "$S/PrivateDrop_Base"
mkdir -p "$S/RelicImpl/include" "$S/OpenSSLImpl/include" "$S/PSI" "$S/OpenSSL" "$S/Libarchive" "$S/PrivateDrop_Base"
touch "$S/RelicImpl/include/RelicImpl.h" "$S/OpenSSLImpl/include/OpenSSLImpl.h"
ln -s "$B/PSI/Relic/relic_wrapper.c" "$S/RelicImpl/"
for f in cms_verify_wrapper.c cms_sign_wrapper.c d2i_wrapper.c; do ln -s "$B/OpenSSL/OpenSSLLib/$f" "$S/OpenSSLImpl/"; done
for f in "$B"/PSI/*.swift; do ln -s "$f" "$S/PSI/"; done
for f in "$B"/OpenSSL/*.swift; do ln -s "$f" "$S/OpenSSL/"; done
for f in "$B"/libarchive/*.swift; do ln -s "$f" "$S/Libarchive/"; done
find "$B/PrivateDrop Base" -name '*.swift' | while read -r f; do
  rel="${f#$B/PrivateDrop Base/}"; ln -s "$f" "$S/PrivateDrop_Base/${rel//\//_}"
done
for f in "$SPICY"/Sources/SpicyPSI/*.swift "$SPICY"/PrivateDropBase/*.swift; do
  ln -s "$f" "$S/PrivateDrop_Base/spicy_$(basename "$f")"
done

# self-signed tls identities with the passphrase privatedrop expects
TLS="$H/.build/tls"
if [[ ! -f "$TLS/ServerCertificate.p12" ]]; then
  mkdir -p "$TLS"
  for who in Server Client; do
    openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj "/CN=PrivateDrop Harness $who" \
      -keyout "$TLS/$who.key" -out "$TLS/$who.pem" 2>/dev/null
    openssl pkcs12 -export -inkey "$TLS/$who.key" -in "$TLS/$who.pem" -passout pass:opendrop \
      -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 -out "$TLS/${who}Certificate.p12"
  done
fi
export HARNESS_TLS_DIR="$TLS"

cd "$H"
swift build -c release --arch x86_64 2>&1 | grep -E "error|warning: unable|Compiling (AirDropE2E|LegacyVsSpicy)|Build complete" || true
BIN="$(swift build -c release --arch x86_64 --show-bin-path)"
WHAT="${1:-all}"; shift || true
case "$WHAT" in
  build) ;;
  e2e) "$BIN/AirDropE2E" "$@" ;;
  compare) "$BIN/LegacyVsSpicy" "$@" ;;
  all) "$BIN/AirDropE2E"; "$BIN/LegacyVsSpicy" ;;
esac
