#!/usr/bin/env bash
# precomputes and signs spicy identity registrations for privatedrop's test identities.
# for each count K the identifiers are read from Shared/Resources/K_other.plist.
# it writes Resources/Identities/K_spicy_{sender,receiver}.cms and K_spicy_{sender,receiver}_secret.bin.
# the .cms files are signed by the test authority.
# SPICY_FFI_DIR must point to the privatedrop folder of the spicy repository.
# usage: scripts/make-identity-resources.sh [K ...], with K = 1 5 10 20 by default.
# usage: MAX_N=15000 scripts/make-identity-resources.sh 1 10
# usage: N_G=9799 scripts/make-identity-resources.sh sets n_g explicitly.
# usage: LEVEL=wic scripts/make-identity-resources.sh writes K_spicy_wic_{sender,receiver}.*
# by default n_g is the recommended one for senders of up to MAX_M and receivers of up to MAX_N items.
# the party identity is privatedrop-identity-K.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
FFI="${SPICY_FFI_DIR:?set SPICY_FFI_DIR to the privatedrop folder of the spicy repository}"
OUT="$HERE/Resources/Identities"
MAX_M="${MAX_M:-20}"
MAX_N="${MAX_N:-1024}"
N_G="${N_G:-}"
LEVEL="${LEVEL:-cic}"
case "$LEVEL" in cic) TAG=spicy ;; wic) TAG=spicy_wic ;; *) echo "LEVEL must be cic or wic" >&2; exit 2 ;; esac
COUNTS=("$@"); [[ ${#COUNTS[@]} -gt 0 ]] || COUNTS=(1 5 10 20)
mkdir -p "$OUT"
(cd "$FFI" && cargo build --release --bin spicy-precompute -q)
PRE="$FFI/target/release/spicy-precompute"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
for K in "${COUNTS[@]}"; do
  python3 -I -c 'import plistlib,sys; print("\n".join(plistlib.load(open(sys.argv[1],"rb"))["ids"]))' \
    "$HERE/../Shared/Resources/${K}_other.plist" > "$TMP/ids.txt"
  for ROLE in sender receiver; do
    ARGS=(--role "$ROLE" --out-dir "$TMP" --prefix "$ROLE" --ids-file "$TMP/ids.txt" --id "privatedrop-identity-$K" --level "$LEVEL")
    if [[ -n $N_G ]]; then ARGS+=(--n-g "$N_G"); else ARGS+=(--max-m "$MAX_M" --max-n "$MAX_N"); fi
    "$PRE" "${ARGS[@]}"
    "$HERE/scripts/sign-registration.sh" "$TMP/${ROLE}_spicy_registration.bin" "$OUT/${K}_${TAG}_${ROLE}.cms"
    cp "$TMP/${ROLE}_spicy_secret.bin" "$OUT/${K}_${TAG}_${ROLE}_secret.bin"
  done
done
ls -l "$OUT"
