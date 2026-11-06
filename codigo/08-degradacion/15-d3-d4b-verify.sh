#!/usr/bin/env bash
# Block 15 - D3/D4b: leaves of the TEST Chimera hierarchy made by Forge15 (classical signature always valid)
# checked by the four verifiers. Standard X.509 accepts all of them; only the hybrid verification can tell
# the controls (L0, L2c) from the downgraded or tampered ones (L1-L4).
# Usage: 15-d3-d4b-verify.sh <dir with forged-bundle.crt and L*.crt>
source "$(dirname "$0")/15-common.sh"
[ $# -eq 1 ] || { echo "usage: $0 <forge dir>" >&2; exit 2; }
for f in "$1"/L*.crt; do
  leaf=$(basename "$f" .crt)
  case "$leaf" in L1-*) test=D3 ;; *) test=D4b ;; esac
  for v in OLD OLDOQS NEW phc; do
    name=$(tr 'A-Z' 'a-z' <<<"$v" | sed 's/oldoqs/old+oqs/')
    case "$leaf:$v" in L0-*|L2c-*) exp=accept ;; *:phc) exp=reject ;; *) exp=accept ;; esac
    verify_with "$v" "$f" "$1/forged-bundle.crt"
    [ "$v" = phc ] && DETAIL=$("$PHCV" "$f" "$1/forged-bundle.crt" 2>&1 | grep -m1 -E '\-> INVALID|RESULT')
    record "$test" "$name" chimera-test "$leaf" "$exp" "$RESULT" "$DETAIL"
  done
done
