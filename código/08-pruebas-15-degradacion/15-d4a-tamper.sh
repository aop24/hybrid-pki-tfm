#!/usr/bin/env bash
# Block 15 - D4a: real certificates of this client manipulated WITHOUT re-signing (15-tamper.py), checked
# by the four verifiers of D1. Every verifier must reject them (the classical signature no longer matches).
# Usage: 15-d4a-tamper.sh
source "$(dirname "$0")/15-common.sh"
D=$HOME/tfm-tests/work/15-tampered; mkdir -p "$D"
ops() { case "$1" in chimera) echo "drop-altsig flip-altsig flip-sig-first flip-sig-last" ;; *) echo "flip-sig-first flip-sig-last" ;; esac; }
for m in classic chimera composite; do
  for op in $(ops "$m"); do
    out=$D/$ME-$m-$op.crt
    python3 -I "$(dirname "$0")/15-tamper.py" "$P/certs/$ME-$m.crt" "$op" "$out" >/dev/null || { echo "tamper failed: $m $op" >&2; continue; }
    for v in OLD OLDOQS NEW phc; do
      name=$(tr 'A-Z' 'a-z' <<<"$v" | sed 's/oldoqs/old+oqs/')
      verify_with "$v" "$out" "$(bundle "$m")"
      record D4a "$name" "$m" "$op" reject "$RESULT" "$DETAIL"
    done
  done
done
