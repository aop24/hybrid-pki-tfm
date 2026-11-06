#!/usr/bin/env bash
# Block 15 - D1: the same real certificate of each model checked by four verifiers:
#   old     = system OpenSSL 3.0.13, original openssl.cnf, no oqs-provider (a legacy verifier)
#   old+oqs = system OpenSSL 3.0.13 + oqs-provider (system openssl.cnf of the PQC runtime)
#   new     = OpenSSL 3.4.0 + oqs-provider
#   phc     = phc-verify (standard X.509 + hybrid verification of every link)
# Usage: 15-d1-verifiers.sh     (on a client; uses $HOME/pki/certs/<host>-<model>.crt)
source "$(dirname "$0")/15-common.sh"
echo "providers old:     $(OLD list -providers 2>&1 | grep -E '^\s+[a-z]' | tr -s ' \n' ' ')"
echo "providers old+oqs: $(OLDOQS list -providers 2>&1 | grep -E '^\s+[a-z]' | tr -s ' \n' ' ')"
echo "versions: $(OLD version) / $(NEW version)"
for m in classic chimera composite; do
  c=$P/certs/$ME-$m.crt; b=$(bundle "$m")
  for v in OLD OLDOQS NEW phc; do
    case "$v:$m" in OLD:composite) exp=reject ;; OLDOQS:composite) exp=unknown ;; *) exp=accept ;; esac
    name=$(tr 'A-Z' 'a-z' <<<"$v" | sed 's/oldoqs/old+oqs/')
    verify_with "$v" "$c" "$b"
    record D1 "$name" "$m" "$(basename "$c")" "$exp" "$RESULT" "$DETAIL"
  done
done
