#!/usr/bin/env bash
# Block 15 - common settings on the client VMs. Sourced, not executed.
set -uo pipefail
P=$HOME/pki; RES=$HOME/tfm-results; ME=$(hostname)
mkdir -p "$RES"
CSV=$RES/15-compat.csv
[ -f "$CSV" ] || echo "timestamp_utc,test,host,verifier,model,artifact,expected,result,detail" > "$CSV"
# The four verifiers. The system OpenSSL 3.0.13 is run without LD_LIBRARY_PATH (block 09 finding);
# "old" uses the original Ubuntu openssl.cnf (no oqs-provider), "old+oqs" the system one with it.
OLD()    { env -u LD_LIBRARY_PATH OPENSSL_CONF=/etc/ssl/openssl.cnf.orig /usr/bin/openssl "$@"; }
OLDOQS() { env -u LD_LIBRARY_PATH /usr/bin/openssl "$@"; }
NEW()    { LD_LIBRARY_PATH=/opt/openssl32/lib64:/opt/openssl32/lib /opt/openssl32/bin/openssl "$@"; }
PHCV=$HOME/phc-client/build/phc-verify
bundle() { case "$1" in chimera) echo "$P/ca-certs/ca-bundle-hybrid.crt" ;; *) echo "$P/ca-certs/ca-bundle-$1.crt" ;; esac; }
# record <test> <verifier> <model> <artifact> <expected> <result> <detail>
record() {
  local d=${7//,/;}; d=${d//$'\n'/ | }
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$1,$ME,$2,$3,$4,$5,$6,$d" >> "$CSV"
  printf '%-4s %-8s %-10s %-34s expected=%-7s result=%-7s %s\n' "$1" "$2" "$3" "$4" "$5" "$6" "${7:0:110}"
}
# verify_with <verifier> <cert> <bundle> -> sets RESULT (accept|reject) and DETAIL
verify_with() {
  local out
  case "$1" in
    phc) out=$("$PHCV" "$2" "$3" 2>&1); if [ $? -eq 0 ]; then RESULT=accept; else RESULT=reject; fi
         DETAIL=$(grep -E '^1\)|RESULT|invalid|INVALID|downgrade|missing' <<<"$out" | head -3 | tr '\n' ' ') ;;
    *)   out=$("$1" verify -CAfile "$3" "$2" 2>&1); if [ $? -eq 0 ] && grep -q ': OK$' <<<"$out"; then RESULT=accept; else RESULT=reject; fi
         DETAIL="$(grep -m1 -E '^error [0-9]+ at' <<<"$out") $(grep -m1 'routines' <<<"$out" | sed -E 's/^[0-9A-F]+:error:[0-9A-F]+://')"
         [ "$RESULT" = accept ] && DETAIL=OK ;;
  esac
}
