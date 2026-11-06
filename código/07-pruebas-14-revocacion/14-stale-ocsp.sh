#!/usr/bin/env bash
# Block 14 - stale first answer of the openssl ocsp responder after a revocation WITHOUT the index
# reload nudge. Everything runs on the CA (one clock): query, revoke (NUDGE_OCSP=0), wait <wait_s>,
# then <after> queries. If the responder only reloads index.txt after serving a request, the first
# query after the revocation still answers "good" however long the wait is.
# Usage: 14-stale-ocsp.sh <cn of $MAT/composite/certs> [wait_s=10] [after=3]
source "$(dirname "$0")/lib.sh"
[ $# -ge 1 ] || die "usage: $0 <cn> [wait_s] [after]"
CN=$1; WAIT=${2:-10}; AFTER=${3:-3}
CRT=$MAT/composite/certs/$CN.crt
[ -s "$CRT" ] || die "no certificate $CRT"
SERIAL=$(o34 x509 -in "$CRT" -noout -serial | cut -d= -f2)
CSV=$RES/14-stale-ocsp.csv
[ -f "$CSV" ] || echo "epoch_ms,utc,cn,step,ocsp_status" > "$CSV"
query() {
  local t st
  t=$(now_ms)
  st=$(o34 ocsp -issuer "$(sub_ca_cert composite)" -cert "$CRT" -url http://127.0.0.1:2560 \
       -CAfile "$CA_CERTS/ca-bundle-composite.crt" 2>/dev/null | awk -v c="$CRT:" '$1 == c {print $2}')
  echo "$t,$(date -u -d @$((t / 1000)) +%H:%M:%S).$(printf %03d $((t % 1000))),$CN,$1,${st:-error}" >> "$CSV"
  echo "  $(date -u -d @$((t / 1000)) +%H:%M:%S).$(printf %03d $((t % 1000))) UTC  $1: ${st:-error}"
}
echo "stale OCSP test on $CN (serial $SERIAL), wait ${WAIT} s after revoking"
query before
NUDGE_OCSP=0 "$(dirname "$0")/14-revoke.sh" composite "$SERIAL"
sleep "$WAIT"
for i in $(seq 1 "$AFTER"); do query "after-$i"; done
echo "rows appended to $CSV"
