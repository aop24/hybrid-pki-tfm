#!/usr/bin/env bash
# Block 12 - CRL size as a function of the number of revoked entries, for one model.
# Uses the test certificates crl-<model>-001..100 (issue them first with issue_test_certs.sh).
# Sequence: CRL with the current revocations, then after revoking 1, 10 and 100 test certificates.
# Appends rows to $RES/12-tamanos.csv and keeps every CRL in $MAT/<model>/crl/.
# Usage: 12-crl-series.sh <chimera|classic|composite>
source "$(dirname "$0")/lib.sh"
[ $# -eq 1 ] || die "usage: $0 <model>"
MODEL=$1; check_model "$MODEL"
D=$MAT/$MODEL; mkdir -p "$D/crl" "$TT/work"
CSV=$RES/12-tamanos.csv
[ -f "$CSV" ] || echo "timestamp_utc,model,artifact,variant,revoked_entries,der_bytes,pem_bytes,signature_algorithm,alt_signature,notes" > "$CSV"
for i in $(seq 1 100); do [ -s "$D/certs/crl-$MODEL-$(printf %03d "$i").crt" ] || die "missing test certificate crl-$MODEL-$(printf %03d "$i")"; done

crl_row() { # $1 = label
  local f=$D/crl/crl-$1.der
  local line; line=$("$(dirname "$0")/make_crl.sh" "$MODEL" "$f")
  echo "$line"
  local txt; txt=$(o34 crl -inform DER -in "$f" -noout -text)
  local n; n=$(grep -c 'Serial Number:' <<<"$txt" || true)
  local sig; sig=$(awk -F': ' '/Signature Algorithm/ {print $2; exit}' <<<"$txt")
  local alt; alt=$(grep -qiE 'Alternative Signature|2\.5\.29\.74' <<<"$txt" && echo yes || echo no)
  local pem; pem=$(o34 crl -inform DER -in "$f" -outform PEM | wc -c)
  echo "$(ts_utc),$MODEL,crl,$1,$n,$(wc -c < "$f"),$pem,$sig,$alt,sub CA full CRL" >> "$CSV"
}
certs() { for i in $(seq "$1" "$2"); do echo "$D/certs/crl-$MODEL-$(printf %03d "$i").crt"; done; }

crl_row step0
"$(dirname "$0")/revoke_certs.sh" "$MODEL" keyCompromise $(certs 1 1);   crl_row step1
"$(dirname "$0")/revoke_certs.sh" "$MODEL" keyCompromise $(certs 2 10);  crl_row step10
"$(dirname "$0")/revoke_certs.sh" "$MODEL" keyCompromise $(certs 11 100); crl_row step100
echo "Rows appended to $CSV"
