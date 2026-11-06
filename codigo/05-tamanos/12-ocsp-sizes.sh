#!/usr/bin/env bash
# Block 12 - size of OCSP requests and responses for one model (status good and revoked).
#   good    : the real client certificate client-01-<model>.crt ($TT/samples)
#   revoked : the test certificate crl-<model>-001 (revoked in 12-crl-series.sh)
#   chimera/classic -> EJBCA OCSP (http://127.0.0.1:8080/ejbca/publicweb/status/ocsp)
#   composite       -> openssl ocsp responder (http://127.0.0.1:2560)
# Requests carry a nonce (openssl ocsp default). Responses are verified against the CA bundle.
# Appends rows to $RES/12-tamanos.csv and keeps request/response DER in $MAT/<model>/ocsp/.
# Usage: 12-ocsp-sizes.sh <chimera|classic|composite>
source "$(dirname "$0")/lib.sh"
[ $# -eq 1 ] || die "usage: $0 <model>"
MODEL=$1; check_model "$MODEL"
CSV=$RES/12-tamanos.csv
D=$MAT/$MODEL/ocsp; mkdir -p "$D"
case "$MODEL" in
  composite) URL=http://127.0.0.1:2560; BUNDLE=$CA_CERTS/ca-bundle-composite.crt ;;
  chimera)   URL=http://127.0.0.1:8080/ejbca/publicweb/status/ocsp; BUNDLE=$CA_CERTS/ca-bundle-hybrid.crt ;;
  classic)   URL=http://127.0.0.1:8080/ejbca/publicweb/status/ocsp; BUNDLE=$CA_CERTS/ca-bundle-classic.crt ;;
esac
ISSUER=$(sub_ca_cert "$MODEL")

query() { # $1 label, $2 cert
  local req=$D/ocsp-$1.req.der resp=$D/ocsp-$1.resp.der out
  out=$(o34 ocsp -issuer "$ISSUER" -cert "$2" -url "$URL" -CAfile "$BUNDLE" -reqout "$req" -respout "$resp" 2>&1) \
    || die "OCSP query failed ($1): $out"
  local status; status=$(awk -F': ' -v c="$2" 'index($0, c) == 1 {print $2; exit}' <<<"$out")
  local verify; verify=$(grep -q 'Response verify OK' <<<"$out" && echo verify_ok || echo verify_FAILED)
  local txt; txt=$(o34 ocsp -respin "$resp" -resp_text -noverify 2>/dev/null)
  local sig; sig=$(awk -F': ' '/Signature Algorithm/ {print $2; exit}' <<<"$txt")
  local ncert; ncert=$(grep -c '^ *Certificate:' <<<"$txt" || true)
  local next; next=$(awk -F'Next Update: ' '/Next Update/ {print $2; exit}' <<<"$txt")
  echo "$(ts_utc),$MODEL,ocsp_request,$1,,$(wc -c < "$req"),,,,with nonce" >> "$CSV"
  echo "$(ts_utc),$MODEL,ocsp_response,$1,,$(wc -c < "$resp"),,$sig,no,status=$status; $verify; embedded_certs=$ncert; next_update=$next" >> "$CSV"
  echo "$MODEL OCSP $1: request=$(wc -c < "$req") B response=$(wc -c < "$resp") B status=$status sig=$sig certs=$ncert $verify next_update='$next'"
}
query good "$TT/samples/client-01-$MODEL.crt"
query revoked "$MAT/$MODEL/certs/crl-$MODEL-001.crt"
