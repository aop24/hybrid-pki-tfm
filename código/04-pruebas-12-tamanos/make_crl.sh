#!/usr/bin/env bash
# Generates a fresh full CRL for the sub CA of one model and stores it in DER.
#   chimera/classic: EJBCA REST  POST /v1/ca/{dn}/createcrl, then GET /v1/ca/{dn}/getLatestCrl
#   composite:       openssl ca -gencrl (validity 1 day, as EJBCA's default CRL period)
# Prints: entries, DER size, signature algorithm, nextUpdate.
# Usage: make_crl.sh <chimera|classic|composite> <output.der>
source "$(dirname "$0")/lib.sh"
[ $# -eq 2 ] || die "usage: $0 <model> <output.der>"
MODEL=$1; OUT=$2
check_model "$MODEL"
t0=$(now_ms)
if [ "$MODEL" = composite ]; then
  TMP=$(mktemp "$TT/work/crl-XXXXXX.pem")
  o34 ca -config "$COMP_CNF" -name ca_sub -gencrl -crldays 1 -crlexts crl_ext -out "$TMP" >/dev/null 2>&1 \
    || die "openssl ca -gencrl failed"
  o34 crl -in "$TMP" -outform DER -out "$OUT"
  rm -f "$TMP"
else
  DN=$(urlenc "$(ejbca_ca_dn "$MODEL")")
  rest -o /dev/null -X POST "$REST/ca/$DN/createcrl?deltacrl=false" || die "REST createcrl failed"
  rest "$REST/ca/$DN/getLatestCrl?deltaCrl=false" | jq -r '.crl' | base64 -d > "$OUT"
fi
GEN_MS=$(( $(now_ms) - t0 ))
TXT=$(o34 crl -inform DER -in "$OUT" -noout -text) || die "output is not a valid CRL"
ENTRIES=$(grep -c 'Serial Number:' <<<"$TXT" || true)
SIGALG=$(awk -F': ' '/Signature Algorithm/ {print $2; exit}' <<<"$TXT")
NEXT=$(awk -F'Next Update: ' '/Next Update/ {print $2; exit}' <<<"$TXT")
ALT=$(grep -qiE 'Alternative Signature|2\.5\.29\.74' <<<"$TXT" && echo yes || echo no)
echo "$MODEL CRL: entries=$ENTRIES der_bytes=$(wc -c < "$OUT") sig=$SIGALG alt_signature=$ALT next_update='$NEXT' gen_ms=$GEN_MS -> $OUT"
