#!/usr/bin/env bash
# Issues <count> test end-entity certificates of one model, named <prefix>-001 .. <prefix>-NNN.
#   chimera/classic: EC P-256 key + one EJBCA REST call (pkcs10enroll creates the end entity)
#   composite:       p384_mldsa65 key + sign_composite.sh (openssl ca, same path as certdist)
# Keys stay in $MAT/<model>/keys (700). Already issued names are skipped.
# Usage: issue_test_certs.sh <chimera|classic|composite> <prefix> <count>
source "$(dirname "$0")/lib.sh"
[ $# -eq 3 ] || die "usage: $0 <chimera|classic|composite> <prefix> <count>"
MODEL=$1; PREFIX=$2; COUNT=$3
check_model "$MODEL"
[[ "$PREFIX" =~ ^[a-z0-9-]{1,40}$ ]] || die "invalid prefix"
D=$MAT/$MODEL
mkdir -p "$D/keys" "$D/csr" "$D/certs"; chmod 700 "$D/keys"
LOG=$RES/issuance-log.csv
[ -f "$LOG" ] || echo "timestamp_utc,model,path,cn,issue_ms,cert_der_bytes" > "$LOG"

ok=0; t_all=$(now_ms)
for i in $(seq 1 "$COUNT"); do
  CN=$(printf '%s-%03d' "$PREFIX" "$i")
  KEY=$D/keys/$CN.key; CSR=$D/csr/$CN.csr; CRT=$D/certs/$CN.crt
  [ -s "$CRT" ] && continue
  if [ "$MODEL" = composite ]; then
    o34 req -new -newkey p384_mldsa65 -nodes -keyout "$KEY" -subj "/CN=$CN/O=UPV-TFM/C=ES" -out "$CSR" 2>/dev/null
    t0=$(now_ms)
    "$SIGN_COMPOSITE" "$CN" "$CSR" "$CRT" >/dev/null || die "composite issuance failed for $CN"
    t1=$(now_ms); path=openssl-ca
  else
    "$OSSL_SYS" req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$KEY" \
      -subj "/CN=$CN/O=UPV-TFM/C=ES" -out "$CSR" 2>/dev/null
    OTP=$("$OSSL_SYS" rand -hex 12)
    PAYLOAD=$(jq -n --rawfile csr "$CSR" --arg ca "$(ejbca_ca_name "$MODEL")" --arg u "$CN" --arg p "$OTP" \
      '{certificate_request:$csr, certificate_profile_name:"PHCCLIENT", end_entity_profile_name:"PHCPROFILE",
        certificate_authority_name:$ca, username:$u, password:$p, include_chain:false}')
    t0=$(now_ms)
    RESP=$(rest -H 'Content-Type: application/json' -X POST --data-binary "$PAYLOAD" "$REST/certificate/pkcs10enroll") \
      || die "REST enrollment failed for $CN: $RESP"
    t1=$(now_ms); path=rest
    jq -r '.certificate' <<<"$RESP" | base64 -d | "$OSSL_SYS" x509 -inform DER -out "$CRT" \
      || die "cannot decode certificate for $CN"
  fi
  chmod 600 "$KEY"
  echo "$(ts_utc),$MODEL,$path,$CN,$((t1 - t0)),$(der_size "$CRT")" >> "$LOG"
  ok=$((ok + 1))
done
echo "$MODEL: issued $ok new certificate(s) with prefix '$PREFIX' in $(( ($(now_ms) - t_all) / 1000 )) s -> $D/certs"
