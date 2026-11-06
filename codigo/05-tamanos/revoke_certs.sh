#!/usr/bin/env bash
# Revokes certificates of one model.
#   chimera/classic: EJBCA REST  PUT /v1/certificate/{issuer_dn}/{serial}/revoke
#   composite:       openssl ca -revoke on the Composite sub CA database
# Usage: revoke_certs.sh <chimera|classic|composite> <reason> <cert_file>...
#   reason: unspecified | keyCompromise | superseded | cessationOfOperation
source "$(dirname "$0")/lib.sh"
[ $# -ge 3 ] || die "usage: $0 <model> <reason> <cert_file>..."
MODEL=$1; REASON=$2; shift 2
check_model "$MODEL"
case "$REASON" in
  unspecified) R_EJBCA=UNSPECIFIED ;; keyCompromise) R_EJBCA=KEY_COMPROMISE ;;
  superseded) R_EJBCA=SUPERSEDED ;; cessationOfOperation) R_EJBCA=CESSATION_OF_OPERATION ;;
  *) die "unsupported reason '$REASON'" ;;
esac
LOG=$RES/revocation-log.csv
[ -f "$LOG" ] || echo "timestamp_utc,model,serial,reason,revoke_ms" > "$LOG"

n=0
for CRT in "$@"; do
  SERIAL=$("$OSSL_SYS" x509 -in "$CRT" -noout -serial | cut -d= -f2)
  t0=$(now_ms)
  if [ "$MODEL" = composite ]; then
    o34 ca -config "$COMP_CNF" -name ca_sub -revoke "$CRT" -crl_reason "$REASON" >/dev/null 2>&1 \
      || die "openssl ca -revoke failed for $CRT"
  else
    DN=$(urlenc "$(ejbca_ca_dn "$MODEL")")
    rest -o /dev/null -X PUT "$REST/certificate/$DN/$SERIAL/revoke?reason=$R_EJBCA" \
      || die "REST revocation failed for $CRT (serial $SERIAL)"
  fi
  echo "$(ts_utc),$MODEL,$SERIAL,$REASON,$(( $(now_ms) - t0 ))" >> "$LOG"
  n=$((n + 1))
done
echo "$MODEL: revoked $n certificate(s) ($REASON)"

# openssl ocsp checks index.txt for changes only before waiting for the next connection, so the
# first query after a change still gets the old state. One throwaway query forces the reload.
# Set NUDGE_OCSP=0 to keep the raw behaviour (block 14).
if [ "$MODEL" = composite ] && [ "${NUDGE_OCSP:-1}" = 1 ]; then
  o34 ocsp -issuer "$(sub_ca_cert composite)" -cert "$CRT" -url http://127.0.0.1:2560 -noverify \
    -timeout 5 >/dev/null 2>&1 && echo "composite: OCSP responder index reload triggered" || true
fi
