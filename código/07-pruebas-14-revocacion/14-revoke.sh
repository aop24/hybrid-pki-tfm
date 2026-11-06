#!/usr/bin/env bash
# Block 14 - revokes ONE certificate by serial number and logs the exact time (epoch ms, UTC).
#   chimera/classic: EJBCA REST revocation (issuer = sub CA of the model)
#   composite:       openssl ca -revoke on /home/ca/pki/composite/sub/newcerts/<SERIAL>.pem
# The OCSP index reload nudge of revoke_certs.sh is applied unless NUDGE_OCSP=0.
# Usage: 14-revoke.sh <chimera|classic|composite> <serial_hex>
source "$(dirname "$0")/lib.sh"
[ $# -eq 2 ] || die "usage: $0 <model> <serial_hex>"
MODEL=$1; SERIAL=$(tr 'a-f' 'A-F' <<<"$2"); check_model "$MODEL"
[[ "$SERIAL" =~ ^[0-9A-F]{2,40}$ ]] || die "invalid serial"
LOG=$RES/14-revocations.csv
[ -f "$LOG" ] || echo "epoch_ms,utc,event,model,serial,detail" > "$LOG"
if [ "$MODEL" = composite ]; then
  CRT=/home/ca/pki/composite/sub/newcerts/$SERIAL.pem
  [ -s "$CRT" ] || die "no issued certificate $CRT"
  T=$(date +%s%3N)
  "$(dirname "$0")/revoke_certs.sh" composite keyCompromise "$CRT"
else
  DN=$(urlenc "$(ejbca_ca_dn "$MODEL")")
  T=$(date +%s%3N)
  rest -o /dev/null -X PUT "$REST/certificate/$DN/$SERIAL/revoke?reason=KEY_COMPROMISE" || die "REST revocation failed"
fi
T2=$(date +%s%3N)
echo "$T,$(date -u -d @$((T / 1000)) +%H:%M:%S).$(printf %03d $((T % 1000))),revoked,$MODEL,$SERIAL,call_ms=$((T2 - T)) nudge=${NUDGE_OCSP:-1}" >> "$LOG"
echo "$MODEL serial $SERIAL revoked at $(date -u -d @$((T / 1000)) +%H:%M:%S).$(printf %03d $((T % 1000))) UTC (call $((T2 - T)) ms)"
