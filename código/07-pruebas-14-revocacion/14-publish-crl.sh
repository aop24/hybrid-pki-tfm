#!/usr/bin/env bash
# Block 14 - generates a fresh CRL of the sub CA of one model and publishes it.
#   chimera/classic: EJBCA REST createcrl (EJBCA serves it itself at /ejbca/publicweb/webdist/certdist)
#   composite:       openssl ca -gencrl, copied to /home/ca/pki/composite/pub/ (served by crl-composite-http on 8081)
# Logs the publication to $RES/14-revocations.csv: epoch_ms = end (CRL fetched back and checked),
# detail gen_start_ms = start. EJBCA serves the new CRL from some point inside that window.
# Usage: 14-publish-crl.sh <chimera|classic|composite>
source "$(dirname "$0")/lib.sh"
[ $# -eq 1 ] || die "usage: $0 <model>"
MODEL=$1; check_model "$MODEL"
PUB=/home/ca/pki/composite/pub; mkdir -p "$PUB"
LOG=$RES/14-revocations.csv
[ -f "$LOG" ] || echo "epoch_ms,utc,event,model,serial,detail" > "$LOG"
OUT=$TT/work/crl-$MODEL-$(date +%s).der
T0=$(now_ms)
"$(dirname "$0")/make_crl.sh" "$MODEL" "$OUT"
[ "$MODEL" = composite ] && install -m 644 "$OUT" "$PUB/tfm-sub-ca-composite.crl"
T=$(date +%s%3N)
echo "$T,$(date -u -d @$((T / 1000)) +%H:%M:%S).$(printf %03d $((T % 1000))),crl_published,$MODEL,,$(o34 crl -inform DER -in "$OUT" -noout -crlnumber | tr -d ' ') gen_start_ms=$T0" >> "$LOG"
echo "$MODEL: CRL published at $(date -u +%H:%M:%S.%3N) UTC (generation started $(( T - T0 )) ms earlier)"
