#!/usr/bin/env bash
# Block 13 - A) signature primitives and B) certificate verification, on this VM.
# Raw samples: $RES/13-raw-sig.csv and $RES/13-raw-verify.csv
# Usage: 13-run-local.sh   (N, WARMUP, COLD, ALGS and PARTS can be overridden in the environment)
source "$(dirname "$0")/13-common.sh"
ALGS=${ALGS:-"rsa4096 ecdsa-p256 ecdsa-p384 ecdsa-p521 mldsa65 mldsa87 p384_mldsa65 p521_mldsa87"}
PARTS=${PARTS:-"sig verify"}   # run only part of the block, e.g. PARTS=sig
if [[ " $PARTS " == *" sig "* ]]; then
echo "== A) signature primitives: N=$N WARMUP=$WARMUP COLD=$COLD"
for a in $ALGS; do
  "$BENCH" sig "$a" $((N + WARMUP)) "$WARMUP" "$RES/13-raw-sig.csv"
  for i in $(seq 1 "$COLD"); do "$BENCH" sig "$a" 1 0 "$RES/13-raw-sig.csv" >/dev/null; done
  echo "   $a: cold x$COLD done"
done
fi
if [[ " $PARTS " == *" verify "* ]]; then
echo "== B) certificate verification"
for m in $MODELS; do
  "$BENCH" verify "$m" "$(cert "$m")" "$(bundle "$m")" $((N + WARMUP)) "$WARMUP" "$RES/13-raw-verify.csv"
  for i in $(seq 1 "$COLD"); do "$BENCH" verify "$m" "$(cert "$m")" "$(bundle "$m")" 1 0 "$RES/13-raw-verify.csv" >/dev/null; done
  echo "   $m: cold x$COLD done"
done
fi
echo "Done. Raw samples in $RES"
