#!/usr/bin/env bash
# Block 13 - C) TLS 1.3 handshakes from this VM against the benchmark servers on <server_ip>.
# For each model and chain policy: WARMUP + N handshakes in one process, then COLD fresh processes.
# Raw samples: $RES/13-raw-tls.csv
# Usage: 13-run-tls.sh <server_ip>
#   PHC_BENCH_PAUSE_MS=<ms>  pause between handshakes (default 0)
#   OUT=<file>               raw output (default $RES/13-raw-tls.csv)
source "$(dirname "$0")/13-common.sh"
[ $# -eq 1 ] || die "usage: $0 <server_ip>"
SRV=$1
OUT=${OUT:-$RES/13-raw-tls.csv}
export PHC_BENCH_PAUSE_MS=${PHC_BENCH_PAUSE_MS:-0}
echo "== C) TLS handshakes against $SRV, pause ${PHC_BENCH_PAUSE_MS} ms -> $OUT"
for m in $MODELS; do
  for c in auto explicit; do
    f=$(cert "$m"); [ "$c" = explicit ] && f=$(chain_file "$m")
    p=$(port "$m" "$c")
    PHC_CHAIN=$c "$BENCH" tls-client "$m" "$SRV" "$p" "$f" "$(key "$m")" "$(bundle "$m")" \
      $((N + WARMUP)) "$WARMUP" "$OUT"
    for i in $(seq 1 "$COLD"); do
      PHC_CHAIN=$c "$BENCH" tls-client "$m" "$SRV" "$p" "$f" "$(key "$m")" "$(bundle "$m")" 1 0 "$OUT" >/dev/null
    done
    echo "   $m $c: cold x$COLD done"
  done
done
echo "Done. Raw samples in $OUT"
