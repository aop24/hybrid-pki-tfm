#!/usr/bin/env bash
# Block 16 - entrypoint of a scale-test container. All parameters come from the environment.
#   ROLE=issue       key + CSR here, READY, wait for GO, certdist request; one CSV row in /results/<CN>.csv
#                    MODEL CN CLIENT=stock|retry [DEADLINE_S=3600 for retry]
#   ROLE=tls-server  phc-bench tls-server with PHC_BENCH_WORKERS=WORKERS on PORT (cert /data/server-<MODEL>.crt)
#   ROLE=tls-client  READY, wait for GO, HS handshakes (WARMUP discarded) against SERVER:PORT -> /results/<CN>.csv
#                    and /results/<CN>.window (epoch ms when phc-bench started and ended)
# Private keys stay in /data (host directory, mode 600) and are never printed.
set -uo pipefail
o34() { LD_LIBRARY_PATH=/opt/openssl32/lib64:/opt/openssl32/lib /opt/openssl32/bin/openssl "$@"; }
now() { date +%s%3N; }
bundle() { case "$1" in chimera) echo /pki/ca-certs/ca-bundle-hybrid.crt ;; *) echo "/pki/ca-certs/ca-bundle-$1.crt" ;; esac; }
chain() { cat "$1"; awk '/BEGIN CERT/{n++} n==1' "$(bundle "$2")"; }   # leaf + sub CA (PHC_CHAIN=explicit)
# Barrier without busy waiting: "read -t" on an idle FIFO is a bash builtin (no fork per poll; with 99 containers a
# "sleep 0.01" loop forked ~10 000 processes per second on the host). GO holds the common start time (epoch ms):
# every container sleeps until that instant, so the clients start within a few ms of each other.
barrier() {
  touch "/results/READY.$CN"; mkfifo /tmp/idle; exec 9<>/tmp/idle
  while [ ! -s /results/GO ]; do read -r -t 0.1 -u 9 _; done
  local wait_ms=$(( $(cat /results/GO) - $(now) ))
  [ "$wait_ms" -gt 0 ] && sleep "$(printf '%d.%03d' $((wait_ms / 1000)) $((wait_ms % 1000)))"
}
umask 077
case "$ROLE" in
  issue)
    K=/data/$CN.key; R=/data/$CN.csr; C=/data/$CN.crt
    t=$(now)
    if [ "$MODEL" = composite ]; then
      o34 req -new -newkey p384_mldsa65 -nodes -keyout "$K" -subj "/CN=$CN/O=UPV-TFM/C=ES" -out "$R" 2>/dev/null
    else
      o34 req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$K" -subj "/CN=$CN/O=UPV-TFM/C=ES" -out "$R" 2>/dev/null
    fi
    keygen_ms=$(( $(now) - t ))
    barrier
    t0=$(now); attempts=0; rc=1; err=""
    if [ "$CLIENT" = stock ]; then
      attempts=1; err=$(certdist-client "$MODEL" "$CN" "$R" "$C" 2>&1 >/dev/null); rc=$?
    else
      deadline=$(( t0 + ${DEADLINE_S:-3600} * 1000 ))
      while :; do
        attempts=$((attempts + 1)); err=$(certdist-client-long "$MODEL" "$CN" "$R" "$C" 2>&1 >/dev/null); rc=$?
        [ $rc -eq 0 ] || [ "$(now)" -ge "$deadline" ] && break
        sleep 1
      done
    fi
    t1=$(now)
    der=$([ $rc -eq 0 ] && o34 x509 -in "$C" -outform DER 2>/dev/null | wc -c || echo 0)
    err=$(tr ',\n' '; ' <<<"$err" | cut -c1-200)
    echo "$CN,$MODEL,$CLIENT,$keygen_ms,$t0,$t1,$((t1 - t0)),$attempts,$rc,$der,$err" > "/results/$CN.csv" ;;
  tls-server)
    chain "/data/server-$MODEL.crt" "$MODEL" > /tmp/server-chain.crt
    PHC_CHAIN=explicit PHC_BENCH_WORKERS=${WORKERS:-2} exec phc-bench tls-server "$PORT" /tmp/server-chain.crt \
      "/data/server-$MODEL.key" "$(bundle "$MODEL")" ;;
  tls-client)
    chain "/data/$CN.crt" "$MODEL" > /tmp/client-chain.crt
    barrier
    s=$(now)
    PHC_CHAIN=explicit phc-bench tls-client "$MODEL" "$SERVER" "$PORT" /tmp/client-chain.crt "/data/$CN.key" \
      "$(bundle "$MODEL")" "$HS" "$WARMUP" "/results/$CN.csv" > "/results/$CN.log" 2>&1
    echo "$CN,$s,$(now)" > "/results/$CN.window" ;;   # active window of this client (container start/teardown excluded)
  *) echo "ROLE must be issue, tls-server or tls-client" >&2; exit 2 ;;
esac
