#!/usr/bin/env bash
# Block 16 - driver of the scale test on the host (run with sudo). One container per client node.
#   16-scale.sh build                         build the image tfm16-node (needs pqc-runtime.tgz here)
#   16-scale.sh server-cert <model>           issue the TLS server identity of <model> through certdist
#   16-scale.sh issue <model> <N> <stock|retry>
#                                             N containers request a certificate at the same instant
#   16-scale.sh tls <model> <N> [HS=20]       N containers (identities of the issue run of N) run HS handshakes
#                                             at the same instant against one server container (2 CPUs, 2 workers)
#   16-scale.sh down                          remove the server containers and the network
# Results: results/16-runs.csv (one row per run), results/16-issue.csv, results/16-tls.csv,
#          results/<run>/ (raw files, host vmstat). Private keys: data/ (root, mode 600), never printed.
set -uo pipefail
export LC_ALL=C   # decimal point in awk/sort/printf (the host locale uses a comma)
cd "$(dirname "$0")"
B16=$(pwd); DATA=$B16/data; RES=$B16/results; IMG=tfm16-node; NET=tfm16
mkdir -p "$DATA" "$RES"
now() { date +%s%3N; }
die() { echo "ERROR: $*" >&2; exit 1; }
check_model() { case "$1" in classic|chimera|composite) ;; *) die "model must be classic, chimera or composite" ;; esac; }
port() { case "$1" in classic) echo 9600 ;; chimera) echo 9601 ;; composite) echo 9602 ;; esac; }
runs_row() { [ -f "$RES/16-runs.csv" ] || echo "run,kind,model,n,policy,go_ms,end_ms,wall_ms,ok,failed,host_load1_before,host_mem_avail_mb_before" > "$RES/16-runs.csv"; echo "$*" >> "$RES/16-runs.csv"; }
host_state() { echo "$(cut -d' ' -f1 /proc/loadavg),$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)"; }

# start_and_wait <run dir> <N> <docker run args for container i: function name>
barrier_go() {  # waits until N READY files, then writes GO = start instant 3 s ahead (atomic rename); prints it
  local d=$1 n=$2 t=$(( $(now) + 600000 ))
  while [ "$(ls "$d" | grep -c '^READY\.')" -lt "$n" ]; do
    [ "$(now)" -gt "$t" ] && die "only $(ls "$d" | grep -c '^READY\.') of $n containers ready after 600 s"
    sleep 0.2
  done
  local g; g=$(( $(now) + 3000 )); echo "$g" > "$d/GO.tmp"; mv "$d/GO.tmp" "$d/GO"; echo "$g"   # common start 3 s ahead
}

case "${1:-}" in
  build)
    [ -s pqc-runtime.tgz ] || die "pqc-runtime.tgz not found in $B16"
    docker build -t "$IMG" . && docker image ls "$IMG" --format '{{.Repository}} {{.ID}} {{.Size}}' ;;

  server-cert)
    M=${2:-}; check_model "$M"; R=$RES/server-cert-$M; rm -rf "$R"; mkdir -p "$R"; now > "$R/GO"
    docker run --rm -e ROLE=issue -e MODEL="$M" -e CN="tfm16-server-$M" -e CLIENT=retry -e DEADLINE_S=300 \
      -v "$DATA/server:/data" -v "$R:/results" "$IMG"
    cat "$R/tfm16-server-$M.csv"
    cp "$DATA/server/tfm16-server-$M.crt" "$DATA/server/server-$M.crt" && cp "$DATA/server/tfm16-server-$M.key" "$DATA/server/server-$M.key"
    echo "server identity of $M ready" ;;

  issue)
    M=${2:-}; N=${3:-}; POL=${4:-}; check_model "$M"
    [[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 1 ] && [ "$N" -le 99 ] || die "N must be 1..99"
    [[ "$POL" =~ ^(stock|retry)$ ]] || die "policy must be stock or retry"
    RUN=issue-$M-n$N-$POL-$(date -u +%Y%m%dT%H%M%S); R=$RES/$RUN; D=$DATA/$M-n$N-$POL; mkdir -p "$R" "$D"
    before=$(host_state)
    for i in $(seq -w 1 "$N"); do
      docker run -d --rm --name "tfm16-$M-$POL-n$N-$i" --memory 96m -e ROLE=issue -e MODEL="$M" -e CN="scale-$M-n$N-$POL-$i" \
        -e CLIENT="$POL" -v "$D:/data" -v "$R:/results" "$IMG" > /dev/null || die "docker run failed for $i"
    done
    vmstat -n 1 > "$R/host-vmstat.txt" & VM=$!
    GO=$(barrier_go "$R" "$N"); echo "$RUN: $N containers ready, GO at $(date -u -d @$((GO / 1000)) +%H:%M:%S) UTC"
    # until every container has written its row (or none of them is still running)
    while [ "$(ls "$R" | grep -c '^scale-.*\.csv$')" -lt "$N" ] && [ -n "$(docker ps -q -f name="^tfm16-$M-$POL-n$N-")" ]; do sleep 1; done
    END=$(now); kill "$VM" 2>/dev/null; for t in $(seq 60); do [ -z "$(docker ps -aq -f name="^tfm16-$M-$POL-n$N-")" ] && break; sleep 1; done
    [ -f "$RES/16-issue.csv" ] || echo "run,n,cn,model,policy,keygen_ms,start_ms,end_ms,issue_ms,attempts,rc,cert_der_bytes,error" > "$RES/16-issue.csv"
    for f in "$R"/scale-*.csv; do echo "$RUN,$N,$(cat "$f")"; done >> "$RES/16-issue.csv"
    ok=$(cat "$R"/scale-*.csv | awk -F, '$9==0' | wc -l)
    runs_row "$RUN,issue,$M,$N,$POL,$GO,$END,$((END - GO)),$ok,$((N - ok)),$before"
    cat "$R"/scale-*.csv | awk -F, -v n="$N" -v w=$((END - GO)) '{ if ($9==0) { ok++; s+=$7; if ($7>mx) mx=$7 } else fail++ }
      END { printf "  ok %d/%d  failed %d  wall %.1f s  mean issue %.0f ms  max %.0f ms\n", ok, n, fail, w/1000, ok ? s/ok : 0, mx }'
    [ "$(ls "$R" | grep -c '^scale-.*\.csv$')" -lt "$N" ] && echo "  WARNING: only $(ls "$R" | grep -c '^scale-.*\.csv$') of $N containers wrote a result"
    awk -F, '$9!=0 {print $11}' "$R"/scale-*.csv | sort | uniq -c | sed 's/^/  failure reason: /' | head -5 ;;

  tls)
    M=${2:-}; N=${3:-}; HS=${4:-20}; check_model "$M"; D=$DATA/$M-n$N-retry; [ -d "$D" ] || D=$DATA/$M-n$N-stock
    [ -s "$DATA/server/server-$M.crt" ] || die "run server-cert $M first"
    ids=$(ls "$D" 2>/dev/null | sed -n 's/\.crt$//p' | head -n "$N"); [ "$(wc -w <<<"$ids")" -eq "$N" ] || die "fewer than $N certificates in $D (run issue $M $N first)"
    docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
    S=tfm16-server-$M
    if [ -z "$(docker ps -q -f name="^$S$")" ]; then
      docker run -d --rm --name "$S" --network "$NET" --cpus 2 --memory 256m -e ROLE=tls-server -e MODEL="$M" \
        -e PORT="$(port "$M")" -e WORKERS=2 -v "$DATA/server:/data" "$IMG" > /dev/null; sleep 2
    fi
    # the clients get the server IP: a name would be resolved by Docker's DNS on every handshake (~0.25 s)
    SIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$S"); [ -n "$SIP" ] || die "no IP for $S"
    RUN=tls-$M-n$N-$(date -u +%Y%m%dT%H%M%S); R=$RES/$RUN; mkdir -p "$R"; before=$(host_state)
    for cn in $ids; do
      docker run -d --rm --name "tfm16-c-$cn" --network "$NET" --memory 96m -e ROLE=tls-client -e MODEL="$M" -e CN="$cn" \
        -e SERVER="$SIP" -e PORT="$(port "$M")" -e HS="$HS" -e WARMUP=2 -v "$D:/data" -v "$R:/results" "$IMG" > /dev/null
    done
    vmstat -n 1 > "$R/host-vmstat.txt" & VM=$!
    GO=$(barrier_go "$R" "$N"); echo "$RUN: $N clients ready, GO at $(date -u -d @$((GO / 1000)) +%H:%M:%S) UTC"
    while [ "$(ls "$R" | grep -c '\.window$')" -lt "$N" ] && [ -n "$(docker ps -q -f name="^tfm16-c-")" ]; do sleep 1; done
    kill "$VM" 2>/dev/null
    END=$(cat "$R"/*.window | awk -F, 'BEGIN{m=0} {if ($3>m) m=$3} END{print m}')   # last client done (teardown excluded)
    while [ -n "$(docker ps -q -f name="^tfm16-c-")" ]; do sleep 1; done
    hdr=$(head -qn1 "$R"/scale-*.csv 2>/dev/null | head -1)
    [ -f "$RES/16-tls.csv" ] || echo "run,n,$hdr" > "$RES/16-tls.csv"
    for f in "$R"/scale-*.csv; do tail -n +2 "$f" | sed "s/^/$RUN,$N,/"; done >> "$RES/16-tls.csv"
    meas=$(cat "$R"/scale-*.csv 2>/dev/null | grep -c ',measure,'); fails=$(grep -ho '[0-9]* failed' "$R"/*.log | awk '{s+=$1} END{print s+0}')
    runs_row "$RUN,tls,$M,$N,hs=$HS,$GO,$END,$((END - GO)),$meas,$fails,$before"
    awk -F, '$5=="measure"{print $8}' "$R"/scale-*.csv | sort -n | awk -v w=$((END - GO)) -v f="$fails" '{a[NR]=$1}
      END { if (NR) printf "  %d measured handshakes, %d failed, wall %.1f s, median %.2f ms, p95 %.2f ms, %.1f handshakes/s\n", NR, f, w/1000, a[int((NR+1)/2)], a[int(NR*0.95)], NR*1000/w }' ;;

  down) docker ps -aq -f name='^tfm16-' | xargs -r docker rm -f > /dev/null; docker network rm "$NET" 2>/dev/null; echo "scale test containers removed" ;;
  *) sed -n 2,13p "$0"; exit 2 ;;
esac
