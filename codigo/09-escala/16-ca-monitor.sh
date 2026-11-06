#!/usr/bin/env bash
# Block 16 - samples the CA once per second while the scale test runs:
#   CPU busy % of the whole VM (from /proc/stat), memory used (MemTotal - MemAvailable), RSS of the
#   WildFly JVM and of MariaDB, load average and number of ejbca.sh CLI JVMs (certdist signing path).
# Usage: 16-ca-monitor.sh start|stop|status      Output: /home/ca/tfm-results/16-ca-monitor.csv
set -uo pipefail
OUT=/home/ca/tfm-results/16-ca-monitor.csv; PID=/home/ca/tfm-tests/work/16-ca-monitor.pid
mkdir -p "$(dirname "$OUT")" "$(dirname "$PID")"
sample() {
  [ -f "$OUT" ] || echo "epoch_ms,utc,cpu_busy_pct,mem_used_mb,wildfly_rss_mb,mariadb_rss_mb,load1,cli_jvms" > "$OUT"
  read -r _ u n s i w x y z _ < /proc/stat; local pb=$((u + n + s + x + y + z)) pt=$((u + n + s + i + w + x + y + z))
  while :; do
    sleep 1
    read -r _ u n s i w x y z _ < /proc/stat; local b=$((u + n + s + x + y + z)) t=$((u + n + s + i + w + x + y + z))
    local cpu; cpu=$(awk -v db=$((b - pb)) -v dt=$((t - pt)) 'BEGIN{printf "%.1f", dt ? 100 * db / dt : 0}'); pb=$b; pt=$t
    local mem; mem=$(awk '/MemTotal/{tt=$2} /MemAvailable/{a=$2} END{print int((tt - a) / 1024)}' /proc/meminfo)
    local wf; wf=$(ps -C java -o rss=,args= | awk '/jboss|wildfly/ && !/ejbca\.sh|clientToolBox|ejbca-ejb-cli/ {s+=$1} END{print int(s/1024)}')
    local db; db=$(ps -C mariadbd -o rss= | awk '{s+=$1} END{print int(s/1024)}')
    local cli; cli=$(ps -C java -o args= | grep -c -E 'ejbca-ejb-cli|ejbca\.sh')
    local e; e=$(date +%s%3N)
    echo "$e,$(date -u -d @$((e / 1000)) +%H:%M:%S),$cpu,$mem,$wf,$db,$(cut -d' ' -f1 /proc/loadavg),$cli" >> "$OUT"
  done
}
case "${1:-}" in
  start) [ -s "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null && { echo "already running (pid $(cat "$PID"))"; exit 0; }
         nohup bash -c "$(declare -f sample); OUT=$OUT; sample" > /dev/null 2>&1 & echo $! > "$PID"; sleep 2.5; tail -n 2 "$OUT" ;;
  stop)  [ -s "$PID" ] && kill "$(cat "$PID")" 2>/dev/null; rm -f "$PID"; echo "monitor stopped; $(($(wc -l < "$OUT") - 1)) samples in $OUT" ;;
  status) [ -s "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null && echo "running (pid $(cat "$PID"))" || echo "not running"; tail -n 3 "$OUT" ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
