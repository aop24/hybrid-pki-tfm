#!/usr/bin/env bash
# Block 13 - C) starts/stops the six TLS benchmark servers on this VM (3 models x 2 chain policies).
#   ports: classic 9300/9301, chimera 9310/9311, composite 9320/9321 (auto/explicit)
# Usage: 13-tls-servers.sh start|stop|status
source "$(dirname "$0")/13-common.sh"
PIDS=$WORK/tls-servers.pids
case "${1:-}" in
  start)
    [ -s "$PIDS" ] && die "servers already running (see $PIDS); run stop first"
    for m in $MODELS; do
      for c in auto explicit; do
        f=$(cert "$m"); [ "$c" = explicit ] && f=$(chain_file "$m")
        PHC_CHAIN=$c nohup "$BENCH" tls-server "$(port "$m" "$c")" "$f" "$(key "$m")" "$(bundle "$m")" \
          > "$WORK/tls-server-$m-$c.log" 2>&1 &
        echo $! >> "$PIDS"
      done
    done
    sleep 1; "$0" status ;;
  stop)
    [ -s "$PIDS" ] && xargs -r kill < "$PIDS" 2>/dev/null || true
    rm -f "$PIDS"; echo "servers stopped" ;;
  status)
    for m in $MODELS; do for c in auto explicit; do
      p=$(port "$m" "$c"); ss -ltn "sport = :$p" | grep -q LISTEN && s=listening || s=DOWN
      echo "$m $c port $p: $s"; done; done ;;
  *) die "usage: $0 start|stop|status" ;;
esac
