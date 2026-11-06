#!/usr/bin/env bash
# Block 15 - D2: plain OpenSSL 3.4.0 + oqs-provider TLS servers (no client authentication) with the
# real certificate of this host for each model, chain sent explicitly (leaf + sub CA):
#   classic 9500, chimera 9501, composite 9502
# SECLEVEL=0 because OpenSSL's security-level tables do not know provider algorithms (block 11).
# Usage: 15-d2-servers.sh start|stop|status
set -uo pipefail
P=$HOME/pki; ME=$(hostname); W=$HOME/tfm-tests/work; PIDS=$W/15-d2-servers.pids; mkdir -p "$W"
NEW() { LD_LIBRARY_PATH=/opt/openssl32/lib64:/opt/openssl32/lib /opt/openssl32/bin/openssl "$@"; }
bundle() { case "$1" in chimera) echo "$P/ca-certs/ca-bundle-hybrid.crt" ;; *) echo "$P/ca-certs/ca-bundle-$1.crt" ;; esac; }
port() { case "$1" in classic) echo 9500 ;; chimera) echo 9501 ;; composite) echo 9502 ;; esac; }
case "${1:-}" in
  start)
    [ -s "$PIDS" ] && { echo "already running (see $PIDS); run stop first" >&2; exit 1; }
    for m in classic chimera composite; do
      awk '/BEGIN CERT/{n++} n==1' "$(bundle "$m")" > "$W/15-sub-$m.crt"   # first certificate of the bundle = sub CA
      NEW s_server -accept "$(port "$m")" -www -tls1_3 -cipher 'DEFAULT:@SECLEVEL=0' \
        -cert "$P/certs/$ME-$m.crt" -key "$P/keys/$ME-$m.key" -cert_chain "$W/15-sub-$m.crt" \
        > "$W/15-d2-server-$m.log" 2>&1 < /dev/null &
      echo $! >> "$PIDS"
    done
    sleep 1; "$0" status ;;
  stop) [ -s "$PIDS" ] && xargs -r kill < "$PIDS" 2>/dev/null; rm -f "$PIDS"; echo "servers stopped" ;;
  status)
    for m in classic chimera composite; do p=$(port "$m")
      ss -ltn "sport = :$p" | grep -q LISTEN && s=listening || s=DOWN
      echo "$m port $p: $s ($(NEW x509 -in "$P/certs/$ME-$m.crt" -noout -subject 2>/dev/null))"; done ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
