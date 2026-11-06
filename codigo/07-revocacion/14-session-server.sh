#!/usr/bin/env bash
# Block 14 - phc-msg server for the hot-session experiment, restarted after every session so the
# same port also takes the reconnection attempt. Every output line is prefixed with the UTC time.
#   method none     -> v2.2 behaviour: no revocation check at all
#   method ocsp|crl -> check at handshake + re-check every <recheck_s> seconds during the session
# The server does not type messages (stdin is an idle process substitution, so bash does not wait for it). Ctrl+C stops it.
# Usage: 14-session-server.sh <model> <none|ocsp|crl> <port> [recheck_s=30]
set -uo pipefail
[ $# -ge 3 ] || { echo "usage: $0 <model> <none|ocsp|crl> <port> [recheck_s]" >&2; exit 2; }
source "$(dirname "$0")/14-env.sh" "$1" "$2"
[ "$2" != none ] && export PHC_RECHECK_SECS=${4:-30}
P=$HOME/pki; ME=$(hostname)
case "$1" in chimera) B=$P/ca-certs/ca-bundle-hybrid.crt ;; *) B=$P/ca-certs/ca-bundle-$1.crt ;; esac
# drops the "\r" and "> " prompt fragments of the interactive output so the time prefix stays visible
stamp() { while IFS= read -r l; do l=${l//$'\r'/}; while [[ $l == '> '* ]]; do l=${l#> }; done
  [ -n "$l" ] && printf '%s %s\n' "$(date -u +%H:%M:%S.%3N)" "$l"; done; }
LOG=$HOME/tfm-results/14-session-$1-$2-$3.log   # copy of everything shown
trap 'exit 0' INT TERM
while :; do
  echo "--- waiting for a connection on port $3 (model $1, revocation $2) ---" | stamp | tee -a "$LOG"
  stdbuf -oL "$HOME/phc-client/build/phc-msg" server "$3" "$P/certs/$ME-$1.crt" "$P/keys/$ME-$1.key" "$B" \
    < <(sleep 3600) 2>&1 | stamp | tee -a "$LOG"
done
