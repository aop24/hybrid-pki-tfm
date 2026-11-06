#!/usr/bin/env bash
# Block 14 - polls the revocation status of one certificate of this client (phc-bench revpoll).
# Usage: 14-poll.sh <model> <cn> <ocsp|crl> <interval_ms> <max_s> [label]
#   Output: $HOME/tfm-results/14-raw-poll-<label>.csv (one file per series; label defaults to <model>-<method>)
#   PHC_CRL_MAXAGE can be set for crl (seconds before a cached CRL is downloaded again)
set -euo pipefail
[ $# -ge 5 ] || { echo "usage: $0 <model> <cn> <ocsp|crl> <interval_ms> <max_s> [label]" >&2; exit 2; }
source "$(dirname "$0")/14-env.sh" "$1" "$3" >/dev/null
case "$1" in chimera) B=$HOME/pki/ca-certs/ca-bundle-hybrid.crt ;; *) B=$HOME/pki/ca-certs/ca-bundle-$1.crt ;; esac
mkdir -p "$HOME/tfm-results"
[ "$3" = crl ] && rm -f "$PHC_CRL_CACHE"/crl-*.der   # start every CRL experiment with an empty cache
LABEL=${6:-$1-$3}
"$HOME/phc-client/build/phc-bench" revpoll "$LABEL" "$HOME/pki/certs/$2.crt" "$B" "$4" "$5" "$HOME/tfm-results/14-raw-poll-$LABEL.csv"
