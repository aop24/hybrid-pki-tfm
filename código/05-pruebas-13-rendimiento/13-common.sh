#!/usr/bin/env bash
# Common settings for block 13 on the client VMs (client-01, client-02). Sourced, not executed.
set -euo pipefail
BENCH=$HOME/phc-client/build/phc-bench
PKI=$HOME/pki
RES=$HOME/tfm-results
WORK=$HOME/tfm-tests/work
N=${N:-200}          # measured iterations
WARMUP=${WARMUP:-20} # discarded iterations
COLD=${COLD:-30}     # fresh processes, first operation only
MODELS=${MODELS:-"classic chimera composite"}
mkdir -p "$RES" "$WORK"
die() { echo "ERROR: $*" >&2; exit 1; }
[ -x "$BENCH" ] || die "phc-bench not found at $BENCH (rebuild phc-client)"
ME=$(hostname)
bundle() { case "$1" in chimera) echo "$PKI/ca-certs/ca-bundle-hybrid.crt" ;; *) echo "$PKI/ca-certs/ca-bundle-$1.crt" ;; esac; }
cert() { echo "$PKI/certs/$ME-$1.crt"; }
key()  { echo "$PKI/keys/$ME-$1.key"; }
# leaf + intermediate (first certificate of the bundle) for PHC_CHAIN=explicit
chain_file() {
  local out=$WORK/$ME-$1-leaf+sub.crt
  { cat "$(cert "$1")"; awk '/BEGIN CERT/{n++} n==1' "$(bundle "$1")"; } > "$out"
  echo "$out"
}
port() { # model chain -> port
  local base; case "$1" in classic) base=9300 ;; chimera) base=9310 ;; composite) base=9320 ;; esac
  [ "$2" = explicit ] && echo $((base + 1)) || echo "$base"
}
