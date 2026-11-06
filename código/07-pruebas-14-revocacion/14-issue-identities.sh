#!/usr/bin/env bash
# Block 14 - issues test identities on THIS client through certdist (key generated here, as for any
# client): rev-<model>-NN for NN = 01..<count>. Prints the serial number of each certificate.
# Usage: 14-issue-identities.sh <count>
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <count>" >&2; exit 2; }
P=$HOME/pki; CD=$HOME/phc-certdist/bin/certdist-client
openssl() { LD_LIBRARY_PATH=/opt/openssl32/lib64:/opt/openssl32/lib /opt/openssl32/bin/openssl "$@"; }
for m in classic chimera composite; do
  for i in $(seq -w 1 "$1"); do
    cn=rev-$m-$i; key=$P/keys/$cn.key; csr=$P/csr/$cn.csr; crt=$P/certs/$cn.crt
    if [ ! -s "$crt" ]; then
      if [ "$m" = composite ]; then
        openssl req -new -newkey p384_mldsa65 -nodes -keyout "$key" -subj "/CN=$cn/O=UPV-TFM/C=ES" -out "$csr" 2>/dev/null
      else
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$key" -subj "/CN=$cn/O=UPV-TFM/C=ES" -out "$csr" 2>/dev/null
      fi
      chmod 600 "$key"
      "$CD" "$m" "$cn" "$csr" "$crt" >/dev/null
    fi
    echo "$cn serial $(openssl x509 -in "$crt" -noout -serial | cut -d= -f2)"
  done
done
