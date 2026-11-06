#!/usr/bin/env bash
# Block 13 - control experiment: is the extra cost of PHC_CHAIN=auto due to the bytes sent
# or to OpenSSL building/verifying its own chain on every handshake?
# Builds a throwaway 3-level Composite PKI (root/sub p521_mldsa87, leaves p384_mldsa65) in a
# temporary directory under $HOME/tfm-tests/work and runs, over loopback, 10 + 50 handshakes for:
#   auto-leaf               PHC_CHAIN=auto,     cert file = leaf                 (sends leaf+sub+root)
#   explicit-leaf+sub       PHC_CHAIN=explicit, cert file = leaf + sub
#   explicit-leaf+sub+root  PHC_CHAIN=explicit, cert file = leaf + sub + root   (same bytes as auto)
# Usage: 13-chain-experiment.sh   (needs phc-bench v2.2 and OpenSSL 3.4.0 + oqs-provider)
set -euo pipefail
O() { LD_LIBRARY_PATH=/opt/openssl32/lib64:/opt/openssl32/lib /opt/openssl32/bin/openssl "$@"; }
B=$HOME/phc-client/build/phc-bench
W=$(mktemp -d "$HOME/tfm-tests/work/chain-exp-XXXXXX"); cd "$W"
O req -x509 -newkey p521_mldsa87 -nodes -keyout r.key -subj "/CN=exp root" -days 2 -out r.crt \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=keyCertSign,cRLSign 2>/dev/null
O req -new -newkey p521_mldsa87 -nodes -keyout s.key -subj "/CN=exp sub" -out s.csr 2>/dev/null
O x509 -req -in s.csr -CA r.crt -CAkey r.key -days 2 -out s.crt \
  -extfile <(printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n') 2>/dev/null
for n in a b; do
  O req -new -newkey p384_mldsa65 -nodes -keyout $n.key -subj "/CN=exp-$n" -out $n.csr 2>/dev/null
  O x509 -req -in $n.csr -CA s.crt -CAkey s.key -days 2 -out $n.crt \
    -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth,serverAuth\n') 2>/dev/null
  cat $n.crt s.crt > $n-ls.crt; cat $n.crt s.crt r.crt > $n-lsr.crt
done
cat s.crt r.crt > bundle.crt
CSV=$HOME/tfm-results/13-raw-chain-experiment.csv
run() { # policy server_cert client_cert label
  PHC_CHAIN=$1 "$B" tls-server 9399 "$2" a.key bundle.crt >/dev/null 2>&1 & local p=$!; sleep 0.5
  PHC_CHAIN=$1 PHC_BENCH_PAUSE_MS=20 "$B" tls-client "$4" 127.0.0.1 9399 "$3" b.key bundle.crt 60 10 "$CSV" >/dev/null
  kill $p; wait $p 2>/dev/null || true
}
run auto a.crt b.crt auto-leaf
run explicit a-ls.crt b-ls.crt explicit-leaf+sub
run explicit a-lsr.crt b-lsr.crt explicit-leaf+sub+root
python3 -I - "$CSV" <<'PY'
import csv, statistics as st, sys
from collections import defaultdict
g = defaultdict(list)
for r in csv.DictReader(open(sys.argv[1])):
    if r["phase"] == "measure":
        g[r["model"]].append(r)
for k, v in g.items():
    print(f'{k:24} handshake median={st.median(float(x["handshake_ms"]) for x in v):6.2f} ms  '
          f'bytes_recv={v[0]["hs_bytes_recv"]} certs={v[0]["peer_chain_certs"]} n={len(v)}')
PY
rm -rf "$W"
