#!/usr/bin/env bash
# Block 12 - sizes of end-entity certificates, CA certificates and chains for one model.
#   ee_cert       : the real client certificate client-01-<model>.crt (copied to $TT/samples)
#   ee_issued_*   : min / median / max DER size of the 100 test certificates crl-<model>-NNN
#   sub_ca, root_ca, chain_leaf_sub (what a peer must receive if it only trusts the root),
#   chain_full (leaf + sub + root)
# Appends rows to $RES/12-tamanos.csv.
# Usage: 12-cert-sizes.sh <chimera|classic|composite>
source "$(dirname "$0")/lib.sh"
[ $# -eq 1 ] || die "usage: $0 <model>"
MODEL=$1; check_model "$MODEL"
CSV=$RES/12-tamanos.csv
[ -f "$CSV" ] || echo "timestamp_utc,model,artifact,variant,revoked_entries,der_bytes,pem_bytes,signature_algorithm,alt_signature,notes" > "$CSV"
EE=$TT/samples/client-01-$MODEL.crt
SUB=$(sub_ca_cert "$MODEL"); ROOT=$(root_ca_cert "$MODEL")
for f in "$EE" "$SUB" "$ROOT"; do [ -s "$f" ] || die "missing $f"; done

sigalg() { o34 x509 -in "$1" -noout -text | awk -F': ' '/Signature Algorithm/ {print $2; exit}'; }
altsig() { o34 x509 -in "$1" -noout -text | grep -qiE 'Alternative Signature|2\.5\.29\.74' && echo yes || echo no; }
# row <artifact> <variant> <der> <pem> <sigalg> <alt> <notes>
row() { echo "$(ts_utc),$MODEL,$1,$2,,$3,$4,$5,$6,$7" >> "$CSV"; echo "$MODEL $1 $2: der=$3 pem=$4 $5 alt=$6"; }

E=$(der_size "$EE"); S=$(der_size "$SUB"); R=$(der_size "$ROOT")
row ee_cert client-01 "$E" "$(pem_size "$EE")" "$(sigalg "$EE")" "$(altsig "$EE")" "real client certificate"
row sub_ca_cert - "$S" "$(o34 x509 -in "$SUB" | wc -c)" "$(sigalg "$SUB")" "$(altsig "$SUB")" ""
row root_ca_cert - "$R" "$(o34 x509 -in "$ROOT" | wc -c)" "$(sigalg "$ROOT")" "$(altsig "$ROOT")" ""
row chain leaf+sub "$((E + S))" "" "" "" "sent by a server that includes the intermediate"
row chain leaf+sub+root "$((E + S + R))" "" "" "" "full path to the trust anchor"

# Variability over the 100 issued test certificates
mapfile -t SIZES < <(for c in "$MAT/$MODEL"/certs/crl-"$MODEL"-*.crt; do der_size "$c"; done | sort -n)
N=${#SIZES[@]}
if [ "$N" -gt 0 ]; then
  row ee_issued min "${SIZES[0]}" "" "" "" "n=$N test certificates"
  row ee_issued median "${SIZES[$((N / 2))]}" "" "" "" "n=$N test certificates"
  row ee_issued max "${SIZES[$((N - 1))]}" "" "" "" "n=$N test certificates"
fi
