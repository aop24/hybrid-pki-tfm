#!/usr/bin/env bash
# Common settings for the TFM v2 test scripts (block 12 onwards). Sourced, not executed.
set -euo pipefail

TT=/home/ca/tfm-tests                 # scripts and test material
RES=/home/ca/tfm-results              # CSV results
MAT=$TT/material                      # keys, CSRs and certificates issued for the tests
CREDS=/home/ca/phc-admin-creds
REST=https://ca:8443/ejbca/ejbca-rest-api/v1
CA_CERTS=/home/ca/pki/ca-certs
COMP_CNF=/home/ca/pki/composite/composite-ca.cnf
SIGN_COMPOSITE=/home/ca/phc-certdist/sign_composite.sh
OSSL_SYS=/usr/bin/openssl

die() { echo "ERROR: $*" >&2; exit 1; }
now_ms() { date +%s%3N; }
ts_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# OpenSSL 3.4.0 + oqs-provider (needed for composite keys and to name the Chimera extensions)
o34() { LD_LIBRARY_PATH=/opt/openssl32/lib64:/opt/openssl32/lib /opt/openssl32/bin/openssl "$@"; }

# REST call to EJBCA with SuperAdmin mTLS
rest() {
  curl -s --fail-with-body --cacert "$CREDS/managementca.crt" --cert "$CREDS/superadmin.crt" \
    --key "$CREDS/superadmin.key" --resolve ca:8443:127.0.0.1 "$@"
}

# model -> EJBCA CA name / issuer DN
ejbca_ca_name() {
  case "$1" in chimera) echo TFM-Sub-CA-Hybrid ;; classic) echo TFM-Sub-CA-Classic ;; *) die "no EJBCA CA for model '$1'" ;; esac
}
ejbca_ca_dn() {
  case "$1" in chimera) echo "CN=TFM Sub CA Hybrid,O=UPV-TFM,C=ES" ;; classic) echo "CN=TFM Sub CA Classic,O=UPV-TFM,C=ES" ;; *) die "no EJBCA CA for model '$1'" ;; esac
}
urlenc() { jq -rn --arg s "$1" '$s|@uri'; }

# model -> CA certificate files
sub_ca_cert()  { case "$1" in chimera) echo "$CA_CERTS/tfm-sub-ca-hybrid.crt" ;; *) echo "$CA_CERTS/tfm-sub-ca-$1.crt" ;; esac; }
root_ca_cert() { case "$1" in chimera) echo "$CA_CERTS/tfm-root-ca-hybrid.crt" ;; *) echo "$CA_CERTS/tfm-root-ca-$1.crt" ;; esac; }

check_model() { case "$1" in chimera|classic|composite) ;; *) die "model must be chimera, classic or composite" ;; esac; }

der_size()  { o34 x509 -in "$1" -outform DER 2>/dev/null | wc -c; }
pem_size()  { wc -c < "$1"; }

mkdir -p "$RES" "$TT/work"
