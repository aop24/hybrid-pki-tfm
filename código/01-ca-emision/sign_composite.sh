#!/usr/bin/env bash
# Issues a Composite (p384_mldsa65) end-entity certificate with the OpenSSL Composite sub CA.
# Usage: sign_composite.sh <username> <csr_file> <output_cert>
set -euo pipefail

# Runs outside an interactive shell (systemd): select OpenSSL 3.4.0 + oqs-provider explicitly.
export PATH=/opt/openssl32/bin:$PATH
export LD_LIBRARY_PATH=/opt/openssl32/lib64:/opt/openssl32/lib
OPENSSL=/opt/openssl32/bin/openssl
CNF=/home/ca/pki/composite/composite-ca.cnf

die() { echo "ERROR: $*" >&2; exit 1; }

[ $# -eq 3 ] || die "usage: $0 <username> <csr_file> <output_cert>"
USERNAME=$1; CSR=$2; OUT=$3

[[ "$USERNAME" =~ ^[A-Za-z0-9.-]{1,64}$ ]] || die "invalid username '$USERNAME'"
[ -r "$CSR" ] || die "CSR not readable: $CSR"
"$OPENSSL" req -in "$CSR" -noout -verify >/dev/null 2>&1 || die "CSR signature does not verify"

# Only Composite keys are accepted by this CA.
ALG=$("$OPENSSL" req -in "$CSR" -noout -text 2>/dev/null | awk -F': ' '/Public Key Algorithm/ && n==0 {print $2; n=1}')
[ "$ALG" = "p384_mldsa65" ] || die "unexpected key algorithm '$ALG' (expected p384_mldsa65)"

# The subject is set by the CA from the username, never taken from the CSR.
"$OPENSSL" ca -config "$CNF" -name ca_sub -extensions v3_client -days 730 -notext -batch \
  -subj "/CN=${USERNAME}/O=UPV-TFM/C=ES" -in "$CSR" -out "$OUT" >/dev/null 2>&1 \
  || die "openssl ca failed for '$USERNAME'"

echo "Issued composite certificate for '$USERNAME' by TFM-Sub-CA-Composite -> $OUT"
