#!/usr/bin/env bash
# Issues an end-entity certificate from an EJBCA CA (Chimera or classic hierarchy).
# Usage: sign_ejbca.sh <hybrid|classic> <username> <csr_file> <output_cert>
# Flow: (re)create the End Entity with PHCCLIENT/PHCPROFILE and a one-time password,
#       then enroll the CSR through the EJBCA REST API (pkcs10enroll) with SuperAdmin mTLS.
set -euo pipefail

EJBCA=/opt/ejbca/ejbca-ce/bin/ejbca.sh
CREDS=/home/ca/phc-admin-creds
REST_URL=https://ca:8443/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll
CERT_PROFILE=PHCCLIENT
EE_PROFILE=PHCPROFILE

die() { echo "ERROR: $*" >&2; exit 1; }

[ $# -eq 4 ] || die "usage: $0 <hybrid|classic> <username> <csr_file> <output_cert>"
MODEL=$1; USERNAME=$2; CSR=$3; OUT=$4

case "$MODEL" in
  hybrid)  CA_NAME=TFM-Sub-CA-Hybrid ;;
  classic) CA_NAME=TFM-Sub-CA-Classic ;;
  *) die "unknown model '$MODEL' (expected hybrid|classic)" ;;
esac

# Username doubles as CN: only letters, digits, dot and hyphen.
[[ "$USERNAME" =~ ^[A-Za-z0-9.-]{1,64}$ ]] || die "invalid username '$USERNAME'"
[ -r "$CSR" ] || die "CSR not readable: $CSR"
/usr/bin/openssl req -in "$CSR" -noout -verify >/dev/null 2>&1 || die "CSR signature does not verify"

DN="CN=${USERNAME},O=UPV-TFM,C=ES"
OTP=$(/usr/bin/openssl rand -hex 12)

# Remove a previous End Entity with the same username (unique DN is enforced per CA).
sudo -n -u wildfly "$EJBCA" ra delendentity --username "$USERNAME" -force >/dev/null 2>&1 || true

sudo -n -u wildfly "$EJBCA" ra addendentity --username "$USERNAME" --dn "$DN" \
  --caname "$CA_NAME" --type 1 --token USERGENERATED \
  --certprofile "$CERT_PROFILE" --eeprofile "$EE_PROFILE" --password "$OTP" >/dev/null \
  || die "could not create End Entity '$USERNAME'"

PAYLOAD=$(jq -n --rawfile csr "$CSR" \
  --arg cp "$CERT_PROFILE" --arg ep "$EE_PROFILE" --arg ca "$CA_NAME" \
  --arg user "$USERNAME" --arg pwd "$OTP" \
  '{certificate_request:$csr, certificate_profile_name:$cp, end_entity_profile_name:$ep,
    certificate_authority_name:$ca, username:$user, password:$pwd, include_chain:false}')

RESPONSE=$(curl -s --fail-with-body \
  --cacert "$CREDS/managementca.crt" --cert "$CREDS/superadmin.crt" --key "$CREDS/superadmin.key" \
  --resolve ca:8443:127.0.0.1 -H 'Content-Type: application/json' \
  -X POST --data-binary "$PAYLOAD" "$REST_URL") || die "REST enrollment failed: $RESPONSE"

CERT_B64=$(jq -r '.certificate // empty' <<<"$RESPONSE")
[ -n "$CERT_B64" ] || die "no certificate in REST response: $RESPONSE"

base64 -d <<<"$CERT_B64" | /usr/bin/openssl x509 -inform DER -out "$OUT" || die "could not decode certificate"
echo "Issued $MODEL certificate for '$USERNAME' by $CA_NAME -> $OUT"
