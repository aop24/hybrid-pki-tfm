#!/usr/bin/env bash
# Creates the delegated OCSP signer of the Composite hierarchy (run once).
#   key p384_mldsa65, issued by the Composite sub CA with EKU OCSPSigning and id-pkix-ocsp-nocheck,
#   validity 730 days (same as the EJBCA responders).
# Adds the [v3_ocsp] extension section to composite-ca.cnf if it is missing (backup kept).
# Output: /home/ca/pki/composite/ocsp/tfm-ocsp-composite.{key,csr,crt}
source "$(dirname "$0")/lib.sh"
OD=/home/ca/pki/composite/ocsp
mkdir -p "$OD"; chmod 700 "$OD"
if ! grep -q '^\[ v3_ocsp \]' "$COMP_CNF"; then
  cp -p "$COMP_CNF" "$COMP_CNF.bak-$(date +%Y%m%d%H%M%S)"
  cat >> "$COMP_CNF" <<'CNF'

[ v3_ocsp ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = OCSPSigning
noCheck                = ignored
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
CNF
  echo "Added [v3_ocsp] to $COMP_CNF"
fi
[ -s "$OD/tfm-ocsp-composite.crt" ] && die "OCSP signer already exists: $OD/tfm-ocsp-composite.crt"
o34 req -new -newkey p384_mldsa65 -nodes -keyout "$OD/tfm-ocsp-composite.key" \
  -subj "/CN=TFM OCSP Composite/O=UPV-TFM/C=ES" -out "$OD/tfm-ocsp-composite.csr" 2>/dev/null
chmod 600 "$OD/tfm-ocsp-composite.key"
o34 ca -config "$COMP_CNF" -name ca_sub -extensions v3_ocsp -days 730 -notext -batch \
  -subj "/CN=TFM OCSP Composite/O=UPV-TFM/C=ES" -in "$OD/tfm-ocsp-composite.csr" \
  -out "$OD/tfm-ocsp-composite.crt" >/dev/null 2>&1 || die "openssl ca failed"
o34 x509 -in "$OD/tfm-ocsp-composite.crt" -noout -subject -issuer -dates -ext extendedKeyUsage,noCheck
echo "Signature algorithm: $(o34 x509 -in "$OD/tfm-ocsp-composite.crt" -noout -text | awk -F': ' '/Signature Algorithm/ {print $2; exit}')"
