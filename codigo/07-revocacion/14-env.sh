#!/usr/bin/env bash
# Block 14 - revocation settings for phc-client v2.3 on the client VMs. Sourced:
#   source 14-env.sh <chimera|classic|composite> <ocsp|crl|none>
# Responders and CRLs are reached through the WireGuard VPN (10.10.0.1).
CA=10.10.0.1
case "$1" in
  chimera)   export PHC_OCSP_URL=http://$CA:8080/ejbca/publicweb/status/ocsp
             export PHC_CRL_URL="http://$CA:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3DTFM%20Sub%20CA%20Hybrid%2CO%3DUPV-TFM%2CC%3DES" ;;
  classic)   export PHC_OCSP_URL=http://$CA:8080/ejbca/publicweb/status/ocsp
             export PHC_CRL_URL="http://$CA:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3DTFM%20Sub%20CA%20Classic%2CO%3DUPV-TFM%2CC%3DES" ;;
  composite) export PHC_OCSP_URL=http://$CA:2560
             export PHC_CRL_URL=http://$CA:8081/tfm-sub-ca-composite.crl ;;
  *) echo "usage: source 14-env.sh <chimera|classic|composite> <ocsp|crl|none>" >&2; return 1 ;;
esac
export PHC_REVOCATION=${2:-ocsp}
export PHC_CRL_CACHE=$HOME/.cache/phc
echo "model=$1 PHC_REVOCATION=$PHC_REVOCATION OCSP=$PHC_OCSP_URL CRL=$PHC_CRL_URL"
