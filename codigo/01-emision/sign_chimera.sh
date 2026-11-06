#!/usr/bin/env bash
# Issues a Chimera end-entity certificate (TFM-Sub-CA-Hybrid).
# Usage: sign_chimera.sh <username> <csr_file> <output_cert>
exec /home/ca/phc-certdist/sign_ejbca.sh hybrid "$@"
