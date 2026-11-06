#!/usr/bin/env bash
# Issues a classic end-entity certificate (TFM-Sub-CA-Classic).
# Usage: sign_classic.sh <username> <csr_file> <output_cert>
exec /home/ca/phc-certdist/sign_ejbca.sh classic "$@"
