#!/usr/bin/env bash
# Block 15 - D3/D4b: builds the TEST Chimera hierarchy with Forge15 (BouncyCastle 1.84, the jars that ship with
# EJBCA in this CA). Output: public certificates only (no private key is written).
# Uses javac if present; otherwise the precompiled Forge15.class of the package (compiled for Java 21).
# Usage: 15-forge.sh [output dir=/home/ca/tfm-tests/work/forge15]
set -euo pipefail
cd "$(dirname "$0")"
OUT=${1:-/home/ca/tfm-tests/work/forge15}; mkdir -p "$OUT"; rm -f "$OUT"/*.crt
jar() { find /opt/ejbca -name "$1-jdk18on-*.jar" -print -quit 2>/dev/null || true; }   # find returns 1 on unreadable dirs
CP=$(jar bcprov):$(jar bcpkix):$(jar bcutil)
[[ "$CP" == *bcprov*bcpkix*bcutil* ]] || { echo "BouncyCastle jars not found under /opt/ejbca" >&2; exit 1; }
echo "classpath: $CP"
if command -v javac >/dev/null; then javac -cp "$CP" -d . Forge15.java; echo "compiled with $(javac -version 2>&1)"; else echo "javac not found: using the precompiled Forge15.class"; fi
java -cp "$CP:." Forge15 "$OUT"
sha256sum "$OUT"/*.crt
