#!/usr/bin/env bash
# Block 15 - D2: TLS clients of three generations against the D2 servers of <server-ip>:
#   old = OpenSSL 3.0.13 without oqs-provider (classic-only client), old+oqs, new = 3.4.0 + oqs-provider.
# The client verifies the server chain against the CA bundle of the model (-verify_return_error).
# Usage: 15-d2-tls-clients.sh <server-ip>
source "$(dirname "$0")/15-common.sh"
[ $# -eq 1 ] || { echo "usage: $0 <server-ip>" >&2; exit 2; }
port() { case "$1" in classic) echo 9500 ;; chimera) echo 9501 ;; composite) echo 9502 ;; esac; }
for m in classic chimera composite; do
  for v in OLD OLDOQS NEW; do
    name=$(tr 'A-Z' 'a-z' <<<"$v" | sed 's/oldoqs/old+oqs/')
    case "$v:$m" in OLD:composite|OLDOQS:composite) exp=reject ;; *) exp=accept ;; esac
    # timeout cannot run a shell function directly: the function definition is passed to a child bash
    out=$(timeout 15 bash -c "$(declare -f "$v"); \"\$@\"" _ "$v" s_client -connect "$1:$(port "$m")" -servername "$1" -CAfile "$(bundle "$m")" \
          -verify_return_error -brief -cipher 'DEFAULT:@SECLEVEL=0' < /dev/null 2>&1)
    if grep -q 'CONNECTION ESTABLISHED' <<<"$out" && grep -q 'Verification: OK' <<<"$out"; then
      RESULT=accept; DETAIL="$(grep -m1 'Protocol version' <<<"$out"); $(grep -m1 -E 'Peer signature type|Signature type' <<<"$out")"
    else
      RESULT=reject; DETAIL="$(grep -m2 -E 'alert|error|verify|routines' <<<"$out" | sed -E 's/^[0-9A-F]+:error:[0-9A-F]+://' | tr '\n' ' ')"
    fi
    record D2 "$name" "$m" "tls $1:$(port "$m")" "$exp" "$RESULT" "$DETAIL"
  done
done
