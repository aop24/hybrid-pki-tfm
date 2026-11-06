#!/usr/bin/env python3
"""Block 12 - breakdown of the OCSP responses measured by 12-ocsp-sizes.sh.
Appends to 12-tamanos.csv, per model and status: the size of the embedded certificates and of the
response without them (status + signature).
Usage: python3 -I 12-ocsp-breakdown.py"""
import datetime, os
MAT = "/home/ca/tfm-tests/material"; CSV = "/home/ca/tfm-results/12-tamanos.csv"
def tlv(b, i):
    l = b[i + 1]; h = 2
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(b[i + 2:i + 2 + n], "big"); h = 2 + n
    return b[i], h, l
def kids(b, i):
    _, h, l = tlv(b, i); j = i + h; out = []
    while j < i + h + l:
        t, hh, ll = tlv(b, j); out.append((t, j, hh + ll)); j += hh + ll
    return out
ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with open(CSV, "a") as out:
    for m in ("classic", "chimera", "composite"):
        for s in ("good", "revoked"):
            d = open(f"{MAT}/{m}/ocsp/ocsp-{s}.resp.der", "rb").read()
            rb = kids(d, kids(d, 0)[1][1])[0]
            octet = kids(d, rb[1])[1]
            _, h, _ = tlv(d, octet[1])
            basic = kids(d, octet[1] + h)
            certs = [x for x in basic if x[0] == 0xa0]
            sizes = [c[2] for c in kids(d, kids(d, certs[0][1])[0][1])] if certs else []
            out.write(f"{ts},{m},ocsp_response_embedded_certs,{s},,{sum(sizes)},,,,certs={len(sizes)} sizes={'+'.join(map(str, sizes))}\n")
            out.write(f"{ts},{m},ocsp_response_without_certs,{s},,{len(d) - sum(sizes)},,,,status + signature (signature BIT STRING {basic[2][2]} B)\n")
            print(f"{m} {s}: embedded={sum(sizes)} without_certs={len(d) - sum(sizes)}")
