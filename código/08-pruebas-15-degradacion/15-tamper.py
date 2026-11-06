#!/usr/bin/env python3
"""Block 15 - D4a: manipulates a REAL certificate without re-signing it (Python standard library only).
Operations:
  drop-altsig    remove the altSignatureValue extension (2.5.29.74) from the TBS     (Chimera)
  flip-altsig    flip one byte in the middle of the altSignatureValue extension      (Chimera)
  flip-sig-first flip one byte near the start of the outer signature value           (any model)
  flip-sig-last  flip the last byte of the outer signature value                      (any model)
The outer signature is left untouched by drop/flip-altsig, so the classical signature no longer matches.
Usage: python3 -I 15-tamper.py <in.crt> <operation> <out.crt>"""
import base64, re, sys

def tlv(b, i):
    """-> (tag, header_len, content_len) of the DER element at offset i"""
    tag = b[i]; l = b[i + 1]
    if l < 0x80:
        return tag, 2, l
    n = l & 0x7F
    return tag, 2 + n, int.from_bytes(b[i + 2:i + 2 + n], "big")

def children(b, start, end):
    out, i = [], start
    while i < end:
        t, h, l = tlv(b, i)
        out.append((i, t, h, l)); i += h + l
    return out

def enc(tag, content):
    l = len(content)
    if l < 0x80:
        hdr = bytes([tag, l])
    else:
        lb = l.to_bytes((l.bit_length() + 7) // 8, "big"); hdr = bytes([tag, 0x80 | len(lb)]) + lb
    return hdr + content

ALT_SIG_VALUE = bytes.fromhex("0603551d4a")   # OID 2.5.29.74 (altSignatureValue)

def main():
    src, op, dst = sys.argv[1:4]
    pem = open(src).read()
    der = bytearray(base64.b64decode("".join(re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END", pem, re.S).group(1).split())))
    _, h, l = tlv(der, 0)
    tbs, alg, sig = children(der, h, h + l)
    if op.startswith("flip-sig"):
        i, t, hh, ll = sig                       # BIT STRING: first content byte = unused bits
        pos = i + hh + 1 + (40 if op == "flip-sig-first" else ll - 2)
        der[pos] ^= 0x01
        out = bytes(der); note = f"byte {pos} of the outer signature flipped"
    else:
        ti, tt, th, tl = tbs
        fields = children(der, ti + th, ti + th + tl)
        ext_i, et, eh, el = fields[-1]                       # [3] EXPLICIT Extensions
        assert et == 0xA3, "certificate without extensions"
        _, st, sh, sl = children(der, ext_i + eh, ext_i + eh + el)[0]   # SEQUENCE OF Extension
        exts = children(der, ext_i + eh + sh, ext_i + eh + sh + sl)
        new_exts, found = b"", False
        for (xi, xt, xh, xl) in exts:
            e = bytes(der[xi:xi + xh + xl])
            if ALT_SIG_VALUE in e[:xh + 8]:
                found = True
                if op == "drop-altsig":
                    continue
                e = bytearray(e); e[len(e) // 2] ^= 0x01; e = bytes(e)
            new_exts += e
        assert found, "no altSignatureValue extension (not a Chimera certificate)"
        new_tbs_body = b"".join(bytes(der[fi:fi + fh + fl]) for (fi, ft, fh, fl) in fields[:-1]) + enc(0xA3, enc(0x30, new_exts))
        new_tbs = enc(0x30, new_tbs_body)
        out = enc(0x30, new_tbs + bytes(der[alg[0]:alg[0] + alg[2] + alg[3]]) + bytes(der[sig[0]:sig[0] + sig[2] + sig[3]]))
        note = "altSignatureValue removed" if op == "drop-altsig" else "one byte of altSignatureValue flipped"
    b64 = base64.b64encode(out).decode()
    with open(dst, "w") as f:
        f.write("-----BEGIN CERTIFICATE-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE-----\n")
    print(f"{op}: {note}; outer signature not recomputed -> {dst} ({len(out)} B DER)")

if __name__ == "__main__":
    main()
