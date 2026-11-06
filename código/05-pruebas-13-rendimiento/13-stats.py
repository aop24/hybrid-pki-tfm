#!/usr/bin/env python3
"""Block 13 - summary statistics from the raw samples of phc-bench.
Excludes the warm-up iterations. Per group: n, mean, sample standard deviation, median, p95
(linear interpolation, inclusive method), min and max. Times in ms, sizes in bytes.
Usage: python3 -I 13-stats.py <output.csv> <raw.csv>...   (any mix of sig, verify and tls raw files)"""
import csv, statistics, sys
from collections import defaultdict

def stats(v):
    v = sorted(v)
    n = len(v)
    p95 = statistics.quantiles(v, n=20, method="inclusive")[18] if n >= 2 else v[0]
    return [n, statistics.fmean(v), statistics.stdev(v) if n >= 2 else 0.0, statistics.median(v), p95, v[0], v[-1]]

out_rows = []
for path in sys.argv[2:]:
    with open(path) as f:
        rows = [r for r in csv.DictReader(f) if r["phase"] != "warmup"]
    if not rows:
        continue
    groups = defaultdict(list)
    if "alg" in rows[0]:
        for r in rows:
            groups[("sig", r["host"], r["alg"], r["op"], r["phase"], "ms")].append(r)
        metrics = {"ms": ("ms", "sig_bytes")}
    elif "x509_ms" in rows[0]:
        for r in rows:
            for m in ("x509_ms", "hybrid_ms", "x509+hybrid_ms"):
                groups[("verify", r["host"], r["model"], m, r["phase"], m)].append(r)
        metrics = None
    else:
        for r in rows:
            for m in ("tcp_ms", "handshake_ms", "hybrid_ms", "total_ms"):
                groups[("tls", r["host"], r["model"] + "/" + r["chain"] + "/pause" + r.get("pause_ms", "0"), m, r["phase"], m)].append(r)
        metrics = None
    for (test, host, subject, variant, phase, metric), rs in sorted(groups.items()):
        if metric == "x509+hybrid_ms":
            vals = [float(r["x509_ms"]) + float(r["hybrid_ms"]) for r in rs]
        else:
            vals = [float(r[metric]) for r in rs]
        extra = ""
        if test == "sig":
            extra = f"sig_bytes={rs[0]['sig_bytes']}"
        elif test == "tls":
            sent = statistics.median(int(r["hs_bytes_sent"]) for r in rs)
            recv = statistics.median(int(r["hs_bytes_recv"]) for r in rs)
            extra = f"hs_bytes_sent_median={sent:.0f}; hs_bytes_recv_median={recv:.0f}; peer_chain_certs={rs[0]['peer_chain_certs']}; group={rs[0]['group']}"
        n, mean, sd, med, p95, mn, mx = stats(vals)
        out_rows.append([test, host, subject, variant, phase, n, f"{mean:.4f}", f"{sd:.4f}", f"{med:.4f}", f"{p95:.4f}", f"{mn:.4f}", f"{mx:.4f}", extra])

with open(sys.argv[1], "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["test", "host", "subject", "variant", "phase", "n", "mean_ms", "sd_ms", "median_ms", "p95_ms", "min_ms", "max_ms", "notes"])
    w.writerows(out_rows)
print(f"{len(out_rows)} summary rows -> {sys.argv[1]}")
