#!/usr/bin/env python3
"""Block 14 - E5: cost of one revocation check (phc-bench revcheck), per model and method.
Measured iterations only (warm-up excluded): n, mean, sample standard deviation, median, p95
(inclusive method, as in block 13), min, max. The first check of each series (iteration 0, empty
cache, first request of the process) is reported apart as first_check_ms.
Usage: python3 -I 14-revcheck-stats.py <output.csv> <14-raw-revcheck.csv>"""
import csv, statistics, sys
from collections import defaultdict

rows = list(csv.DictReader(open(sys.argv[2])))
groups, first = defaultdict(list), {}
for r in rows:
    k = (r["host"], r["model"], r["method"])
    if r["iter"] == "0":
        first[k] = r
    if r["phase"] == "measure":
        groups[k].append(r)
with open(sys.argv[1], "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["host", "model", "method", "n", "mean_ms", "sd_ms", "median_ms", "p95_ms", "min_ms", "max_ms",
                "status", "from_cache_share", "first_check_ms", "first_check_from_cache"])
    for k in sorted(groups):
        rs = groups[k]
        v = sorted(float(r["check_ms"]) for r in rs)
        st = sorted({r["status"] for r in rs})
        cache = sum(int(r["from_cache"]) for r in rs) / len(rs)
        p95 = statistics.quantiles(v, n=20, method="inclusive")[18]
        fc = first.get(k)
        w.writerow([*k, len(v), f"{statistics.fmean(v):.4f}", f"{statistics.stdev(v):.4f}", f"{statistics.median(v):.4f}",
                    f"{p95:.4f}", f"{v[0]:.4f}", f"{v[-1]:.4f}", "/".join(st), f"{cache:.2f}",
                    fc["check_ms"] if fc else "", fc["from_cache"] if fc else ""])
        print(f"{k[1]:9} {k[2]:4} n={len(v)} median={statistics.median(v):.3f} p95={p95:.3f} mean={statistics.fmean(v):.3f} "
              f"sd={statistics.stdev(v):.3f} first={fc['check_ms'] if fc else '-'}")
