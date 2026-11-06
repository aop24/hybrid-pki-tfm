#!/usr/bin/env python3
"""Block 16 - summary of the scale test (host results + CA monitor) -> resultados/16-escala.csv (long format).
Inputs: <results dir> (16-runs.csv, 16-issue.csv, 16-tls.csv, <run>/ with *.window and host-vmstat.txt)
        <16-ca-monitor.csv> (one sample per second on the CA)
Run series:
  issue  every run in 16-runs.csv except those with 0 certificates issued (CA down, see bitácora)
  tls    "tls" = reference series of 2026-11-03 (common start instant); "tls-replica1" = earlier valid runs
         (composite 2026-11-01 11:2x, chimera 2026-11-03 07:4x); "tls-superseded" = runs not usable, with the reason.
Usage: python3 -I 16-analyze.py <results dir> <16-ca-monitor.csv> <output.csv>"""
import csv, os, statistics, sys

RES, MON, OUT = sys.argv[1:4]
runs = list(csv.DictReader(open(os.path.join(RES, "16-runs.csv"))))
issue = list(csv.DictReader(open(os.path.join(RES, "16-issue.csv"))))
tls = list(csv.DictReader(open(os.path.join(RES, "16-tls.csv"))))
# The CA lost power on 2026-10-29 after 17:51:19 UTC: the unwritten tail of the file is a run of NUL bytes,
# which is dropped here (the samples before and after it are intact).
raw = open(MON, "rb").read()
nul = raw.count(b"\x00")
mon = [r for r in csv.DictReader(raw.replace(b"\x00", b"").decode().splitlines()) if r["epoch_ms"].isdigit()]
for r in mon:
    r["t"] = int(r["epoch_ms"])
print(f"CA monitor: {len(mon)} samples, {nul} NUL bytes dropped")

def q(v, p):
    v = sorted(v)
    return statistics.quantiles(v, n=100, method="inclusive")[p - 1] if len(v) > 1 else v[0]

def ca_window(t0, t1):
    s = [r for r in mon if t0 - 1000 <= r["t"] <= t1 + 1000]
    if not s:
        return None
    f = lambda k: [float(r[k]) for r in s]
    return {"samples": len(s), "cpu_mean": statistics.fmean(f("cpu_busy_pct")), "cpu_max": max(f("cpu_busy_pct")),
            "mem_max": max(f("mem_used_mb")), "wildfly_max": max(f("wildfly_rss_mb")), "mariadb_max": max(f("mariadb_rss_mb")),
            "cli_jvms_max": max(f("cli_jvms"))}

def vmstat(run):
    p = os.path.join(RES, run, "host-vmstat.txt")
    if not os.path.exists(p):
        return None
    rows = [l.split() for l in open(p) if l.strip() and l.split()[0].isdigit()]
    if not rows:
        return None
    busy = [100 - int(r[14]) for r in rows]          # 100 - id
    return {"busy_mean": statistics.fmean(busy), "busy_max": max(busy), "free_min_mb": min(int(r[3]) for r in rows) // 1024,
            "swpd_max_mb": max(int(r[2]) for r in rows) // 1024, "runq_max": max(int(r[0]) for r in rows)}

def windows(run):
    d = os.path.join(RES, run)
    w = []
    for f in os.listdir(d) if os.path.isdir(d) else []:
        if f.endswith(".window"):
            cn, s, e = open(os.path.join(d, f)).read().strip().split(",")
            w.append((int(s), int(e)))
    return w

out = []
def add(series, model, n, policy, metric, value, unit, notes=""):
    out.append([series, model, n, policy, metric, value if isinstance(value, str) else f"{value:.3f}" if isinstance(value, float) else value, unit, notes])

for run in runs:
    rid, kind, model, n = run["run"], run["kind"], run["model"], int(run["n"])
    go, end = int(run["go_ms"]), int(run["end_ms"])
    if kind == "issue":
        rows = [r for r in issue if r["run"] == rid]
        ok = [r for r in rows if r["rc"] == "0"]
        if not ok:
            add("issue-invalid", model, n, run["policy"], "issued", 0, "count", f"{rid}: WildFly down on the CA (excluded)")
            continue
        it = [float(r["issue_ms"]) for r in ok]
        att = [int(r["attempts"]) for r in rows]
        tag = f"run {rid}"
        add("issue", model, n, run["policy"], "issued_ok", len(ok), "count", tag)
        add("issue", model, n, run["policy"], "failed", n - len(ok), "count",
            "; ".join(sorted({r["error"].strip() for r in rows if r["rc"] != "0"})) or "")
        for name, v, u in (("issue_median", statistics.median(it), "ms"), ("issue_p95", q(it, 95), "ms"),
                           ("issue_max", max(it), "ms"), ("issue_mean", statistics.fmean(it), "ms")):
            add("issue", model, n, run["policy"], name, v, u)
        add("issue", model, n, run["policy"], "wall", (end - go) / 1000, "s", "common start -> last result")
        add("issue", model, n, run["policy"], "throughput", len(ok) / ((end - go) / 1000), "certificates/s")
        add("issue", model, n, run["policy"], "attempts_max", max(att), "count", "retry: re-sent after a failed attempt")
        add("issue", model, n, run["policy"], "keygen_median", statistics.median(float(r["keygen_ms"]) for r in rows), "ms",
            "key + CSR in the container, before the common start")
        ca = ca_window(go, end)
        if ca:
            for k, u in (("cpu_mean", "%"), ("cpu_max", "%"), ("mem_max", "MB"), ("wildfly_max", "MB"),
                         ("mariadb_max", "MB"), ("cli_jvms_max", "count")):
                add("issue", model, n, run["policy"], "ca_" + k, ca[k], u, f"{ca['samples']} CA samples (1 s)")
        else:
            add("issue", model, n, run["policy"], "ca_samples", 0, "count", "no CA monitor samples in this window")
    else:
        rows = [r for r in tls if r["run"] == rid and r["phase"] == "measure"]
        hs = [float(r["handshake_ms"]) for r in rows]
        w = windows(rid)
        policy = run["policy"]
        stamp = rid.split("-")[-1]
        # Classification (see bitácora 16): only runs whose clients really overlapped are kept.
        if stamp.startswith("20261029") or stamp in ("20261101T105041", "20261101T105106", "20261101T105222",
                                                     "20261101T105520", "20261101T110139"):
            series, why = "tls-superseded", "duration included container teardown; server name resolved by Docker DNS on every handshake"
        elif (model, n, policy) in (("chimera", 99, "hs=20"), ("classic", 99, "hs=20")) and stamp in ("20261103T075031", "20261103T101608"):
            series, why = "tls-superseded", "clients did not overlap: median below that of N=25 and duration >> 20 x median"
        elif stamp.startswith("20261101T112") or stamp.startswith("20261103T074"):
            series, why = "tls-replica1", "first valid replica"
        else:
            series, why = "tls", "reference series (2026-11-03, common start instant)"
        if not hs:
            continue
        add(series, model, n, policy, "handshakes_measured", len(hs), "count", f"run {rid}" + (f"; {why}" if why else ""))
        add(series, model, n, policy, "handshakes_failed", int(run["failed"]), "count")
        for name, v in (("handshake_median", statistics.median(hs)), ("handshake_p95", q(hs, 95)), ("handshake_mean", statistics.fmean(hs))):
            add(series, model, n, policy, name, v, "ms", "TLS 1.3 handshake measured by the client")
        if w:
            s0, e1 = min(s for s, _ in w), max(e for _, e in w)
            add(series, model, n, policy, "client_start_spread", max(s for s, _ in w) - s0, "ms", "first to last client start")
            add(series, model, n, policy, "active_window", (e1 - s0) / 1000, "s")
            add(series, model, n, policy, "throughput", len(hs) / ((e1 - s0) / 1000), "handshakes/s",
                "measured handshakes / active window (warm-up included in the window)")
        else:
            add(series, model, n, policy, "throughput_wall", len(hs) / ((end - go) / 1000), "handshakes/s", "no client windows: wall time")
    vm = vmstat(rid)
    if vm and not (kind == "issue" and not [r for r in issue if r["run"] == rid and r["rc"] == "0"]):
        ser = "issue" if kind == "issue" else out[-1][0]
        pol = run["policy"]
        for k, u in (("busy_mean", "%"), ("busy_max", "%"), ("free_min_mb", "MB"), ("swpd_max_mb", "MB"), ("runq_max", "count")):
            add(ser, model, n, pol, "host_" + k, vm[k], u, "host vmstat (1 s) during the run")

with open(OUT, "w", newline="") as f:
    wr = csv.writer(f)
    wr.writerow(["series", "model", "n", "policy", "metric", "value", "unit", "notes"])
    wr.writerows(out)
print(f"{len(out)} rows -> {OUT}")
