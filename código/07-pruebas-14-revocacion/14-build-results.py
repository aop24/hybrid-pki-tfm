#!/usr/bin/env python3
"""Block 14 - builds resultados/14-revocacion.csv (long format: one value per row, with unit) from
  14-propagation.csv      (E2 OCSP / E3 CRL propagation, output of 14-propagation.py)
  14-revcheck-summary.csv (E5 cost of one check, output of 14-revcheck-stats.py)
  14-stale-ocsp.csv       (E2b stale first answer of openssl ocsp, single clock)
  14-revocations.csv      (CA log: revocation instants of the hot-session identities)
and the hot-session events (E4/E1) read from the server logs of client-01, listed in SESSIONS.
Usage: python3 -I 14-build-results.py <raw dir> <propagation.csv> <output.csv>"""
import csv, datetime, os, sys

RAW, PROP, OUT = sys.argv[1:4]

def ms_of(day, hms):  # "2026-10-27", "08:40:34.658" -> epoch ms (UTC)
    d = datetime.datetime.strptime(f"{day} {hms}", "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)
    return round(d.timestamp() * 1000)

rev = {r["serial"]: r for r in csv.DictReader(open(os.path.join(RAW, "14-revocations.csv"))) if r["event"] == "revoked"}
rows = []
def add(exp, model, method, series, metric, value, unit, notes=""):
    rows.append([exp, model, method, series, metric, value, unit, notes])

# E2 / E2b / E3 - propagation polls on client-02 (250 ms OCSP, 1000 ms CRL with PHC_CRL_MAXAGE=30)
for r in csv.DictReader(open(PROP)):
    exp = "E3" if r["method"] == "crl" else ("E2b" if "nonudge" in r["series"] else "E2")
    n = "client clock vs CA clock (uncertainty ~115 ms)"
    add(exp, r["model"], r["method"], r["series"], "delay_from_revocation_start", r["delay_ms"], "ms", n)
    add(exp, r["model"], r["method"], r["series"], "delay_from_revocation_call_end", r["delay_after_revocation_call_ms"], "ms", n)
    add(exp, r["model"], r["method"], r["series"], "last_good_poll_minus_revocation_start", r["last_good_poll_minus_revocation_ms"], "ms",
        "negative = last good poll before the revocation" + ("; inconclusive for the stale answer: within clock uncertainty,"
        " see the single-clock test stale-001" if exp == "E2b" else ""))
    if r["notes"]:
        add(exp, r["model"], r["method"], r["series"], "crl_publication", "", "", r["notes"])

# E2b - single clock on the CA: query, revoke without reload nudge, wait 10 s, query x3
st = list(csv.DictReader(open(os.path.join(RAW, "14-stale-ocsp.csv"))))
t_rev = int(rev["916765CA905488097B5ACC16E7041DA1"]["epoch_ms"])
for r in st:
    add("E2b", "composite", "ocsp", "stale-001 (CA only)", f"answer_{r['step']}", r["ocsp_status"], "status",
        f"{int(r['epoch_ms']) - t_rev} ms after revocation start")

# E4 / E1 - hot session (server client-01: 9400 no check, 9401 OCSP re-check every 30 s; client client-02)
# (model, run, serial, day, cut, accepted after revocation on 9401, on 9400, reconnect 9400, reconnect 9401 check ms, notes)
SESSIONS = [
    ("classic", "run1 rev-classic-1", "4B9349795417193A8C5A128F99F16CAD345BD762", "2026-10-27", "08:23:26.220", None, None, None, None,
     "client v2.3 (NewSessionTicket bug): no client message delivered, cut only"),
    ("classic", "run2 rev-classic-5", "3FB60F18C2CDAF114837BDD1F95FB3585F1A40EF", "2026-10-27", "08:40:34.658", "08:40:34.172",
     "08:40:30.599", "accepted", "21.66", ""),
    ("chimera", "rev-chimera-5", "304D0CF72166AE55318C858E29454E75BD282D25", "2026-10-27", "08:46:03.363", "08:46:02.072",
     "08:46:06.910", "accepted", "68.01", "reconnection done at 17:21 after the VMs had been idle"),
    ("composite", "rev-composite-5", "916765CA905488097B5ACC16E7041DA2", "2026-10-27", "17:24:59.252", None,
     "17:25:03.885", "accepted", "12.46", "no client message between revocation and cut on 9401"),
]
for model, run, serial, day, cut, acc9401, acc9400, rec9400, rec9401, notes in SESSIONS:
    t0 = int(rev[serial]["epoch_ms"])
    n = "server clock (client-01) vs CA clock (uncertainty ~127 ms)"
    add("E4", model, "ocsp", run, "session_cut_after_revocation", ms_of(day, cut) - t0, "ms", n + ("; " + notes if notes else ""))
    add("E4", model, "ocsp", run, "recheck_interval", 30, "s", "PHC_RECHECK_SECS")
    if acc9401:
        add("E4", model, "ocsp", run, "message_accepted_after_revocation", ms_of(day, acc9401) - t0, "ms", "exposure window, port 9401")
    if acc9400:
        add("E1", model, "none", run, "message_accepted_after_revocation", ms_of(day, acc9400) - t0, "ms", "port 9400, session never cut")
    if rec9400:
        add("E1", model, "none", run, "reconnection_with_revoked_cert", rec9400, "result", "port 9400")
    if rec9401:
        add("E4", model, "ocsp", run, "reconnection_with_revoked_cert", "rejected", "result", f"REVOKED after TLS handshake; check {rec9401} ms")

# E5 - cost of one check from client-01 (n = 200 after 20 warm-up)
for r in csv.DictReader(open(os.path.join(RAW, "14-revcheck-summary.csv"))):
    s = f"{r['host']} n={r['n']}"
    for m in ("median", "mean", "sd", "p95", "min", "max"):
        add("E5", r["model"], r["method"], s, f"check_{m}", r[f"{m}_ms"], "ms",
            "CRL from cache (signature verified each time)" if r["method"] == "crl" else "one OCSP request with nonce")
    add("E5", r["model"], r["method"], s, "first_check", r["first_check_ms"], "ms",
        "iteration 0: CRL download + verification" if r["method"] == "crl" else "iteration 0: first OCSP request of the process")

with open(OUT, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["experiment", "model", "method", "series", "metric", "value", "unit", "notes"])
    w.writerows(rows)
print(f"{len(rows)} rows -> {OUT}")
