#!/usr/bin/env python3
"""Block 14 - propagation delay of each revocation, from the revocation log of the CA
(14-revocations.csv) and the polls of the clients (14-raw-poll.csv).
For each poll series (column model = label) the revocation event used is the last one of that
model before the first REVOKED poll. delay_ms = first REVOKED poll - revocation; the bound
"last good poll" gives the uncertainty interval of the measure.
Usage: python3 -I 14-propagation.py <14-revocations.csv> <output.csv> <14-raw-poll-*.csv>..."""
import csv, sys, datetime

# CA and client clocks are compared: NTP offsets measured in the lab differ by up to ~115 ms
CLOCK_TOL_MS = 200

def fmt(ms):
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%H:%M:%S.") + f"{ms % 1000:03d}"

from collections import defaultdict
rev = [r for r in csv.DictReader(open(sys.argv[1]))]
polls = defaultdict(list)
for path in sys.argv[3:]:
    for r in csv.DictReader(open(path)):
        polls[r["model"]].append(r)
out = []
for label, rows in polls.items():
    model = label.split("-")[0]
    first = next((r for r in rows if r["status"] == "REVOKED"), None)
    if not first:
        out.append([label, model, rows[0]["method"], "", "", "", "", "", "not observed", len(rows)])
        continue
    tf = int(first["epoch_ms"])
    cands = [r for r in rev if r["event"] == "revoked" and r["model"] == model and int(r["epoch_ms"]) <= tf]
    if not cands:
        out.append([label, model, first["method"], "", first["utc"], "", "", "", "no revocation logged before", len(rows)])
        continue
    ev = max(cands, key=lambda r: int(r["epoch_ms"]))
    t0 = int(ev["epoch_ms"])
    last_good = max((int(r["epoch_ms"]) for r in rows if r["status"] == "good" and int(r["epoch_ms"]) <= tf), default=None)
    def pub_start(r):  # gen_start_ms=<ms> in detail (older rows: end only)
        for tok in r["detail"].split():
            if tok.startswith("gen_start_ms="):
                return int(tok.split("=")[1])
        return int(r["epoch_ms"])
    pubs = [r for r in rev if r["event"] == "crl_published" and r["model"] == model
            and int(r["epoch_ms"]) >= t0 and pub_start(r) <= tf + CLOCK_TOL_MS]
    note = ""
    if pubs:
        p = pubs[-1]
        note = (f"CRL publication {fmt(pub_start(p))}-{fmt(int(p['epoch_ms']))} UTC; "
                f"detection - publication end = {tf - int(p['epoch_ms'])} ms")
    call = next((int(t.split("=")[1]) for t in ev["detail"].split() if t.startswith("call_ms=")), 0)
    out.append([label, model, first["method"], fmt(t0), first["utc"], tf - t0, tf - t0 - call,
                (last_good - t0) if last_good is not None else "", note, len(rows)])
with open(sys.argv[2], "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["series", "model", "method", "revoked_utc", "first_revoked_poll_utc", "delay_ms", "delay_after_revocation_call_ms", "last_good_poll_minus_revocation_ms", "notes", "polls"])
    w.writerows(out)
for r in out:
    print(" | ".join(str(x) for x in r))
