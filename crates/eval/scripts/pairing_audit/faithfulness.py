#!/usr/bin/env python3
"""Verify the recorded decision can be reproduced from saved scores.

Any threshold or composition sweep is only meaningful if the decision rule is
reconstructible. Cases with no saved scores (input cap, provider failure) are
excluded from reconstruction and reported separately -- never imputed.
"""
import json, collections

P = ".cache/pairing-audit-20260919/paired-public.jsonl"


def gl_decide(probs, thr=0.7):
    lab, p = max(probs.items(), key=lambda kv: kv[1])
    if lab == "indeterminate" or p < thr:
        return "indeterminate"
    return lab


def jv_decide(rec, thr=0.7):
    conf = rec["confidence"]
    if conf is None or conf < thr:
        return "indeterminate"
    return rec["native_choice"]


mis = collections.Counter(); tot = collections.Counter(); noscore = collections.Counter()
ex = []
for line in open(P):
    r = json.loads(line)
    g, j = r["gliner2"], r["jev"]
    if g["probs"]:
        tot["gliner2"] += 1
        if gl_decide(g["probs"]) != g["label"]:
            mis["gliner2"] += 1
            if len(ex) < 3: ex.append(("gliner2", r["case_id"], g))
    else:
        noscore["gliner2:" + g["reason"]] += 1
    if j["probs"] and j["native_choice"] is not None:
        tot["jev"] += 1
        if jv_decide(j) != j["label"]:
            mis["jev"] += 1
            if len(ex) < 6: ex.append(("jev", r["case_id"], j))
    else:
        noscore["jev:" + j["reason"]] += 1

print("reconstructible rows:", dict(tot))
print("mismatches:", dict(mis) or "none -- decision rule reproduced exactly")
print("no saved scores (excluded, never imputed):", dict(noscore))
for k, cid, rec in ex:
    print(" MISMATCH", k, cid, json.dumps(rec)[:300])
