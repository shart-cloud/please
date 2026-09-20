#!/usr/bin/env python3
"""Size a prioritised label-review queue and the unused corpus headroom.

Offline. Prioritisation uses model disagreement ONLY to choose what a human looks
at; reviewers must still be shown cases blind, and a random control stratum is
included so the label-error base rate can be estimated without selection bias.
"""
import json, collections

R = [json.loads(l) for l in open(".cache/pairing-audit-20260919/paired-public.jsonl")]
SEL = json.load(open(".cache/jev-scale-20260918/selection.json"))

def top(s):
    p = s["probs"]; return (None, 0.0) if not p else max(p.items(), key=lambda kv: kv[1])
def dec(s):
    return None if s["abstained"] else s["label"]
def conf(s, t=0.9):
    lab, mx = top(s); return lab is not None and lab != "indeterminate" and mx >= t

print("=" * 84)
print("A. UNUSED CORPUS HEADROOM  (already cached locally, zero acquisition cost)")
print("=" * 84)
print(f"{'stratum':38s} {'used':>7s} {'available':>10s} {'unused':>9s}")
tot_u = 0
for pol in ("injection", "benign"):
    for src, used in SEL["quotas"][pol].items():
        avail = SEL["available"].get(f"{pol}:{src}", 0)
        unused = max(avail - used, 0); tot_u += unused
        star = "  <-- large" if unused >= 500 else ""
        print(f"{pol+':'+src:38s} {used:7d} {avail:10d} {unused:9d}{star}")
print(f"{'TOTAL UNUSED':38s} {'':7s} {'':10s} {tot_u:9d}")
print("\nexclusions applied during selection:", SEL["exclusions"])

print()
print("=" * 84)
print("B. PRIORITISED LABEL-REVIEW QUEUE  (where the upstream label is most suspect)")
print("=" * 84)
strata = collections.OrderedDict()
strata["both systems confidently contradict the label"] = lambda r: (
    conf(r["gliner2"]) and conf(r["jev"]) and dec(r["gliner2"]) == dec(r["jev"])
    and dec(r["jev"]) is not None and dec(r["jev"]) != r["truth"])
strata["both confidently agree WITH the label (control)"] = lambda r: (
    conf(r["gliner2"]) and conf(r["jev"]) and dec(r["gliner2"]) == dec(r["jev"])
    and dec(r["jev"]) == r["truth"])
strata["systems confidently contradict EACH OTHER"] = lambda r: (
    conf(r["gliner2"]) and conf(r["jev"]) and dec(r["gliner2"]) != dec(r["jev"]))
strata["one confidently contradicts, other abstained"] = lambda r: (
    ((conf(r["gliner2"]) and dec(r["gliner2"]) != r["truth"] and dec(r["jev"]) is None) or
     (conf(r["jev"]) and dec(r["jev"]) != r["truth"] and dec(r["gliner2"]) is None)))
strata["both abstained (definition may not apply)"] = lambda r: (
    dec(r["gliner2"]) is None and dec(r["jev"]) is None)

assigned = set()
for name, fn in strata.items():
    rows = [r for r in R if r["case_id"] not in assigned and fn(r)]
    for r in rows: assigned.add(r["case_id"])
    by_truth = collections.Counter(r["truth"] for r in rows)
    print(f"\n{name}")
    print(f"   n = {len(rows)}   (attacks {by_truth['injection']}, benign {by_truth['benign']})")
    for s, n in collections.Counter(r["source"] for r in rows).most_common(5):
        print(f"      {s:30s} {n:5d}")

print(f"\nunassigned remainder: {len(R) - len(assigned)}")
print("""
Review design note: strata 1, 3 and 4 are model-selected and therefore BIASED --
reviewing only these finds the label errors models happen to notice and pulls the
label set toward model predictions. Stratum 2 is the random-control counterweight:
sample it at the same rate, present every case blind and interleaved, and the
difference in confirmed-error rate estimates the true base rate.""")
