#!/usr/bin/env python3
"""Phase 3: Pareto frontier + recall at explicit false-positive budgets."""
import json

R = [json.loads(l) for l in open(".cache/pairing-audit-20260919/paired-public.jsonl")]
ATT = [r for r in R if r["truth"] == "injection"]
BEN = [r for r in R if r["truth"] == "benign"]
GRID = [0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 0.999]


def top(s):
    p = s["probs"]
    if not p: return None, 0.0
    return max(p.items(), key=lambda kv: kv[1])


def flag(s, t):
    lab, mx = top(s)
    return lab == "injection" and mx >= t


def decided(s, t):
    lab, mx = top(s)
    return lab is not None and lab != "indeterminate" and mx >= t


def build():
    cfgs = []
    for jt in GRID:
        cfgs.append((f"jev@{jt}", lambda r, jt=jt: flag(r["jev"], jt)))
    for gt in GRID:
        cfgs.append((f"gliner2@{gt}", lambda r, gt=gt: flag(r["gliner2"], gt)))
    for jt in GRID:
        for gt in GRID:
            cfgs.append((f"OR jev@{jt}|gl@{gt}",
                         lambda r, jt=jt, gt=gt: flag(r["jev"], jt) or flag(r["gliner2"], gt)))
            cfgs.append((f"AND jev@{jt}&gl@{gt}",
                         lambda r, jt=jt, gt=gt: flag(r["jev"], jt) and flag(r["gliner2"], gt)))
            cfgs.append((f"SEL jev@{jt} else gl@{gt}",
                         lambda r, jt=jt, gt=gt: flag(r["jev"], jt) or
                         (not decided(r["jev"], jt) and flag(r["gliner2"], gt))))
    return cfgs


res = []
for name, fn in build():
    tp = sum(1 for r in ATT if fn(r))
    fp = sum(1 for r in BEN if fn(r))
    res.append((name, tp, fp))

print("=" * 92)
print("RECALL AT EXPLICIT FALSE-POSITIVE BUDGETS  (denominators: 3000 attacks / 3000 benign)")
print("=" * 92)
print(f"{'FP budget':>12s}  {'best recall':>13s}  configuration")
for budget in (0, 4, 10, 20, 50, 100, 200):
    ok = [x for x in res if x[2] <= budget]
    if not ok:
        print(f"{budget:>12d}  {'--':>13s}  (no configuration)"); continue
    best = max(ok, key=lambda x: (x[1], -x[2]))
    print(f"{budget:>12d}  {best[1]:5d} ({best[1]/30:4.1f}%)  {best[0]}   [FP={best[2]}]")

print()
print("=" * 92)
print("FALSE ALARMS AT MATCHED RECALL  (how cheaply can each family reach a recall level?)")
print("=" * 92)
print(f"{'recall >=':>10s}  {'family':>10s}  {'min FP':>7s}  configuration")
for target in (1854, 1976, 2100, 2200, 2300):
    for fam, pred in (("jev-only", lambda n: n.startswith("jev@")),
                      ("gliner2", lambda n: n.startswith("gliner2@")),
                      ("OR", lambda n: n.startswith("OR")),
                      ("SEL", lambda n: n.startswith("SEL")),
                      ("AND", lambda n: n.startswith("AND"))):
        ok = [x for x in res if x[1] >= target and pred(x[0])]
        if not ok:
            print(f"{target:>10d}  {fam:>10s}  {'--':>7s}  unreachable"); continue
        best = min(ok, key=lambda x: (x[2], -x[1]))
        print(f"{target:>10d}  {fam:>10s}  {best[2]:7d}  {best[0]}  [recall={best[1]}]")
    print()

print("=" * 92)
print("PARETO FRONTIER (nondominated: no other config has >= recall AND <= false alarms)")
print("=" * 92)
front = [x for x in res if not any(y[1] >= x[1] and y[2] <= x[2] and y[:1] != x[:1] and
                                   (y[1] > x[1] or y[2] < x[2]) for y in res)]
seen = set()
for name, tp, fp in sorted(front, key=lambda x: x[2]):
    if (tp, fp) in seen: continue
    seen.add((tp, fp))
    print(f"  FP={fp:4d} ({fp/30:5.2f}%)  recall={tp:5d} ({tp/30:5.1f}%)   {name}")
