#!/usr/bin/env python3
"""Phase 2: operating points and composition from cached scores only.

Rules honoured:
  - never impute a missing score (input cap / provider failure stay non-decisions)
  - denominators are always all 3000 attacks / all 3000 benign
  - no source id or expected label may enter any policy
"""
import json

R = [json.loads(l) for l in open(".cache/pairing-audit-20260919/paired-public.jsonl")]
ATT = [r for r in R if r["truth"] == "injection"]
BEN = [r for r in R if r["truth"] == "benign"]


def flag(sysrec, thr):
    """Would this system flag injection at threshold thr? None-safe."""
    p = sysrec["probs"]
    if not p:
        return False                      # cap / provider failure: never a detection
    lab, mx = max(p.items(), key=lambda kv: kv[1])
    return lab == "injection" and mx >= thr


def decided(sysrec, thr):
    p = sysrec["probs"]
    if not p:
        return False
    lab, mx = max(p.items(), key=lambda kv: kv[1])
    return lab != "indeterminate" and mx >= thr


def evaluate(policy):
    tp = sum(1 for r in ATT if policy(r))
    fp = sum(1 for r in BEN if policy(r))
    return tp, fp


def row(name, policy):
    tp, fp = evaluate(policy)
    print(f"{name:52s} {tp:5d}/3000 ({tp/30:5.1f}%) {fp:5d}/3000 ({fp/30:5.2f}%)")
    return tp, fp


print("=" * 100)
print("OPERATING POINTS -- all denominators are the full 3000; abstentions/failures count as misses")
print(f"{'configuration':52s} {'attack recall':>20s} {'benign false alarms':>21s}")
print("=" * 100)

print("\n-- shipped baselines --")
base_tp, base_fp = row("Jev alone @0.7 (shipping gate)", lambda r: flag(r["jev"], 0.7))
row("GLiNER2 alone @0.7", lambda r: flag(r["gliner2"], 0.7))

print("\n-- GLiNER2 alone, threshold sweep --")
for t in (0.7, 0.8, 0.9, 0.95, 0.99, 0.995, 0.999):
    row(f"GLiNER2 alone @{t}", lambda r, t=t: flag(r["gliner2"], t))

print("\n-- Jev alone, threshold sweep --")
for t in (0.5, 0.6, 0.7, 0.8, 0.9):
    row(f"Jev alone @{t}", lambda r, t=t: flag(r["jev"], t))

print("\n-- OR (either flags) --")
for t in (0.7, 0.9, 0.99, 0.999):
    row(f"OR: Jev@0.7 or GLiNER2@{t}", lambda r, t=t: flag(r["jev"], 0.7) or flag(r["gliner2"], t))

print("\n-- AND (both flag) --")
row("AND: Jev@0.7 and GLiNER2@0.7", lambda r: flag(r["jev"], 0.7) and flag(r["gliner2"], 0.7))

print("\n-- SELECTIVE: GLiNER2 used ONLY where Jev returned no decision --")
print("   (Jev keeps full authority wherever it decided; GLiNER2 repairs coverage only)")
for t in (0.7, 0.9, 0.99, 0.999):
    row(f"Jev@0.7, else GLiNER2@{t} on Jev non-decisions",
        lambda r, t=t: flag(r["jev"], 0.7) or (not decided(r["jev"], 0.7) and flag(r["gliner2"], t)))

print("\n" + "=" * 100)
print("CASCADE CEILING ANALYSIS (what a GLiNER2-prefilter cascade can NEVER recover)")
print("=" * 100)
gl_neg = [r for r in ATT if not flag(r["gliner2"], 0.7)]
print(f"attacks GLiNER2 does not flag @0.7           : {len(gl_neg):5d}/3000")
print(f"  ... of which Jev alone WOULD have caught   : {sum(1 for r in gl_neg if flag(r['jev'],0.7)):5d}"
      "   <- lost forever if only GLiNER2 positives are routed to Jev")
routed = [r for r in ATT if flag(r["gliner2"], 0.7)]
print(f"attack routing fraction (GLiNER2 positives)  : {len(routed)/len(ATT)*100:5.1f}% of attacks")
ben_routed = [r for r in BEN if flag(r["gliner2"], 0.7)]
print(f"benign routing fraction                      : {len(ben_routed)/len(BEN)*100:5.1f}% of benign")
jv_conf_miss = [r for r in ATT if decided(r["jev"], 0.7) and not flag(r["jev"], 0.7)]
print(f"\nJev CONFIDENT misses (decided 'benign' on an attack): {len(jv_conf_miss):5d}")
print(f"  ... recoverable by routing Jev *uncertainty* only  :     0   (they are not uncertain)")
print(f"  ... of which GLiNER2 flags                         : {sum(1 for r in jv_conf_miss if flag(r['gliner2'],0.7)):5d}"
      "   <- only an OR/selective-override reaches these")
