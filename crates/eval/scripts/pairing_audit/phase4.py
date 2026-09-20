#!/usr/bin/env python3
"""Phase 4: are the errors calibration-fixable? Where does the SEL gain come from?"""
import json, collections

R = [json.loads(l) for l in open(".cache/pairing-audit-20260919/paired-public.jsonl")]
ATT = [r for r in R if r["truth"] == "injection"]
BEN = [r for r in R if r["truth"] == "benign"]

def top(s):
    p = s["probs"]
    return (None, 0.0) if not p else max(p.items(), key=lambda kv: kv[1])
def flag(s, t): 
    lab, mx = top(s); return lab == "injection" and mx >= t
def decided(s, t):
    lab, mx = top(s); return lab is not None and lab != "indeterminate" and mx >= t

BANDS = [(0.7,0.9),(0.9,0.99),(0.99,0.999),(0.999,1.01)]
print("="*88)
print("CONFIDENCE OF WRONG DECISIONS -- can a threshold fix these?")
print("="*88)
for sysname in ("gliner2","jev"):
    print(f"\n{sysname}: FALSE ALARMS (benign called injection), by winning probability")
    fps=[r for r in BEN if flag(r[sysname],0.7)]
    for lo,hi in BANDS:
        n=sum(1 for r in fps if lo<=top(r[sysname])[1]<hi)
        print(f"   p in [{lo:5.3f},{hi:5.3f}) : {n:4d}  ({n/max(len(fps),1)*100:5.1f}% of its false alarms)")
    print(f"   total false alarms          : {len(fps):4d}")
    print(f"\n{sysname}: MISSES called benign (model choice on an attack), by winning probability")
    ms=[r for r in ATT if decided(r[sysname],0.7) and not flag(r[sysname],0.7)]
    for lo,hi in BANDS:
        n=sum(1 for r in ms if lo<=top(r[sysname])[1]<hi)
        print(f"   p in [{lo:5.3f},{hi:5.3f}) : {n:4d}  ({n/max(len(ms),1)*100:5.1f}%)")
    print(f"   total confident misses      : {len(ms):4d}")

print()
print("="*88)
print("WHERE THE SELECTIVE CONFIG'S GAIN COMES FROM")
print("  baseline  = jev@0.5 alone")
print("  candidate = jev@0.5, else GLiNER2@0.99 on rows where Jev did not decide")
print("="*88)
b = lambda r: flag(r["jev"],0.5)
c = lambda r: flag(r["jev"],0.5) or (not decided(r["jev"],0.5) and flag(r["gliner2"],0.99))
gain=[r for r in ATT if c(r) and not b(r)]
cost=[r for r in BEN if c(r) and not b(r)]
print(f"attacks newly caught : +{len(gain)}")
print(f"benign newly flagged : +{len(cost)}")
print("\nnewly caught attacks by source:")
for s,n in collections.Counter(r["source"] for r in gain).most_common():
    print(f"   {s:28s} {n:4d}")
print("\nnewly flagged benign by source:")
for s,n in collections.Counter(r["source"] for r in cost).most_common():
    print(f"   {s:28s} {n:4d}")
print("\nmechanism of the Jev non-decision that GLiNER2 repaired (attacks):")
for s,n in collections.Counter(r["jev"]["reason"] for r in gain).most_common():
    print(f"   {s:34s} {n:4d}")

print()
print("="*88)
print("FALSE-ALARM CONCENTRATION -- does one source drive the OR cliff?")
print("="*88)
fps=[r for r in BEN if flag(r["gliner2"],0.999)]
print(f"GLiNER2 false alarms surviving a 0.999 gate: {len(fps)}")
for s,n in collections.Counter(r["source"] for r in fps).most_common():
    tot=sum(1 for r in BEN if r["source"]==s)
    print(f"   {s:28s} {n:4d} / {tot:4d} benign rows ({n/tot*100:4.1f}%)")
