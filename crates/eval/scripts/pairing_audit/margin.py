#!/usr/bin/env python3
"""Does GLiNER2's LOGIT MARGIN rank better than its saturated probability?

Offline, no inference. If margin-ranking does not beat max-prob ranking, the
features are uninformative on these cases and head-only tuning will not help.
"""
import json

R = [json.loads(l) for l in open(".cache/pairing-audit-20260919/paired-public.jsonl")]
ATT = [r for r in R if r["truth"] == "injection"]
BEN = [r for r in R if r["truth"] == "benign"]

def margin(s):
    """z_injection - max(z_benign, z_indeterminate); None when no saved logits."""
    z = s["logits"]
    if not z: return None
    return z["injection"] - max(z["benign"], z["indeterminate"])

def maxprob(s):
    p = s["probs"]
    if not p: return None
    lab, mx = max(p.items(), key=lambda kv: kv[1])
    return mx if lab == "injection" else -1.0

def curve(score_fn, label):
    a = sorted([x for x in (score_fn(r["gliner2"]) for r in ATT) if x is not None])
    b = sorted([x for x in (score_fn(r["gliner2"]) for r in BEN) if x is not None])
    print(f"\n{label}: scored {len(a)} attacks / {len(b)} benign (no-score rows excluded from"
          f" the curve but counted as misses in recall below)")
    print(f"   {'FP budget':>10s} {'threshold':>12s} {'recall':>16s}")
    for budget in (0, 4, 9, 20, 50, 100):
        # highest threshold achieving <= budget false positives
        thr = b[len(b) - budget - 1] if budget < len(b) else float("-inf")
        thr = thr + 1e-12
        tp = sum(1 for x in a if x > thr)
        print(f"   {budget:>10d} {thr:12.4f} {tp:6d}/3000 ({tp/30:5.1f}%)")
    # AUC over scored rows only
    import bisect
    auc = sum(bisect.bisect_left(b, x) + 0.5*(bisect.bisect_right(b,x)-bisect.bisect_left(b,x))
              for x in a) / (len(a)*len(b))
    print(f"   AUC (scored rows only): {auc:.4f}")

print("="*78)
print("RANKING QUALITY OF GLiNER2's OWN SCORES  (no training, cached logits)")
print("="*78)
curve(maxprob, "max-probability (what the current gate uses)")
curve(margin,  "logit margin  z_inj - max(z_ben, z_ind)")
