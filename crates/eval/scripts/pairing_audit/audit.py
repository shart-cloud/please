#!/usr/bin/env python3
"""Phase 1: offline paired disagreement and error audit. No inference, no API."""
import json, collections

P = ".cache/pairing-audit-20260919/paired-public.jsonl"
R = [json.loads(l) for l in open(P)]


def det(sysrec):
    """Determinate detection decision, or None when the system did not decide."""
    return None if sysrec["abstained"] else sysrec["label"]


def cell(r):
    g, j = det(r["gliner2"]), det(r["jev"])
    gi, ji = (g == "injection"), (j == "injection")
    if g is None and j is None: return "neither_decided"
    if g is None: return "jev_only_decided"
    if j is None: return "gliner2_only_decided"
    if gi and ji: return "both_flag"
    if gi: return "gliner2_only_flag"
    if ji: return "jev_only_flag"
    return "neither_flags"


print("=" * 78)
print("PAIRED DETECTOR TABLE -- 6,000 public cases, frozen runs, no new inference")
print("=" * 78)
for truth in ("injection", "benign"):
    sub = [r for r in R if r["truth"] == truth]
    c = collections.Counter(cell(r) for r in sub)
    print(f"\n{truth.upper()}  (n={len(sub)})")
    for k in ("both_flag", "gliner2_only_flag", "jev_only_flag", "neither_flags",
              "gliner2_only_decided", "jev_only_decided", "neither_decided"):
        v = c.get(k, 0)
        print(f"  {k:24s} {v:5d}  ({v/len(sub)*100:5.1f}%)")

print()
print("=" * 78)
print("ERROR / NON-DECISION TAXONOMY  (mechanism of every non-detection)")
print("=" * 78)
for name in ("gliner2", "jev"):
    print(f"\n{name}")
    for truth in ("injection", "benign"):
        sub = [r for r in R if r["truth"] == truth]
        c = collections.Counter()
        for r in sub:
            s = r[name]
            d = det(s)
            if d == "injection":
                c["flagged injection"] += 1
            elif d == "benign":
                c["called benign (model choice)"] += 1
            elif s["reason"] == "score_gate":
                c["abstained: score gate"] += 1
            elif s["reason"] == "input_cap":
                c["abstained: input cap"] += 1
            else:
                c["failed: " + s["reason"].split(":", 1)[1]] += 1
        print(f"  truth={truth} (n={len(sub)})")
        for k, v in sorted(c.items(), key=lambda kv: -kv[1]):
            print(f"      {k:34s} {v:5d} ({v/len(sub)*100:5.1f}%)")

print()
print("=" * 78)
print("COMPLEMENTARITY BY SOURCE  (attacks: who catches what the other misses)")
print("=" * 78)
print(f"{'source':28s} {'n':>5s} {'both':>6s} {'gl_only':>8s} {'jev_only':>9s} {'neither':>8s}")
for src in sorted({r["source"] for r in R if r["truth"] == "injection"}):
    sub = [r for r in R if r["truth"] == "injection" and r["source"] == src]
    c = collections.Counter(cell(r) for r in sub)
    both = c.get("both_flag", 0)
    go = c.get("gliner2_only_flag", 0) + sum(1 for r in sub if cell(r) == "gliner2_only_decided" and det(r["gliner2"]) == "injection")
    jo = c.get("jev_only_flag", 0) + sum(1 for r in sub if cell(r) == "jev_only_decided" and det(r["jev"]) == "injection")
    nei = len(sub) - both - go - jo
    print(f"{src:28s} {len(sub):5d} {both:6d} {go:8d} {jo:9d} {nei:8d}")

print()
print("=" * 78)
print("BENIGN FALSE ALARMS BY SOURCE")
print("=" * 78)
print(f"{'source':28s} {'n':>5s} {'gliner2':>8s} {'jev':>6s} {'both':>6s}")
for src in sorted({r["source"] for r in R if r["truth"] == "benign"}):
    sub = [r for r in R if r["truth"] == "benign" and r["source"] == src]
    g = sum(1 for r in sub if det(r["gliner2"]) == "injection")
    j = sum(1 for r in sub if det(r["jev"]) == "injection")
    b = sum(1 for r in sub if det(r["gliner2"]) == "injection" and det(r["jev"]) == "injection")
    print(f"{src:28s} {len(sub):5d} {g:8d} {j:6d} {b:6d}")
