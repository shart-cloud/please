#!/usr/bin/env python3
"""Offline paired extraction for the September 18 public runs.

Reads only frozen saved-run evidence. Performs no inference and no API calls.
Emits one joined JSONL record per case with both systems' decisions, the
reason each non-decision occurred, and the raw saved distributions.
"""
import json, hashlib, sys, os

GL = ".cache/framework-models-20260918/run-public/results.jsonl"
JV = ".cache/jev-scale-20260918/run-public/results.jsonl"
OUT = ".cache/pairing-audit-20260919/paired-public.jsonl"

GL_ORDER = ["injection", "benign", "indeterminate"]  # candle.recipe.json label order


def diag(native):
    d = native.get("diagnostics") or []
    try:
        return json.loads(d[0]) if d else {}
    except Exception:
        return {}


def load(path, kind):
    rows = {}
    for line in open(path):
        r = json.loads(line)
        n = (r.get("raw_output") or {}).get("native") or {}
        dd = diag(n)
        rec = {
            "case_id": r["case_id"],
            "input_sha256": r["input_sha256"],
            "pack_digest": r["pack_digest"],
            "truth": r["ground_truth"]["label"],
            "source": r["source"],
            "family": r.get("family_id"),
            "group": r.get("group_id"),
            "delivery": r.get("delivery_vector"),
            "techniques": r.get("techniques") or [],
            "coverage": r["coverage"],
            "label": n.get("label"),
            "abstained": bool(n.get("abstained")),
        }
        if kind == "gliner2":
            p = dd.get("probabilities")
            rec["probs"] = dict(zip(GL_ORDER, p)) if p else None
            rec["logits"] = dict(zip(GL_ORDER, dd["logits"])) if dd.get("logits") else None
            rec["tokens"] = dd.get("encoded_tokens")
            err = dd.get("error")
            rec["reason"] = ("input_cap" if err == "encoded input exceeds token cap; no truncation"
                             else ("score_gate" if rec["abstained"] else "decided"))
            assert not (err and err != "encoded input exceeds token cap; no truncation"), err
        else:
            p = dd.get("probabilities")
            rec["probs"] = dict(p) if p else None
            rec["native_choice"] = dd.get("native_choice")
            rec["confidence"] = dd.get("confidence")
            rec["usage_in"] = (dd.get("usage") or {}).get("input_tokens")
            err = dd.get("error")
            rec["reason"] = (("provider_contract:" + err) if err
                             else ("score_gate" if rec["abstained"] else "decided"))
        rows[r["case_id"]] = rec
    return rows


def main():
    gl, jv = load(GL, "gliner2"), load(JV, "jev")
    assert set(gl) == set(jv), "case id sets differ"
    packs = {r["pack_digest"] for r in gl.values()} | {r["pack_digest"] for r in jv.values()}
    assert len(packs) == 1, f"pack digests differ: {packs}"
    n = 0
    with open(OUT, "w") as f:
        for cid in sorted(gl):
            g, j = gl[cid], jv[cid]
            assert g["input_sha256"] == j["input_sha256"], cid
            assert g["truth"] == j["truth"], cid
            rec = {k: g[k] for k in ("case_id", "input_sha256", "truth", "source", "family",
                                    "group", "delivery", "techniques")}
            rec["gliner2"] = {k: g[k] for k in ("label", "abstained", "reason", "probs", "logits", "tokens")}
            rec["jev"] = {k: j[k] for k in ("label", "abstained", "reason", "probs",
                                            "native_choice", "confidence", "usage_in")}
            f.write(json.dumps(rec, sort_keys=True) + "\n")
            n += 1
    h = hashlib.sha256(open(OUT, "rb").read()).hexdigest()
    print(f"joined {n} cases -> {OUT}")
    print(f"pack_digest (shared): {packs.pop()}")
    print(f"paired sha256: {h}")


if __name__ == "__main__":
    os.chdir(os.environ.get("REPO", "/home/jg/git/bee-swarm"))
    main()
