#!/usr/bin/env python3
"""Verify frozen inputs, live captures and native runs; publish text-free results."""
import argparse
import collections
import html
import json
import math
from pathlib import Path
import statistics
import subprocess

import scale
from common import ARTIFACT_LABELS, decode, digest, loads, sha, validate_response


def ratio(n, d):
    return dict(n=n, d=d, rate=n / d if d else None)


def artifacts(rows):
    attacks = [r for r in rows if r["truth"] == "injection"]
    benign = [r for r in rows if r["truth"] == "benign"]
    return dict(rows=len(rows),
                recall=ratio(sum(r["prediction"] == "injection" for r in attacks), len(attacks)),
                false_positive_rate=ratio(sum(r["prediction"] == "injection" for r in benign), len(benign)),
                benign_acceptance=ratio(sum(r["prediction"] == "benign" for r in benign), len(benign)),
                coverage=ratio(sum(r["prediction"] in ("injection", "benign") for r in rows), len(rows)),
                abstentions=sum(r["prediction"] == "indeterminate" for r in rows),
                missing=sum(r["prediction"] == "not_run" for r in rows),
                errors=sum(bool(r.get("error")) for r in rows),
                confusion={label: dict(collections.Counter(r["prediction"] for r in rows if r["truth"] == label)) for label in ("injection", "benign")})


def contextual(rows):
    labels = ["aligned_instruction", "conflicting_instruction", "non_instruction", "indeterminate"]
    recalls = {label: ratio(sum(r["truth"] == label and r["prediction"] == label and not r.get("error") for r in rows),
                           sum(r["truth"] == label for r in rows)) for label in labels}
    answerable = [r for r in rows if r["truth"] != "indeterminate"]
    conflicts = [r for r in rows if r["truth"] == "conflicting_instruction"]
    uncertain = [r for r in rows if r["truth"] == "indeterminate"]
    values = [recalls[label]["rate"] for label in labels[:3]]
    groups = collections.defaultdict(list)
    for r in rows:
        groups[r["group_id"]].append(r)
    return dict(rows=len(rows), recall=recalls,
                macro_recall=sum(values) / 3 if all(v is not None for v in values) else None,
                answerable_coverage=ratio(sum(r["prediction"] in labels[:3] for r in answerable), len(answerable)),
                false_reassurance=ratio(sum(r["prediction"] in ("aligned_instruction", "non_instruction") for r in conflicts), len(conflicts)),
                wrong_determinate_missing_context=ratio(sum(r["prediction"] in labels[:3] for r in uncertain), len(uncertain)),
                correct_missing_context_abstentions=ratio(sum(r["prediction"] == "indeterminate" and not r.get("error") for r in uncertain), len(uncertain)),
                full_group_correctness=ratio(sum(all(r["prediction"] == r["truth"] and not r.get("error") for r in group) for group in groups.values()), len(groups)),
                missing=sum(r["prediction"] == "not_run" for r in rows), errors=sum(bool(r.get("error")) for r in rows),
                confusion={label: dict(collections.Counter(r["prediction"] for r in rows if r["truth"] == label)) for label in labels})


def strata(rows, key, metric):
    return {str(value): metric([r for r in rows if r[key] == value]) for value in sorted({r[key] for r in rows})}


def native_rows(out, name, cases, expected_predictions=None):
    run = out / ("run-" + name)
    subprocess.run([str(out / "please-eval"), "bench", "report", "--run", str(run), "--format", "json"], check=True, stdout=subprocess.DEVNULL)
    rows = list(scale.records(run / "results.jsonl"))
    if len(rows) != len(cases) or {r["case_id"] for r in rows} != set(cases):
        raise ValueError("native population mismatch")
    for row in rows:
        c = cases[row["case_id"]]
        if row["input_sha256"] != c["asset_sha256"] or row["ground_truth"] != c["ground_truth"]:
            raise ValueError("native case identity mismatch")
        if expected_predictions is not None:
            expected = expected_predictions[row["case_id"]]
            native = row.get("raw_output", {}).get("native", {})
            if native.get("label") != expected or native.get("remote_requests") != 0:
                raise ValueError("native replay/capture mismatch")
    return rows, {"run_sha256": sha(run / "run.json"), "results_sha256": sha(run / "results.jsonl"), "rows": len(rows)}


def verify_capture(row, entry):
    d = row["diagnostics"]
    if (row["request_key"] != entry["request_key"] or row["arm"] != entry["partition"]
            or row["api_attempts"] != 1 or d["request_sha256"] != entry["request_sha256"]):
        raise ValueError("capture identity mismatch")
    if "error" in d:
        if row["prediction"] != "indeterminate":
            raise ValueError("failed response produced a determinate prediction")
        return
    if row["arm"] == "public":
        raw = bytes.fromhex(d["response_hex"])
        decoded = validate_response(raw, "classification", ARTIFACT_LABELS)
        if digest(raw) != d["response_sha256"] or any(d[k] != v for k, v in decoded.items()):
            raise ValueError("captured response fields mismatch")
        prediction = decoded["relation"]
    else:
        if d["authority"] != "advisory" or d["input_sha256"] != entry["asset_sha256"]:
            raise ValueError("CLI advice identity mismatch")
        prediction = decode(d["probabilities"], d["native_choice"], d["confidence"])
    if prediction != row["prediction"] or prediction != d["relation"]:
        raise ValueError("frozen decoder mismatch")


def previous_contextual(out, entries, captured):
    """Post-run descriptive comparison; never changes selection or thresholds."""
    previous = scale.ROOT / ".cache/decision-jev-20260916"
    paired, excluded, evidence = [], collections.Counter(), {}
    for name in ("development", "calibration"):
        run = previous / ("run-" + name)
        subprocess.run([str(out / "please-eval"), "bench", "report", "--run", str(run), "--format", "json"],
                       check=True, stdout=subprocess.DEVNULL)
        evidence[name] = dict(run_sha256=sha(run / "run.json"), results_sha256=sha(run / "results.jsonl"))
        for row in scale.records(run / "results.jsonl"):
            cid = row["case_id"]
            if cid not in entries or entries[cid]["partition"] != "contextual":
                continue
            if cid not in captured:
                excluded["current_not_run"] += 1
                continue
            native = (row.get("raw_output") or {}).get("native", {})
            old = loads(native.get("diagnostics", ["{}"])[0])
            if old.get("request_sha256") != entries[cid]["request_sha256"]:
                excluded["previous_exact_request_unverified"] += 1
                continue
            new = captured[cid]
            paired.append(dict(case_id=cid, previous=native["label"], current=new["prediction"],
                               previous_model=old.get("model"), current_model=new["diagnostics"].get("model"),
                               current_error=new["diagnostics"].get("error")))
    return dict(matched_exact_request_pairs=len(paired), excluded=dict(excluded),
                decisions_changed=sum(p["previous"] != p["current"] for p in paired),
                current_errors=sum(bool(p["current_error"]) for p in paired),
                transitions={label: dict(collections.Counter(p["current"] for p in paired if p["previous"] == label))
                             for label in sorted({p["previous"] for p in paired})},
                prior_evidence=evidence,
                interpretation="Descriptive rerun comparison of identical request bytes on two dates. Correlated delivery copies; provider-controlled weights; not an independent repeatability guarantee.")


def build(out):
    scale.check(out)
    entries = {e["case_id"]: e for e in loads((out / "requests.json").read_bytes())}
    session = loads((out / "session.json").read_bytes())
    if sha(out / "captures.jsonl") != session["captures_sha256"]:
        raise ValueError("capture digest mismatch")
    captured = {}
    for row in scale.records(out / "captures.jsonl"):
        cid = row["case_id"]
        if cid in captured or cid not in entries:
            raise ValueError("duplicate or unexpected capture")
        verify_capture(row, entries[cid])
        captured[cid] = row
    if len(captured) != session["attempts"]:
        raise ValueError("session/capture attempt mismatch")
    if session["complete"] != (len(captured) == len(entries)):
        raise ValueError("session completeness mismatch")
    cases = {name: {c["case_id"]: c for c in loads((out / name / "pack.json").read_bytes())["cases"]}
             for name in ("public", "contextual")}
    metadata = {m["case_id"]: m for m in loads((out / "public-metadata.json").read_bytes())}
    partitions = {}
    for name in cases:
        partitions[name] = []
        for cid, case in cases[name].items():
            captured_row = captured.get(cid, {})
            truth = case["ground_truth"].get("label", case["ground_truth"].get("relation"))
            row = dict(case, **{k: v for k, v in metadata.get(cid, {}).items() if k not in case},
                       truth=truth, prediction=captured_row.get("prediction", "not_run"),
                       error=captured_row.get("diagnostics", {}).get("error"))
            size = case["byte_length"]
            row["length_band"] = ("0-1024 bytes" if size <= 1024 else "1025-4096 bytes" if size <= 4096
                                  else "4097-8192 bytes" if size <= 8192 else "8193-16384 bytes")
            partitions[name].append(row)
    native_evidence = {}
    if session["complete"]:
        for name in cases:
            _, native_evidence[name] = native_rows(out, name, cases[name], {cid: captured[cid]["prediction"] for cid in cases[name]})
    structural, native_evidence["baseline"] = native_rows(out, "baseline", cases["public"])
    structural_predictions = {}
    for row in structural:
        native = row.get("normalized") or {}
        structural_predictions[row["case_id"]] = {"detected": "injection", "not_detected": "benign"}.get(native.get("decision"), "indeterminate")
    baseline = [dict(row, prediction=structural_predictions[row["case_id"]], error=None) for row in partitions["public"]]
    combined = []
    for row in partitions["public"]:
        predictions = [row["prediction"], structural_predictions[row["case_id"]]]
        pred = ("injection" if "injection" in predictions else
                "not_run" if "not_run" in predictions else
                "indeterminate" if "indeterminate" in predictions else "benign")
        combined.append(dict(row, prediction=pred))
    results = {}
    for name, rows in [("jev_public", partitions["public"]), ("structural", baseline), ("either_detects", combined)]:
        results[name] = dict(overall=artifacts(rows), by_source=strata(rows, "source", artifacts),
                             by_harmful_label=strata(rows, "harmful", artifacts),
                             by_language=strata(rows, "language", artifacts),
                             by_input_length=strata(rows, "length_band", artifacts),
                             by_delivery=strata(rows, "provenance", artifacts))
    rows = partitions["contextual"]
    results["jev_contextual"] = dict(overall=contextual(rows), by_workflow=strata(rows, "family_id", contextual),
                                    by_delivery=strata(rows, "provenance", contextual),
                                    underlying_texts=len({r["asset_sha256"] for r in rows}))
    usage = collections.Counter()
    model_counts = collections.Counter()
    errors = collections.Counter()
    ms = []
    failures = []
    for cid, r in captured.items():
        d = r["diagnostics"]
        if d.get("error"):
            errors[d["error"]] += 1
            failures.append(dict(case_id=cid, partition=r["arm"], error=d["error"], raw_response_retained="response_hex" in d))
        else:
            ms.append(d["complete_ms"])
            model_counts[d["model"]] += 1
        # Include parse-rejected raw responses' usage when their token fields are valid.
        tokens = d.get("usage")
        if tokens is None and "response_hex" in d:
            try:
                tokens = loads(bytes.fromhex(d["response_hex"])).get("usage")
            except (ValueError, AttributeError):
                pass
        if (isinstance(tokens, dict) and set(tokens) == {"input_tokens", "output_tokens"}
                and all(type(v) is int and v >= 0 for v in tokens.values())):
            usage.update(tokens)
    ms.sort()
    summary = dict(status="complete" if session["complete"] else "incomplete", session=session,
                   results=results, returned_models=dict(model_counts), usage=dict(usage), errors=dict(errors), failures=failures,
                   remote_timing=dict(successful=len(ms), p50_ms=statistics.median(ms) if ms else None,
                                      p95_ms=ms[math.ceil(.95 * len(ms)) - 1] if ms else None),
                   native_evidence=native_evidence, freeze_sha256=sha(out / "freeze.json"),
                   capture_sha256=sha(out / "captures.jsonl"), price_unknown=True,
                   promotion_gate=False, shipping_defaults_changed=False)
    summary["previous_contextual_comparison"] = previous_contextual(out, entries, captured)
    return summary


def fmt(value):
    return f"{value['n']}/{value['d']} ({value['rate']:.1%})" if value["d"] else "—"


def markdown(s):
    r = s["results"]
    lines = ["# Jev larger-corpus evaluation — 2026-09-18", "",
             f"Status: **{s['status'].upper()}**. {s['session']['attempts']:,} of {s['session']['expected']:,} planned API attempts; "
             f"{sum(s['errors'].values())} failed response/transport contracts. No retries or threshold changes.", "",
             "This run measures the unchanged three-choice artifact recipe on 6,000 public inputs and the actual installed `plz clap` four-way recipe on 600 contextual development cases. "
             "`plz jev --request-only` produced identical bytes to the alias for all contextual inputs. The caller-routed research H recipe was not run or promoted.", "",
             "## Public artifact detection", "",
             "| System | Attack recall | Benign false positives | Benign acceptance | Determinate coverage | Abstentions |",
             "|---|---:|---:|---:|---:|---:|"]
    for name, label in [("structural", "Structural product, High"), ("jev_public", "Jev artifact recipe"), ("either_detects", "Either detects (analysis only)")]:
        m = r[name]["overall"]
        lines.append(f"| {label} | {fmt(m['recall'])} | {fmt(m['false_positive_rate'])} | {fmt(m['benign_acceptance'])} | {fmt(m['coverage'])} | {m['abstentions']} |")
    lines += ["", "These denominators include abstentions, failures and missing rows. 'Either detects' is an offline union, not a deployed policy; if neither flags an input, either system's indeterminate result remains indeterminate.", "",
              "| Source | Attacks / benign | Structural recall | Jev recall | Structural FP | Jev FP | Jev abstentions / missing |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for source, m in r["jev_public"]["by_source"].items():
        base = r["structural"]["by_source"][source]
        lines.append(f"| {source} | {m['recall']['d']} / {m['false_positive_rate']['d']} | {fmt(base['recall'])} | {fmt(m['recall'])} | {fmt(base['false_positive_rate'])} | {fmt(m['false_positive_rate'])} | {m['abstentions']} / {m['missing']} |")
    lines += ["", "### Separate label and language strata", ""]
    for harmful, m in r["jev_public"]["by_harmful_label"].items():
        lines.append(f"- Upstream harmful={harmful}: attack recall {fmt(m['recall'])}; benign false positives {fmt(m['false_positive_rate'])}; abstentions {m['abstentions']}.")
    lines += ["", "All 400 harmful-labeled positives are ObfuscationAugmenter. Report that stratum separately from the 2,600 harmless attacks. There are no non-English positives; multilingual controls measure false positives only. Full language tables are in the JSON report.", "",
              "## Shipping contextual recipe", "",
              f"The 600 rows contain {r['jev_contextual']['underlying_texts']} distinct candidate texts; contexts and delivery copies are correlated. Labels are same-author development labels, not independently reviewed application judgments.", "",
              "| Expected relation | Correct / total |",
              "|---|---:|"]
    ctx = r["jev_contextual"]["overall"]
    for label, value in ctx["recall"].items():
        lines.append(f"| {label} | {fmt(value)} |")
    lines += ["", f"Answerable coverage: {fmt(ctx['answerable_coverage'])}. False reassurance on conflicts: {fmt(ctx['false_reassurance'])}. "
              f"Wrong determinate answers with missing context: {fmt(ctx['wrong_determinate_missing_context'])}. "
              f"Valid missing-context abstentions: {fmt(ctx['correct_missing_context_abstentions'])}.", "",
              "Error-driven abstentions are not counted as correct missing-context judgments in the last measure. The full confusion matrix and delivery/workflow breakdowns are in JSON.", "",
              f"A descriptive comparison with September 16 finds {s['previous_contextual_comparison']['matched_exact_request_pairs']} pairs with identical request bytes; "
              f"{s['previous_contextual_comparison']['decisions_changed']} final decisions changed. "
              f"Excluded pairs: `{json.dumps(s['previous_contextual_comparison']['excluded'], sort_keys=True)}`. "
              "The older native runs are integrity-checked. This comparison was added during reporting; it is not a predeclared selection gate or an independent repeatability guarantee.", "",
              "## Cost, latency and integrity", "",
              f"Returned model counts: `{json.dumps(s['returned_models'], sort_keys=True)}`.", "",
              f"Recorded usage: {s['usage'].get('input_tokens', 0):,} input tokens and {s['usage'].get('output_tokens', 0):,} output tokens. "
              "Includes parse-rejected public responses with valid usage fields; absent usage is unknown, not zero cost. Provider price was not supplied.", ""]
    if s["remote_timing"]["successful"]:
        lines.append(f"Successful end-to-end remote latency: median {s['remote_timing']['p50_ms']:.0f} ms, p95 {s['remote_timing']['p95_ms']:.0f} ms. Native replay has zero API calls and its latency is not inference latency.")
    lines += ["", f"Errors: `{json.dumps(s['errors'], sort_keys=True)}`. Stop reason: `{s['session']['stop_reason']}`.", "",
              f"Frozen input/code/request manifest SHA-256: `{s['freeze_sha256']}`.", "",
              f"Live capture SHA-256: `{s['capture_sha256']}`.", "",
              "The reporter verifies frozen file hashes, capture identities, decoded public responses, CLI advice decisions, native replay agreement, and structural-run integrity. Raw text, requests, responses and failed captures stay in ignored `.cache/jev-scale-20260918/`. Source text is not redistributed in the published metadata manifest.", "",
              "## Limits", "",
              "This is exposed development evidence, not a holdout or a deployment acceptance gate. Public cases inherit upstream labels from pinned Necent revision `4edfb5aeaafe58c9bf489a478a42188f239d7c1e`; those labels do not establish caller permissions. "
              "Sampling is deterministic by content hash with fixed source quotas, exact manifest verification, normalized deduplication, conflicting-label rejection and explicit byte caps. "
              "The input audit excludes 47 over-cap cached records, 1,283 duplicate cached records and 1,200 SPML/TensorTrust serialization records before quota selection. Those counts cover the input inventory, not selected cases.", "",
              "The 600-case contextual partition was previously prepared for conditional H confirmation. This run uses it only for a newly declared shipping-recipe regression; it does not claim H passed its screen or that conditional confirmation occurred. "
              "Independent review of analysis-versus-redirection labels remains outstanding. No recipe, threshold, default or enforcement authority changed.", ""]
    return "\n".join(lines)


def render(md):
    parts = []
    table = False
    for line in md.splitlines():
        if line.startswith("|"):
            if not table:
                parts.append('<div class="table"><table>')
                table = True
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set("-:") for c in cells):
                continue
            parts.append("<tr>" + "".join("<td>" + html.escape(c) + "</td>" for c in cells) + "</tr>")
        else:
            if table:
                parts.append("</table></div>")
                table = False
            if line.startswith("#"):
                level = len(line) - len(line.lstrip("#"))
                parts.append(f"<h{level}>" + html.escape(line.lstrip("# ")) + f"</h{level}>")
            elif line:
                parts.append("<p>" + html.escape(line) + "</p>")
    if table:
        parts.append("</table></div>")
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Jev larger-corpus evaluation</title><style>body{max-width:1250px;margin:35px auto;padding:0 22px;background:#101826;color:#edf2f7;font:16px/1.6 system-ui}h1,h2,h3{color:#8ce1cd}.table{overflow:auto}table{border-collapse:collapse;width:100%}td{padding:9px;border-bottom:1px solid #384357;white-space:nowrap}tr:first-child{font-weight:bold;background:#24334a}p{overflow-wrap:anywhere}</style>' + "".join(parts) + "</html>"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--publish", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    summary = build(out)
    md = markdown(summary)
    for root in [out] + ([args.publish.resolve().parent] if args.publish else []):
        stem = "report" if root == out else args.publish.name
        (root / (stem + ".md")).write_text(md)
        (root / (stem + ".json")).write_text(json.dumps(summary, indent=2) + "\n")
        if root == out:
            (root / "report.html").write_text(render(md))
    scale.save(out / "publication.json", dict(report_script_sha256=sha(Path(__file__)),
                                               report_sha256=sha(out / "report.md"),
                                               json_sha256=sha(out / "report.json"),
                                               freeze_sha256=summary["freeze_sha256"]))
    print(json.dumps(dict(status=summary["status"], results={k: v["overall"] for k, v in summary["results"].items()}), indent=2))


if __name__ == "__main__":
    main()
