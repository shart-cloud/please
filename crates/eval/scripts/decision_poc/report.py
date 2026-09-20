"""Verify saved outputs, then build paired source-stratified research tables."""
import collections,hashlib,html,json,pathlib,statistics,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[4]
OUT=ROOT/".cache/decision-poc-20260916"
BENCH=ROOT/"crates/eval/target/release/please-eval"
def sha(p):
    with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def rate(a,b):return f"{a}/{b} ({100*a/b:.1f}%)" if b else "N/A"
def table(headers,rows):return "| "+" | ".join(headers)+" |\n|"+"|".join("---" for _ in headers)+"|\n"+"\n".join("| "+" | ".join(map(str,r))+" |" for r in rows)+"\n"
def main():
    pack=json.loads((OUT/"suite/pack.json").read_text())
    cases={c["case_id"]:c for c in pack["cases"]}
    runs={};artifact={};context={};timings={};failures={}
    text=["# Lightweight decision-model pilot — 2026-09-16", "Development evidence only: 600 previously exposed public cases plus 30 first-party groups (30 artifact / 90 contextual cases). No independent holdout; no remote judge. All candidate thresholds were frozen at 0.7 before inference. Model scores are uncalibrated."]
    text.append("## Current shipping baselines")
    base={}
    for mode in ("structural","structural_ml"):
        d=json.loads((OUT/"baseline"/(mode+"-summary.json")).read_text())
        assert sha(OUT/"baseline"/(mode+".json"))==d["raw_sha256"]
        assert len(d["cases"])==630
        raw=json.loads((OUT/"baseline"/(mode+".json")).read_text())
        by_path={str(OUT/"suite"/c["asset_path"]):c for c in pack["cases"] if c["surface"]=="artifact_detection"}
        derived={}
        for v in raw:
            c=by_path[v["target"]["name"]]
            assert sha(pathlib.Path(v["target"]["name"]))==c["asset_sha256"]
            derived[c["case_id"]]=dict(case_id=c["case_id"],source=c["source"],label=c["ground_truth"]["label"],detected=v["outcome"]=="risk_found" and v["risk"] in ("high","critical"),incomplete=bool(v.get("incomplete",[])),risk=v["risk"],ml_present="ml" in v)
        assert derived=={r["case_id"]:r for r in d["cases"]}
        base[mode]={r["case_id"]:r for r in d["cases"]}
        artifact[mode]=base[mode]
        text.append(f"{mode}: {d['seconds_including_load']:.3f} seconds for 630 documents, including model load and CLI output. These are CPU/Candle batch totals, not warm per-request model latency.")
    for device in ("cuda0","cpu"):
        run=OUT/("run-cuda0-v2" if device=="cuda0" else "run-cpu")
        # The canonical verifier checks completeness, stored hashes and expected rows.
        subprocess.run([str(BENCH),"bench","report","--run",str(run),"--format","json","--out",str(run/"verified-report.json")],check=True,stdout=subprocess.DEVNULL)
        rr=[json.loads(x) for x in (run/"results.jsonl").read_text().splitlines()]
        runs[device]=rr
        for sid in sorted({r["system_id"] for r in rr}):
            selected=[r for r in rr if r["system_id"]==sid and r["coverage"]!="unsupported"]
            if sid=="please-structural-product":
                for r in selected:
                    assert ((r.get("normalized") or {}).get("decision")=="detected")==base["structural"][r["case_id"]]["detected"],"CLI and bench structural mismatch"
                continue
            ar={};cr={};ms=[];diags=[]
            for r in selected:
                n=r.get("normalized") or {}
                native=(r.get("raw_output") or {}).get("native") or {}
                if r["surface"]=="artifact_detection":
                    ar[r["case_id"]]=dict(case_id=r["case_id"],source=r["source"],label=r["ground_truth"]["label"],detected=n.get("decision")=="detected",incomplete=r["coverage"]!="completed")
                else:cr[r["case_id"]]=dict(expected=r["ground_truth"]["relation"],predicted=n.get("relation","indeterminate"),coverage=r["coverage"],delivery=r["delivery_vector"],group=r["group_id"])
                for diag in native.get("diagnostics",[]):
                    try:
                        parsed=json.loads(diag)
                        if "inference_ms" in parsed:ms.append(parsed["inference_ms"])
                    except (ValueError,TypeError):diags.append(diag)
            if ar:artifact[sid]=ar
            if cr:context[sid]=cr
            if ms:
                timings[sid]=dict(n=len(ms),median_ms=statistics.median(ms),p95_ms=sorted(ms)[int(.95*(len(ms)-1))])
            failures[sid]=dict(collections.Counter(diags))
    text.append("## Artifact detection at frozen operating points")
    text.append("Each cell is detections / attacks or false positives / benign inputs. Failures remain in denominators and appear as incomplete counts; zero false positives alone cannot establish coverage. Public source labels are inherited, not owner-adjudicated. The first-party pilot contains attacks only on this surface.")
    sources=sorted({c["source"] for c in cases.values() if c["surface"]=="artifact_detection"})
    metrics=[]
    for source in sources:
        rows=[]
        for sid,data in artifact.items():
            selected=[r for r in data.values() if r["source"]==source]
            pos=[r for r in selected if r["label"]=="injection"]
            neg=[r for r in selected if r["label"]=="benign"]
            metric=dict(system=sid,source=source,attacks=len(pos),detections=sum(r["detected"] for r in pos),benign=len(neg),false_positives=sum(r["detected"] for r in neg),incomplete=sum(r["incomplete"] for r in selected))
            metrics.append(metric)
            rows.append([sid,rate(metric["detections"],len(pos)),rate(metric["false_positives"],len(neg)),metric["incomplete"]])
        text.append("### "+source)
        text.append(table(["System","Detection","False positives","Incomplete"],rows))
    text.append("## Incremental detection when OR-combined with current structural rules")
    text.append("Post-processing only: no shipping policy change. Counts below are additional detections and additional false positives relative to structural rules; an unavailable model is not a clean decision.")
    increments=[]
    for sid,data in artifact.items():
        if not sid.startswith("gliclass") or "cpu" in sid:continue
        for source in sources:
            recovered=sum(r["detected"] and not base["structural"][cid]["detected"] and r["label"]=="injection" for cid,r in data.items() if r["source"]==source)
            added=sum(r["detected"] and not base["structural"][cid]["detected"] and r["label"]=="benign" for cid,r in data.items() if r["source"]==source)
            increments.append([sid,source,recovered,added])
    text.append(table(["Candidate","Source","Additional attacks detected","Additional false positives"],increments))
    text.append("## Contextual decisions")
    text.append("The same 30 candidate texts each appear under three trusted contexts. The blind ablation sees candidate text only. Please's existing structural/native classifier interfaces do not produce these contextual labels, so no contextual accuracy is assigned to them. These conspicuous task templates are an instrument pilot, not a general reasoning benchmark.")
    ctxmetrics=[]
    for sid,data in context.items():
        for delivery in sorted({r["delivery"] for r in data.values()}):
            selected=[r for r in data.values() if r["delivery"]==delivery]
            correct=sum(r["expected"]==r["predicted"] for r in selected)
            abstain=sum(r["coverage"]!="completed" for r in selected)
            ctxmetrics.append([sid,delivery,rate(correct,len(selected)),abstain])
    text.append(table(["System","Delivery","Correct","Abstained/failed"],ctxmetrics))
    for sid,data in context.items():
        matrix=collections.Counter((r["expected"],r["predicted"]) for r in data.values())
        text.append("### "+sid)
        text.append(table(["Expected","Predicted","Count"],[[a,b,n] for (a,b),n in sorted(matrix.items())]))
        groups=collections.defaultdict(list)
        for r in data.values():groups[r["group"]].append(r)
        text.append("Entire three-context groups correct: "+rate(sum(len(v)==3 and all(r["expected"]==r["predicted"] for r in v) for v in groups.values()),len(groups))+".")
    text.append("## Warm local model timing")
    text.append("PyTorch float32; batch size 1; 4 CPU threads; i9-12900HK under WSL (8 logical CPUs exposed), RTX 3050 Laptop 4 GB. Model load, integrity hashing and one warmup are excluded from these per-call times. Failed/overflow calls are excluded from timing only, never from effectiveness denominators. Single sequential pass, no repeated-run confidence interval. Label overhead and input lengths differ by arm.")
    text.append(table(["System","Measured calls","Median ms","p95 ms"],[[sid,t["n"],f"{t['median_ms']:.2f}",f"{t['p95_ms']:.2f}"] for sid,t in timings.items()]))
    text.append("## Coverage diagnostics")
    for sid,d in failures.items():
        text.append(sid+": "+json.dumps(d,sort_keys=True))
    agreement=[]
    for mode in ("binary","decomposed"):
        gpu=artifact["gliclass-"+mode+"-cuda0"];cpu=artifact["gliclass-"+mode+"-cpu"]
        agreement.append(dict(mode=mode,cases=len(gpu),different_decisions=sum(gpu[c]["detected"]!=cpu[c]["detected"] for c in gpu),different_coverage=sum(gpu[c]["incomplete"]!=cpu[c]["incomplete"] for c in gpu)))
    text.append("CPU/GPU artifact decision agreement: "+json.dumps(agreement))
    text.append("## Limits and reproduction")
    text.append("The first GPU run (run-cuda0) failed at startup because the adapter omitted an explicit output-class count. It is retained as a failed integration run. The corrected run-cuda0-v2 uses identical questions, weights and thresholds; no corpus predictions were available from the failed attempt. Actual runtime scripts are staged and hashed by the bench.")
    text.append("No tuning or fine-tuning was performed. No evidence of calibrated probabilities, resistance to adversarial label manipulation, multilingual performance, or safe autonomous release. Context input is serialized text; field names do not establish a learned trust boundary. Multiple sigmoid labels can disagree; the frozen composition rule resolves them, not a correctness guarantee. Long documents are refused at 512 total model tokens, unlike the baseline's windowing. This is not a like-for-like long-document capability comparison. CPU/GPU/backend differences prohibit attributing timing differences solely to architecture. See crates/eval/scripts/decision_poc/README.md and PLAN.md for reproduction and the next experiment.")
    markdown="\n\n".join(text)+"\n"
    (OUT/"report.md").write_text(markdown)
    # Escape every dynamic field. This standalone view intentionally contains no raw corpus text.
    pieces=[];in_table=False
    for line in markdown.splitlines():
        if line.startswith("|"):
            if set(line.replace("|","").strip()) <= {"-"," "}:continue
            if not in_table:pieces.append("<table>");in_table=True
            pieces.append("<tr>"+"".join("<td>"+html.escape(cell.strip())+"</td>" for cell in line.strip("|").split("|"))+"</tr>")
        else:
            if in_table:pieces.append("</table>");in_table=False
            if line.startswith("#"):
                depth=min(3,len(line)-len(line.lstrip("#")))
                pieces.append(f"<h{depth}>"+html.escape(line.lstrip("# "))+f"</h{depth}>")
            elif line:pieces.append("<p>"+html.escape(line)+"</p>")
    if in_table:pieces.append("</table>")
    (OUT/"report.html").write_text('<!doctype html><meta charset="utf-8"><title>Decision-model pilot</title><style>body{max-width:1200px;margin:40px auto;padding:0 24px;background:#101725;color:#e8edf5;font:15px/1.6 system-ui}h1,h2{color:#83d9cf}h2{margin-top:40px}table{border-collapse:collapse;width:100%;margin:20px 0}td{padding:10px;border-bottom:1px solid #334257}tr:first-child{background:#24334a;font-weight:bold}p{overflow-wrap:anywhere}</style>'+"".join(pieces))

    summary=dict(artifact=metrics,contextual=ctxmetrics,timings=timings,coverage_diagnostics=failures,cpu_gpu_agreement=agreement,inputs=dict(pack_sha256=sha(OUT/"suite/pack.json"),freeze_sha256=sha(OUT/"freeze.json")),outputs={device:dict(results_sha256=sha(OUT/("run-cuda0-v2" if device=="cuda0" else "run-cpu")/"results.jsonl"),run_sha256=sha(OUT/("run-cuda0-v2" if device=="cuda0" else "run-cpu")/"run.json")) for device in runs})
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary,indent=2))
if __name__=="__main__":main()
