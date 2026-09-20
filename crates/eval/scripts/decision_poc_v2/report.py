"""Verify native evidence before recomputing source-stratified development metrics."""
import collections,hashlib,json,math,pathlib,random,statistics,subprocess
from adapter import decode
ROOT=pathlib.Path(__file__).resolve().parents[4];OUT=ROOT/".cache/decision-poc-v2-20260916";BENCH=ROOT/"crates/eval/target/release/please-eval"
LABELS=["aligned_instruction","conflicting_instruction","non_instruction"]
_ROW_CACHE={}
def rows(run):
 if str(run) in _ROW_CACHE:return _ROW_CACHE[str(run)]
 subprocess.run([str(BENCH),"bench","report","--run",str(run),"--format","json"],stdout=subprocess.DEVNULL,check=True)
 result=[json.loads(x) for x in (run/"results.jsonl").read_text().splitlines()]
 for r in result:
  native=r.get("raw_output",{}).get("native",{})
  r["_prediction"]=native.get("label","indeterminate")
  try:r["_diag"]=json.loads(native.get("diagnostics",[])[0])
  except (ValueError,IndexError):r["_diag"]={}
 _ROW_CACHE[str(run)]=result
 return result
def fraction(num,den):return dict(n=num,d=den,rate=num/den if den else None)
def metrics(rs):
 groups=collections.defaultdict(list)
 for r in rs:groups[r["group_id"]].append(r)
 truth=lambda r:r["ground_truth"]["relation"]
 answerable=[r for r in rs if truth(r) in LABELS]
 recall={l:fraction(sum(r["_prediction"]==l for r in rs if truth(r)==l),sum(truth(r)==l for r in rs)) for l in LABELS}
 vals=[v["rate"] for v in recall.values()]
 conflicts=[r for r in rs if truth(r)==LABELS[1]]
 missing=[r for r in rs if truth(r)=="indeterminate"]
 return dict(n=len(rs),recall=recall,macro_recall=sum(vals)/3 if all(v is not None for v in vals) else None,
  coverage=fraction(sum(r["_prediction"] in LABELS for r in answerable),len(answerable)),
  complete_groups=fraction(sum(all(r["_prediction"]==truth(r) for r in g) for g in groups.values()),len(groups)),
  false_conflict={l:fraction(sum(r["_prediction"]==LABELS[1] for r in rs if truth(r)==l),sum(truth(r)==l for r in rs)) for l in (LABELS[0],LABELS[2])},
  false_reassurance=fraction(sum(r["_prediction"] in (LABELS[0],LABELS[2]) for r in conflicts),len(conflicts)),
  missing_context_wrong=fraction(sum(r["_prediction"]!="indeterminate" for r in missing),len(missing)),
  confusion={l:dict(collections.Counter(r["_prediction"] for r in rs if truth(r)==l)) for l in LABELS+["indeterminate"]},
  predictions=dict(collections.Counter(r["_prediction"] for r in rs)),
  transport=dict(collections.Counter(r["coverage"] for r in rs)),
  errors=dict(collections.Counter(r["_diag"].get("error") for r in rs if r["_diag"].get("error"))))
def strata(rs,key):return {s:metrics([r for r in rs if r[key]==s]) for s in sorted({r[key] for r in rs})}
def bootstrap(rs,unit="family_id",iterations=1000):
 buckets=collections.defaultdict(list)
 for r in rs:buckets[r[unit]].append(r)
 keys=sorted(buckets);rng=random.Random(1701);values=[]
 for _ in range(iterations):
  sample=[r for k in rng.choices(keys,k=len(keys)) for r in buckets[k]]
  v=metrics(sample)["macro_recall"]
  if v is not None:values.append(v)
 values.sort()
 return dict(unit=unit,clusters=len(keys),iterations=iterations,low=values[int(.025*len(values))] if values else None,high=values[min(len(values)-1,int(.975*len(values)))] if values else None,interpretation="Conditional descriptive cluster bootstrap on authored templates; not a population accuracy guarantee.")
def summarize(rs):
 return dict(overall=metrics(rs),delivery=strata(rs,"delivery_vector"),source=strata(rs,"source"),workflow=strata(rs,"family_id"),uncertainty=bootstrap(rs))
def select(rs):
 arms={}
 for arm in ("G1","N1","N2"):
  subset=[r for r in rs if r["system_id"]==arm+"-full-cuda0"]
  if len(subset)!=480:raise ValueError("incomplete development candidate")
  arms[arm]=summarize(subset)
 winner=sorted(arms,key=lambda a:(-min(v["macro_recall"] for v in arms[a]["delivery"].values()),-arms[a]["overall"]["complete_groups"]["rate"],a))[0]
 return winner,arms
def calibration(rs):
 points=[]
 for threshold in [.5,.6,.7,.8,.9,.95]:
  for margin in [.05,.1,.15,.2,.3]:
   changed=[]
   for r in rs:
    v=dict(r);v["_prediction"]=decode(r["_diag"].get("scores",[]),threshold,margin);changed.append(v)
   m=metrics(changed);by=strata(changed,"delivery_vector")
   eligible=all(v["coverage"]["rate"]>=.9 and all(x["rate"]<=.01 for x in v["false_conflict"].values()) for v in by.values()) and m["missing_context_wrong"]["n"]==0
   points.append(dict(threshold=threshold,margin=margin,eligible=eligible,metrics=m,delivery=by))
 accepted=[p for p in points if p["eligible"]]
 accepted.sort(key=lambda p:(p["metrics"]["coverage"]["rate"],p["metrics"]["macro_recall"],p["threshold"],p["margin"]),reverse=True)
 return dict(points=points,selected=accepted[0] if accepted else None)
def timing(rs):
 ms=[r["_diag"]["decision_ms"] for r in rs if "decision_ms" in r["_diag"] and not r["_diag"].get("error")]
 ms.sort()
 return dict(attempted_rows=len(rs),coverage_states=dict(collections.Counter(r["coverage"] for r in rs)),n=len(ms),p50_ms=statistics.median(ms) if ms else None,p95_ms=ms[math.ceil(.95*len(ms))-1] if ms else None,
 rss_peak_bytes=max((r["_diag"].get("rss_peak_bytes",0) for r in rs),default=0),
 gpu_peak_allocated_bytes=max((r["_diag"].get("gpu_peak_allocated_bytes",0) for r in rs),default=0),
 gpu_peak_reserved_bytes=max((r["_diag"].get("gpu_peak_reserved_bytes",0) for r in rs),default=0),
 harness_elapsed_ms=sum(r["telemetry"]["elapsed_micros"] for r in rs)/1000,
 runner_overhead_ms=sum(r["telemetry"].get("runner_overhead_micros",0) for r in rs)/1000,
 limitations="Three planned full passes in fixed shuffled case order, rotating model order; failed passes retained and any retry separately identified; one startup warmup, no length-bucket warmup. Screening timing, not a release benchmark.")
def main():
 first=rows(OUT/"run-development-cuda0-pass1");winner,arms=select(first)
 controls={sid:summarize([r for r in first if r["system_id"]==sid]) for sid in sorted({r["system_id"] for r in first if "-full-" not in r["system_id"]})}
 cal=calibration(rows(OUT/"run-calibration"))
 times={};parity={}
 for arm in arms:
  device_rows={}
  for device in ("cpu","cuda0"):
   rr=[r for i in (1,2,3) for r in rows(OUT/("run-development-"+device+"-pass"+str(i))) if r["system_id"]==arm+"-full-"+device]
   if arm=="N2" and device=="cuda0" and (OUT/"run-development-cuda0-N2-retry").exists():rr+=rows(OUT/"run-development-cuda0-N2-retry")
   times[arm+"-"+device]=timing(rr);device_rows[device]=rr
  a={r["case_id"]:r["_prediction"] for r in device_rows["cpu"] if "scores" in r["_diag"]};b={r["case_id"]:r["_prediction"] for r in device_rows["cuda0"] if "scores" in r["_diag"]}
  common=set(a)&set(b)
  score_rows={device:{r["case_id"]:r["_diag"].get("scores",[]) for r in rr if "scores" in r["_diag"]} for device,rr in device_rows.items()}
  delta=[abs(x-y) for k in common for x,y in zip(score_rows["cpu"][k],score_rows["cuda0"][k])]
  repeats=collections.defaultdict(set)
  for device,rr in device_rows.items():
   for row in rr:
    if "scores" in row["_diag"]:repeats[(device,row["case_id"])].add(row["_prediction"])
  parity[arm]=dict(cases=len(common),unmatched_cases=len(set(a)^set(b)),decision_mismatches=sum(a[k]!=b[k] for k in common),maximum_support_delta=max(delta,default=None),within_device_unstable_cases=sum(len(v)>1 for v in repeats.values()))
 challenge=rows(OUT/"run-challenge");shuffled=rows(OUT/"run-shuffled")
 disputed=json.loads((OUT/"shuffled-label-disagreements.json").read_text());excluded=set(disputed["case_ids"])
 shuffled=[r for r in shuffled if r["case_id"] not in excluded]
 extra={name:{sid:summarize([r for r in rr if r["system_id"]==sid]) for sid in sorted({r["system_id"] for r in rr})} for name,rr in (("challenge",challenge),("shuffled",shuffled))}
 gains={}
 for arm in arms:
  own=[controls[arm+"-"+c+"-cuda0"]["overall"]["macro_recall"] for c in ("candidate_only","context_only")]
  strongest=max(v["overall"]["macro_recall"] for v in controls.values())
  gains[arm]=dict(own_control_gain=arms[arm]["overall"]["macro_recall"]-max(own),strongest_control_gain=arms[arm]["overall"]["macro_recall"]-strongest)
 gates={}
 for arm,a in arms.items():
  t_cpu=times[arm+"-cpu"];t_gpu=times[arm+"-cuda0"]
  gates[arm]=dict(macro_recall=all(v["macro_recall"]>=.8 for v in a["delivery"].values()),
   complete_groups=a["overall"]["complete_groups"]["rate"]>=.7,
   coverage=all(v["coverage"]["rate"]>=.9 for v in a["delivery"].values()),
   control_gain=gains[arm]["strongest_control_gain"]>=.1,
   zero_false_reassurance=a["overall"]["false_reassurance"]["n"]==0,
   missing_context=a["overall"]["missing_context_wrong"]["n"]==0,
   cpu_timing_screen=t_cpu["p95_ms"] is not None and t_cpu["p95_ms"]<=250,
   gpu_timing_screen=t_gpu["p95_ms"] is not None and t_gpu["p95_ms"]<=100,
   ram_screen=max(t_cpu["rss_peak_bytes"],t_gpu["rss_peak_bytes"])<=2**31,
   gpu_memory_screen=t_gpu["gpu_peak_allocated_bytes"]<=3*2**30)
 result=dict(shuffled_label_disagreement=disputed,gates=gates,winner_for_calibration=winner,arms=arms,controls=controls,control_gains=gains,calibration=cal,timing=times,device_decision_parity=parity,additional=extra,decision="STOP: no deployment or advisory authority; independent labels and holdout remain pending.")
 result["cold_load_seconds"]={}
 for device in ("cpu","cuda0"):
  for passno in (1,2,3):
   manifest=json.loads((OUT/("run-development-"+device+"-pass"+str(passno))/"run.json").read_text())
   for process in manifest["processes"]:
    for line in bytes.fromhex(process["retained_stderr_hex"]).decode("utf-8",errors="replace").splitlines():
     try:record=json.loads(line)
     except ValueError:continue
     if isinstance(record,dict) and "load_seconds" in record:result["cold_load_seconds"].setdefault(process["system_id"],[]).append(record["load_seconds"])
 result["timing_environment"]="Concurrent unrelated C++ compilation observed in WSL; user-requested Jev compilation/tests also shared the host during CPU passes. No exclusive host control. Latency gates are not uncontended deployment measurements."
 result["calibration_reliability"]={}
 for label_index,label in enumerate(LABELS):
  bins=[]
  calibration_rows=rows(OUT/"run-calibration")
  for low in range(10):
   values=[r for r in calibration_rows if len(r["_diag"].get("scores",[]))==3 and low/10<=r["_diag"]["scores"][label_index] and (r["_diag"]["scores"][label_index]<(low+1)/10 or low==9)]
   bins.append(dict(lower=low/10,n=len(values),mean_support=sum(r["_diag"]["scores"][label_index] for r in values)/len(values) if values else None,observed_relation=fraction(sum(r["ground_truth"]["relation"]==label for r in values),len(values))))
  result["calibration_reliability"][label]=bins
 (OUT/"summary.json").write_text(json.dumps(result,indent=2)+"\n")
 lines=["# Phase 2A contextual decision-model development result","","Self-authored/self-reviewed development evidence. No independent holdout; no training or shipping changes from these local-model recipes. The separately requested Jev command is outside this comparison.","","| Arm | Delivery | Macro recall | Determinate / answerable | Complete groups | False reassurance |","|---|---|---:|---:|---:|---:|"]
 fmt=lambda f:str(f["n"])+"/"+str(f["d"])
 for arm,a in arms.items():
  for delivery,m in a["delivery"].items():lines.append(f'| {arm} | {delivery} | {m["macro_recall"]:.1%} | {fmt(m["coverage"])} | {fmt(m["complete_groups"])} | {fmt(m["false_reassurance"])} |')
 lines+=["","| Arm | Authorized recall | Conflict recall | Non-operative recall | Strongest one-sided control gain |","|---|---:|---:|---:|---:|"]
 for arm,a in arms.items():
  m=a["overall"];lines.append("| "+arm+" | "+" | ".join(fmt(m["recall"][l]) for l in LABELS)+" | "+f'{gains[arm]["strongest_control_gain"]:+.1%}'+" |")
 lines+=["",f"Development selection: {winner}. Eligible calibration points: {sum(p['eligible'] for p in cal['points'])}/{len(cal['points'])}.","",result["decision"],"","| Arm/device | Complete decisions | p50 ms | p95 ms | Peak RSS GiB | Peak GPU allocated GiB |","|---|---:|---:|---:|---:|---:|"]
 for sid,t in times.items():lines.append(f'| {sid} | {t["n"]} | {t["p50_ms"]:.1f} | {t["p95_ms"]:.1f} | {t["rss_peak_bytes"]/2**30:.2f} | {t["gpu_peak_allocated_bytes"]/2**30:.2f} |')
 lines+=["","The tables and JSON retain conflict recall, false reassurance and the gain over the strongest one-sided control. Abstention can avoid false reassurance while still failing coverage; it is not an effective classifier by itself.","","There are 40 distinct primary development candidates across 10 workflow families and 20 calibration candidates across five families. Each is repeated under four contexts and three delivery types; delivery strata are correlated. Native bench contextual accuracy counts abstentions as misses; this report separately credits expected indeterminate outcomes only in group and missing-context metrics.","","| Arm | Failed proposed gates |","|---|---|"]
 for arm,g in gates.items():lines.append("| "+arm+" | "+", ".join(k for k,v in g.items() if not v)+" |")
 lines+=["","The frozen shuffled pack has 120 disputed broad-task mappings, excluded from scored shuffled metrics after semantic self-review; the original run is preserved. This does not change primary development or calibration labels. Independent review is still needed.","","Concurrent unrelated C++ compilation was observed in WSL; the later user-requested Jev build/tests also shared the host during CPU passes. Resource results are contention-affected, not an uncontended deployment benchmark.","","Timings use successful measured decisions; coverage_states retain every attempted row, including timeout and unavailable results. Any separately identified same-limit retry is retained alongside its original failure.","","Timing is screening evidence: three rotated model passes with a fixed shuffled case order and a single startup warmup. Length-bucket warmup remains outstanding.","","See summary.json for label/source/workflow denominators, failures, all rejected calibration points, controls and family-cluster bootstrap intervals. Shared templates and delivery variants are correlated. Zero observed errors do not establish a sub-1% population error rate.","","Independent label review and fresh blinded holdout collection remain external dependencies. No Colab account was accessed or corpus uploaded."]
 (OUT/"report.md").write_text("\n".join(lines)+"\n")
 import html
 (OUT/"report.html").write_text("<!doctype html><meta charset='utf-8'><title>Phase 2A decision models</title><style>body{max-width:1200px;margin:3rem auto;padding:1rem;background:#101820;color:#e5edf2;font:16px/1.6 system-ui}pre{white-space:pre-wrap;font-size:14px}</style><pre>"+html.escape("\n".join(lines))+"</pre>")
 print("\n".join(lines))
if __name__=="__main__":main()
