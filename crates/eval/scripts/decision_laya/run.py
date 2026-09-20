"""Run sealed local systems sequentially with a wall deadline; preserve all failures."""
import pathlib,subprocess,json,time,datetime
R=pathlib.Path(__file__).resolve().parents[4];O=R/".cache/laya-experiment-20260919"
# Alternate checkpoints by surface/recipe to reduce a simple order confound.
jobs=[f"laya-{arm}-{control}-{part}" for control in ["exact","full"] for part in ["public","contextual"] for arm in ["english","typed"]]
jobs += [f"laya-{arm}-{control}-controls" for control in ["candidate_only","context_only","reverse"] for arm in ["english","typed"]]
results=[]
for name in jobs:
 start=time.monotonic();log=O/(name+".pass2.log")
 print("START",name,flush=True)
 try:
  with log.open("x") as f:
   p=subprocess.run([str(O/"please-eval"),"bench","run","--experiment",str(O/(name+".pass2.experiment.json")),"--out",str(O/("run-"+name+"-pass2"))],cwd=R,stdout=f,stderr=subprocess.STDOUT,timeout=2100)
  code=p.returncode
 except subprocess.TimeoutExpired:code=124
 record=dict(run=name,exit_code=code,seconds=time.monotonic()-start,completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
 results.append(record);(O/"run-progress-pass2.json").write_text(json.dumps(results,indent=2)+"\n")
 print(json.dumps(record),flush=True)
 if code:raise SystemExit(code)
 rows=[json.loads(l) for l in (O/("run-"+name+"-pass2")/"results.jsonl").read_text().splitlines()]
 for row in rows:
  native=row["raw_output"].get("native")
  if native is None:raise RuntimeError("Native execution unavailable: "+row["case_id"])
  diag=json.loads(native["diagnostics"][0])
  if "error" in diag and diag["error"] not in ["state_token_cap","total_token_cap","instruction_token_cap","option_token_cap","option_budget_cap","special_marker","candidate_byte_cap"]:
   raise RuntimeError("Unexpected adapter error: "+diag["error"])
 print("VALIDATED",name,len(rows),"rows",flush=True)
 with (O/(name+".pass2.verify.log")).open("x") as f:
  subprocess.run([str(O/"please-eval"),"bench","report","--run",str(O/("run-"+name+"-pass2"))],cwd=R,stdout=f,stderr=subprocess.STDOUT,check=True)
print("All native runs completed and verified.",flush=True)
