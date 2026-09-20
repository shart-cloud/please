"""Resume pending arms; retain and at most once retry zero-response startup failures."""
import pathlib,subprocess,json,time
R=pathlib.Path(__file__).resolve().parents[4];O=R/".cache/laya-experiment-20260919"
jobs=[f"laya-{arm}-{control}-{part}" for control in ["exact","full"] for part in ["public","contextual"] for arm in ["english","typed"]]
jobs += [f"laya-{arm}-{control}-controls" for control in ["candidate_only","context_only","reverse"] for arm in ["english","typed"]]
index=json.loads((O/"run-index.json").read_text());records=[]
for name in jobs:
 if name in index:continue
 for attempt in [1,2]:
  suffix="-retry1" if name=="laya-english-exact-contextual" and attempt==1 else "-continued"+str(attempt)
  directory="run-"+name+suffix
  start=time.monotonic();print("START",name,suffix,flush=True)
  with (O/(name+suffix+".log")).open("x") as f:
   p=subprocess.run([str(O/"please-eval"),"bench","run","--experiment",str(O/(name+".pass2.experiment.json")),"--out",str(O/directory)],cwd=R,stdout=f,stderr=subprocess.STDOUT,timeout=2100)
  if p.returncode:raise RuntimeError("runner failure")
  rr=[json.loads(l) for l in (O/directory/"results.jsonl").read_text().splitlines()]
  native=[x for x in rr if x.get("raw_output",{}).get("native")]
  record=dict(run=name,directory=directory,rows=len(rr),native_rows=len(native),seconds=time.monotonic()-start,attempt=attempt)
  records.append(record);(O/"continuation-progress.json").write_text(json.dumps(records,indent=2)+"\n")
  print(json.dumps(record),flush=True)
  if not native:
   if attempt==1:
    print("Zero responses; retain failed startup and retry with identical limits.",flush=True);continue
   raise RuntimeError("repeated startup failure")
  for row in native:
   d=json.loads(row["raw_output"]["native"]["diagnostics"][0])
   if d.get("error") and d["error"] not in ["state_token_cap","total_token_cap","instruction_token_cap","option_token_cap","option_budget_cap","special_marker","candidate_byte_cap"]:raise RuntimeError("adapter contract "+d["error"])
  with (O/(name+suffix+".verify.log")).open("x") as f:subprocess.run([str(O/"please-eval"),"bench","report","--run",str(O/directory)],stdout=f,stderr=subprocess.STDOUT,check=True)
  index[name]=directory;(O/"run-index.json").write_text(json.dumps(index,indent=2)+"\n")
  break
print("ALL 14 runs completed and verified",flush=True)
