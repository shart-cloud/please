"""Verify completed evidence and publish aggregate results; no inference."""
import json,pathlib,subprocess,hashlib,sys
R=pathlib.Path(__file__).resolve().parents[4];H=pathlib.Path(__file__).resolve().parent;O=R/".cache/laya-experiment-20260919"
index=json.loads((O/"run-index.json").read_text())
assert len(index)==14
count=0
for name,d in index.items():
 rr=[json.loads(l) for l in (O/d/"results.jsonl").read_text().splitlines()]
 expected=60 if name.endswith("-controls") else (1200 if name.endswith("-public") else 600)
 assert len(rr)==expected
 assert len({x["case_id"] for x in rr})==expected
 assert all(x.get("raw_output",{}).get("native") is not None for x in rr)
 assert all(x["telemetry"]["remote_requests"]==0 for x in rr)
 count+=len(rr)
assert count==7560
f=json.loads((O/"execution-freeze-v3.json").read_text())
for n,digest in f["files"].items():
 with (O/n).open("rb") as stream:actual=hashlib.file_digest(stream,"sha256").hexdigest()
 assert actual==digest,n
subprocess.run([sys.executable,str(H/"report.py")],cwd=R,check=True)
subprocess.run([sys.executable,str(H/"render.py")],cwd=R,check=True)
results=json.loads((O/"comparison.json").read_text())
summary=dict(measured_rows=count,native_runs=14,new_jev_api_calls=0,independent_holdout=False,shipping_changed=False,
 model_quality_result=results["partitions"]["public"]["superiority_screen"],
 contextual_result=results["partitions"]["contextual"]["superiority_screen"],
 run_index=index,validation=["seven offline adapter/report contracts","official token-packing parity on every admitted row","synthetic repeatability for both checkpoints","real 512/513 and 1024/1025 token boundaries","all native runs verified","case/input/request identities matched to historical Jev captures","frozen code/runtime/model identities verified"])
(O/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
with (R/"docs/attribution.md").open("a") as f:
 f.write("\n## Laya measured development experiment — 2026-09-19\n\nAt Jared's request, Codex authored and ran an isolated local Laya evaluation: two pinned checkpoints, original Jev and compact question sets, a frozen 1,200-public/600-contextual sample, and three diagnostic controls. The 7,560 reported model/recipe rows use native benchmark verification and matched historical Jev evidence without additional Jev requests. Offline contracts, tokenizer parity, synthetic repeatability and exact token boundaries were checked. Original protocol failures and zero-response startup attempts remain retained; same-limit retries are explicitly indexed. No shipping defaults, environment packages, training or calibration were changed. All data remains exposed development evidence; independent review and a fresh holdout are outstanding.\n")
print(json.dumps(summary),flush=True)
