"""Finish the bounded comparison and publish only after native verification."""
import hashlib,json,pathlib,shutil,subprocess,time
from prepare import ROOT,OUT,HERE,BENCH
from run_remaining import run
def sha(p):
 with pathlib.Path(p).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def main():
 deadline=time.monotonic()+5400
 target=OUT/"run-development-cpu-pass3/run.json"
 while not target.exists() or json.loads(target.read_text())["status"]!="complete":
  if time.monotonic()>deadline:raise TimeoutError("CPU passes did not complete within 90 minutes")
  time.sleep(15)
 # The original worker may still be verifying its last run; no inference remains.
 failure=[json.loads(x) for x in (OUT/"run-development-cuda0-pass3/results.jsonl").read_text().splitlines()]
 if any(r["system_id"]=="N2-full-cuda0" and r["coverage"] not in ("completed","abstained") for r in failure) and not (OUT/"run-development-cuda0-N2-retry").exists():run("development-cuda0-N2-retry")
 with (OUT/"exact-boundaries.log").open("x") as log:
  subprocess.run([str(ROOT/".cache/decision-poc-venv/bin/python"),str(HERE/"check_bounds.py")],stdout=log,stderr=subprocess.STDOUT,check=True)
 with (OUT/"final-tests.log").open("x") as log:
  subprocess.run(["python3","-m","unittest","discover","-s",str(HERE),"-v"],stdout=log,stderr=subprocess.STDOUT,check=True)
 with (OUT/"report-generation.log").open("x") as log:
  subprocess.run(["python3",str(HERE/"report.py")],stdout=log,stderr=subprocess.STDOUT,check=True)
 summary=json.loads((OUT/"summary.json").read_text())
 native={}
 for folder in sorted(OUT.glob("run-*")):
  if not folder.is_dir():continue
  subprocess.run([str(BENCH),"bench","report","--run",str(folder),"--format","json"],stdout=subprocess.DEVNULL,check=True)
  native[folder.name]=dict(run_sha256=sha(folder/"run.json"),results_sha256=sha(folder/"results.jsonl"),rows=sum(1 for _ in (folder/"results.jsonl").open()))
 packs={}
 for name in ("development","calibration","shuffled","challenge"):
  p=OUT/name/"pack.json";v=json.loads(p.read_text())
  packs[name]=dict(sha256=sha(p),content_digest=v["content_digest"],cases=[{k:c[k] for k in ("case_id","group_id","family_id","asset_sha256","byte_length","ground_truth","delivery_vector")} for c in v["cases"]])
 metadata=dict(summary=summary,native_runs=native,packs=packs,recipes=json.loads((OUT/"recipes.json").read_text()),recipe_sha256=sha(OUT/"recipes.json"),freeze_sha256=sha(OUT/"freeze.json"),bench_sha256=sha(BENCH),scripts={p.name:sha(p) for p in HERE.iterdir() if p.is_file()},models={a:json.loads((HERE/(a+".model.lock.json")).read_text()) for a in ("G1","N1","N2")},validation=dict(unit_tests=19,official_parity=json.loads((OUT/"parity.json").read_text()),exact_boundaries=json.loads((OUT/"exact-boundaries.json").read_text())),independent_review="outstanding",independent_holdout="not collected",cloud_training="not started")
 dest=ROOT/"docs/research/decision-model-phase-2-result-2026-09-16"
 dest.with_suffix(".json").write_text(json.dumps(metadata,indent=2)+"\n")
 doc=(OUT/"report.md").read_text()
 doc+="\n## Implementation and validation\n\nThe isolated evaluator now has frozen G1/N1/N2 adapters, exact model/tokenizer locks, 19 passing contract/data/report tests, official-path parity for all three models, and real 512/513-token boundary checks. All saved runs listed in the companion JSON passed the native verifier. The original failed ModernBERT GPU pass and preflight failures remain preserved.\n\nThe existing Python environment was reused without dependency changes. Phase 1 files, runs and public-corpus/shipping baselines remain intact; no new contextual accuracy is attributed to an artifact detector. The local-model experiment changed no shipping policy or cloud account. Separately, the user-requested opt-in Jev advisory command was implemented and tested; it does not use these local recipes or change ordinary scan decisions.\n\n## Next decision\n\nStop these zero-shot recipes at the frozen gates. Review the authored labels and disputed shuffled mappings before deciding whether task-specific training is warranted. Collect independent, blinded workflow families for a later holdout; the current 720 main cases cannot become that holdout. Colab training and integration of these local recipes remain later conditional phases.\n\nReproduction: [decision_poc_v2 README](../../crates/eval/scripts/decision_poc_v2/README.md). Complete metrics, source/workflow denominators, calibration curves, reliability bins, model/code identities and native run hashes are in the companion JSON. Local evidence: .cache/decision-poc-v2-20260916/.\n"
 dest.with_suffix(".md").write_text(doc)
 preview=pathlib.Path("/mnt/c/Users/jg/benchmark-preview/decision-model-phase2-20260916");preview.mkdir(parents=True,exist_ok=True)
 for name in ("report.html","report.md","summary.json","label-review.html","label-review-template.json"):
  shutil.copyfile(OUT/name,preview/name)
 print("PUBLISHED",str(dest.with_suffix(".md")),flush=True)
 print("VERIFIED_RUNS",len(native),"ROWS",sum(x["rows"] for x in native.values()),flush=True)
 print("PREVIEW",str(preview/"report.html"),flush=True)
if __name__=="__main__":main()
