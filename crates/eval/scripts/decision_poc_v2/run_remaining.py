"""Run remaining experiments sequentially; requires verified development pass 1."""
import json,pathlib,subprocess,time
from report import OUT,BENCH,rows,select
def run(name,experiment=None):
 experiment=experiment or name
 dest=OUT/("run-"+name)
 if dest.exists():raise ValueError("refuse existing run: "+str(dest))
 with (OUT/(name+".log")).open("x") as log:
  subprocess.run([str(BENCH),"bench","experiment","--manifest",str(OUT/(experiment+".experiment.json"))],stdout=log,stderr=subprocess.STDOUT,check=True)
  subprocess.run([str(BENCH),"bench","run","--experiment",str(OUT/(experiment+".experiment.json")),"--out",str(dest)],stdout=log,stderr=subprocess.STDOUT,check=True)
 rows(dest);print("VERIFIED",name,flush=True)
def main():
 deadline=time.monotonic()+3600
 while json.loads((OUT/"run-development-cuda0-pass1/run.json").read_text())["status"]!="complete":
  if time.monotonic()>deadline:raise TimeoutError("first run did not complete within one hour")
  time.sleep(15)
 first=rows(OUT/"run-development-cuda0-pass1");winner,arms=select(first)
 selection=dict(arm=winner,basis="development minimum delivery macro recall, complete-group correctness, lexical arm id",metrics=arms,calibration_unread=True,finalist=False)
 with (OUT/"development-selection.json").open("x") as f:json.dump(selection,f,indent=2)
 p=OUT/"calibration.experiment.json";m=json.loads(p.read_text());m["system_paths"]=[winner+"-full-cuda0.system.json"]
 # Preserve the unused all-arm calibration proposal; calibration is opened for one selected arm only.
 (OUT/"calibration-selected.experiment.json").write_text(json.dumps(m,indent=2)+"\n")
 print("SELECTED",winner,flush=True)
 run("calibration","calibration-selected")
 for name in ("challenge","shuffled","development-cuda0-pass2","development-cuda0-pass3","development-cpu-pass1","development-cpu-pass2","development-cpu-pass3"):run(name)
 failed=[r for r in rows(OUT/"run-development-cuda0-pass3") if r["system_id"]=="N2-full-cuda0" and r["coverage"] not in ("completed","abstained")]
 if failed:run("development-cuda0-N2-retry")
if __name__=="__main__":main()
