"""Download only pinned public assets; never sends experiment inputs."""
import hashlib,json,pathlib,shutil,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[4];HERE=pathlib.Path(__file__).resolve().parent
OUT=ROOT/".cache/decision-poc-v2-20260916"
def sha(p):
 with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def main():
 OUT.mkdir(exist_ok=True)
 recipe=json.loads((HERE/"recipes.json").read_text())
 research=json.loads((ROOT/"docs/research/decision-model-phase-2-research-2026-09-16.json").read_text())
 for arm,m in recipe["arms"].items():
  lock=OUT/(arm+".model.json")
  if lock.exists():
   print("Retained existing lock",arm,flush=True);continue
  if arm=="G1":
   shutil.copyfile(ROOT/".cache/decision-poc-20260916/model.json",lock);continue
  url="https://huggingface.co/"+m["repo"]
  with urllib.request.urlopen("https://huggingface.co/api/models/"+m["repo"]+"/revision/"+m["revision"],timeout=60) as response:info=json.load(response)
  names=[s["rfilename"] for s in info["siblings"] if "/" not in s["rfilename"] and (s["rfilename"].endswith((".json",".model",".safetensors")) or s["rfilename"]=="README.md")]
  if "model.safetensors" not in names:raise ValueError("missing safetensors")
  folder=OUT/"models"/m["revision"];folder.mkdir(parents=True,exist_ok=True)
  for name in names:
   target=folder/name
   if not target.exists():
    print("Downloading",arm,name,flush=True)
    with urllib.request.urlopen(url+"/resolve/"+m["revision"]+"/"+name,timeout=180) as src,target.with_suffix(target.suffix+".partial").open("wb") as dst:shutil.copyfileobj(src,dst,1024*1024)
    target.with_suffix(target.suffix+".partial").rename(target)
  assets={n:dict(bytes=(folder/n).stat().st_size,sha256=sha(folder/n)) for n in names}
  pinned=json.loads((HERE/(arm+".model.lock.json")).read_text()) if (HERE/(arm+".model.lock.json")).exists() else None
  if pinned is not None and assets!=pinned["assets"]:raise ValueError("download differs from recorded asset lock")
  metadata=next(x for x in research["models"] if x["model_id"]==m["repo"])
  for n,a in metadata["metadata_assets"].items():
   if assets[n]["sha256"]!=a["sha256"]:raise ValueError("research identity mismatch")
  lock.write_text(json.dumps(dict(repo=m["repo"],revision=m["revision"],license=metadata["license_declared"],path=str(folder),assets=assets),indent=2)+"\n")
  print("Locked",arm,flush=True)
if __name__=="__main__":main()
