"""Resolve once, download public assets, pin hashes. No corpus is sent remotely."""
import hashlib,json,pathlib,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[4]
OUT=ROOT/".cache/decision-poc-20260916"
OUT.mkdir(exist_ok=True)
lock=OUT/"model.json"
if lock.exists():
    raise SystemExit("Model lock already exists; use recorded assets, never re-resolve implicitly")
pinned=json.loads((pathlib.Path(__file__).parent/"model.lock.json").read_text())
repo=pinned["repo"]
revision=pinned["revision"]
folder=OUT/"models"/revision
folder.mkdir(parents=True,exist_ok=True)
names=list(pinned["assets"])
assets={}
for name in names:
    target=folder/name
    print("Downloading "+name,flush=True)
    if not target.exists():
        with urllib.request.urlopen(f"https://huggingface.co/{repo}/resolve/{revision}/{name}",timeout=180) as r,target.with_suffix(target.suffix+".partial").open("wb") as f:
            while chunk:=r.read(1024*1024): f.write(chunk)
        target.with_suffix(target.suffix+".partial").rename(target)
    digest=hashlib.file_digest(target.open("rb"),"sha256").hexdigest()
    assets[name]=dict(bytes=target.stat().st_size,sha256=digest)
    if assets[name]!=pinned["assets"][name]: raise ValueError("download identity mismatch: "+name)
lock.write_text(json.dumps(dict(repo=repo,revision=revision,license="Apache-2.0",path=str(folder),assets=assets),indent=2)+"\n")
print(json.dumps(dict(revision=revision,files=len(assets),bytes=sum(v["bytes"] for v in assets.values()))))
