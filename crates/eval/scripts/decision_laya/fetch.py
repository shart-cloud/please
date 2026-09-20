"""Pinned asset provisioning; never sends benchmark inputs."""
import json,pathlib,urllib.request,hashlib,shutil,concurrent.futures
R=pathlib.Path(__file__).resolve().parents[4];O=R/".cache/laya-experiment-20260919"
def sha(p):
 with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def get(url,target):
 target.parent.mkdir(parents=True,exist_ok=True)
 if target.exists():return
 print("Downloading",str(target.relative_to(O)),flush=True)
 req=urllib.request.Request(url,headers={"User-Agent":"Please-Laya-experiment"})
 with urllib.request.urlopen(req,timeout=180) as response,target.with_name(target.name+".partial").open("wb") as f:shutil.copyfileobj(response,f,1024*1024)
 target.with_name(target.name+".partial").rename(target)
recipe=json.loads((O/"recipes.json").read_text())
base="https://raw.githubusercontent.com/NandhaKishorM/laya/"+recipe["source_revision"]+"/"
files=["__init__.py","agent.py","common.py","router.py","lang.py","email.py","presets.py"]
for n in files:get(base+"laya/"+n,O/"upstream/laya"/n)
get(base+"LICENSE",O/"upstream/LICENSE")
locks={}
for arm,config in recipe["arms"].items():
 names=["model.safetensors","rl_agent_config.json","encoder/config.json","tokenizer/tokenizer.json","tokenizer/tokenizer_config.json"]
 folder=O/"models"/arm
 urls=[("https://huggingface.co/"+config["repo"]+"/resolve/"+config["revision"]+"/"+n,folder/n) for n in names]
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
  for future in [pool.submit(get,*x) for x in urls]:future.result()
 # The upstream compatibility fix writes tokenizer_config. Freeze that derived file explicitly.
 p=folder/"tokenizer/tokenizer_config.json";before=sha(p);cfg=json.loads(p.read_text())
 if cfg.get("tokenizer_class") in (None,"TokenizersBackend"):
  cfg["tokenizer_class"]="PreTrainedTokenizerFast";cfg.pop("backend",None);cfg.pop("is_local",None)
 if isinstance(cfg.get("extra_special_tokens"),list):cfg["extra_special_tokens"]={f"extra_{i}":v for i,v in enumerate(cfg["extra_special_tokens"])}
 if cfg!=json.loads(p.read_text()):
  shutil.copyfile(p,folder/"tokenizer/tokenizer_config.original.json");p.write_text(json.dumps(cfg,indent=2))
 locks[arm]=dict(config,path=str(folder),tokenizer_config_original_sha256=before,assets={str(p.relative_to(folder)):{"bytes":p.stat().st_size,"sha256":sha(p)} for p in folder.rglob("*") if p.is_file()})
 print("Locked",arm,flush=True)
locks["source"]={str(p.relative_to(O/"upstream")):sha(p) for p in (O/"upstream").rglob("*") if p.is_file()}
(O/"assets.lock.json").write_text(json.dumps(locks,indent=2)+"\n")
print("Asset provisioning complete.",flush=True)
