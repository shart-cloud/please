"""Seal native packs, runtime and adapter identity before model execution."""
import json,pathlib,hashlib,shutil,subprocess,datetime,importlib.metadata
R=pathlib.Path(__file__).resolve().parents[4];H=pathlib.Path(__file__).resolve().parent;O=R/".cache/laya-experiment-20260919";S=R/".cache/jev-scale-20260918"
def sha(p):
 with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def save(p,v):
 with p.open("x") as f:json.dump(v,f,indent=2);f.write("\n")
selected=json.loads((O/"selection.json").read_text())
shutil.copyfile(R/"crates/eval/target/release/please-eval",O/"please-eval");(O/"please-eval").chmod(0o755)
shutil.copyfile(H/"adapter.py",O/"adapter.py");(O/"adapter.py").chmod(0o755)
save(O/"runtime.json",{p:importlib.metadata.version(p) for p in ["torch","transformers","safetensors","huggingface-hub","numpy","tokenizers"]})
for part in ["public","contextual","controls"]:
 source=S/("contextual" if part=="controls" else part)
 pack=json.loads((source/"pack.json").read_text());wanted=set(selected[part]);pack["cases"]=[c for c in pack["cases"] if c["case_id"] in wanted]
 assert len(pack["cases"])==len(wanted)
 pack["group_baselines"]={g:c for g,c in pack["group_baselines"].items() if c in wanted}
 pack["pack_id"]="laya-screen-"+part;pack["content_digest"]="0"*64
 pack["creation_provenance"]="Frozen outcome-independent subset of exposed Jev September 18 development cases; no new labels."
 dest=O/part;dest.mkdir()
 shutil.copyfile(source/"taxonomy.json",dest/"taxonomy.json")
 for c in pack["cases"]:
  p=dest/c["asset_path"];p.parent.mkdir(parents=True,exist_ok=True)
  if not p.exists():shutil.copyfile(source/c["asset_path"],p)
 save(dest/"pack.json",pack)
 pack["content_digest"]=subprocess.check_output([str(O/"please-eval"),"bench","pack","digest","--pack",str(dest/"pack.json")],text=True).strip()
 (dest/"pack.json").write_text(json.dumps(pack,indent=2)+"\n")
 subprocess.run([str(O/"please-eval"),"bench","pack","check","--pack",str(dest/"pack.json")],check=True)
files=["adapter.py","recipes.json","selection.json","plan-freeze.json","assets.lock.json","runtime.json","please-eval"]+[p+"/pack.json" for p in ["public","contextual","controls"]]
save(O/"execution-freeze.json",dict(created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),files={n:sha(O/n) for n in files},provider_calls=0))
recipe=json.loads((O/"recipes.json").read_text())
for arm,model in recipe["arms"].items():
 for control in ["full","candidate_only","context_only","reverse"]:
  sid="laya-"+arm+"-"+control
  m=dict(schema_version="please-bench-system/v1",system_id=sid,version="1",adapter_version="please-bench-jsonl/v1",configuration_identity=sha(O/"execution-freeze.json"),
   supported_surfaces=["artifact_detection","contextual_alignment"],requires_trusted_context=False,deterministic=True,review_authority="none",
   operating_point=dict(threshold="max probability >=0.7; margin >=0.15; no entropy-confidence gate; no truncation",description="Frozen exploratory local model screen; scores uncalibrated."),
   identities=dict(model=model["repo"]+"@"+model["revision"],prompt=sha(O/"recipes.json"),runtime=sha(O/"runtime.json")+":cuda:0:official-autocast"),
   adapter=dict(kind="subprocess",program="adapter.py",args=["--root",str(O),"--arm",arm,"--control",control,"--freeze-sha256",sha(O/"execution-freeze.json")],sandbox_command=[],executable_sha256=sha(O/"adapter.py"),
    environment=dict(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",TOKENIZERS_PARALLELISM="false",LD_LIBRARY_PATH="/usr/lib/wsl/lib",HOME=str(pathlib.Path.home())),network_capable=False),
   normalizers=[dict(normalizer_id="native-"+surface,version="1",surface=surface,mapping=dict(kind="native_v1",positive_labels=["injection"] if surface=="artifact_detection" else [],negative_labels=["benign"] if surface=="artifact_detection" else [])) for surface in ["artifact_detection","contextual_alignment"]])
  save(O/(sid+".system.json"),m)
  for part in (["public","contextual"] if control=="full" else ["controls"]):
   name=sid+"-"+part
   e=dict(schema_version="please-bench-experiment/v1",experiment_id=name,version="1",pack_path=part+"/pack.json",system_paths=[sid+".system.json"],exposure_paths=[],repetitions=1,execution_mode="offline",
     limits=dict(max_input_bytes=32768,max_request_bytes=131072,max_stdout_bytes=1048576,max_stderr_bytes=131072,startup_timeout_ms=180000,case_timeout_ms=30000,max_restarts=0,max_in_flight=1))
   save(O/(name+".experiment.json"),e)
print("Native packs and execution identities sealed.",flush=True)
