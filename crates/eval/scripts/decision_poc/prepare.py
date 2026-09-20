"""Build a cache-only case pack, system manifests, and prompt-free reproduction records."""
import collections,datetime,hashlib,json,os,pathlib,shutil,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[4]
HERE=pathlib.Path(__file__).resolve().parent
OUT=ROOT/".cache/decision-poc-20260916"
BENCH=ROOT/"crates/eval/target/release/please-eval"
def sha(p):
    with pathlib.Path(p).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=True)+"\n")
def rows(p):return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
def main():
    suite=OUT/"suite"
    suite.mkdir()
    (suite/"assets").mkdir()
    original=ROOT/"crates/eval/corpus/bench/contextual-pilot"
    pack=json.loads((original/"pack.json").read_text())
    for c in pack["cases"]:
        src=original/c["asset_path"]
        assert sha(src)==c["asset_sha256"]
        shutil.copyfile(src,suite/c["asset_path"])
    shutil.copyfile(original/"taxonomy.json",suite/"taxonomy.json")
    frozen=ROOT/".cache/dataset-evaluation-20260911/frozen-01"
    assert sha(frozen/"freeze.json")=="b639b914754726b6211fd8ef064b12355ebeb792fe7bf050327638d9eb70c8e4"
    original_freeze=json.loads((frozen/"freeze.json").read_text())
    for rel,expected in original_freeze["files"].items():
        assert sha(frozen/rel)==expected, "original freeze file mismatch: "+rel
    captures=rows(frozen/"captures.jsonl")
    provenance={r["id"]:r for r in rows(frozen/"provenance.jsonl")}
    assert len(captures)==600
    for r in captures:
        src=frozen/r["input_path"]
        assert sha(src)==r["input_sha256"]==provenance[r["id"]]["input_sha256"]
        asset="assets/"+r["id"]+".bin"
        shutil.copyfile(src,suite/asset)
        pack["cases"].append(dict(case_id=r["id"],surface="artifact_detection",source=provenance[r["id"]]["source"],provenance="user_input",ground_truth=dict(kind="artifact",label=r["label"]),label_provenance=r["label_reason"],group_id=r["id"],family_id=r["id"],split="development",delivery_vector="user_input",techniques=[],presentation_context="unscoped",asset_path=asset,asset_sha256=r["input_sha256"],byte_length=src.stat().st_size))
    pack.update(pack_id="decision-poc-development",version="1",created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),creation_provenance="Existing exposed 600-case public freeze and 30-group first-party contextual pilot; no untouched holdout",license_summary="Public texts remain in ignored cache under upstream licenses; first-party pilot MIT OR Apache-2.0",content_digest="0"*64)
    save(suite/"pack.json",pack)
    digest=subprocess.check_output([str(BENCH),"bench","pack","digest","--pack",str(suite/"pack.json")],text=True).strip()
    pack["content_digest"]=digest
    save(suite/"pack.json",pack)
    # Runtime script is frozen into each bench run; no mutable imports from this project.
    adapter=OUT/"adapter.py"
    python=ROOT/".cache/decision-poc-venv/bin/python"
    adapter.write_text("#!"+str(python)+"\n"+(HERE/"adapter.py").read_text().split("\n",1)[1])
    adapter.chmod(0o755)
    lock=json.loads((OUT/"model.json").read_text())
    from adapter import QUESTIONS
    question_digest=hashlib.sha256(json.dumps(QUESTIONS,sort_keys=True).encode()).hexdigest()
    baseline=json.loads((ROOT/"crates/eval/bench/please-mechanism.system.json").read_text())
    baseline.update(system_id="please-structural-product",version="current",configuration_identity="builtin/enforcement/high")
    baseline["operating_point"]=dict(threshold="high",description="Shipping structural product; no ML or judge")
    baseline["adapter"].update(mode="product",profile="enforcement",threshold="high")
    save(OUT/"structural.system.json",baseline)
    for device in ("cpu","cuda:0"):
        systems=["structural.system.json"]
        for mode in ("binary","decomposed","blind"):
            sid="gliclass-"+mode+"-"+device.replace(":","")
            surfaces=["artifact_detection"] if mode=="binary" else ["contextual_alignment"] if mode=="blind" else ["artifact_detection","contextual_alignment"]
            normalizers=[dict(normalizer_id="native-"+s,version="1",surface=s,mapping=dict(kind="native_v1",positive_labels=["injection"] if s=="artifact_detection" else [],negative_labels=["benign"] if s=="artifact_detection" else [])) for s in surfaces]
            manifest=dict(schema_version="please-bench-system/v1",system_id=sid,version="1",adapter_version="please-bench-jsonl/v1",configuration_identity=sha(OUT/"model.json")+":"+question_digest+":"+mode+":"+device,supported_surfaces=surfaces,requires_trusted_context=False,deterministic=True,review_authority="none",operating_point=dict(threshold="0.7 uncalibrated",description="Frozen development pilot; overflow abstains; contextual blind arm is intentionally context-free"),identities=dict(model=lock["repo"]+"@"+lock["revision"],prompt=question_digest,runtime="Python/PyTorch float32; "+device+"; 4 CPU threads"),adapter=dict(kind="subprocess",program="adapter.py",args=["--lock",str(OUT/"model.json"),"--device",device,"--mode",mode],sandbox_command=[],executable_sha256=sha(adapter),environment=dict(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",TOKENIZERS_PARALLELISM="false",LD_LIBRARY_PATH="/usr/lib/wsl/lib",HOME=str(pathlib.Path.home())),network_capable=False),normalizers=normalizers)
            filename=sid+".system.json"
            save(OUT/filename,manifest)
            systems.append(filename)
        experiment=dict(schema_version="please-bench-experiment/v1",experiment_id="decision-poc-"+device.replace(":",""),version="1",pack_path="suite/pack.json",system_paths=systems,exposure_paths=[],repetitions=1,execution_mode="offline",limits=dict(max_input_bytes=1048576,max_request_bytes=3145728,max_stdout_bytes=1048576,max_stderr_bytes=65536,startup_timeout_ms=180000,case_timeout_ms=30000,max_restarts=0,max_in_flight=1))
        save(OUT/("experiment-"+device.replace(":","")+".json"),experiment)
    model=pathlib.Path.home()/".cache/please-eval/models/protectai-deberta-v3-small/d7c8842daf06de3179cc3aca76b7b3a057acc5e7"
    ml=dict(model_path=str(model),model_id="protectai-deberta-v3-small",revision=model.name,max_tokens=512,malicious_label=1,threshold=700)
    save(OUT/"baseline-ml.json",ml)
    metadata=dict(created_at=pack["created_at"],head=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),pack_digest=digest,freeze_sha256=sha(frozen/"freeze.json"),pilot_sha256=sha(original/"pack.json"),bench_sha256=sha(BENCH),plz_sha256=sha(ROOT/"target/release/plz"),scripts={x.name:sha(x) for x in HERE.iterdir() if x.is_file()},questions=QUESTIONS,questions_sha256=question_digest,model=lock,baseline_model_assets={x.name:sha(x) for x in model.iterdir() if x.is_file()},cases=[{k:c[k] for k in ("case_id","surface","source","group_id","asset_sha256","byte_length","ground_truth")} for c in pack["cases"]])
    save(OUT/"freeze.json",metadata)
    print(json.dumps(dict(cases=len(pack["cases"]),digest=digest,sources=dict(collections.Counter(c["source"] for c in pack["cases"])))) )
if __name__=="__main__":main()
