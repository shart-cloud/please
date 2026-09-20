"""Interleaved live capture, then native verification of bound capture replay."""
import getpass,json,os,pathlib,subprocess,time
from contracts import *
from prepare import ROOT,OUT,BENCH,save
from metrics import selection
def replay(name,arms):
 capture=OUT/(name+"-captures.jsonl");capture_hash=sha(capture)
 systems=[]
 for arm in arms:
  sid="jev-usage-"+arm
  manifest=dict(schema_version="please-bench-system/v1",system_id=sid,version="1",adapter_version="please-bench-jsonl/v1",configuration_identity=sha(OUT/"freeze.json")+":"+capture_hash+":"+arm,supported_surfaces=["contextual_alignment"],requires_trusted_context=True,deterministic=True,review_authority="none",operating_point=dict(threshold="support>=0.7; margin>=0.15; confidence>=0.5",description="Hash-bound replay of predeclared live Jev captures. Replay is deterministic; remote model was not assumed deterministic."),identities=dict(model="jev-latest; returned identifiers in live captures",prompt=sha(OUT/"recipe.json"),runtime="native verified capture replay; API timings recorded separately"),adapter=dict(kind="subprocess",program="capture_adapter.py",args=["--capture",str(capture),"--sha256",capture_hash,"--arm",arm],sandbox_command=[],executable_sha256=sha(OUT/"capture_adapter.py"),environment={},network_capable=False),normalizers=[dict(normalizer_id="native-contextual_alignment",version="1",surface="contextual_alignment",mapping=dict(kind="native_v1",positive_labels=[],negative_labels=[]))])
  filename=name+"-"+arm+".system.json";save(OUT/filename,manifest);systems.append(filename)
 exp=dict(schema_version="please-bench-experiment/v1",experiment_id="jev-usage-"+name,version="1",pack_path=name+"/pack.json",system_paths=systems,exposure_paths=[],repetitions=1,execution_mode="offline",limits=dict(max_input_bytes=32768,max_request_bytes=131072,max_stdout_bytes=1048576,max_stderr_bytes=131072,startup_timeout_ms=10000,case_timeout_ms=10000,max_restarts=0,max_in_flight=1))
 path=OUT/(name+".experiment.json");save(path,exp)
 with (OUT/(name+"-native.log")).open("x") as log:subprocess.run([str(BENCH),"bench","run","--experiment",str(path),"--out",str(OUT/("run-"+name))],stdout=log,stderr=subprocess.STDOUT,check=True)
 with (OUT/(name+"-verify.json")).open("x") as log:subprocess.run([str(BENCH),"bench","report","--run",str(OUT/("run-"+name)),"--format","json"],stdout=log,check=True)
 print("NATIVE VERIFIED",name,flush=True)
class Session:
 def __init__(self,key):
  self.key=key;self.started=time.monotonic();self.attempts=0;self.errors=0;self.consecutive=0;self.stop_reason=None
  self.recipe=loads((OUT/"recipe.json").read_bytes())
  self.env={k:v for k,v in os.environ.items() if k in ("HOME","PATH","LANG")};self.env["TYPESAFE_API_KEY"]=key
 def evaluate(self,entry,arm):
  variant=entry["variants"][arm];body=json.dumps(variant["body"],separators=(",",":"),ensure_ascii=True).encode()
  assert digest(body)==variant["sha256"]
  started=time.perf_counter();label="indeterminate";attempted=0
  diag=dict(arm=arm,request_sha256=digest(body),host_guard=variant["host_guard"],unpriced=True)
  if variant["host_guard"]:
   diag["decision_origin"]="deterministic unavailable-permission guard"
  else:
   diag["decision_origin"]="model and frozen decoder"
   try:
    if self.stop_reason:raise ValueError("not attempted: "+self.stop_reason)
    if self.attempts>=self.recipe["max_attempts"] or time.monotonic()-self.started>=self.recipe["max_elapsed_seconds"]:
     self.stop_reason="request/time budget";raise ValueError("not attempted: "+self.stop_reason)
    self.attempts+=1;attempted=1
    result=subprocess.run(["/usr/bin/python3",str(OUT/"code/api_worker.py")],input=body,env=self.env,capture_output=True,timeout=30)
    if self.key.encode() in result.stdout or self.key.encode() in result.stderr:raise ValueError("credential reflection blocked")
    wire=loads(result.stdout)
    if "error" in wire:raise ValueError(wire["error"])
    raw=bytes.fromhex(wire["response_hex"])
    if self.key.encode() in raw:raise ValueError("credential reflection blocked")
    diag.update(response_hex=raw.hex(),response_sha256=digest(raw))
    # Record token usage even if choice validation later fails, when usage is well-formed.
    try:
     usage=loads(raw).get("usage",{})
     if set(usage)=={"input_tokens","output_tokens"} and all(type(v)==int and v>=0 for v in usage.values()):diag["observed_usage"]=usage
    except (ValueError,AttributeError,TypeError):pass
    label,response=parse(raw,variant["body"]["questions"],partial_previous=arm=="P");diag.update(response=response)
    self.consecutive=0
   except (ValueError,KeyError,TypeError,AttributeError,subprocess.TimeoutExpired) as e:
    error=str(e) if isinstance(e,ValueError) else "transport or response contract failure"
    if self.key in error:error="credential reflection blocked"
    diag["error"]=error
    if attempted:
     self.errors+=1;self.consecutive+=1
     if any(s in error for s in ("HTTP 401","HTTP 403","HTTP 422")) or self.consecutive>=3 or self.errors>=30:self.stop_reason="provider/contract circuit breaker"
  diag["complete_ms"]=(time.perf_counter()-started)*1000
  return dict(case_id=entry["case_id"],request_key=entry["request_key"],arm=arm,prediction=label,api_attempts=attempted,diagnostics=diag)
 def capture(self,name,arms):
  entries=loads((OUT/(name+"-requests.json")).read_bytes());records=[]
  with (OUT/(name+"-captures.jsonl")).open("x") as f:
   for i,entry in enumerate(entries):
    order=arms[i%len(arms):]+arms[:i%len(arms)]
    for arm in order:
     record=self.evaluate(entry,arm);f.write(json.dumps(record,sort_keys=True)+"\n");f.flush();records.append(record)
    if "C" in arms:
     source=next(r for r in records[-len(arms):] if r["arm"]=="C")
     derived=partial_capture(source,entry)
     f.write(json.dumps(derived,sort_keys=True)+"\n");f.flush();records.append(derived)
    if (i+1)%12==0 or i+1==len(entries):print("PROGRESS",name,i+1,"/",len(entries),"API",self.attempts,"ERRORS",self.errors,flush=True)
  (OUT/(name+"-captures.jsonl")).chmod(0o444)
  replay(name,ARMS if "C" in arms else arms)
  return records
def partial_capture(source,entry):
 import copy
 row=copy.deepcopy(source);row["arm"]="P";row["api_attempts"]=0
 d=row["diagnostics"];d["arm"]="P";d["shared_capture"]="C";d["decision_origin"]="component-scoped decoder of same C response"
 d.pop("observed_usage",None);d.pop("response",None);d.pop("error",None)
 row["prediction"]="indeterminate"
 if "response_hex" in d:
  try:row["prediction"],d["response"]=parse(bytes.fromhex(d["response_hex"]),entry["variants"]["P"]["body"]["questions"],partial_previous=True)
  except (ValueError,KeyError,TypeError,AttributeError):d["error"]="global response contract failure"
 else:d["error"]="no usable source response"
 return row
def main():
 freeze=loads((OUT/"freeze.json").read_bytes())
 for rel,expected in freeze["files"].items():
  if sha(OUT/rel)!=expected:raise ValueError("frozen file changed: "+rel)
 if sha(BENCH)!=freeze["bench_sha256"]:raise ValueError("native benchmark changed")
 key=getpass.getpass("Temporary Jev token (hidden; memory only): ")
 if not key or any(c.isspace() for c in key):raise ValueError("invalid credential")
 session=Session(key)
 try:
  records=session.capture("screen",LIVE_ARMS)
  cases=loads((OUT/"screen/pack.json").read_bytes())["cases"];choice=selection(cases,records);save(OUT/"selection.json",choice)
  print("SCREEN",json.dumps({a:dict(macro=choice["arms"][a]["original"]["overall"]["macro_recall"],eligible=choice["arms"][a]["eligible"]) for a in ARMS}),flush=True)
  print("ADVANCE",choice["advance"],"ARM",choice["selected_arm"],flush=True)
  if choice["advance"] and not session.stop_reason:session.capture("confirmation",[choice["selected_arm"]])
 finally:
  save(OUT/"session.json",dict(api_attempts=session.attempts,errors=session.errors,stop_reason=session.stop_reason,elapsed_seconds=time.monotonic()-session.started,credential_persisted=False))
if __name__=="__main__":main()
