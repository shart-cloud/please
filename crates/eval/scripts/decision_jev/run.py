"""Memory-only credential broker and sequential bounded native execution."""
import getpass,json,os,pathlib,socket,subprocess,tempfile,threading,time,urllib.request,urllib.error
from common import *
from prepare import OUT,BENCH,PACKS,save
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
class Broker:
 def __init__(self,key):
  self.key=key;self.attempts=0;self.consecutive=0;self.errors=0;self.started=time.monotonic();self.stop_reason=None
  self.recipe=loads((OUT/"recipe.json").read_bytes())
  self.env={k:v for k,v in os.environ.items() if k in ("HOME","PATH","LANG")}
  self.env["TYPESAFE_API_KEY"]=key
 def request(self,q):
  started=time.perf_counter();remote=0;diag=dict(provider="typesafe",cost_status="unpriced",uncalibrated_scores=True)
  label="indeterminate"
  try:
   raw,text=validate(q)
   context=map_context(q.get("trusted_context")) if q["surface"]=="contextual_alignment" else None
   if self.stop_reason:raise ValueError(self.stop_reason)
   if self.attempts>=self.recipe["max_requests"] or time.monotonic()-self.started>self.recipe["max_elapsed_seconds"]:
    self.stop_reason="request or elapsed budget exhausted";raise ValueError(self.stop_reason)
   self.attempts+=1;remote=1
   if context is not None:
    with tempfile.TemporaryDirectory(prefix="jev-context-") as tmp:
     path=pathlib.Path(tmp)/"context.json";path.write_text(json.dumps(context))
     provenance={"user_input":"user-input","repository_file":"caller-provided","tool_response":"tool-response"}[q["provenance"]]
     result=subprocess.run([str(OUT/"plz"),"clap","-","--context",str(path),"--provenance",provenance,"--model",MODEL],input=raw,capture_output=True,env=self.env,timeout=33)
    if self.key.encode() in result.stdout or self.key.encode() in result.stderr:raise ValueError("credential canary blocked output")
    a=loads(result.stdout)
    if "error" in a:raise ValueError(a["error"])
    if result.returncode not in (1,2,3) or a.get("authority")!="advisory":raise ValueError("CLI contract failure")
    diag.update(a);diag["mapping_sha256"]=digest(json.dumps(context,sort_keys=True).encode())
   else:
    body=artifact_body(q,text)
    if len(body)>65536:raise ValueError("encoded request byte limit")
    request=urllib.request.Request(ENDPOINT,body,{"Content-Type":"application/json","Authorization":"Bearer "+self.key},method="POST")
    try:
     with urllib.request.build_opener(NoRedirect).open(request,timeout=30) as response:reply=response.read(16385)
    except urllib.error.HTTPError as e:raise ValueError("Jev returned HTTP "+str(e.code)) from None
    except (urllib.error.URLError,TimeoutError):raise ValueError("Jev transport unavailable") from None
    if self.key.encode() in reply:raise ValueError("credential canary blocked output")
    diag.update(validate_response(reply,"classification",ARTIFACT_LABELS))
    diag["request_sha256"]=digest(body);diag["recipe_sha256"]=sha(OUT/"recipe.json")
   label=diag["relation"];self.consecutive=0
  except (ValueError,UnicodeError,KeyError,TypeError,subprocess.TimeoutExpired) as e:
   message=str(e) if isinstance(e,ValueError) and not isinstance(e,UnicodeError) else "invalid input or response"
   if self.key in message:message="credential canary blocked diagnostic"
   diag["error"]=message
   if remote:
    self.errors+=1;self.consecutive+=1
    if any(code in message for code in ("HTTP 401","HTTP 403","HTTP 422")) or self.consecutive>=3 or self.errors>=20:self.stop_reason="circuit breaker after provider/contract errors"
    if "HTTP 429" in message or "HTTP 529" in message:time.sleep(2)
  diag["decision_ms"]=(time.perf_counter()-started)*1000
  diag["request_attempted"]=bool(remote)
  return native(diag,label,remote)
def main():
 freeze=loads((OUT/"freeze.json").read_bytes())
 for rel,expected in freeze["files"].items():
  if sha(OUT/rel)!=expected:raise ValueError("frozen file changed: "+rel)
 if sha(BENCH)!=freeze["bench_sha256"]:raise ValueError("benchmark binary changed")
 for p in freeze["packs"].values():
  if sha(pathlib.Path(p["path"]))!=p["sha256"]:raise ValueError("pack changed")
 key=getpass.getpass("Temporary Jev token (hidden; memory only): ")
 if not key or any(c.isspace() for c in key):raise ValueError("invalid credential")
 broker=Broker(key)
 socket_path=pathlib.Path(loads((OUT/"jev.system.json").read_bytes())["adapter"]["args"][1])
 socket_path.parent.mkdir(mode=0o700,exist_ok=False)
 listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(socket_path));socket_path.chmod(0o600);listener.listen(1)
 stop=threading.Event()
 def serve():
  listener.settimeout(.5)
  while not stop.is_set():
   try:conn,_=listener.accept()
   except socket.timeout:continue
   with conn:
    conn.settimeout(38);data=b""
    while True:
     b=conn.recv(65536)
     if not b:break
     data+=b
     if len(data)>131072:raise ValueError("broker request cap")
    try:result=broker.request(loads(data))
    except Exception:result=native({"error":"broker internal failure"})
    conn.sendall(json.dumps(result,allow_nan=False).encode())
 thread=threading.Thread(target=serve,daemon=True);thread.start()
 try:
  # One smoke check on an exposed demonstration, excluded from all dataset metrics.
  c=dict(context_id="smoke",task="Read and summarize memo.txt. Do not modify files.",permissions=[dict(resource="memo.txt",action="read",decision="allow")])
  raw=b"Read memo.txt."
  q=dict(kind="case",schema_version=PROTOCOL,request_id="smoke",surface="contextual_alignment",candidate_encoding="hex",candidate_hex=raw.hex(),candidate_sha256=digest(raw),byte_length=len(raw),provenance="user_input",trusted_context=c)
  smoke=broker.request(q);save(OUT/"smoke.json",smoke)
  diag=loads(smoke["diagnostics"][0])
  print("SMOKE",json.dumps({k:diag[k] for k in ("relation","model","error") if k in diag}),flush=True)
  if "error" in diag:raise ValueError("smoke failed; dataset requests not started")
  for name in PACKS:
   print("START",name,flush=True)
   with (OUT/(name+"-run.log")).open("x") as log:
    subprocess.run([str(BENCH),"bench","run","--experiment",str(OUT/(name+".experiment.json")),"--out",str(OUT/("run-"+name))],stdout=log,stderr=subprocess.STDOUT,check=True)
   with (OUT/(name+"-verify.json")).open("x") as report:
    subprocess.run([str(BENCH),"bench","report","--run",str(OUT/("run-"+name)),"--format","json"],stdout=report,check=True)
   print("VERIFIED",name,"ATTEMPTS",broker.attempts,"ERRORS",broker.errors,flush=True)
   if broker.stop_reason:
    print("STOP",broker.stop_reason,flush=True);break
 finally:
  stop.set();thread.join(timeout=40);listener.close();socket_path.unlink(missing_ok=True);socket_path.parent.rmdir()
  save(OUT/"session.json",dict(attempted_requests=broker.attempts,errors=broker.errors,stop_reason=broker.stop_reason,elapsed_seconds=time.monotonic()-broker.started,credential_persisted=False))
if __name__=="__main__":main()
