#!/home/jg/git/bee-swarm/.cache/decision-poc-venv/bin/python
"""Bounded local Laya adapter. Model outputs are advice, never enforcement."""
import argparse,contextlib,copy,hashlib,json,math,os,pathlib,resource,sys,time
P="please-bench-jsonl/v1"
def sha(p):
 with pathlib.Path(p).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def key(q):
 return hashlib.sha256(json.dumps({k:q.get(k) for k in ("surface","candidate_sha256","byte_length","provenance","trusted_context")},sort_keys=True,separators=(",",":")).encode()).hexdigest()
def validate_case(q):
 fields={"kind","schema_version","request_id","surface","candidate_encoding","candidate_hex","candidate_sha256","byte_length","provenance","trusted_context"}
 if set(q) not in (fields,fields-{"trusted_context"}) or q["kind"]!="case" or q["schema_version"]!=P or q["candidate_encoding"]!="hex":raise ValueError("invalid_envelope")
 if q["surface"] not in ("artifact_detection","contextual_alignment") or not isinstance(q["request_id"],str):raise ValueError("invalid_surface")
 if q["provenance"] not in ("user_input","repository_file","tool_response"):raise ValueError("invalid_provenance")
 if not isinstance(q["candidate_hex"],str) or len(q["candidate_hex"])>32768:raise ValueError("candidate_byte_cap")
 raw=bytes.fromhex(q["candidate_hex"])
 if len(raw)!=q["byte_length"] or hashlib.sha256(raw).hexdigest()!=q["candidate_sha256"]:raise ValueError("input_identity")
 return raw.decode("utf-8",errors="strict")
def decode(p,choice,support,margin):
 if not isinstance(p,dict) or len(p)<2 or choice not in p or any(type(v) not in (float,int) or not math.isfinite(v) or not 0<=v<=1 for v in p.values()) or abs(sum(p.values())-1)>.001:raise ValueError("invalid_distribution")
 top=max(p.values())
 if abs(p[choice]-top)>1e-9:raise ValueError("inconsistent_choice")
 runner=max(v for k,v in p.items() if k!=choice)
 return choice if top>=support and top-runner>=margin else "indeterminate"
def sequence_check(tok,state,q,max_len,head_max_len):
 """Mirror packing WITHOUT allowing any upstream shortening or marker rewriting."""
 text=state if isinstance(state,str) else json.dumps(state,ensure_ascii=False)
 if q["type"]!="choice" or len(q["criteria"])<2:raise ValueError("question_type")
 opts=[k if v is None or v=="" else k+": "+v for k,v in q["criteria"].items()]
 if any(s and s in value for s in tok.all_special_tokens for value in [text,q["instructions"],*opts]):raise ValueError("special_marker")
 head=tok(q["type"]+" question: "+q["instructions"],add_special_tokens=False)["input_ids"]
 options=[]
 for opt in opts:
  ids=tok(" "+opt,add_special_tokens=False)["input_ids"]
  if len(ids)>48:raise ValueError("option_token_cap")
  options.append([tok.mask_token_id]+ids)
 budget=head_max_len-sum(map(len,options))
 if budget<16:
  per=max(4,(head_max_len-16)//len(options))
  if any(len(o)>per for o in options):raise ValueError("option_budget_cap")
  budget=head_max_len-sum(map(len,options))
 if len(head)>max(8,budget):raise ValueError("instruction_token_cap")
 ids=[tok.cls_token_id]+head+[tok.sep_token_id];markers=[]
 for option in options:markers.append(len(ids));ids+=option
 ids.append(tok.sep_token_id)
 body=tok(text,add_special_tokens=False)["input_ids"]
 if len(body)>max(0,max_len-len(ids)-1):raise ValueError("state_token_cap")
 ids+=body+[tok.sep_token_id]
 if len(ids)>max_len:raise ValueError("total_token_cap")
 return dict(tokens=len(ids),state_tokens=len(body),head_tokens=len(ids)-len(body),ids=ids,markers=markers)
class Engine:
 def __init__(self,root,arm,control="full"):
  self.root=pathlib.Path(root);self.arm=arm;self.control=control
  self.recipe=json.loads((self.root/"recipes.json").read_text())
  freeze=json.loads((self.root/"plan-freeze.json").read_text())
  if sha(self.root/"recipes.json")!=freeze["recipe_sha256"]:raise ValueError("recipe_changed")
  locks=json.loads((self.root/"assets.lock.json").read_text());lock=locks[arm]
  for name,value in lock["assets"].items():
   if sha(pathlib.Path(lock["path"])/name)!=value["sha256"]:raise ValueError("asset_changed")
  for name,digest in locks["source"].items():
   if sha(self.root/"upstream"/name)!=digest:raise ValueError("source_changed")
  source=self.root.parent/"jev-scale-20260918/requests.json"
  if sha(source)!=freeze["requests_sha256"]:raise ValueError("requests_changed")
  self.entries={x["request_key"]:x for x in json.loads(source.read_text())}
  os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",TOKENIZERS_PARALLELISM="false")
  sys.path.insert(0,str(self.root/"upstream"))
  import torch,laya
  torch.set_num_threads(4);torch.manual_seed(20260919)
  if not torch.cuda.is_available():raise ValueError("requested_cuda_unavailable")
  self.torch=torch
  started=time.perf_counter()
  self.agent=laya.load(lock["path"],device="cuda:0")
  if str(self.agent.device)!="cuda:0":raise ValueError("device_fallback")
  # Verify the runtime did not modify pinned tokenizer assets.
  for name,value in lock["assets"].items():
   if sha(pathlib.Path(lock["path"])/name)!=value["sha256"]:raise ValueError("loader_modified_asset")
  self.load_seconds=time.perf_counter()-started
  self.elapsed_start=time.monotonic()
  print(json.dumps(dict(arm=arm,load_seconds=self.load_seconds,device=str(self.agent.device),dtype=str(self.agent.dtype))),file=sys.stderr,flush=True)
 def payload(self,q):
  candidate=validate_case(q)
  e=self.entries[key(q)]
  body=bytes.fromhex(e["body_hex"])
  if hashlib.sha256(body).hexdigest()!=e["request_sha256"]:raise ValueError("historical_request_identity")
  original=json.loads(body)
  if original["state"]["untrusted_candidate"]!=candidate:raise ValueError("candidate_mismatch")
  state=copy.deepcopy(original["state"]);questions=copy.deepcopy(self.recipe["questions"][q["surface"]])
  if self.control=="candidate_only":state={"untrusted_candidate":candidate}
  elif self.control=="context_only":state.pop("untrusted_candidate")
  elif self.control=="reverse":
   for question in questions.values():question["criteria"]=dict(reversed(list(question["criteria"].items())))
  elif self.control=="exact":questions=copy.deepcopy(original["questions"])
  elif self.control!="full":raise ValueError("unknown_control")
  return state,questions,original
 def decision(self,q):
  start=time.perf_counter();diag=dict(arm=self.arm,control=self.control,uncalibrated_scores=True,device=str(self.agent.device));label="indeterminate"
  try:
   if time.monotonic()-self.elapsed_start>1800:raise RuntimeError("run_budget")
   state,questions,original=self.payload(q)
   checks=[sequence_check(self.agent.tok,state,v,self.agent.cfg["max_len"],self.agent.cfg["head_max_len"]) for v in questions.values()]
   # Confirm no-difference packing against the pinned official implementation.
   from laya.common import build_sequence
   for v,c in zip(questions.values(),checks):
    ids,markers=build_sequence(self.agent.tok,state,self.agent._to_internal(v),self.agent.cfg["max_len"],self.agent.cfg["head_max_len"])
    if ids!=c["ids"] or markers!=c["markers"]:raise RuntimeError("packing_parity")
   self.torch.cuda.synchronize();infer_start=time.perf_counter()
   result=self.agent.predict(state,questions)
   self.torch.cuda.synchronize()
   if str(self.agent.device)!="cuda:0":raise RuntimeError("device_fallback")
   inference_ms=(time.perf_counter()-infer_start)*1000
   question_id=next(iter(questions));answer=result["answers"][question_id]
   if set(answer["probabilities"])!=set(questions[question_id]["criteria"]):raise ValueError("label_mismatch")
   if not math.isfinite(answer["confidence"]) or not 0<=answer["confidence"]<=1:raise ValueError("invalid_confidence")
   label=decode(answer["probabilities"],answer["choice"],self.recipe["decoding"]["support"],self.recipe["decoding"]["margin"])
   diag.update(native=result,native_choice=answer["choice"],probabilities=answer["probabilities"],confidence=answer["confidence"],inference_ms=inference_ms,
    model_tokens=[c["tokens"] for c in checks],state_sha256=hashlib.sha256(json.dumps(state,ensure_ascii=False).encode()).hexdigest(),
    question_sha256=hashlib.sha256(json.dumps(questions,ensure_ascii=False).encode()).hexdigest(),
    gate_abstained=label=="indeterminate" and answer["choice"]!="indeterminate",
    gpu_peak_allocated_bytes=self.torch.cuda.max_memory_allocated(),
    rss_peak_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024)
  except (ValueError,UnicodeError,KeyError) as e:
   diag["error"]=str(e) if isinstance(e,ValueError) and not isinstance(e,UnicodeError) else type(e).__name__
  diag["decision_ms"]=(time.perf_counter()-start)*1000
  if diag["decision_ms"]>30000:raise RuntimeError("case_deadline")
  return dict(label=label,evidence=[],diagnostics=[json.dumps(diag,sort_keys=True,allow_nan=False)],abstained=label=="indeterminate",remote_requests=0,declared_cost_microusd=0)
def main():
 p=argparse.ArgumentParser();p.add_argument("--root",required=True);p.add_argument("--arm",choices=["english","typed"],required=True);p.add_argument("--control",default="full");p.add_argument("--freeze-sha256",required=True);p.add_argument("--freeze-file",default="execution-freeze.json");a=p.parse_args()
 root=pathlib.Path(a.root)
 if sha(root/a.freeze_file)!=a.freeze_sha256:raise ValueError("execution_freeze_changed")
 for name,digest in json.loads((root/a.freeze_file).read_text())["files"].items():
  if sha(root/name)!=digest:raise ValueError("execution_asset_changed")
 hello=json.loads(sys.stdin.readline(4096))
 if set(hello)!={"kind","schema_version","system_id","system_digest"} or hello["kind"]!="handshake" or hello["schema_version"]!=P:raise ValueError("handshake")
 with contextlib.redirect_stdout(sys.stderr):
  engine=Engine(root,a.arm,a.control)
  # One synthetic warmup, never a corpus case.
  engine.agent.predict("A plain memo.",{"warmup":{"type":"choice","instructions":"Classify the text.","criteria":{"memo":"A memo.","other":"Other text."}}})
 print(json.dumps(dict(hello,adapter_version=P)),flush=True)
 while True:
  line=sys.stdin.readline(131073)
  if not line:break
  if len(line.encode())>131072 or not line.endswith("\n"):raise ValueError("request_cap")
  q=json.loads(line)
  with contextlib.redirect_stdout(sys.stderr):native=engine.decision(q)
  print(json.dumps(dict(kind="result",schema_version=P,request_id=q["request_id"],native=native),allow_nan=False),flush=True)
if __name__=="__main__":main()
