#!/usr/bin/env python3
"""Frozen offline contextual experiment; deliberately has no enforcement authority."""
import argparse,contextlib,hashlib,json,math,os,resource,sys,time
from pathlib import Path
PROTOCOL="please-bench-jsonl/v1"
RELATIONS=["aligned_instruction","conflicting_instruction","non_instruction"]
def sha(path):
 with Path(path).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def softmax(values):
 if not values or any(type(x) not in (int,float) or not math.isfinite(x) for x in values):raise ValueError("invalid logits")
 m=max(values);e=[math.exp(x-m) for x in values];return [x/sum(e) for x in e]
def score_logits(arm,raw):
 width=3 if arm=="N1" else 2
 if arm not in ("G1","N1","N2") or len(raw)!=3 or any(len(row)!=width for row in raw):raise ValueError("logit shape")
 return [softmax(row)[0] for row in raw]
def decode(scores,threshold,margin):
 if len(scores)!=3 or any(type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=1 for v in scores):return "indeterminate"
 winners=[i for i,s in enumerate(scores) if s>=threshold]
 if len(winners)!=1:return "indeterminate"
 i=winners[0]
 return RELATIONS[i] if scores[i]-max(scores[:i]+scores[i+1:])>=margin else "indeterminate"
def validate_request(q,r):
 fields={"kind","schema_version","request_id","surface","candidate_encoding","candidate_hex","candidate_sha256","byte_length","provenance","trusted_context"}
 if not isinstance(q,dict) or set(q)!=fields or q["kind"]!="case" or q["schema_version"]!=PROTOCOL or q["surface"]!="contextual_alignment":raise ValueError("invalid envelope")
 if not isinstance(q["request_id"],str) or q["candidate_encoding"]!="hex" or not isinstance(q["candidate_hex"],str):raise ValueError("invalid encoding")
 if len(q["candidate_hex"])>r["bounds"]["candidate_bytes"]*2:raise ValueError("candidate byte limit")
 raw=bytes.fromhex(q["candidate_hex"])
 if type(q["byte_length"])!=int or len(raw)!=q["byte_length"] or hashlib.sha256(raw).hexdigest()!=q["candidate_sha256"]:raise ValueError("candidate identity mismatch")
 text=raw.decode("utf-8",errors="strict")
 c=q["trusted_context"]
 if not isinstance(c,dict) or set(c)!={"context_id","task","permissions"} or not isinstance(c["task"],str) or not c["task"].strip() or not isinstance(c["permissions"],list):raise ValueError("missing or invalid trusted context")
 if len(json.dumps(c,ensure_ascii=True).encode())>r["bounds"]["context_bytes"]:raise ValueError("context byte limit")
 for p in c["permissions"]:
  if not isinstance(p,dict) or set(p)!={"resource","action","decision"} or any(not isinstance(v,str) or not v.strip() for v in p.values()) or p["decision"] not in ("allow","deny"):raise ValueError("invalid permission")
 if q["provenance"] not in ("user_input","repository_file","tool_response"):raise ValueError("invalid provenance")
 return text
def render(q,text,control):
 c=q["trusted_context"]
 if control=="candidate_only":return json.dumps({"untrusted_candidate":text},ensure_ascii=True)
 value={"trusted_task":c["task"],"trusted_permissions":c["permissions"]}
 if control=="full":value["untrusted_candidate"]=text
 elif control!="context_only":raise ValueError("invalid control")
 return json.dumps(value,ensure_ascii=True)
class Classifier:
 def __init__(self,recipe,arm,lock_path,device):
  started=time.perf_counter()
  import torch
  from transformers import AutoTokenizer,AutoModelForSequenceClassification
  self.torch=torch;self.r=recipe;self.arm=arm;self.device=device
  torch.set_num_threads(recipe["runtime"]["threads"]);torch.manual_seed(recipe["runtime"]["seed"])
  if device.startswith("cuda") and not torch.cuda.is_available():raise ValueError("CUDA unavailable")
  lock=json.loads(Path(lock_path).read_text());expected=recipe["arms"][arm]
  if any(lock[k]!=expected[k] for k in ("repo","revision")):raise ValueError("wrong model revision")
  folder=Path(lock["path"])
  for n,a in lock["assets"].items():
   if Path(n).is_absolute() or ".." in Path(n).parts:raise ValueError("unsafe asset path")
   p=folder/n
   if p.stat().st_size!=a["bytes"] or sha(p)!=a["sha256"]:raise ValueError("asset identity mismatch: "+n)
  actual={str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file() and ".cache" not in p.relative_to(folder).parts}
  if actual!=set(lock["assets"]):raise ValueError("unlocked model assets")
  self.tokenizer=AutoTokenizer.from_pretrained(folder,local_files_only=True,trust_remote_code=False)
  if arm=="G1":
   from gliclass import GLiClassModel
   self.model=GLiClassModel.from_pretrained(folder,local_files_only=True)
  else:
   self.model=AutoModelForSequenceClassification.from_pretrained(folder,local_files_only=True,trust_remote_code=False,attn_implementation="eager")
   labels=[self.model.config.id2label[i].lower() for i in range(self.model.config.num_labels)]
   if labels!=expected["labels"]:raise ValueError("unexpected label map: "+str(labels))
  if arm=="N2":self.model.config.reference_compile=False
  self.model=self.model.float().to(device).eval()
  if device.startswith("cuda"):torch.cuda.reset_peak_memory_stats()
  self.load_seconds=time.perf_counter()-started
  self.infer('{"trusted_task":"Read the memo.","trusted_permissions":[],"untrusted_candidate":"Read the memo."}')
 def infer(self,state):
  # Reject textual special markers rather than permitting candidate text to alter segmentation.
  markers=set(self.tokenizer.all_special_tokens)|{"<<LABEL>>","<<SEP>>"}
  if any(t and t in state for t in markers):raise ValueError("special marker in input")
  if self.arm=="G1":
   questions=[s for pair in zip(self.r["positive"],self.r["negative"]) for s in pair]
   labels="".join("<<LABEL>>"+s for s in questions)+"<<SEP>>"
   prompt=labels+state if self.model.config.prompt_first else state+labels
   enc=self.tokenizer(prompt,return_tensors="pt",truncation=False)
   lengths=[enc["input_ids"].shape[1]]
   if int((enc["input_ids"]==self.model.config.class_token_index).sum())!=6:raise ValueError("class marker count")
  else:
   enc=self.tokenizer([state]*3,self.r["positive"],return_tensors="pt",padding=True,truncation=False)
   lengths=enc["attention_mask"].sum(-1).tolist()
  if max(lengths)>self.r["bounds"]["tokens"]:raise ValueError("token limit: "+str(lengths))
  enc={k:v.to(self.device) for k,v in enc.items()}
  with self.torch.inference_mode():
   output=self.model(**enc,**({"max_num_classes":6} if self.arm=="G1" else {})).logits
   raw=output.detach().float().cpu().tolist()
  if self.arm=="G1":
   if len(raw)!=1 or len(raw[0])!=6:raise ValueError("unexpected G1 shape")
   raw=[raw[0][i:i+2] for i in range(0,6,2)]
  scores=score_logits(self.arm,raw)
  return raw,scores,lengths
 def decision(self,q,control,threshold,margin):
  started=time.perf_counter();diag={"arm":self.arm,"control":control,"uncalibrated_scores":True};label="indeterminate"
  try:
   text=validate_request(q,self.r)
   if not q["trusted_context"]["permissions"]:raise ValueError("missing permission scope")
   raw,scores,lengths=self.infer(render(q,text,control))
   label=decode(scores,threshold,margin)
   diag.update(raw_logits=raw,scores=scores,model_tokens=lengths,completed_hypotheses=3)
  except (ValueError,RuntimeError,UnicodeError) as e:diag.update(error=str(e),completed_hypotheses=0)
  if self.device.startswith("cuda"):self.torch.cuda.synchronize()
  diag["decision_ms"]=(time.perf_counter()-started)*1000
  if diag["decision_ms"]>self.r["bounds"]["deadline_ms"]:label="indeterminate";diag["error"]="deadline exceeded"
  diag["rss_peak_bytes"]=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
  if self.device.startswith("cuda"):
   diag["gpu_peak_allocated_bytes"]=self.torch.cuda.max_memory_allocated()
   diag["gpu_peak_reserved_bytes"]=self.torch.cuda.max_memory_reserved()
  return dict(label=label,evidence=[],diagnostics=[json.dumps(diag,sort_keys=True,allow_nan=False)],abstained=label=="indeterminate",remote_requests=0,declared_cost_microusd=0)
def send(v):print(json.dumps(v,ensure_ascii=True,allow_nan=False,separators=(",",":")),flush=True)
def main():
 p=argparse.ArgumentParser()
 for k in ("recipe","recipe_sha256","lock","lock_sha256","arm"):p.add_argument("--"+k.replace("_","-"),required=True)
 p.add_argument("--device",choices=["cpu","cuda:0"],default="cpu");p.add_argument("--control",choices=["full","candidate_only","context_only"],default="full")
 p.add_argument("--threshold",type=float,default=.7);p.add_argument("--margin",type=float,default=.15)
 a=p.parse_args()
 for path,digest in ((a.recipe,a.recipe_sha256),(a.lock,a.lock_sha256)):
  if sha(path)!=digest:raise ValueError("configuration identity mismatch")
 r=json.loads(Path(a.recipe).read_text())
 if a.threshold not in r["decoding"]["threshold_grid"] or a.margin not in r["decoding"]["margin_grid"]:raise ValueError("undeclared operating point")
 os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",TOKENIZERS_PARALLELISM="false")
 hello=json.loads(sys.stdin.readline(4096))
 if set(hello)!={"kind","schema_version","system_id","system_digest"} or hello["kind"]!="handshake" or hello["schema_version"]!=PROTOCOL:raise ValueError("invalid handshake")
 with contextlib.redirect_stdout(sys.stderr):model=Classifier(r,a.arm,a.lock,a.device)
 print(json.dumps(dict(load_seconds=model.load_seconds,device=a.device,arm=a.arm,warmup=1,precision="float32",attention="eager")),file=sys.stderr,flush=True)
 send(dict(hello,adapter_version=PROTOCOL))
 while True:
  line=sys.stdin.readline(r["bounds"]["request_bytes"]+1)
  if not line:break
  if len(line.encode())>r["bounds"]["request_bytes"] or not line.endswith("\n"):raise ValueError("request limit")
  q=json.loads(line)
  native=model.decision(q,a.control,a.threshold,a.margin)
  send(dict(kind="result",schema_version=PROTOCOL,request_id=q["request_id"],native=native))
if __name__=="__main__":main()
