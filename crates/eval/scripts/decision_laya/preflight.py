"""Token admission and synthetic parity only; never evaluates corpus outcomes."""
import json,pathlib,sys,collections,os
R=pathlib.Path(__file__).resolve().parents[4];H=pathlib.Path(__file__).resolve().parent;O=R/".cache/laya-experiment-20260919"
sys.path.insert(0,str(H));from adapter import sequence_check,Engine
os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1")
from transformers import AutoTokenizer
requests=json.loads((R/".cache/jev-scale-20260918/requests.json").read_text())
selection=json.loads((O/"selection.json").read_text());selected=set(selection["public"]+selection["contextual"])
recipe=json.loads((O/"recipes.json").read_text());counts={}
for arm in recipe["arms"]:
 folder=O/"models"/arm;cfg=json.loads((folder/"rl_agent_config.json").read_text());tok=AutoTokenizer.from_pretrained(folder/"tokenizer",local_files_only=True)
 arm_counts=collections.defaultdict(collections.Counter)
 for row in requests:
  if row["case_id"] not in selected:continue
  body=json.loads(bytes.fromhex(row["body_hex"]));surface="artifact_detection" if row["partition"]=="public" else "contextual_alignment"
  for kind,questions in [("jev_exact",body["questions"]),("compact",recipe["questions"][surface])]:
   reason="fits"
   try:
    for q in questions.values():sequence_check(tok,body["state"],q,cfg["max_len"],cfg["head_max_len"])
   except ValueError as e:reason=str(e)
   arm_counts[row["partition"]+"/"+kind][reason]+=1
 counts[arm]={k:dict(v) for k,v in arm_counts.items()}
(O/"token-admission.json").write_text(json.dumps(counts,indent=2)+"\n")
print(json.dumps(counts),flush=True)
# Synthetic repeated predictions verify deterministic and official packing parity.
for arm in recipe["arms"]:
 engine=Engine(O,arm)
 question=recipe["questions"]["artifact_detection"]
 state={"untrusted_candidate":"A plain memo for discussion.","provenance":"user_input"}
 from laya.common import build_sequence
 for q in question.values():
  check=sequence_check(engine.agent.tok,state,q,engine.agent.cfg["max_len"],engine.agent.cfg["head_max_len"])
  seq,pos=build_sequence(engine.agent.tok,state,engine.agent._to_internal(q),engine.agent.cfg["max_len"],engine.agent.cfg["head_max_len"])
  assert check["ids"]==seq and check["markers"]==pos
 a=engine.agent.predict(state,question);b=engine.agent.predict(state,question)
 assert a==b
 (O/("synthetic-"+arm+".json")).write_text(json.dumps(dict(native=a,repeat_equal=True,packing_equal=True,device=str(engine.agent.device)),indent=2)+"\n")
 del engine
 import gc,torch;gc.collect();torch.cuda.empty_cache()
print("Synthetic parity/determinism passed for both models.",flush=True)
