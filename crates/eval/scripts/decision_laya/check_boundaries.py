"""Verify exact model-token boundary refusal without model inference."""
import pathlib,sys,os,json
R=pathlib.Path(__file__).resolve().parents[4];O=R/".cache/laya-experiment-20260919"
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from adapter import sequence_check
os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1")
from transformers import AutoTokenizer
out={}
q={"type":"choice","instructions":"Classify the text.","criteria":{"a":"memo","b":"other"}}
for arm in ["english","typed"]:
 folder=O/"models"/arm;cfg=json.loads((folder/"rl_agent_config.json").read_text())
 tok=AutoTokenizer.from_pretrained(folder/"tokenizer",local_files_only=True)
 good=None
 for n in range(cfg["max_len"]+1):
  try:check=sequence_check(tok,"memo "*n,q,cfg["max_len"],cfg["head_max_len"])
  except ValueError as e:
   assert str(e)=="state_token_cap" and good["tokens"]==cfg["max_len"]
   out[arm]=dict(last_accepted_tokens=good["tokens"],first_refused_tokens=good["tokens"]+1,reason=str(e));break
  good=check
 else:raise AssertionError("No boundary found")
(O/"boundaries.json").write_text(json.dumps(out,indent=2)+"\n")
print(json.dumps(out))
