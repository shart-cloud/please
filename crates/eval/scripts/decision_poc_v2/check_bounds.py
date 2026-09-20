"""Exact 512/513 encoded-token boundary contracts, separate from quality evaluation."""
import json,os
from pathlib import Path
os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",TOKENIZERS_PARALLELISM="false")
from adapter import Classifier
from prepare import OUT,HERE
def main():
 r=json.loads((HERE/"recipes.json").read_text());records=[]
 for arm in ("G1","N1","N2"):
  m=Classifier(r,arm,OUT/(arm+".model.json"),"cpu")
  def length(state):
   if arm=="G1":
    statements=[s for pair in zip(r["positive"],r["negative"]) for s in pair]
    prefix="".join("<<LABEL>>"+s for s in statements)+"<<SEP>>"
    prompt=prefix+state if m.model.config.prompt_first else state+prefix
    return len(m.tokenizer(prompt,truncation=False)["input_ids"])
   return max(len(x) for x in m.tokenizer([state]*3,r["positive"],truncation=False)["input_ids"])
  states={}
  for n in range(600):
   text="word "*n;count=length(text)
   if count in (512,513):states[count]=text
   if len(states)==2:break
  assert set(states)=={512,513},(arm,states.keys())
  raw,scores,lens=m.infer(states[512]);assert max(lens)==512
  try:m.infer(states[513])
  except ValueError as e:assert "token limit" in str(e)
  else:raise AssertionError("513-token input accepted")
  records.append(dict(arm=arm,accepted_tokens=max(lens),rejected_tokens=513,no_truncation=True))
  print("BOUNDARY PASS",arm,flush=True)
  del m
 with (OUT/"exact-boundaries.json").open("x") as f:json.dump(records,f,indent=2)
if __name__=="__main__":main()
