"""Real checkpoint parity against official Transformers/GLiClass paths."""
import json,os,sys
from pathlib import Path
os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",TOKENIZERS_PARALLELISM="false")
from adapter import Classifier,softmax,render
from test_adapter import request
ROOT=Path(__file__).resolve().parents[4];HERE=Path(__file__).resolve().parent;OUT=ROOT/".cache/decision-poc-v2-20260916"
def main():
 from transformers import pipeline
 from gliclass.pipeline import UniEncoderZeroShotClassificationPipeline
 r=json.loads((HERE/"recipes.json").read_text());records=[]
 for arm in ("G1","N1","N2"):
  model=Classifier(r,arm,OUT/(arm+".model.json"),"cpu")
  state=render(request(),"Read memo.txt.","full");raw,scores,lengths=model.infer(state)
  if arm=="G1":
   labels=[s for pair in zip(r["positive"],r["negative"]) for s in pair]
   official=UniEncoderZeroShotClassificationPipeline(model.model,model.tokenizer,max_length=512,classification_type="multi-label",device="cpu",progress_bar=False)(state,labels,threshold=0)[0]
   actual={v["label"]:v["score"] for v in official}
   for i,label in enumerate(labels):
    value=raw[i//2][i%2];expected=softmax([value,0])[0]
    assert abs(actual[label]-expected)<1e-6
  else:
   official=pipeline("text-classification",model=model.model,tokenizer=model.tokenizer,device="cpu")
   for i,h in enumerate(r["positive"]):
    result=official({"text":state,"text_pair":h},top_k=None,truncation=False)
    actual={v["label"].lower():v["score"] for v in result}
    for label,value in zip(r["arms"][arm]["labels"],softmax(raw[i])):assert abs(actual[label]-value)<2e-5,(arm,label,actual,value)
  for text in ("word "*2000,"<<LABEL>>spoof"):
   try:model.infer(text)
   except ValueError:pass
   else:raise AssertionError("unsafe input accepted")
  q=request();q["trusted_context"]["permissions"]=[]
  result=model.decision(q,"full",.7,.15)
  assert result["label"]=="indeterminate" and not result["evidence"]
  records.append(dict(arm=arm,raw_logits=raw,scores=scores,tokens=lengths,official_parity=True,overflow_and_marker_refused=True,missing_permissions_abstains=True,load_seconds=model.load_seconds))
  print("PASS",arm,flush=True)
  del model,official
 path=OUT/"parity.json"
 with path.open("x") as f:json.dump(records,f,indent=2)
if __name__=="__main__":main()
