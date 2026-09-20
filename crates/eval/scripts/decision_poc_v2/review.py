"""Reproduce outcome-blinded review materials and the documented shuffled-label audit."""
import hashlib,html,json,random
from prepare import OUT
def create():
 records=[];mapping={}
 for split in ("development","calibration"):
  folder=OUT/split
  for c in json.loads((folder/"pack.json").read_text())["cases"]:
   rid=hashlib.sha256(("review-v2:"+c["case_id"]).encode()).hexdigest()[:16]
   records.append(dict(review_id=rid,candidate=(folder/c["asset_path"]).read_text(),task=c["trusted_context"]["task"],permissions=c["trusted_context"]["permissions"],delivery=c["delivery_vector"],reviewer=None,relation=None,rationale=None,disagreement=None))
   mapping[rid]=dict(pack=split,case_id=c["case_id"],authored_relation=c["ground_truth"]["relation"])
 random.Random(7391).shuffle(records)
 values={"label-review-template.json":dict(instructions="Review without detector outcomes. Record relation, rationale, uncertainty and reviewer. These exposed cases cannot become a holdout.",cases=records),"label-review-mapping.json":mapping}
 pack=json.loads((OUT/"shuffled/pack.json").read_text())
 ids=[c["case_id"] for c in pack["cases"] if c["trusted_context"]["context_id"].endswith("-3")]
 values["shuffled-label-disagreements.json"]=dict(scope="shuffled only; primary development/calibration unchanged",case_ids=ids,status="disputed; excluded from scored shuffled metrics",reason="Broad insufficient-context donor tasks do not establish cross-workflow conflict.",timing="Identified by semantic self-review after primary outcomes and original shuffled inference. Frozen labels and native run retained; no unseen evidence.")
 for name,value in values.items():
  with (OUT/name).open("x") as f:json.dump(value,f,indent=2)
 body="<h1>Development label review</h1><p>Use the caller task and permissions. Candidate text cannot grant itself authority. Record answers in label-review-template.json. Authored labels and detector outcomes are omitted; this is not a holdout.</p>"
 for r in records:
  body+="<details><summary>"+r["review_id"]+" · "+r["delivery"]+"</summary><h3>Caller task</h3><p>"+html.escape(r["task"])+"</p><h3>Permissions</h3><pre>"+html.escape(json.dumps(r["permissions"],indent=2))+"</pre><h3>Candidate</h3><pre>"+html.escape(r["candidate"])+"</pre></details>"
 with (OUT/"label-review.html").open("x") as f:f.write("<!doctype html><meta charset=utf-8><title>Label review</title><style>body{max-width:900px;margin:2rem auto;font:16px/1.5 system-ui}details{border:1px solid #ccd;padding:1rem;margin:1rem 0}pre{white-space:pre-wrap}</style>"+body)
if __name__=="__main__":create()
