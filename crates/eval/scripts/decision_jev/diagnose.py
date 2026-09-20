"""Inspect up to five rejected cases after the run; never replace benchmark results."""
import getpass,json,math,pathlib,subprocess,tempfile,urllib.request,urllib.error
from prepare import OUT,ROOT,save
from common import ENDPOINT,MODEL,RELATIONS,map_context,loads,digest,validate_response
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
def main():
 session=loads((OUT/"session.json").read_bytes())
 rows=[loads(line) for line in (OUT/"run-development/results.jsonl").read_bytes().splitlines()]
 errors=[r for r in rows if "error" in loads(r["raw_output"]["native"]["diagnostics"][0])][:5]
 if session["attempted_requests"]+1+len(errors)>2000:raise ValueError("no diagnostic request budget remains")
 pack=loads((OUT/"development/pack.json").read_bytes());cases={c["case_id"]:c for c in pack["cases"]}
 dest=OUT/"response-diagnostics.json"
 if dest.exists():raise ValueError("diagnostics already exist")
 key=getpass.getpass("Temporary Jev token for up to five diagnostics (hidden): ")
 results=[]
 for row in errors:
  c=cases[row["case_id"]];raw=(OUT/"development"/c["asset_path"]).read_bytes()
  with tempfile.TemporaryDirectory(prefix="jev-diagnostic-") as tmp:
   p=pathlib.Path(tmp)/"context.json";p.write_text(json.dumps(map_context(c["trusted_context"])))
   provenance={"user_input":"user-input","repository_file":"caller-provided","tool_response":"tool-response"}[c["provenance"]]
   request=subprocess.run([str(OUT/"plz"),"clap","-","--context",str(p),"--provenance",provenance,"--model",MODEL,"--request-only"],input=raw,capture_output=True,check=True).stdout.strip()
  record=dict(case_id=c["case_id"],original_error=loads(row["raw_output"]["native"]["diagnostics"][0])["error"],request_sha256=digest(request),post_outcome_diagnostic=True)
  try:
   q=urllib.request.Request(ENDPOINT,request,{"Content-Type":"application/json","Authorization":"Bearer "+key},method="POST")
   with urllib.request.build_opener(NoRedirect).open(q,timeout=30) as response:raw_response=response.read(16385)
   if key.encode() in raw_response:raise ValueError("credential reflection blocked")
   v=loads(raw_response);a=v["answers"]["relation"]
   if a["choice"] not in RELATIONS or set(a["probabilities"])!=set(RELATIONS):raise ValueError("unexpected response labels")
   if any(type(x) not in (int,float) or not math.isfinite(x) for x in [a["confidence"],*a["probabilities"].values()]):raise ValueError("invalid numeric fields")
   p=a["probabilities"];record.update(response_sha256=digest(raw_response),probabilities=p,choice=a["choice"],confidence=a["confidence"],probability_sum=sum(p.values()),choice_gap=max(p.values())-p[a["choice"]],usage=v.get("usage"))
   try:validate_response(raw_response,"relation",RELATIONS);record["fresh_validation"]="valid"
   except ValueError as e:record["fresh_validation"]=str(e)
  except urllib.error.HTTPError as e:record["error"]="HTTP "+str(e.code)
  except Exception:record["error"]="diagnostic response unavailable"
  results.append(record)
  print(json.dumps({k:record[k] for k in ("case_id","original_error","probability_sum","choice_gap","fresh_validation","error") if k in record}),flush=True)
 save(dest,dict(attempts=len(results),results=results,original_results_replaced=False,interpretation="Fresh post-outcome requests can differ from the original responses; no original invalid response body was retained by the CLI. These diagnostics do not repair or rescore the frozen run."))
if __name__=="__main__":main()
