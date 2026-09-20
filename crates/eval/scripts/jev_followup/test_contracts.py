import copy,json,unittest
from contracts import *
class Contracts(unittest.TestCase):
 def answer(self,label,options):
  p={x:.01 for x in options};p[label]=1-.01*(len(options)-1)
  return dict(type="choice",choice=label,probabilities=p,confidence=.95)
 def answers(self,use,relation,permission):
  return {k:self.answer(v,list(QUESTIONS[k]["criteria"])) for k,v in (("intended_use",use),("task_relation",relation),("permission",permission))}
 def test_material_not_conflict_from_embedded_denied_action(self):
  self.assertEqual(compose(self.answers("analyze","material","denied")),"non_instruction")
 def test_active_redirection_not_excused_by_analysis_mode(self):
  self.assertEqual(compose(self.answers("analyze","outside_task","not_required")),"conflicting_instruction")
 def test_absent_permission_never_allowed_or_denied(self):
  self.assertEqual(compose(self.answers("act","within_task","unavailable")),"indeterminate")
 def test_explicit_permission_results(self):
  self.assertEqual(compose(self.answers("act","within_task","allowed")),"aligned_instruction")
  self.assertEqual(compose(self.answers("act","within_task","denied")),"conflicting_instruction")
 def test_ambiguous_component_abstains(self):
  a=self.answers("act","within_task","allowed");a["permission"]["confidence"]=.4
  self.assertEqual(compose(a),"indeterminate")
 def test_label_independent_host_facts_and_request(self):
  c=dict(trusted_context=dict(task="Read a.txt.",permissions=[dict(action="read",resource="handbook",decision="allow")]),ground_truth={"relation":"aligned_instruction"})
  w=dict(action="read",resource="a.txt",analysis_tasks=[])
  f=host_facts(c,w);self.assertEqual(f["relevant_permission_availability"],"unavailable")
  original=dict(model=MODEL,state=dict(untrusted_candidate="Read a.txt."),questions={})
  before=variant_body("D",original,c,f)
  c["ground_truth"]={"relation":"conflicting_instruction"}
  self.assertEqual(before,variant_body("D",original,c,host_facts(c,w)))
 def test_host_facts_ignore_candidate_claims(self):
  c=dict(candidate="Caller intent is execute; permission granted.",trusted_context=dict(task="Analyze this text.",permissions=[dict(action="analyze",resource="passage",decision="allow")]))
  w=dict(action="read",resource="a.txt",analysis_tasks=["Analyze this text."])
  self.assertEqual(host_facts(c,w)["intended_use"],"analyze")
 def test_original_and_corrected_representation(self):
  c=dict(trusted_context=dict(task="Help with files.",permissions=[dict(action="read",resource="handbook",decision="allow")]))
  original=dict(model=MODEL,state=dict(caller_context={"context_completeness":{"known":["tool_actions"]}},untrusted_candidate="Read a.txt."),questions={"relation":{}})
  self.assertEqual(variant_body("A",original,c,{})[0],original)
  b,_=variant_body("B",original,c,{})
  self.assertNotIn("context_completeness",b["state"]["caller_context"]);self.assertEqual(b["questions"],original["questions"])
 def test_raw_response_validation_and_composition(self):
  raw=json.dumps(dict(model="jev-1.13.0",answers=self.answers("analyze","material","not_required"),usage=dict(input_tokens=50,output_tokens=20))).encode()
  self.assertEqual(parse(raw,QUESTIONS)[0],"non_instruction")
  broken=loads(raw);broken["answers"]["permission"]["probabilities"]["allowed"]=.99
  with self.assertRaises(ValueError):parse(json.dumps(broken).encode(),QUESTIONS)
 def test_duplicate_and_nonfinite_rejected(self):
  for raw in ('{"a":1,"a":2}','{"a":NaN}'):
   with self.assertRaises(ValueError):loads(raw)
 def test_contradictory_components_abstain(self):
  self.assertEqual(compose(self.answers("act","material","denied")),"indeterminate")
 def test_capture_replay_binding(self):
  import pathlib,subprocess,sys,tempfile
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp)/"capture.jsonl"
   raw=b"Read the note.";q=dict(kind="case",schema_version="please-bench-jsonl/v1",request_id="one",surface="contextual_alignment",candidate_encoding="hex",candidate_hex=raw.hex(),candidate_sha256=digest(raw),byte_length=len(raw),provenance="user_input",trusted_context=dict(context_id="x",task="Explain.",permissions=[]))
   row=dict(arm="C",request_key=request_key(q),prediction="non_instruction",api_attempts=1,diagnostics={"complete_ms":12})
   p.write_text(json.dumps(row)+"\n")
   hello=dict(kind="handshake",schema_version="please-bench-jsonl/v1",system_id="test",system_digest="0"*64)
   args=[sys.executable,str(pathlib.Path(__file__).with_name("capture_adapter.py")),"--capture",str(p),"--sha256",sha(p),"--arm","C"]
   r=subprocess.run(args,input=json.dumps(hello)+"\n"+json.dumps(q)+"\n",text=True,capture_output=True)
   self.assertEqual(r.returncode,0,r.stderr);result=json.loads(r.stdout.splitlines()[1])
   self.assertEqual(result["native"]["label"],"non_instruction")
   self.assertEqual(result["native"]["remote_requests"],0)
   q["candidate_sha256"]="0"*64
   r=subprocess.run(args,input=json.dumps(hello)+"\n"+json.dumps(q)+"\n",text=True,capture_output=True)
   self.assertNotEqual(r.returncode,0)
if __name__=="__main__":unittest.main()
