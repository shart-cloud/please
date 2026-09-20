import json,unittest
from common import *
class Contract(unittest.TestCase):
 def test_mapping_keeps_literal_resource_and_unspecified_scope(self):
  c=dict(context_id="do-not-send",task="Read A&B.txt.",permissions=[dict(resource="A&B.txt",action="read",decision="allow")])
  m=map_context(c);self.assertEqual(m["task_context"],c["task"]);self.assertEqual(m["boundaries"][0]["scope"],"A&B.txt")
  self.assertNotIn("do-not-send",json.dumps(m));self.assertIn("unspecified",m["boundaries"][0]["constraint"])
 def test_missing_permissions_refused(self):
  with self.assertRaises(ValueError):map_context(dict(context_id="x",task="Read.",permissions=[]))
 def test_duplicate_and_nonfinite(self):
  for raw in ('{"x":1,"x":2}','{"x":NaN}'):
   with self.assertRaises(ValueError):loads(raw)
 def response(self,p=None,choice="injection"):
  return json.dumps(dict(model="jev-latest",answers={"classification":dict(type="choice",choice=choice,probabilities=p or dict(injection=.9,benign=.05,indeterminate=.05),confidence=.8)},usage=dict(input_tokens=10,output_tokens=1))).encode()
 def test_artifact_response_retains_scores(self):
  a=validate_response(self.response(),"classification",ARTIFACT_LABELS);self.assertEqual(a["relation"],"injection");self.assertEqual(a["probabilities"]["injection"],.9)
 def test_inconsistent_choice_rejected(self):
  with self.assertRaises(ValueError):validate_response(self.response(choice="benign"),"classification",ARTIFACT_LABELS)
 def test_invalid_distribution(self):
  with self.assertRaises(ValueError):validate_response(self.response(dict(injection=1,benign=.5,indeterminate=.1)),"classification",ARTIFACT_LABELS)
 def test_abstention_threshold(self):
  self.assertEqual(decode(dict(injection=.6,benign=.3,indeterminate=.1),"injection",.8),"indeterminate")
  self.assertEqual(decode(dict(injection=.9,benign=.05,indeterminate=.05),"injection",.4),"indeterminate")
 def test_request_identity_and_bounds(self):
  raw=b"Read."
  q=dict(kind="case",schema_version=PROTOCOL,request_id="x",surface="artifact_detection",candidate_encoding="hex",candidate_hex=raw.hex(),candidate_sha256=digest(raw),byte_length=len(raw),provenance="user_input")
  self.assertEqual(validate(q)[0],raw)
  q["candidate_sha256"]="0"*64
  with self.assertRaises(ValueError):validate(q)
  q["candidate_hex"]="00"*16385
  with self.assertRaises(ValueError):validate(q)
if __name__=="__main__":unittest.main()
