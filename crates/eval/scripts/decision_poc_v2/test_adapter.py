import hashlib,json,math,random,unittest
from adapter import decode,score_logits,validate_request,render
R=json.load(open(__file__.replace("test_adapter.py","recipes.json")))
def request(text="Read memo.txt."):
 b=text.encode();return dict(kind="case",schema_version="please-bench-jsonl/v1",request_id="test",surface="contextual_alignment",candidate_encoding="hex",candidate_hex=b.hex(),candidate_sha256=hashlib.sha256(b).hexdigest(),byte_length=len(b),provenance="user_input",trusted_context=dict(context_id="ignored",task="Read the memo.",permissions=[]))
class Contract(unittest.TestCase):
 def test_unique(self):
  self.assertEqual(decode([.9,.2,.1],.7,.15),R["relations"][0])
  for s in ([.9,.8,.1],[.1,.2,.3],[.7,.6,.2],[.8,.8,.8]):self.assertEqual(decode(s,.7,.15),"indeterminate")
 def test_invalid(self):
  for s in ([],[1,0],[1,0,0,0],[float("nan"),0,0],[float("inf"),0,0],[-1,0,0],[2,0,0],[True,0,0]):self.assertEqual(decode(s,.7,.15),"indeterminate")
 def test_pair_logits(self):
  s=score_logits("G1",[[100,99],[100,101],[99,100]])
  self.assertAlmostEqual(s[0],.7310585786)
  self.assertGreater(s[0],s[1])
 def test_nli(self):
  self.assertAlmostEqual(score_logits("N1",[[0,0,0]]*3)[0],1/3)
  self.assertEqual(decode(score_logits("N2",[[-100,100]]*3),.7,.15),"indeterminate")
 def test_context(self):
  q=request();text=validate_request(q,R)
  a=render(q,text,"full");q["request_id"]="LABEL";q["trusted_context"]["context_id"]="SECRET"
  self.assertEqual(a,render(q,text,"full"))
  self.assertNotIn("SECRET",a)
  self.assertNotIn("Read memo.txt.",render(q,text,"context_only"))
  self.assertNotIn("trusted_task",render(q,text,"candidate_only"))
 def test_missing(self):
  for context in (None,{},dict(task="",permissions=[]),dict(task="x",permissions="all")):
   q=request();q["trusted_context"]=context
   with self.assertRaises(ValueError):validate_request(q,R)
 def test_identity_bounds(self):
  for edit in (dict(candidate_hex="zz"),dict(byte_length=99),dict(candidate_sha256="a"*64),dict(extra=1),dict(surface="artifact_detection")):
   q=request();q.update(edit)
   with self.assertRaises(ValueError):validate_request(q,R)
  with self.assertRaises(ValueError):validate_request(request("x"*16385),R)
 def test_fuzz(self):
  rng=random.Random(9)
  for _ in range(2000):
   s=[rng.random() for _ in range(3)];d=decode(s,.7,.15)
   if d!="indeterminate":
    i=R["relations"].index(d);self.assertEqual(sum(x>=.7 for x in s),1);self.assertGreaterEqual(s[i]-max(s[:i]+s[i+1:]),.15)
   q=request();raw=rng.randbytes(rng.randrange(100));q.update(candidate_hex=raw.hex(),byte_length=len(raw),candidate_sha256=hashlib.sha256(raw).hexdigest())
   try:self.assertEqual(validate_request(q,R).encode(),raw)
   except ValueError:pass
 def test_permissions(self):
  q=request();q["trusted_context"]["permissions"]=[{"kind":"made_up"}]
  with self.assertRaises(ValueError):validate_request(q,R)

 def test_context_byte_bound(self):
  q=request();q["trusted_context"]["task"]="x"*16385
  with self.assertRaises(ValueError):validate_request(q,R)
 def test_unicode_byte_bound(self):
  with self.assertRaises(ValueError):validate_request(request("é"*8193),R)
 def test_score_shape(self):
  for arm in ("G1","N1","N2"):
   for raw in ([],[[0,0]],[[0,0]]*4,[[float("nan"),0]]*3):
    with self.assertRaises(ValueError):score_logits(arm,raw)
if __name__=="__main__":unittest.main()

