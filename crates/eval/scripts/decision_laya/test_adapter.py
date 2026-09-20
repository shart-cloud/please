import unittest,math
from adapter import decode,validate_case,sequence_check
class Tokenizer:
 mask_token="[MASK]";mask_token_id=9;cls_token_id=1;sep_token_id=2
 all_special_tokens=["[MASK]","[CLS]","[SEP]"]
 def __call__(self,text,add_special_tokens=False):return {"input_ids":list(range(10,10+len(text.split())))}
class Contracts(unittest.TestCase):
 def test_decoder(self):
  self.assertEqual(decode({"a":.9,"b":.1},"a",.7,.15),"a")
  self.assertEqual(decode({"a":.6,"b":.4},"a",.7,.15),"indeterminate")
  for p in [{"a":float('nan'),"b":.1},{"a":1.1,"b":-.1},{"a":.9,"b":.9}]:
   with self.assertRaises(ValueError):decode(p,"a",.7,.15)
  with self.assertRaises(ValueError):decode({"a":.9,"b":.1},"b",.7,.15)
 def test_bounds_no_truncation(self):
  t=Tokenizer();q={"type":"choice","instructions":"Choose a label.","criteria":{"a":"yes","b":"no"}}
  info=sequence_check(t,"a b",q,512,192)
  self.assertGreater(info["tokens"],2)
  with self.assertRaisesRegex(ValueError,"state_token_cap"):sequence_check(t,"x "*1000,q,512,192)
  q["instructions"]="x "*300
  with self.assertRaisesRegex(ValueError,"instruction_token_cap"):sequence_check(t,"hi",q,512,192)
  q["instructions"]="choose";q["criteria"]["a"]="x "*60
  with self.assertRaisesRegex(ValueError,"option_token_cap"):sequence_check(t,"hi",q,512,192)
 def test_special_markers_and_identity(self):
  import hashlib
  raw=b"hello"
  q=dict(kind="case",schema_version="please-bench-jsonl/v1",request_id="1",surface="artifact_detection",candidate_encoding="hex",candidate_hex=raw.hex(),candidate_sha256=hashlib.sha256(raw).hexdigest(),byte_length=5,provenance="user_input",trusted_context=None)
  self.assertEqual(validate_case(q),"hello")
  q.pop("trusted_context");self.assertEqual(validate_case(q),"hello")
  q["byte_length"]=4
  with self.assertRaises(ValueError):validate_case(q)
  question={"type":"choice","instructions":"choose","criteria":{"a":"yes","b":"no"}}
  with self.assertRaisesRegex(ValueError,"special_marker"):sequence_check(Tokenizer(),"[MASK]",question,512,192)
 def test_random_invalid_scores(self):
  import random
  rng=random.Random(20260919)
  for _ in range(1000):
   v=rng.uniform(-100,100)
   if not 0<=v<=1:
    with self.assertRaises(ValueError):decode({"a":v,"b":1-v},"a",.7,.15)
if __name__=="__main__":unittest.main()
