import unittest
from report import metrics,paired
def row(truth,pred,valid=True,group="1",choice=None):
 return dict(case_id=group,truth=truth,prediction=pred,choice=choice or pred,valid=valid,group=group,source="test",family="test",error=None if valid else "input_cap",decision_ms=10 if valid else 99999,inference_ms=5 if valid else None)
class Metrics(unittest.TestCase):
 def test_failed_unknown_is_not_correct(self):
  m=metrics([row("indeterminate","indeterminate",False),row("indeterminate","indeterminate",True,"2")])
  self.assertEqual(m["recalls"]["indeterminate"],{"correct":1,"total":2})
  self.assertEqual(m["decided"],0)
  self.assertEqual(m["decision_ms_median"],10)
 def test_abstentions_remain_in_denominators(self):
  m=metrics([row("injection","injection"),row("injection","indeterminate",True,"2"),row("benign","injection",True,"3")])
  self.assertEqual(m["recalls"]["injection"],{"correct":1,"total":2})
  self.assertEqual(m["false_alarms"],1)
 def test_pairing_uses_case_identity(self):
  a=[row("injection","injection",True,"a"),row("injection","benign",True,"b")]
  b=[row("injection","injection",True,"b"),row("injection","benign",True,"a")]
  p=paired(a,b)["injection"]
  self.assertEqual(p["laya_only_correct"],1);self.assertEqual(p["jev_only_correct"],1)
if __name__=="__main__":unittest.main()
