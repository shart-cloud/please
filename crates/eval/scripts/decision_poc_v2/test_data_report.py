import copy,unittest
from prepare import data,exclusions
from report import metrics,calibration
class DataContract(unittest.TestCase):
 def test_allocations_and_groups(self):
  d=data();self.assertEqual([len(d[k]) for k in ("development","calibration","shuffled","challenge")],[480,240,480,30])
  for key,n in (("development",120),("calibration",60)):
   groups={}
   for c in d[key]:groups.setdefault(c["group_id"],[]).append(c)
   self.assertEqual(len(groups),n)
   for group in groups.values():
    self.assertEqual(len({c["_bytes"] for c in group}),1)
    self.assertEqual(len({c["ground_truth"]["relation"] for c in group}),4)
 def test_separation(self):
  d=data();self.assertEqual(exclusions(d)["near_duplicates"],[])
  d["calibration"][0]["family_id"]=d["development"][0]["family_id"]
  with self.assertRaises(AssertionError):exclusions(d)
 def test_absence_not_closed_world(self):
  for c in data()["development"]+data()["calibration"]:
   if c["ground_truth"]["relation"]=="indeterminate":
    self.assertNotIn("only",c["trusted_context"]["task"])
    self.assertEqual(c["trusted_context"]["permissions"][0]["resource"],"operator handbook")
 def test_abstention_counts_as_miss(self):
  rows=[]
  for c in data()["development"]:
   r=copy.deepcopy(c);r.update(_prediction="indeterminate",_diag={},coverage="completed");rows.append(r)
  m=metrics(rows)
  self.assertEqual(m["macro_recall"],0)
  self.assertEqual(m["coverage"]["n"],0)
  self.assertEqual(m["complete_groups"]["n"],0)
  self.assertEqual(m["missing_context_wrong"]["n"],0)
  self.assertIsNone(calibration(rows)["selected"])

 def perfect_rows(self):
  labels=["aligned_instruction","conflicting_instruction","non_instruction"]
  result=[]
  for c in data()["development"]:
   r=copy.deepcopy(c);label=c["ground_truth"]["relation"];scores=[.01,.01,.01]
   if label in labels:scores[labels.index(label)]=.99
   r.update(_prediction=label,_diag=dict(scores=scores),coverage="completed");result.append(r)
  return result
 def test_grid_accepts_supported_point(self):
  c=calibration(self.perfect_rows())
  self.assertEqual(len(c["points"]),30)
  self.assertIsNotNone(c["selected"])
 def test_false_conflict_is_per_stratum(self):
  rs=self.perfect_rows()
  r=next(r for r in rs if r["ground_truth"]["relation"]=="aligned_instruction")
  r["_diag"]["scores"]=[.01,.99,.01]
  self.assertIsNone(calibration(rs)["selected"])
 def test_missing_context_is_mandatory(self):
  rs=self.perfect_rows()
  r=next(r for r in rs if r["ground_truth"]["relation"]=="indeterminate")
  r["_diag"]["scores"]=[.99,.01,.01]
  self.assertIsNone(calibration(rs)["selected"])

if __name__=="__main__":unittest.main()
