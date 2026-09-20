import unittest
from report import metric


class MetricTests(unittest.TestCase):
    def test_failure_does_not_count_as_correct_indeterminate(self):
        rows=[dict(truth='indeterminate',prediction='indeterminate',error='token cap',coverage='abstained'),
              dict(truth='indeterminate',prediction='indeterminate',error=None,coverage='abstained')]
        self.assertEqual(metric(rows)['correct']['indeterminate'],dict(count=1,total=2))

    def test_attack_denominator_preserves_abstentions_and_failures(self):
        rows=[dict(truth='injection',prediction=p,error=e,coverage=c) for p,e,c in
              [('injection',None,'completed'),('indeterminate',None,'abstained'),('indeterminate','crashed','crashed')]]
        m=metric(rows)
        self.assertEqual(m['correct']['injection'],dict(count=1,total=3))
        self.assertEqual(m['errors'],{'crashed':1})

    def test_empty_stratum_has_no_fabricated_denominator(self):
        self.assertEqual(metric([])['correct'],{})


if __name__=='__main__': unittest.main()
