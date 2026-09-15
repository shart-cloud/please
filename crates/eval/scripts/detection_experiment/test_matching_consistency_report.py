"""Small evidence/presentation regressions; no private corpus required."""
import copy
import unittest

from report_matching_consistency import check_claimed_report, compact, render_html
from role_marker_follow_up import compare


class MatchingReportTests(unittest.TestCase):
    def test_recounts_finding_multiplicity_and_corrupt_totals(self):
        finding = {'rule_id':'boundary.marker', 'start':0, 'end':3}
        old = {'one': {'id':'one', 'detected':False, 'reasons':[]}}
        new = {'one': {'id':'one', 'detected':True, 'reasons':[finding, finding],
                       'incomplete':['max_matches_per_rule']}}
        derived = compact(compare(old,new))
        self.assertEqual(derived['added_findings'],2)
        self.assertEqual(derived['added_detections'],1)
        self.assertEqual(derived['newly_incomplete'],1)
        check_claimed_report(copy.deepcopy(derived),derived)
        corrupt = copy.deepcopy(derived)
        corrupt['candidate']['detected'] = 27963
        with self.assertRaisesRegex(ValueError,'native evidence'):
            check_claimed_report(corrupt,derived)

    def test_html_escapes_evidence_labels(self):
        report = {'packages':{}, 'rules':{'<script>alert(1)</script>':{
            'disposition':'deferred', 'probe_rows_matching_intended_rule':dict.fromkeys(['baseline','accepted','reference'],0),
            'new_reference_findings':1}}, 'runtime':{'cases':[],'preparation_ns':[1,2,3]}, 'corpus_runtime':{}, 'gap_investigations':[]}
        rendered = render_html(report)
        self.assertNotIn('<script>',rendered)
        self.assertIn('&lt;script&gt;',rendered)


if __name__=='__main__': unittest.main()
