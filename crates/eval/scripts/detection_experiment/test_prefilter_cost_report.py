"""Freeze and presentation regressions; no network or private corpus required."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from fresh_prefilter_holdout import candidate
from report_prefilter_cost import render_html
from report_matching_consistency import check_claimed_report


class CostReportTests(unittest.TestCase):
    def test_candidate_freeze_rejects_changed_rules_before_acquisition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'candidate.toml';source.write_bytes(b'original candidate')
            (root/'candidate-freeze.json').write_text(json.dumps({'files':{'candidate.toml':hashlib.sha256(source.read_bytes()).hexdigest()}}))
            candidate(root)
            source.write_bytes(b'candidate retuned after freezing')
            with self.assertRaisesRegex(ValueError,'frozen candidate changed'):candidate(root)

    def test_corrupt_holdout_count_cannot_pass_report_check(self):
        derived={'holdout':{'candidate':{'detected':7,'incomplete':0}}}
        claimed=json.loads(json.dumps(derived));claimed['holdout']['candidate']['detected']=587
        with self.assertRaisesRegex(ValueError,'native evidence'):check_claimed_report(claimed,derived)

    def test_html_escapes_evidence_labels(self):
        value={'median_ns_per_scan':100,'gaps':[]}
        report={'attribution':{},'optimization':{},'datasets':{},'deferred':{},'runtime':{'cases':[
            {'case':'<script>bad()</script>','bytes':1,'configs':{'baseline':value,'accepted':value}}]}}
        document=render_html(report)
        self.assertNotIn('<script>',document);self.assertIn('&lt;script&gt;',document)


if __name__=='__main__':unittest.main()
