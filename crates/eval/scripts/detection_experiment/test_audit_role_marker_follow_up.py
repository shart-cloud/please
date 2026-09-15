"""CLI regression against retained local evidence; private corpus bytes are not copied.

The always-runnable synthetic native-run regressions live in tests/role_marker_audit.rs.
This additional replay test requires the locally retained September 15 evidence.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[4]
EVIDENCE = REPO/'.cache/role-marker-follow-up-20260915'


class CorruptedSummaryRegression(unittest.TestCase):
    @unittest.skipUnless((EVIDENCE/'summary.json').exists(), 'requires retained local research evidence')
    def test_cli_rejects_inflated_llmail_detections_without_publishing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for path in EVIDENCE.iterdir():
                if path.name != 'summary.json':
                    (root/path.name).symlink_to(path.resolve())
            summary = json.loads((EVIDENCE/'summary.json').read_text())
            summary['packages']['development']['pos_llmail']['candidate']['detected'] = 27963
            (root/'summary.json').write_text(json.dumps(summary))
            output = root/'must-not-exist.json'
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('audit_role_marker_follow_up.py')),
                                     str(root), str(output)], cwd=REPO, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, 'auditor accepted an inflated detection count')
            self.assertIn('summary disagrees with verified native results: development/pos_llmail', result.stderr)
            self.assertFalse(output.exists(), 'failed audit published a report')


if __name__ == '__main__':
    unittest.main()
