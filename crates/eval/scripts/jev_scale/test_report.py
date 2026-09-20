import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import report
import scale


class ReportingContracts(unittest.TestCase):
    def test_missing_results_are_not_benign_or_completed(self):
        rows = [dict(truth="benign", prediction=p) for p in ("benign", "indeterminate", "not_run")]
        m = report.artifacts(rows)
        self.assertEqual(m["benign_acceptance"], report.ratio(1, 3))
        self.assertEqual(m["coverage"], report.ratio(1, 3))
        self.assertEqual(m["missing"], 1)
        self.assertEqual(m["false_positive_rate"], report.ratio(0, 3))

    def test_error_is_not_correct_missing_permission_reasoning(self):
        rows = [dict(truth="indeterminate", prediction="indeterminate", error="bad response", group_id="one"),
                dict(truth="indeterminate", prediction="indeterminate", error=None, group_id="two")]
        m = report.contextual(rows)
        self.assertEqual(m["correct_missing_context_abstentions"], report.ratio(1, 2))
        self.assertEqual(m["recall"]["indeterminate"], report.ratio(1, 2))
        self.assertEqual(m["full_group_correctness"], report.ratio(1, 2))

    def test_captured_error_cannot_be_reported_as_determinate(self):
        row = dict(request_key="key", arm="public", api_attempts=1, prediction="benign",
                   diagnostics=dict(error="invalid distribution", request_sha256="hash"))
        entry = dict(request_key="key", partition="public", request_sha256="hash")
        with self.assertRaisesRegex(ValueError, "determinate"):
            report.verify_capture(row, entry)

    def test_changed_capture_prediction_is_rejected(self):
        raw = json.dumps(dict(model="jev-test", usage=dict(input_tokens=2, output_tokens=3),
                              answers=dict(classification=dict(type="choice", choice="injection", confidence=.9,
                                                               probabilities=dict(injection=.9, benign=.05, indeterminate=.05))))).encode()
        diag = report.validate_response(raw, "classification", report.ARTIFACT_LABELS)
        diag.update(response_hex=raw.hex(), request_sha256="request")
        row = dict(request_key="key", arm="public", api_attempts=1, prediction="injection", diagnostics=diag)
        entry = dict(request_key="key", partition="public", request_sha256="request")
        report.verify_capture(row, entry)
        row["prediction"] = "benign"
        with self.assertRaisesRegex(ValueError, "decoder mismatch"):
            report.verify_capture(row, entry)

    def test_replay_preserves_abstention_and_makes_zero_requests(self):
        raw = b"synthetic instrument fixture"
        q = dict(kind="case", schema_version="please-bench-jsonl/v1", request_id="instrument",
                 surface="artifact_detection", candidate_encoding="hex", candidate_hex=raw.hex(),
                 candidate_sha256=scale.digest(raw), byte_length=len(raw), provenance="user_input")
        c = dict(surface=q["surface"], asset_sha256=q["candidate_sha256"], byte_length=len(raw), provenance=q["provenance"])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "capture.jsonl"
            p.write_text(json.dumps(dict(arm="public", request_key=scale.request_key(c), prediction="indeterminate",
                                        api_attempts=1, diagnostics=dict(error="synthetic instrument"))) + "\n")
            hello = dict(kind="handshake", schema_version="please-bench-jsonl/v1", system_id="instrument", system_digest="0" * 64)
            adapter = Path(__file__).resolve().parent.parent / "jev_usage/capture_adapter.py"
            result = subprocess.run([sys.executable, str(adapter), "--capture", str(p), "--sha256", scale.sha(p), "--arm", "public"],
                                    input=json.dumps(hello) + "\n" + json.dumps(q) + "\n", text=True, capture_output=True, check=True)
            answer = json.loads(result.stdout.splitlines()[1])
            self.assertTrue(answer["native"]["abstained"])
            self.assertEqual(answer["native"]["remote_requests"], 0)
            self.assertEqual(answer["native"]["label"], "indeterminate")


if __name__ == "__main__":
    unittest.main()
