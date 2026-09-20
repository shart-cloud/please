import json
from pathlib import Path
import tempfile
import unittest

import scale


class SelectionContracts(unittest.TestCase):
    def row(self, text, label="benign", source="fixture"):
        return dict(text=text, label=label, source=source)

    def test_conflicting_normalized_labels_never_selected(self):
        rows = [self.row("Ａ test"), self.row("a TEST", "injection"), self.row("ordinary")]
        chosen, excluded, _ = scale.select(rows, {"benign": {"fixture": 1}})
        self.assertEqual([r["text"] for r in chosen], ["ordinary"])
        self.assertEqual(excluded["conflicting_normalized_labels"], 2)

    def test_caps_exposure_and_duplicates_are_accounted_without_truncation(self):
        rows = [self.row("a" * 16385), self.row("seen"), self.row("keep"), self.row(" KEEP ")]
        chosen, excluded, _ = scale.select(rows, {"benign": {"fixture": 1}}, {scale.digest(b"seen")})
        self.assertEqual(len(chosen), 1)
        self.assertEqual(excluded, dict(over_16384_bytes=1, previous_jev_public_bytes=1, normalized_duplicate=1))
        self.assertIn(chosen[0]["text"], ["keep", " KEEP "])

    def test_shortage_is_not_silent_downsampling(self):
        with self.assertRaisesRegex(ValueError, "quota shortage"):
            scale.select([self.row("one")], {"benign": {"fixture": 2}})

    def test_selection_is_order_independent(self):
        rows = [self.row(str(i)) for i in range(20)]
        self.assertEqual(scale.select(rows, {"benign": {"fixture": 7}}),
                         scale.select(rows[::-1], {"benign": {"fixture": 7}}))

    def test_legacy_newlines_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "rows"
            p.write_text('{"text":"line one\nline two"}\n{"text":"other"}\n')
            self.assertEqual(list(scale.records(p))[0]["text"], "line one\nline two")

    def test_tampered_freeze_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scale.save(root / "requests.json", [])
            scale.save(root / "freeze.json", dict(files={"requests.json": scale.sha(root / "requests.json")}))
            scale.check(root)
            (root / "requests.json").write_text("[{}]")
            with self.assertRaisesRegex(ValueError, "frozen file changed"):
                scale.check(root)

    def test_missing_and_abstaining_rows_remain_in_denominator(self):
        rows = [dict(ground_truth=dict(label="injection"), prediction=p) for p in ["injection", "indeterminate", "not_run"]]
        result = scale.metric(rows)
        self.assertEqual(result["recall"]["injection"], dict(correct=1, total=3))
        self.assertEqual(result["missing"], 1)
        self.assertEqual(result["abstentions"], 1)


if __name__ == "__main__":
    unittest.main()
