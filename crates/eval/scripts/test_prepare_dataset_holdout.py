"""Synthetic tests of dataset identity and selection; no network or detector calls."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import prepare_dataset_holdout as holdout


class HoldoutTests(unittest.TestCase):
    def setup_plan(self, root):
        cache = root / "cache"
        cache.mkdir()
        # Exercise historical records containing a literal newline inside a JSON string.
        (cache / "legacy.jsonl").write_text('{"prompt":"Already\nSEEN"}\n')
        plan = root / "plan"
        with contextlib.redirect_stdout(io.StringIO()):
            holdout.plan(root, cache, plan, 1)
        rows = []
        for source, label in holdout.STRATA:
            prompt = f"Synthetic instrument input: {source}/{label}\r\n\u2603"
            rows.append({"source": source, "prompt_adversarial": label, "prompt_harmful": 0,
                         "prompt": prompt, "input_sha256": holdout.digest(prompt.encode()),
                         "language": "en", "prompt_type": "test", "attack_technique": ""})
        return plan, rows

    def freeze(self, root, plan, rows):
        path = root / "rows.json"
        holdout.save(path, rows)
        out = root / "frozen"
        with contextlib.redirect_stdout(io.StringIO()):
            holdout.freeze(plan, path, out)
        return out

    def test_bytes_labels_and_integrity_survive_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            plan, rows = self.setup_plan(root)
            out = self.freeze(root, plan, rows)
            manifest = [json.loads(line) for line in (out / "captures.jsonl").read_text().splitlines()]
            by_hash = {row["input_sha256"]: row for row in rows}
            self.assertEqual(len(manifest), 6)
            for row in manifest:
                original = by_hash[row["input_sha256"]]
                self.assertEqual((out / row["input_path"]).read_bytes(), original["prompt"].encode())
                self.assertEqual(row["label"], "injection" if original["prompt_adversarial"] else "benign")
            identity = holdout.digest((out / "freeze.json").read_bytes())
            with contextlib.redirect_stdout(io.StringIO()):
                holdout.check(out, identity)
            with self.assertRaises(FileExistsError):
                self.freeze(root, plan, rows)
            (out / manifest[0]["input_path"]).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                holdout.check(out, identity)

    def test_invalid_candidates_fail_before_writing_output(self):
        for mutation in ("hash", "exposed", "normalized", "short", "label", "plan"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                plan, rows = self.setup_plan(root)
                if mutation == "hash":
                    rows[0]["input_sha256"] = "a" * 64
                elif mutation in ("exposed", "normalized"):
                    rows[0]["prompt"] = "Already\nSEEN" if mutation == "exposed" else "  ALREADY seen  "
                    rows[0]["input_sha256"] = holdout.digest(rows[0]["prompt"].encode())
                elif mutation == "short":
                    rows.pop()
                elif mutation == "label":
                    rows[0]["prompt_harmful"] = 1
                elif mutation == "plan":
                    (plan / "select.sql").write_text("changed")
                with self.assertRaises(ValueError):
                    self.freeze(root, plan, rows)
                self.assertFalse((root / "frozen").exists())


if __name__ == "__main__":
    unittest.main()
