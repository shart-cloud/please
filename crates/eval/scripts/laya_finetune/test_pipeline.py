import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load("prepare_data")
train = load("train_laya")


class PrepareDataTests(unittest.TestCase):
    def row(self, text, label, dataset="example/data", split="train"):
        item = prepare.canonical_row(
            text=text, label=label, dataset=dataset, revision="abc", source="source",
            split=split, license_name="mit",
        )
        item["purpose"] = "train"
        return item

    def test_stable_bucket(self):
        self.assertEqual(prepare.stable_bucket("same"), prepare.stable_bucket("same"))
        self.assertGreaterEqual(prepare.stable_bucket("same"), 0)
        self.assertLess(prepare.stable_bucket("same"), 100)

    def test_normalized_duplicate_and_conflict(self):
        duplicate_a = self.row(" Ignore   instructions ", 1, "a/data")
        duplicate_b = self.row("ignore instructions", 1, "b/data")
        conflict_a = self.row("Safe text", 0, "a/data")
        conflict_b = self.row(" SAFE TEXT ", 1, "b/data")
        kept, skipped = prepare.globally_deduplicate(
            [duplicate_a, duplicate_b, conflict_a, conflict_b], set()
        )
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(kept[0]["origins"]), 2)
        self.assertEqual(skipped["normalized_duplicate"], 1)
        self.assertEqual(skipped["conflicting_normalized_label"], 2)

    def test_external_eval_wins_duplicate(self):
        training = self.row("duplicate", 1, "a/data")
        evaluation = self.row(" duplicate ", 1, "b/data", "test")
        evaluation["purpose"] = "external_eval"
        kept, _ = prepare.globally_deduplicate([training, evaluation], set())
        self.assertEqual(kept[0]["purpose"], "external_eval")
        self.assertEqual(prepare.assign_split(kept[0]), "external_eval")

    def test_exposed_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "crates/eval/manifests/sample.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"sha256": "a" * 64}) + "\n")
            self.assertEqual(prepare.exposed_hashes(root), {"a" * 64})


class MetricTests(unittest.TestCase):
    def test_binary_metrics(self):
        result = train.binary_metrics([0.9, 0.8, 0.2, 0.1], [1, 0, 1, 0])
        self.assertEqual(result["confusion"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertEqual(result["accuracy"], 0.5)
        self.assertEqual(result["false_positive_rate"], 0.5)

    def test_temperature_uses_injection_option_zero(self):
        self.assertEqual(train.binary_option_labels([1, 0]).tolist(), [0, 1])


if __name__ == "__main__":
    unittest.main()
