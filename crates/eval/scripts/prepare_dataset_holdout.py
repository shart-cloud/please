#!/usr/bin/env python3
"""Plan and freeze an upstream-labeled direct-prompt holdout. Never invokes a detector.

plan writes a pinned Hugging Face SQL query and an exposure index. Run that query with `hf datasets
sql` separately; freeze validates its JSON output and packages exact UTF-8 bytes for offline replay.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import unicodedata

DATASET = "Necent/llm-jailbreak-prompt-injection-dataset"
REVISION = "4edfb5aeaafe58c9bf489a478a42188f239d7c1e"
STRATA = [("Gandalf-Ignore", 1), ("safe-guard-PI", 1), ("safe-guard-PI", 0),
          ("jayavibhav-PI", 1), ("jayavibhav-PI", 0), ("OR-Bench", 0)]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def normalized(text):
    return digest(" ".join(unicodedata.normalize("NFKC", text).casefold().split()).encode())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def json_records(path):
    # Some legacy exports contain literal newlines inside JSON strings. Preserve those characters
    # rather than splitting their records into invalid lines and silently losing exclusion hashes.
    text = path.read_text()
    decoder = json.JSONDecoder(strict=False)
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            return
        if text[offset] == "#":
            newline = text.find("\n", offset)
            offset = len(text) if newline < 0 else newline + 1
            continue
        value, offset = decoder.raw_decode(text, offset)
        yield value


def exposure(paths):
    exact, folded, sources = set(), set(), []

    def visit(value):
        if isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key in ("sha256", "input_sha256") and isinstance(item, str):
                    if len(item) != 64 or any(c not in "0123456789abcdef" for c in item):
                        raise ValueError("invalid historical SHA-256")
                    exact.add(item)
                if key in ("prompt", "text", "user_prompt") and isinstance(item, str):
                    exact.add(digest(item.encode()))
                    folded.add(normalized(item))
                if isinstance(item, (dict, list)):
                    visit(item)

    for path in sorted(set(paths)):
        raw = path.read_bytes()
        sources.append({"path": str(path.resolve()), "sha256": digest(raw)})
        for value in json_records(path):
            visit(value)
    return exact, folded, sources


def plan(repo, cache, out, per_stratum):
    if per_stratum < 1:
        raise ValueError("per-stratum must be positive")
    paths = (list((repo / "crates/eval/manifests").glob("*.jsonl"))
             + list((repo / "tests/fixtures").rglob("*.jsonl"))
             + list(cache.glob("*.jsonl")) + list((cache / "slices").glob("*.jsonl")))
    for relative in (".cache/lab-replay/shart-ai-20260910/history-candidates.json",
                     ".cache/lab-replay/shart-ai-20260910/captures.jsonl"):
        path = repo / relative
        if path.is_file():
            paths.append(path)
    exact, folded, sources = exposure(paths)
    if not exact or not folded:
        raise ValueError("exposure history is empty or has no text for normalized comparisons")
    out.mkdir(mode=0o700)
    csv = "sha256\n" + "\n".join(sorted(exact)) + "\n"
    (out / "exposed.csv").write_text(csv)
    save(out / "normalized-exposed.json", sorted(folded))
    save(out / "exposure-inventory.json", sources)
    exclusions = str((out / "exposed.csv").resolve()).replace("'", "''")
    predicates = " OR ".join(f"(source = '{source}' AND prompt_adversarial = {label})"
                             for source, label in STRATA)
    # Reject exact duplicates with conflicting adversarial labels even when a conflicting row is
    # outside the selected sources. Deduplicate across sources before the stratified limit.
    sql = f"""WITH all_rows AS (
  SELECT sha256(prompt) AS input_sha256, prompt, source, language, prompt_type,
         prompt_adversarial, prompt_harmful, coalesce(attack_technique, '') AS attack_technique,
         min(prompt_adversarial) OVER (PARTITION BY sha256(prompt)) AS min_label,
         max(prompt_adversarial) OVER (PARTITION BY sha256(prompt)) AS max_label
  FROM 'hf://datasets/{DATASET}@{REVISION}/**/*.parquet'
  WHERE prompt IS NOT NULL
), eligible AS (
  SELECT * EXCLUDE (min_label, max_label) FROM all_rows
  WHERE min_label = max_label AND prompt_harmful = 0 AND ({predicates})
    AND input_sha256 NOT IN (SELECT sha256 FROM read_csv('{exclusions}', header=true))
  QUALIFY row_number() OVER (PARTITION BY input_sha256 ORDER BY source, language, prompt_type) = 1
)
SELECT * FROM eligible
QUALIFY row_number() OVER (PARTITION BY source, prompt_adversarial ORDER BY input_sha256) <= {per_stratum * 4}
ORDER BY input_sha256
"""
    (out / "select.sql").write_text(sql)
    metadata = {
        "format_version": 1, "dataset": DATASET, "revision": REVISION,
        "strata": [{"source": source, "prompt_adversarial": label, "count": per_stratum}
                   for source, label in STRATA],
        "selection": "ascending exact content SHA-256 after exposure/label-conflict exclusions; fourfold overfetch for normalized deduplication",
        "source_policy": "untrusted_user_input", "control_role": "user",
        "label_authority": "upstream prompt_adversarial; prompt_harmful must be zero",
        "owner_review": "not performed; not required to inherit benchmark labels",
        "exact_exposure_hashes": len(exact), "normalized_exposure_hashes": len(folded),
        "files": {name: digest((out / name).read_bytes()) for name in
                  ("exposed.csv", "normalized-exposed.json", "exposure-inventory.json", "select.sql")},
        "limitations": ["Direct-prompt benchmark only; no tool-response or security-reference coverage.",
                        "Disjoint from indexed local evaluations, not guaranteed absent from model training.",
                        "Normalization is NFKC/case/whitespace; semantic paraphrases may still overlap.",
                        "Labels do not establish application-specific export authorization."]
    }
    save(out / "plan.json", metadata)
    print(json.dumps({"plan": str(out), "exact_exposed": len(exact), "normalized_exposed": len(folded),
                      "target_rows": len(STRATA) * per_stratum}))


def freeze(plan_dir, rows_path, out):
    metadata = json.loads((plan_dir / "plan.json").read_text())
    for name, expected in metadata["files"].items():
        if digest((plan_dir / name).read_bytes()) != expected:
            raise ValueError(f"plan artifact changed: {name}")
    exact = set((plan_dir / "exposed.csv").read_text().splitlines()[1:])
    folded = set(json.loads((plan_dir / "normalized-exposed.json").read_text()))
    limits = {(row["source"], row["prompt_adversarial"]): row["count"] for row in metadata["strata"]}
    candidates = json.loads(rows_path.read_text())
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("candidate query returned no rows")
    seen = set()
    for row in candidates:
        if digest(row["prompt"].encode()) != row["input_sha256"]:
            raise ValueError("candidate byte hash mismatch")
        if row["input_sha256"] in exact or row["input_sha256"] in seen:
            raise ValueError("candidate contains exposed or duplicate exact bytes")
        if (row["source"], row["prompt_adversarial"]) not in limits or row["prompt_harmful"] != 0:
            raise ValueError("candidate outside the declared strata/label definition")
        seen.add(row["input_sha256"])
    # Exclude normalized duplicates with conflicting labels rather than choosing one label by order.
    label_sets = collections.defaultdict(set)
    for row in candidates:
        label_sets[normalized(row["prompt"])].add(row["prompt_adversarial"])
    selected, counts, skipped = [], collections.Counter(), collections.Counter()
    for row in sorted(candidates, key=lambda row: row["input_sha256"]):
        group = normalized(row["prompt"])
        key = row["source"], row["prompt_adversarial"]
        if len(label_sets[group]) > 1:
            skipped["normalized_label_conflict"] += 1
        elif group in folded:
            skipped["normalized_exposure_or_duplicate"] += 1
        elif counts[key] >= limits[key]:
            skipped["stratum_full"] += 1
        else:
            folded.add(group)
            selected.append(row)
            counts[key] += 1
    if any(counts[key] != limit for key, limit in limits.items()):
        raise ValueError(f"insufficient fresh rows after deduplication: {dict(counts)}")
    out.mkdir(mode=0o700)
    (out / "inputs").mkdir()
    captures, provenance, file_hashes = [], [], {}
    for row in selected:
        case_id = "dataset-" + row["input_sha256"][:20]
        name = f"inputs/{case_id}.bin"
        payload = row["prompt"].encode()
        (out / name).write_bytes(payload)
        file_hashes[name] = digest(payload)
        captures.append({"id": case_id, "input_path": name, "input_sha256": row["input_sha256"],
                         "source": metadata["source_policy"], "control_role": metadata["control_role"],
                         "label": "injection" if row["prompt_adversarial"] else "benign",
                         "label_reason": f"Inherited {DATASET}@{REVISION}, source {row['source']}: prompt_adversarial={row['prompt_adversarial']}, prompt_harmful=0. Not owner-adjudicated."})
        provenance.append({"id": case_id, **{k: v for k, v in row.items() if k != "prompt"},
                           "normalized_group_sha256": normalized(row["prompt"])})
    (out / "captures.jsonl").write_text("".join(json.dumps(row) + "\n" for row in captures))
    (out / "provenance.jsonl").write_text("".join(json.dumps(row) + "\n" for row in provenance))
    # No payloads in review metadata. The query output and prior-exposure snapshot stay in plan_dir.
    save(out / "plan.json", metadata)
    for name in ("captures.jsonl", "provenance.jsonl", "plan.json"):
        file_hashes[name] = digest((out / name).read_bytes())
    identity = {
        "format_version": 1, "mode": "upstream_labeled_dataset_holdout",
        "dataset": DATASET, "revision": REVISION, "files": file_hashes,
        "plan_sha256": digest((plan_dir / "plan.json").read_bytes()),
        "candidate_export_sha256": digest(rows_path.read_bytes()),
        "preparation_script_sha256": digest(Path(__file__).read_bytes()),
        "rows": len(selected), "candidate_rows": len(candidates), "skipped": dict(skipped),
        "strata": [{"source": source, "label": "injection" if label else "benign", "rows": count}
                   for (source, label), count in sorted(counts.items())],
        "detector_run": False, "owner_reviewed": False,
        "limitations": metadata["limitations"]
    }
    save(out / "freeze.json", identity)
    print(json.dumps({"rows": len(selected), "strata": identity["strata"],
                      "freeze_sha256": digest((out / "freeze.json").read_bytes())}, indent=2))


def check(directory, expected):
    raw = (directory / "freeze.json").read_bytes()
    if digest(raw) != expected:
        raise ValueError("freeze differs from the separately retained digest")
    for name, expected_hash in json.loads(raw)["files"].items():
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("invalid frozen path")
        if digest((directory / path).read_bytes()) != expected_hash:
            raise ValueError(f"changed frozen artifact: {name}")
    print("Dataset holdout integrity verified; no detector run.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    p.add_argument("--cache", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--per-stratum", type=int, default=100)
    p = sub.add_parser("freeze")
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--rows", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("check")
    p.add_argument("--dir", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if args.command == "plan":
        plan(args.repo, args.cache, args.out, args.per_stratum)
    elif args.command == "freeze":
        freeze(args.plan, args.rows, args.out)
    else:
        check(args.dir, args.sha256)


if __name__ == "__main__":
    main()
