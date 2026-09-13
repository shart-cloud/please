#!/usr/bin/python3
"""Deterministic context-aware protocol fixture; not a production detector."""

import hashlib
import json
import sys

PROTOCOL = "please-bench-jsonl/v1"


def send(value):
    sys.stdout.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def exact_keys(value, expected):
    if set(value) != set(expected):
        raise ValueError("unexpected or missing protocol field")


def main():
    line = sys.stdin.readline()
    if not line:
        raise ValueError("missing handshake")
    hello = json.loads(line)
    exact_keys(hello, ["kind", "schema_version", "system_id", "system_digest"])
    if hello["kind"] != "handshake" or hello["schema_version"] != PROTOCOL:
        raise ValueError("invalid handshake")
    send({
        "kind": "handshake",
        "schema_version": PROTOCOL,
        "system_id": hello["system_id"],
        "system_digest": hello["system_digest"],
        "adapter_version": PROTOCOL,
    })

    for line in sys.stdin:
        request = json.loads(line)
        expected = [
            "kind", "schema_version", "request_id", "surface", "candidate_encoding",
            "candidate_hex", "candidate_sha256", "byte_length", "provenance",
        ]
        if request.get("surface") == "contextual_alignment":
            expected.append("trusted_context")
        exact_keys(request, expected)
        if request["kind"] != "case" or request["schema_version"] != PROTOCOL:
            raise ValueError("invalid case envelope")
        if request["candidate_encoding"] != "hex":
            raise ValueError("unsupported candidate encoding")
        candidate = bytes.fromhex(request["candidate_hex"])
        if len(candidate) != request["byte_length"]:
            raise ValueError("candidate length mismatch")
        if hashlib.sha256(candidate).hexdigest() != request["candidate_sha256"]:
            raise ValueError("candidate digest mismatch")

        if request["surface"] == "artifact_detection":
            folded = candidate.decode("utf-8", errors="replace").lower()
            label = "injection" if any(term in folded for term in (
                "ignore", "override", "secret", "access token", "system policy",
            )) else "benign"
        else:
            task = request["trusted_context"]["task"].lower()
            if "authorized:" in task:
                label = "aligned_instruction"
            elif "analyze" in task or "quoted example" in task:
                label = "non_instruction"
            elif not task.strip():
                label = "indeterminate"
            else:
                label = "conflicting_instruction"
        send({
            "kind": "result",
            "schema_version": PROTOCOL,
            "request_id": request["request_id"],
            "native": {
                "label": label,
                "confidence_permille": 800,
                "evidence": [],
                "diagnostics": ["deterministic instrument fixture; not an accuracy claim"],
                "abstained": False,
                "remote_requests": 0,
                "declared_cost_microusd": 0,
            },
        })


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"contextual-reference: {error}", file=sys.stderr)
        raise SystemExit(2)
