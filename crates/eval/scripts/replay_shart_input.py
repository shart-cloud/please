#!/usr/bin/env python3
"""Replay frozen captures through shart.platform's original /scan-input function, offline.

Requires the lab's Python dependencies, a populated HF_HOME, and an existing label-freeze.json.
Writes a NEW output directory. No HTTP server, model download, or production mutation.
See docs/research/lab-replay-shart-2026-09-10.md for the measured environment.
"""
import argparse
import asyncio
import hashlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import tomllib


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', type=Path, required=True)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root = args.cases.resolve().parent
    frozen = json.loads((root / 'label-freeze.json').read_text())
    if digest(args.cases) != frozen['captures_sha256']:
        raise ValueError('capture labels changed after freeze')
    cases = [json.loads(line) for line in args.cases.read_text().splitlines() if line.strip()]
    inputs = []
    for case in cases:
        path = root / case['input_path']
        if digest(path) != case['input_sha256']:
            raise ValueError(f"{case['id']}: altered capture")
        if case['source'] != 'untrusted_user_input' or case['control_role'] != 'user':
            raise ValueError('this adapter only replays untrusted user input as UserMessage')
        content = path.read_bytes().decode('utf-8')
        if len(json.dumps({'text': content}).encode()) > 64 * 1024:
            raise ValueError('request exceeds original endpoint body cap')
        inputs.append(content)

    for key in ('HF_HUB_OFFLINE', 'TRANSFORMERS_OFFLINE', 'HF_HUB_DISABLE_TELEMETRY'):
        os.environ[key] = '1'
    sys.dont_write_bytecode = True
    # Defense in depth: imports and inference cannot connect to any network socket.
    def no_network(event, _args):
        if event in ('socket.connect', 'socket.getaddrinfo', 'socket.sendto'):
            raise RuntimeError('network disabled for offline replay')
    sys.addaudithook(no_network)

    catalog = tomllib.loads((Path(__file__).resolve().parents[1] / 'corpus/models.toml').read_text())
    model = next(m for m in catalog['model'] if m['id'] == 'prompt-guard-2-86m')
    model_dir = Path(os.environ['HF_HOME']) / model['repo'].replace('/', '--')
    for entry in model['file']:
        if digest(model_dir / entry['path']) != entry['sha256']:
            raise ValueError(f"model hash mismatch: {entry['path']}")

    lab_source = args.lab.resolve() / 'lab-worker/llamafirewall'
    sys.path.insert(0, str(lab_source))
    import torch
    import server
    from llamafirewall.scanners.prompt_guard_scanner import PromptGuardScanner
    from wulf_scanners import WulfRegexScanner

    torch.set_num_threads(2)
    start = time.monotonic()
    server.prompt_guard = PromptGuardScanner()
    server.wulf_regex = WulfRegexScanner()
    init_ms = (time.monotonic() - start) * 1000
    if str(server.prompt_guard.pg.device) != 'cpu':
        raise ValueError('this measured configuration requires CPU inference')
    sources = [lab_source / 'server.py', lab_source / 'wulf_scanners.py',
               Path(inspect.getfile(PromptGuardScanner)),
               Path(inspect.getfile(type(server.prompt_guard.pg))),
               Path(inspect.getfile(WulfRegexScanner.__bases__[0]))]
    config = dict(
        endpoint='/scan-input', role_mapping='UserMessage(content=user_prompt)',
        prompt_guard_threshold=server.prompt_guard.block_threshold,
        aggregation='block if either scanner blocks; highest-score blocker supplies headline',
        model_repo=model['repo'], model_revision=model['revision'], model_files=model['file'],
        device='cpu', torch_threads=2, preprocess=True, max_tokens=512, temperature=1.0,
        source_sha256={p.name: digest(p) for p in sources},
        packages={p: importlib.metadata.version(p) for p in
                  ['llamafirewall', 'torch', 'transformers', 'tokenizers', 'huggingface-hub', 'fastapi']},
    )
    revision = subprocess.check_output(['git', '-C', str(args.lab), 'rev-parse', 'HEAD'], text=True).strip()
    scanner = dict(name='shart.platform input: PromptGuard2 + WulfRegex', version=revision, configuration=config)
    args.out.mkdir(exist_ok=False)
    (args.out / 'environment.json').write_text(json.dumps(dict(
        scanner=scanner, initialization_ms=init_ms, adapter_sha256=digest(Path(__file__)),
        captures_sha256=digest(args.cases), python=sys.version,
        installed_packages=sorted(f'{d.metadata["Name"]}=={d.version}' for d in importlib.metadata.distributions()),
    ), indent=2) + '\n')

    async def run():
        with (args.out / 'baseline.jsonl').open('x') as normalized, (args.out / 'raw.jsonl').open('x') as raw:
            for case, content in zip(cases, inputs):
                pg = server.prompt_guard.pg
                processed = pg._preprocess_text_for_promptguard(content)
                tokens = len(pg.tokenizer(processed, truncation=False)['input_ids'])
                response = (await server.scan_input(server.ScanRequest(text=content))).model_dump()
                errors = [f'{name}: {v["error"]}' for name, v in response['scanner_breakdown'].items() if v['error']]
                incomplete = bool(errors) or tokens > 512
                reasons = [f'{name}: {v["decision"]}; score={v["score"]}; {v["reason"]}'
                           for name, v in response['scanner_breakdown'].items()]
                decision = response['decision']
                if errors or (incomplete and decision == 'allow'):
                    reasons.append(f'original endpoint decision: {decision}')
                    decision = 'review'
                if tokens > 512:
                    reasons.append(f'PromptGuard truncated {tokens} tokens to 512')
                row = {k: case[k] for k in ('id', 'input_sha256', 'source', 'control_role')}
                row.update(scanner=scanner, decision=decision, reasons=reasons, incomplete=incomplete,
                           error='; '.join(errors) if errors else None)
                normalized.write(json.dumps(row) + '\n'); normalized.flush()
                raw.write(json.dumps(dict(id=case['id'], preprocessed_tokens=tokens, response=response)) + '\n'); raw.flush()
                print(case['id'], decision, 'tokens', tokens, flush=True)
    asyncio.run(run())


if __name__ == '__main__':
    main()
