"""Derive research claims from native rows verified by please-eval's run module.

Completion checks stay in the native verifier. Python additionally binds the bytes
it counts to that completion record and checks input identities and paired deltas.
These checks establish consistency, not authenticity against an attacker who can
replace all inputs, manifests, executables, and results together.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from role_marker_follow_up import compare, counts


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verified_run(directory, evaluator):
    directory = Path(directory).resolve()
    manifest_bytes = (directory/'run.json').read_bytes()
    result = subprocess.run(
        [str(Path(evaluator).resolve()), 'report', '--run', directory.name, '--format', 'json'],
        env={**os.environ, 'PLEASE_EVAL_CACHE': str(directory.parent.parent)},
        capture_output=True, text=True, check=True,
    )
    report = json.loads(result.stdout)
    require(report['integrity']['status'] == 'complete',
            f'{directory.name}: native run verification failed: {report["integrity"]}')
    require(manifest_bytes == (directory/'run.json').read_bytes(),
            f'{directory.name}: run manifest changed during verification')
    manifest = json.loads(manifest_bytes)
    completion = manifest['completion']
    metrics = {m['slice']: m for m in report['slices']}
    require(set(metrics) == set(completion['results']), f'{directory.name}: report selection differs')
    rows, files = {}, {'run.json': sha256(manifest_bytes)}
    for sid, saved in completion['results'].items():
        content = (directory/f'{sid}.jsonl').read_bytes()
        require(sha256(content) == saved['sha256'], f'{directory.name}/{sid}: result checksum mismatch')
        data = [json.loads(line) for line in content.splitlines()]
        indexed = {row['id']: row for row in data}
        require(len(data) == saved['rows'] == len(indexed),
                f'{directory.name}/{sid}: row count or duplicate ID mismatch')
        measured = counts(indexed)
        require((measured['rows'], measured['detected'], measured['incomplete']) ==
                (metrics[sid]['total']['n'], metrics[sid]['total']['hits'], metrics[sid]['incomplete_rows']),
                f'{directory.name}/{sid}: native/Python count mismatch')
        rows[sid] = indexed
        files[f'{sid}.jsonl'] = sha256(content)
    return rows, manifest, files


def recompute_packages(root, packages, evaluator):
    """packages maps names to checksum-verified frozen input objects and their hashes."""
    root = Path(root)
    derived, verified, first_runs = {}, {}, {}
    pipeline_by_version = {}
    for name, (package, input_hash) in packages.items():
        paired = {}
        for version in ['baseline', 'candidate']:
            first = None
            for trial in ([1, 2, 3] if name == 'development' else [1]):
                label = f'{version}-{name}-{trial}'
                directory = root/'eval-cache/results'/label
                data, manifest, files = verified_run(directory, evaluator)
                input_bytes = (directory/'input-sha256.txt').read_bytes()
                require(input_bytes.decode().strip() == input_hash, f'{label}: frozen input identity mismatch')
                require(manifest['completion']['corpus'] == package['corpus'], f'{label}: frozen selection mismatch')
                require(set(data) == set(package['rows']), f'{label}: input/result slices differ')
                for sid, inputs in package['rows'].items():
                    ids = {r['id'] for r in inputs}
                    require(len(ids) == len(inputs) and ids == set(data[sid]), f'{label}/{sid}: input/result IDs differ')
                    require(all(data[sid][r['id']]['source'] == r['source'] for r in inputs),
                            f'{label}/{sid}: input/result sources differ')
                pipeline = {k:v for k,v in manifest.items() if k != 'completion'}
                require(pipeline['mode'] == 'product' and pipeline['ruleset'] == 'builtin' and
                        pipeline['policy']['profile'] == 'enforcement' and pipeline['policy']['threshold'] == 'high' and
                        pipeline['policy']['provenance'] == 'unspecified' and pipeline['tiers'] == {},
                        f'{label}: unexpected measurement mode')
                require(pipeline_by_version.setdefault(version, pipeline) == pipeline,
                        f'{label}: pipeline differs between runs')
                if first is None:
                    first = data
                else:
                    require(first == data, f'{label}: repeat native results differ')
                files['input-sha256.txt'] = sha256(input_bytes)
                verified[label] = files
            paired[version] = first
        derived[name] = {sid:compare(paired['baseline'][sid], paired['candidate'][sid]) for sid in package['rows']}
        first_runs[name] = paired
    if packages:
        require({k:v for k,v in pipeline_by_version['baseline'].items() if k != 'ruleset_digest'} ==
                {k:v for k,v in pipeline_by_version['candidate'].items() if k != 'ruleset_digest'},
                'paired pipeline configuration differs beyond ruleset identity')
    return derived, verified, first_runs


def check_claimed_packages(claimed, derived):
    require(set(claimed) == set(derived), 'summary package selection differs from native results')
    for name, slices in derived.items():
        require(set(claimed[name]) == set(slices), f'summary slice selection differs: {name}')
        for sid, delta in slices.items():
            require(claimed[name][sid] == delta, f'summary disagrees with verified native results: {name}/{sid}')
