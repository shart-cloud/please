"""Paired native replay. Local frozen inputs only; never overwrites run evidence.

Usage: python3 role_marker_follow_up.py ROOT BASELINE_BINARY CANDIDATE_BINARY
Run from the repository root. ROOT must contain preserved.json from the initial
snapshot. Output contains row IDs and findings, never upstream prompt bytes.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_rows(path):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    indexed = {row['id']: row for row in rows}
    assert len(indexed) == len(rows), path
    return indexed


def counts(rows):
    return dict(rows=len(rows), detected=sum(r['detected'] for r in rows.values()),
                incomplete=sum(bool(r.get('incomplete')) for r in rows.values()),
                gap_causes=dict(collections.Counter(c for r in rows.values() for c in r.get('incomplete', []))))


def compare(old, new):
    assert old.keys() == new.keys()
    added_findings, lost_findings, added_causes, lost_causes = [], [], [], []
    for key in old:
        for before, after, added, lost in [('reasons', 'reasons', added_findings, lost_findings),
                                          ('incomplete', 'incomplete', added_causes, lost_causes)]:
            a = collections.Counter(json.dumps(v, sort_keys=True) for v in old[key].get(before, []))
            b = collections.Counter(json.dumps(v, sort_keys=True) for v in new[key].get(after, []))
            for target, delta in [(added, b-a), (lost, a-b)]:
                target.extend({'id': key, 'value': json.loads(value), 'count': n} for value, n in delta.items())
    return dict(baseline=counts(old), candidate=counts(new),
                added_detections=[k for k in old if new[k]['detected'] and not old[k]['detected']],
                lost_detections=[k for k in old if old[k]['detected'] and not new[k]['detected']],
                newly_incomplete=[k for k in old if new[k].get('incomplete') and not old[k].get('incomplete')],
                resolved_incomplete=[k for k in old if old[k].get('incomplete') and not new[k].get('incomplete')],
                added_findings=added_findings, lost_findings=lost_findings,
                added_gap_causes=added_causes, lost_gap_causes=lost_causes)


def main():
    root = Path(sys.argv[1]).resolve()
    binaries = dict(zip(['baseline', 'candidate'], map(lambda p: Path(p).resolve(), sys.argv[2:4])))
    assert len(binaries) == 2
    prior = Path('.cache/detection-improvement-20260914')
    review = Path('.cache/detection-review-response-20260914')
    packages = {'development': prior/'development.json', 'exposed-validation': prior/'validation/corpus.json',
                'three-gaps': review/'role-marker-inputs.json'}
    # These new labels describe syntax and ordinary prose, not task authorization.
    fixture = Path('crates/core/tests/data/role_marker_controls.jsonl')
    controls = [json.loads(line) for line in fixture.read_text().splitlines()]
    frozen = json.loads(packages['development'].read_text())
    corpus = frozen['corpus']
    corpus['excluded_source'] = []
    corpus['slice'] = []
    rows = {}
    for expected, name in [(True, 'role_syntax'), (False, 'role_prose')]:
        corpus['slice'].append(dict(id=name, kind='positive' if expected else 'negative', label=name,
                                   origin={'kind': 'query', 'sql': 'SELECT * FROM first_party_controls'},
                                   gate_eligible=not expected, excluded_sources=[], baseline_permille=None,
                                   notes='Codex-authored development mechanism controls; no independent review.'))
        rows[name] = [dict(id=r['id'], text=r['text'], source='first-party-role-controls', language='en')
                      for r in controls if r['expected_role'] == expected]
    packages['fresh-controls'] = root/'fresh-controls.json'
    save(packages['fresh-controls'], {'corpus': corpus, 'rows': rows})
    save(root/'identities.json', dict(binaries={k: digest(v) for k,v in binaries.items()},
                                    packages={k: {'path': str(v), 'sha256': digest(v)} for k,v in packages.items()},
                                    controls_sha256=digest(fixture)))
    env = {**os.environ, 'PLEASE_EVAL_CACHE': str(root/'eval-cache')}
    timings = []
    for name, package in packages.items():
        slices = list(json.loads(package.read_text())['rows'])
        orders = [['baseline','candidate'], ['candidate','baseline'], ['baseline','candidate']] if name == 'development' else [['baseline','candidate']]
        for trial, order in enumerate(orders, 1):
            for version in order:
                label = f'{version}-{name}-{trial}'
                cmd = [str(binaries[version]), 'run', str(package), digest(package), label, 'high', *slices]
                log = root/f'{label}.log'
                start = time.perf_counter()
                with log.open('x') as stream:
                    subprocess.run(cmd, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
                elapsed = time.perf_counter()-start
                timings.append(dict(package=name, trial=trial, version=version, seconds=elapsed,
                                    slice_seconds={k:float(v) for k,v in re.findall(r'^([a-z_]+): \d+/\d+; ([0-9.]+)s$', log.read_text(), re.M)}))
                print(label, round(elapsed,3), flush=True)
    save(root/'timings.json', timings)
    summary = {'mode': 'product/enforcement/high; structural; unspecified provenance', 'packages': {}}
    results = root/'eval-cache/results'
    for name, package in packages.items():
        summary['packages'][name] = {}
        for slice_id in json.loads(package.read_text())['rows']:
            old = read_rows(results/f'baseline-{name}-1'/f'{slice_id}.jsonl')
            new = read_rows(results/f'candidate-{name}-1'/f'{slice_id}.jsonl')
            summary['packages'][name][slice_id] = compare(old,new)
            if name == 'development':
                for trial in [2,3]:
                    assert old == read_rows(results/f'baseline-{name}-{trial}'/f'{slice_id}.jsonl')
                    assert new == read_rows(results/f'candidate-{name}-{trial}'/f'{slice_id}.jsonl')
    summary['performance'] = {}
    for version in binaries:
        trials = [t for t in timings if t['package']=='development' and t['version']==version]
        summary['performance'][version] = {'total_median_seconds': statistics.median(t['seconds'] for t in trials),
            'slice_median_seconds': {s: statistics.median(t['slice_seconds'][s] for t in trials) for s in trials[0]['slice_seconds']}}
    summary['performance']['change_percent'] = (summary['performance']['candidate']['total_median_seconds']/summary['performance']['baseline']['total_median_seconds']-1)*100
    # Preserve the exact historical row-level outcomes, including the three gaps.
    for version, historical in [('baseline','baseline-high-01'), ('candidate','e1-full-01')]:
        previous = read_rows(prior/'eval-cache/results'/historical/'pos_llmail.jsonl')
        current = read_rows(results/f'{version}-development-1/pos_llmail.jsonl')
        assert previous == current, f'{version} LLMail historical replay differs'
        three = read_rows(results/f'{version}-three-gaps-1/pos_llmail.jsonl')
        assert all(current[k] == v for k,v in three.items())
    summary['historical_llmail_native_rows_identical'] = True
    preserved = json.loads((root/'preserved.json').read_text())
    for path, expected in preserved.items():
        if path == 'rules/builtin.toml':
            assert digest(root/'baseline.toml') == expected
        else:
            assert digest(Path(path)) == expected, path
    summary['preserved_artifacts_verified'] = len(preserved)
    save(root/'summary.json', summary)
    for name, slices in summary['packages'].items():
        for s,d in slices.items():
            print(name,s,d['baseline']['detected'],'->',d['candidate']['detected'],
                  'lost',len(d['lost_detections']),'new gaps',len(d['newly_incomplete']), flush=True)


if __name__ == '__main__':
    main()
