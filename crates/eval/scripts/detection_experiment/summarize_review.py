"""Audit preserved evidence and summarize native per-row review measurements."""
import collections
import hashlib
import json
from pathlib import Path

root = Path('.cache/detection-review-response-20260914')
prior = Path('.cache/detection-improvement-20260914')
results = root / 'eval-cache/results'


def read(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def rows(run, slice_id):
    return read(results / run / f'{slice_id}.jsonl')


def counts(data):
    return {'rows': len(data), 'detected': sum(r['detected'] for r in data),
            'incomplete': sum(bool(r.get('incomplete')) for r in data)}


summary = {'decision': 'withdraw both email rules from built-in defaults',
           'mode': 'product/enforcement/high; structural; unspecified provenance',
           'targeted': {}, 'reviewer': {}, 'development': {}, 'validation': {},
           'label_provenance': 'New mechanism scenarios authored and self-reviewed by Codex; no independent label review. Reviewer ten supplied as reviewer_authored; identity unspecified.'}
scenarios = read(Path('crates/core/tests/data/email_review_scenarios.jsonl'))
for version in ['baseline', 'email-candidate', 'withdrawn']:
    summary['reviewer'][version] = counts(rows(f'{version}-reviewer', 'review_authorized_email'))
    summary['targeted'][version] = {}
    for slice_id in ['authorized_transmission', 'unauthorized_tool_directive', 'explicit_override_control']:
        data = rows(f'{version}-targeted-v2', slice_id)
        by_id = {r['id']: r for r in data}
        strata = collections.defaultdict(list)
        for s in scenarios:
            if s['slice'] == slice_id:
                strata[s['variant']].append(by_id[s['id']])
        summary['targeted'][version][slice_id] = {**counts(data), 'variants': {k: counts(v) for k, v in strata.items()}}
    # Meaning-preserving changes compared with direct recipient, per object.
    auth = {r['id']: r for r in rows(f'{version}-targeted-v2', 'authorized_transmission')}
    pairs = []
    for s in scenarios:
        if s['slice'] == 'authorized_transmission' and s['variant'] != 'direct':
            direct = f"authorized_transmission-object-{s['pair'].split('-')[1]}-direct"
            pairs.append(auth[s['id']]['detected'] != auth[direct]['detected'])
    summary['targeted'][version]['wording_pairs'] = {'comparisons': len(pairs), 'verdict_flips': sum(pairs)}

for path in sorted((results / 'withdrawn-development').glob('*.jsonl')):
    data = read(path)
    baseline = prior / 'eval-cache/results/final-baseline-01' / path.name
    if not baseline.exists():
        baseline = prior / 'eval-cache/results/baseline-high-01' / path.name
    # The separate mechanism gate uses reference analysis; compare only enforcement runs.
    if not baseline.exists():
        baseline = prior / 'eval-cache/results/baseline-transfer-01' / path.name
    assert baseline.exists(), path.name
    old = read(baseline)
    assert data == old, f'Baseline behavior changed: {path.name}'
    summary['development'][path.stem] = {**counts(data), 'identical_native_rows_to': str(baseline)}
for path in sorted((results / 'withdrawn-exposed-validation').glob('*.jsonl')):
    old = prior / 'eval-cache/results/baseline-validation-01' / path.name
    assert read(path) == read(old)
    summary['validation'][path.stem] = counts(read(path))

old_rows = {r['id']: r for r in read(prior / 'eval-cache/results/baseline-high-01/pos_llmail.jsonl')}
new_rows = {r['id']: r for r in read(prior / 'eval-cache/results/e1-full-01/pos_llmail.jsonl')}
assert old_rows.keys() == new_rows.keys()
assert all(not r['detected'] or new_rows[key]['detected'] for key, r in old_rows.items())
assert all(set(r.get('incomplete', [])) <= set(new_rows[key].get('incomplete', [])) for key, r in old_rows.items())
summary['role_marker'] = {
    'baseline': counts(list(old_rows.values())), 'prefilter_candidate': counts(list(new_rows.values())),
    'added_detections': sum(new_rows[k]['detected'] and not old_rows[k]['detected'] for k in old_rows),
    'lost_detections': 0, 'old_gap_causes_preserved': True,
    'diagnostic': read(root / 'role-marker-diagnostic-v2.jsonl'),
    'new_gaps': [{'baseline': old_rows[k], 'prefilter_candidate': new_rows[k]} for k in old_rows
                 if new_rows[k].get('incomplete') and not old_rows[k].get('incomplete')],
    'status': 'separate follow-up; no acceptance-criterion change authorized; prefilter remains unchanged'}
for version, full in [('baseline', old_rows), ('e1', new_rows)]:
    assert all(row == full[row['id']] for row in rows(f'role-marker-{version}', 'pos_llmail'))

preserved = json.loads((root / 'preserved-sha256.json').read_text())
for name, expected in preserved.items():
    assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected, name
summary['preservation'] = {'files_verified_unchanged': len(preserved), 'manifest': str(root / 'preserved-sha256.json')}
summary['rules_restored_byte_identical_to_baseline'] = (
    Path('rules/builtin.toml').read_bytes() == (prior / 'baseline-source/rules/builtin.toml').read_bytes())
assert summary['rules_restored_byte_identical_to_baseline']
with (root / 'summary.json').open('x') as stream:
    json.dump(summary, stream, indent=2)
    stream.write('\n')
print(json.dumps({k: summary[k] for k in ['reviewer', 'development', 'validation', 'preservation']}, indent=2))
