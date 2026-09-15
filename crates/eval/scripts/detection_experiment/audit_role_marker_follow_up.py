"""Audit a completed replay and write a compact, prompt-free research record.

Usage: python3 audit_role_marker_follow_up.py ROOT OUTPUT.json [--evaluator PATH]
Build please-eval first. Its native run verifier checks saved-run completeness;
this audit recomputes counts/deltas from verified bytes and rejects stale summaries.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import statistics
import tomllib

from verified_role_marker_results import (check_claimed_packages, recompute_packages,
                                         require, verified_run)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--evaluator', type=Path,
                        default=Path(__file__).resolve().parents[2]/'target/release/please-eval')
    args = parser.parse_args()
    root, output = args.root, args.output
    summary = json.loads((root/'summary.json').read_text())
    identities = json.loads((root/'identities.json').read_text())
    packages = {}
    for name, identity in identities['packages'].items():
        # The fresh-control package belongs to this evidence root, including isolated copies.
        path = root/'fresh-controls.json' if name == 'fresh-controls' else Path(identity['path'])
        content = path.read_bytes()
        require(hashlib.sha256(content).hexdigest() == identity['sha256'], f'{name}: input package checksum mismatch')
        packages[name] = (json.loads(content), identity['sha256'])
    native, verified, first_runs = recompute_packages(root, packages, args.evaluator)
    check_claimed_packages(summary['packages'], native)
    summary['packages'] = native  # All downstream counts and differences come from verified rows.
    require(summary['mode'] == 'product/enforcement/high; structural; unspecified provenance', 'summary mode mismatch')
    prior = Path('.cache/detection-improvement-20260914')
    for version, historical in [('baseline','baseline-high-01'), ('candidate','e1-full-01')]:
        old_rows, _, files = verified_run(prior/'eval-cache/results'/historical, args.evaluator)
        current = first_runs['development'][version]['pos_llmail']
        require(old_rows['pos_llmail'] == current, f'{version}: historical LLMail results differ')
        require(all(current[k] == row for k,row in first_runs['three-gaps'][version]['pos_llmail'].items()),
                f'{version}: three-gap replay differs from full run')
        verified[f'historical/{historical}'] = files
    require(summary['historical_llmail_native_rows_identical'] is True, 'historical replay summary mismatch')
    preserved = json.loads((root/'preserved.json').read_text())
    for name, expected in preserved.items():
        path = root/'baseline.toml' if name == 'rules/builtin.toml' else Path(name)
        require(digest(path) == expected, f'preserved artifact changed: {name}')
    require(summary['preserved_artifacts_verified'] == len(preserved), 'preservation count mismatch')
    timings = json.loads((root/'timings.json').read_text())
    performance = {}
    for version in ['baseline','candidate']:
        trials = [t for t in timings if t['package']=='development' and t['version']==version]
        require(len(trials)==3 and {t['trial'] for t in trials}=={1,2,3}, 'missing or duplicate timing trial')
        require(all(set(t['slice_seconds'])==set(native['development']) for t in trials), 'timing slices differ')
        performance[version] = {'total_median_seconds':statistics.median(t['seconds'] for t in trials),
                               'slice_median_seconds':{s:statistics.median(t['slice_seconds'][s] for t in trials) for s in native['development']}}
    performance['change_percent'] = (performance['candidate']['total_median_seconds']/performance['baseline']['total_median_seconds']-1)*100
    require(summary['performance'] == performance, 'summary timing medians disagree with recorded samples')
    diagnostics = [json.loads(line) for line in (root/'all-gap-diagnostic-v2.jsonl').read_text().splitlines()]
    costs = [json.loads(line) for line in (root/'matcher-cost.jsonl').read_text().splitlines()]
    gap_ids = {g['id'] for g in summary['packages']['development']['pos_llmail']['added_gap_causes']}
    require(len(diagnostics) == len(gap_ids) == 6, 'expected six gap diagnostic rows')
    require({row['id'] for row in diagnostics} == gap_ids, 'diagnostic IDs differ from native gaps')
    require(len(costs) == 9, 'missing matcher-cost measurements')
    old = tomllib.loads((root/'baseline.toml').read_text())
    new = tomllib.loads((root/'candidate.toml').read_text())
    role = next(rule for rule in new['rule'] if rule['id']=='boundary.forged_role_marker')
    require(role['literals'] == ['system','assistant'], 'candidate literals differ from accepted patch')
    role['literals'] = next(rule for rule in old['rule'] if rule['id']==role['id'])['literals']
    require(old == new, 'change beyond the role literal gate')
    for row in diagnostics:
        before = collections.Counter(json.dumps(g,sort_keys=True) for g in row['baseline']['gaps'])
        after = collections.Counter(json.dumps(g,sort_keys=True) for g in row['candidate']['gaps'])
        require(not before-after, 'diagnostic lost existing gap details')
        added = after-before
        require(sum(added.values()) == sum(g['count'] for g in native['development']['pos_llmail']['added_gap_causes'] if g['id']==row['id']), 'diagnostic/native gap count differs')
        for gap in added:
            require(json.loads(gap) == {'cause':'max_matches_per_rule', 'configured':16,
                                       'detail':'rule `boundary.forged_role_marker` saturated'}, 'unexpected gap cause or bound')
        require(row['baseline']['score'] == row['candidate']['score'], 'gap-row score changed')
        require(not row['original_prefilter_admits'] and row['corrected_prefilter_admits'], 'diagnostic gate mismatch')
    expected_ids = {'3096a57c528bea49','d2ac22d03a13dd9b','de487116dcd21af2'}
    require(set(native['development']['pos_llmail']['newly_incomplete']) == expected_ids, 'newly incomplete rows differ from accepted exception')
    corpus = packages['development'][0]['rows']
    require(set(native) == {'development','exposed-validation','three-gaps','fresh-controls'}, 'missing evidence package')
    require(set(native['development']) == set(corpus), 'development selection differs')
    require(set(native['exposed-validation']) == {'validation_positive','validation_benign'}, 'validation selection differs')
    require(set(native['fresh-controls']) == {'role_syntax','role_prose'}, 'fresh-control selection differs')
    for sid, rows in corpus.items():
        delta = summary['packages']['development'][sid]
        require(delta['baseline']['rows'] == delta['candidate']['rows'] == len(rows), 'native/input row count differs')
    llmail_texts = {row['text'] for row in corpus['pos_llmail']}
    record = {'status':'accepted and enabled; documented saturation exception passes; original zero-increase criterion still fails',
              'acceptance': {'date':'2026-09-15', 'authority':'user', 'statement':'i accept them',
                             'scope':'This measured patch: exactly three newly incomplete LLMail rows and seven added role-rule saturation records across six rows, with unchanged limits, no lost findings, and no added benign findings in evaluated controls.'},
              'mode':summary['mode'], 'authorship':'Fresh controls authored by Codex on 2026-09-15; no independent label review; mechanism evidence, not unseen-family validation.',
              'packages':{}, 'performance':performance, 'matcher_cost':costs, 'gap_diagnostics':diagnostics,
              'only_rule_semantic_change':'boundary.forged_role_marker literals',
              'historical_llmail_native_rows_identical':True,
              'preserved_artifacts_verified':len(preserved),
              'verification':{'method':'please-eval native saved-run verification, followed by byte-bound row counts and differences; supplied summary must agree',
                              'evaluator_sha256':digest(args.evaluator), 'native_run_files':verified},
              'evidence':{}}
    for name, slices in summary['packages'].items():
        record['packages'][name] = {}
        for sid, delta in slices.items():
            require(not delta['lost_detections'] and not delta['lost_findings'] and not delta['lost_gap_causes'], f'{name}/{sid}: lost detection, finding, or gap')
            if name != 'three-gaps' and sid != 'pos_llmail':
                require(not delta['newly_incomplete'] and not delta['added_gap_causes'], f'{name}/{sid}: unaccepted additional gap')
            if sid.startswith('neg_') or sid in ['fix_benign','gen_matched_negative','repo_prose','validation_benign','role_prose']:
                require(not delta['added_detections'] and not delta['added_findings'], f'{name}/{sid}: added benign finding')
            record['packages'][name][sid] = {
                **{k:delta[k] for k in ['baseline','candidate','newly_incomplete','resolved_incomplete']},
                **{k:sum(v['count'] for v in delta[k]) if k.endswith('findings') or k.endswith('gap_causes') else len(delta[k])
                   for k in ['added_detections','lost_detections','added_findings','lost_findings','added_gap_causes','lost_gap_causes']}}
            if name == 'development' and sid in ['pos_obfuscation','pos_stratified']:
                added = [r for r in corpus[sid] if r['id'] in delta['added_detections']]
                record['packages'][name][sid]['added_exact_llmail_duplicates'] = sum(r['text'] in llmail_texts for r in added)
    for name in ['summary.json','timings.json','identities.json','preserved.json','diagnostic.jsonl',
                 'all-gap-inputs.json','all-gap-diagnostic-v2.jsonl','matcher-cost.jsonl','baseline.toml','candidate.toml']:
        path = root/name
        record['evidence'][name] = {'path':str(path),'sha256':digest(path)}
    with output.open('x') as stream:
        json.dump(record,stream,indent=2)
        stream.write('\n')
    print('Audited: no lost native findings, no new benign findings; exactly three newly incomplete rows, seven role saturation records across six rows.')


if __name__ == '__main__':
    main()
