"""Recompute matching claims from checksum-verified native results, then render HTML/TUI.

Usage: python3 report_matching_consistency.py ROOT [--tui] [--check REPORT.json]
No benchmark count is trusted from an existing summary. Sidecar checksums bind the
recorded diagnostics/timings, not their authenticity against wholesale replacement.
"""
import argparse
from collections import Counter
import curses
import hashlib
import html
import json
from pathlib import Path
import statistics
import tomllib

from prepare_prefilter_corrections import CONFLICTING
from role_marker_follow_up import compare
from verified_role_marker_results import require, verified_run


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def compact(delta):
    return {**{k: delta[k] for k in ['baseline', 'candidate']},
            **{k: sum(r['count'] for r in delta[k]) for k in
               ['added_findings', 'lost_findings', 'added_gap_causes', 'lost_gap_causes']},
            **{k: len(delta[k]) for k in
               ['added_detections', 'lost_detections', 'newly_incomplete', 'resolved_incomplete']}}


def derive(root):
    identities = read(root/'experiment-identities.json')
    for category in ['binaries', 'packages', 'sources']:
        for key, item in identities[category].items():
            require(digest(item['path']) == item['sha256'], f'{category}/{key}: identity mismatch')
    sidecars = read(root/'sidecar-sha256.json')
    expected_sidecars = {'experiment-identities.json', 'runtime.json'}
    for name in identities['packages']:
        expected_sidecars.update(f'full-{v}-{name}.json' for v in ['accepted','corrected','shipping'])
        for version in ['baseline','accepted','reference','corrected','shipping']:
            trials = range(1,4) if name=='development' and version in ['baseline','accepted','reference'] else [1]
            expected_sidecars.update(f'eval-cache/results/{version}-{name}-{t}/experiment.json' for t in trials)
    require(set(sidecars) == expected_sidecars, 'sidecar manifest selection differs')
    for path, expected in sidecars.items():
        require(digest(root/path) == expected, f'{path}: sidecar checksum mismatch')
    sources = {k: tomllib.loads(Path(v['path']).read_text()) for k,v in identities['sources'].items()}
    ids = [r['id'] for r in sources['baseline']['rule']]
    require(CONFLICTING <= set(ids), 'deferred rule selection differs')
    for a,b in zip(sources['baseline']['rule'], sources['accepted']['rule']):
        require((a['literals'] == b['literals']) == (a['id'] in CONFLICTING), f'{a["id"]}: accepted disposition differs')
    for variant in ['accepted', 'corrected']:
        restored = tomllib.loads(Path(identities['sources'][variant]['path']).read_text())
        require([r['id'] for r in restored['rule']] == ids, 'candidate rule identity/order differs')
        for a,b in zip(sources['baseline']['rule'], restored['rule']): b['literals'] = a['literals']
        require(restored == sources['baseline'], f'{variant}: changed semantics beyond literal admission')
    report = {'scope': 'Product / High / enforcement / structural; test-only ungated reference',
              'identities': identities, 'sidecar_sha256': sidecars, 'native_verified': {}, 'packages': {},
              'rules': {}, 'runtime': read(root/'runtime.json'), 'corpus_runtime': {}, 'gap_investigations': []}
    details = {}
    expected_policy = None
    for name, identity in identities['packages'].items():
        package = read(identity['path'])
        runs, times = {}, {}
        for version in ['baseline', 'accepted', 'reference', 'corrected', 'shipping']:
            trials = range(1,4) if name == 'development' and version in ['baseline','accepted','reference'] else [1]
            times[version] = []
            for trial in trials:
                label = f'{version}-{name}-{trial}'
                directory = root/'eval-cache/results'/label
                data, manifest, files = verified_run(directory, identities['binaries']['verifier']['path'])
                require((directory/'input-sha256.txt').read_text().strip() == identity['sha256'], f'{label}: input hash differs')
                require(manifest['completion']['corpus'] == package['corpus'], f'{label}: corpus definition differs')
                require(set(data) == set(package['rows']), f'{label}: input/result slices differ')
                for sid, rows in package['rows'].items():
                    require(len(rows) == len(data[sid]) and {r['id'] for r in rows} == set(data[sid]), f'{label}/{sid}: input/result IDs differ')
                    require(all(data[sid][r['id']]['source'] == r['source'] for r in rows), f'{label}/{sid}: input/result sources differ')
                policy = manifest['policy']
                require(manifest['mode'] == 'product' and manifest['tiers'] == {} and
                        policy['profile'] == 'enforcement' and policy['threshold'] == 'high' and
                        policy['provenance'] == 'unspecified' and not policy['suppress_in_quotes'] and
                        [policy[k] for k in ['max_input_bytes','max_decode_depth','max_matches_per_rule','max_observations','max_reasons']] ==
                        [1048576, 3, 16, 4096, 64], f'{label}: changed policy or limits')
                if expected_policy is None: expected_policy = policy
                require(policy == expected_policy, f'{label}: paired policies differ')
                meta = read(directory/'experiment.json')
                source = 'baseline' if version in ['baseline','reference'] else 'accepted' if version == 'shipping' else version
                mode = version if version in ['reference','shipping'] else 'normal'
                require(meta['source_sha256'] == identities['sources'][source]['sha256'] and
                        meta['configuration'] == mode and manifest['ruleset'] == f'matching-consistency/{mode}', f'{label}: source/configuration differs')
                require(set(meta['slice_ns']) == set(data), f'{label}: timing selection differs')
                times[version].append(meta)
                if version in runs: require(runs[version] == data, f'{label}: repeat results differ')
                else: runs[version] = data
                report['native_verified'][label] = files
        require(runs['corrected'] == runs['reference'], f'{name}: complete corrections still differ from reference')
        require(runs['accepted'] == runs['shipping'], f'{name}: shipping differs from candidate')
        report['corpus_runtime'][name] = {v: {
            'total_scan_publish_ms': [sum(t['slice_ns'].values())/1e6 for t in samples],
            'median_total_ms': statistics.median(sum(t['slice_ns'].values()) for t in samples)/1e6,
            'preparation_ms': [t['preparation_ns']/1e6 for t in samples],
        } for v,samples in times.items()}
        full = {v: read(root/f'full-{v}-{name}.json') for v in ['accepted','corrected','shipping']}
        for version, result in full.items():
            require(result['input_sha256'] == identity['sha256'] and set(result['slices']) == set(package['rows']), f'{name}/{version}: full comparison input differs')
            left = {'accepted':'baseline','corrected':'corrected','shipping':'accepted'}[version]
            require(result['left_source_sha256'] == identities['sources'][left]['sha256'], f'{name}/{version}: full comparison source differs')
            if version != 'corrected': require(result['right_source_sha256'] == identities['sources']['accepted']['sha256'], f'{name}/{version}: full comparison candidate differs')
            for sid, comparison in result['slices'].items():
                require(comparison['rows'] == len(package['rows'][sid]), f'{name}/{sid}: full comparison count differs')
                if version != 'accepted': require(not comparison['full_different_ids'], f'{name}/{sid}/{version}: full verdicts differ')
                require(not comparison['suppression_different_ids'], f'{name}/{sid}/{version}: investigate changed suppression')
                require(not comparison['gap_differences'], f'{name}/{sid}/{version}: investigate full coverage-gap differences')
        details[name] = {}
        report['packages'][name] = {}
        for sid in package['rows']:
            delta = {v: compare(runs['baseline'][sid], runs[v][sid]) for v in ['accepted','reference']}
            details[name][sid] = delta
            accepted = delta['accepted']
            require(not accepted['lost_detections'] and not accepted['lost_findings'], f'{name}/{sid}: lost detection/finding')
            definition = next(s for s in package['corpus']['slice'] if s['id'] == sid)
            if definition['kind'] == 'negative': require(not accepted['added_findings'], f'{name}/{sid}: new benign findings')
            report['packages'][name][sid] = {'kind': definition['kind'],
                **{v: compact(d) for v,d in delta.items()},
                'full_behavior_changed_rows': len(full['accepted']['slices'][sid]['full_different_ids']),
                'median_slice_ms': {v: statistics.median(t['slice_ns'][sid] for t in samples)/1e6 for v,samples in times.items()}}
        if name == 'syntax':
            for rid in ids:
                probe_ids = {r['id'] for r in package['rows']['prefilter_syntax'] if r['technique'] == rid}
                added = details[name]['prefilter_syntax']['reference']['added_findings']
                affected = {r['id'] for r in added if r['value']['rule_id'] == rid}
                probes = [r for r in package['rows']['prefilter_syntax'] if r['id'] in affected]
                report['rules'][rid] = {
                    'disposition': 'deferred: new benign findings' if rid in CONFLICTING else 'corrected',
                    'authored_probe_rows': len(probe_ids),
                    'probe_rows_matching_intended_rule': {v:sum(any(f['rule_id'] == rid for f in runs[v]['prefilter_syntax'][i].get('reasons',[])) for i in probe_ids) for v in ['baseline','accepted','reference']},
                    'new_reference_findings': sum(r['count'] for r in added if r['value']['rule_id'] == rid),
                    'affected_variations': sorted({r['context'] for r in probes}),
                    'affected_carriers': sorted({r['carrier'] for r in probes}),
                }
                require(report['rules'][rid]['new_reference_findings'] > 0, f'{rid}: missing discrepancy evidence')
    report['policy'] = expected_policy
    for case in report['runtime']['cases']:
        before = case['configs']['baseline']['gaps']
        after = case['configs']['accepted']['gaps']
        if before != after:
            require(all(g['cause']=='max_matches_per_rule' and g['configured']==16 for g in after), f'{case["case"]}: unexplained runtime gap')
            require(case['accepted_equals_reference'], f'{case["case"]}: runtime candidate/reference differs')
            report['gap_investigations'].append({'case':case['case'],'before':before,'after':after,
                'explanation':'The corrected gate admits an existing regex. More than 16 raw occurrences saturate the unchanged per-rule cap before framing. Off-frame occurrences still consume the cap; no limit was raised.'})
    report['row_deltas_sha256'] = hashlib.sha256(json.dumps(details,sort_keys=True).encode()).hexdigest()
    return report, details


def tables(report):
    datasets = [['Dataset', 'Rows', 'Baseline hits', 'Accepted hits', 'Reference hits', '+/- findings accepted', '+/- findings reference', 'Gaps B/A/R', 'ms B/A/R']]
    for package, slices in report['packages'].items():
        for sid, row in slices.items():
            a,r = row['accepted'],row['reference']; b = a['baseline']; ms=row['median_slice_ms']
            datasets.append([f'{package}/{sid}',str(b['rows']),str(b['detected']),str(a['candidate']['detected']),str(r['candidate']['detected']),
                f'+{a["added_findings"]}/-{a["lost_findings"]}',
                f'+{r["added_findings"]}/-{r["lost_findings"]}',
                '/'.join(str(x['incomplete']) for x in [b,a['candidate'],r['candidate']]),
                '/'.join(f'{ms[v]:.1f}' for v in ['baseline','accepted','reference'])])
    rules = [['Rule', 'Disposition', 'Intended rule probe hits B/A/R', 'Reference added findings']]
    for rid,r in report['rules'].items():
        rules.append([rid,r['disposition'],'/'.join(str(r['probe_rows_matching_intended_rule'][v]) for v in ['baseline','accepted','reference']),str(r['new_reference_findings'])])
    perf = [['Runtime case','Bytes','Baseline us','Accepted us','Reference us','Accepted change','Gap counts B/A/R']]
    for row in report['runtime']['cases']:
        c=row['configs']; t=[c[v]['median_ns_per_scan']/1000 for v in ['baseline','accepted','reference']]
        perf.append([row['case'],str(row['bytes']),*[f'{x:.2f}' for x in t],f'{(t[1]/t[0]-1)*100:+.1f}%',
                     '/'.join(str(len(c[v]['gaps'])) for v in ['baseline','accepted','reference'])])
    gaps = [['Runtime case','Investigation','New gap details']]
    for g in report['gap_investigations']: gaps.append([g['case'],g['explanation'],json.dumps(g['after'])])
    corpus = [['Package', 'Trials B/A/R', 'Median seconds B/A/R', 'Accepted change']]
    for name,configs in report['corpus_runtime'].items():
        t=[configs[v]['median_total_ms']/1000 for v in ['baseline','accepted','reference']]
        corpus.append([name,'/'.join(str(len(configs[v]['total_scan_publish_ms'])) for v in ['baseline','accepted','reference']),
                       '/'.join(f'{x:.3f}' for x in t),f'{(t[1]/t[0]-1)*100:+.1f}%'])
    return {'Datasets':datasets,'Rules':rules,'Corpus runtime':corpus,'Runtime':perf,'Coverage gaps':gaps}


NOTES = [
    '13 gate corrections accepted; 5 retained as known inconsistencies because full corrections add benign findings.',
    'B/A/R = baseline / accepted / ungated reference. High enforcement; original resource limits. Reference is test-only.',
    'Syntax probes include deliberately invalid variants. These counts measure matching behavior, not attack recall. First-party controls have no independent label review.',
    'Development and validation corpora were previously exposed; dataset slices can overlap. Counts include existing wrapper artifacts and benign findings. No population false-positive claim.',
    'Native rows were independently verified and recounted. Complete corrections equal reference; accepted equals shipping, including full in-memory verdict comparisons.',
    'Corpus milliseconds include scan and native result publication; development uses three rotating-order trials. Microbenchmarks use five warmed rotating-order samples; source preparation is separate.',
    'No new corpus gaps. Dense runtime probes expose the existing cap at 16 raw matches; each changed case is documented below.',
]


def render_html(report):
    chunks = ['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Matching consistency audit</title>',
              '<style>body{font:16px system-ui;margin:2rem;color:#17212b}table{border-collapse:collapse;font-size:14px}th,td{padding:.5rem;border:1px solid #ccd;text-align:left}th{background:#edf2fa}section{overflow:auto}li{margin:.5rem 0}</style>',
              '<h1>Matching consistency audit · 2026-09-15</h1><ul>']
    chunks += ['<li>'+html.escape(n)+'</li>' for n in NOTES]
    chunks += ['</ul>']
    for title, rows in tables(report).items():
        chunks += ['<h2>'+html.escape(title)+'</h2><section><table>']
        for i,row in enumerate(rows):
            tag='th' if i==0 else 'td'
            chunks += ['<tr>'+''.join(f'<{tag}>{html.escape(cell)}</{tag}>' for cell in row)+'</tr>']
        chunks += ['</table></section>']
    chunks += ['<h2>Preparation</h2><p>Supplied engine construction, milliseconds B/A/R: '+
               ' / '.join(f'{n/1e6:.2f}' for n in report['runtime']['preparation_ns'])+'</p>',
               '<p>See the companion JSON for input, executable and result checksums, per-rule variation/carrier coverage, sample timings and complete gap details.</p></html>']
    return '\n'.join(chunks)


def text_pages(report):
    return {name: [' | '.join(row) for row in rows] for name,rows in tables(report).items()}


def tui(report):
    pages = text_pages(report)
    pages['Notes'] = NOTES + ['Preparation ms B/A/R: '+' / '.join(f'{n/1e6:.2f}' for n in report['runtime']['preparation_ns'])]
    def show(screen):
        tab, top, left = 0, 0, 0
        names = list(pages)
        while True:
            screen.erase(); height,width=screen.getmaxyx()
            lines = [f'Matching consistency | {names[tab]} | Tab: page  arrows: scroll  q: quit', *pages[names[tab]][top:]]
            for y,line in enumerate(lines[:max(0,height-1)]):
                try: screen.addnstr(y,0,line[left:] if y else line,max(0,width-1))
                except curses.error: pass
            screen.refresh(); key=screen.getch()
            if key in [ord('q'),27]: break
            if key in [9,ord(']')]: tab=(tab+1)%len(names); top=left=0
            elif key in [curses.KEY_DOWN,ord('j')]: top=min(top+1,max(0,len(pages[names[tab]])-1))
            elif key in [curses.KEY_UP,ord('k')]: top=max(0,top-1)
            elif key==curses.KEY_RIGHT: left+=16
            elif key==curses.KEY_LEFT: left=max(0,left-16)
    curses.wrapper(show)


def check_claimed_report(claimed, derived):
    require(claimed == derived, 'saved report disagrees with independently verified native evidence')


def save_same_or_new(path, value):
    content = json.dumps(value, indent=2)+'\n'
    if path.exists(): require(path.read_text()==content, f'{path}: refusing to replace different evidence')
    else: path.write_text(content)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root',type=Path); parser.add_argument('--tui',action='store_true'); parser.add_argument('--check',type=Path)
    args=parser.parse_args()
    report,details=derive(args.root.resolve())
    if args.check: check_claimed_report(read(args.check),report)
    save_same_or_new(args.root/'report.json',report)
    save_same_or_new(args.root/'row-deltas.json',details)
    (args.root/'report.html').write_text(render_html(report))
    (args.root/'report.txt').write_text('\n\n'.join(name+'\n'+'\n'.join(lines) for name,lines in text_pages(report).items())+'\n')
    print(f'Verified {len(report["native_verified"])} native runs; HTML/JSON/text reports written to {args.root}')
    if args.tui: tui(report)


if __name__=='__main__': main()
