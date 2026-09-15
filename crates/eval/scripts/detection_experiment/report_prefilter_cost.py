"""Verify native evidence, recount deltas and render attribution/deferred/holdout HTML/TUI.
Usage: python3 report_prefilter_cost.py ROOT [--tui] [--check REPORT.json]
"""
import argparse
import curses
import hashlib
import html
import json
from pathlib import Path
import statistics
import tomllib
from fresh_prefilter_holdout import candidate, digest, h
from report_matching_consistency import compact, check_claimed_report, save_same_or_new
from role_marker_follow_up import compare
from verified_role_marker_results import require, verified_run


def read(p): return json.loads(Path(p).read_bytes())
def total_samples(config):
    return [sum(v[i] for k,v in config['samples_ns'].items() if k not in ['ordinary_prose','many_literals'])/1e6 for i in range(5)]
def interval(values): return {'median_ms':statistics.median(values),'min_ms':min(values),'max_ms':max(values),'samples_ms':values}


def derive(root):
    frozen=candidate(root); freeze=read(root/'candidate-freeze.json'); identities=read(root/'final-identities.json')
    require(identities['candidate_freeze_sha256']==frozen,'evaluation candidate differs')
    for name,sha in freeze['development_selection_evidence'].items():
        require(digest(root/name)==sha,'selection evidence changed after candidate freeze')
    sidecars=read(root/'evidence-sha256.json')
    for path,sha in sidecars.items(): require(digest(root/path)==sha,f'changed sidecar: {path}')
    required={'candidate-freeze.json','final-identities.json','attribution.json','precise.json','final-runtime.json',
              'holdout-plan/plan.json','holdout-plan/query-result.json','holdout/package-identity.json','holdout/evaluation-complete.json'}
    require(required<=sidecars.keys(),'missing required evidence sidecars')
    plan=read(root/'holdout-plan/plan.json'); query=read(root/'holdout-plan/query-result.json')
    pack=read(root/'holdout/package-identity.json'); exposure=read(root/'holdout/exposure.json'); complete=read(root/'holdout/evaluation-complete.json')
    for record in [plan,query,pack,exposure,complete]: require(record['candidate_freeze_sha256']==frozen,'holdout candidate changed')
    acquisition_plan=read(root/'holdout-plan-expanded/plan.json') if 'availability_amendment' in plan else plan
    require(freeze['created_utc']<=acquisition_plan['created_utc']<=query['started_utc']<=query['finished_utc']<=pack['created_utc']<=exposure['started_utc']<=complete['finished_utc'],'freeze/acquisition/evaluation order differs')
    if 'availability_amendment' in plan:
        amendment=plan['availability_amendment']
        require(query['finished_utc']<=plan['created_utc']<=pack['created_utc'],'availability amendment order differs')
        require(digest(root/'holdout-plan-expanded/plan.json')==amendment['acquisition_plan_sha256']==query['plan_sha256'],'availability acquisition identity differs')
        require([(s['source'],s['prompt_adversarial']) for s in acquisition_plan['strata']]==[(s['source'],s['prompt_adversarial']) for s in plan['strata']],'availability amendment changed strata')
        require(all(0<b['count']<=a['count'] for a,b in zip(acquisition_plan['strata'],plan['strata'])),'availability amendment expands selection')
        require(acquisition_plan['files']==plan['files'],'availability amendment changed ordering/exclusions')
    require(complete['candidate_retuned'] is False,'holdout was used for retuning')
    for name,sha in plan['files'].items(): require(digest(root/'holdout-plan'/name)==sha,'exposure plan changed')
    require(digest(root/'holdout/freeze.json')==pack['freeze_sha256'],'holdout freeze changed')
    for name,sha in read(root/'holdout/freeze.json')['files'].items(): require(digest(root/'holdout'/name)==sha,'frozen holdout input changed')
    require(digest(root/'holdout/corpus.json')==pack['corpus_sha256'],'holdout package changed')
    exact=set((root/'holdout-plan/exposed.csv').read_text().splitlines()[1:]); folded=set(read(root/'holdout-plan/normalized-exposed.json'))
    seen=set(); provenance={r['input_sha256']:r for r in map(json.loads,(root/'holdout/provenance.jsonl').read_text().splitlines())}
    for sid,rows in read(root/'holdout/corpus.json')['rows'].items():
        for row in rows:
            sha=h.digest(row['text'].encode()); norm=h.normalized(row['text'])
            require(sha==row['id'] and sha in provenance,'holdout original byte identity differs')
            require(sha not in exact and norm not in folded and norm not in seen,'holdout exposure or duplicate')
            require(provenance[sha]['prompt_adversarial']==(sid=='holdout_positive'),'holdout label changed')
            seen.add(norm)
    require(len(seen)==len(provenance)==sum(s['count'] for s in plan['strata']),'holdout selection count differs')
    report={'candidate_freeze_sha256':frozen,'candidate_freeze':freeze,'identities':identities,'evidence_sha256':sidecars,
            'fresh_holdout':{'plan':plan,'query':query,'package':pack,'exposure':exposure,'complete':complete,
                            'exact_overlap':0,'normalized_overlap':0,'rows':len(seen)},
            'attribution':{},'optimization':{},'datasets':{},'deferred':{},'native_verified':{},
            'runtime':read(root/'final-runtime.json'),'layout':read(root/'precise-layout.json')}
    if 'amendment' in plan:
        initial=read(root/'holdout-plan-initial/plan.json'); initial_query=read(root/'holdout-plan-initial/query-result.json')
        require(digest(root/'holdout-plan-initial/plan.json')==plan['amendment']['initial_plan_sha256'],'initial selection plan changed')
        require(initial['strata']==acquisition_plan['strata'] and initial['candidate_freeze_sha256']==frozen,'overfetch amendment changed target or detector')
        require(initial_query['finished_utc']<=acquisition_plan['created_utc'],'amendment timeline differs')
        for n in ['exposed.csv','normalized-exposed.json']:
            require(initial['files'][n]==plan['files'][n],'amendment changed exclusions')
        report['fresh_holdout']['initial_query']=initial_query
        report['fresh_holdout']['amendment']=plan['amendment']
    confirmation=None;confirmation_files={}
    if (root/'timing-confirmation-plan.json').exists():
        cp=read(root/'timing-confirmation-plan.json');cc=read(root/'timing-confirmation-complete.json')
        require(cp['trials']==10 and cc['plan_sha256']==digest(root/'timing-confirmation-plan.json'),'timing confirmation plan differs')
        require(cp['candidate_freeze_sha256']==cc['candidate_freeze_sha256']==frozen and cc['candidate_retuned'] is False,'timing confirmation changed candidate')
        require(complete['finished_utc']<=cp['started_utc']<=cc['finished_utc'],'confirmation timeline differs')
        confirmation_files=cc['files']
        expected={f'eval-cache/results/timing-{v}-holdout-{i:02}/experiment.json' for i in range(1,11) for v in ['baseline','candidate']}
        require(set(confirmation_files)==expected,'confirmation is not the fixed ten-pair batch')
        for p,sha in confirmation_files.items():require(digest(root/p)==sha,'confirmation sidecar changed')
        confirmation={'plan':cp,'complete':cc,'complete_sha256':digest(root/'timing-confirmation-complete.json')}
    details={}; expected_policy=None;holdout_runs={}
    def load(label,package,source,mode='normal'):
        nonlocal expected_policy
        directory=root/'eval-cache/results'/label
        rows,manifest,files=verified_run(directory,root/'bin/verifier')
        meta=read(directory/'experiment.json')
        require(str(directory.relative_to(root)/'experiment.json') in (sidecars.keys()|confirmation_files.keys()),'unbound run timing')
        require((directory/'input-sha256.txt').read_text().strip()==digest(package),'run input identity differs')
        require(meta['source_sha256']==digest(source) and meta['configuration']==mode,'run source differs')
        inputs=read(package)
        require(manifest['completion']['corpus']==inputs['corpus'] and set(rows)==set(inputs['rows']),'run selection differs')
        for sid,data in inputs['rows'].items():
            require(len(data)==len(rows[sid]) and {r['id'] for r in data}==set(rows[sid]),'run row IDs differ')
            require(all(rows[sid][r['id']]['source']==r['source'] for r in data),'run row sources differ')
        policy=manifest['policy']
        require(manifest['mode']=='product' and manifest['tiers']=={} and policy['profile']=='enforcement' and policy['threshold']=='high' and
                policy['provenance']=='unspecified' and not policy['suppress_in_quotes'] and
                [policy[k] for k in ['max_input_bytes','max_decode_depth','max_matches_per_rule','max_observations','max_reasons']]==[1048576,3,16,4096,64],'policy/limits changed')
        if expected_policy is None: expected_policy=policy
        require(policy==expected_policy,'paired policies differ')
        report['native_verified'][label]=files
        return rows,meta
    for name,item in identities['packages'].items():
        package=Path(item['path']); require(digest(package)==item['sha256'],'frozen package changed')
        runs={};timings={}
        for version in ['baseline','candidate','shipping']:
            source=root/'sources/current.toml' if version=='baseline' else root/'candidate.toml'
            trials=range(1,4) if name in ['development','holdout'] and version!='shipping' else [1]
            timings[version]=[]
            for trial in trials:
                rows,meta=load(f'final-{version}-{name}-{trial}',package,source,'shipping' if version=='shipping' else 'normal')
                if version in runs: require(runs[version]==rows,'repeat verdicts changed')
                else:runs[version]=rows
                timings[version].append(meta)
        require(runs['candidate']==runs['shipping'],'shipping differs from frozen candidate')
        if name=='holdout':holdout_runs=runs
        full=read(root/f'full-final-{name}.json'); require(full['input_sha256']==item['sha256'],'full comparison input differs')
        require(full['left_source_sha256']==digest(root/'sources/current.toml') and full['right_source_sha256']==digest(root/'candidate.toml'),'full comparison sources differ')
        require(set(full['slices'])==set(runs['candidate']),'full comparison selection differs')
        report['datasets'][name]={'slices':{},'runtime':{v:{'total_ms_samples':[sum(t['slice_ns'].values())/1e6 for t in samples],
            'median_total_ms':statistics.median(sum(t['slice_ns'].values())/1e6 for t in samples),
            'preparation_ms':[t['preparation_ns']/1e6 for t in samples]} for v,samples in timings.items()}}
        details[name]={}
        for sid,old in runs['baseline'].items():
            comparison=full['slices'][sid]
            require(comparison['rows']==len(old),'full comparison row count differs')
            delta=compare(old,runs['candidate'][sid]); details[name][sid]=delta
            report['datasets'][name]['slices'][sid]={**compact(delta),
                'native_equal':old==runs['candidate'][sid], 'full_changed_rows':len(comparison['full_different_ids']),
                'full_gap_differences':comparison['gap_differences'],
                'median_ms':{v:statistics.median(t['slice_ns'][sid]/1e6 for t in samples) for v,samples in timings.items()}}
        if name=='syntax':
            previous,_,files=verified_run(Path('.cache/matching-consistency-20260915/eval-cache/results/baseline-syntax-1'),root/'bin/verifier')
            report['native_verified']['previous-audit/baseline-syntax-1']=files
            delta=compare(previous['prefilter_syntax'],runs['candidate']['prefilter_syntax'])
            report['retained_syntax_coverage']=compact(delta)
            require(len(delta['added_detections'])==2251 and not delta['lost_findings'],'prior recovered coverage changed')
    if confirmation:
        samples={'baseline':[],'candidate':[]};p=root/'holdout/corpus.json'
        require(confirmation['plan']['input_sha256']==digest(p),'confirmation input differs')
        for i in range(1,11):
            for v in samples:
                source=root/'sources/current.toml' if v=='baseline' else root/'candidate.toml'
                rows,meta=load(f'timing-{v}-holdout-{i:02}',p,source)
                require(rows==holdout_runs[v],'timing-only confirmation changed native results')
                samples[v].append(sum(meta['slice_ns'].values())/1e6)
        confirmation['timings_ms']={v:interval(s) for v,s in samples.items()}
        confirmation['paired_change_percent']=[(b/a-1)*100 for a,b in zip(samples['baseline'],samples['candidate'])]
        report['timing_confirmation']=confirmation
    authored=Path('crates/core/tests/data/deferred_prefilter_pairs.json')
    require(digest(authored)==(root/'paired-controls-sha256.txt').read_text().strip(),'paired controls changed after preregistration')
    before_rules={r['id']:r for r in tomllib.loads((root/'sources/current.toml').read_text())['rule']}
    for pair in read(root/'deferred-plan.json'):
        rid=pair['rule'];index=pair['index'];package=Path(pair['package']);source=Path(pair['candidate'])
        after=tomllib.loads(source.read_text())
        for r in after['rule']:
            a=before_rules[r['id']]
            if r['id']==rid:r['literals']=a['literals']
            require(r==a,'deferred candidate changes another rule or semantics')
        a,_=load(f'deferred-{index}-baseline',package,root/'sources/current.toml')
        b,_=load(f'deferred-{index}-broader',package,source)
        deltas={sid:compare(a[sid],b[sid]) for sid in a}
        require(deltas['ordinary']['added_findings'],'deferred decision lacks benign conflict')
        report['deferred'][rid]={'status':'rejected; new ordinary-language findings','candidate_sha256':digest(source),
            'package_sha256':digest(package),'pairs':[p for p in read(authored)['pairs'] if p['rule']==rid],
            'slices':{sid:{**compact(d), 'added_target_findings':sum(f['count'] for f in d['added_findings'] if f['value']['rule_id']==rid)} for sid,d in deltas.items()}}
        details[rid]=deltas
    attrib=read(root/'attribution.json'); layout=read(root/'layout.json'); plan_a=read(root/'attribution-plan.json')
    require(attrib['input_sha256']==plan_a['input_sha256']==digest(root/'attribution-inputs.json'),'attribution input changed')
    c=attrib['configurations'];old=total_samples(c['previous']);current=total_samples(c['current'])
    for i,rid in enumerate(plan_a['changed_rules']):
        add=f'add-{i:02}';remove=f'remove-{i:02}'
        for v in [add,remove]:require(c[v]['source_sha256']==digest(root/'sources'/f'{v}.toml'),'attribution source differs')
        report['attribution'][rid]={'addition':interval([a-b for a,b in zip(total_samples(c[add]),old)]),
            'removal_benefit':interval([a-b for a,b in zip(current,total_samples(c[remove]))]),
            'addition_layout':layout[add],'removal_layout':layout[remove]}
    for phase in ['optimization','precise']:
        experiment=read(root/f'{phase}.json');require(experiment['input_sha256']==attrib['input_sha256'],'optimization workload changed')
        report['optimization'][phase]={k:{'corpus':interval(total_samples(c)),
            'ordinary_prose_ms':statistics.median(c['samples_ns']['ordinary_prose'])/1e6,
            'many_literals_ms':statistics.median(c['samples_ns']['many_literals'])/1e6} for k,c in experiment['configurations'].items()}
    for case in report['runtime']['cases']:
        a,b=case['configs']['baseline'],case['configs']['accepted']
        require(all(a[k]==b[k] for k in ['score','outcome','findings','suppressed','gaps']),'runtime behavior changed')
    report['policy']=expected_policy
    report['acceptance']={'native_and_full_verdicts_preserved':all(s['native_equal'] and s['full_changed_rows']==0 for p in report['datasets'].values() for s in p['slices'].values()),
                          'candidate_retuned_after_holdout':False}
    report['row_deltas_sha256']=hashlib.sha256(json.dumps(details,sort_keys=True).encode()).hexdigest()
    return report,details


NOTES=[
    'Performance-only candidate: recovered syntax coverage retained; five deferred rule expansions rejected individually.',
    'Acceptance requires unchanged native rows and full verdicts. High/enforcement and existing resource limits retained; the JSON records the acceptance result.',
    'Individual additions and removals use five rotating-order warmed trials on an exposed sample (at most 128 rows per slice). Small deltas can be noise; costs are not additive.',
    'The 100-pattern automatic-layout threshold explains the large shared cost. Compact candidate: 96 literals, DFA, about 378 KiB; baseline: 126 literals, NFA, about 38 KiB.',
    'Corpus times include native result publication; development and fresh holdout have three trials. Microbenchmarks exclude preparation and use five warmed samples.',
    'Fresh holdout: 587 direct prompts; an exhausted stratum was capped at 87 before detector outcomes were opened. Candidate frozen before acquisition; exact/normalized exposure overlap zero. Within-source upstream labels, no independent owner review or semantic-overlap guarantee.',
    'Generated syntax detections are not natural-dataset gains. Frozen holdout outcomes were not used to retune the candidate.',
]


def tables(r):
    attribution=[['Rule','Added alone ms (range)','Removed from full: saved ms (range)','Added-alone layout']]
    for rid,x in r['attribution'].items():
        def cell(v):return f'{v["median_ms"]:+.2f} ({v["min_ms"]:+.2f}..{v["max_ms"]:+.2f})'
        attribution.append([rid,cell(x['addition']),cell(x['removal_benefit']),x['addition_layout']['kind']])
    datasets=[['Slice','Rows','Detections B/C','Findings +/-','Incomplete B/C','Scan/publish ms B/C']]
    totals=[['Package','Median seconds B/C','Candidate change','Trials']]
    for name,p in r['datasets'].items():
        rt=p['runtime'];a=rt['baseline']['median_total_ms'];b=rt['candidate']['median_total_ms']
        totals.append([name,f'{a/1000:.3f}/{b/1000:.3f}',f'{(b/a-1)*100:+.1f}%',str(len(rt['baseline']['total_ms_samples']))])
        for sid,d in p['slices'].items():
            datasets.append([name+'/'+sid,str(d['baseline']['rows']),f'{d["baseline"]["detected"]}/{d["candidate"]["detected"]}',
                f'+{d["added_findings"]}/-{d["lost_findings"]}',f'{d["baseline"]["incomplete"]}/{d["candidate"]["incomplete"]}',
                f'{d["median_ms"]["baseline"]:.1f}/{d["median_ms"]["candidate"]:.1f}'])
    if 'timing_confirmation' in r:
        c=r['timing_confirmation']['timings_ms'];a=c['baseline']['median_ms'];b=c['candidate']['median_ms']
        totals.append(['Holdout timing confirmation (already exposed)',f'{a/1000:.3f}/{b/1000:.3f}',f'{(b/a-1)*100:+.1f}%','10'])
    deferred=[['Rule','Attack target findings added','Ordinary target findings added','Disposition']]
    for rid,d in r['deferred'].items():deferred.append([rid,str(d['slices']['attack']['added_target_findings']),str(d['slices']['ordinary']['added_target_findings']),d['status']])
    micro=[['Case','Bytes','Baseline us','Candidate us','Change','Coverage gaps B/C']]
    for case in r['runtime']['cases']:
        a=case['configs']['baseline'];b=case['configs']['accepted'];t=a['median_ns_per_scan'];u=b['median_ns_per_scan']
        micro.append([case['case'],str(case['bytes']),f'{t/1000:.2f}',f'{u/1000:.2f}',f'{(u/t-1)*100:+.1f}%',f'{len(a["gaps"])}/{len(b["gaps"])}'])
    opts=[['Stage / variant','Sample corpus median ms','Range ms','Ordinary prose ms','Many literals ms']]
    for stage,variants in r['optimization'].items():
        for name,d in variants.items():
            t=d['corpus'];opts.append([stage+'/'+name,f'{t["median_ms"]:.2f}',f'{t["min_ms"]:.2f}..{t["max_ms"]:.2f}',f'{d["ordinary_prose_ms"]:.2f}',f'{d["many_literals_ms"]:.2f}'])
    return {'Attribution':attribution,'Candidate selection':opts,'Datasets and holdout':datasets,'Corpus runtime':totals,'Deferred rules':deferred,'Runtime and gaps':micro}


def render_html(r):
    s=['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Prefilter cost and fresh holdout</title>',
       '<style>body{font:16px system-ui;margin:2rem;color:#17212b}section{overflow:auto}table{border-collapse:collapse;font-size:14px}th,td{padding:.5rem;border:1px solid #ccd;text-align:left}th{background:#edf2fa}li{margin:.6rem 0}</style>',
       '<h1>Prefilter cost, deferred rules and fresh holdout</h1><ul>',*['<li>'+html.escape(n)+'</li>' for n in NOTES],'</ul>']
    for title,rows in tables(r).items():
        s+=['<h2>'+html.escape(title)+'</h2><section><table>']
        for i,row in enumerate(rows):
            tag='th' if i==0 else 'td';s+=['<tr>'+''.join(f'<{tag}>{html.escape(x)}</{tag}>' for x in row)+'</tr>']
        s+=['</table></section>']
    s+=['<p>Companion JSON includes native result hashes, freeze/acquisition timeline, paired examples, gap details and all timing samples. No holdout prompt text is redistributed.</p></html>']
    return '\n'.join(s)


def tui(r):
    pages={name:[' | '.join(row) for row in rows] for name,rows in tables(r).items()}; pages['Notes']=NOTES
    def show(screen):
        tab=top=left=0;names=list(pages)
        while True:
            screen.erase();height,width=screen.getmaxyx()
            for y,line in enumerate([f'Prefilter cost | {names[tab]} | Tab: page  arrows: scroll  q: quit',*pages[names[tab]][top:]][:max(0,height-1)]):
                try:screen.addnstr(y,0,line[left:] if y else line,max(0,width-1))
                except curses.error:pass
            screen.refresh();key=screen.getch()
            if key in [ord('q'),27]:break
            if key==9:tab=(tab+1)%len(names);top=left=0
            elif key in [curses.KEY_DOWN,ord('j')]:top=min(top+1,max(0,len(pages[names[tab]])-1))
            elif key in [curses.KEY_UP,ord('k')]:top=max(0,top-1)
            elif key==curses.KEY_RIGHT:left+=16
            elif key==curses.KEY_LEFT:left=max(0,left-16)
    curses.wrapper(show)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--tui',action='store_true');p.add_argument('--check',type=Path);args=p.parse_args()
    report,details=derive(args.root.resolve())
    if args.check:check_claimed_report(read(args.check),report)
    save_same_or_new(args.root/'report.json',report);save_same_or_new(args.root/'row-deltas.json',details)
    (args.root/'report.html').write_text(render_html(report))
    (args.root/'report.txt').write_text('\n\n'.join(name+'\n'+'\n'.join(' | '.join(row) for row in rows) for name,rows in tables(report).items())+'\n')
    print(f'Verified {len(report["native_verified"])} native runs and freeze-first holdout; reports written to {args.root}')
    if args.tui:tui(report)


if __name__=='__main__':main()
