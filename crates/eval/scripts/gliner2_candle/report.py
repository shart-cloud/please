#!/usr/bin/env python3
"""Compare verified native Candle runs with frozen Jev and structural results; publish no text."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text())


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def metric(xs):
    return dict(rows=len(xs),coverage=dict(collections.Counter(x['coverage'] for x in xs)),
                errors=dict(collections.Counter(x['error'] for x in xs if x['error'])),
                confusion={label:dict(collections.Counter(x['prediction'] for x in xs if x['truth']==label)) for label in sorted({x['truth'] for x in xs})},
                correct={label:dict(count=sum(x['truth']==label and x['prediction']==label and not x['error'] for x in xs),total=sum(x['truth']==label for x in xs)) for label in sorted({x['truth'] for x in xs})})


def native(root,arm,runner,meta):
    run=root/('run-'+arm)
    # Native verifier checks run identity and every saved row before reporting.
    subprocess.run([str(runner),'bench','report','--run',str(run),'--format','json'],check=True,stdout=subprocess.DEVNULL)
    result=[]
    for r in rows(run/'results.jsonl'):
        source=meta[r['case_id']]
        assert r['input_sha256']==source['asset_sha256'] and r['ground_truth']==source['ground_truth']
        raw=(r.get('raw_output') or {}).get('native') or {}
        diag=json.loads(raw['diagnostics'][0]) if raw.get('diagnostics') and raw['diagnostics'][0].startswith('{') else {}
        prediction=raw.get('label','indeterminate')
        if arm=='baseline':
            decision=(r.get('normalized') or {}).get('decision')
            prediction={'detected':'injection','not_detected':'benign'}.get(decision,'indeterminate')
        result.append(dict(case_id=r['case_id'],source=r['source'],truth=r['ground_truth'].get('label',r['ground_truth'].get('relation')),prediction=prediction,coverage=r['coverage'],error=diag.get('error') or (r['coverage'] if r['coverage'] not in ['completed','abstained'] else None),inference_ms=diag.get('inference_ms'),**{k:source.get(k) for k in ['delivery_vector','presentation_context','family_id']}))
    assert len(result)==len(meta) and {x['case_id'] for x in result}==set(meta)
    return result


def rate(m,label):
    c=m['correct'][label];return f"{c['count']}/{c['total']} ({c['count']/c['total']:.1%})" if c['total'] else 'N/A'


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--jev-run',type=Path,required=True);p.add_argument('--publish',type=Path,required=True);a=p.parse_args()
    root=a.out.resolve();jev=a.jev_run.resolve();freeze=load(root/'freeze.json')
    for name,expected in freeze['files'].items(): assert sha(root/name)==expected, f'changed frozen file: {name}'
    report=load(jev/'report.json');assert report['status']=='complete'
    session=load(jev/'session.json');assert session['complete'] and sha(jev/'captures.jsonl')==session['captures_sha256']
    meta={arm:{r['case_id']:r for r in load(root/arm/'pack.json')['cases']} for arm in ['public','contextual']}
    for arm in meta: assert sha(root/arm/'pack.json')==freeze['packs'][arm]
    candle={arm:native(root,arm,root/'please-eval',meta[arm]) for arm in meta}
    baseline=native(jev,'baseline',jev/'please-eval',meta['public'])
    public_metadata={m['case_id']:m for m in load(jev/'public-metadata.json')}
    for row in candle['public']:
        row.update({k:public_metadata[row['case_id']][k] for k in ['language','harmful']})
        size=meta['public'][row['case_id']]['byte_length']
        row['length_band']='0-1024 bytes' if size<=1024 else '1025-4096 bytes' if size<=4096 else '4097-8192 bytes' if size<=8192 else '8193-16384 bytes'
    captures=rows(jev/'captures.jsonl');jev_rows={arm:[] for arm in meta}
    for r in captures:
        arm=r['arm'];m=meta[arm][r['case_id']];error=r['diagnostics'].get('error');pred=r['prediction']
        jev_rows[arm].append(dict(case_id=r['case_id'],source=m['source'],truth=m['ground_truth'].get('label',m['ground_truth'].get('relation')),prediction=pred,coverage='unavailable' if error else 'abstained' if pred=='indeterminate' else 'completed',error=error))
    summary=dict(parity=freeze['parity'],tokenization_fuzz_cases=128,systems={name:{arm:metric(xs) for arm,xs in parts.items()} for name,parts in [('candle',candle),('jev',jev_rows),('structural',{'public':baseline})]},sources={name:{s:metric([x for x in xs if x['source']==s]) for s in sorted({x['source'] for x in xs})} for name,xs in [('candle',candle['public']),('jev',jev_rows['public']),('structural',baseline)]},contextual_strata={key:{v:metric([x for x in candle['contextual'] if x[key]==v]) for v in sorted({x[key] for x in candle['contextual']})} for key in ['delivery_vector','presentation_context','family_id']},identities=dict(freeze_sha256=sha(root/'freeze.json'),jev_report_sha256=sha(jev/'report.json'),candle_runs={arm:sha(root/('run-'+arm)/'run.json') for arm in meta}))
    summary['candle_public_strata']={key:{str(v):metric([x for x in candle['public'] if x[key]==v]) for v in sorted({x[key] for x in candle['public']})} for key in ['language','harmful','length_band']}
    durations=sorted(x['inference_ms'] for arm in candle.values() for x in arm if x['inference_ms'] is not None and not x['error'])
    summary['candle_inference_ms']=dict(count=len(durations),p50=durations[len(durations)//2] if durations else None,p95=durations[min(len(durations)-1,int(len(durations)*.95))] if durations else None)
    lines=['# PLEASE framework: Candle GLiNER2 and Jev — September 18, 2026','', 'All 6,000 public and 600 contextual GLiNER2 rows ran through the native PLEASE bench using Rust/Candle. Jev results are the separate frozen live capture, imported through the same framework without extra API calls. Different models use different recipes and score gates; this is an exploratory comparison, not calibrated deployment accuracy.','', '| Public system | Attack recall | Benign false positives | Abstained | Failed |','|---|---:|---:|---:|---:|']
    for name,parts in summary['systems'].items():
        m=parts['public'];false=m['confusion']['benign'].get('injection',0);total=m['correct']['benign']['total'];failed=sum(n for k,n in m['coverage'].items() if k not in ['completed','abstained'])
        lines.append(f"| {name} | {rate(m,'injection')} | {false}/{total} ({false/total:.1%}) | {m['coverage'].get('abstained',0)} | {failed} |")
    lines+=['','All-row recall includes abstentions and failures as misses. False-positive rates require reading coverage alongside them. Detailed native reports retain every stratum and row.','','## Public source breakdown','','| Source | Candle attack recall | Jev attack recall | Structural attack recall | Candle benign false positives |','|---|---:|---:|---:|---:|']
    for s,m in summary['sources']['candle'].items():
        attack=lambda name:rate(summary['sources'][name][s],'injection') if 'injection' in summary['sources'][name][s]['correct'] else 'N/A'
        benign=m['correct'].get('benign'); fp=f"{m['confusion'].get('benign',{}).get('injection',0)}/{benign['total']}" if benign else 'N/A'
        lines.append(f"| {s} | {attack('candle')} | {attack('jev')} | {attack('structural')} | {fp} |")
    lines+=['','## Contextual regression','','| True relation | Candle correct | Jev correct |','|---|---:|---:|']
    for label in sorted(summary['systems']['candle']['contextual']['correct']): lines.append(f"| {label} | {rate(summary['systems']['candle']['contextual'],label)} | {rate(summary['systems']['jev']['contextual'],label)} |")
    lines+=['','The 600 contextual rows contain only 50 distinct candidate texts, 150 correlated groups and 15 workflow families. Correct indeterminate rows exclude input/runtime failures. Independent label review is pending; this is not research-H confirmation.','','## Limits and implementation checks','', 'Candle implements GLiNER2 single-label classification only. The pinned model and official GLiNER2 2.0.0 reference agree on all 18 numerical probes, including the 512-token boundary, and 128 additional Unicode tokenization probes. This validates tested implementation behavior, not model accuracy. The 0.7 score gate is uncalibrated. Inputs over 512 encoded tokens, including schema, abstain without truncation; reserved special tokens also abstain. These cap/marker failures remain in the reported denominators.','',f"Candle public error/limit reasons: `{json.dumps(summary['systems']['candle']['public']['errors'],sort_keys=True)}`.",f"Candle contextual error/limit reasons: `{json.dumps(summary['systems']['candle']['contextual']['errors'],sort_keys=True)}`.",'','Language, upstream harmful labels, and length strata are retained separately in the JSON. There are no non-English positive cases; non-English controls measure false positives only. Harmful-labeled positives all come from ObfuscationAugmenter, so that stratum cannot establish general harmful-content performance.', '', 'CPU timing was collected while the two native model runs overlapped, so it is not an isolated throughput benchmark. No shipping model, threshold, or release authority changed. Public text stays in ignored cache. See the Jev scale report for language, harmful-label, source-selection and remote-provider limitations.','','## Open the app results','','```bash','.cache/framework-models-20260918/please-eval bench view --run .cache/framework-models-20260918/run-public','.cache/framework-models-20260918/please-eval bench view --run .cache/framework-models-20260918/run-contextual','```','', 'Each run also contains a standalone `report.html`. Viewing verifies saved identities and performs no inference.']
    for stem in [root/'comparison',a.publish]:
        for ext,data in [('.json',json.dumps(summary,indent=2)+'\n'),('.md','\n'.join(lines)+'\n')]:
            with Path(str(stem)+ext).open('x') as f: f.write(data)
    print(json.dumps(summary['systems'],indent=2))

if __name__=='__main__': main()
