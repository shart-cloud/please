"""Freeze-first fresh within-source holdout. No prompt text is printed.
Usage: python3 fresh_prefilter_holdout.py plan|expand|available|query|freeze ROOT
plan/query/freeze all verify the candidate freeze; no detector is invoked here.
"""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

spec=importlib.util.spec_from_file_location('holdout',Path(__file__).resolve().parents[1]/'prepare_dataset_holdout.py')
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)


def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,value):
    with p.open('x') as f: json.dump(value,f,indent=2); f.write('\n')


def candidate(root):
    path=root/'candidate-freeze.json'; frozen=json.loads(path.read_bytes())
    for name,sha in frozen['files'].items():
        if digest(root/name)!=sha: raise ValueError(f'frozen candidate changed: {name}')
    return digest(path)


def main():
    command=sys.argv[1]; root=Path(sys.argv[2]).resolve(); freeze_sha=candidate(root)
    plan=root/'holdout-plan'
    if command=='plan':
        repo=Path.cwd(); cache=Path('/home/jg/.cache/please-eval')
        paths=set((repo/'.cache').rglob('*.json')) | set((repo/'.cache').rglob('*.jsonl'))
        paths={p for p in paths if not p.is_relative_to(root)}
        paths.update((repo/'tests/fixtures').rglob('*.jsonl'))
        paths.update((repo/'crates/eval/manifests').glob('*.jsonl'))
        paths.update((repo/'crates/core/tests/data').glob('*.jsonl'))
        paths.update(cache.glob('*.jsonl')); paths.update((cache/'slices').glob('*.jsonl'))
        paths.update((root/'deferred').glob('pair-*.json')); paths.add(root/'attribution-inputs.json')
        # Identical historical snapshots are indexed once, retaining their first
        # path and byte digest. Include unused overfetch conservatively too.
        unique={}
        for p in sorted(paths): unique.setdefault(digest(p),p)
        # Carrier source templates contain deliberate non-JSON insertion markers.
        # Index their raw text; actual materialized carrier inputs are indexed
        # from the frozen corpus packages and captures, not parsed from templates.
        templates=[p for p in unique.values() if '/crates/eval/corpus/carriers/' in p.as_posix()]
        exact,folded,inventory=h.exposure([p for p in unique.values() if p not in templates])
        for p in templates:
            raw=p.read_bytes(); exact.add(h.digest(raw)); folded.add(h.normalized(raw.decode('utf-8')))
            inventory.append({'path':str(p),'sha256':h.digest(raw),'kind':'raw carrier source template'})
        for p in unique.values():
            if p.name=='normalized-exposed.json': folded.update(json.loads(p.read_bytes()))
            if p.name=='captures.jsonl':
                for row in h.json_records(p):
                    if isinstance(row,dict) and 'input_path' in row:
                        input_path=p.parent/row['input_path']; raw=input_path.read_bytes()
                        exact.add(h.digest(raw)); folded.add(h.normalized(raw.decode('utf-8')))
                        inventory.append({'path':str(input_path.resolve()),'sha256':h.digest(raw)})
        for p in (repo/'.cache').rglob('exposed.csv'):
            if not p.is_relative_to(root): exact.update(p.read_text().splitlines()[1:])
        pairs=json.loads(Path('crates/core/tests/data/deferred_prefilter_pairs.json').read_text())
        for row in pairs['pairs']:
            for key in ['attack','ordinary']:
                exact.add(h.digest(row[key].encode())); folded.add(h.normalized(row[key]))
        plan.mkdir()
        (plan/'exposed.csv').write_text('sha256\n'+'\n'.join(sorted(exact))+'\n')
        save(plan/'normalized-exposed.json',sorted(folded)); save(plan/'exposure-inventory.json',inventory)
        exclusions=str(plan/'exposed.csv').replace("'","''")
        strata=' OR '.join(f"(source='{s}' AND prompt_adversarial={label})" for s,label in h.STRATA)
        sql=f"""WITH all_rows AS (
 SELECT sha256(prompt) AS input_sha256, prompt, source, language, prompt_type,
 prompt_adversarial, prompt_harmful, coalesce(attack_technique,'') AS attack_technique,
 min(prompt_adversarial) OVER (PARTITION BY sha256(prompt)) AS min_label,
 max(prompt_adversarial) OVER (PARTITION BY sha256(prompt)) AS max_label
 FROM 'hf://datasets/{h.DATASET}@{h.REVISION}/**/*.parquet' WHERE prompt IS NOT NULL
), eligible AS (
 SELECT * EXCLUDE(min_label,max_label) FROM all_rows
 WHERE min_label=max_label AND prompt_harmful=0 AND ({strata})
 AND input_sha256 NOT IN (SELECT sha256 FROM read_csv('{exclusions}',header=true))
 QUALIFY row_number() OVER (PARTITION BY input_sha256 ORDER BY source,language,prompt_type)=1
)
SELECT * FROM eligible
QUALIFY row_number() OVER (PARTITION BY source,prompt_adversarial ORDER BY input_sha256)<=400
ORDER BY input_sha256
"""
        (plan/'select.sql').write_text(sql)
        save(plan/'plan.json',{'format_version':1,'created_utc':now(),'candidate_freeze_sha256':freeze_sha,
            'dataset':h.DATASET,'revision':h.REVISION,'strata':[{'source':s,'prompt_adversarial':v,'count':100} for s,v in h.STRATA],
            'selection':'Ascending input SHA256 after exact exposure exclusion, fourfold overfetch; then NFKC/case/whitespace deduplication and conflicting-label exclusion.',
            'source_policy':'untrusted_user_input','control_role':'user','label_authority':'Unmodified upstream adversarial labels; harmful=0.',
            'exact_exposure_hashes':len(exact),'normalized_exposure_hashes':len(folded),
            'files':{n:digest(plan/n) for n in ['exposed.csv','normalized-exposed.json','exposure-inventory.json','select.sql']},
            'limitations':['Fresh relative to indexed local exposure, including previous unused overfetch. Unrecorded historical inspection cannot be ruled out.',
                           'Within-source direct-prompt holdout; not new-source or fresh indirect-injection evidence.',
                           'Upstream labels, not application-specific authorization or independently owner-reviewed labels.',
                           'Semantic paraphrases and model-training overlap are not excluded.']})
        print('Holdout selection preregistered after candidate freeze;',len(exact),'exact exclusions;',len(folded),'normalized exclusions')
    elif command=='expand':
        # Blinded acquisition amendment only: keep the target selection and frozen
        # detector unchanged when normalized deduplication exhausts the overfetch.
        if (root/'holdout').exists(): raise ValueError('cannot amend after holdout selection')
        initial=root/'holdout-plan-initial'
        meta=json.loads((plan/'plan.json').read_bytes())
        assert meta['candidate_freeze_sha256']==freeze_sha
        sql=(plan/'select.sql').read_text()
        assert sql.count('<=400\n')==1
        plan.rename(initial);plan.mkdir()
        for name in ['exposed.csv','normalized-exposed.json','exposure-inventory.json']:
            (plan/name).write_bytes((initial/name).read_bytes())
        (plan/'select.sql').write_text(sql.replace('<=400\n','<=4000\n'))
        meta.update(created_utc=now(),selection=meta['selection'].replace('fourfold','fortyfold'))
        meta['amendment']={'initial_plan_sha256':digest(initial/'plan.json'),
            'reason':'Initial 400-row overfetch left Gandalf-Ignore at 87/100 after normalized exclusions; no detector outcomes opened.',
            'target_strata_and_order_unchanged':True}
        meta['files']={name:digest(plan/name) for name in meta['files']}
        save(plan/'plan.json',meta)
        print('Blinded overfetch amendment saved; candidate and 600-row target unchanged')
    elif command=='available':
        if (root/'holdout').exists(): raise ValueError('cannot amend after selection')
        import collections
        meta=json.loads((plan/'plan.json').read_bytes());query=json.loads((plan/'query-result.json').read_bytes())
        rows=json.loads((plan/query['file']).read_bytes())
        exact=set((plan/'exposed.csv').read_text().splitlines()[1:]);folded=set(json.loads((plan/'normalized-exposed.json').read_bytes()))
        labels=collections.defaultdict(set)
        for r in rows:labels[h.normalized(r['prompt'])].add(r['prompt_adversarial'])
        counts=collections.Counter()
        for r in sorted(rows,key=lambda r:r['input_sha256']):
            norm=h.normalized(r['prompt']);key=r['source'],r['prompt_adversarial']
            if r['input_sha256'] in exact or norm in folded or len(labels[norm])>1:continue
            folded.add(norm);counts[key]+=1
        changes=[]
        for s in meta['strata']:
            available=counts[s['source'],s['prompt_adversarial']]
            if available<s['count']:
                assert (s['source'],s['prompt_adversarial'])==('Gandalf-Ignore',1) and available>0
                # Establish exhaustion, not just a still-too-small overfetch.
                assert sum(r['source']==s['source'] and r['prompt_adversarial']==s['prompt_adversarial'] for r in rows)<4000
                changes.append({'source':s['source'],'prompt_adversarial':s['prompt_adversarial'],'requested':s['count'],'available':available})
                s['count']=available
        assert changes
        expanded=root/'holdout-plan-expanded';old_sha=digest(plan/'plan.json');plan.rename(expanded);plan.mkdir()
        for name in [*meta['files'],query['file'],'query-result.json']:(plan/name).write_bytes((expanded/name).read_bytes())
        meta['created_utc']=now()
        meta['availability_amendment']={'acquisition_plan_sha256':old_sha,'changes':changes,
            'reason':'Exhausted stratum after conservative exposure/deduplication; retain all remaining rows. Candidate and ordering unchanged; no detector outcomes opened.'}
        save(plan/'plan.json',meta)
        print('Availability-capped holdout target:',sum(s['count'] for s in meta['strata']))
    elif command=='query':
        meta=json.loads((plan/'plan.json').read_bytes())
        if meta['candidate_freeze_sha256']!=freeze_sha: raise ValueError('candidate freeze differs from plan')
        for name,sha in meta['files'].items():
            if digest(plan/name)!=sha: raise ValueError('selection plan changed')
        if (plan/'query-result.json').exists(): raise FileExistsError('holdout already acquired')
        attempt=len(list(plan.glob('candidates-*.json')))+1
        output=plan/f'candidates-{attempt:02}.json'; started=now()
        with output.open('x') as out,(plan/f'query-{attempt:02}.log').open('x') as err:
            subprocess.run(['hf','datasets','sql',(plan/'select.sql').read_text(),'--format','json'],stdout=out,stderr=err,check=True)
        save(plan/'query-result.json',{'file':output.name,'sha256':digest(output),'started_utc':started,'finished_utc':now(),
                                     'candidate_freeze_sha256':freeze_sha,'plan_sha256':digest(plan/'plan.json')})
        print('Fresh holdout export acquired without displaying prompts or invoking a detector')
    elif command=='freeze':
        result=json.loads((plan/'query-result.json').read_bytes()); exported=plan/result['file']
        if result['candidate_freeze_sha256']!=freeze_sha or result['sha256']!=digest(exported): raise ValueError('query identity differs')
        meta=json.loads((plan/'plan.json').read_bytes())
        expected=meta.get('availability_amendment',{}).get('acquisition_plan_sha256',digest(plan/'plan.json'))
        if result['plan_sha256']!=expected: raise ValueError('acquisition plan identity differs')
        h.freeze(plan,exported,root/'holdout')
        selected=[json.loads(line) for line in (root/'holdout/provenance.jsonl').read_text().splitlines()]
        package=json.loads(Path('.cache/detection-improvement-20260914/development.json').read_bytes())
        corpus=package['corpus']; corpus['slice']=[];corpus['excluded_source']=[];rows={}
        for label,sid in [(1,'holdout_positive'),(0,'holdout_benign')]:
            corpus['slice'].append({'id':sid,'kind':'positive' if label else 'negative','label':sid,
                'origin':{'kind':'query','sql':(plan/'select.sql').read_text()},'gate_eligible':not label,
                'excluded_sources':[],'baseline_permille':None,'notes':'Fresh within-source holdout selected only after candidate freeze; upstream labels unchanged.'})
            rows[sid]=[{'id':r['input_sha256'],'text':(root/'holdout/inputs'/f'{r["id"]}.bin').read_bytes().decode('utf-8'),
                        'source':r['source'],'language':r['language']} for r in selected if r['prompt_adversarial']==label]
        save(root/'holdout/corpus.json',{'corpus':corpus,'rows':rows})
        save(root/'holdout/package-identity.json',{'corpus_sha256':digest(root/'holdout/corpus.json'),
            'freeze_sha256':digest(root/'holdout/freeze.json'),'candidate_freeze_sha256':freeze_sha,'created_utc':now(),'detector_run':False})
    else: raise ValueError('expected plan, query or freeze')


if __name__=='__main__':main()
