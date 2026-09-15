from pathlib import Path
import json,hashlib,copy,subprocess,os,datetime
root=Path.cwd(); p=root/'.cache/detection-improvement-20260914'; v=p/'validation'
hashof=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
assert hashof(v/'freeze.json')=='d306df3fb614657bf8600261069fee66f5245408c0a74413bcbd8c4caf9f25e4'
meta=json.loads((v/'freeze.json').read_text()); assert hashof(v/'rows.json')==meta['files']['rows.json']
assert hashof(p/'candidate-freeze/freeze.json')=='48653f39a26bdaf03b8d46a57b7d9006433fdc3622eb35b3413d834e71c88009'
candidate=json.loads((p/'candidate-freeze/freeze.json').read_text())
for name,expected in candidate['files'].items(): assert hashof(p/'candidate-freeze'/name)==expected
f=json.loads((p/'development.json').read_text()); s=copy.deepcopy(f['corpus']); s['slice']=[]; rows={}
raw=json.loads((v/'rows.json').read_text())
for positive in [True,False]:
 id='validation_positive' if positive else 'validation_benign'; template=copy.deepcopy(next(x for x in f['corpus']['slice'] if x['id']==('pos_stratified' if positive else 'neg_clean')))
 template.update(id=id,label='Frozen previously unscanned within-source validation: '+('attack' if positive else 'benign'),baseline_permille=None,notes='Ascending SHA256; 100 per source/label stratum; labels inherited unchanged. See validation/freeze.json. Direct-prompt data; not a source-independent or fresh indirect holdout.')
 template['origin']={'kind':'query','sql':'-- Frozen local selection from September 11 pinned upstream overfetch; see validation/freeze.json and its candidate_export_sha256. No acquisition during evaluation.'}
 s['slice'].append(template)
 rows[id]=[{'id':r['input_sha256'],'source':r['source'],'text':r['prompt'],'language':r['language']} for r in raw if bool(r['prompt_adversarial'])==positive]
 assert len(rows[id])==300
package=v/'corpus.json'; assert not package.exists(); package.write_text(json.dumps({'corpus':s,'rows':rows},ensure_ascii=False)+'\n'); sha=hashof(package)
(v/'corpus.sha256').write_text(sha+'\n')
exposure={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'freeze_sha256':hashof(v/'freeze.json'),'candidate_freeze_sha256':hashof(p/'candidate-freeze/freeze.json'),'status':'evaluation_started','payloads_manually_inspected':False}
assert not (v/'exposure.json').exists(); (v/'exposure.json').write_text(json.dumps(exposure,indent=2)+'\n')
commands=[]
for binary,label in [(p/'frozen-corpus-baseline','baseline-validation-01'),(p/'candidate-freeze/frozen-corpus','candidate-validation-01')]:
 cmd=[str(binary),'run',str(package),sha,label,'high','validation_positive','validation_benign']; commands.append({'command':cmd,'binary_sha256':hashof(binary)})
 with (p/f'{label}.log').open('x') as log: subprocess.run(cmd,env=dict(os.environ,PLEASE_EVAL_CACHE=str(p/'eval-cache')),stdout=log,stderr=subprocess.STDOUT,check=True)
exposure.update(status='evaluated; exposed for future tuning',finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),commands=commands); (v/'exposure.json').write_text(json.dumps(exposure,indent=2)+'\n')
print('Validation complete; reports saved. Frozen inputs SHA256',sha)
