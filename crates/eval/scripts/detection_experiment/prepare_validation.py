from pathlib import Path
import importlib.util,json,collections,hashlib,datetime
root=Path.cwd(); out=root/'.cache/detection-improvement-20260914'
spec=importlib.util.spec_from_file_location('prepare',root/'crates/eval/scripts/prepare_dataset_holdout.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
cache=Path('/home/jg/.cache/please-eval')
paths=list((root/'crates/eval/manifests').glob('*.jsonl'))+list((root/'tests/fixtures').rglob('*.jsonl'))+list(cache.glob('*.jsonl'))+list((cache/'slices').glob('*.jsonl'))
# Include every prior capture manifest and its actual input bytes, including the exposed 600-case pack.
for base in [root/'.cache/lab-replay',root/'.cache/dataset-evaluation-20260911',root/'.cache/action-evidence-20260910',root/'.cache/fresh-evaluation-20260911']:
 paths+=list(base.rglob('captures.jsonl'))
p=root/'.cache/lab-replay/shart-ai-20260910/history-candidates.json'
if p.exists(): paths.append(p)
exact,folded,inventory=m.exposure(paths)
for p in paths:
 if p.name!='captures.jsonl': continue
 for row in m.json_records(p):
  if not isinstance(row,dict) or 'input_path' not in row: continue
  raw=(p.parent/row['input_path']).read_bytes(); exact.add(m.digest(raw)); folded.add(m.normalized(raw.decode('utf-8')))
# The original preparation indexed normalized exposure before selection; preserve that entire set too.
prior=root/'.cache/dataset-evaluation-20260911/plan-01'
folded.update(json.loads((prior/'normalized-exposed.json').read_text()))
exact.update((prior/'exposed.csv').read_text().splitlines()[1:])
# Only metadata/labels are inspected. The overfetch was prepared before the previous experiment;
# only the selected 600 were scanned. This is a within-source holdout, never a new-source claim.
export=prior/'candidates.json'; candidates=json.loads(export.read_text())
labels=collections.defaultdict(set)
for r in candidates: labels[m.normalized(r['prompt'])].add(r['prompt_adversarial'])
counts=collections.Counter(); selected=[]; skips=collections.Counter()
for r in sorted(candidates,key=lambda x:x['input_sha256']):
 assert m.digest(r['prompt'].encode())==r['input_sha256']
 key=(r['source'],r['prompt_adversarial']); norm=m.normalized(r['prompt'])
 if r['input_sha256'] in exact or norm in folded: skips['exposed_or_duplicate']+=1; continue
 if len(labels[norm])>1: skips['conflicting_normalized_labels']+=1; continue
 if counts[key]>=100: continue
 assert r['prompt_harmful']==0 and key in m.STRATA
 selected.append(r); counts[key]+=1; exact.add(r['input_sha256']); folded.add(norm)
assert all(counts[k]==100 for k in m.STRATA),counts
package=out/'validation'; package.mkdir()
(package/'rows.json').write_text(json.dumps(selected,ensure_ascii=False)+'\n')
m.save(package/'freeze.json',{'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'rows':len(selected),'strata':[[*k,v] for k,v in sorted(counts.items())],'selection':'ascending SHA256 within original six strata, exact and NFKC/case/whitespace exclusion, 100 each; upstream labels unchanged','exposure_inventory':inventory,'candidate_export_sha256':m.digest(export.read_bytes()),'files':{'rows.json':m.digest((package/'rows.json').read_bytes())},'script_sha256':m.digest(Path(__file__).read_bytes()),'detector_run':False,'payloads_inspected':False,'limitations':['Within-source unscanned overfetch from indexed previous experiment. Not a source-independent holdout.','No fresh indirect attack population; semantic and unrecorded inspection overlap cannot be ruled out.','Fresh outcomes are opened only after freezing the candidate; after opening they are exposed.'],'skipped':dict(skips)})
print('Fresh validation freeze:',m.digest((package/'freeze.json').read_bytes()),'strata:',counts)
