from pathlib import Path
import json,sys,collections,hashlib
base=Path('.cache/detection-improvement-20260914'); root=base/'eval-cache/results'; a=root/sys.argv[1]; b=root/sys.argv[2]; out={}
for p in sorted(b.glob('*.jsonl')):
 if not (a/p.name).exists(): continue
 old=[json.loads(s) for s in (a/p.name).read_text().split('\n') if s]; new=[json.loads(s) for s in p.read_text().split('\n') if s]; x={r['id']:r for r in old}; y={r['id']:r for r in new}; assert len(x)==len(old) and len(y)==len(new) and x.keys()==y.keys()
 added=[k for k in x if y[k]['detected'] and not x[k]['detected']]; lost=[k for k in x if x[k]['detected'] and not y[k]['detected']]; covadd=[k for k in x if y[k].get('incomplete') and not x[k].get('incomplete')]; covlost=[k for k in x if x[k].get('incomplete') and not y[k].get('incomplete')]
 sources={}
 for source in sorted({r['source'] for r in old}):
  o=[r for r in old if r['source']==source]; n=[r for r in new if r['source']==source]; sources[source]={'n':len(o),'baseline_hits':sum(r['detected'] for r in o),'candidate_hits':sum(r['detected'] for r in n)}
 v={'n':len(x),'baseline_hits':sum(r['detected'] for r in old),'candidate_hits':sum(r['detected'] for r in new),'new_detections':added,'lost_detections':lost,'new_incomplete':covadd,'resolved_incomplete':covlost,'baseline_incomplete':sum(bool(r.get('incomplete')) for r in old),'candidate_incomplete':sum(bool(r.get('incomplete')) for r in new),'sources':sources,'new_detection_rules':dict(collections.Counter(q['rule_id'] for k in added for q in y[k]['reasons']))}; out[p.stem]=v
 print(p.stem, v['baseline_hits'],'->',v['candidate_hits'],'new',len(added),'lost',len(lost),'coverage',v['baseline_incomplete'],'->',v['candidate_incomplete'],v['new_detection_rules'])
path=base/f'{a.name}--{b.name}.json'; assert not path.exists(); path.write_text(json.dumps(out,indent=2)+'\n')
