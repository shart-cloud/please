from pathlib import Path
import subprocess,sys,json,statistics,re
p=Path('.cache/detection-improvement-20260914')
orders=[['baseline','candidate'],['candidate','baseline'],['baseline','candidate']]
for i,order in enumerate(orders,1):
 for which in order:
  binary=p/('frozen-corpus-baseline' if which=='baseline' else 'candidate-freeze/frozen-corpus')
  label=f'final-{which}-{i:02d}'
  subprocess.run([sys.executable,str(p/'measure.py'),str(binary),label],check=True,stdout=subprocess.DEVNULL)
  result=json.loads((p/f'{label}-measurement.json').read_text())
  print(label,result['elapsed_seconds'],flush=True)
summary={}
for which in ['baseline','candidate']:
 runs=[json.loads((p/f'final-{which}-{i:02d}-measurement.json').read_text()) for i in range(1,4)]
 slices={}
 for i in range(1,4):
  for name,seconds in re.findall(r'^([a-z_]+): \d+/\d+; ([0-9.]+)s$',(p/f'final-{which}-{i:02d}.log').read_text(),re.M): slices.setdefault(name,[]).append(float(seconds))
 summary[which]={'elapsed_seconds':[r['elapsed_seconds'] for r in runs],'median_seconds':statistics.median(r['elapsed_seconds'] for r in runs),'per_slice_seconds':slices,'per_slice_median_seconds':{k:statistics.median(v) for k,v in slices.items()}}
summary['change_percent']=(summary['candidate']['median_seconds']/summary['baseline']['median_seconds']-1)*100
(p/'performance.json').write_text(json.dumps(summary,indent=2)+'\n'); print('Median total change percent:',summary['change_percent'],flush=True)
