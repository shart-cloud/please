#!/usr/bin/env python3
"""Freeze the validated Candle adapter into two native PLEASE bench experiments (no inference)."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

p=argparse.ArgumentParser()
p.add_argument('--out',type=Path,required=True)
p.add_argument('--jev-run',type=Path,required=True)
a=p.parse_args();root=a.out.resolve();jev=a.jev_run.resolve()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
write=lambda p,v:p.write_text(json.dumps(v,indent=2)+'\n')
parity=json.loads((root/'parity.result.json').read_text());assert parity['passed']
assert parity['reference_sha256']==sha(root/'parity.reference.jsonl')
assert parity['candle_sha256']==sha(root/'parity.candle.final.jsonl'), 'parity output incomplete or changed'
r=[json.loads(l) for l in (root/'fuzz.reference.jsonl').read_text().splitlines()]
c=[json.loads(l) for l in (root/'fuzz.candle.jsonl').read_text().splitlines()]
assert len(r)==len(c)==128 and all(x['id']==y['id'] and x['encoded']==y['encoded'] for x,y in zip(r,c)), 'tokenization parity failed'
assert not (root/'freeze.json').exists(), 'refuse to overwrite a frozen experiment'
recipe=json.loads((root/'gliner2.recipe.json').read_text())
recipe=dict(labels={s:[dict(name=k,description=v) for k,v in labels.items()] for s,labels in recipe['labels'].items()},threshold=recipe['threshold'],max_tokens=recipe['max_tokens'])
write(root/'candle.recipe.json',recipe)
binary=root/'please-eval-gliner2';shutil.copy2('crates/eval/target/release/please-eval-gliner2',binary);binary.chmod(0o555)
runner=root/'please-eval';shutil.copy2('crates/eval/target/release/please-eval',runner);runner.chmod(0o555)
args=['--bench','--lock',str(root/'gliner2.lock.json'),'--lock-sha256',sha(root/'gliner2.lock.json'),'--recipe',str(root/'candle.recipe.json'),'--recipe-sha256',sha(root/'candle.recipe.json')]
system=dict(schema_version='please-bench-system/v1',system_id='gliner2-candle',version='1',adapter_version='please-bench-jsonl/v1',configuration_identity='gliner2-base-v1/classification/candle-f32-cpu/v1',supported_surfaces=['artifact_detection','contextual_alignment'],requires_trusted_context=False,deterministic=True,review_authority='none',operating_point=dict(threshold='top probability >=0.7; 512 encoded tokens; no truncation',description='Exploratory uncalibrated single-label softmax; classification-only Candle implementation, validated against GLiNER2 2.0.0. No span extraction.'),identities=dict(model='fastino/gliner2-base-v1@79c3a777abc572b4767922f3916cf63fb5754df2',prompt=sha(root/'candle.recipe.json'),runtime='Candle 0.11 CPU f32; Rust tokenization; RAYON_NUM_THREADS=4'),adapter=dict(kind='subprocess',program=binary.name,args=args,sandbox_command=[],executable_sha256=sha(binary),environment={'RAYON_NUM_THREADS':'4'},network_capable=False),normalizers=[dict(normalizer_id='native-'+s,version='1',surface=s,mapping=dict(kind='native_v1',positive_labels=['injection'] if s=='artifact_detection' else [],negative_labels=['benign'] if s=='artifact_detection' else [])) for s in recipe['labels']])
write(root/'candle.system.json',system)
for arm in ['public','contextual']:
    shutil.copytree(jev/arm,root/arm)
    exp=dict(schema_version='please-bench-experiment/v1',experiment_id='gliner2-candle-'+arm,version='1',pack_path=arm+'/pack.json',system_paths=['candle.system.json'],exposure_paths=[],repetitions=1,execution_mode='offline',limits=dict(max_input_bytes=32768,max_request_bytes=131072,max_stdout_bytes=1048576,max_stderr_bytes=131072,startup_timeout_ms=60000,case_timeout_ms=30000,max_restarts=0,max_in_flight=1))
    write(root/(arm+'.experiment.json'),exp)
files=['please-eval-gliner2','please-eval','gliner2.lock.json','candle.recipe.json','candle.system.json','public.experiment.json','contextual.experiment.json','parity.reference.jsonl','parity.candle.final.jsonl','parity.result.json','fuzz.reference.jsonl','fuzz.candle.jsonl','requirements.actual.txt']
write(root/'freeze.json',dict(files={f:sha(root/f) for f in files},packs={arm:sha(jev/arm/'pack.json') for arm in ['public','contextual']},parity=parity,tokenization_fuzz_cases=128,scope='Development benchmark; uses the same preselected Jev scale packs; no GLiNER2 corpus inference before freeze.'))
print('Frozen native PLEASE Candle experiments:',root)
