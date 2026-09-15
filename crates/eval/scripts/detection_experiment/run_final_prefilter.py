"""Replay the frozen performance candidate and baseline, including the one-shot holdout.
Usage: python3 run_final_prefilter.py ROOT
"""
import json
import os
from pathlib import Path
import subprocess
import sys
from fresh_prefilter_holdout import candidate, digest, now, save


def main():
    root=Path(sys.argv[1]).resolve(); frozen=candidate(root)
    holdout=json.loads((root/'holdout/package-identity.json').read_bytes())
    assert holdout['candidate_freeze_sha256']==frozen
    assert digest(root/'holdout/corpus.json')==holdout['corpus_sha256']
    packages={'syntax':Path('.cache/matching-consistency-20260915/syntax.json').resolve(),
              'development':Path('.cache/detection-improvement-20260914/development.json').resolve(),
              'exposed-validation':Path('.cache/detection-improvement-20260914/validation/corpus.json').resolve(),
              'holdout':root/'holdout/corpus.json'}
    save(root/'final-identities.json',{'started_utc':now(),'candidate_freeze_sha256':frozen,
        'packages':{k:{'path':str(p),'sha256':digest(p)} for k,p in packages.items()}})
    save(root/'holdout/exposure.json',{'started_utc':now(),'status':'evaluation started; exposed for future tuning',
                                      'candidate_freeze_sha256':frozen,'corpus_sha256':holdout['corpus_sha256']})
    env={**os.environ,'PLEASE_EVAL_CACHE':str(root/'eval-cache')}
    sources={'baseline':root/'sources/current.toml','candidate':root/'candidate.toml','shipping':root/'candidate.toml'}
    def run(args,label):
        with (root/f'{label}.log').open('x') as log: subprocess.run(args,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        print(label,flush=True)
    for name,p in packages.items():
        trials=range(1,4) if name in ['development','holdout'] else [1]
        for t in trials:
            order=['baseline','candidate'] if t%2 else ['candidate','baseline']
            if t==1:order+=['shipping']
            for v in order:
                label=f'final-{v}-{name}-{t}'
                run([str(root/'bin/matching'),'run',str(p),digest(p),str(sources[v]),'shipping' if v=='shipping' else 'normal',label],label)
        run([str(root/'bin/matching'),'pair',str(p),digest(p),str(sources['baseline']),str(sources['candidate']),str(root/f'full-final-{name}.json')],f'full-final-{name}')
    run([str(root/'bin/runtime'),str(sources['baseline']),str(sources['candidate']),str(root/'final-runtime.json')],'final-runtime')
    save(root/'holdout/evaluation-complete.json',{'finished_utc':now(),'candidate_freeze_sha256':candidate(root),'candidate_retuned':False})
    files=[root/'candidate-freeze.json',root/'final-identities.json',root/'attribution-plan.json',root/'attribution.json',
        root/'optimization.json',root/'precise.json',root/'layout.json',root/'precise-layout.json',
        root/'final-runtime.json',root/'deferred-plan.json',root/'paired-controls-sha256.txt',
        *root.glob('full-final-*.json'),*[p for p in (root/'holdout').rglob('*.json')],*[p for p in (root/'holdout-plan').glob('*.json')],
        *[p for p in (root/'eval-cache/results').glob('*/experiment.json')]]
    save(root/'evidence-sha256.json',{str(p.relative_to(root)):digest(p) for p in files})


if __name__=='__main__':main()
