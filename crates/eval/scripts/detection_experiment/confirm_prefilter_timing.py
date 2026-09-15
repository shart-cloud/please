"""One fixed ten-pair timing confirmation on now-exposed holdout rows; no retuning."""
import json
import os
from pathlib import Path
import subprocess
import sys
from fresh_prefilter_holdout import candidate, digest, now, save


def main():
    root=Path(sys.argv[1]).resolve();frozen=candidate(root);package=root/'holdout/corpus.json'
    assert (root/'holdout/evaluation-complete.json').exists()
    save(root/'timing-confirmation-plan.json',{'started_utc':now(),'trials':10,'candidate_freeze_sha256':frozen,
        'input_sha256':digest(package),'purpose':'Resolve initial timing variance with a fixed batch, not a new unseen accuracy evaluation; no outcome-based stopping or retuning.'})
    env={**os.environ,'PLEASE_EVAL_CACHE':str(root/'eval-cache')};files={}
    for i in range(1,11):
        order=['baseline','candidate'] if i%2 else ['candidate','baseline']
        for v in order:
            label=f'timing-{v}-holdout-{i:02}';source=root/'sources/current.toml' if v=='baseline' else root/'candidate.toml'
            with (root/f'{label}.log').open('x') as f:
                subprocess.run([str(root/'bin/matching'),'run',str(package),digest(package),str(source),'normal',label],env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
            p=root/'eval-cache/results'/label/'experiment.json';files[str(p.relative_to(root))]=digest(p)
    save(root/'timing-confirmation-complete.json',{'finished_utc':now(),'candidate_freeze_sha256':candidate(root),
        'plan_sha256':digest(root/'timing-confirmation-plan.json'),'files':files,'candidate_retuned':False})
    print('Fixed ten-pair confirmation complete; candidate unchanged')


if __name__=='__main__':main()
