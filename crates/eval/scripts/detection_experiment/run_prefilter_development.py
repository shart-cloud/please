"""Reproduce attribution, candidate selection evidence and isolated deferred screens.
Run after preparing ROOT and building the documented examples. Does not touch a holdout.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from prepare_prefilter_candidates import main as prepare_candidates
from role_marker_follow_up import compare
from verified_role_marker_results import verified_run


def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    root=Path(sys.argv[1]).resolve();prepare_candidates()
    binary=root/'attribution-binary'
    if binary.exists():raise FileExistsError(binary)
    shutil.copy2('crates/eval/target/release/examples/prefilter_attribution',binary)
    (root/'attribution-binary.sha256').write_text(digest(binary)+'\n')
    inputs=root/'attribution-inputs.json';sha=digest(inputs)
    def run(cmd,label,env=None):
        with (root/f'{label}.log').open('x') as f:subprocess.run(list(map(str,cmd)),stdout=f,stderr=subprocess.STDOUT,env=env,check=True)
        print(label,flush=True)
    run(['target/release/examples/prefilter_layout',root/'all-layout-configs.json',root/'layout.json'],'layout')
    run(['target/release/examples/prefilter_layout',root/'precise-configs.json',root/'precise-layout.json'],'precise-layout')
    for label,configs in [('attribution','configs.json'),('optimization','optimization-configs.json'),('precise','precise-configs.json')]:
        run([binary,inputs,sha,root/configs,root/f'{label}.json'],label)
    # Replay the documented selected candidate. Do not choose a new candidate
    # automatically from noisy timing minima, and never select from holdout outcomes.
    matching=Path('crates/eval/target/release/examples/matching_consistency').resolve()
    for name,p in {'syntax':Path('.cache/matching-consistency-20260915/syntax.json'),
                   'development':Path('.cache/detection-improvement-20260914/development.json'),
                   'exposed-validation':Path('.cache/detection-improvement-20260914/validation/corpus.json')}.items():
        run([matching,'pair',p,digest(p),root/'sources/current.toml',root/'sources/precise.toml',root/f'pre-freeze-equality-{name}.json'],f'pre-freeze-equality-{name}')
    (root/'paired-controls-sha256.txt').write_text(digest('crates/core/tests/data/deferred_prefilter_pairs.json')+'\n')
    env={**os.environ,'PLEASE_EVAL_CACHE':str(root/'eval-cache')};deltas={}
    for pair in json.loads((root/'deferred-plan.json').read_text()):
        p=Path(pair['package']);i=pair['index'];rows={}
        for version,source in [('baseline',root/'sources/current.toml'),('broader',Path(pair['candidate']))]:
            label=f'deferred-{i}-{version}'
            run([matching,'run',p,digest(p),source,'normal',label],label,env)
            rows[version]=verified_run(root/'eval-cache/results'/label,'crates/eval/target/release/please-eval')[0]
        deltas[pair['rule']]={sid:compare(rows['baseline'][sid],rows['broader'][sid]) for sid in ['attack','ordinary']}
    with (root/'deferred-deltas.json').open('x') as f:json.dump(deltas,f,indent=2);f.write('\n')


if __name__=='__main__':main()
