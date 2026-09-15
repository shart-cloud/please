"""Freeze the selected gate-only candidate before acquiring any holdout inputs."""
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tomllib
from prepare_prefilter_corrections import CONFLICTING


def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    root=Path(sys.argv[1]).resolve()
    if (root/'candidate-freeze.json').exists(): raise FileExistsError('candidate already frozen')
    source=Path('rules/builtin.toml').read_text()
    assert tomllib.loads(source)==tomllib.loads((root/'sources/precise.toml').read_text())
    before=tomllib.loads((root/'sources/current.toml').read_text()); after=tomllib.loads(source)
    for a,b in zip(before['rule'],after['rule']):
        assert a['id']==b['id']
        if a['id'] in CONFLICTING: assert a==b
        b['literals']=a['literals']
    assert before==after
    for name in ['syntax','development','exposed-validation']:
        result=json.loads((root/f'pre-freeze-equality-{name}.json').read_bytes())
        assert all(not s['full_different_ids'] for s in result['slices'].values()),name
    (root/'candidate.toml').write_text(source)
    (root/'bin').mkdir()
    for name,path in {'matching':'crates/eval/target/release/examples/matching_consistency',
                       'runtime':'crates/eval/target/release/examples/prefilter_runtime',
                       'verifier':'crates/eval/target/release/please-eval'}.items(): shutil.copy2(path,root/'bin'/name)
    source_files=[*Path('crates/core/src').rglob('*.rs'),*Path('crates/scan/src').rglob('*.rs'),
                  Path('crates/eval/examples/matching_consistency.rs'),Path('crates/eval/examples/prefilter_runtime.rs'),
                  Path('crates/core/tests/support/prefilter_reference.rs'),Path('Cargo.lock'),Path('crates/eval/Cargo.lock')]
    for p in source_files:
        target=root/'frozen-source'/p; target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
    files=[root/'candidate.toml',root/'sources/current.toml',root/'sources/precise.toml',
           *[p for p in (root/'bin').iterdir()],*[p for p in (root/'frozen-source').rglob('*') if p.is_file()]]
    record={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'selection':'precise; compact specific mandatory fragments, keep complete action verbs; no deferred-rule expansion',
            'development_selection_evidence':{p.name:digest(p) for p in [root/'attribution.json',root/'optimization.json',root/'precise.json',root/'deferred-deltas.json',*root.glob('pre-freeze-equality-*.json')]},
            'holdout_acquired':False,'files':{str(p.relative_to(root)):digest(p) for p in files}}
    with (root/'candidate-freeze.json').open('x') as f:json.dump(record,f,indent=2);f.write('\n')
    print('Candidate frozen:',digest(root/'candidate-freeze.json'))


if __name__=='__main__':main()
