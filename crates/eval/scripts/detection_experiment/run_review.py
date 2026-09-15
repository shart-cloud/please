"""Run native frozen evaluations into new, non-overwriting review evidence directories."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path('.cache/detection-review-response-20260914').resolve()
prior = Path('.cache/detection-improvement-20260914').resolve()
env = {**os.environ, 'PLEASE_EVAL_CACHE': str(root / 'eval-cache')}
phase = sys.argv[1]
binaries = ({'baseline': prior / 'frozen-corpus-baseline',
             'email-candidate': prior / 'candidate-freeze/frozen-corpus'} if phase == 'before'
            else {'withdrawn': Path('crates/eval/target/release/examples/frozen_corpus').resolve()})
packages = {'targeted-v2': root / 'targeted-inputs-v2.json',
            'reviewer': Path('.cache/detection-review-oi0bjm5x/inputs.json').resolve()}
if phase == 'after':
    packages.update({'development': prior / 'development.json',
                     'exposed-validation': prior / 'validation/corpus.json'})
for version, binary in binaries.items():
    for name, package in packages.items():
        content = package.read_bytes()
        data = json.loads(content)
        label = f'{version}-{name}'
        cmd = [str(binary), 'run', str(package), hashlib.sha256(content).hexdigest(),
               label, 'high', *data['rows']]
        with (root / f'{label}.log').open('x') as stream:
            result = subprocess.run(cmd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        print(label, result.returncode, flush=True)
        result.check_returncode()
