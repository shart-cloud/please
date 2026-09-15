"""Offline experiment, refusing to overwrite evidence. Run from repository root.

Usage: python3 run_matching_consistency.py ROOT
ROOT must contain baseline.toml, safe-corrections.toml, all-corrections.toml,
and syntax.json (see the reproduction guide for the preparation commands).
Existing development/validation inputs are reused as exposed regression corpora.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def main():
    root = Path(sys.argv[1]).resolve()
    binaries = {}
    (root/'bin').mkdir(exist_ok=True)
    for name, path in {
        'matching': 'crates/eval/target/release/examples/matching_consistency',
        'runtime': 'crates/eval/target/release/examples/prefilter_runtime',
        'verifier': 'crates/eval/target/release/please-eval',
    }.items():
        target = root/'bin'/name
        if target.exists(): raise FileExistsError(target)
        shutil.copy2(path, target)
        binaries[name] = {'path': str(target), 'sha256': digest(target)}
    packages = {'syntax': root/'syntax.json',
                'development': Path('.cache/detection-improvement-20260914/development.json').resolve(),
                'exposed-validation': Path('.cache/detection-improvement-20260914/validation/corpus.json').resolve()}
    sources = {'baseline': root/'baseline.toml', 'accepted': root/'safe-corrections.toml',
               'corrected': root/'all-corrections.toml'}
    configs = {'baseline': ('baseline', 'normal'), 'accepted': ('accepted', 'normal'),
               'reference': ('baseline', 'reference'), 'corrected': ('corrected', 'normal'),
               'shipping': ('accepted', 'shipping')}
    save(root/'experiment-identities.json', {
        'binaries': binaries,
        'packages': {k: {'path': str(v), 'sha256': digest(v)} for k,v in packages.items()},
        'sources': {k: {'path': str(v), 'sha256': digest(v)} for k,v in sources.items()},
        'host': platform.platform(),
        'source_files': {str(p):digest(p) for p in [
            *Path('crates/core/src').rglob('*.rs'), *Path('crates/scan/src').rglob('*.rs'),
            Path('crates/eval/examples/matching_consistency.rs'),
            Path('crates/eval/examples/prefilter_runtime.rs'),
            Path('crates/core/tests/support/prefilter_reference.rs'),
            Path('Cargo.lock'), Path('crates/eval/Cargo.lock')]},
    })
    env = {**os.environ, 'PLEASE_EVAL_CACHE': str(root/'eval-cache')}
    def run(args, label):
        with (root/f'{label}.log').open('x') as log:
            subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        print(label, flush=True)
    # All corpus timings use this one frozen executable, sequentially, rotating order.
    for name, package in packages.items():
        for trial in range(1, 4 if name == 'development' else 2):
            order = ['baseline', 'accepted', 'reference']
            order = order[trial-1:] + order[:trial-1]
            if trial == 1: order += ['corrected', 'shipping']
            for version in order:
                source, mode = configs[version]
                label = f'{version}-{name}-{trial}'
                run([binaries['matching']['path'], 'run', str(package), digest(package),
                     str(sources[source]), mode, label], label)
        # Full in-memory reasons, suppression, transform chains and gap details,
        # beyond the native row projection. No upstream prompt text is published.
        for label, left, right in [('accepted', 'baseline', str(sources['accepted'])),
                                    ('corrected', 'corrected', 'reference'),
                                    ('shipping', 'accepted', 'shipping')]:
            output = root/f'full-{label}-{name}.json'
            run([binaries['matching']['path'], 'pair', str(package), digest(package),
                 str(sources[left]), right, str(output)], f'full-{label}-{name}')
    run([binaries['runtime']['path'], str(sources['baseline']), str(sources['accepted']),
         str(root/'runtime.json')], 'runtime')
    # Bind sidecars separately; native completion already binds result rows.
    save(root/'sidecar-sha256.json', {str(p.relative_to(root)):digest(p) for p in [
        root/'experiment-identities.json', root/'runtime.json', *root.glob('full-*.json'),
        *[root/'eval-cache/results'/f'{v}-{n}-{t}'/'experiment.json'
          for n in packages for v in configs
          for t in (range(1,4) if n=='development' and v in ['baseline','accepted','reference'] else [1])]]})


if __name__ == '__main__': main()
