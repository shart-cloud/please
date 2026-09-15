"""Freeze individual-addition and leave-one-out literal ablations, using exposed data only.
Usage: python3 prepare_prefilter_attribution.py ROOT [PRE_COMPACTION_RULES]
Defaults to the preserved thirteen-correction snapshot, not today's checkout.
"""
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib


def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def literals(source, rid, values):
    pattern=r'(^id = "'+re.escape(rid)+r'".*?^literals = )\[.*?\]'
    source,n=re.subn(pattern,lambda m:m[1]+json.dumps(values,ensure_ascii=False),source,count=1,flags=re.M|re.S)
    assert n==1
    return source


def main():
    root=Path(sys.argv[1]).resolve(); root.mkdir(); (root/'sources').mkdir()
    previous=Path('docs/research/matching-consistency-2026-09-15/baseline.toml').read_text()
    current=Path(sys.argv[2] if len(sys.argv)>2 else 'docs/research/matching-consistency-2026-09-15/accepted.toml').read_text()
    old={r['id']:r for r in tomllib.loads(previous)['rule']}
    new={r['id']:r for r in tomllib.loads(current)['rule']}
    changed=[rid for rid in old if old[rid]['literals']!=new[rid]['literals']]
    assert len(changed)==13
    sources={'previous':previous,'current':current}
    for i,rid in enumerate(changed):
        sources[f'add-{i:02}']=literals(previous,rid,new[rid]['literals'])
        sources[f'remove-{i:02}']=literals(current,rid,old[rid]['literals'])
    for k,s in sources.items(): (root/'sources'/f'{k}.toml').write_text(s)
    configs=[{'label':k,'source':str(root/'sources'/f'{k}.toml')} for k in sources]
    (root/'configs.json').write_text(json.dumps(configs,indent=2)+'\n')
    development=Path('.cache/detection-improvement-20260914/development.json')
    package=json.loads(development.read_bytes())
    # Preregistered exposed workload: at most 128 rows per existing slice by a salted
    # content hash. Not a fresh holdout and not representative population weights.
    package['rows']={sid:sorted(rows,key=lambda r:hashlib.sha256(('prefilter-cost-v1\0'+r['id']).encode()).hexdigest())[:128] for sid,rows in package['rows'].items()}
    for name,unit in [('ordinary_prose','The spring garden contains red flowers and a stone path. Birds rest beside the pond. '),
                       ('many_literals','ignore revised system forget assistant tool_output reveal share grant transfer curl ')]:
        package['rows'][name]=[{'id':f'{name}-{i}','text':(unit*210)[:16384]} for i in range(20)]
    (root/'attribution-inputs.json').write_text(json.dumps(package,ensure_ascii=False)+'\n')
    record={'changed_rules':changed,'development_sha256':digest(development),
            'input_sha256':digest(root/'attribution-inputs.json'),'sample_cap_per_slice':128,
            'source_sha256':{k:digest(root/'sources'/f'{k}.toml') for k in sources}}
    (root/'attribution-plan.json').write_text(json.dumps(record,indent=2)+'\n')
    print(record['input_sha256'])


if __name__=='__main__': main()
