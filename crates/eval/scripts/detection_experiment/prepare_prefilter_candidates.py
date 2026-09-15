"""Generate gate-only alternatives and independently paired deferred-rule probes.
Run after prepare_prefilter_attribution.py: python3 prepare_prefilter_candidates.py ROOT
Existing identical files are retained; differing evidence is never replaced.
"""
import base64
import json
from pathlib import Path
import re
import sys
import tomllib
from prepare_prefilter_attribution import literals


def write(path, value):
    if path.exists():
        if path.read_text()!=value: raise ValueError(f'refusing to replace {path}')
    else: path.write_text(value)


def stable_fragment(literal):
    # ASCII letters other than s/k have no additional non-ASCII simple-fold
    # equivalents in these regex literals. Every original literal contains the
    # chosen fragment even when s/k are written as long-s/Kelvin sign.
    return max(re.split('[sSkKſK]',literal),key=lambda s:(len(s),s))


def alternatives(current, changed):
    rules={r['id']:r for r in tomllib.loads(current)['rule']}
    def apply(replacements):
        source=current
        for rid,values in replacements.items(): source=literals(source,rid,sorted(set(values)))
        return source
    nouns={'override.forget_everything':['everything'],'override.new_instructions_follow':['truction']}
    compacted={rid:sorted({stable_fragment(l) for l in rules[rid]['literals']}) for rid in changed}
    assert all(all(l for l in ls) for ls in compacted.values())
    return {'nouns':apply(nouns),
            'role-tails':apply({'boundary.forged_role_marker':['ystem','yſtem','istant','iſtant']}),
            'compact':apply({**compacted,**nouns}), 'compact-no-nouns':apply(compacted),
            'compact-selective':apply({**compacted,**nouns,'boundary.forged_role_marker':['ystem','yſtem','istant','iſtant']})}


def precise_alternatives(current):
    # Retain complete action verbs: shortening send to end admits too much prose.
    # Compact the large case-variant families with specific mandatory fragments.
    replacements={
        'override.disregard_prior':['bypa','disregard','diſregard','forget','ignore','override'],
        'override.new_identity':['act a','you are no longer','you are now'],
        'boundary.forged_role_marker':['ystem','yſtem','istant','iſtant'],
        'boundary.forged_tool_result':['tool_result','tool_reſult','function_result','function_reſult','tool_output'],
        'boundary.delimiter_breakout':['begin','end of'],
        'solicitation.system_prompt':['initial prompt','tem prompt','your instruction','your inſtruction','your prompt'],
        'external_action.remote_execution':['curl','iex','invoke-webreque','invoKe-webreque','iwr','wget'],
    }
    def apply(values):
        s=current
        for rid,ls in values.items(): s=literals(s,rid,sorted(set(ls)))
        return s
    nouns={'override.forget_everything':['everything'], 'override.new_instructions_follow':['instruction','inſtruction']}
    return {'precise':apply({**replacements,**nouns}),
            'precise-dashes':apply({**replacements,**nouns,'boundary.delimiter_breakout':['--']}),
            'precise-no-nouns':apply(replacements)}


def main():
    root=Path(sys.argv[1]).resolve(); current=(root/'sources/current.toml').read_text()
    plan=json.loads((root/'attribution-plan.json').read_text())
    variants=alternatives(current,plan['changed_rules'])
    for k,s in variants.items(): write(root/'sources'/f'{k}.toml',s)
    configs=[{'label':k,'source':str(root/'sources'/f'{k}.toml')} for k in ['previous','current',*variants]]
    write(root/'optimization-configs.json',json.dumps(configs,indent=2)+'\n')
    write(root/'all-layout-configs.json',json.dumps(json.loads((root/'configs.json').read_text())+configs[2:],indent=2)+'\n')
    precise=precise_alternatives(current)
    for k,s in precise.items(): write(root/'sources'/f'{k}.toml',s)
    configs=[{'label':k,'source':str(root/'sources'/f'{k}.toml')} for k in ['previous','current',*precise]]
    write(root/'precise-configs.json',json.dumps(configs,indent=2)+'\n')
    controls=json.loads(Path('crates/core/tests/data/deferred_prefilter_pairs.json').read_text())
    full={r['id']:r for r in tomllib.loads(Path('docs/research/matching-consistency-2026-09-15/full-corrections.toml').read_text())['rule']}
    base=json.loads(Path('.cache/detection-improvement-20260914/development.json').read_text())
    corpus=base['corpus']; corpus['slice']=[]; corpus['excluded_source']=[]
    for sid in ['attack','ordinary']:
        corpus['slice'].append({'id':sid,'kind':'positive' if sid=='attack' else 'negative','label':sid,
            'origin':{'kind':'query','sql':'SELECT * FROM authored_deferred_rule_pairs'},'gate_eligible':sid=='ordinary',
            'excluded_sources':[],'baseline_permille':None,'notes':controls['authorship']})
    index=[]; directory=root/'deferred'; directory.mkdir(exist_ok=True)
    for i,rid in enumerate(dict.fromkeys(p['rule'] for p in controls['pairs'])):
        source=root/'sources'/f'deferred-{i}.toml'
        write(source,literals(current,rid,full[rid]['literals']))
        rows={'attack':[],'ordinary':[]}
        for pair in controls['pairs']:
            if pair['rule']!=rid: continue
            for label in rows:
                text=pair[label]
                for variation,text in [('original',text),('upper',text.upper()),('unicode_case',text.lower().replace('s','ſ').replace('k','K'))]:
                    for carrier,wrapped in {'plain':text,'json':json.dumps({'value':text},ensure_ascii=False),'html':f'<!-- {text} -->',
                                            'markdown':f'> {text}','base64':base64.b64encode(text.encode()).decode()}.items():
                        rows[label].append({'id':f'{pair["id"]}/{label}/{variation}/{carrier}', 'source':'first-party-deferred-pairs',
                                            'text':wrapped,'technique':rid,'context':variation,'carrier':carrier,'language':'en'})
        package=directory/f'pair-{i}.json'; write(package,json.dumps({'corpus':corpus,'rows':rows},ensure_ascii=False)+'\n')
        index.append({'rule':rid,'candidate':str(source),'package':str(package),'index':i})
    write(root/'deferred-plan.json',json.dumps(index,indent=2)+'\n')


if __name__=='__main__': main()
