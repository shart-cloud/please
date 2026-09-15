"""Build explicit candidate literal lists without changing any regex or rule semantics.
Unicode variants cover long-s and Kelvin sign accepted by Unicode-aware (?i).
No candidate is selected by dataset IDs, scores, or input hashes.
Usage: python3 prepare_prefilter_corrections.py BASELINE.toml OUTPUT_DIRECTORY
"""
import itertools
import json
from pathlib import Path
import re
import sys
import tomllib

REPLACEMENTS = {
    'override.forget_everything':['forget','disregard','ignore'],
    'override.new_instructions_follow':['new','updated','revised'],
    'boundary.forged_tool_result':['<tool_result','</tool_result','tool_output','function_results'],
    'boundary.delimiter_breakout':['end of document','end of user input','end of context','begin system'],
    'solicitation.credentials':['environment variable','api key','id_rsa','credential','access token','secret','.env','.npmrc','.aws/credentials','.git-credentials','.ssh/id_'],
    'solicitation.tool_enumeration':['tool'],
    'boundary.forged_system_directive':['systemoverride','system override','system_override','system-override'],
    'agent_directed.addressed_marker':['note','message','instruction','reminder','ai','assistant','llm','agent','dear','attention','you'],
    'privilege.permission_widening':['auto','bypass','skip','dangerously','allow','disable','turn'],
}
# Full corrections to these patterns produce new findings on the authored benign
# controls. Preserve their source semantics while the disposition is discussed.
CONFLICTING = {'solicitation.credentials','solicitation.tool_enumeration',
               'boundary.forged_system_directive','agent_directed.addressed_marker','privilege.permission_widening'}


def expanded(literals):
    return sorted({''.join(chars) for literal in literals for chars in itertools.product(
        *[('s','ſ') if c=='s' else ('k','K') if c=='k' else (c,) for c in literal])})


def main():
    original = Path(sys.argv[1]).read_text()
    rules = tomllib.loads(original)['rule']
    for variant in ['all','safe']:
        source=original
        for rule in rules:
            if variant=='safe' and rule['id'] in CONFLICTING: continue
            literals=expanded(REPLACEMENTS.get(rule['id'],rule['literals']))
            pattern=r'(^id = "'+re.escape(rule['id'])+r'".*?^literals = )\[.*?\]'
            replacement='[\n'+''.join('    '+json.dumps(s,ensure_ascii=False)+',\n' for s in literals)+']'
            source,count=re.subn(pattern,lambda m:m[1]+replacement,source,count=1,flags=re.M|re.S)
            assert count==1
        with (Path(sys.argv[2])/f'{variant}-corrections.toml').open('x') as f:f.write(source)


if __name__=='__main__':main()
