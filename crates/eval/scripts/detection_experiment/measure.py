from pathlib import Path
import subprocess,sys,json,hashlib,time,os
root=Path.cwd(); base=root/'.cache/detection-improvement-20260914'
binary=Path(sys.argv[1]).resolve(); label=sys.argv[2]; ids=sys.argv[3:] or ['pos_injecagent','pos_llmail','neg_orbench','neg_clean','neg_nonadversarial','neg_multilingual','fix_benign','gen_matched_negative','repo_prose']
cmd=[str(binary),'run',str(base/'development.json'),(base/'development.sha256').read_text().strip(),label,'high',*ids]
identity={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'rules_sha256':hashlib.sha256((root/'rules/builtin.toml').read_bytes()).hexdigest(),'command':cmd,'env':{'PLEASE_EVAL_CACHE':str(base/'eval-cache')}}
path=base/f'{label}-measurement.json'; assert not path.exists(); path.write_text(json.dumps(identity,indent=2)+'\n')
env=dict(os.environ,**identity['env']); start=time.monotonic()
with (base/f'{label}.log').open('x') as log: status=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
identity.update(elapsed_seconds=time.monotonic()-start,exit_code=status); path.write_text(json.dumps(identity,indent=2)+'\n')
print(json.dumps(identity,indent=2)); sys.exit(status)
