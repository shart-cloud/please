"""Cache-only context-conditioned MiniLM probe; no external inference or live agent execution."""
import argparse, os, sys, json, hashlib, time, statistics, platform, tomllib
from pathlib import Path
os.environ['HF_HUB_OFFLINE']='1'
os.environ['TRANSFORMERS_OFFLINE']='1'
os.environ['TOKENIZERS_PARALLELISM']='false'
def no_network(event,args):
    if event in ('socket.connect','socket.connect_ex','socket.getaddrinfo'):
        raise RuntimeError('network disabled for the experiment')
sys.addaudithook(no_network)
import numpy as np
import torch
from transformers import BertModel
from tokenizers import Tokenizer

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--cases',type=Path,required=True);p.add_argument('--lab-captures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(exist_ok=False)
    root=a.repo
    freeze=json.loads((root/'tests/fixtures/action-evidence/freeze.json').read_text())
    if sha(a.cases)!=freeze['sha256']:raise ValueError('frozen case manifest changed')
    # Use the same pinned runtime assets as the repository's existing model feasibility experiment.
    model_dir=Path('/home/jg/.cache/please-eval/models/all-minilm-l6-v2/1110a243fdf4706b3f48f1d95db1a4f5529b4d41')
    pins={'config.json':'953f9c0d463486b10a6871cc2fd59f223b2c70184f49815e7efbcab5d8908b41','tokenizer.json':'be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037','model.safetensors':'53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db'}
    for name,digest in pins.items():
        if sha(model_dir/name)!=digest:raise ValueError('model pin mismatch: '+name)
    torch.set_num_threads(2);torch.manual_seed(0);np.random.seed(0);torch.use_deterministic_algorithms(True)
    started=time.perf_counter();model=BertModel.from_pretrained(str(model_dir),local_files_only=True,use_safetensors=True,attn_implementation='eager').eval();tokenizer=Tokenizer.from_file(str(model_dir/'tokenizer.json'));tokenizer.no_truncation();tokenizer.no_padding();init_ms=(time.perf_counter()-started)*1000
    rows=[json.loads(s) for s in a.cases.read_text().splitlines() if s.strip()]
    for s in a.lab_captures.read_text().splitlines():
        capture=json.loads(s);path=a.lab_captures.parent/capture['input_path'];raw=path.read_bytes()
        if sha(path)!=capture['input_sha256']:raise ValueError('capture hash mismatch')
        rows.append(dict(id=capture['id'],split='lab-development',family='captured',text=raw.decode('utf-8'),label=capture['label'],policy='restricted',source=capture['source']))
    # Context is input to the encoder. Case IDs, labels, split names and family names are never encoded.
    policy_paths={'restricted':root/'examples/export-policy.toml','approved':root/'tests/fixtures/action-evidence/approved.toml'}
    policies={name:tomllib.loads(path.read_text()) for name,path in policy_paths.items()}
    def context(row):
        resources=policies[row['policy']]['resource']
        descriptions=[]
        for resource in resources:
            allowed=', '.join(resource['allowed_destinations']) or 'none'
            descriptions.append('Protected: '+', '.join(resource['aliases'])+'. Allowed export destinations: '+allowed+'.')
        return 'Application policy. '+' '.join(descriptions)+' Source: '+row['source']+'. Text: '
    embeddings=[];times=[];chunks=[]
    with torch.inference_mode():
        for row in rows:
            start=time.perf_counter();ctx=tokenizer.encode(context(row),add_special_tokens=False).ids;ids=tokenizer.encode(row['text'],add_special_tokens=False).ids
            capacity=256-len(ctx)-3
            if capacity<32:raise ValueError('context leaves insufficient model window')
            # Preserve complete token coverage; overlapping windows, never silent truncation.
            encoded=[]
            for at in range(0,max(1,len(ids)),max(1,capacity-32)):
                seq=[101]+ctx+[102]+ids[at:at+capacity]+[102]
                values=torch.tensor([seq]);mask=torch.ones_like(values)
                states=model(input_ids=values,attention_mask=mask).last_hidden_state
                pooled=states.mean(dim=1);pooled=torch.nn.functional.normalize(pooled,p=2,dim=1)
                encoded.append(pooled[0].numpy())
                if at+capacity>=len(ids):break
            embeddings.append(np.stack(encoded));times.append((time.perf_counter()-start)*1000);chunks.append(len(encoded))
    train=[i for i,r in enumerate(rows) if r['split']=='train']
    x=torch.tensor(np.concatenate([embeddings[i] for i in train]),dtype=torch.float32)
    y=torch.tensor([float(rows[i]['label']=='injection') for i in train for _ in embeddings[i]],dtype=torch.float32)
    # Fixed recipe, no held-out hyperparameter search. This is a tiny experimental linear head.
    head=torch.nn.Linear(x.shape[1],1);optim=torch.optim.Adam(head.parameters(),lr=0.03)
    for _ in range(800):
        optim.zero_grad();loss=torch.nn.functional.binary_cross_entropy_with_logits(head(x).flatten(),y)+0.01*head.weight.square().sum();loss.backward();optim.step()
    with torch.inference_mode():scores=[float(torch.sigmoid(head(torch.tensor(e))).max()) for e in embeddings]
    benign_cal=[scores[i] for i,r in enumerate(rows) if r['split']=='calibration' and r['label']=='benign']
    threshold=float(np.nextafter(max(benign_cal),float('inf')))
    weights={'weight':head.weight.detach().numpy().tolist(),'bias':head.bias.detach().numpy().tolist()}
    (a.out/'head.json').write_text(json.dumps(weights))
    results=[]
    for i,row in enumerate(rows):results.append(dict(id=row['id'],split=row['split'],label=row['label'],source=row['source'],policy=row['policy'],input_sha256=hashlib.sha256(row['text'].encode()).hexdigest(),score=scores[i],decision='block' if scores[i]>=threshold else 'allow',chunks=chunks[i],inference_ms=times[i]))
    (a.out/'results.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in results))
    summary={}
    for split in ['train','calibration','holdout','lab-development']:
        rs=[r for r in results if r['split']==split]
        summary[split]={label:{'total':sum(r['label']==label for r in rs),'blocked':sum(r['label']==label and r['decision']=='block' for r in rs)} for label in ['injection','benign','uncertain']}
    metadata=dict(model='all-MiniLM-L6-v2 + context-conditioned linear head',revision=model_dir.name,asset_sha256=pins,policy_sha256={k:sha(v) for k,v in policy_paths.items()},head_sha256=sha(a.out/'head.json'),script_sha256=sha(__file__),cases_sha256=sha(a.cases),lab_manifest_sha256=sha(a.lab_captures),threshold=threshold,threshold_selection='next float above maximum of four calibration-benign scores; no general FPR claim',seed=0,steps=800,l2=0.01,learning_rate=0.03,initialization_ms=init_ms,median_inference_ms=statistics.median(times),max_chunks=max(chunks),python=platform.python_version(),torch=torch.__version__,numpy=np.__version__,summary=summary,network='blocked by socket audit hook',note='Local experimental comparator, not CAD or a validated prompt-injection model. No agent execution measured.')
    (a.out/'run.json').write_text(json.dumps(metadata,indent=2)+'\n');print(json.dumps(metadata,indent=2))
if __name__=='__main__':main()
