#!/usr/bin/env python3
"""Require token/marker identity, full-logit and probability parity, and identical decisions."""
import argparse
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('reference',type=Path)
p.add_argument('candle',type=Path)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
read=lambda p:[json.loads(l) for l in p.read_text().splitlines()]
reference,candle=read(a.reference),read(a.candle)
assert len(reference)==len(candle)>0
max_logit=max_probability=0
for x,y in zip(reference,candle):
    assert x['id']==y['id'], 'case order mismatch'
    assert x['encoded']==y['encoded'], f"token/position mismatch: {x['id']}"
    for field in ['logits','probabilities']:
        assert len(x[field])==len(y[field])>1
    max_logit=max(max_logit,max(abs(j-k) for j,k in zip(x['logits'],y['logits'])))
    max_probability=max(max_probability,max(abs(j-k) for j,k in zip(x['probabilities'],y['probabilities'])))
    assert x['probabilities'].index(max(x['probabilities']))==y['probabilities'].index(max(y['probabilities']))
    assert (max(x['probabilities'])>=.7)==(max(y['probabilities'])>=.7)
assert max_logit<=.001 and max_probability<=.0001, 'numerical parity gate failed'
r=dict(cases=len(reference),exact_encoded_inputs=len(reference),top_label_agreement=len(reference),threshold_decision_agreement=len(reference),max_absolute_logit_error=max_logit,max_absolute_probability_error=max_probability,logit_tolerance=.001,probability_tolerance=.0001,reference_sha256=hashlib.sha256(a.reference.read_bytes()).hexdigest(),candle_sha256=hashlib.sha256(a.candle.read_bytes()).hexdigest(),passed=True)
a.out.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r))
