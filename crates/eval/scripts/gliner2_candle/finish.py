#!/usr/bin/env python3
"""Wait for both native runs, then verify and publish the comparison once. No inference or API calls."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--jev-run',type=Path,required=True);p.add_argument('--publish',type=Path,required=True);a=p.parse_args()
root=a.out.resolve();started=time.monotonic();report=Path(__file__).with_name('report.py')
script_hash=hashlib.sha256(report.read_bytes()).hexdigest()
status=root/'completion.json'
if status.exists(): raise RuntimeError('completion watcher already recorded')
status.write_text(json.dumps(dict(status='waiting',report_script_sha256=script_hash))+'\n')
try:
    while True:
        states={arm:json.loads((root/('run-'+arm)/'run.json').read_text()).get('status') for arm in ['public','contextual']}
        if all(s=='complete' for s in states.values()): break
        if time.monotonic()-started>14400: raise RuntimeError('four-hour completion wait elapsed; native runs retained')
        print(json.dumps(dict(status='waiting',rows={arm:sum(1 for _ in (root/('run-'+arm)/'results.jsonl').open()) for arm in states})),flush=True)
        time.sleep(30)
    if hashlib.sha256(report.read_bytes()).hexdigest()!=script_hash: raise RuntimeError('report script changed during wait')
    subprocess.run([sys.executable,str(report),'--out',str(root),'--jev-run',str(a.jev_run.resolve()),'--publish',str(a.publish.resolve())],check=True)
    status.write_text(json.dumps(dict(status='complete',report_script_sha256=script_hash,comparison_sha256=hashlib.sha256((root/'comparison.json').read_bytes()).hexdigest()),indent=2)+'\n')
    print('Native reports verified and comparison published.',flush=True)
except Exception as exc:
    status.write_text(json.dumps(dict(status='failed',error=str(exc),report_script_sha256=script_hash),indent=2)+'\n')
    raise
