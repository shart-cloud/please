#!/usr/bin/python3
"""Verified native replay of explicitly identified live captures; no network calls here."""
import argparse,hashlib,json,sys
from pathlib import Path
PROTOCOL="please-bench-jsonl/v1"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def key(q):return hashlib.sha256(json.dumps({k:q.get(k) for k in ("surface","candidate_sha256","byte_length","provenance","trusted_context")},sort_keys=True,separators=(",",":")).encode()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--capture",required=True);p.add_argument("--sha256",required=True);p.add_argument("--arm",required=True);a=p.parse_args()
 if sha(a.capture)!=a.sha256:raise ValueError("capture hash mismatch")
 records={}
 for line in Path(a.capture).read_text().splitlines():
  row=json.loads(line)
  if row["arm"]==a.arm:
   if row["request_key"] in records:raise ValueError("duplicate capture key")
   records[row["request_key"]]=row
 hello=json.loads(sys.stdin.readline(4096))
 if set(hello)!={"kind","schema_version","system_id","system_digest"} or hello["kind"]!="handshake" or hello["schema_version"]!=PROTOCOL:raise ValueError("bad handshake")
 print(json.dumps(dict(hello,adapter_version=PROTOCOL)),flush=True)
 for line in sys.stdin:
  if len(line.encode())>131072:raise ValueError("request cap")
  q=json.loads(line);raw=bytes.fromhex(q["candidate_hex"])
  if len(raw)!=q["byte_length"] or hashlib.sha256(raw).hexdigest()!=q["candidate_sha256"]:raise ValueError("input identity mismatch")
  r=records[key(q)];label=r["prediction"]
  diag=dict(r["diagnostics"],captured_api_attempts=r["api_attempts"],capture_mode="replay of hash-bound live evidence; harness timing is replay overhead")
  native=dict(label=label,evidence=[],diagnostics=[json.dumps(diag,sort_keys=True)],abstained=label=="indeterminate",remote_requests=0,declared_cost_microusd=0)
  print(json.dumps(dict(kind="result",schema_version=PROTOCOL,request_id=q["request_id"],native=native)),flush=True)
if __name__=="__main__":main()
