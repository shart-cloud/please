#!/usr/bin/python3
"""Native JSONL adapter. The local broker owns the ephemeral credential."""
import argparse,json,socket,sys
PROTOCOL="please-bench-jsonl/v1"
def send(v):print(json.dumps(v,separators=(",",":")),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument("--socket",required=True);a=p.parse_args()
 hello=json.loads(sys.stdin.readline(4096))
 if set(hello)!={"kind","schema_version","system_id","system_digest"} or hello["kind"]!="handshake" or hello["schema_version"]!=PROTOCOL:raise ValueError("invalid handshake")
 send(dict(hello,adapter_version=PROTOCOL))
 while True:
  line=sys.stdin.buffer.readline(131073)
  if not line:break
  if len(line)>131072 or not line.endswith(b"\n"):raise ValueError("request cap")
  q=json.loads(line)
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
   s.settimeout(37);s.connect(a.socket);s.sendall(line);s.shutdown(socket.SHUT_WR)
   answer=b""
   while True:
    chunk=s.recv(65536)
    if not chunk:break
    answer+=chunk
    if len(answer)>65536:raise ValueError("broker response cap")
  send(dict(kind="result",schema_version=PROTOCOL,request_id=q["request_id"],native=json.loads(answer)))
if __name__=="__main__":main()
