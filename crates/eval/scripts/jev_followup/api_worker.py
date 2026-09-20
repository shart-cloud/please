"""One bounded HTTP operation; credentials are never command arguments or persisted."""
import json,os,sys,urllib.request,urllib.error
URL="https://api.typesafe.ai/v1/systemone"
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
def main():
 key=os.environ["TYPESAFE_API_KEY"];body=sys.stdin.buffer.read(65537)
 if len(body)>65536:raise ValueError("request cap")
 q=urllib.request.Request(URL,body,{"Content-Type":"application/json","Authorization":"Bearer "+key},method="POST")
 try:
  with urllib.request.build_opener(NoRedirect).open(q,timeout=29) as response:raw=response.read(32769)
  if len(raw)>32768:result=dict(error="response byte limit")
  elif key.encode() in raw:result=dict(error="credential reflection blocked")
  else:result=dict(response_hex=raw.hex())
 except urllib.error.HTTPError as e:result=dict(error="HTTP "+str(e.code),status=e.code)
 except Exception:result=dict(error="transport unavailable")
 print(json.dumps(result),flush=True)
if __name__=="__main__":main()
