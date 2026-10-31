import os, requests, re
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
except Exception as e: print("cookie err",e)
# does GET create a comment?
r=s.get(BASE+"/box/1/comment?body=GETTEST123",timeout=20,allow_redirects=False)
print("GET comment ->",r.status_code, r.text[:200])
t=s.get(BASE+"/box/1",timeout=20).text
print("comment present:", "GETTEST123" in t)
# GET settings?
r=s.get(BASE+"/settings?bio=GETBIO123",timeout=20,allow_redirects=False)
print("GET settings ->",r.status_code, r.text[:120].replace("\n"," "))
print("bio set:", "GETBIO123" in s.get(BASE+"/u/trainer01",timeout=20).text)
# POST comment body via form-urlencoded vs multipart naming
r=s.post(BASE+"/box/1/comment",data={"body":"POSTTEST456"},timeout=20,allow_redirects=False)
print("POST comment ->",r.status_code,"present:", "POSTTEST456" in s.get(BASE+"/box/1",timeout=20).text)
