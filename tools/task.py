import os, sys, requests, re
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
OUT=open("artifacts/out.txt","w")
def log(*a):
    s=" ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
    log("cookie loaded")
except Exception as e: log("cookie err",e)
paths=["/users","/api","/api/boxes","/api/users","/admin/users","/admin","/report","/bot","/flag","/flag.txt","/debug","/health","/stats","/profile","/me","/account","/logout","/box/1.json","/box/1.txt","/box/1?format=json","/box/1/edit","/box/1/delete","/export","/import"]
for p in paths:
    try:
        r=s.get(BASE+p,timeout=20,allow_redirects=False)
        log(p,"->",r.status_code,"len",len(r.content), repr(r.text[:160]))
    except Exception as e: log(p,"ERR",e)
names=["admin","administrator","moderator","mod","oak","professor","red","ash","blue","cynthia","champion","trainer","staff","support","bot","flag","pokebox","admin1","root","Agent"]
for n in names:
    try:
        r=s.get(BASE+"/u/"+n,timeout=20,allow_redirects=False)
        marker="MISS"
        m=re.search(r'<h1>(.*?)</h1>',r.text,re.S)
        if r.status_code==200 and m: marker=m.group(1)
        log("user",n,"->",r.status_code,marker, re.findall(r'(ctfcup\{[^}]*\})',r.text)[:1])
    except Exception as e: log("user",n,"ERR",e)
OUT.close()
