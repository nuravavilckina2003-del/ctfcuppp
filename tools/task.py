import os, sys, requests, re
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
os.makedirs("artifacts",exist_ok=True)
OUT=open("artifacts/out.txt","w")
def log(*a):
    s=" ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
def show(label,r,limit=6000):
    log("="  *12,label,"="*12); log(r.request.method,r.url,"->",r.status_code,"len",len(r.content))
    for k,v in r.headers.items():
        if k.lower() in ('content-type','location'): log("H",k+":",v[:150])
    log(r.text[:limit]); log()
main=requests.Session(); main.headers['User-Agent']='Mozilla/5.0'
anon=requests.Session(); anon.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): main.cookies.set(k,v)
    log("cookie loaded")
except Exception as e: log("cookie err",e)
def peek(r, pat, label):
    m=re.search(pat, r.text, re.S)
    log("PEEK",label,":", (m.group(0)[:800] if m else "NOT FOUND"))
show("anon /box/1", anon.get(BASE+"/box/1",timeout=20))
show("anon /boxes", anon.get(BASE+"/boxes",allow_redirects=False,timeout=20), 300)
# comment
r=main.post(BASE+"/box/1/comment",data={"body":"hi <script>alert(3)</script> [b]bold[/b] [shiny]s[/shiny]"},allow_redirects=False,timeout=20)
show("post comment",r,800)
show("get /box/1 after comment", main.get(BASE+"/box/1",timeout=20))
# bio
r=main.post(BASE+"/settings",data={"bio":"bio <script>alert(4)</script> [i]it[/i] [pokeball]p[/pokeball] [heart]h[/heart] [fire]f[/fire] [sparkle]sp[/sparkle]"},allow_redirects=False,timeout=20)
show("post settings",r,800)
show("get /u/trainer01", main.get(BASE+"/u/trainer01",timeout=20))
# share
r=main.post(BASE+"/box/1/share",allow_redirects=False,timeout=20)
show("share",r,500)
show("feed /", main.get(BASE+"/",timeout=20), 3000)
# enumerate boxes
for i in range(1,8):
    r=anon.get(BASE+"/box/%d"%i,allow_redirects=False,timeout=20)
    log("anon box",i,"->",r.status_code,"len",len(r.content), re.findall(r'<h1>(.*?)</h1>',r.text,re.S)[:1])
OUT.close()
