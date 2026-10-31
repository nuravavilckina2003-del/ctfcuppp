import os, sys, requests
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
os.makedirs("artifacts",exist_ok=True)
OUT=open("artifacts/out.txt","w")
def log(*a):
    s=" ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
def show(label,r,limit=4000):
    log("="*15,label,"="*15); log(r.request.method,r.url,"->",r.status_code,"len",len(r.content))
    for k,v in r.headers.items():
        if k.lower() in ('content-type','location'): log("H",k+":",v[:150])
    log(r.text[:limit]); log()
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
def save():
    open("artifacts/cookie.txt","w").write(repr(s.cookies.get_dict()))
def load():
    try:
        for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
        log("cookie loaded")
    except Exception as e: log("cookie err",e)
load()
u="trainer01"
show("GET /settings", s.get(BASE+"/settings",timeout=20))
show("GET /u/"+u, s.get(BASE+"/u/"+u,timeout=20))
# upload random save
data=os.urandom(0x20000)
files={'save':('rand.sav',data,'application/octet-stream')}
r=s.post(BASE+"/boxes",data={"title":"T [b]bold[/b] <script>alert(1)</script>","description":"desc [shiny]x[/shiny] <img src=x onerror=alert(1)>"},files=files,timeout=30,allow_redirects=False)
show("POST /boxes random",r)
show("GET /boxes after", s.get(BASE+"/boxes",timeout=20))
show("GET /", s.get(BASE+"/",timeout=20))
# zero save
data=bytes(0x20000)
files={'save':('zero.sav',data,'application/octet-stream')}
r=s.post(BASE+"/boxes",data={"title":"zero box","description":"zero desc"},files=files,timeout=30,allow_redirects=False)
show("POST /boxes zeros",r)
save(); OUT.close()
