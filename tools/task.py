import os, sys, re, requests
BASE = os.environ.get("BASE", "http://27wg1nxt69l0o1gh.instances.ctfcup.online")
os.makedirs("artifacts", exist_ok=True)
OUT = open("artifacts/out.txt", "w")
def log(*a):
    s = " ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
def show(label, r, limit=6000):
    log("="*15, label, "="*15)
    log(r.request.method, r.url, "->", r.status_code, "len", len(r.content))
    for k,v in r.headers.items():
        if k.lower() in ('content-type','location','set-cookie'): log("H",k+":",v[:120])
    log(r.text[:limit])
    log()

s = requests.Session()
s.headers['User-Agent']='Mozilla/5.0'
u="trainer%s" % os.environ.get("TAG","01")
p="pass12345"
COOKIE_FILE="artifacts/cookie.txt"

def save_cookie():
    sc = s.cookies.get_dict()
    open(COOKIE_FILE,"w").write(repr(sc))
    log("cookies:", sc)
def load_cookie():
    try:
        d=eval(open(COOKIE_FILE).read())
        for k,v in d.items(): s.cookies.set(k,v)
        log("loaded cookies", d)
    except Exception as e: log("no cookie", e)

load_cookie()
r=s.get(BASE+"/boxes", allow_redirects=False, timeout=20)
show("GET /boxes (before login)", r, 500)
r=s.post(BASE+"/register", data={"username":u,"password":p}, allow_redirects=False, timeout=20)
show("POST /register", r, 1500)
save_cookie()
r=s.post(BASE+"/login", data={"username":u,"password":p}, allow_redirects=False, timeout=20)
show("POST /login", r, 1500)
save_cookie()
for path in ["/boxes","/boxes/new","/box/new","/new","/upload"]:
    r=s.get(BASE+path, allow_redirects=False, timeout=20)
    show("GET "+path, r, 4000)
OUT.close()
