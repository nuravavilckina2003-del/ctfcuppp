import os, sys, struct, requests, re
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
os.makedirs("artifacts",exist_ok=True)
OUT=open("artifacts/out.txt","w")
def log(*a):
    s=" ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
main=requests.Session(); main.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): main.cookies.set(k,v)
    log("cookie loaded")
except Exception as e: log("cookie err",e)
def g(label,r,limit=2500):
    log("--",label,r.status_code,"len",len(r.content))
    log(r.text[:limit])
# feed with shared box 1
g("feed", main.get(BASE+"/",timeout=20), 3000)
g("profile", main.get(BASE+"/u/trainer01",timeout=20), 2000)
# error reflections
for p in ["/box/%3Cscript%3Ealert(1)%3C/script%3E","/box/abc","/u/%3Cscript%3E","/box/-1","/box/0"]:
    r=main.get(BASE+p,timeout=20); g("GET "+p, r, 700)
r=main.post(BASE+"/login",data={"username":"<script>x</script>","password":"x"},timeout=20,allow_redirects=False); g("bad login",r,700)
r=main.post(BASE+"/register",data={"username":"<script>x</script>","password":"x"},timeout=20,allow_redirects=False); g("bad register",r,700)
# tag fuzz on bio
names=["url","link","a","img","color","size","u","s","code","quote","center","youtube","email","mention","user","b","i","shiny","sparkle","fire","pokeball","heart","bg","marquee","script","style","iframe","svg","x",""]
payload=" | ".join("[%s]T[/%s]"%(n,n) for n in names)
r=main.post(BASE+"/settings",data={"bio":payload},timeout=20,allow_redirects=False); log("set bio",r.status_code)
r=main.get(BASE+"/u/trainer01",timeout=20)
m=re.search(r'<div class="trainer-card">.*?</div>',r.text,re.S)
log("BIO RENDER RAW:", repr(m.group(0)) if m else r.text[:1500])
OUT.close()
