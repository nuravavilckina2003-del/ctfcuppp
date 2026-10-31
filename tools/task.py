import os, sys, struct, requests, re, traceback
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
except Exception as e: print("cookie err",e)
def checksum(data):
    t=0
    for i in range(0,len(data)-len(data)%4,4): t=(t+struct.unpack_from('<I',data,i)[0])&0xFFFFFFFF
    return ((t&0xFFFF)+(t>>16))&0xFFFF
SIZES={0:3884,1:3968,2:3968,3:3968,4:3848,5:3968,6:3968,7:3968,8:3968,9:3968,10:3968,11:3968,12:3968,13:2000}
def make_save(party):
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
def pkm(nickbytes, pid=0x12345678):
    p=bytearray(100)
    struct.pack_into('<I',p,0,pid); struct.pack_into('<I',p,4,12345)
    p[8:8+10]=nickbytes.ljust(10,b'\x00')[:10]
    struct.pack_into('<I',p,0x54,50)
    return bytes(p)
mapping={}
out=open("artifacts/map.txt","w")
bs=[b for b in range(0x00,0x100) if b not in (0xff,)]
for start in range(0,len(bs),6):
    chunk=bs[start:start+6]
    party=[pkm(bytes([b])*4+b'\xff') for b in chunk]
    sv=make_save(party)
    r=s.post(BASE+"/boxes",data={"title":"map%02x"%start,"description":"d"},files={'save':('m.sav',sv)},timeout=30,allow_redirects=False)
    if r.status_code!=303:
        print("FAIL",start,r.status_code); continue
    t=s.get(r.headers['location'],timeout=20).text
    nicks=re.findall(r'<span class="nick">(.*?)</span>',t,re.S)
    for b,n in zip(chunk,nicks):
        mapping[b]=n
        out.write("%02x %r\n"%(b,n))
    out.flush()
out.close()
for b in range(0,0x100):
    if b in mapping: print("%02x %r"%(b,mapping[b]))
