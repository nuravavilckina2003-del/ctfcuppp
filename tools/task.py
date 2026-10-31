import os, sys, struct, requests, re, traceback
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
OUT=open("artifacts/out.txt","w")
def log(*a):
    s=" ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
try:
    for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
except Exception as e: log("cookie err",e)
def checksum(data):
    t=0
    for i in range(0,len(data)-len(data)%4,4): t=(t+struct.unpack_from('<I',data,i)[0])&0xFFFFFFFF
    return ((t&0xFFFF)+(t>>16))&0xFFFF
SIZES={0:3884,1:3968,2:3968,3:3968,4:3848,5:3968,6:3968,7:3968,8:3968,9:3968,10:3968,11:3968,12:3968,13:2000}
def make_save():
    buf=bytearray(0x20000)
    def sec(idx,counter,data):
        sc=bytearray(0x1000); sc[0:len(data)]=data
        struct.pack_into('<H',sc,0xFF4,idx); struct.pack_into('<H',sc,0xFF6,checksum(sc[0:SIZES.get(idx,3968)]))
        struct.pack_into('<I',sc,0xFF8,0x08012025); struct.pack_into('<I',sc,0xFFC,counter)
        buf[idx*0x1000:(idx+1)*0x1000]=sc
    s0=bytearray(SIZES[0]); struct.pack_into('<I',s0,0x0A,12345); sec(0,100,s0)
    s1=bytearray(SIZES[1]); sec(1,100,s1)
    for i in range(2,14): sec(i,100,bytes(SIZES[i]))
    return bytes(buf)
try:
  sv=make_save()
except Exception:
  traceback.print_exc(); raise
tags="b i u s code quote spoiler url img color size center left right font table tr td list hr br p div script style iframe svg marquee a link mention user shiny sparkle fire pokeball heart ball star ice water electric grass psychic dragon dark fairy normal fighting poison ground flying bug rock ghost steel".split()
results={}
for t in tags:
    for form in ["[%s]X[/%s]"%t, "[%s=V]Y[/%s]"%t, "[%s V]Z[/%s]"%t]:
        r=s.post(BASE+"/boxes",data={"title":"t","description":form},files={'save':('x.sav',sv)},timeout=30,allow_redirects=False)
        if r.status_code!=303: 
            log("FAIL",form,r.status_code); continue
        loc=r.headers['location']
        b=s.get(loc,timeout=20).text
        m=re.search(r'<p class="box-desc">(.*?)</p>',b,re.S)
        out=m.group(1) if m else "NONE"
        if out!=form:
            log("MARKUP",repr(form),"->",repr(out))
log("done")
OUT.close()
