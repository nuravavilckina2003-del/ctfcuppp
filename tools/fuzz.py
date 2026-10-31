import os, requests, re
BASE=os.environ.get("BASE","http://27wg1nxt69l0o1gh.instances.ctfcup.online")
s=requests.Session(); s.headers['User-Agent']='Mozilla/5.0'
for k,v in eval(open("artifacts/cookie.txt").read()).items(): s.cookies.set(k,v)
words="""admin administration moderation moderator mod report reports flag flags bot bots trainer trainers share shares inbox inboxes messages dm trade trades offer offers import export upload uploads save saves download raw preview image images img card cards team party pokemon storage pc box boxes user users profile profiles settings bio comment comments like likes star stars view views stats leaderboard top rank search api v1 v2 graphql debug env config secrets secret key keys token tokens session sessions auth login logout register signup health ping status metrics logs log errors error static assets files file public private internal system manage management dashboard panel control root superuser sudo god owner staff review queue pending approve verify reset password email mail notify notification webhook hooks cron job jobs task tasks worker process run exec shell cmd ssrf fetch proxy url redirect go out link links comment/new new edit delete update create add remove""".split()
seen=set()
for w in words:
    for path in ["/"+w, "/box/242/"+w]:
        try:
            r=s.get(BASE+path,timeout=12,allow_redirects=False)
            if r.status_code!=404 or len(r.content)>40:
                key=(path,r.status_code)
                if key not in seen:
                    seen.add(key)
                    print(f"GET {path} -> {r.status_code} {len(r.content)} {re.sub(chr(10),' ',r.text[:100])}", flush=True)
        except Exception as e: print(path,"ERR",e, flush=True)
# share follow
r=s.post(BASE+"/box/242/share",timeout=20,allow_redirects=True)
print("share follow:", r.status_code, r.url, re.sub(r'\s+',' ',r.text)[:400], flush=True)
