import os, sys, json, time, urllib.parse
import requests

BASE = os.environ.get("BASE", "http://27wg1nxt69l0o1gh.instances.ctfcup.online")
OUT = open("artifacts/out.txt", "w")

def log(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    OUT.write(s + "\n")

def show(label, r, body=True, limit=4000):
    log("="*20, label, "="*20)
    log(r.request.method, r.url, "->", r.status_code)
    for k, v in r.headers.items():
        log("H", k + ":", v)
    if body:
        t = r.text
        log(t[:limit])
        if len(t) > limit: log("...[truncated %d bytes]" % len(t))
    log()

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64)'

paths = sys.argv[1:] or ["/", "/login", "/register", "/style.css", "/robots.txt", "/flag", "/admin", "/upload", "/boxes", "/feed"]
for p in paths:
    try:
        r = s.get(BASE + p, timeout=20, allow_redirects=False)
        show(p, r, limit=3000)
    except Exception as e:
        log("ERR", p, repr(e))

OUT.close()
