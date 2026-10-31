#!/usr/bin/env python3
"""Local probe/fuzz harness for the image-viewer service (port 8097)."""
import socket, struct, sys

HOST, PORT = "127.0.0.1", 8097

def tga(w, h, bpp=24, imgtype=2, desc=0, x=0, y=0, idlen=0, cmap=0,
        cmap_entries=0, cmap_bpp=0, payload=None):
    hdr = struct.pack("<BBBHHBHHHHBB",
                      idlen, cmap, imgtype,
                      0, cmap_entries, cmap_bpp,
                      x, y, w, h, bpp, desc)
    hdr += b"A" * idlen
    body = payload
    if body is None:
        body = b"\x10" * (w * h * (bpp // 8) if bpp >= 8 else w * h)
    return hdr + body

def request(method="POST", path="/process", headers=None, body=b"", timeout=6.0):
    h = {"Host": "x", "Connection": "close"}
    if headers:
        h.update(headers)
    req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
    req = req.encode() + b"\r\n" + body
    try:
        s = socket.create_connection((HOST, PORT), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(req)
        out = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
            if len(out) > 200000:
                break
        s.close()
        return out
    except Exception as e:
        return b"<<%s: %s>>" % (type(e).__name__.encode(), str(e).encode())

def show(label, resp, maxlen=300):
    head, _, body = resp.partition(b"\r\n\r\n")
    print(f"--- {label}: {len(resp)} bytes")
    print("   hdr:", head.replace(b"\r\n", b" | ").decode("latin1")[:400])
    if body:
        print("   body:", repr(body[:maxlen]))

if __name__ == "__main__":
    show("baseline 4x4x24", request(headers={"X-Preview-Size": "16", "X-Scale": "1", "X-Gamma": "1"},
                                   body=tga(4, 4)))
    show("baseline 4x4x24 size=228", request(headers={"X-Preview-Size": "228", "X-Scale": "1", "X-Gamma": "1"},
                                            body=tga(4, 4)))
    show("GET /", request("GET", "/"))
    show("GET / offset=0 len=64 depth=8",
         request("GET", "/", {"X-Preview-Offset": "0", "X-Preview-Length": "64", "X-Preview-Depth": "8"}))
    show("GET / offset=4096 len=64",
         request("GET", "/", {"X-Preview-Offset": "4096", "X-Preview-Length": "64"}))
