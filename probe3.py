#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Polite handshake probe: wait for prompt -> token -> wait -> HTTP."""
import socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "instances.ctfcup.online"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
TOKEN = sys.argv[3] if len(sys.argv) > 3 else "5CYH8BZ95GHQV3IYLDJS83X0HIXSSQTG"


def http_req():
    hdr = struct.pack("<BBBHHBHHHHBB", 0, 0, 10, 0, 0, 0, 0, 0, 4, 4, 24, 0)
    body = hdr + bytes([15]) + b"\x11\x22\x33" * 16
    return (b"POST /process HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n"
            b"X-Filter: warm\r\nX-Preview-Size: 48\r\nX-Preview-Offset: 0\r\n"
            b"X-Preview-Length: 1024\r\nX-Preview-Depth: 2000000000\r\n"
            b"X-Scale: 1\r\nX-Gamma: 0\r\n\r\n" % len(body)) + body


def rd(s, wait):
    s.settimeout(wait)
    out = b""
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            return out, False
        if not d:
            return out, True
        out += d


def attempt(mode, quiet=False):
    t0 = time.time()
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.settimeout(8)
    log = []

    def note(tag, data, closed):
        if not quiet:
            print("      %-14s %r%s" % (tag, data[:90], " [closed]" if closed else ""))

    if mode in ("polite", "polite-http"):
        pre, closed = rd(s, 3.0)
        note("prompt", pre, closed)
        if closed:
            s.close()
            return False, pre
        s.sendall(TOKEN.encode() + b"\r\n")
        ack, closed = rd(s, 3.0)
        note("after token", ack, closed)
        if closed:
            s.close()
            return b"HTTP/" in ack, pre + ack
        s.sendall(http_req())
        resp, closed = rd(s, 8.0)
        note("after http", resp, closed)
        s.close()
        return b"HTTP/" in resp, pre + ack + resp

    s.sendall(TOKEN.encode() + b"\r\n")
    if mode == "paced":
        time.sleep(0.7)
        s.sendall(http_req())
    elif mode == "batched":
        s.sendall(http_req())
    elif mode == "batch1":
        s.sendall(http_req())
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    resp, closed = rd(s, 8.0)
    note("resp", resp, closed)
    s.close()
    return b"HTTP/" in resp, resp


def main():
    print("target %s:%d" % (HOST, PORT))
    modes = ["polite", "paced", "batched", "batch1"]
    for rnd in range(3):
        for m in modes:
            try:
                ok, data = attempt(m)
            except Exception as e:
                print("  round %d %-7s EXC %s: %s" % (rnd, m, type(e).__name__, e))
                time.sleep(1.0)
                continue
            print("  round %d %-7s -> %s (%d B)%s"
                  % (rnd, m, "OK" if ok else "no", len(data),
                     "  " + repr(data[:100]) if not ok and data else ""))
            if ok:
                print("\n[+] working mode:", m)
                return 0
            time.sleep(1.2)
    print("\n[!] no mode worked")
    return 1


sys.exit(main())
