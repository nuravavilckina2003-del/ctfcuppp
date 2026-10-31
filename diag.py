#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Diagnostics for the ctfcup instance.

The exploit works locally, but the remote instance returned b'' (no bytes at
all). This script tries every plausible way to talk to the wrapper that sits
in front of the service and prints exactly what comes back.

    python3 diag.py [host] [port]
"""
import socket, ssl, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "instances.ctfcup.online"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

TOKENS = [
    "BTG0ZSUL8I78E6C0M650RT6ZIXAS7M3Z",   # current
    "PS5MK0X1VA8DHSIIOUTG62FRCY9T3FCI",   # older
]


def tga():
    """Valid 4x4 24bpp RLE image: one raw chunk of 16 pixels."""
    hdr = struct.pack("<BBBHHBHHHHBB", 0, 0, 10, 0, 0, 0, 0, 0, 4, 4, 24, 0)
    return hdr + bytes([15]) + b"\x11\x22\x33" * 16


def http(body=None, extra=b"", depth=False):
    if body is None:
        body = tga()
    h = (b"POST /process HTTP/1.1\r\nHost: x\r\n"
         b"Content-Length: %d\r\n"
         b"X-Filter: warm\r\nX-Preview-Size: 48\r\nX-Scale: 1\r\nX-Gamma: 0\r\n"
         % len(body))
    if depth:
        h += (b"X-Preview-Offset: 0\r\nX-Preview-Length: 1024\r\n"
              b"X-Preview-Depth: 2000000000\r\n")
    h += extra + b"\r\n"
    return h + body


def probe(label, data, delay=0.0, wait=4.0, halfclose=False, banner_first=False):
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, PORT), timeout=wait)
        s.settimeout(wait)
        got = b""
        if banner_first:
            try:
                got += s.recv(4096)
            except socket.timeout:
                pass
        if data:
            s.sendall(data)
        if halfclose:
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        if delay:
            time.sleep(delay)
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            got += d
        s.close()
        dt = time.time() - t0
        print("%-34s %5.2fs  %4d B  %r" % (label, dt, len(got), got[:220]))
        return got
    except Exception as e:
        dt = time.time() - t0
        print("%-34s %5.2fs  ERR    %s: %s" % (label, dt, type(e).__name__, e))
        return None


def tls_probe():
    t0 = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.settimeout(5)
        ss = ctx.wrap_socket(s)
        print("%-34s %5.2fs  TLS ok  %r / %r"
              % ("TLS handshake", time.time() - t0, ss.version(), ss.cipher()))
        ss.close()
    except Exception as e:
        print("%-34s %5.2fs  ERR    %s: %s"
              % ("TLS handshake", time.time() - t0, type(e).__name__, e))


def main():
    print("target: %s:%d\n" % (HOST, PORT))
    try:
        print("resolved:", socket.gethostbyname(HOST), "\n")
    except OSError as e:
        print("DNS error:", e)

    probe("banner only (send nothing)", b"", wait=4.0)
    probe("plain HTTP (benign)", http())
    probe("plain HTTP + half-close", http(), halfclose=True)
    probe("GET /", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    for tok in TOKENS:
        probe("token only (%s..)" % tok[:4], (tok + "\n").encode())
        probe("token\\n + HTTP (%s..)" % tok[:4], (tok + "\n").encode() + http())
        probe("token\\r\\n + HTTP (%s..)" % tok[:4], (tok + "\r\n").encode() + http())
        probe("token, 1s pause, HTTP (%s..)" % tok[:4],
              (tok + "\n").encode() + http(), delay=1.0, banner_first=False)
        probe("HTTP + token header (%s..)" % tok[:4],
              http(extra=("X-Token: %s\r\n" % tok).encode()))
        probe("HTTP + Authorization (%s..)" % tok[:4],
              http(extra=("Authorization: %s\r\n" % tok).encode()))
    probe("leak-style HTTP (depth=big)", http(depth=True))
    tls_probe()
    print("\ndone")


if __name__ == "__main__":
    main()
