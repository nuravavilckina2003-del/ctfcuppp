#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flaky wrapper: drops a configurable share of connections (test harness).

    python3 wrapper2.py <listen> <backend> [drop_ratio] [token]
"""
import os, random, socket, sys, threading

LPORT, BACK = int(sys.argv[1]), int(sys.argv[2])
DROP = float(sys.argv[3]) if len(sys.argv) > 3 else 0.7
TOKEN = sys.argv[4] if len(sys.argv) > 4 else "5CYH8BZ95GHQV3IYLDJS83X0HIXSSQTG"


def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass


def handle(c):
    if random.random() < DROP:
        try:
            c.close()
        except OSError:
            pass
        return
    try:
        c.sendall(b"[*] Please, enter token:\n> ")
        buf = b""
        while b"\n" not in buf:
            d = c.recv(1)
            if not d:
                c.close()
                return
            buf += d
        line = buf.split(b"\n")[0].strip().decode()
        if line != TOKEN:
            c.sendall(b"[-] bad token\n")
            c.close()
            return
        c.sendall(b"[+] Connecting...\n")
        b = socket.create_connection(("127.0.0.1", BACK), timeout=10)
        t = threading.Thread(target=pipe, args=(b, c), daemon=True)
        t.start()
        pipe(c, b)
        t.join(timeout=2)
        c.close()
        b.close()
    except OSError:
        try:
            c.close()
        except OSError:
            pass


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", LPORT))
srv.listen(100)
print("flaky wrapper on %d -> %d (drop %.0f%%)" % (LPORT, BACK, DROP * 100), flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
