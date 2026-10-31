#!/usr/bin/env python3
"""Local imitation of the ctfcup instance wrapper (for testing only)."""
import socket, sys, threading, time

TOKEN = "5CYH8BZ95GHQV3IYLDJS83X0HIXSSQTG"
LPORT, BACK = int(sys.argv[1]), int(sys.argv[2])


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
            try: s.shutdown(socket.SHUT_WR)
            except OSError: pass


def handle(c):
    c.sendall(b"[*] Please, enter token:\n> ")
    buf = b""
    while b"\r\n" not in buf:
        d = c.recv(1)
        if not d:
            c.close(); return
        buf += d
    line = buf.split(b"\r\n")[0].decode().strip()
    if line != TOKEN:
        c.sendall(b"[-] bad token\n"); c.close(); return
    c.sendall(b"[+] Connecting...\n")
    try:
        b = socket.create_connection(("127.0.0.1", BACK), timeout=10)
    except OSError:
        c.close(); return
    t = threading.Thread(target=pipe, args=(b, c), daemon=True)
    t.start()
    pipe(c, b)
    t.join(timeout=2)
    c.close(); b.close()


srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", LPORT)); srv.listen(50)
print("wrapper on", LPORT, "->", BACK, flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
