#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sequenced handshake diagnostics: does the instance answer at all,
does it wait for a banner-less token line, does it close early, etc.

    python3 diag2.py [host] [port]
"""
import socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "instances.ctfcup.online"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

TOKENS = ["BTG0ZSUL8I78E6C0M650RT6ZIXAS7M3Z",
          "PS5MK0X1VA8DHSIIOUTG62FRCY9T3FCI"]


def tga_body():
    hdr = struct.pack("<BBBHHBHHHHBB", 0, 0, 10, 0, 0, 0, 0, 0, 4, 4, 24, 0)
    return hdr + bytes([15]) + b"\x11\x22\x33" * 16


def http_req(body=None, extra=b""):
    if body is None:
        body = tga_body()
    return (b"POST /process HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n"
            b"X-Filter: warm\r\nX-Preview-Size: 48\r\nX-Scale: 1\r\nX-Gamma: 0\r\n"
            % len(body)) + extra + b"\r\n" + body


def drain(s, wait):
    """Read whatever arrives within `wait` seconds. Returns (data, closed)."""
    s.settimeout(wait)
    data = b""
    closed = False
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            closed = True
            break
        data += d
    return data, closed


def run(label, script):
    """script(sock) -> None. Prints what happened at every step."""
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, PORT), timeout=6)
    except Exception as e:
        print("%-30s CONNECT FAIL  %s: %s" % (label, type(e).__name__, e))
        return
    log = []
    try:
        script(s, log)
    except Exception as e:
        log.append("%s:%s" % (type(e).__name__, e))
    finally:
        try:
            s.close()
        except OSError:
            pass
    print("%-30s %5.2fs  %s" % (label, time.time() - t0, " | ".join(log) or "nothing"))


def show(tag, data, closed):
    return "%s=%r%s" % (tag, data[:100], " [peer closed]" if closed else "")


def step_banner(s, log):
    d, c = drain(s, 6)
    log.append(show("banner", d, c))


def step_http(s, log):
    s.sendall(http_req())
    d, c = drain(s, 6)
    log.append(show("resp", d, c))


def step_http_half(s, log):
    s.sendall(http_req())
    try:
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    d, c = drain(s, 6)
    log.append(show("resp", d, c))


def make_token_step(tok, nl, pause, then_http):
    def step(s, log):
        s.sendall(tok.encode() + nl)
        d, c = drain(s, max(pause, 0.3))
        log.append(show("after token", d, c))
        if c:
            return
        if then_http:
            s.sendall(http_req())
            d2, c2 = drain(s, 6)
            log.append(show("after http", d2, c2))
    return step


def main():
    print("target %s:%d   dns=%s\n" % (HOST, PORT, socket.gethostbyname(HOST)))
    run("connect, say nothing", step_banner)
    run("plain HTTP", step_http)
    run("plain HTTP + half-close", step_http_half)
    for tok in TOKENS:
        for nl in (b"\n", b"\r\n"):
            for pause in (0.0, 2.0):
                label = "tok %s %s pause=%.0f" % (tok[:4], nl, pause)
                run(label, make_token_step(tok, nl, pause, True))
        run("tok %s only, wait" % tok[:4], make_token_step(tok, b"\n", 6.0, False))
    print("\ndone")


if __name__ == "__main__":
    main()
