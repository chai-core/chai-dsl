import socket, sys

def send(host, port, raw):
    s = socket.create_connection((host, port), timeout=5); s.sendall(raw)
    data = b""
    while True:
        c = s.recv(4096)
        if not c: break
        data += c
    s.close(); return data

def chunked(b): return (b"%x\r\n" % len(b)) + b + b"\r\n0\r\n\r\n" if b else b"0\r\n\r\n"

def reqmod(host, port, jsonrpc):
    h = b"POST /mcp HTTP/1.1\r\nHost: x\r\n\r\n"
    raw = (b"REQMOD icap://%s/reqmod ICAP/1.0\r\nHost: %s\r\nEncapsulated: req-hdr=0, req-body=%d\r\n\r\n%s%s"
           % (host.encode(), host.encode(), len(h), h, chunked(jsonrpc)))
    return send(host, port, raw)

def respmod(host, port, body):
    h = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    raw = (b"RESPMOD icap://%s/respmod ICAP/1.0\r\nHost: %s\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n%s%s"
           % (host.encode(), host.encode(), len(h), h, chunked(body)))
    return send(host, port, raw)

def options(host, port):
    return send(host, port, b"OPTIONS icap://%s/ ICAP/1.0\r\nHost: %s\r\n\r\n" % (host.encode(), host.encode()))

H, P = "127.0.0.1", 1344
res = []
def chk(n, ok, d=""): res.append(ok); print(f"  [{'PASS' if ok else 'FAIL'}] {n}  {d}")

o = options(H, P)
chk("OPTIONS advertises REQMOD/RESPMOD", b"Methods: REQMOD, RESPMOD" in o)
call = lambda t: b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":{}}}' % t.encode()
chk("REQMOD read -> allow (204)", b"204" in reqmod(H, P, call("read")).split(b"\r\n")[0])
chk("REQMOD write -> blocked (403)", b"403 Forbidden" in reqmod(H, P, call("write")))
clean = respmod(H, P, b"row count is 42")
chk("RESPMOD clean -> emitted", b"row count is 42" in clean)
pii = respmod(H, P, b"user ssn 123-45-6789 email bob@corp.com")
chk("RESPMOD PII -> redacted (span-masked)", b"[SSN]" in pii and b"[EMAIL]" in pii and b"123-45-6789" not in pii)
secret = respmod(H, P, b"password: hunter2")
chk("RESPMOD secret -> withheld", b"withheld by Chai policy" in secret)
print(f"\n{sum(res)}/{len(res)}"); sys.exit(0 if all(res) else 1)
