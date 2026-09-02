"""Send one REQMOD to shield-icap the way a SWG would, without needing Squid.

    python deploy/swg/dev/icap_probe.py <port> "<prompt text>" [host]

Prints the ICAP status line, and for a block the reason and the correlation
reference a user would quote to the help desk. Development only.
"""
import json
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 1344
text = sys.argv[2] if len(sys.argv) > 2 else "what is the weather"
host = sys.argv[3] if len(sys.argv) > 3 else "api.anthropic.com"

body = json.dumps({"model": "claude-opus-4", "messages": [{"role": "user", "content": text}]}).encode()
http_hdr = (
    f"POST /v1/messages HTTP/1.1\r\nHost: {host}\r\n"
    f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
).encode()

head = (
    "REQMOD icap://127.0.0.1/screen ICAP/1.0\r\n"
    "Host: 127.0.0.1\r\n"
    "Allow: 204\r\n"
    "X-Authenticated-User: alice@corp.example\r\n"
    f"Encapsulated: req-hdr=0, req-body={len(http_hdr)}\r\n\r\n"
).encode()
chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)

s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(head + http_hdr + chunked)
s.settimeout(3)
buf = b""
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
except socket.timeout:
    pass
s.close()

print(f"  prompt : {text!r}")
first = buf.split(b"\r\n", 1)[0].decode(errors="replace")
print(f"  verdict: {first}")
if b"403" in buf:
    payload = buf[buf.rindex(b"{"):buf.rindex(b"}") + 1]
    print("  reason :", json.loads(payload)["reason"])
    print("  ref    :", json.loads(payload)["reference"])
