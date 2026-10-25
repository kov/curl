# One-shot HTTP server: prints the request head it receives, answers 200 with an empty body.
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(1)
c, _ = s.accept(); data = b""
while b"\r\n\r\n" not in data:
    d = c.recv(65536)
    if not d: break
    data += d
sys.stdout.write(repr(data.split(b"\r\n\r\n")[0].decode()) + "\n"); sys.stdout.flush()
c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); c.close()
