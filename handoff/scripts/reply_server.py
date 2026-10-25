# One-shot server: reads a request head, sends the bytes of the file argv[2], then closes.
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(1)
c, _ = s.accept(); data = b""
while b"\r\n\r\n" not in data:
    d = c.recv(65536)
    if not d: break
    data += d
c.sendall(open(sys.argv[2], "rb").read()); c.close()
