# Keep-alive HTTP server: /a answers at once, /b0 after 0.5 s with a 302 to /b1, /b1 at once.
import socket, sys, threading, time
def serve(c):
    buf = b""
    while True:
        while b"\r\n\r\n" not in buf:
            d = c.recv(65536)
            if not d: c.close(); return
            buf += d
        head, buf = buf.split(b"\r\n\r\n", 1)
        path = head.split(b" ")[1]
        if path == b"/b0":
            time.sleep(0.5)
            c.sendall(b"HTTP/1.1 302 Found\r\nLocation: /b1\r\nContent-Length: 0\r\n\r\n")
        else:
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(8)
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
