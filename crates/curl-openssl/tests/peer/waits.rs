//! What the session waits for, and what it does when the socket below
//! would block or fails (`ossl_connect_step2`, `ossl_send`,
//! `Curl_ssl_adjust_pollset`): over a network whose sockets stutter, each
//! send and receive that would go through first saying it would block,
//! or failing as told.

use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use curl_alloc::TryArc;
use curl_core::conn::io::{
    AtOnce, Connect, InterfaceAddress, Ipv6Scope, Net, PollFd, Readiness, Recv, Remote, Resolver,
    Sent, Sock, Socket, SocketKey, SocketOption, SocketPoll,
};
use curl_core::options::{Method, UploadSource};

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "a_socket_that_stutters_has_each_step_wait_and_go_on",
        a_socket_that_stutters_has_each_step_wait_and_go_on,
    ),
    (
        "a_send_the_socket_fails_is_said_as_c_says",
        a_send_the_socket_fails_is_said_as_c_says,
    ),
    (
        "a_receive_failing_without_errno_is_said_as_c_says",
        a_receive_failing_without_errno_is_said_as_c_says,
    ),
    (
        "a_handshake_waiting_for_the_peer_waits_for_it_to_be_readable",
        a_handshake_waiting_for_the_peer_waits_for_it_to_be_readable,
    ),
    (
        "a_read_waiting_for_the_peer_waits_for_it_to_be_readable",
        a_read_waiting_for_the_peer_waits_for_it_to_be_readable,
    ),
];

/// What the sockets of a `Stutter` do.
#[derive(Clone, Copy, Default)]
pub(crate) struct Plan {
    /// Every first try of a send or a receive would block.
    pub(crate) stutter: bool,
    /// The send of this number, counting from 1, fails as a system call
    /// fails, `errno` set: a send on an unconnected socket's.
    pub(crate) fail_send: Option<u32>,
    /// Once this many sends went through, each receive fails, as a layer
    /// below fails that says no system error (`errno` 0).
    pub(crate) fail_recv_after: Option<u32>,
    /// Every name resolves to 127.0.0.1, however long.
    pub(crate) any_name: bool,
}

/// The system's network, its sockets as the plan says.
struct Stutter(SystemNet, Plan);

#[derive(Debug)]
struct StutterSocket {
    inner: Box<dyn Socket>,
    stutter: bool,
    fail_send: Option<u32>,
    fail_recv_after: Option<u32>,
    sends: AtomicU32,
    /// The tries so far, a send's and a receive's: an odd one would block.
    tries: [AtomicU32; 2],
}

impl StutterSocket {
    fn blocks(&self, way: usize) -> bool {
        self.stutter
            && self.tries[way]
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(2)
    }
}

impl Socket for StutterSocket {
    fn key(&self) -> SocketKey {
        self.inner.key()
    }
    fn readiness(&self) -> Readiness<'_> {
        self.inner.readiness()
    }
    fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn set(&self, option: SocketOption) -> io::Result<()> {
        self.inner.set(option)
    }
    fn set_nonblocking(&self) -> io::Result<()> {
        self.inner.set_nonblocking()
    }
    fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        self.inner.bind(addr)
    }
    fn bind_to_device(&self, name: &[u8]) -> io::Result<()> {
        self.inner.bind_to_device(name)
    }
    fn connect(&self, addr: &Remote) -> io::Result<Connect> {
        self.inner.connect(addr)
    }
    fn recv(&self, buf: &mut [u8]) -> io::Result<Recv> {
        if self.blocks(1) {
            return Ok(Recv::WouldBlock);
        }
        if let Some(after) = self.fail_recv_after
            && self.sends.load(Ordering::Relaxed) >= after
        {
            return Err(io::Error::other("the layer below failed"));
        }
        self.inner.recv(buf)
    }
    fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        if self.blocks(0) {
            return Ok(Sent::WouldBlock);
        }
        let n = self.sends.fetch_add(1, Ordering::Relaxed) + 1;
        if self.fail_send == Some(n) {
            let unconnected = std::net::UdpSocket::bind("127.0.0.1:0")?;
            return Err(unconnected.send(buf).expect_err("no address to send to"));
        }
        self.inner.send(buf)
    }
    fn release(self: Box<Self>) -> SocketKey {
        self.inner.release()
    }
}

impl Net for Stutter {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32> {
        self.0.poll(sockets, fds, timeout)
    }
    fn open(
        &mut self,
        addr: &Remote,
        kind: curl_core::conn::io::SocketKind,
    ) -> io::Result<Box<dyn Socket>> {
        let inner = self.0.open(addr, kind)?;
        let socket = StutterSocket {
            inner,
            stutter: self.1.stutter,
            fail_send: self.1.fail_send,
            fail_recv_after: self.1.fail_recv_after,
            sends: AtomicU32::new(0),
            tries: [AtomicU32::new(0), AtomicU32::new(0)],
        };
        Ok(try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)?)
    }
    fn close(&mut self, socket: Sock) {
        self.0.close(socket)
    }
    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
        if self.1.any_name {
            f(&mut AtOnce(|_: &[u8], _| {
                Ok(track::untracked(|| vec![IpAddr::from([127, 0, 0, 1])]))
            }));
            return;
        }
        self.0.with_resolver(f);
    }
    fn link_local_scope(&mut self) -> Option<NonZeroU32> {
        self.0.link_local_scope()
    }
    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: Ipv6Scope,
        scope_id: u32,
    ) -> InterfaceAddress {
        self.0.interface_address(name, v6, remote_scope, scope_id)
    }
}

/// A GET of `host` at `at`'s port over a network that does as `plan`
/// says, the TLS layer traced.
pub(crate) fn get_over(
    plan: Plan,
    host: &str,
    at: SocketAddr,
    set: impl FnOnce(&mut Options),
) -> Got {
    let env = Env {
        clock: try_box(SystemClock::new()).unwrap(),
        net: try_box(Stutter(SystemNet::default(), plan)).unwrap(),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    get_in(&mut m, "https", host, at, set, true)
}

fn count(got: &Got, line: &str) -> usize {
    got.seen.lines.iter().filter(|l| l.as_str() == line).count()
}

/// A socket whose every first try would block: the handshake waits to
/// send (`SSL_ERROR_WANT_WRITE`) and to receive, and a send waits and is
/// given again, until the transfer is done as it would be without.
fn a_socket_that_stutters_has_each_step_wait_and_go_on() {
    let certs = certs("stutter", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    let plan = Plan {
        stutter: true,
        ..Plan::default()
    };
    let began = std::time::Instant::now();
    let got = get_over(plan, "localhost", at, trusting(&certs));
    let took = began.elapsed();
    let sent = server.join().unwrap();
    // A send that would block waits for the socket to be writable, which
    // it is at once; waiting for it to be readable instead, the handshake
    // would stall until the multi's wait gives up, a second each time.
    assert!(took < Duration::from_millis(1500), "{took:?}");
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);
    assert!(sent.starts_with(b"GET / HTTP/1.1\r\n"));
    for line in [
        "[SSL] SSL_connect() -> want send",
        "[SSL] SSL_connect() -> want recv",
    ] {
        assert!(count(&got, line) > 0, "{line} in {:#?}", got.seen.lines);
    }
    // The request's record, its first try blocked.
    assert!(
        got.seen
            .lines
            .iter()
            .any(|l| l.starts_with("[SSL] ossl_bio_cf_out_write(len=") && l.ends_with(" -> 81, 0")),
        "{:#?}",
        got.seen.lines
    );
}

/// A send the socket fails, the request's, fails the transfer: the
/// socket's failure said first, then OpenSSL's write said with the error
/// the library queued for the system call (`SSL_ERROR_SYSCALL`).
fn a_send_the_socket_fails_is_said_as_c_says() {
    let certs = certs("sendfails", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    // The ClientHello, the Finished, then the request.
    let plan = Plan {
        fail_send: Some(3),
        ..Plan::default()
    };
    let got = get_over(plan, "localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(
        got.result,
        Err(ErrorKind::SendError),
        "{:#?}",
        got.seen.lines
    );
    assert_eq!(got.failure, b"Send failure: Destination address required");
    let line = format!(
        "OpenSSL SSL_write: OpenSSL/{}: error:80000059:system library::Destination address \
         required, errno 89",
        openssl::version::version().split(' ').nth(1).unwrap()
    );
    assert!(said(&got, &line), "{:#?}", got.seen.lines);
}

/// A receive that fails without a system error, as a layer below may
/// (`SOCKERRNO` 0), is said by what OpenSSL's answer was: in the
/// handshake with the peer, after it with `errno 0`.
fn a_receive_failing_without_errno_is_said_as_c_says() {
    let certs = certs("recvfails", "localhost", &["localhost"]);
    // After the ClientHello: the handshake's first receive.
    let (at, server) = serve(&certs);
    let plan = Plan {
        fail_recv_after: Some(1),
        ..Plan::default()
    };
    let got = get_over(plan, "localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(got.result, Err(ErrorKind::SslConnectError));
    assert_eq!(got.failure, b"Recv failure: the layer below failed");
    let line = format!(
        "OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to localhost:{}",
        at.port()
    );
    assert!(said(&got, &line), "{line:?} in {:#?}", got.seen.lines);
    // After the request: the response's.
    let (at, server) = serve(&certs);
    let plan = Plan {
        fail_recv_after: Some(3),
        ..Plan::default()
    };
    let got = get_over(plan, "localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(
        got.result,
        Err(ErrorKind::RecvError),
        "{:#?}",
        got.seen.lines
    );
    assert_eq!(got.failure, b"Recv failure: the layer below failed");
    assert!(
        said(&got, "OpenSSL SSL_read: SSL_ERROR_SYSCALL, errno 0"),
        "{:#?}",
        got.seen.lines
    );
}

/// A server that answers the ClientHello after `delay`, then serves as
/// `serve` does, with the body sent in three parts `delay` apart.
fn serve_late(certs: &Certs, delay: Duration) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&certs.key).unwrap();
    acceptor.set_certificate(&certs.cert).unwrap();
    let acceptor = acceptor.build();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_nodelay(true).unwrap();
        std::thread::sleep(delay);
        let mut tls = acceptor.accept(tcp).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BODY.len());
        tls.write_all(head.as_bytes()).unwrap();
        for part in BODY.chunks(BODY.len().div_ceil(3)) {
            std::thread::sleep(delay);
            tls.write_all(part).unwrap();
        }
        let _ = tls.shutdown();
    });
    (at, server)
}

/// The handshake waiting for the server's answer waits for the socket to
/// be readable: a server that answers late is tried a few times, not
/// spun on.
fn a_handshake_waiting_for_the_peer_waits_for_it_to_be_readable() {
    let certs = certs("latehello", "localhost", &["localhost"]);
    let (at, server) = serve_late(&certs, Duration::from_millis(300));
    let plan = Plan::default();
    let got = get_over(plan, "localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let waits = count(&got, "[SSL] SSL_connect() -> want recv");
    assert!((1..20).contains(&waits), "{waits} waits");
}

/// A read that would block waits for the socket to be readable: the
/// session holds nothing then, and a body that comes late is not spun on.
fn a_read_waiting_for_the_peer_waits_for_it_to_be_readable() {
    let certs = certs("latebody", "localhost", &["localhost"]);
    let (at, server) = serve_late(&certs, Duration::from_millis(100));
    let plan = Plan::default();
    let got = get_over(plan, "localhost", at, |o| {
        trusting(&certs)(o);
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(TryArc::try_new(b"posted".to_vec()).unwrap());
    });
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert_eq!(got.seen.body, BODY);
    let waits = got
        .seen
        .lines
        .iter()
        .filter(|l| l.starts_with("[SSL] ossl_recv(") && l.contains(") -> 81, 0"))
        .count();
    assert!((1..40).contains(&waits), "{waits} waits");
}
