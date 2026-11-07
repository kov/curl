//! Schannel as the core's TLS library against a real peer: a server
//! thread speaking TLS through the `openssl` crate on a loopback socket,
//! the client's transfers through the system's network. Windows only.

#![cfg(windows)]
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::io::{self, Read, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use curl_alloc::{TryArc, try_box};
use curl_core::conn::io::{
    Connect, InterfaceAddress, Ipv6Scope, Net, PollFd, Readiness, Recv, Remote, Resolver, Sent,
    Sock, Socket, SocketKey, SocketKind, SocketOption, SocketPoll, SystemNet,
};
use curl_core::easy::Easy;
use curl_core::error::ErrorKind;
use curl_core::handler::{Handler, Write, WriteHandler};
use curl_core::id::ArenaPolicy;
use curl_core::libraries::{Libraries, Library, SharedLibraries};
use curl_core::multi::{Env, Multi, NoEvents, TransferCx};
use curl_core::options::{IpVersion, Method, UploadSource};
use curl_core::time::SystemClock;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::{X509, X509Name};

static LIBRARIES: Libraries = Libraries {
    tls: Some(Library::Static(&curl_schannel::SCHANNEL)),
    ..Libraries::NONE
};

/// The most a socket's send takes at once, so that a record goes in
/// pieces.
const PIECE: usize = 700;

/// The system's network, each socket's sends of more than `PIECE` bytes,
/// the body's records, taking `PIECE` and every other one saying it
/// would block. The handshake's, smaller, go whole: C's sends each of
/// them once and fails if it does not go whole, as the session does.
struct Choppy(SystemNet, Arc<Seen>);

/// What the sockets saw.
#[derive(Debug, Default)]
struct Seen {
    /// The last send took part of what it was given.
    cut: AtomicBool,
    /// Sends that would block right after one that took part of what it
    /// was given: a record left half sent.
    blocked_mid_record: AtomicU32,
    /// A record was left half sent, and the multi has not polled since.
    unpolled: AtomicBool,
    /// Sends tried again with a record half sent before the multi polled:
    /// a session spinning on the socket in place of waiting.
    spun: AtomicU32,
}

#[derive(Debug)]
struct ChoppySocket {
    inner: Box<dyn Socket>,
    tries: AtomicU32,
    seen: Arc<Seen>,
}

impl Socket for ChoppySocket {
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
    fn connect(&self, addr: &Remote) -> io::Result<Connect> {
        self.inner.connect(addr)
    }
    fn recv(&self, buf: &mut [u8]) -> io::Result<Recv> {
        self.inner.recv(buf)
    }
    fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        let seen = &self.seen;
        if buf.len() <= PIECE && !seen.cut.load(Ordering::Relaxed) {
            return self.inner.send(buf);
        }
        if seen.unpolled.load(Ordering::Relaxed) {
            seen.spun.fetch_add(1, Ordering::Relaxed);
        }
        if self.tries.fetch_add(1, Ordering::Relaxed) % 2 == 1 {
            if seen.cut.swap(false, Ordering::Relaxed) {
                seen.blocked_mid_record.fetch_add(1, Ordering::Relaxed);
                seen.unpolled.store(true, Ordering::Relaxed);
            }
            return Ok(Sent::WouldBlock);
        }
        let n = buf.len().min(PIECE);
        let sent = self.inner.send(&buf[..n])?;
        if let Sent::Bytes(went) = sent {
            seen.cut.store(went.get() < buf.len(), Ordering::Relaxed);
        }
        Ok(sent)
    }
    fn release(self: Box<Self>) -> SocketKey {
        self.inner.release()
    }
}

impl Net for Choppy {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32> {
        self.1.unpolled.store(false, Ordering::Relaxed);
        self.0.poll(sockets, fds, timeout)
    }
    fn open(&mut self, addr: &Remote, kind: SocketKind) -> io::Result<Box<dyn Socket>> {
        let inner = self.0.open(addr, kind)?;
        let socket = ChoppySocket {
            inner,
            tries: AtomicU32::new(0),
            seen: self.1.clone(),
        };
        Ok(try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)?)
    }
    fn close(&mut self, socket: Sock) {
        self.0.close(socket)
    }
    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
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

/// A server for one connection, with a certificate of its own: it reads
/// a request and its body of `Content-Length` bytes, answers `ok`, and
/// gives back what it read.
fn serve() -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "localhost")
        .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = cert.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    let acceptor = acceptor.build();
    let server = std::thread::spawn(move || {
        let (tcp, _) = curl_core::test_server::accept(&listener);
        // A handshake the client gives up is the client's failure to say.
        let Ok(mut tls) = acceptor.accept(tcp) else {
            return Vec::new();
        };
        let mut got = Vec::new();
        let mut buf = [0u8; 16384];
        let body_at = loop {
            if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return got,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        };
        let head = String::from_utf8_lossy(&got[..body_at]).to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .and_then(|n| n.trim().parse().ok())
            .unwrap_or(0);
        while got.len() < body_at + length {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return got,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = tls.shutdown();
        got
    });
    (at, server)
}

struct Body(Arc<Mutex<Vec<u8>>>);

impl WriteHandler for Body {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.lock().unwrap().extend_from_slice(body);
        Write::Took(body.len())
    }
}

/// A record the socket takes part of and then would not take more of is
/// not waited for in the session, as C's `schannel_send` waits for the
/// socket (`SOCKET_WRITABLE` with the transfer's timeout) until the record
/// has gone whole: the session says it waits to send and is called again,
/// sending the rest of the record before anything else, so the peer gets
/// each byte once and in order. DIVERGENCE.md, "Waits C makes blocking".
#[test]
fn a_record_half_sent_is_waited_for_by_the_multi() {
    let (at, server) = serve();
    let seen = Arc::new(Seen::default());
    let env = Env {
        clock: try_box(SystemClock::new()).unwrap(),
        net: try_box(Choppy(SystemNet::default(), seen.clone())).unwrap(),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let posted: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let body = Arc::new(Mutex::new(Vec::new()));
    let mut easy = Easy::new();
    easy.set_libraries(SharedLibraries::of_static(&LIBRARIES));
    let o = easy.options_mut();
    let url = format!("https://localhost:{}/", at.port());
    o.set_url(Some(url.as_bytes())).unwrap();
    o.ip_version = IpVersion::V4;
    o.tls.verify_peer = false;
    o.tls.verify_host = false;
    o.method = Method::Post;
    o.upload = UploadSource::Bytes(TryArc::try_new(posted.clone()).unwrap());
    o.callbacks.write = Some(Handler::write(Body(body.clone())).unwrap());
    let id = m.add(try_box(easy).unwrap(), (), &mut NoEvents).unwrap();
    let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let easy = m.remove(id, &mut NoEvents).unwrap().easy;
    let failure = String::from_utf8_lossy(easy.report().failure().unwrap_or_default()).into_owned();
    let got = server.join().unwrap();
    assert_eq!(result, Ok::<(), ErrorKind>(()), "{failure}");
    assert_eq!(&*body.lock().unwrap(), b"ok");
    let at = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(got[..at].starts_with(b"POST / HTTP/1.1\r\n"));
    assert_eq!(got.len() - at, posted.len());
    assert!(got[at..] == posted[..], "the body arrived changed");
    // Records go in pieces, and some piece was refused with the rest of
    // its record still to go; the session gave the wait back, the multi
    // polling before the record's next piece was tried, where a session
    // waiting in place would try it again at once every time.
    let waits = seen.blocked_mid_record.load(Ordering::Relaxed);
    let spun = seen.spun.load(Ordering::Relaxed);
    assert!(waits > 0, "no record was left half sent");
    assert!(spun < waits, "{spun} of {waits} waits tried again in place");
}
