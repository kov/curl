//! HTTPS GETs over OpenSSL with each of the client's tracked allocations
//! refused in turn, with the rest as `runtests.pl -t` refuses them, and
//! alone: each run must fail, never abort, and leave nothing allocated. The options set are the ones whose code allocates beside
//! the handshake: a pinned key's file, a client certificate, the chain
//! reported and a CRL.

use std::sync::atomic::{AtomicBool, Ordering};

use super::client::{bytes, client};
use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[(
    "an_https_get_survives_each_allocation_refused",
    an_https_get_survives_each_allocation_refused,
)];

/// A server answering every connection's GET with `BODY`, each on a
/// thread of its own, until the flag is set: a run refused before it
/// connects leaves no connection to wait for. A client's certificate is
/// asked for, and checked against `ca` if given.
fn serve_all(certs: &Certs, ca: Option<X509>) -> (SocketAddr, Arc<AtomicBool>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&certs.key).unwrap();
    acceptor.set_certificate(&certs.cert).unwrap();
    if let Some(ca) = ca {
        use openssl::ssl::SslVerifyMode;
        acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        acceptor.cert_store_mut().add_cert(ca).unwrap();
    }
    let acceptor = Arc::new(acceptor.build());
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    // Untracked, so that what a connection's thread holds as the client
    // ends is not counted as the client's.
    let server = std::thread::spawn(move || {
        track::untracked(|| {
            for tcp in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(tcp) = tcp else { continue };
                let acceptor = acceptor.clone();
                std::thread::spawn(move || {
                    track::untracked(|| {
                        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                            .unwrap();
                        let Ok(mut tls) = acceptor.accept(tcp) else {
                            return;
                        };
                        let mut got = Vec::new();
                        let mut buf = [0u8; 4096];
                        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                            match tls.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => got.extend_from_slice(&buf[..n]),
                            }
                        }
                        let head =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BODY.len());
                        let _ = tls.write_all(head.as_bytes());
                        let _ = tls.write_all(BODY);
                        let _ = tls.shutdown();
                    })
                });
            }
        })
    });
    (at, stop, server)
}

/// What a run came to: its transfer's result, or out of memory before
/// it could have one; and the body it wrote.
type Outcome = (Result<(), ErrorKind>, Vec<u8>);

/// A GET of `/` at `at` with the options `set` makes, every refusal of
/// the client's own setup taken as the transfer's out of memory.
fn try_get(
    at: SocketAddr,
    set: &dyn Fn(&mut Options) -> Result<(), curl_alloc::OutOfMemory>,
) -> Outcome {
    use curl_core::error::MultiErrorKind;
    use curl_core::multi::AddError;
    let seen = track::untracked(|| Arc::new(Mutex::new(Seen::default())));
    let oom = (Err(ErrorKind::OutOfMemory), Vec::new());
    let result = (|| {
        let env = Env {
            clock: try_box(SystemClock::new())?,
            net: try_box(SystemNet::default())?,
            arena: ArenaPolicy::new(16, 0).unwrap(),
            waker: None,
        };
        let mut m: Multi = Multi::new(env)?;
        let mut easy = Easy::new();
        easy.set_libraries(SharedLibraries::of_static(&LIBRARIES));
        let o = easy.options_mut();
        let url = track::untracked(|| format!("https://localhost:{}/", at.port()));
        o.set_url(Some(url.as_bytes()))?;
        o.ip_version = IpVersion::V4;
        o.callbacks.write = Some(Handler::write(Taker(seen.clone()))?);
        set(o)?;
        let id = match m.add(try_box(easy)?, (), &mut NoEvents) {
            Ok(id) => id,
            Err(AddError {
                kind: MultiErrorKind::OutOfMemory,
                ..
            }) => return Err(curl_alloc::OutOfMemory),
            Err(e) => panic!("add refused with {:?}, not for memory", e.kind),
        };
        let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents)
            .expect("the transfer is in the multi");
        m.remove(id, &mut NoEvents).expect("in the multi");
        Ok(result)
    })();
    let Ok(result) = result else { return oom };
    let body = track::untracked(|| std::mem::take(&mut seen.lock().unwrap().body));
    (result, body)
}

/// A copy of bytes that fails for memory as the library's own do.
trait Copied {
    fn copied(&self) -> Result<Vec<u8>, curl_alloc::OutOfMemory>;
}

impl Copied for Vec<u8> {
    fn copied(&self) -> Result<Vec<u8>, curl_alloc::OutOfMemory> {
        use curl_alloc::TryVec as _;
        let mut v = Vec::new();
        v.try_extend_from_slice(self)?;
        Ok(v)
    }
}

fn an_https_get_survives_each_allocation_refused() {
    let certs = certs("torture", "localhost", &["localhost"]);
    let client = client("torture");
    let pin = certs_dir().join("torture.pub.der");
    std::fs::write(&pin, certs.key.public_key_to_der().unwrap()).unwrap();
    let crl = super::checks::crl(&certs, "torture", false);
    let (at, stop, server) = serve_all(&certs, Some(client.ca.clone()));
    let (ca, pin, crl, cert, key) = track::untracked(|| {
        (
            bytes(&certs.ca_file),
            bytes(&pin),
            bytes(&crl),
            bytes(&client.cert_pem),
            bytes(&client.key_pem),
        )
    });
    let set = |o: &mut Options| -> Result<(), curl_alloc::OutOfMemory> {
        o.tls.certinfo = true;
        let t = o.tls.options.make_mut()?;
        t.ca_file = CaSetting::Given(ca.copied()?);
        t.pinned_key = Some(pin.copied()?);
        t.crl_file = Some(crl.copied()?);
        t.cert = Some(cert.copied()?);
        t.key = Some(key.copied()?);
        Ok(())
    };
    let (result, body) = try_get(at, &set);
    assert_eq!(result, Ok(()));
    assert_eq!(body, BODY);
    // As `runtests.pl -t` refuses them, the rest refused too: the GET
    // fails out of memory. Then that one alone, the rest allowed: the GET
    // fails, though not always for memory, as a store set up once the
    // hello is sent is set up again if the read the hello's answer is
    // in could not, as C does; or it succeeds whole.
    let mut limit = 0;
    loop {
        let mut refused_any = false;
        for once in [false, true] {
            let live = track::live_tracked();
            let run = || try_get(at, &set);
            let ((result, body), refused) = if once {
                track::fail_once_after_here(limit, run)
            } else {
                track::fail_after(limit, run)
            };
            assert_eq!(
                track::live_tracked(),
                live,
                "refusing allocation {limit} (alone: {once}) left memory allocated"
            );
            refused_any |= refused;
            if !refused || (once && result.is_ok()) {
                // A refusal alone of what C lets fail, a ticket's copy
                // for the session cache (`ossl_new_session_cb`), leaves
                // the transfer whole.
                assert_eq!(result, Ok(()));
                assert_eq!(body, BODY, "refusing allocation {limit} alone");
            } else if !once {
                // Out of memory, or as C answers the peer's key's copy
                // refused: a mismatch (`ossl_pkp_pin_peer_pubkey`).
                assert!(
                    matches!(
                        result,
                        Err(ErrorKind::OutOfMemory | ErrorKind::SslPinnedpubkeynotmatch)
                    ),
                    "refusing allocation {limit} and the rest: {result:?}"
                );
            }
        }
        if !refused_any {
            break;
        }
        limit += 1;
    }
    track::untracked(|| eprintln!("torture: an HTTPS GET refused each of {limit} allocations"));
    stop.store(true, Ordering::SeqCst);
    let _ = std::net::TcpStream::connect(at);
    server.join().unwrap();
}
