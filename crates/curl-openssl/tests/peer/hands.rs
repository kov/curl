//! The application's hands on OpenSSL: the context handler
//! (`CURLOPT_SSL_CTX_FUNCTION`), called with the `SSL_CTX` made whole,
//! and the `SSL_CTX` and `SSL` a transfer's handlers reach
//! (`CURLINFO_TLS_SESSION`, `CURLINFO_TLS_SSL_PTR`).

use curl_core::handler::TlsContextHandler;
use curl_core::tls::TlsNative;

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "the_context_handler_gets_the_context_with_its_trust_store_set_up",
        the_context_handler_gets_the_context_with_its_trust_store_set_up,
    ),
    (
        "the_context_handler_s_error_fails_the_handshake_before_it_starts",
        the_context_handler_s_error_fails_the_handshake_before_it_starts,
    ),
];

/// The addresses of a library's objects, which a test can keep.
type Objects = (usize, Option<usize>);

fn objects(n: TlsNative) -> Objects {
    (
        n.context().addr().get(),
        n.session().map(|s| s.addr().get()),
    )
}

/// What the handlers saw: the context the handler was given, with the
/// lines the transfer had said by then; and the objects the write
/// handler reached.
#[derive(Default)]
struct Hands {
    given: Vec<(Objects, usize)>,
    written: Vec<Option<Objects>>,
}

/// A context handler noting what it is given, answering `answer`; and a
/// write handler noting what the transfer reaches.
struct Noting {
    hands: Arc<Mutex<Hands>>,
    seen: Arc<Mutex<Seen>>,
    answer: Result<(), ErrorKind>,
}

impl TlsContextHandler for Noting {
    fn configure(&self, _: &mut TransferCx<'_>, native: TlsNative) -> Result<(), ErrorKind> {
        track::untracked(|| {
            let said = self.seen.lock().unwrap().lines.len();
            self.hands
                .lock()
                .unwrap()
                .given
                .push((objects(native), said));
        });
        self.answer
    }
}

impl WriteHandler for Noting {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
        let reached = cx.tls_native(cx.me()).map(objects);
        track::untracked(|| self.hands.lock().unwrap().written.push(reached));
        Write::Took(body.len())
    }
}

/// A GET whose context handler answers `answer`: what it came to, and
/// what the handlers saw.
fn get_noting(certs: &Certs, at: SocketAddr, answer: Result<(), ErrorKind>) -> (Got, Hands) {
    let hands = track::untracked(|| Arc::new(Mutex::new(Hands::default())));
    // The debug handler `get` installs notes its lines here.
    let seen = track::untracked(|| Arc::new(Mutex::new(Seen::default())));
    let got = get("localhost", at, |o| {
        trusting(certs)(o);
        let noting = || Noting {
            hands: hands.clone(),
            seen: seen.clone(),
            answer,
        };
        o.tls.options.make_mut().unwrap().context = Some(Handler::tls_context(noting()).unwrap());
        o.callbacks.write = Some(Handler::write(noting()).unwrap());
        o.callbacks.debug = Some(Handler::debug(Taker(seen.clone())).unwrap());
    });
    let hands = track::untracked(|| std::mem::take(&mut *hands.lock().unwrap()));
    let lines = track::untracked(|| std::mem::take(&mut seen.lock().unwrap().lines));
    let got = Got {
        seen: Seen { lines, ..got.seen },
        ..got
    };
    (got, hands)
}

/// The handler is called once, given the context before the `SSL` is
/// made, its trust store loaded already (C loads it first for the
/// handler, #11800), and the write handler reaches the same context and
/// the connection's `SSL`.
fn the_context_handler_gets_the_context_with_its_trust_store_set_up() {
    let certs = certs("hands", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    let (got, hands) = get_noting(&certs, at, Ok(()));
    server.join().unwrap();
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    let [((context, None), said)] = hands.given[..] else {
        panic!("{:?}", hands.given);
    };
    let ca = format!("  CAfile: {}", certs.ca_file.display());
    let loaded = got.seen.lines.iter().position(|l| *l == ca);
    assert!(
        loaded.is_some_and(|at| at < said),
        "the store set up after the handler: {:#?}",
        got.seen.lines
    );
    assert!(!hands.written.is_empty());
    for reached in &hands.written {
        let Some((c, Some(ssl))) = *reached else {
            panic!("{:?}", hands.written);
        };
        assert_eq!(c, context);
        assert_ne!(ssl, context);
    }
}

/// The handler's error fails the transfer with its kind, said as C says
/// it, before a byte of the handshake is sent: the server sees none.
fn the_context_handler_s_error_fails_the_handshake_before_it_starts() {
    let certs = certs("hands-error", "localhost", &["localhost"]);
    let (at, server) = serve(&certs);
    let (got, hands) = get_noting(&certs, at, Err(ErrorKind::SslCertproblem));
    assert_eq!(got.result, Err(ErrorKind::SslCertproblem));
    assert_eq!(got.failure, b"error signaled by SSL ctx callback");
    assert_eq!(hands.given.len(), 1);
    assert!(server.join().unwrap().is_empty());
}
