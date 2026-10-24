//! HTTPS over the fake TLS library: the handshake as the last stage of
//! the setup, the bytes through its layer both ways, reuse by identity,
//! what the transfer waits for, and the goodbye.

use super::*;
use crate::conn::io::Events;
use crate::conn::io::{Recv, Sent};
use crate::libraries::Libraries;
use crate::tls::fake::{self, FINISHED, FakeTls, HELLO, WELCOME};
use crate::tls::{Handshake, TlsPeerKind, fake::FakeLog};
use curl_alloc::TryArc;
use std::io;

/// A fake TLS library of the test's own, and the libraries naming it,
/// for the test's handles: made once per test, kept to its end.
pub(super) fn tls() -> (&'static FakeTls, &'static Libraries) {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let libraries = Box::leak(Box::new(Libraries {
        tls: Some(backend),
        ..Libraries::NONE
    }));
    (backend, libraries)
}

/// What a server says for `response`: its handshake's answer, then the
/// response as records.
fn served(response: &[u8]) -> [Vec<u8>; 2] {
    [WELCOME.to_vec(), fake::records(response).unwrap()]
}

/// A verbose HTTPS GET of `path` on `m`, whose server is `talk`, by a
/// handle with `libraries`.
fn get_tls(
    m: &mut Multi,
    libraries: &'static Libraries,
    path: &str,
    talk: Conversation,
    set: impl FnOnce(&mut Options),
) -> Ran {
    let mut e = Easy::new();
    e.set_libraries(libraries);
    get_with(m, e, path, talk, |o| {
        let url = format!("https://127.0.0.1:{PORT}{path}");
        o.set_url(Some(url.as_bytes())).unwrap();
        set(o);
    })
}

/// What the server was sent, its records read.
fn sent(talk: &Conversation) -> Vec<u8> {
    fake::read_client(&talk.received()).unwrap()
}

/// What the server was sent in the clear, its first `n` bytes, and what
/// it was sent over TLS after, its records read.
fn sent_after(talk: &Conversation, n: usize) -> (Vec<u8>, Vec<u8>) {
    let wire = talk.received();
    let (clear, tls) = wire.split_at(n);
    (clear.to_vec(), fake::read_client(tls).unwrap())
}

/// A handle with the libraries `libraries`, getting `/` from the server
/// over HTTPS as `get` would.
fn https_handle(libraries: &'static Libraries) -> Box<Easy> {
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let url = format!("https://127.0.0.1:{PORT}/");
    e.options_mut().set_url(Some(url.as_bytes())).unwrap();
    e.options_mut().http.user_agent = Some(b"curl/test".to_vec());
    Box::new(e)
}

/// The handshake, then the request, as the client sends them.
fn handshake_then(request: &[u8]) -> Vec<u8> {
    [HELLO, FINISHED, request].concat()
}

/// An HTTPS GET makes its TLS over the connection once it is up, as the
/// last of its setup, with the origin as the peer; the request goes
/// through it as records and the response comes back through it.
#[test]
fn an_https_get_goes_through_its_tls_layer() {
    let (backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let (mut m, talk, _) = server(&[&welcome, &response], false);
    let ran = get_tls(&mut m, libraries, "/a", talk.clone(), |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(sent(&talk), handshake_then(&request_of("/a")));
    // On the wire the request is records, not in the clear.
    let wire = talk.received();
    let records = fake::records(&request_of("/a")).unwrap();
    assert_eq!(wire, [HELLO, FINISHED, &records].concat());
    assert!(!wire.windows(4).any(|w| w == b"GET "), "{wire:?}");
    assert_eq!(ran.seen.body(), b"ok\n");
    let log: FakeLog = backend.log();
    assert_eq!((log.sessions, log.handshakes), (1, 1));
    assert_eq!(log.name(), b"127.0.0.1");
    assert_eq!((log.port, log.kind), (PORT, Some(TlsPeerKind::Ipv4)));
    assert!(log.verify_peer);
    let text = ran.seen.text();
    assert_eq!(
        text.last().unwrap(),
        &format!("Connection #0 to host 127.0.0.1:{PORT} left intact\n")
    );
    // Its TLS was up as the connection was (`TIMER_APPCONNECT`), which a
    // plain GET never marks.
    let timings = ran.easy.report().timings();
    assert!(timings.appconnect() > Duration::ZERO);
    let plain = run("/", OK, false, |_| {});
    assert_eq!(plain.easy.report().timings().appconnect(), Duration::ZERO);
}

/// A record longer than the transfer's read is given out over as many
/// reads, from what the session holds, without waiting on the socket,
/// which has nothing more to say.
#[test]
fn a_record_longer_than_a_read_is_read_without_waiting() {
    let (_, libraries) = tls();
    let body = vec![b'x'; 3000];
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(&body);
    let [welcome, records] = served(&response);
    let (mut m, talk, clock) = server(&[&welcome, &records], false);
    let start = clock.now();
    let ran = get_tls(&mut m, libraries, "/", talk, |o| {
        o.limits.buffer_size = crate::options::BufferSize::clamped(1024);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), body);
    assert_eq!(clock.now(), start, "the transfer waited on its socket");
}

/// Without a TLS library, `https` is a scheme the build leaves out, as in
/// C built without TLS: refused before anything connects.
#[test]
fn https_without_a_tls_library_is_not_supported() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_tls(&mut m, &Libraries::NONE, "/", talk.clone(), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    assert_eq!(talk.received(), b"");
}

/// A connection made with TLS serves the next transfer only if its TLS
/// would be made the same (`url_match_ssl_config`): the same settings
/// reuse it; a transfer that does not verify its peer, or plain HTTP to
/// the same host and port, gets a connection of its own.
#[test]
fn an_https_connection_is_reused_only_with_the_same_tls() {
    let (backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let first = Conversation::replies(&[&welcome, &response, &response], false);
    let insecure = Conversation::replies(&[&welcome, &response], false);
    let plain = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&first, &insecure, &plain]);
    let one = get_tls(&mut m, libraries, "/a", first.clone(), |_| {});
    assert_eq!(one.result, Ok(()));
    let two = get_tls(&mut m, libraries, "/b", first.clone(), |_| {});
    assert_eq!(two.result, Ok(()));
    assert!(
        two.seen
            .text()
            .iter()
            .any(|l| l.starts_with("Reusing existing https: connection")),
        "{:?}",
        two.seen.text()
    );
    let three = get_tls(&mut m, libraries, "/c", insecure.clone(), |o| {
        o.tls.verify_peer = false;
    });
    assert_eq!(three.result, Ok(()));
    assert_eq!(sent(&insecure), handshake_then(&request_of("/c")));
    assert!(!backend.log().verify_peer, "the session made without");
    let four = get(&mut m, "/d", plain.clone(), |_| {});
    assert_eq!(four.result, Ok(()));
    assert_eq!(plain.received(), request_of("/d"));
    assert_eq!(
        sent(&first),
        [handshake_then(&request_of("/a")), request_of("/b")].concat()
    );
    assert_eq!(backend.log().sessions, 2);
}

/// A multi hands each session the one state the library keeps for it,
/// made with its first session and dropped with the multi; another multi
/// keeps its own.
#[test]
fn a_multi_keeps_one_state_of_the_library_s_for_its_sessions() {
    let (backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let talks: Vec<Conversation> = (0..3)
        .map(|_| Conversation::replies(&[&welcome, &response], false))
        .collect();
    let mut m = serving(Peer::Accepts, &[&talks[0], &talks[1]]);
    assert_eq!(backend.log().states_made, 0, "none before a session");
    let fresh = |o: &mut Options| o.limits.reuse.fresh = true;
    for talk in &talks[..2] {
        let got = get_tls(&mut m, libraries, "/", talk.clone(), fresh);
        assert_eq!(got.result, Ok(()));
    }
    let log = backend.log();
    assert_eq!((log.sessions, log.states_made, log.state), (2, 1, 1));
    let mut other = serving(Peer::Accepts, &[&talks[2]]);
    let got = get_tls(&mut other, libraries, "/", talks[2].clone(), |_| {});
    assert_eq!(got.result, Ok(()));
    let log = backend.log();
    assert_eq!((log.sessions, log.states_made, log.state), (3, 2, 2));
    assert_eq!(log.states_dropped, 0);
    drop(m);
    assert_eq!(backend.log().states_dropped, 1);
    drop(other);
    assert_eq!(backend.log().states_dropped, 2);
}

/// A transfer that names the library's default CA file reuses the
/// connection of one that kept the default, as in C, which copies the
/// default into the setting before it compares; one that trusts no file
/// gets a connection of its own.
#[test]
fn naming_the_default_ca_file_reuses_a_connection_made_with_it() {
    use crate::options::CaSetting;
    let (backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let first = Conversation::replies(&[&welcome, &response, &response], false);
    let other = Conversation::replies(&[&welcome, &response], false);
    let mut m = serving(Peer::Accepts, &[&first, &other]);
    let one = get_tls(&mut m, libraries, "/a", first.clone(), |_| {});
    assert_eq!(one.result, Ok(()));
    let two = get_tls(&mut m, libraries, "/b", first.clone(), |o| {
        o.tls.options.make_mut().unwrap().ca_file =
            CaSetting::Given(fake::CA_FILE.as_bytes().to_vec());
    });
    assert_eq!(two.result, Ok(()));
    let three = get_tls(&mut m, libraries, "/c", other.clone(), |o| {
        o.tls.options.make_mut().unwrap().ca_file = CaSetting::Unset;
    });
    assert_eq!(three.result, Ok(()));
    assert_eq!(
        sent(&first),
        [handshake_then(&request_of("/a")), request_of("/b")].concat()
    );
    assert_eq!(sent(&other), handshake_then(&request_of("/c")));
    assert_eq!(backend.log().sessions, 2);
}

/// What a transfer's pollset says between the passes of `m` until the
/// transfer `id` completes: each set of events it waits on, in turn, a
/// set the same as the one before not said again.
fn waits_until_done(m: &mut Multi, id: crate::multi::TransferId) -> Vec<Events> {
    let mut waits: Vec<Events> = Vec::new();
    for _ in 0..50 {
        m.perform(&mut NoEvents).unwrap();
        if m.state_of(id).is_completed() {
            return waits;
        }
        let mut now = Events::NONE;
        m.sockets(&mut NoEvents, |_, e| now = now | e);
        if waits.last() != Some(&now) {
            waits.push(now);
        }
    }
    panic!("the transfer never completed: {waits:?}");
}

/// A handshake takes as many passes as its peer makes it: it waits to
/// read the server's flight, then, its answer stalled, to write while it
/// is still reading; the socket's own wait to read stays beside, as the
/// socket filter adds it before the connection is used
/// (`Curl_ssl_adjust_pollset`, `cf_socket_adjust_pollset`).
#[test]
fn a_handshake_waits_to_write_while_it_reads() {
    let (backend, libraries) = tls();
    let [welcome, response] = served(OK);
    // The welcome a poll late, and the finished line's first send stalled.
    let talk = Conversation::replies(&[&welcome, &response], false)
        .late_replies()
        .stalling_sends_after(1, 1);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let id = m.add(https_handle(libraries), (), &mut NoEvents).unwrap();
    let waits = waits_until_done(&mut m, id);
    assert_eq!(
        waits,
        [
            Events::OUT,
            Events::IN,
            Events::IN | Events::OUT,
            Events::IN
        ],
        "connecting, the welcome, the finished line, the response"
    );
    assert!(matches!(
        m.state_of(id),
        crate::multi::state::TransferState::Completed(c) if c.outcome == Ok(())
    ));
    assert_eq!(backend.log().handshakes, 1);
    assert_eq!(sent(&talk), handshake_then(&request_of("/")));
}

/// A read over TLS that has a record still to send sends it first, and
/// waits to write, not to read, while the socket will not take it: the
/// transfer, which wants to read, waits on what its layer needs
/// (`Curl_ssl_adjust_pollset`'s `set_out_only`).
#[test]
fn a_read_waits_to_write_what_tls_still_has_to_send() {
    let (_, libraries) = tls();
    let [welcome, response] = served(OK);
    // The hello and the finished line go; the request's record, and the
    // read's first try to send it, stall.
    let talk = Conversation::replies(&[&welcome, &response], false).stalling_sends_after(2, 2);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let id = m.add(https_handle(libraries), (), &mut NoEvents).unwrap();
    let waits = waits_until_done(&mut m, id);
    assert!(waits.ends_with(&[Events::OUT]), "{waits:?}");
    assert!(matches!(
        m.state_of(id),
        crate::multi::state::TransferState::Completed(c) if c.outcome == Ok(())
    ));
    assert_eq!(sent(&talk), handshake_then(&request_of("/")));
}

/// Each read of the response asks the TLS session for the transfer's
/// own length, the most one read takes (`SSL_read(len)`): the layer
/// passes the caller's size as it is, and the session reads below as
/// its records need.
#[test]
fn a_read_asks_the_session_for_the_transfer_s_length() {
    let (backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let (mut m, talk, _) = server(&[&welcome, &response], false);
    let size = crate::options::BufferSize::clamped(5000);
    let ran = get_tls(&mut m, libraries, "/", talk, |o| {
        o.limits.buffer_size = size
    });
    assert_eq!(ran.result, Ok(()));
    let asked = backend.log().asked().to_vec();
    assert!(!asked.is_empty());
    assert!(asked.iter().all(|&n| n == size.get()), "{asked:?}");
}

/// A handshake its peer never answers is held to the connect limit, as
/// the rest of the setup is, and fails as a connect that timed out
/// (`multi_handle_timeout`).
#[test]
fn an_unanswered_handshake_times_out_as_the_connect() {
    let (_, libraries) = tls();
    let (mut m, _talk, _) = server(&[], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", Conversation::new(b"", false), |o| {
        let url = format!("https://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.connect = crate::time::TimeLimit::from_millis(1000);
    });
    assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
    let text = ran.seen.text();
    assert!(
        text.iter()
            .any(|l| l.starts_with("Connection timed out after 1")),
        "{text:?}"
    );
}

/// A setup that times out in its TLS handshake keeps what it knew of its
/// connection: the ends, and when TCP connected (`Curl_conn_report_failed`,
/// test 5029).
#[test]
fn a_handshake_cut_short_keeps_the_connection_s_ends_and_time() {
    let (_, libraries) = tls();
    let talk = Conversation::new(b"", false);
    let accepted = std::time::Duration::from_millis(10);
    let mut m = serving(Peer::AcceptsAfter(accepted), &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk, |o| {
        let url = format!("https://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.connect = crate::time::TimeLimit::from_millis(1000);
    });
    assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
    let report = ran.easy.report();
    let ends = report.primary().expect("the ends kept");
    assert_eq!(
        ends.remote,
        crate::conn::io::Remote::Inet(SocketAddr::from(([127, 0, 0, 1], PORT)))
    );
    assert!(ends.local.is_some());
    assert_eq!(report.timings().connect(), accepted);
}

/// HTTPS through an HTTP proxy tunnels, whether asked or not
/// (`Curl_proxy_init_conn`), and its TLS is made with the origin through
/// the tunnel. The bytes the proxy sent past its answer are the origin's
/// first: the handshake reads them before it reads the connection again,
/// as C, which reads the answer a byte at a time, would read them next.
#[test]
fn https_through_a_proxy_reads_what_followed_its_answer_first() {
    let (backend, libraries) = tls();
    let mut answer = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
    answer.extend_from_slice(WELCOME);
    let response = fake::records(OK).unwrap();
    let (mut m, talk, _) = server(&[&answer, &response], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.set_url(Some(b"https://origin.example/p")).unwrap();
        let proxy = format!("http://127.0.0.1:{PORT}");
        o.proxy.make_mut().unwrap().url = Some(proxy.into_bytes());
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n");
    let connect = b"CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n\
        User-Agent: curl/test\r\nProxy-Connection: Keep-Alive\r\n\r\n";
    let request = b"GET /p HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\n\
        Accept: */*\r\n\r\n";
    let (clear, tls) = sent_after(&talk, connect.len());
    assert_eq!(clear, connect);
    assert_eq!(tls, handshake_then(request));
    let log = backend.log();
    assert_eq!(log.name(), b"origin.example");
    assert_eq!((log.port, log.kind), (443, Some(TlsPeerKind::Name)));
}

/// The PROXY protocol's line goes before the TLS handshake, in the
/// clear, as cf-setup.c adds the SSL filter last.
#[test]
fn the_proxy_protocol_s_line_goes_before_tls() {
    let (_, libraries) = tls();
    let [welcome, response] = served(OK);
    let (mut m, talk, _) = server(&[&welcome, &response], false);
    let ran = get_tls(&mut m, libraries, "/", talk.clone(), |o| {
        o.proxy.make_mut().unwrap().haproxy = true;
    });
    assert_eq!(ran.result, Ok(()));
    let wire = talk.received();
    let line = "PROXY TCP4 127.0.0.1 127.0.0.1 ";
    assert!(wire.starts_with(line.as_bytes()), "{}", wire.escape_ascii());
    let after = wire.iter().position(|&b| b == b'\n').unwrap() + 1;
    let (_, tls) = sent_after(&talk, after);
    assert_eq!(tls, handshake_then(&request_of("/")));
}

/// A secure cookie is kept from, and sent to, any host over TLS, and
/// over plain HTTP only to this one (`Curl_secure_context`).
#[test]
fn secure_cookies_go_over_tls() {
    let (_, libraries) = tls();
    let sets = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1; Secure\r\nContent-Length: 0\r\n\r\n";
    let jar = |o: &mut Options| {
        o.http.headers = UserHeaders::new([&b"Host: secure.example"[..]]).unwrap();
        o.http.cookies.make_mut().unwrap().files.push(b"").unwrap();
    };
    let [welcome, first] = served(sets);
    let second = fake::records(OK).unwrap();
    let talk = Conversation::replies(&[&welcome, &first, &second], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let one = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.set_url(Some(format!("https://127.0.0.1:{PORT}/").as_bytes()))
            .unwrap();
        jar(o);
    });
    assert_eq!(one.result, Ok(()));
    let mut e = one.easy;
    e.set_libraries(libraries);
    let two = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.set_url(Some(format!("https://127.0.0.1:{PORT}/b").as_bytes()))
            .unwrap();
    });
    assert_eq!(two.result, Ok(()));
    let wire = String::from_utf8(sent(&talk)).unwrap();
    let second = &wire[wire.find("GET /b ").unwrap()..];
    assert!(second.contains("\r\nCookie: s=1\r\n"), "{second}");
    // Over plain HTTP, to the same host, it is not even kept.
    let plain = Conversation::replies(&[sets, OK], false);
    let mut m = serving(Peer::Accepts, &[&plain]);
    let one = get(&mut m, "/", plain.clone(), jar);
    assert_eq!(one.result, Ok(()));
    let two = get_with(&mut m, one.easy, "/b", plain.clone(), |_| {});
    assert_eq!(two.result, Ok(()));
    let wire = String::from_utf8(plain.received()).unwrap();
    assert!(!wire.contains("Cookie:"), "{wire}");
}

/// A TLS library whose sessions pass the bytes as they are and say why
/// they fail, as OpenSSL's do: a read of `BAD` from the peer, or a
/// failure below; that trace the records they pass for a debug handler;
/// and whose handshake says a line of verbose output and one of its
/// filter's trace; and that note whether they were told to trace them.
struct Saying;

std::thread_local! {
    /// What the last handshake of a `SayingSession` on this thread was
    /// told of a debug handler (`TlsIo::debugs`).
    static SAYING_DEBUGS: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

impl crate::tls::TlsBackend for Saying {
    fn session(
        &self,
        _: &TryArc<crate::tls::TlsIdentity>,
        _: &crate::tls::TlsPeer<'_>,
        _: crate::tls::Alpn,
        _: &crate::tls::TlsShared,
    ) -> Result<Box<dyn crate::tls::TlsSession>, ErrorKind> {
        Ok(Box::new(SayingSession))
    }

    fn ca_defaults(&self) -> crate::tls::CaDefaults {
        crate::tls::CaDefaults::default()
    }
}

struct SayingSession;

impl crate::tls::TlsSession for SayingSession {
    fn handshake(&mut self, io: &mut crate::tls::TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        io.info(format_args!("SAYING: connected"));
        io.trace(format_args!("handshake done"));
        SAYING_DEBUGS.set(Some(io.debugs()));
        Ok(Handshake::Done)
    }

    fn recv(&mut self, io: &mut crate::tls::TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        match io.recv(buf) {
            Ok(Recv::Data(n)) if &buf[..n.get()] == b"BAD" => {
                io.fail(ErrorKind::RecvError, format_args!("the peer said BAD"));
                Err(io::ErrorKind::InvalidData.into())
            }
            Ok(Recv::Data(n)) => {
                if io.debugs() {
                    io.record(crate::tls::TlsWay::In, &buf[..n.get()]);
                }
                Ok(Recv::Data(n))
            }
            got => got,
        }
    }

    fn send(&mut self, io: &mut crate::tls::TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent> {
        io.send(bytes).inspect_err(|_| {
            io.fail(
                ErrorKind::SendError,
                format_args!("the session could not send"),
            );
        })
    }

    fn shutdown(&mut self, _: &mut crate::tls::TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        Ok(Handshake::Done)
    }

    fn waits(&self) -> crate::tls::TlsWait {
        crate::tls::TlsWait::Nothing
    }

    fn pending(&self) -> bool {
        false
    }
}

fn saying() -> &'static Libraries {
    static SAYING: Saying = Saying;
    Box::leak(Box::new(Libraries {
        tls: Some(&SAYING),
        ..Libraries::NONE
    }))
}

/// A session that says why its read failed is not said for again: the
/// transfer keeps its reason, traced once, with no `Recv failure` of the
/// socket's, which did not fail.
#[test]
fn a_session_s_reason_for_a_failed_read_is_the_transfer_s() {
    let (mut m, talk, _) = server(&[b"BAD"], false);
    let ran = get_tls(&mut m, saying(), "/", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RecvError));
    assert_eq!(ran.easy.report().failure(), Some(&b"the peer said BAD"[..]));
    let text = ran.seen.text();
    assert_eq!(
        text.iter().filter(|l| *l == "the peer said BAD\n").count(),
        1
    );
    assert!(
        !text.iter().any(|l| l.starts_with("Recv failure")),
        "{text:?}"
    );
}

/// The socket under a session failing is said as the socket says it
/// (`cf_socket_send`'s `Send failure:`), first, so the transfer keeps
/// it; the session's own reason follows, and nothing more.
#[test]
fn a_socket_failing_under_a_session_is_said_first() {
    let libraries = saying();
    let talk = Conversation::new(OK, false).breaking_after(0);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get_tls(&mut m, libraries, "/", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    let failure = ran.easy.report().failure().unwrap();
    assert!(failure.starts_with(b"Send failure: "), "{failure:?}");
    let text = ran.seen.text();
    let send = text
        .iter()
        .position(|l| l.starts_with("Send failure: "))
        .unwrap();
    assert_eq!(text[send + 1], "the session could not send\n", "{text:?}");
    assert_eq!(
        text.iter()
            .filter(|l| l.starts_with("Send failure"))
            .count(),
        1
    );
}

/// The records a session passes reach a verbose transfer's debug handler
/// as SSL data (`CURLINFO_SSL_DATA_IN`).
#[test]
fn a_session_s_records_reach_the_debug_handler() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_tls(&mut m, saying(), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.of("ssl_in").concat(), OK);
}

/// A session is told to trace its records for a debug handler only when
/// the transfer has one and is verbose (C's `data->set.fdebug` and
/// `verbose`, under which OpenSSL's message callback is set).
#[test]
fn a_session_traces_its_records_only_for_a_verbose_debug_handler() {
    /// Verbose output without a debug handler, kept.
    #[derive(Clone, Default)]
    struct Stderr(Arc<Mutex<Vec<u8>>>);
    impl crate::handler::TextSink for Stderr {
        fn write(&self, text: &[u8]) {
            self.0.lock().unwrap().extend_from_slice(text);
        }
    }
    for (handler, verbose) in [(true, true), (true, false), (false, true), (false, false)] {
        let (mut m, talk, _) = server(&[OK], false);
        let stderr = Stderr::default();
        SAYING_DEBUGS.set(None);
        let ran = get_tls(&mut m, saying(), "/", talk, |o| {
            if !handler {
                o.callbacks.debug = None;
            }
            o.callbacks.stderr = Some(Handler::text(stderr.clone()).unwrap());
            o.output.verbose = verbose;
        });
        assert_eq!(ran.result, Ok(()));
        assert_eq!(
            SAYING_DEBUGS.get(),
            Some(handler && verbose),
            "{handler} {verbose}"
        );
        // The needle: verbose without a handler is verbose all the same.
        let said = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            said.contains("* SAYING: connected\n"),
            verbose && !handler,
            "{said}"
        );
    }
}

/// A session's lines reach the transfer: its verbose output always, its
/// trace as its filter's (`[SSL]`) only when that is traced.
#[test]
fn a_session_s_info_and_trace_lines_reach_the_transfer() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_tls(&mut m, saying(), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    assert!(text.iter().any(|l| l == "SAYING: connected\n"), "{text:?}");
    assert!(
        !text.iter().any(|l| l.contains("handshake done")),
        "{text:?}"
    );

    let (mut m, talk, _) = server(&[OK], false);
    let mut e = Easy::new();
    e.set_libraries(saying());
    let components = crate::components::Components::new().unwrap();
    components.configure(b"ssl");
    e.set_components(Some(components));
    let ran = get_with(&mut m, e, "/", talk, |o| {
        let url = format!("https://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    assert!(
        text.iter().any(|l| l == "[SSL] handshake done\n"),
        "{text:?}"
    );
}

/// A body that runs to the connection's end ends as the session reads
/// the end, between records; a session that fails its read, the
/// connection cut inside a record or a record that is not one, fails the
/// transfer as a receive error.
#[test]
fn a_session_s_end_ends_the_body_and_its_failure_fails_the_read() {
    let (_, libraries) = tls();
    let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nto the end";
    let records = fake::records(response).unwrap();
    let (mut m, talk, _) = server(&[WELCOME, &records], true);
    let ran = get_tls(&mut m, libraries, "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"to the end");

    let cut = [&records[..], b"[00"].concat();
    let (mut m, talk, _) = server(&[WELCOME, &cut], true);
    let ran = get_tls(&mut m, libraries, "/", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RecvError));

    let mut not_one = records.clone();
    not_one[0] = b'(';
    let (mut m, talk, _) = server(&[WELCOME, &not_one], true);
    let ran = get_tls(&mut m, libraries, "/", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RecvError));
}

/// A body longer than a record goes over as many: the layer sends what
/// the session takes, and sends the rest after.
#[test]
fn a_body_longer_than_a_record_goes_as_many() {
    let (_, libraries) = tls();
    let [welcome, response] = served(OK);
    let (mut m, talk, _) = server(&[&welcome, &response], false);
    let body = vec![b'x'; fake::RECORD + 1000];
    let upload = body.clone();
    let ran = get_tls(&mut m, libraries, "/p", talk.clone(), |o| {
        o.method = Method::Post;
        o.upload = crate::options::UploadSource::Bytes(TryArc::try_new(upload).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let sent = sent(&talk);
    assert!(
        sent.ends_with(&body),
        "{:?}",
        String::from_utf8_lossy(&sent)
    );
    assert!(!talk.received().ends_with(&body[..1000]), "in the clear");
}
