//! HTTPS over the fake TLS library: the handshake as the last stage of
//! the setup, the bytes through its layer both ways, reuse by identity,
//! what the transfer waits for, and the goodbye.

use super::*;
use crate::conn::io::Events;
use crate::conn::io::{Recv, Sent};
use crate::libraries::{Libraries, Library, SharedLibraries};
use crate::tls::fake::{self, CLOSE, FINISHED, FakeTls, HELLO, WELCOME};
use crate::tls::{Handshake, TlsPeerKind, fake::FakeLog};
use curl_alloc::TryArc;
use std::io;

/// A fake TLS library of the test's own, and the libraries naming it,
/// for the test's handles: made once per test, kept to its end.
pub(super) fn tls() -> (&'static FakeTls, SharedLibraries) {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
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
    libraries: &SharedLibraries,
    path: &str,
    talk: Conversation,
    set: impl FnOnce(&mut Options),
) -> Ran {
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
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
fn https_handle(libraries: &SharedLibraries) -> Box<Easy> {
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
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
    let ran = get_tls(&mut m, &libraries, "/a", talk.clone(), |_| {});
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

/// The socket under a session traces each send and receive the session
/// makes of it, with the session's lengths (`cf_socket_send` under the
/// SSL filter's BIO), and the request's send as the record that went,
/// not as the bytes the transfer handed the session.
#[test]
fn the_socket_under_a_session_traces_what_the_session_asks_of_it() {
    let (_, libraries) = tls();
    let [welcome, response] = served(OK);
    let (mut m, talk, _) = server(&[&welcome, &response], false);
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let components = crate::components::Components::new().unwrap();
    components.configure(b"tcp");
    e.set_components(Some(components));
    let request = request_of("/a");
    let ran = get_with(&mut m, e, "/a", talk, |o| {
        let url = format!("https://127.0.0.1:{PORT}/a");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let lines: Vec<String> = ran
        .seen
        .text()
        .into_iter()
        .filter(|l| l.starts_with("[TCP] send(") || l.starts_with("[TCP] recv("))
        .map(|l| l.trim_end().to_owned())
        .collect();
    let (hello, wel, fin) = (HELLO.len(), WELCOME.len(), FINISHED.len());
    let record = fake::records(&request).unwrap().len();
    assert_eq!(
        lines[..4],
        [
            format!("[TCP] send(len={hello}) -> 0, {hello}"),
            format!("[TCP] recv(len={wel}) -> 0, {wel}"),
            format!("[TCP] send(len={fin}) -> 0, {fin}"),
            format!("[TCP] send(len={record}) -> 0, {record}"),
        ]
    );
    let plain = format!("send(len={})", request.len());
    assert!(!lines.iter().any(|l| l.contains(&plain)), "{lines:?}");
}

/// A response the session holds more of than a step's eleven reads take
/// runs the transfer again, and says so as C's does over TLS: the step
/// stopping short of a read that would block (`sendrecv_dl`), then, while
/// the session still holds input, the pollset that wants to read
/// (`multi_adjust_pollset`). C's tool traces the
/// two lines in that order, 16 times over a 3 MB download from h2o.
#[test]
fn a_step_that_stops_with_input_held_marks_the_transfer_dirty_as_c() {
    let (_, libraries) = tls();
    let body = vec![b'x'; 20 * fake::RECORD];
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(&body);
    let [welcome, records] = served(&response);
    let (mut m, talk, _) = server(&[&welcome, &records], false);
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let components = crate::components::Components::new().unwrap();
    components.configure(b"multi");
    e.set_components(Some(components));
    let ran = get_with(&mut m, e, "/", talk, |o| {
        let url = format!("https://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.buffer_size = crate::options::BufferSize::clamped(1024);
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(ran.seen.body(), body);
    let said: Vec<String> = ran
        .seen
        .text()
        .iter()
        .filter(|l| l.contains("mark as dirty") || l.contains("] pollset["))
        .map(|l| l.trim_end().to_owned())
        .collect();
    // Eleven reads of 1024 bytes a step, out of 4096-byte records: the
    // fourth step ends at a record's end, the session holding nothing and
    // only the socket more, and C's pollset, which asks the filters and
    // not the socket, says nothing of it.
    let stop = "[MULTI] [PERFORMING] sendrecv_dl() no EAGAIN/pending data, mark as dirty";
    let held = "[MULTI] [PERFORMING] pollset[] has POLLIN, but there is still buffered input -> mark as dirty";
    let wait = "[MULTI] [PERFORMING] pollset[fd=1000 IN], timeouts=1";
    let mut want = Vec::new();
    for step in 1..=7 {
        want.push(stop);
        if step != 4 {
            want.push(held);
        }
        want.push(wait);
    }
    assert_eq!(said[2..], want, "{said:#?}");
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
    let ran = get_tls(&mut m, &libraries, "/", talk, |o| {
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
    let ran = get_tls(
        &mut m,
        &SharedLibraries::default(),
        "/",
        talk.clone(),
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    assert_eq!(talk.received(), b"");
}

/// A handle's next transfer on the connection its last made keeps that
/// handshake's verification result, as C keeps it in the handle's
/// settings (`ssl_config->certverifyresult`; the C build reports 18 for
/// both transfers on a self-signed server, the second reusing).
#[test]
fn a_reused_connection_keeps_the_handle_s_verify_result() {
    let (_backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let talk = Conversation::replies(&[&welcome, &response, &response], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let one = get_tls(&mut m, &libraries, "/a", talk.clone(), |_| {});
    assert_eq!(one.result, Ok(()));
    let first = one.easy.report().verify_result();
    assert_ne!(first, 0, "the fake says a result");
    let two = get_with(&mut m, one.easy, "/b", talk.clone(), |o| {
        let url = format!("https://127.0.0.1:{PORT}/b");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(two.result, Ok(()));
    assert!(
        two.seen
            .text()
            .iter()
            .any(|l| l.starts_with("Reusing existing https: connection")),
        "{:?}",
        two.seen.text()
    );
    assert_eq!(two.easy.report().verify_result(), first);
}

/// The same of the proxy's: a handle's next transfer through the HTTPS
/// proxy connection its last made keeps the proxy's verification result.
#[test]
fn a_reused_proxy_connection_keeps_the_handle_s_proxy_verify_result() {
    let (_backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let talk = Conversation::replies(&[&welcome, &response, &response], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let one = get_with(&mut m, e, "/", talk.clone(), |o| {
        https_proxy(o, b"http://origin.example/p");
    });
    assert_eq!(one.result, Ok(()));
    let first = one.easy.report().proxy_verify_result();
    assert_ne!(first, 0, "the fake says a result");
    let two = get_with(&mut m, one.easy, "/", talk.clone(), |o| {
        https_proxy(o, b"http://origin.example/q");
    });
    assert_eq!(two.result, Ok(()), "{:?}", two.seen.text());
    assert!(
        two.seen
            .text()
            .iter()
            .any(|l| l.starts_with("Reusing existing")),
        "{:?}",
        two.seen.text()
    );
    assert_eq!(two.easy.report().proxy_verify_result(), first);
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
    let one = get_tls(&mut m, &libraries, "/a", first.clone(), |_| {});
    assert_eq!(one.result, Ok(()));
    let two = get_tls(&mut m, &libraries, "/b", first.clone(), |_| {});
    assert_eq!(two.result, Ok(()));
    assert!(
        two.seen
            .text()
            .iter()
            .any(|l| l.starts_with("Reusing existing https: connection")),
        "{:?}",
        two.seen.text()
    );
    let three = get_tls(&mut m, &libraries, "/c", insecure.clone(), |o| {
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
        let got = get_tls(&mut m, &libraries, "/", talk.clone(), fresh);
        assert_eq!(got.result, Ok(()));
    }
    let log = backend.log();
    assert_eq!((log.sessions, log.states_made, log.state), (2, 1, 1));
    let mut other = serving(Peer::Accepts, &[&talks[2]]);
    let got = get_tls(&mut other, &libraries, "/", talks[2].clone(), |_| {});
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
/// gets a connection of its own. Not where the build makes the system's
/// store the default, which naming a file turns off (C's Apple build has
/// no default file to name).
#[cfg(not(all(target_os = "macos", feature = "apple-sectrust")))]
#[test]
fn naming_the_default_ca_file_reuses_a_connection_made_with_it() {
    use crate::options::CaSetting;
    let (backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let first = Conversation::replies(&[&welcome, &response, &response], false);
    let other = Conversation::replies(&[&welcome, &response], false);
    let mut m = serving(Peer::Accepts, &[&first, &other]);
    let one = get_tls(&mut m, &libraries, "/a", first.clone(), |_| {});
    assert_eq!(one.result, Ok(()));
    let two = get_tls(&mut m, &libraries, "/b", first.clone(), |o| {
        o.tls.options.make_mut().unwrap().ca_file =
            CaSetting::Given(fake::CA_FILE.as_bytes().to_vec());
    });
    assert_eq!(two.result, Ok(()));
    let three = get_tls(&mut m, &libraries, "/c", other.clone(), |o| {
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

/// Each line a transfer's debug handler hears, with whether the TLS
/// library's objects were in its reach as it heard it.
#[derive(Clone, Default)]
struct NativeHeard(std::sync::Arc<std::sync::Mutex<Vec<(String, bool)>>>);

impl crate::handler::DebugHandler for NativeHeard {
    fn debug(&self, cx: &mut TransferCx<'_>, kind: crate::handler::DebugKind, data: &[u8]) {
        if kind == crate::handler::DebugKind::Text {
            let native = cx.tls_native(cx.me()).is_some();
            let line = String::from_utf8_lossy(data).trim_end().to_owned();
            self.0.lock().unwrap().push((line, native));
        }
    }
}

/// A transfer on a connection it reuses has the connection attached
/// from the start, as C attaches it as it finds it: its handlers reach
/// the connection's TLS library's objects from the line that says it is
/// reused and while it connects (`CURLINFO_TLS_SSL_PTR`), as they do once
/// its request goes.
#[test]
fn a_transfer_reusing_a_connection_reaches_its_tls_objects_as_it_connects() {
    let (_, libraries) = tls();
    let [welcome, response] = served(OK);
    let talk = Conversation::replies(&[&welcome, &response, &response], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let heard = NativeHeard::default();
    for path in ["/a", "/b"] {
        heard.0.lock().unwrap().clear();
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        let c = crate::components::Components::new().unwrap();
        c.configure(b"multi");
        e.set_components(Some(c));
        let ran = get_with(&mut m, e, path, talk.clone(), |o| {
            let url = format!("https://127.0.0.1:{PORT}{path}");
            o.set_url(Some(url.as_bytes())).unwrap();
            o.callbacks.debug = Some(crate::handler::Handler::debug(heard.clone()).unwrap());
        });
        assert_eq!(ran.result, Ok(()));
    }
    assert_eq!(
        sent(&talk),
        [handshake_then(&request_of("/a")), request_of("/b")].concat()
    );
    let heard = heard.0.lock().unwrap().clone();
    let at = heard
        .iter()
        .position(|(l, _)| l.starts_with("Reusing existing"))
        .expect("the second reuses");
    let connecting: Vec<_> = heard[at..]
        .iter()
        .filter(|(l, _)| l.starts_with("[MULTI] [CONNECTING]"))
        .collect();
    assert!(!connecting.is_empty(), "{heard:#?}");
    assert!(connecting.iter().all(|(_, native)| *native), "{heard:#?}");
    // C attaches the connection it found before it says so
    // (`url_find_or_create_conn`), so the line saying so reaches them.
    assert!(heard[at].1, "{heard:#?}");
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
        m.sockets(&mut NoEvents, |_, e| now = now | e).unwrap();
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
    let id = m.add(https_handle(&libraries), (), &mut NoEvents).unwrap();
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
    let id = m.add(https_handle(&libraries), (), &mut NoEvents).unwrap();
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
    let ran = get_tls(&mut m, &libraries, "/", talk, |o| {
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
    e.set_libraries(libraries.clone());
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
    e.set_libraries(libraries.clone());
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
    e.set_libraries(libraries.clone());
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

/// Set `o` to go through the HTTPS proxy on the test's port.
fn https_proxy(o: &mut Options, url: &[u8]) {
    o.set_url(Some(url)).unwrap();
    let proxy = format!("https://127.0.0.1:{PORT}");
    o.proxy.make_mut().unwrap().url = Some(proxy.into_bytes());
}

/// Plain HTTP through an HTTPS proxy is forwarded over TLS made with the
/// proxy (`cf_ssl_proxy`, added as the origin's filter): the request,
/// with the URL whole, goes as records, and the session's peer is the
/// proxy, not the origin.
#[test]
fn http_through_an_https_proxy_goes_over_tls_to_the_proxy() {
    let (backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let (mut m, talk, _) = server(&[&welcome, &response], false);
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        https_proxy(o, b"http://origin.example/p");
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n");
    let wire = talk.received();
    assert!(!wire.windows(4).any(|w| w == b"GET "), "{wire:?}");
    let sent = String::from_utf8(sent(&talk)).unwrap();
    let request = sent.strip_prefix("FAKETLS HELLO\r\n\r\nFAKETLS FINISHED\n");
    let request = request.unwrap_or_else(|| panic!("{sent}"));
    assert!(
        request.starts_with("GET http://origin.example/p HTTP/1.1\r\nHost: origin.example\r\n"),
        "{request}"
    );
    let log = backend.log();
    assert_eq!((log.sessions, log.handshakes), (1, 1));
    assert_eq!(log.name(), b"127.0.0.1");
    assert_eq!((log.port, log.kind), (PORT, Some(TlsPeerKind::Ipv4)));
    // Its TLS is the proxy's: the transfer's connection is not secured
    // by TLS with the origin (`TIMER_APPCONNECT` is the origin's), and
    // the verification is the proxy's.
    let report = ran.easy.report();
    assert_eq!(report.timings().appconnect(), Duration::ZERO);
    assert_eq!(
        (report.proxy_verify_result(), report.verify_result()),
        (1, 0)
    );
}

/// Plain HTTP forwarded to an HTTPS proxy goes over TLS, so HTTP/2 is not
/// asked for by an upgrade: the connection is TLS though the origin's
/// part of it is not (`Curl_conn_is_ssl` seeing the proxy's filter).
#[test]
fn http_through_an_https_proxy_asks_no_upgrade_to_http_2() {
    static FAKE: crate::http2::fake::FakeH2 = crate::http2::fake::FakeH2;
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        h2: Some(&FAKE),
        ..Libraries::NONE
    })
    .unwrap();
    let [welcome, response] = served(OK);
    let (mut m, talk, _) = server(&[&welcome, &response], false);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        https_proxy(o, b"http://origin.example/p");
        o.http.version = crate::options::HttpVersion::Http2;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok\n");
    let sent = String::from_utf8(sent(&talk)).unwrap();
    assert!(
        sent.contains("GET http://origin.example/p HTTP/1.1\r\n"),
        "{sent}"
    );
    assert!(!sent.contains("Upgrade"), "{sent}");
    assert!(!sent.contains("HTTP2-Settings"), "{sent}");
}

/// The HTTPS proxy's TLS filter puts its socket in the pollset for what
/// its session waits for: once on its own, and once more, once a tunnel
/// through it is made, as the tunnel's filter, connected, asks it again
/// (`cf_h1_proxy_adjust_pollset`, `Curl_ssl_adjust_pollset`).
#[test]
fn an_https_proxy_s_tls_is_asked_again_by_its_tunnel() {
    for tunnel in [false, true] {
        let established = fake::records(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
        let response = fake::records(OK).unwrap();
        let replies: &[&[u8]] = if tunnel {
            &[WELCOME, &established, &response]
        } else {
            &[WELCOME, &response]
        };
        let (_, libraries) = tls();
        let (mut m, talk, _) = server(replies, false);
        let talk = talk.late_replies();
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let c = crate::components::Components::new().unwrap();
        c.configure(b"ssl-proxy");
        e.set_components(Some(c));
        let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
            https_proxy(o, b"http://origin.example/p");
            o.proxy.make_mut().unwrap().tunnel = tunnel;
        });
        assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
        let text = ran.seen.text();
        let polled: Vec<usize> = (0..text.len())
            .filter(|&i| text[i] == "[SSL-PROXY] adjust_pollset, POLLIN fd=1000\n")
            .collect();
        // Waiting for the proxy's handshake, then, the tunnel's, for its
        // answer to the CONNECT; then, the request sent, for its answer:
        // asked twice in a row through a tunnel, as C's trace shows.
        if tunnel {
            assert_eq!(polled.len(), 4, "{text:#?}");
            assert_eq!(polled[3], polled[2] + 1, "{text:#?}");
        } else {
            assert_eq!(polled.len(), 2, "{text:#?}");
            assert_ne!(polled[1], polled[0] + 1, "{text:#?}");
        }
    }
}

/// HTTPS through an HTTPS proxy makes TLS with the proxy first, then the
/// tunnel through it, then TLS with the origin inside that: the origin's
/// records travel inside the proxy's, and the CONNECT never goes in the
/// clear.
#[test]
fn https_through_an_https_proxy_is_tls_in_tls() {
    let (backend, libraries) = tls();
    let established = fake::records(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
    let inner_welcome = fake::records(WELCOME).unwrap();
    let response = fake::records(&fake::records(OK).unwrap()).unwrap();
    let (mut m, talk, _) = server(&[WELCOME, &established, &inner_welcome, &response], false);
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        https_proxy(o, b"https://origin.example/p");
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n");
    let wire = talk.received();
    assert!(wire.starts_with(HELLO), "{}", wire.escape_ascii());
    assert!(!wire.windows(8).any(|w| w == b"CONNECT "), "{wire:?}");
    let connect = b"CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n\
        User-Agent: curl/test\r\nProxy-Connection: Keep-Alive\r\n\r\n";
    let request = b"GET /p HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\n\
        Accept: */*\r\n\r\n";
    let outer = sent(&talk);
    let inner = [HELLO, FINISHED, connect].concat();
    assert!(outer.starts_with(&inner), "{}", outer.escape_ascii());
    let through = fake::read_client(&outer[inner.len()..]).unwrap();
    assert_eq!(through, handshake_then(request));
    let log = backend.log();
    assert_eq!((log.sessions, log.handshakes), (2, 2));
    assert_eq!(
        log.name(),
        b"origin.example",
        "the last session, the origin's"
    );
    assert_eq!((log.port, log.kind), (443, Some(TlsPeerKind::Name)));
    let report = ran.easy.report();
    assert!(report.timings().appconnect() > Duration::ZERO);
    // Each session's verification is kept as its own: the proxy's, the
    // first, apart from the origin's (`CURLINFO_PROXY_SSL_VERIFYRESULT`).
    assert_eq!(
        (report.proxy_verify_result(), report.verify_result()),
        (1, 2)
    );
}

/// A connection through an HTTPS proxy serves the next transfer only if
/// its TLS with the proxy would be made the same (`url_match_proxy_use`
/// comparing `proxy_ssl_config`): another proxy CA file makes another
/// connection, the same one reuses it.
#[test]
fn an_https_proxy_s_connection_is_reused_only_with_the_same_proxy_tls() {
    use crate::options::CaSetting;
    let (backend, libraries) = tls();
    let [welcome, response] = served(OK);
    let first = Conversation::replies(&[&welcome, &response, &response], false);
    let other = Conversation::replies(&[&welcome, &response], false);
    let mut m = serving(Peer::Accepts, &[&first, &other]);
    let mut get = |path: &str, talk: &Conversation, ca: Option<&[u8]>| {
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        let url = format!("http://origin.example{path}");
        get_with(&mut m, e, path, talk.clone(), |o| {
            https_proxy(o, url.as_bytes());
            if let Some(ca) = ca {
                let tls = &mut o.proxy.make_mut().unwrap().tls;
                tls.options.make_mut().unwrap().ca_file = CaSetting::Given(ca.to_vec());
            }
        })
    };
    assert_eq!(get("/a", &first, None).result, Ok(()));
    assert_eq!(get("/b", &first, None).result, Ok(()));
    assert_eq!(get("/c", &other, Some(b"/other/ca.crt")).result, Ok(()));
    assert_eq!(backend.log().sessions, 2);
    let gets = |talk: &Conversation| {
        let text = String::from_utf8(sent(talk)).unwrap();
        text.matches("GET http://origin.example/").count()
    };
    assert_eq!((gets(&first), gets(&other)), (2, 1));
}

/// The PROXY protocol's line goes before the TLS handshake, in the
/// clear, as cf-setup.c adds the SSL filter last.
#[test]
fn the_proxy_protocol_s_line_goes_before_tls() {
    let (_, libraries) = tls();
    let [welcome, response] = served(OK);
    let (mut m, talk, _) = server(&[&welcome, &response], false);
    let ran = get_tls(&mut m, &libraries, "/", talk.clone(), |o| {
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
    e.set_libraries(libraries.clone());
    let one = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.set_url(Some(format!("https://127.0.0.1:{PORT}/").as_bytes()))
            .unwrap();
        jar(o);
    });
    assert_eq!(one.result, Ok(()));
    let mut e = one.easy;
    e.set_libraries(libraries.clone());
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

    fn id(&self) -> &dyn std::fmt::Display {
        &"Saying/1"
    }
}

struct SayingSession;

impl crate::tls::TlsSession for SayingSession {
    fn channel_binding(
        &self,
        _: &mut dyn crate::tls::BindingNotes,
    ) -> Result<Option<Vec<u8>>, ErrorKind> {
        Ok(None)
    }

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

    fn shutdown(
        &mut self,
        _: &mut crate::tls::TlsIo<'_>,
        _: crate::tls::Goodbye,
    ) -> Result<Handshake, ErrorKind> {
        Ok(Handshake::Done)
    }

    fn waits(&self) -> crate::tls::TlsWait {
        crate::tls::TlsWait::Nothing
    }

    fn pending(&self) -> bool {
        false
    }
}

fn saying() -> SharedLibraries {
    static SAYING: Saying = Saying;
    SharedLibraries::new(Libraries {
        tls: Some(Library::Static(&SAYING)),
        ..Libraries::NONE
    })
    .unwrap()
}

/// A session that says why its read failed is not said for again: the
/// transfer keeps its reason, traced once, with no `Recv failure` of the
/// socket's, which did not fail.
#[test]
fn a_session_s_reason_for_a_failed_read_is_the_transfer_s() {
    let (mut m, talk, _) = server(&[b"BAD"], false);
    let ran = get_tls(&mut m, &saying(), "/", talk, |_| {});
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
    let ran = get_tls(&mut m, &libraries, "/", talk, |_| {});
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
    let ran = get_tls(&mut m, &saying(), "/", talk, |_| {});
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
        let ran = get_tls(&mut m, &saying(), "/", talk, |o| {
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
    let ran = get_tls(&mut m, &saying(), "/", talk, |_| {});
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
    let ran = get_tls(&mut m, &libraries, "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"to the end");

    let cut = [&records[..], b"[00"].concat();
    let (mut m, talk, _) = server(&[WELCOME, &cut], true);
    let ran = get_tls(&mut m, &libraries, "/", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RecvError));

    let mut not_one = records.clone();
    not_one[0] = b'(';
    let (mut m, talk, _) = server(&[WELCOME, &not_one], true);
    let ran = get_tls(&mut m, &libraries, "/", talk, |_| {});
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
    let ran = get_tls(&mut m, &libraries, "/p", talk.clone(), |o| {
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

/// A fake TLS library that resumes tickets and gives them, and the
/// libraries naming it.
fn ticketing() -> (&'static FakeTls, SharedLibraries) {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::ticketing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    (backend, libraries)
}

/// `n` connections a server answers with its handshake and one OK each.
fn answering(n: usize) -> Vec<Conversation> {
    let [welcome, response] = served(OK);
    (0..n)
        .map(|_| Conversation::replies(&[&welcome, &response], false))
        .collect()
}

/// A multi keeps the sessions its connections are given: the next
/// connection to the peer with the same settings resumes one; one made
/// with other settings, or one keeping no sessions
/// (`CURLOPT_SSL_SESSIONID_CACHE` off), does not.
#[test]
fn the_next_connection_to_a_peer_resumes_a_session_its_multi_kept() {
    let (backend, libraries) = ticketing();
    let talks = answering(5);
    let refs: Vec<&Conversation> = talks.iter().collect();
    let mut m = serving(Peer::Accepts, &refs);
    let fresh = |o: &mut Options| o.limits.reuse.fresh = true;
    let run = |m: &mut Multi, i: usize, set: &dyn Fn(&mut Options)| {
        let got = get_tls(m, &libraries, "/", talks[i].clone(), |o| {
            fresh(o);
            set(o);
        });
        assert_eq!(got.result, Ok(()));
        backend.log().resumed
    };
    let no_cache = |o: &mut Options| o.tls.options.make_mut().unwrap().session_cache = false;
    assert_eq!(run(&mut m, 0, &no_cache), 0, "keeping none: none kept");
    assert_eq!(run(&mut m, 1, &|_| {}), 0, "none kept by the first");
    assert_eq!(run(&mut m, 2, &|_| {}), 1, "the second's resumed");
    let ciphers = |o: &mut Options| o.tls.options.make_mut().unwrap().ciphers = Some(b"X".to_vec());
    assert_eq!(run(&mut m, 3, &ciphers), 1, "other settings: none");
    assert_eq!(run(&mut m, 4, &no_cache), 1, "keeping none: none taken");
}

/// The cache traces what it does under `ssls`, as C traces it.
#[test]
fn the_session_cache_traces_its_uses() {
    let (_, libraries) = ticketing();
    let talks = answering(2);
    let mut m = serving(Peer::Accepts, &[&talks[0], &talks[1]]);
    let traced = |o: &mut Options| o.limits.reuse.fresh = true;
    let mut lines = Vec::new();
    for talk in &talks {
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        let c = crate::components::Components::new().unwrap();
        c.configure(b"ssls");
        e.set_components(Some(c));
        let got = get_with(&mut m, e, "/", talk.clone(), |o| {
            let url = format!("https://127.0.0.1:{PORT}/");
            o.set_url(Some(url.as_bytes())).unwrap();
            traced(o);
        });
        assert_eq!(got.result, Ok(()));
        lines.extend(
            got.seen
                .text()
                .into_iter()
                .filter(|l| l.starts_with("[SSLS] "))
                .map(|l| l.trim_end().to_owned()),
        );
    }
    // On Windows the CA's path made absolute (`_fullpath`).
    #[cfg(unix)]
    let ca = "CA-19:/fake/ca-bundle.crt";
    #[cfg(windows)]
    let ca = "CA-21:C:\\fake\\ca-bundle.crt";
    let key = format!("https:127.0.0.1:{PORT}:KEY-V3:TLSVER-6-0:{ca}:IMPL-11:FakeTLS/1.0:G");
    let want = [
        format!("[SSLS] find peer slot for {key} among 25 slots"),
        format!("[SSLS] peer not found for {key}"),
        format!("[SSLS] no cached session for {key}"),
        format!("[SSLS] find peer slot for {key} among 25 slots"),
        format!("[SSLS] peer not found for {key}"),
        format!(
            "[SSLS] added session for {key} [proto=0x304, valid_secs=7200, alpn=(nil), \
             earlydata=0, quic_tp=no], peer has 1 sessions now"
        ),
        format!("[SSLS] find peer slot for {key} among 25 slots"),
        format!(
            "[SSLS] took session for {key} [proto=0x304, alpn=(nil), earlydata=0, \
             quic_tp=no], 0 sessions remain"
        ),
        format!("[SSLS] find peer slot for {key} among 25 slots"),
        format!(
            "[SSLS] added session for {key} [proto=0x304, valid_secs=7200, alpn=(nil), \
             earlydata=0, quic_tp=no], peer has 1 sessions now"
        ),
    ];
    assert_eq!(lines, want);
}

/// A share keeping TLS sessions serves them to the transfers of every
/// multi it is given to, in place of each multi's own, the application
/// told around each use; one keeping none leaves each multi its own.
#[test]
fn a_share_keeping_sessions_serves_them_across_multis() {
    use crate::share::{Kind, Share, Told};
    let (backend, libraries) = ticketing();
    let share = Share::new().unwrap();
    share.keep(Kind::SslSessions).unwrap();
    let told = Told::new(&share);
    let talks = answering(4);
    let clock = ManualClock::new().unwrap();
    for (i, talk) in talks[..2].iter().enumerate() {
        let mut m = serving_on(clock.clone(), Peer::Accepts, &[talk]);
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        e.set_share_watched(share.clone(), told.handler()).unwrap();
        let c = crate::components::Components::new().unwrap();
        c.configure(b"ssls");
        e.set_components(Some(c));
        let got = get_with(&mut m, e, "/", talk.clone(), |o| {
            let url = format!("https://127.0.0.1:{PORT}/");
            o.set_url(Some(url.as_bytes())).unwrap();
        });
        assert_eq!(got.result, Ok(()));
        // What the cache says under the share's lock is said after it.
        let said = got.seen.text();
        let added = said
            .iter()
            .filter(|l| l.starts_with("[SSLS] added session for "));
        assert_eq!(added.count(), 1, "{said:#?}");
        let took = said
            .iter()
            .filter(|l| l.starts_with("[SSLS] took session for "));
        assert_eq!(took.count(), i, "{said:#?}");
        assert_eq!(
            backend.log().resumed,
            i,
            "the share's kept for the next multi"
        );
    }
    // Each transfer took one, then gave one.
    let s = Kind::SslSessions;
    assert_eq!(told.uses(), [s, s, s, s]);
    let other = Share::new().unwrap();
    for talk in &talks[2..] {
        let mut m = serving(Peer::Accepts, &[talk]);
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        e.set_share(Some(other.clone())).unwrap();
        let got = get_with(&mut m, e, "/", talk.clone(), |o| {
            let url = format!("https://127.0.0.1:{PORT}/");
            o.set_url(Some(url.as_bytes())).unwrap();
        });
        assert_eq!(got.result, Ok(()));
    }
    assert_eq!(
        backend.log().resumed,
        1,
        "each multi its own, none kept between"
    );
}

/// A share that stops keeping its sessions between a transfer's choice of
/// them and its use, as one racing a handle that links on another thread
/// does, leaves the transfer no cache: it neither takes nor gives one, and
/// still runs, each lock told let go. C uses the cache it has freed.
#[test]
fn sessions_gone_under_a_transfer_s_use_are_no_cache() {
    use crate::share::{Emptying, Kind, Share, Told};
    let (backend, libraries) = ticketing();
    let share = Share::new().unwrap();
    share.keep(Kind::SslSessions).unwrap();
    let told = Told::new(&share);
    let talk = answering(1).remove(0);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let watch = Emptying::handler(&told, Kind::SslSessions);
    e.set_share_watched(share.clone(), watch).unwrap();
    let got = get_with(&mut m, e, "/", talk.clone(), |o| {
        let url = format!("https://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(got.result, Ok(()));
    assert_eq!(backend.log().resumed, 0);
    assert_eq!(told.uses(), [Kind::SslSessions], "told of the one use");
    assert!(!share.keeps(Kind::SslSessions));
}

/// Out of its multi, the same: the ticket read after the transfer has
/// nowhere to go.
#[test]
fn sessions_gone_under_a_use_out_of_a_multi_are_no_cache() {
    use crate::share::{Emptying, Kind, Share, Told};
    let (backend, libraries) = ticketing_late();
    let share = Share::new().unwrap();
    share.keep(Kind::SslSessions).unwrap();
    let told = Told::new(&share);
    let talk = answering(1).remove(0);
    let mut m = serving(Peer::Accepts, &[&talk]);
    m.make_handle_own();
    let mut e = only_connecting(&libraries);
    e.set_share_watched(share.clone(), told.handler()).unwrap();
    e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    told.uses();
    e.share_watch = Some(Emptying::handler(&told, Kind::SslSessions));
    let sent = m.send_raw_for(&mut e, b"x", &mut |_, _| {});
    assert!(sent.is_ok(), "{sent:?}");
    let mut buf = [0u8; 64];
    let got = m.recv_raw_for(&mut e, &mut buf, &mut |_, _| {});
    assert!(got.is_ok(), "{got:?}");
    assert_eq!(told.uses(), [Kind::SslSessions], "told of the one use");
    assert_eq!(backend.log().resumed, 0);
}

/// A handle that only connected, over a library giving its ticket on the
/// first read, as TLS 1.3's, and what it goes through: `calls` runs its
/// transfer in `m` and makes one send and one receive on its connection.
fn only_connecting(libraries: &SharedLibraries) -> Easy {
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let o = e.options_mut();
    let url = format!("https://127.0.0.1:{PORT}/");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.connect_only = crate::options::ConnectOnly::Yes;
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    e
}

/// A library giving its ticket as TLS 1.3's comes.
fn ticketing_late() -> (&'static FakeTls, SharedLibraries) {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::ticketing_late().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    (backend, libraries)
}

/// Send and receive on the connection `id` only made, until something
/// comes.
fn talk_on(m: &mut Multi, id: crate::multi::TransferId) {
    let sent = m.send_raw(id, b"x", &mut |_, _| {});
    assert!(matches!(sent, Some(Ok(_))), "{sent:?}");
    let mut buf = [0u8; 64];
    let got = m.recv_raw(id, &mut buf, &mut |_, _| {});
    assert!(matches!(got, Some(Ok(_))), "{got:?}");
}

/// The connection a handle only made gives its TLS library's objects
/// through the handle once a raw call took it up, from the share's pool
/// that keeps it, as C's `data->conn` gives them once the call set it;
/// none before.
#[test]
fn a_connection_only_made_gives_its_tls_objects_once_a_call_took_it_up() {
    use crate::share::{Kind, Share};
    let (_backend, libraries) = tls();
    let talk = answering(1).remove(0);
    let mut m = serving(Peer::Accepts, &[&talk]);
    m.make_handle_own();
    let share = Share::new().unwrap();
    share.keep(Kind::Connections).unwrap();
    let mut e = only_connecting(&libraries);
    e.set_share(Some(share.clone())).unwrap();
    e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    assert!(e.tls_native().is_none(), "none before a call");
    let sent = m.send_raw_for(&mut e, b"x", &mut |_, _| {});
    assert!(sent.is_ok(), "{sent:?}");
    assert!(e.tls_native().is_some(), "the share's connection's");
}

/// A ticket that comes as a handle in a multi reads the connection it only
/// made is its multi's to keep, for the next connection to resume: without
/// a share, as C's `data->multi` is still there.
#[test]
fn a_ticket_read_on_a_connection_only_made_is_its_multi_s() {
    let (backend, libraries) = ticketing_late();
    let [talk_a, talk_b] = [answering(1).remove(0), answering(1).remove(0)];
    let mut m = serving(Peer::Accepts, &[&talk_a, &talk_b]);
    let a = m
        .add(Box::new(only_connecting(&libraries)), (), &mut NoEvents)
        .unwrap();
    assert_eq!(
        drive_to_completion(&mut m, a, &mut NoEvents).unwrap(),
        Ok(())
    );
    talk_on(&mut m, a);
    m.remove(a, &mut NoEvents).unwrap();
    let b = m
        .add(Box::new(only_connecting(&libraries)), (), &mut NoEvents)
        .unwrap();
    assert_eq!(
        drive_to_completion(&mut m, b, &mut NoEvents).unwrap(),
        Ok(())
    );
    assert_eq!(backend.log().resumed, 1, "the second resumes the first's");
    m.remove(b, &mut NoEvents).unwrap();
}

/// Out of its multi, a ticket goes to the handle's share, the application
/// told around it, out of the connections' lock, and what the cache says
/// said after; C's `cf_ssl_scache_get`.
#[test]
fn a_ticket_read_out_of_a_multi_is_its_share_s() {
    use crate::share::{Kind, Share, Told};
    let (backend, libraries) = ticketing_late();
    let share = Share::new().unwrap();
    share.keep(Kind::SslSessions).unwrap();
    let told = Told::new(&share);
    let clock = ManualClock::new().unwrap();
    for (i, talk) in answering(2).iter().enumerate() {
        let mut m = serving_on(clock.clone(), Peer::Accepts, &[talk]);
        m.make_handle_own();
        let mut e = only_connecting(&libraries);
        let components = crate::components::Components::new().unwrap();
        components.configure(b"ssls");
        e.set_components(Some(components));
        e.options_mut().output.verbose = true;
        e.set_share_watched(share.clone(), told.handler()).unwrap();
        e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
        assert_eq!(backend.log().resumed, i, "the share's kept for the next");
        told.uses();
        let sent = m.send_raw_for(&mut e, b"x", &mut |_, _| {});
        assert!(sent.is_ok(), "{sent:?}");
        let mut lines = Vec::new();
        let mut buf = [0u8; 64];
        let got = m.recv_raw_for(&mut e, &mut buf, &mut |_, b| {
            lines.push(String::from_utf8_lossy(b).into_owned());
        });
        assert!(got.is_ok(), "{got:?}");
        assert_eq!(told.uses(), [Kind::SslSessions], "told of the one use");
        let added = lines
            .iter()
            .filter(|l| l.starts_with("[SSLS] added session for "));
        assert_eq!(added.count(), 1, "{lines:#?}");
    }
}

/// Out of its multi with no share, a ticket has nowhere to go: C's
/// `data->multi` is none once a perform is done. The next connection in
/// the same own multi has none to resume.
#[test]
fn a_ticket_read_with_nowhere_to_go_is_dropped() {
    let (backend, libraries) = ticketing_late();
    let talks = answering(2);
    let mut m = serving(Peer::Accepts, &[&talks[0], &talks[1]]);
    m.make_handle_own();
    let mut e = only_connecting(&libraries);
    e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    let sent = m.send_raw_for(&mut e, b"x", &mut |_, _| {});
    assert!(sent.is_ok(), "{sent:?}");
    let mut buf = [0u8; 64];
    let got = m.recv_raw_for(&mut e, &mut buf, &mut |_, _| {});
    assert!(got.is_ok(), "{got:?}");
    let mut other = only_connecting(&libraries);
    other.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    assert_eq!(backend.log().resumed, 0, "none kept");
}

/// `CURLINFO_TLS_SSL_PTR` on a connection only made answers as C's: none
/// as the transfer lets it go, its session once a call takes it up, in a
/// multi or out of it.
#[test]
fn a_connection_only_made_shows_its_tls_objects_once_taken_up() {
    let (_backend, libraries) = ticketing_late();
    let talks = answering(2);
    let mut m = serving(Peer::Accepts, &[&talks[0]]);
    let id = m
        .add(Box::new(only_connecting(&libraries)), (), &mut NoEvents)
        .unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    assert!(m.tls_native(id).is_none(), "not taken up");
    talk_on(&mut m, id);
    assert!(m.tls_native(id).is_some(), "taken up");
    m.remove(id, &mut NoEvents).unwrap();
    let mut m = serving(Peer::Accepts, &[&talks[1]]);
    m.make_handle_own();
    let mut e = only_connecting(&libraries);
    e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    assert!(m.tls_native_for(&e).is_none(), "not taken up");
    let sent = m.send_raw_for(&mut e, b"x", &mut |_, _| {});
    assert!(sent.is_ok(), "{sent:?}");
    assert!(m.tls_native_for(&e).is_some(), "taken up");
}

/// Two transfers on fresh connections by a library whose tickets allow
/// `most` bytes of early data, the second's server answering `second`,
/// each transfer asking for early data if `asks`: the second's run.
fn early_pair(most: usize, second: &[&[u8]], asks: bool) -> (Ran, Conversation) {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::early(most).unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let first = answering(1).remove(0);
    let second = Conversation::replies(second, false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let set = |o: &mut Options| {
        o.limits.reuse.fresh = true;
        if asks {
            o.tls.options.make_mut().unwrap().ssl_options = crate::options::SslOptions::EARLYDATA;
        }
    };
    let got = get_tls(&mut m, &libraries, "/", first, set);
    assert_eq!(got.result, Ok(()));
    assert_eq!(
        got.easy.report().earlydata_sent(),
        0,
        "the first resumes none"
    );
    let got = get_tls(&mut m, &libraries, "/", second.clone(), set);
    assert_eq!(got.result, Ok(()));
    assert_eq!(backend.log().resumed, 1);
    (got, second)
}

/// The request a transfer of `early_pair` sends.
fn early_get() -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n"
    )
    .into_bytes()
}

/// Resuming a session that allows early data, a transfer that asks puts
/// its handshake off until its request, which goes in it, after the
/// hello: the server taking it, it is not sent again, and the transfer
/// counts it and times its TLS as the handshake ends
/// (`ssl_cf_connect_deferred`).
#[test]
fn a_request_goes_as_early_data_where_the_server_takes_it() {
    let [_, response] = served(OK);
    let (got, talk) = early_pair(16384, &[fake::EARLY_OK, &response], true);
    let get = early_get();
    let n = get.len();
    let wire = sent(&talk);
    let want = [HELLO, &get, FINISHED, CLOSE].concat();
    assert_eq!(
        String::from_utf8_lossy(&wire),
        String::from_utf8_lossy(&want)
    );
    assert_eq!(got.easy.report().earlydata_sent(), n as i64);
    // Its TLS is timed as the put-off handshake ends.
    assert!(got.easy.report().timings().appconnect() > Duration::ZERO);
    let accepted = format!("Server accepted {n} bytes of TLS early data.");
    assert!(said(&got, &accepted), "{:?}", got.seen.text());
}

/// The transfer's verbose output has the line `line`.
fn said(got: &Ran, line: &str) -> bool {
    got.seen.text().iter().any(|l| l.trim_end() == line)
}

/// The server refusing the early data, the request is sent again after
/// the handshake, and counted as refused.
#[test]
fn early_data_the_server_refuses_is_sent_again() {
    let [welcome, response] = served(OK);
    let (got, talk) = early_pair(16384, &[&welcome, b"", &response], true);
    let get = early_get();
    let n = get.len() as i64;
    let wire = sent(&talk);
    let want = [HELLO, &get, FINISHED, &get, CLOSE].concat();
    assert_eq!(
        String::from_utf8_lossy(&wire),
        String::from_utf8_lossy(&want)
    );
    assert_eq!(got.easy.report().earlydata_sent(), -n);
    assert!(said(&got, "Server rejected TLS early data."));
}

/// No more goes early than the session allows; the rest follows the
/// handshake.
#[test]
fn early_data_is_cut_at_what_the_session_allows() {
    let [_, response] = served(OK);
    let (got, talk) = early_pair(10, &[fake::EARLY_OK, &response], true);
    let get = early_get();
    let want = [HELLO, &get[..10], FINISHED, &get[10..], CLOSE].concat();
    assert_eq!(
        String::from_utf8_lossy(&sent(&talk)),
        String::from_utf8_lossy(&want)
    );
    assert_eq!(got.easy.report().earlydata_sent(), 10);
}

/// Early data to an HTTPS proxy goes as to an origin, its request in the
/// proxy's resumed session's hello and the proxy's acceptance said, but
/// is not the transfer's: neither counted nor timed, as C reports early
/// data and the TLS time of the origin's filter alone
/// (`ssl_cf_connect_deferred`'s `Curl_ssl_cf_is_proxy` and
/// `Curl_cft_ssl` tests).
#[test]
fn early_data_to_an_https_proxy_is_neither_counted_nor_timed() {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::early(16384).unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let [_, response] = served(OK);
    let first = answering(1).remove(0);
    let second = Conversation::replies(&[fake::EARLY_OK, &response], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let run = |m: &mut Multi, talk: &Conversation| {
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        get_with(m, e, "/", talk.clone(), |o| {
            https_proxy(o, b"http://origin.example/p");
            o.limits.reuse.fresh = true;
            let proxy = o.proxy.make_mut().unwrap();
            proxy.tls.options.make_mut().unwrap().ssl_options =
                crate::options::SslOptions::EARLYDATA;
        })
    };
    assert_eq!(run(&mut m, &first).result, Ok(()));
    let got = run(&mut m, &second);
    assert_eq!(got.result, Ok(()), "{:?}", got.seen.text());
    assert_eq!(backend.log().resumed, 1);
    let get = "GET http://origin.example/p HTTP/1.1\r\nHost: origin.example\r\n";
    let wire = String::from_utf8(sent(&second)).unwrap();
    let early = wire.strip_prefix("FAKETLS HELLO\r\n\r\n");
    assert!(early.is_some_and(|w| w.starts_with(get)), "{wire}");
    let n = wire.find("FAKETLS FINISHED").unwrap() - HELLO.len();
    let accepted = format!("Server accepted {n} bytes of TLS early data.");
    assert!(said(&got, &accepted), "{:?}", got.seen.text());
    let report = got.easy.report();
    assert_eq!(report.earlydata_sent(), 0, "the proxy's, not counted");
    assert_eq!(report.timings().appconnect(), Duration::ZERO, "nor timed");
}

/// A transfer that does not ask sends none, its handshake not put off.
#[test]
fn without_asking_no_early_data_goes() {
    let (got, talk) = early_pair(16384, &[WELCOME, &fake::records(OK).unwrap()], false);
    let want = [HELLO, FINISHED, &early_get(), CLOSE].concat();
    assert_eq!(
        String::from_utf8_lossy(&sent(&talk)),
        String::from_utf8_lossy(&want)
    );
    assert_eq!(got.easy.report().earlydata_sent(), 0);
}

/// A handshake put off that fails as the request lets it go on fails the
/// transfer with the handshake's error, not the send's; the send adds no
/// reason of its own to the session's, here none (`Curl_xfer_send` says
/// nothing).
#[test]
fn a_handshake_put_off_that_fails_fails_the_transfer_with_its_error() {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::early(16384).unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let first = answering(1).remove(0);
    let second = Conversation::replies(&[b"FAKETLS GOODBYE\r\n\r\n"], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let set = |o: &mut Options| {
        o.limits.reuse.fresh = true;
        o.tls.options.make_mut().unwrap().ssl_options = crate::options::SslOptions::EARLYDATA;
    };
    assert_eq!(get_tls(&mut m, &libraries, "/", first, set).result, Ok(()));
    let got = get_tls(&mut m, &libraries, "/", second, set);
    assert_eq!(got.result, Err(ErrorKind::SslConnectError));
    let text = got.seen.text();
    assert!(
        text.iter().any(|l| l.starts_with("using HTTP/1.x")),
        "{text:#?}"
    );
    assert!(!text.iter().any(|l| l.contains("failure")), "{text:#?}");
}

/// Plain HTTP through an HTTPS proxy asked for in HTTP/2 offers the
/// proxy HTTP/2 by ALPN, ALPN on or off; agreed, the request goes to the
/// proxy over HTTP/2, its URL's scheme, authority and path the stream's
/// fields (`cf_ssl_proxy_create`, `Curl_http2_switch`, `start_req`).
#[test]
fn http_through_an_http_2_proxy_goes_as_its_streams_fields() {
    static FAKE: crate::http2::fake::FakeH2 = crate::http2::fake::FakeH2;
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        h2: Some(&FAKE),
        ..Libraries::NONE
    })
    .unwrap();
    let response =
        fake::records(b"S\nH 1 0\n:status: 200\ncontent-length: 3\n\nD 1 3 1\nok\n").unwrap();
    let talk = Conversation::replies(&[WELCOME, &response], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        https_proxy(o, b"http://origin.example/p?q");
        o.proxy.make_mut().unwrap().kind = crate::options::ProxyType::Https2;
        o.tls.options.make_mut().unwrap().alpn = false;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok\n");
    assert_eq!(backend.log().alpn, Some(crate::tls::Alpn::H2Http11));
    let sent = String::from_utf8(sent(&talk)).unwrap();
    let fields = "H 1 1\n:method: GET\n:scheme: http\n:authority: origin.example\n:path: /p?q\n";
    assert!(sent.contains(fields), "{sent}");
}

/// A server of an HTTPS proxy that agrees to HTTP/2, answering the
/// `CONNECT` with `answer` and, if it agrees, what goes through the
/// tunnel with `then`; with the handle's libraries and a log of its TLS.
fn h2_proxy(answer: &[u8], then: &[u8]) -> (&'static FakeTls, SharedLibraries, Vec<Vec<u8>>) {
    static FAKE: crate::http2::fake::FakeH2 = crate::http2::fake::FakeH2;
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        h2: Some(&FAKE),
        ..Libraries::NONE
    })
    .unwrap();
    let mut replies = vec![WELCOME.to_vec(), fake::records(answer).unwrap()];
    if !then.is_empty() {
        replies.push(fake::records(then).unwrap());
    }
    (backend, libraries, replies)
}

/// A GET of `url` through an HTTPS proxy asked for in HTTP/2, tunneling,
/// whose server says `replies`.
fn through_h2_proxy(
    libraries: SharedLibraries,
    replies: &[Vec<u8>],
    url: &[u8],
) -> (Ran, Conversation) {
    through_h2_proxy_by(Easy::new(), libraries, replies, url)
}

/// `through_h2_proxy`, by the handle `e`.
fn through_h2_proxy_by(
    mut e: Easy,
    libraries: SharedLibraries,
    replies: &[Vec<u8>],
    url: &[u8],
) -> (Ran, Conversation) {
    let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    let talk = Conversation::replies(&replies, false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        https_proxy(o, url);
        let proxy = o.proxy.make_mut().unwrap();
        proxy.kind = crate::options::ProxyType::Https2;
        proxy.tunnel = true;
    });
    (ran, talk)
}

/// A tunnel through an HTTPS proxy that agreed to HTTP/2 is a stream of a
/// session with it (`cf-h2-proxy.c`): the `CONNECT` goes as the stream's
/// fields, no `Host` and no `Proxy-Connection`; the proxy's answer is
/// traced as C traces it, and the origin's request and response, in
/// HTTP/1.1 whatever the proxy speaks, go as the stream's DATA.
#[test]
fn a_tunnel_through_an_http_2_proxy_is_a_stream() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
    let data = [format!("D 1 {} 0\n", response.len()).as_bytes(), response].concat();
    let (backend, libraries, replies) = h2_proxy(b"S\nH 1 0\n:status: 200\nvia: x\n\n", &data);
    let (ran, talk) = through_h2_proxy(libraries, &replies, b"http://origin.example/p");
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok\n");
    assert_eq!(backend.log().alpn, Some(crate::tls::Alpn::H2Http11));
    let sent = String::from_utf8(sent(&talk)).unwrap();
    let connect =
        "H 1 0\n:method: CONNECT\n:authority: origin.example:80\nuser-agent: curl/test\n\n";
    assert!(sent.contains(connect), "{sent}");
    let request =
        "GET /p HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n";
    let framed = format!("D 1 {} 0\n{request}", request.len());
    assert!(sent.contains(&framed), "{sent}");
    let text = ran.seen.text();
    let from = text
        .iter()
        .position(|l| l == "CONNECT: 'h2' negotiated\n")
        .unwrap_or_else(|| panic!("{text:?}"));
    assert_eq!(
        text[from + 1..from + 7],
        [
            "Establishing HTTP/2 proxy tunnel to origin.example:80\n",
            "CONNECT Response Status 200\n",
            "Response Headers (1 total):\n",
            "  via: x\n",
            "CONNECT tunnel established, response 200\n",
            "CONNECT phase completed for HTTP/2 proxy\n",
        ]
    );
    assert!(text.iter().any(|l| l == "using HTTP/1.x\n"), "{text:?}");
}

/// What a run's trace says the session with an HTTP/2 proxy sent the
/// layers below, in runs each ending as its output is flushed: the
/// sizes of the chunks it passed on, each as given to its first send,
/// the rest of a chunk given again until it is all taken
/// (`nw_out_writer`, `nw send buffer flushed`).
fn nw_out_runs(text: &[String]) -> Vec<Vec<usize>> {
    let mut runs = vec![Vec::new()];
    let mut rest = 0;
    for line in text {
        if let Some(said) = line.split("[H2-PROXY] [0] nw_out_writer(len=").nth(1) {
            // "<given>) -> <code>, <taken>"
            let (given, said) = said.split_once(") -> ").unwrap();
            let given: usize = given.parse().unwrap();
            let taken: usize = said.split(", ").nth(1).unwrap().trim().parse().unwrap();
            if rest == 0 {
                runs.last_mut().unwrap().push(given);
            } else {
                assert_eq!(given, rest, "the rest of the chunk, given again");
            }
            rest = given - taken;
        } else if line.ends_with("[H2-PROXY] [0] nw send buffer flushed\n") {
            runs.push(Vec::new());
        }
    }
    runs.retain(|r| !r.is_empty());
    runs
}

/// The DATA payloads of stream 1 in what the proxy was sent, in order.
fn tunneled(sent: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    let mut at = 0;
    while let Some(i) = sent[at..].windows(4).position(|w| w == b"D 1 ") {
        let start = at + i;
        let nl = start + sent[start..].iter().position(|&b| b == b'\n').unwrap();
        let line = std::str::from_utf8(&sent[start..nl]).unwrap();
        let n: usize = line.split(' ').nth(2).unwrap().parse().unwrap();
        payload.extend_from_slice(&sent[nl + 1..nl + 1 + n]);
        at = nl + 1 + n;
    }
    payload
}

/// The session with an HTTP/2 proxy passes the layers below its frames
/// through an output of one 16 KiB chunk, sent whole as the next frame
/// needs its room and what is left once the session frames no more
/// (`proxy_h2_on_session_send`'s `Curl_bufq_write_pass`,
/// `proxy_h2_nw_out_flush`), and holds the tunnel's bytes in 128 KiB of
/// chunks, taking what they have room for (`cf_h2_proxy_send`'s
/// `Curl_bufq_write`). The C build through `nghttpx --http2-proxy`
/// passes its TLS 16384 bytes at a time of 16393-byte DATA frames, each
/// run of them ended by what is left: `nw_out_writer(len=16384) -> 0,
/// 16384`, then `nw_out_writer(len=35)` and `nw send buffer flushed`.
#[test]
fn an_http_2_proxy_s_session_sends_below_a_chunk_at_a_time() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
    let data = [format!("D 1 {} 0\n", response.len()).as_bytes(), response].concat();
    let (_, libraries, replies) = h2_proxy(b"S\nH 1 0\n:status: 200\n\n", &data);
    let body = vec![b'.'; 200_000];
    let mut e = Easy::new();
    let c = crate::components::Components::new().unwrap();
    c.configure(b"h2-proxy");
    e.set_components(Some(c));
    let o = e.options_mut();
    o.upload = crate::options::UploadSource::Bytes(TryArc::try_new(body.clone()).unwrap());
    o.method = Method::Post;
    let (ran, talk) = through_h2_proxy_by(e, libraries, &replies, b"http://origin.example/p");
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let text = ran.seen.text();
    let runs = nw_out_runs(&text);
    for run in &runs {
        let (last, whole) = run.split_last().unwrap();
        assert!(whole.iter().all(|&n| n == 16384), "{runs:?}");
        assert!(*last <= 16384, "{runs:?}");
    }
    let chunks = runs.iter().flatten().filter(|&&n| n == 16384).count();
    assert!(chunks >= body.len() / 16384, "{runs:?}");
    // The tunnel's buffer takes the first send whole, C's 64 KiB of it.
    assert!(
        text.iter()
            .any(|l| l.ends_with("[H2-PROXY] cf_send(), bufq_write 0, 65536\n")),
        "{text:#?}"
    );
    let tunneled = tunneled(&sent(&talk));
    assert!(tunneled.ends_with(&body), "{}", tunneled.len());
}

/// The tunnel's bytes wait in 128 KiB of chunks while the proxy's window
/// is shut, and a send they have no room for takes none, which C says is
/// `CURLE_AGAIN` (`cf_h2_proxy_send`'s `Curl_bufq_write` into a full
/// `sendbuf`, `H2_TUNNEL_SEND_CHUNKS`), on both its lines.
#[test]
fn an_http_2_proxy_tunnel_holds_its_chunks_and_no_more() {
    let (_, libraries, replies) = h2_proxy(b"S 100 0\nH 1 0\n:status: 200\n\n", b"");
    let mut e = Easy::new();
    let c = crate::components::Components::new().unwrap();
    c.configure(b"h2-proxy");
    e.set_components(Some(c));
    let o = e.options_mut();
    let body = vec![b'.'; 300_000];
    o.upload = crate::options::UploadSource::Bytes(TryArc::try_new(body).unwrap());
    o.method = Method::Post;
    o.limits.total = crate::time::TimeLimit::from_millis(3000);
    let (ran, _) = through_h2_proxy_by(e, libraries, &replies, b"http://origin.example/p");
    assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
    let text = ran.seen.text();
    let writes: Vec<&str> = text
        .iter()
        .filter_map(|l| l.split("[H2-PROXY] cf_send(), ").nth(1))
        .map(str::trim_end)
        .collect();
    let took: usize = writes
        .iter()
        .filter_map(|w| w.strip_prefix("bufq_write 0, "))
        .map(|n| n.parse::<usize>().unwrap())
        .sum();
    assert_eq!(took, 128 * 1024, "{writes:?}");
    assert!(writes.contains(&"bufq_write 81, 0"), "{writes:?}");
    let again = "[H2-PROXY] [1] cf_send(len=";
    assert!(
        text.iter()
            .any(|l| l.contains(again) && l.contains(") -> 81, 0, h2 windows 0-")),
        "{text:#?}"
    );
}

/// ALPN off, a proxy asked for in HTTP/2 is still offered it, but the
/// origin's TLS through its tunnel offers nothing: the proxy's ALPN is
/// the proxy filter's alone (`cf_ssl_proxy_create`).
#[test]
fn https_through_an_http_2_proxy_with_alpn_off_offers_the_origin_nothing() {
    let (backend, libraries, replies) = h2_proxy(b"S\nH 1 0\n:status: 200\n\n", b"");
    let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    let talk = Conversation::replies(&replies, false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        https_proxy(o, b"https://origin.example/p");
        o.proxy.make_mut().unwrap().kind = crate::options::ProxyType::Https2;
        o.tls.options.make_mut().unwrap().alpn = false;
        o.limits.total = crate::time::TimeLimit::from_millis(300);
    });
    assert!(ran.result.is_err(), "the origin never answers");
    let log = backend.log();
    assert_eq!(log.sessions, 2, "the proxy's session, then the origin's");
    assert_eq!(
        log.name(),
        b"origin.example",
        "the last session, the origin's"
    );
    assert_eq!(log.alpn, Some(crate::tls::Alpn::None));
}

/// The request follows an HTTP/2 proxy's `CONNECT`, so once the tunnel
/// is up what reads it starts over, after the phase is said to be
/// completed (`cf_h2_proxy_connect`'s `Curl_client_reset`).
#[test]
fn the_readers_start_over_once_an_http_2_proxy_s_tunnel_is_up() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
    let data = [format!("D 1 {} 0\n", response.len()).as_bytes(), response].concat();
    let (_, libraries, replies) = h2_proxy(b"S\nH 1 0\n:status: 200\n\n", &data);
    let mut e = Easy::new();
    let c = crate::components::Components::new().unwrap();
    c.configure(b"read");
    e.set_components(Some(c));
    let (ran, _) = through_h2_proxy_by(e, libraries, &replies, b"http://origin.example/p");
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let text = ran.seen.text();
    let picked: Vec<&str> = text
        .iter()
        .map(|l| l.trim_end())
        .map(|l| l.find("[READ] ").map_or(l, |at| &l[at..]))
        .filter(|l| l.starts_with("CONNECT") || l.starts_with("[READ] client_reset"))
        .collect();
    assert_eq!(
        picked,
        [
            "[READ] client_reset, clear readers",
            "CONNECT: 'h2' negotiated",
            "CONNECT Response Status 200",
            "CONNECT tunnel established, response 200",
            "CONNECT phase completed for HTTP/2 proxy",
            "[READ] client_reset, clear readers",
            "[READ] client_reset, clear readers",
        ],
        "{text:#?}"
    );
}

/// HTTP/3 alone through an HTTPS proxy that speaks HTTP/2 asks it for a
/// CONNECT-UDP, an extended `CONNECT` (RFC 9298, 8441): the proxy's
/// scheme and authority, the path naming the origin, the protocol and
/// the capsules asked for, and no `user-agent` (`http_proxy_create_CONNECTUDP`).
/// A 2xx makes the tunnel, said as C says it whether the proxy names the
/// capsule protocol or not; one naming another fails it
/// (`Curl_http_proxy_inspect_tunnel_response`).
#[test]
fn http3_through_an_http_2_proxy_asks_for_connect_udp() {
    static FAKE: crate::http2::fake::FakeH2 = crate::http2::fake::FakeH2;
    let cases: [(&str, &str, bool); 3] = [
        (
            "capsule-protocol: ?1\n",
            "CONNECT-UDP tunnel established, response 200",
            true,
        ),
        (
            "",
            "CONNECT-UDP tunnel established, response 200 but no capsule-protocol header found",
            true,
        ),
        (
            "capsule-protocol: ?0\n",
            "Failed to establish CONNECT-UDP tunnel, response 200, unsupported \
             capsule-protocol value '?0'",
            false,
        ),
    ];
    for (field, said, made) in cases {
        let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
        let script = crate::http3::fake::Script::new();
        script.lock().unwrap().out.extend([vec![1; 1200], vec![]]);
        let h3: &'static crate::http3::fake::FakeHttp3 =
            Box::leak(Box::new(crate::http3::fake::FakeHttp3::new(script)));
        let libraries = SharedLibraries::new(Libraries {
            tls: Some(Library::Static(backend)),
            h2: Some(&FAKE),
            h3: Some(h3),
            ..Libraries::NONE
        })
        .unwrap();
        let answer = format!("S\nH 1 0\n:status: 200\n{field}\n");
        let replies = [WELCOME.to_vec(), fake::records(answer.as_bytes()).unwrap()];
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let talk = Conversation::replies(&replies, false).per_send();
        let mut m = serving(Peer::Accepts, &[&talk]);
        let mut e = Easy::new();
        e.set_libraries(libraries);
        let c = crate::components::Components::new().unwrap();
        c.configure(b"read");
        e.set_components(Some(c));
        let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
            https_proxy(o, b"https://origin.example/p");
            o.http.version = crate::options::HttpVersion::Http3Only;
            o.proxy.make_mut().unwrap().kind = crate::options::ProxyType::Https2;
            o.limits.total = crate::time::TimeLimit::from_millis(500);
        });
        let raw = sent(&talk);
        let sent = String::from_utf8_lossy(&raw).into_owned();
        let connect = format!(
            "H 1 0\n:method: CONNECT\n:scheme: https\n:authority: 127.0.0.1:{PORT}\n\
             :path: /.well-known/masque/udp/origin.example/443/\n:protocol: connect-udp\n\
             capsule-protocol: ?1\n\n"
        );
        assert!(sent.contains(&connect), "{field}: {sent}");
        let text = ran.seen.text();
        assert!(
            text.iter().any(|l| l.trim_end() == said),
            "{field}: {text:#?}"
        );
        let phase = text
            .iter()
            .position(|l| l == "CONNECT-UDP phase completed for HTTP/2 proxy\n");
        assert_eq!(phase.is_some(), made, "{field}: {text:#?}");
        if let Some(at) = phase {
            // The request follows: what reads it starts over
            // (`cf_h2_proxy_connect`'s `Curl_client_reset`).
            assert!(
                text[at + 1].ends_with("[READ] client_reset, clear readers\n"),
                "{field}: {text:#?}"
            );
        }
        if made {
            // The origin's first datagram goes through it as a capsule.
            let (head, len) = crate::conn::capsule::header(1200);
            let mut capsule = head[..len].to_vec();
            capsule.extend([1; 1200]);
            let data = [format!("D 1 {} 0\n", capsule.len()).into_bytes(), capsule].concat();
            assert!(
                raw.windows(data.len()).any(|w| w == data),
                "{field}: {sent}"
            );
        } else {
            assert_eq!(ran.result, Err(ErrorKind::CouldntConnect), "{field}");
        }
    }
}

/// The proxy's answer is held to C's limit as each field arrives: a MiB
/// of names and values; a field past it fails the session's read, and
/// no tunnel is made (`Curl_http_resp_make`'s `dynhds`).
#[test]
fn an_http_2_proxy_s_answer_is_held_to_c_s_limit() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
    let data = [format!("D 1 {} 0\n", response.len()).as_bytes(), response].concat();
    // A MiB less the name's one byte is a value that fills it.
    let fills = 1024 * 1024 - 1;
    for (value, made) in [(fills, true), (fills + 1, false)] {
        let mut answer = b"S\nH 1 0\n:status: 200\nx: ".to_vec();
        answer.extend(std::iter::repeat_n(b'v', value));
        answer.extend_from_slice(b"\n\n");
        let (_, libraries, replies) = h2_proxy(&answer, &data);
        let (ran, _) = through_h2_proxy(libraries, &replies, b"http://origin.example/p");
        let text = ran.seen.text();
        let established = text
            .iter()
            .any(|l| l == "CONNECT tunnel established, response 200\n");
        assert_eq!(established, made, "{value}");
        assert_eq!(ran.result.is_ok(), made, "{value}: {:?}", ran.result);
    }
}

/// The tunnel's layer shuts down in its filter's name, `H2-PROXY`, on
/// the multi's internal trace, as the connection closes after its
/// transfer (C's `[H2-PROXY] shut down successfully`).
#[test]
fn a_tunnel_through_an_http_2_proxy_shuts_down_in_its_name() {
    use crate::components::{Component, Components, Level};
    #[derive(Clone, Default)]
    struct Written(Arc<Mutex<Vec<u8>>>);
    impl crate::handler::TextSink for Written {
        fn write(&self, text: &[u8]) {
            self.0.lock().unwrap().extend_from_slice(text);
        }
    }
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
    let data = [format!("D 1 {} 0\n", response.len()).as_bytes(), response].concat();
    let (_, libraries, replies) = h2_proxy(b"S\nH 1 0\n:status: 200\n\n", &data);
    let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    let talk = Conversation::replies(&replies, false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let components = Components::new().unwrap();
    components.set(Component::H2Proxy, Level::Info);
    let written = Written::default();
    m.trace_internally_to(components, Handler::text(written.clone()).unwrap());
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        https_proxy(o, b"http://origin.example/p");
        let proxy = o.proxy.make_mut().unwrap();
        proxy.kind = crate::options::ProxyType::Https2;
        proxy.tunnel = true;
        o.limits.reuse.forbid = true;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let text = String::from_utf8(written.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("* [H2-PROXY] shut down "), "{text}");
    // It says GOAWAY as it goes, no stream of the proxy's served.
    let sent = String::from_utf8(sent(&talk)).unwrap();
    assert!(sent.ends_with("G 0 0\n"), "{sent}");
}

/// A tunnel the proxy resets fails the transfer's read, naming who
/// ended it and how (`h2_handle_tunnel_close`).
#[test]
fn a_tunnel_an_http_2_proxy_resets_fails_naming_its_error() {
    let half = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
    let data = [
        format!("D 1 {} 0\n", half.len()).as_bytes(),
        half,
        b"R 1 8\n",
    ]
    .concat();
    let (_, libraries, replies) = h2_proxy(b"S\nH 1 0\n:status: 200\n\n", &data);
    let (ran, _) = through_h2_proxy(libraries, &replies, b"http://origin.example/p");
    assert_eq!(
        ran.result,
        Err(ErrorKind::RecvError),
        "{:?}",
        ran.seen.text()
    );
    let said = "HTTP/2 stream 1 reset by server (error 0x8 CANCEL)";
    assert_eq!(ran.easy.report().failure(), Some(said.as_bytes()));
}

/// A proxy that speaks HTTP/2 refusing the `CONNECT` fails the transfer
/// as one that could not connect, with no message of its own, and a 407's
/// challenge does not ask again, as only Negotiate's would
/// (`Curl_http_proxy_inspect_tunnel_response`).
#[test]
fn a_refused_tunnel_through_an_http_2_proxy_fails_to_connect() {
    let answer = b"S\nH 1 0\n:status: 407\nproxy-authenticate: Basic realm=\"x\"\n\n";
    let (_, libraries, replies) = h2_proxy(answer, b"");
    let (ran, talk) = through_h2_proxy(libraries, &replies, b"http://origin.example/p");
    assert_eq!(
        ran.result,
        Err(ErrorKind::CouldntConnect),
        "{:?}",
        ran.seen.text()
    );
    let text = ran.seen.text();
    assert!(
        text.iter().any(|l| l == "CONNECT Response Status 407\n"),
        "{text:?}"
    );
    // The challenge is taken in: what the proxy offered is reported.
    assert_eq!(
        ran.easy.report().proxy_auth_offered(),
        crate::options::AuthMethods::BASIC
    );
    let sent = String::from_utf8(sent(&talk)).unwrap();
    assert_eq!(sent.matches(":method: CONNECT").count(), 1, "{sent}");
    assert_eq!(ran.easy.report().failure(), None, "no message");
}

/// A 407 through a proxy that speaks HTTP/2 whose challenge Negotiate
/// with the proxy takes asks again, on a stream of its own, with the
/// context's answer (`Curl_http_proxy_inspect_tunnel_response`, C's
/// `newurl` set by `auth_spnego`), and the tunnel is made.
#[test]
fn a_negotiate_challenge_through_an_http_2_proxy_asks_again() {
    use crate::gss::testing::Scripted;
    static FAKE: crate::http2::fake::FakeH2 = crate::http2::fake::FakeH2;
    let gss = Scripted::leaked();
    gss.then_token(b"first").then_token(b"second");
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        h2: Some(&FAKE),
        gss: Some(gss),
        ..Libraries::NONE
    })
    .unwrap();
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
    let challenge = b"S\nH 1 0\n:status: 407\nproxy-authenticate: Negotiate Y2hhbGxlbmdl\n\n";
    let data = [format!("D 3 {} 0\n", response.len()).as_bytes(), response].concat();
    let replies = [
        WELCOME.to_vec(),
        fake::records(challenge).unwrap(),
        fake::records(b"H 3 0\n:status: 200\n\n").unwrap(),
        fake::records(&data).unwrap(),
    ];
    let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    let talk = Conversation::replies(&replies, false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        https_proxy(o, b"http://origin.example/p");
        let proxy = o.proxy.make_mut().unwrap();
        proxy.kind = crate::options::ProxyType::Https2;
        proxy.tunnel = true;
        proxy.auth = crate::options::HttpAuth(crate::options::AuthMethods::NEGOTIATE);
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    assert_eq!(ran.seen.body(), b"ok\n");
    let sent = String::from_utf8(sent(&talk)).unwrap();
    assert_eq!(sent.matches(":method: CONNECT").count(), 2, "{sent}");
    assert!(sent.contains("Negotiate c2Vjb25k"), "{sent}");
}

/// What the layer above reads of the tunnel's DATA is used of its
/// stream's window, which the proxy is told of as the session sees fit
/// (`cf_h2_proxy_recv`'s `nghttp2_session_consume`): a body larger than
/// half the window opens it again.
#[test]
fn a_tunnel_through_an_http_2_proxy_opens_its_window_as_it_is_read() {
    let body = vec![b'x'; 40_000];
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    let response = [head.as_bytes(), &body].concat();
    let data = [format!("D 1 {} 0\n", response.len()).as_bytes(), &response].concat();
    let (_, libraries, replies) = h2_proxy(b"S\nU 0\nH 1 0\n:status: 200\n\n", &data);
    let (ran, talk) = through_h2_proxy(libraries, &replies, b"http://origin.example/p");
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    assert_eq!(ran.seen.body(), body);
    let sent = String::from_utf8(sent(&talk)).unwrap();
    assert!(sent.contains("\nU 1 "), "{sent}");
}

/// What the progress handler saw on each call: the bytes downloaded, and
/// whether the connection's TLS objects were within reach.
#[derive(Clone, Default)]
struct ProgressSeen(std::sync::Arc<std::sync::Mutex<Vec<(u64, bool)>>>);

impl crate::handler::ProgressHandler for ProgressSeen {
    fn progress(
        &self,
        cx: &mut crate::multi::TransferCx<'_>,
        now: crate::handler::ProgressNow,
    ) -> crate::handler::ProgressVerdict {
        let tls = cx.tls_native(cx.me()).is_some();
        self.0.lock().unwrap().push((now.downloaded, tls));
        crate::handler::ProgressVerdict::Continue
    }
}

/// A transfer taken out mid-response has a last progress pass as it
/// goes, its bytes counted and its connection's TLS objects still within
/// the handler's reach, as C's `curl_multi_remove_handle` gives one in
/// `multi_done`, its connection still attached (`Curl_pgrsDone`).
#[test]
fn a_transfer_removed_mid_response_hears_its_progress_once_more() {
    let (_backend, libraries) = tls();
    let half = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
    let talk = Conversation::replies(&[WELCOME, &fake::records(half).unwrap()], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = https_handle(&libraries);
    let seen = ProgressSeen::default();
    e.options_mut().progress =
        crate::options::Progress::Handler(Handler::progress(seen.clone()).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    for _ in 0..50 {
        if seen.0.lock().unwrap().iter().any(|&(down, _)| down == 5) {
            break;
        }
        m.perform(&mut NoEvents).unwrap();
    }
    let before = seen.0.lock().unwrap().len();
    assert!(before > 0, "the response's start was read");
    m.remove(id, &mut NoEvents).unwrap();
    let calls = seen.0.lock().unwrap().clone();
    assert_eq!(calls.len(), before + 1, "{calls:?}");
    assert_eq!(calls.last(), Some(&(5, true)), "{calls:?}");
}

/// A session imported into a share by no more than the salted HMAC of its
/// peer's key resumes the next connection to that peer, its key learned; a
/// connection of other settings does not find it.
#[test]
fn an_imported_session_resumes_the_peer_its_hmac_names() {
    use crate::share::{Kind, Share};
    use crate::tls::SessionFor;
    let (backend, libraries) = ticketing();
    let talks = answering(3);
    let share = Share::new().unwrap();
    share.keep(Kind::SslSessions).unwrap();
    let clock = ManualClock::new().unwrap();
    let transfer = |share: &Share, talk: &Conversation, verify: bool| {
        let mut m = serving_on(clock.clone(), Peer::Accepts, &[talk]);
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        e.set_share(Some(share.clone())).unwrap();
        let c = crate::components::Components::new().unwrap();
        c.configure(b"ssls");
        e.set_components(Some(c));
        let got = get_with(&mut m, e, "/", talk.clone(), |o| {
            let url = format!("https://127.0.0.1:{PORT}/");
            o.set_url(Some(url.as_bytes())).unwrap();
            o.tls.verify_peer = verify;
        });
        assert_eq!(got.result, Ok(()));
        got.seen.text()
    };
    // The peer's key, as a first transfer on a share of its own says it.
    let first = Share::new().unwrap();
    first.keep(Kind::SslSessions).unwrap();
    let said = transfer(&first, &talks[0], true);
    let line = said
        .iter()
        .find_map(|l| l.strip_prefix("[SSLS] find peer slot for "))
        .unwrap();
    let key = line.split(" among ").next().unwrap();
    assert_eq!(backend.log().resumed, 0);

    let salt = [9u8; 32];
    let hmac = crate::hash::hmac_sha256(&salt, &[key.as_bytes()]);
    let both = [salt, hmac].concat();
    let ticket = crate::tls::fake::TICKET;
    let len = u16::try_from(ticket.len()).unwrap().to_be_bytes();
    let packed = [&[1, 4, len[0], len[1]][..], ticket].concat();
    let mut holder = Easy::new();
    holder.set_share(Some(share.clone())).unwrap();
    holder
        .ssls_import(SessionFor::SaltedHmac(&both), &packed, &mut |_, _| {})
        .unwrap();

    transfer(&share, &talks[1], false);
    assert_eq!(backend.log().resumed, 0, "made with other settings");
    let said = transfer(&share, &talks[2], true);
    assert_eq!(backend.log().resumed, 1, "{said:#?}");
    assert!(
        said.iter()
            .any(|l| l.contains("peer entry 0 key recovered: ")),
        "{said:#?}"
    );
}
