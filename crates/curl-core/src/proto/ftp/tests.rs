//! Transfers over a fake server: the login, a file retrieved over a
//! passive data connection, a refused file, the data connection closed
//! with its control connection, an answer awaited in DONE, and a
//! protected data connection resuming its control connection's session.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::conn::io::{Conversation, FakeNet, Peer as Net};
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{DebugHandler, DebugKind, Handler, Write, WriteHandler};
use crate::id::ArenaPolicy;
use crate::libraries::{Libraries, Library, SharedLibraries};
use crate::multi::{Env, Multi, NoEvents, TransferCx, TransferId, drive_to_completion};
use crate::options::{Ccc, Options};
use crate::time::ManualClock;

const PORT: u16 = 8021;
/// The port the server's `EPSV` answer names.
const DATA_PORT: u16 = 8022;

/// Collects the body.
#[derive(Clone, Default)]
struct Body(Arc<Mutex<Vec<u8>>>);

impl WriteHandler for Body {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.lock().unwrap().extend_from_slice(body);
        Write::Took(body.len())
    }
}

/// Collects the trace's text.
#[derive(Clone, Default)]
struct Text(Arc<Mutex<Vec<u8>>>);

impl Text {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl DebugHandler for Text {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text {
            self.0.lock().unwrap().extend_from_slice(data);
        }
    }
}

/// The fake network, its open sockets counted by the test while a multi
/// holds it.
#[derive(Clone)]
struct Counted(Arc<Mutex<FakeNet>>);

impl Counted {
    fn open(&self) -> usize {
        self.0.lock().unwrap().open_sockets()
    }
}

impl crate::conn::io::Net for Counted {
    fn poll(
        &mut self,
        sockets: &mut [crate::conn::io::SocketPoll<'_>],
        fds: &mut [crate::conn::io::PollFd<'_>],
        timeout: std::time::Duration,
    ) -> std::io::Result<u32> {
        self.0.lock().unwrap().poll(sockets, fds, timeout)
    }

    fn open(
        &mut self,
        addr: &crate::conn::io::Remote,
        kind: crate::conn::io::SocketKind,
    ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
        self.0.lock().unwrap().open(addr, kind)
    }

    fn close(&mut self, socket: crate::conn::io::Sock) {
        self.0.lock().unwrap().close(socket);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn crate::conn::io::Resolver)) {
        self.0.lock().unwrap().with_resolver(f);
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        None
    }

    fn interface_address(
        &mut self,
        _: &[u8],
        _: bool,
        _: crate::conn::io::Ipv6Scope,
        _: u32,
    ) -> crate::conn::io::InterfaceAddress {
        crate::conn::io::InterfaceAddress::NotFound
    }
}

/// A multi whose server at `PORT` takes `control` in turn, and at
/// `DATA_PORT` takes `data` in turn.
fn serving(control: &[&Conversation], data: &[&Conversation]) -> Multi {
    counting(control, data).0
}

/// `serving`'s multi, and its network's count of open sockets.
fn counting(control: &[&Conversation], data: &[&Conversation]) -> (Multi, Counted) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let data_at = SocketAddr::from(([127, 0, 0, 1], DATA_PORT));
    let mut net = FakeNet::new(clock.clone())
        .with_peer(at, Net::Accepts)
        .with_peer(data_at, Net::Accepts);
    for c in control {
        net = net.with_conversation(at, (*c).clone());
    }
    for c in data {
        net = net.with_conversation(data_at, (*c).clone());
    }
    let counted = Counted(Arc::new(Mutex::new(net)));
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(counted.clone()),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), counted)
}

/// A transfer of `url` (`PORT` in it replaced) added to `m`, its body and
/// its trace kept.
fn added(m: &mut Multi, url: &str, set: impl FnOnce(&mut Options)) -> (TransferId, Body, Text) {
    added_with(m, url, None, set)
}

/// The same, the transfer given `libraries` if any.
fn added_with(
    m: &mut Multi,
    url: &str,
    libraries: Option<SharedLibraries>,
    set: impl FnOnce(&mut Options),
) -> (TransferId, Body, Text) {
    let mut e = Easy::new();
    if let Some(libraries) = libraries {
        e.set_libraries(libraries);
    }
    added_easy(m, url, e, set)
}

/// The same, made of `e`.
fn added_easy(
    m: &mut Multi,
    url: &str,
    mut e: Easy,
    set: impl FnOnce(&mut Options),
) -> (TransferId, Body, Text) {
    let url = url.replace("PORT", &PORT.to_string());
    let traced = crate::components::Components::new().unwrap();
    traced.configure(b"multi");
    e.set_components(Some(traced));
    let body = Body::default();
    let text = Text::default();
    let o = e.options_mut();
    o.set_url(Some(url.as_bytes())).unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.output.verbose = true;
    o.callbacks.write = Some(Handler::write(body.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(text.clone()).unwrap());
    set(o);
    (m.add(Box::new(e), (), &mut NoEvents).unwrap(), body, text)
}

const URL: &str = "ftp://127.0.0.1:PORT/f";

/// The answers to the login and the setup for a file's data: the
/// greeting, `USER`, `PASS`, `PWD`, `EPSV`, `TYPE` and `SIZE`.
const LOGIN_AND_SETUP: [&[u8]; 7] = [
    b"220 hi\r\n",
    b"331 password?\r\n",
    b"230 in\r\n",
    b"257 \"/\" is it\r\n",
    b"229 Entering Extended Passive Mode (|||8022|)\r\n",
    b"200 binary\r\n",
    b"213 5\r\n",
];

/// A server that answers the login and the setup, then `more`.
fn control(more: &[&[u8]]) -> Conversation {
    let mut replies = LOGIN_AND_SETUP.to_vec();
    replies.extend_from_slice(more);
    Conversation::replies(&replies, false).greeting()
}

/// A data connection that sends `data` and closes.
fn data(data: &[u8]) -> Conversation {
    Conversation::replies(&[data], true).greeting()
}

/// What the server was sent, but the QUIT its connection says as it
/// closes.
fn received(talk: &Conversation) -> String {
    let said = String::from_utf8_lossy(&talk.received()).into_owned();
    match said.strip_suffix("QUIT\r\n") {
        Some(before) => before.to_owned(),
        None => said,
    }
}

const COMMANDS: &str = "USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nEPSV\r\nTYPE I\r\n\
                        SIZE f\r\nRETR f\r\n";

/// The data connection goes as the transfer ends, its control connection
/// kept for the next; each is counted as one the transfer made.
#[test]
fn a_file_is_retrieved_over_a_passive_data_connection() {
    let talk = control(&[b"150 here\r\n226 done\r\n"]);
    let file = data(b"hello");
    let (mut m, net) = counting(&[&talk], &[&file]);
    let (id, body, text) = added(&mut m, URL, |_| {});
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()), "{}", text.text());
    assert_eq!(*body.0.lock().unwrap(), b"hello");
    assert_eq!(received(&talk), COMMANDS);
    assert_eq!(net.open(), 1, "the control connection alone");
    // Both connections are the transfer's (`CURLINFO_NUM_CONNECTS`).
    let removed = m.remove(id, &mut NoEvents).unwrap();
    assert_eq!(removed.easy.report().connects(), 2);
}

/// A file the server refuses fails the transfer though DONE, which finds
/// nothing wrong with the connection, goes well: the transfer's failure
/// stands over DONE's result (`multi_done`'s callers keep theirs).
#[test]
fn a_refused_file_fails_though_done_goes_well() {
    let talk = control(&[b"550 no such file\r\n"]);
    let file = Conversation::replies(&[], false);
    let mut m = serving(&[&talk], &[&file]);
    let (id, body, text) = added(&mut m, URL, |_| {});
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(
        result,
        Err(ErrorKind::RemoteFileNotFound),
        "{}",
        text.text()
    );
    assert!(body.0.lock().unwrap().is_empty());
    assert_eq!(received(&talk), COMMANDS);
}

/// The data connection is the control connection's: a multi that goes
/// with a download under way closes both, and a socket dropped unclosed
/// fails the test. The transfer's end closes it first; the control
/// connection's end closes it if the transfer's did not.
#[test]
fn the_data_connection_closes_with_its_control_connection() {
    let talk = control(&[b"150 here\r\n"]);
    let file = Conversation::replies(&[b"hello"], false)
        .greeting()
        .endless(std::time::Duration::from_millis(1));
    let mut m = serving(&[&talk], &[&file]);
    let (_, body, _) = added(&mut m, URL, |_| {});
    while file.endless_reads() == 0 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(body.0.lock().unwrap().starts_with(b"hello"));
    drop(m);
}

/// The answer to a command sent after the transfer (`-Q -NOOP`) is
/// awaited in DONE without stalling the multi's other transfers. C reads
/// it blocking in `ftp_done` (`ftp_sendquote`), so a transfer beside it
/// waits for it (DIVERGENCE.md).
#[test]
fn an_answer_awaited_in_done_stalls_no_other_transfer() {
    let first = control(&[b"150 here\r\n226 done\r\n", b"200 noop\r\n"]).held();
    first.allow(LOGIN_AND_SETUP.len() + 1);
    let second = control(&[b"150 here\r\n226 done\r\n"]);
    let (one, two) = (data(b"hello"), data(b"world"));
    let mut m = serving(&[&first, &second], &[&one, &two]);
    let (waiting, _, text) = added(&mut m, URL, |o| {
        o.line
            .make_mut()
            .unwrap()
            .postquote
            .set([&b"NOOP"[..]])
            .unwrap();
    });
    for _ in 0..40 {
        m.perform(&mut NoEvents).unwrap();
    }
    let said = text.text();
    assert!(said.contains("[PERFORMING] -> [DONE]"), "{said}");
    assert!(received(&first).ends_with("RETR f\r\nNOOP\r\n"), "{said}");
    assert!(m.info_read().is_none(), "the answer is awaited");
    let (beside, body, _) = added(&mut m, URL, |_| {});
    let result = drive_to_completion(&mut m, beside, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(*body.0.lock().unwrap(), b"world");
    assert!(m.info_read().is_none(), "the first still waits");
    first.allow(LOGIN_AND_SETUP.len() + 2);
    let result = drive_to_completion(&mut m, waiting, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()));
}

/// A protected data connection resumes its control connection's latest
/// session, not one the cache holds, as servers that insist the data's
/// session is the control connection's need (`Curl_ssl_get_cf_session`).
#[test]
fn a_protected_data_connection_resumes_its_control_connection_s_session() {
    use crate::tls::fake::{self, FakeTls, WELCOME};
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let control = [
        WELCOME.to_vec(),
        tls(b"220 hi\r\n"),
        tls(b"331 password?\r\n"),
        tls(b"230 in\r\n"),
        tls(b"200 PBSZ\r\n"),
        tls(b"200 PROT\r\n"),
        tls(b"257 \"/\" is it\r\n"),
        tls(b"229 Entering Extended Passive Mode (|||8022|)\r\n"),
        tls(b"200 binary\r\n"),
        tls(b"213 5\r\n"),
        tls(b"150 here\r\n226 done\r\n"),
    ];
    let control: Vec<&[u8]> = control.iter().map(Vec::as_slice).collect();
    let control = Conversation::replies(&control, false).per_send();
    let file = [WELCOME.to_vec(), tls(b"hello")];
    let file: Vec<&[u8]> = file.iter().map(Vec::as_slice).collect();
    let file = Conversation::replies(&file, true).per_send();
    let mut m = serving(&[&control], &[&file]);
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::ticketing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let url = "ftps://127.0.0.1:PORT/f";
    let (id, body, text) = added_with(&mut m, url, Some(libraries), |_| {});
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()), "{}", text.text());
    assert_eq!(*body.0.lock().unwrap(), b"hello");
    let log = backend.log();
    assert_eq!(log.handshakes, 2, "{}", text.text());
    assert_eq!((log.resumed, log.resumed_given), (1, 1), "{}", text.text());
}

/// An FTPS download whose control connection is cleared by `CCC` as
/// `ccc` says, the server answering with `after_ccc` and then, in clear,
/// the rest of the login: the result, what the server was sent as it
/// reads it, and the trace.
fn cleared(ccc: Ccc, after_ccc: &[u8]) -> (Result<(), ErrorKind>, Vec<u8>, String) {
    use crate::tls::fake::{self, FakeTls, WELCOME};
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let control = [
        WELCOME.to_vec(),
        tls(b"220 hi\r\n"),
        tls(b"331 password?\r\n"),
        tls(b"230 in\r\n"),
        tls(b"200 PBSZ\r\n"),
        tls(b"200 PROT\r\n"),
        after_ccc.to_vec(),
        b"257 \"/\" is it\r\n".to_vec(),
        b"229 Entering Extended Passive Mode (|||8022|)\r\n".to_vec(),
        b"200 binary\r\n".to_vec(),
        b"213 5\r\n".to_vec(),
        b"150 here\r\n226 done\r\n".to_vec(),
    ];
    let control: Vec<&[u8]> = control.iter().map(Vec::as_slice).collect();
    let control = Conversation::replies(&control, false).per_send();
    let file = [WELCOME.to_vec(), tls(b"hello")];
    let file: Vec<&[u8]> = file.iter().map(Vec::as_slice).collect();
    let file = Conversation::replies(&file, true).per_send();
    let mut m = serving(&[&control], &[&file]);
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::ticketing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let url = "ftps://127.0.0.1:PORT/f";
    let (id, body, text) = added_with(&mut m, url, Some(libraries), |o| {
        o.line.make_mut().unwrap().ftp.ssl_ccc = ccc;
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    if result.is_ok() {
        assert_eq!(*body.0.lock().unwrap(), b"hello", "{}", text.text());
        // The data connection had no session of the control's to resume:
        // its TLS was gone.
        assert_eq!(backend.log().resumed_given, 0, "{}", text.text());
    }
    drop(m);
    let sent = fake::read_client(&control.received()).unwrap();
    (result, sent, text.text())
}

/// The commands after `CCC`, whatever came before it.
fn after_ccc(sent: &[u8]) -> String {
    let at = sent
        .windows(5)
        .position(|w| w == b"CCC\r\n")
        .expect("CCC sent");
    String::from_utf8_lossy(&sent[at..]).into_owned()
}

/// Passive `CCC` reads the server's close_notify and sends none: the
/// login goes on in clear, and so does the QUIT at the end
/// (`CURLFTPSSL_CCC_PASSIVE`, `Curl_ssl_cfilter_remove`).
#[test]
fn a_passive_ccc_hears_the_server_s_goodbye_and_says_none() {
    use crate::tls::fake::{self, CLOSE};
    let mut ccc = fake::records(b"200 CCC\r\n").unwrap();
    ccc.extend_from_slice(CLOSE);
    let (result, sent, said) = cleared(Ccc::Passive, &ccc);
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(
        after_ccc(&sent),
        "CCC\r\nPWD\r\nEPSV\r\nTYPE I\r\nSIZE f\r\nRETR f\r\nQUIT\r\n",
        "{said}"
    );
}

/// Active `CCC` sends its close_notify too, before the login goes on in
/// clear (`CURLFTPSSL_CCC_ACTIVE`).
#[test]
fn an_active_ccc_says_its_goodbye_too() {
    use crate::tls::fake::{self, CLOSE};
    let mut ccc = fake::records(b"200 CCC\r\n").unwrap();
    ccc.extend_from_slice(CLOSE);
    let (result, sent, said) = cleared(Ccc::Active, &ccc);
    assert_eq!(result, Ok(()), "{said}");
    let close = String::from_utf8_lossy(CLOSE);
    assert_eq!(
        after_ccc(&sent),
        format!("CCC\r\n{close}PWD\r\nEPSV\r\nTYPE I\r\nSIZE f\r\nRETR f\r\nQUIT\r\n"),
        "{said}"
    );
}

/// A server that never says its close_notify fails the transfer once
/// the shutdown's time is out, the TLS taken off unsaid, as C's
/// blocking shutdown does (`vtls_shutdown_blocking`).
#[test]
fn a_ccc_the_server_never_closes_fails_in_the_shutdown_s_time() {
    let ccc = crate::tls::fake::records(b"200 CCC\r\n").unwrap();
    let (result, sent, said) = cleared(Ccc::Passive, &ccc);
    assert_eq!(result, Err(ErrorKind::OperationTimedout), "{said}");
    assert!(said.contains("SSL shutdown timeout"), "{said}");
    assert!(
        said.contains("Failed to clear the command channel (CCC)"),
        "{said}"
    );
    // Nothing more was sent, in TLS or not.
    assert_eq!(after_ccc(&sent), "CCC\r\n", "{said}");
}

/// A server that refuses `CCC` keeps the TLS: the login goes on in it.
#[test]
fn a_ccc_refused_keeps_the_tls() {
    let ccc = crate::tls::fake::records(b"500 no\r\n").unwrap();
    let tls = |plain: &[u8]| crate::tls::fake::records(plain).unwrap();
    let control = [
        crate::tls::fake::WELCOME.to_vec(),
        tls(b"220 hi\r\n"),
        tls(b"331 password?\r\n"),
        tls(b"230 in\r\n"),
        tls(b"200 PBSZ\r\n"),
        tls(b"200 PROT\r\n"),
        ccc,
        tls(b"257 \"/\" is it\r\n"),
    ];
    let control: Vec<&[u8]> = control.iter().map(Vec::as_slice).collect();
    let control = Conversation::replies(&control, false).per_send();
    let mut m = serving(&[&control], &[]);
    let backend: &'static crate::tls::fake::FakeTls =
        Box::leak(Box::new(crate::tls::fake::FakeTls::ticketing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let (id, _, text) = added_with(&mut m, "ftps://127.0.0.1:PORT/f", Some(libraries), |o| {
        o.line.make_mut().unwrap().ftp.ssl_ccc = Ccc::Passive;
    });
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    let said = text.text();
    assert!(!said.contains("shutdown and remove SSL"), "{said}");
    let raw = control.received();
    // EPSV, after PWD, went as a record: the TLS stayed.
    let epsv = crate::tls::fake::records(b"EPSV\r\n").unwrap();
    assert!(raw.windows(epsv.len()).any(|w| w == epsv), "{said}");
    m.remove(id, &mut NoEvents).unwrap();
}

/// A connection logged in as one user serves no transfer as another: it
/// keeps its credentials for the reuse match (`url_set_conn_login`).
#[test]
fn a_connection_logged_in_serves_no_other_user() {
    let first = control(&[b"150 here\r\n226 done\r\n"]);
    let second = control(&[b"150 here\r\n226 done\r\n"]);
    let (one, two) = (data(b"hello"), data(b"world"));
    let mut m = serving(&[&first, &second], &[&one, &two]);
    for user in ["a", "b"] {
        let url = format!("ftp://{user}:p@127.0.0.1:PORT/f");
        let (id, _, text) = added(&mut m, &url, |_| {});
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()), "{}", text.text());
        m.remove(id, &mut NoEvents).unwrap();
    }
    assert!(received(&first).starts_with("USER a\r\n"));
    assert!(received(&second).starts_with("USER b\r\n"));
}

/// FTPS is built only with a TLS library: without one its scheme is
/// unsupported, as C's table has it only with SSL.
#[test]
fn ftps_wants_a_tls_library() {
    let talk = control(&[]);
    let mut m = serving(&[&talk], &[]);
    let (id, _, text) = added(&mut m, "ftps://127.0.0.1:PORT/f", |_| {});
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(
        result,
        Err(ErrorKind::UnsupportedProtocol),
        "{}",
        text.text()
    );
    assert!(talk.received().is_empty());
}

/// While the data comes, the transfer waits on its data connection
/// alone, for it to be readable: the socket a download receives on
/// (`Curl_xfer_pollset` of the second socket).
#[test]
fn a_download_waits_on_its_data_connection() {
    let mut replies = LOGIN_AND_SETUP.to_vec();
    replies[6] = b"502 no SIZE here\r\n";
    replies.push(b"150 here\r\n");
    let talk = Conversation::replies(&replies, false).greeting();
    let file = Conversation::replies(&[b"hello"], false)
        .greeting()
        .endless(std::time::Duration::from_millis(1));
    let (mut m, net) = counting(&[&talk], &[&file]);
    let (_, body, text) = added(&mut m, URL, |_| {});
    for _ in 0..1000 {
        if file.endless_reads() > 0 {
            break;
        }
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(file.endless_reads() > 0, "{}", text.text());
    assert!(body.0.lock().unwrap().starts_with(b"hello"));
    assert_eq!(net.open(), 2, "{}", text.text());
    let mut waits = Vec::new();
    m.sockets(&mut NoEvents, |key, events| waits.push((key, events)))
        .unwrap();
    let data = crate::conn::io::SocketKey::new(1001);
    assert_eq!(
        waits,
        [(data, crate::conn::io::Events::IN)],
        "{}",
        text.text()
    );
}

/// The port of the proxy the transfers go through.
const PROXY_PORT: u16 = 8080;

/// A multi whose proxy at `PROXY_PORT` takes the control connection's
/// talk and then the data connection's.
fn proxied(control: &Conversation, data: &Conversation) -> Multi {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PROXY_PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Net::Accepts)
        .with_conversation(at, control.clone())
        .with_conversation(at, data.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(Counted(Arc::new(Mutex::new(net)))),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
}

/// The control connection's talk through a proxy whose last answer to
/// its setup is `setup`, after `before`: each command answered as it is
/// sent, the greeting after the setup's answer.
fn through(before: &[&[u8]], setup: &[u8]) -> Conversation {
    let greeted = [setup, LOGIN_AND_SETUP[0]].concat();
    let mut replies = before.to_vec();
    replies.push(&greeted);
    replies.extend_from_slice(&LOGIN_AND_SETUP[1..]);
    replies.push(b"150 here\r\n226 done\r\n");
    Conversation::replies(&replies, false).per_send()
}

const TUNNELED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// The data connection goes through the HTTP proxy's tunnel as the
/// control connection does, with a `CONNECT` of its own to the port the
/// server named, on the origin's name (`ftp_control_addr_dup`); its
/// lines name the control connection's proxy, as C's second socket's
/// filters say them.
#[test]
fn the_data_connection_tunnels_through_the_proxy() {
    let talk = through(&[], TUNNELED);
    let file = Conversation::replies(&[&[TUNNELED, b"hello"].concat()], true).per_send();
    let mut m = proxied(&talk, &file);
    let (id, body, text) = added(&mut m, URL, |o| {
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("http://127.0.0.1:{PROXY_PORT}").into_bytes());
        proxy.tunnel = true;
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(*body.0.lock().unwrap(), b"hello");
    let sent = String::from_utf8_lossy(&talk.received()).into_owned();
    assert!(
        sent.starts_with("CONNECT 127.0.0.1:8021 HTTP/1.1\r\n"),
        "{sent}"
    );
    let asked = String::from_utf8_lossy(&file.received()).into_owned();
    assert!(
        asked.starts_with("CONNECT 127.0.0.1:8022 HTTP/1.1\r\n"),
        "{asked}"
    );
    assert!(
        said.contains("Establishing HTTP proxy tunnel to 127.0.0.1:8022\n"),
        "{said}"
    );
    assert!(
        said.contains("Established 2nd connection to 127.0.0.1 (127.0.0.1 port 8080)"),
        "{said}"
    );
    let established = "CONNECT tunnel established, response 200";
    assert_eq!(said.matches(established).count(), 2, "{said}");
    let removed = m.remove(id, &mut NoEvents).unwrap();
    assert_eq!(removed.easy.report().connects(), 2);
}

/// SOCKS5's answers: no authentication, then the connect to `port`
/// granted.
fn granted(port: u16) -> Vec<u8> {
    let [hi, lo] = port.to_be_bytes();
    vec![5, 0, 0, 1, 127, 0, 0, 1, hi, lo]
}

/// The data connection goes through the SOCKS proxy as the control
/// connection does, said as the second's (`socks_proxy_cf_connect`), the
/// proxy's name found in the cache, where the control connection's left
/// it.
#[test]
fn the_data_connection_goes_through_the_socks_proxy() {
    let talk = through(&[&[5, 0]], &granted(PORT));
    let data = [&granted(DATA_PORT)[..], b"hello"].concat();
    let file = Conversation::replies(&[&[5, 0], &data], true).per_send();
    let mut m = proxied(&talk, &file);
    // The names are a share's, as the tool's are.
    let share = crate::share::Share::new().unwrap();
    share.keep(crate::share::Kind::Names).unwrap();
    let mut e = Easy::new();
    e.set_share(Some(share));
    let (id, body, text) = added_easy(&mut m, URL, e, |o| {
        o.proxy.make_mut().unwrap().url =
            Some(format!("socks5://127.0.0.1:{PROXY_PORT}").into_bytes());
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(*body.0.lock().unwrap(), b"hello");
    let asked = file.received();
    assert_eq!(&asked[..3], [5, 1, 0], "{asked:?}");
    assert_eq!(asked[3..6], [5, 1, 0], "{asked:?}");
    assert_eq!(asked[6..], granted(DATA_PORT)[3..], "{asked:?}");
    assert!(
        said.contains("Opened 2nd SOCKS connection from 127.0.0.1 port "),
        "{said}"
    );
    assert!(
        said.contains("Hostname 127.0.0.1 was found in DNS cache"),
        "{said}"
    );
}

const WILDCARD: &str = "ftp://127.0.0.1:PORT/d/*.txt";

/// A directory's listing, in the Unix form: a file the pattern matches, a
/// directory it matches, a file it does not, and another it does.
const LISTING: &[u8] = b"-rw-r--r--    1 u g       5 Jan 17 11:01 a.txt\r\n\
drwxr-xr-x    2 u g    4096 Jan 17 11:01 dir.txt\r\n\
-rw-r--r--    1 u g       5 Jan 17 11:01 b.dat\r\n\
-rw-r--r--    1 u g       3 Jan 17 11:01 c%.txt\r\n";

/// The server of a wildcard download of `LISTING`'s directory: the
/// login, `CWD`, the listing, then `RETR` for each file got.
fn listing_server(files: usize) -> Conversation {
    let mut replies: Vec<&[u8]> = vec![
        b"220 hi\r\n",
        b"331 password?\r\n",
        b"230 in\r\n",
        b"257 \"/\" is it\r\n",
        b"250 there\r\n",
        b"229 Entering Extended Passive Mode (|||8022|)\r\n",
        b"200 ascii\r\n",
        b"150 here\r\n226 done\r\n",
    ];
    for n in 0..files {
        replies.push(b"229 Entering Extended Passive Mode (|||8022|)\r\n");
        if n == 0 {
            replies.push(b"200 binary\r\n");
        }
        replies.push(b"150 here\r\n226 done\r\n");
    }
    Conversation::replies(&replies, false).greeting()
}

/// The matching files are got, one request each, their paths escaped and decoded back:
/// the directory is reached once, the size each line gives is not asked
/// for, a directory is passed over, and a last request finds nothing more
/// to get. The listing goes to its reader, not the write handler.
#[test]
fn a_wildcard_download_gets_each_file_the_listing_matches() {
    let talk = listing_server(2);
    let (list, a, c) = (data(LISTING), data(b"aaaaa"), data(b"ccc"));
    let mut m = serving(&[&talk], &[&list, &a, &c]);
    let (id, body, text) = added(&mut m, WILDCARD, |o| {
        o.line.make_mut().unwrap().ftp.wildcard = true;
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(*body.0.lock().unwrap(), b"aaaaaccc");
    assert_eq!(
        received(&talk),
        "USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\nCWD d\r\nEPSV\r\nTYPE A\r\nLIST\r\n\
         EPSV\r\nTYPE I\r\nRETR a.txt\r\nEPSV\r\nRETR c%.txt\r\n"
    );
    for line in [
        "Wildcard - Parsing started",
        "Wildcard - START of \"a.txt\"",
        "Wildcard - START of \"dir.txt\"",
        "Wildcard - START of \"c%.txt\"",
    ] {
        assert!(said.contains(line), "{line}: {said}");
    }
}

/// The application's handlers: the names matched by its own, each file
/// told of with how many are left, and of its end; one it passes over is
/// not got, and told the end of still.
#[test]
fn a_wildcard_download_tells_the_application_of_each_file() {
    use crate::handler::{
        ChunkBegin, ChunkBeginHandler, ChunkEndHandler, FileInfo, FnMatchHandler, Matched,
    };
    #[derive(Clone, Default)]
    struct Told(Arc<Mutex<Vec<String>>>);
    impl ChunkBeginHandler for Told {
        fn begin(&self, _: &mut TransferCx<'_>, file: &FileInfo<'_>, remains: usize) -> ChunkBegin {
            let name = String::from_utf8_lossy(file.name).into_owned();
            let said = format!("begin {name} {remains} {:?} {:?}", file.size, file.perm);
            self.0.lock().unwrap().push(said);
            if name == "a.txt" {
                ChunkBegin::Skip
            } else {
                ChunkBegin::Get
            }
        }
    }
    impl ChunkEndHandler for Told {
        fn end(&self, _: &mut TransferCx<'_>) {
            self.0.lock().unwrap().push("end".into());
        }
    }
    impl FnMatchHandler for Told {
        fn matches(
            &self,
            _: &mut TransferCx<'_>,
            pattern: &[u8],
            name: &[u8],
        ) -> Result<Matched, curl_alloc::OutOfMemory> {
            assert_eq!(pattern, b"*.txt");
            let said = format!("match {}", String::from_utf8_lossy(name));
            self.0.lock().unwrap().push(said);
            Ok(if name == b"b.dat" {
                Matched::Fail
            } else {
                Matched::Match
            })
        }
    }
    let talk = listing_server(1);
    let (list, c) = (data(LISTING), data(b"ccc"));
    let mut m = serving(&[&talk], &[&list, &c]);
    let told = Told::default();
    let (id, body, text) = added(&mut m, WILDCARD, |o| {
        let ftp = &mut o.line.make_mut().unwrap().ftp;
        ftp.wildcard = true;
        ftp.chunk_begin = Some(Handler::chunk_begin(told.clone()).unwrap());
        ftp.chunk_end = Some(Handler::chunk_end(told.clone()).unwrap());
        ftp.fnmatch = Some(Handler::fnmatch(told.clone()).unwrap());
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(*body.0.lock().unwrap(), b"ccc");
    assert_eq!(
        *told.0.lock().unwrap(),
        [
            "match a.txt",
            "match dir.txt",
            "match b.dat",
            "match c%.txt",
            "begin a.txt 3 Some(5) Some(420)",
            "end",
            "begin dir.txt 2 Some(4096) Some(493)",
            "end",
            "begin c%.txt 1 Some(3) Some(420)",
            "end",
        ]
    );
    assert!(
        said.contains("Wildcard - \"a.txt\" skipped by user"),
        "{said}"
    );
    assert!(received(&talk).ends_with("LIST\r\nEPSV\r\nTYPE I\r\nRETR c%.txt\r\n"));
}

/// A listing that cannot be read fails the download as its next request
/// starts, after it was read whole; one that names nothing the pattern
/// matches fails it as nothing found.
#[test]
fn a_wildcard_download_fails_on_its_listing() {
    for (listing, failure) in [
        (
            &b"?rw-r--r-- 1 u g 5 Jan 17 11:01 a.txt\r\n"[..],
            ErrorKind::FtpBadFileList,
        ),
        (
            b"-rw-r--r-- 1 u g 5 Jan 17 11:01 a.dat\r\n",
            ErrorKind::RemoteFileNotFound,
        ),
    ] {
        let talk = listing_server(0);
        let list = data(listing);
        let mut m = serving(&[&talk], &[&list]);
        let (id, body, text) = added(&mut m, WILDCARD, |o| {
            o.line.make_mut().unwrap().ftp.wildcard = true;
        });
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Err(failure), "{}", text.text());
        assert!(body.0.lock().unwrap().is_empty());
        assert!(received(&talk).ends_with("LIST\r\n"));
    }
}

/// A URL that ends with its directory is only listed, its listing the
/// body, as without a wildcard; a scheme other than FTP's has none.
#[test]
fn a_wildcard_download_without_a_pattern_lists_its_directory() {
    let talk = listing_server(0);
    let list = data(LISTING);
    let mut m = serving(&[&talk], &[&list]);
    let (id, body, text) = added(&mut m, "ftp://127.0.0.1:PORT/d/", |o| {
        o.line.make_mut().unwrap().ftp.wildcard = true;
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(*body.0.lock().unwrap(), LISTING);
    assert!(!said.contains("Wildcard - Parsing started"), "{said}");
}

/// How long after a transfer listens its server connects.
const ACCEPT_AFTER: std::time::Duration = std::time::Duration::from_millis(5);

/// The server's address its active data connections come from.
const ACTIVE_FROM: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    20,
);

/// A multi whose server at `PORT` takes `control` in turn, and connects
/// to each socket the transfers listen on with the next of `data`.
fn serving_active(control: &[&Conversation], data: &[&Conversation]) -> (Multi, Counted) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let mut net = FakeNet::new(clock.clone()).with_peer(at, Net::Accepts);
    for c in control {
        net = net.with_conversation(at, (*c).clone());
    }
    for c in data {
        net = net.with_incoming(at.ip(), ACTIVE_FROM, c, ACCEPT_AFTER);
    }
    let counted = Counted(Arc::new(Mutex::new(net)));
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(counted.clone()),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), counted)
}

/// The answers to the login and an active download's setup: the
/// greeting, `USER`, `PASS`, `PWD`, `EPRT`, `TYPE` and `SIZE`.
const ACTIVE_LOGIN_AND_SETUP: [&[u8]; 7] = [
    b"220 hi\r\n",
    b"331 password?\r\n",
    b"230 in\r\n",
    b"257 \"/\" is it\r\n",
    b"200 EPRT ok\r\n",
    b"200 binary\r\n",
    b"213 5\r\n",
];

/// An active download: offered by `EPRT` at the socket it listens on,
/// the server's connection accepted, said as C says it, and its bytes
/// read; the data connection closes as the transfer ends.
#[test]
fn an_active_download_accepts_the_server_s_connection() {
    let mut replies = ACTIVE_LOGIN_AND_SETUP.to_vec();
    replies.push(b"150 here\r\n226 done\r\n");
    let control = Conversation::replies(&replies, false).greeting();
    let data = Conversation::replies(&[b"hello"], true).greeting();
    let (mut m, counted) = serving_active(&[&control], &[&data]);
    let (id, body, text) = added(&mut m, URL, |o| {
        o.line.make_mut().unwrap().ftp.port = Some(b"-".to_vec());
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(*body.0.lock().unwrap(), b"hello");
    assert!(
        received(&control).contains("EPRT |1|127.0.0.1|40001|\r\nTYPE I\r\n"),
        "{}",
        received(&control)
    );
    assert!(said.contains("Connection accepted from server"), "{said}");
    assert!(
        said.contains(
            "Established 2nd connection to 127.0.0.1 (127.0.0.1 port 20) from 127.0.0.1 port 40001"
        ),
        "{said}"
    );
    // Waiting for it, the transfer polls the listening socket beside the
    // control connection, as C's `ftp_domore_pollset` does.
    assert!(
        said.contains("[DOING_MORE] pollset[fd=1000 IN, fd=1001 IN]"),
        "{said}"
    );
    assert_eq!(counted.open(), 1, "only the control connection is left");
}

/// A request for no body asks the type before the size, as sizes differ
/// between them, takes any 2xx to it, saying so of one not 200, and
/// tells the application the size and that ranges go, as header lines
/// it writes as the body (`ftp_state_type`, `client_write_header`).
#[test]
fn a_request_for_no_body_sets_the_type_and_says_the_size() {
    let control = Conversation::replies(
        &[
            b"220 hi\r\n",
            b"331 password?\r\n",
            b"230 in\r\n",
            b"257 \"/\" is it\r\n",
            b"250 binary\r\n",
            b"213 5\r\n",
            b"350 restarting\r\n",
        ],
        false,
    )
    .greeting();
    let mut m = serving(&[&control], &[]);
    let (id, body, text) = added(&mut m, URL, |o| o.method = crate::options::Method::Head);
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        received(&control).ends_with("PWD\r\nTYPE I\r\nSIZE f\r\nREST 0\r\n"),
        "{}",
        received(&control)
    );
    assert!(
        said.contains("Got a 250 response code instead of the assumed 200"),
        "{said}"
    );
    assert_eq!(
        String::from_utf8_lossy(&body.0.lock().unwrap()),
        "Content-Length: 5\r\nAccept-ranges: bytes\r\n"
    );
}

/// A download on a time condition asks the file's time first and gets
/// the file only if the time meets it, the server's time and the
/// condition's compared as C compares them (`ftp_state_mdtm_resp`).
#[test]
fn a_time_condition_is_met_by_the_server_s_time() {
    // 2020-01-01 00:00:00 UTC.
    const AT: i64 = 1_577_836_800;
    let run = |when, time| {
        let control = Conversation::replies(
            &[
                b"220 hi\r\n",
                b"331 password?\r\n",
                b"230 in\r\n",
                b"257 \"/\" is it\r\n",
                b"213 20200101000000\r\n",
                b"229 Entering Extended Passive Mode (|||8022|)\r\n",
                b"200 binary\r\n",
                b"213 5\r\n",
                b"150 here\r\n226 done\r\n",
            ],
            false,
        )
        .greeting();
        let file = data(b"hello");
        let mut m = serving(&[&control], &[&file]);
        let (id, body, text) = added(&mut m, URL, |o| {
            o.time_condition = Some(crate::options::TimeCondition { when, time });
        });
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        let said = text.text();
        assert_eq!(result, Ok(()), "{said}");
        let unmet = m
            .remove(id, &mut NoEvents)
            .unwrap()
            .easy
            .report()
            .condition_unmet();
        let got = body.0.lock().unwrap().clone();
        // A condition at 0 is not compared: any file meets it.
        assert_eq!(
            said.contains("Skipping time comparison"),
            time == 0,
            "{said}"
        );
        (got, unmet)
    };
    use crate::options::Condition::{ModifiedSince, UnmodifiedSince};
    let got = |unmet| (if unmet { vec![] } else { b"hello".to_vec() }, unmet);
    assert_eq!(run(ModifiedSince, AT - 1), got(false));
    assert_eq!(run(ModifiedSince, AT), got(true));
    assert_eq!(run(UnmodifiedSince, AT), got(false));
    assert_eq!(run(UnmodifiedSince, AT - 1), got(true));
    assert_eq!(run(ModifiedSince, 0), got(false));
}

/// An upload sets its type, then stores the file, its bytes sent over
/// the data connection (`ftp_state_type_resp` for `STOR_TYPE`).
#[test]
fn an_upload_sets_its_type_and_stores_the_file() {
    let control = Conversation::replies(
        &[
            b"220 hi\r\n",
            b"331 password?\r\n",
            b"230 in\r\n",
            b"257 \"/\" is it\r\n",
            b"229 Entering Extended Passive Mode (|||8022|)\r\n",
            b"200 binary\r\n",
            b"150 go on\r\n226 stored\r\n",
        ],
        false,
    )
    .greeting();
    let file = Conversation::replies(&[], false);
    let mut m = serving(&[&control], &[&file]);
    let (id, _, text) = added(&mut m, URL, |o| {
        o.method = crate::options::Method::Upload;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"up".to_vec()).unwrap(),
        );
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()), "{}", text.text());
    assert!(
        received(&control).ends_with("EPSV\r\nTYPE I\r\nSTOR f\r\n"),
        "{}",
        received(&control)
    );
    assert_eq!(file.received(), b"up");
}

/// A command before the transfer and a URL to a directory list it after
/// setting ASCII, the commands first (`ftp_state_type_resp` for
/// `RETR_LIST_TYPE`).
#[test]
fn a_directory_with_a_prequote_lists_after_its_type() {
    let control = Conversation::replies(
        &[
            b"220 hi\r\n",
            b"331 password?\r\n",
            b"230 in\r\n",
            b"257 \"/\" is it\r\n",
            b"250 there\r\n",
            b"229 Entering Extended Passive Mode (|||8022|)\r\n",
            b"200 ascii\r\n",
            b"200 site\r\n",
            b"150 here\r\n226 done\r\n",
        ],
        false,
    )
    .greeting();
    let list = data(LISTING);
    let mut m = serving(&[&control], &[&list]);
    let (id, body, text) = added(&mut m, "ftp://127.0.0.1:PORT/d/", |o| {
        o.line
            .make_mut()
            .unwrap()
            .prequote
            .set([&b"SITE x"[..]])
            .unwrap();
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()), "{}", text.text());
    assert!(
        received(&control).ends_with("EPSV\r\nTYPE A\r\nSITE x\r\nLIST\r\n"),
        "{}",
        received(&control)
    );
    assert_eq!(*body.0.lock().unwrap(), LISTING);
}

/// The control replies of a login and `PWD`, then these.
fn logged_in(then: &[&'static [u8]]) -> Conversation {
    let mut replies: Vec<&'static [u8]> = vec![
        b"220 hi\r\n",
        b"331 password?\r\n",
        b"230 in\r\n",
        b"257 \"/\" is it\r\n",
    ];
    replies.extend_from_slice(then);
    Conversation::replies(&replies, false).greeting()
}

/// A download resumed asks the size, then `REST` from where it resumes,
/// and fails if the server will not restart there
/// (`ftp_state_rest_resp` for `RETR_REST`).
#[test]
fn a_resumed_download_restarts_where_it_resumes() {
    let run = |rest: &'static [u8]| {
        let control = logged_in(&[
            b"229 Entering Extended Passive Mode (|||8022|)\r\n",
            b"200 binary\r\n",
            b"213 5\r\n",
            rest,
            b"150 here\r\n226 done\r\n",
        ]);
        let file = data(b"llo");
        let mut m = serving(&[&control], &[&file]);
        let (id, body, _) = added(&mut m, URL, |o| {
            o.resume = Some(crate::options::Resume::At(
                std::num::NonZeroU64::new(2).unwrap(),
            ));
        });
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        let got = body.0.lock().unwrap().clone();
        (result, received(&control), got)
    };
    let (result, sent, got) = run(b"350 restarting\r\n");
    assert_eq!(result, Ok(()), "{sent}");
    assert!(sent.ends_with("SIZE f\r\nREST 2\r\nRETR f\r\n"), "{sent}");
    assert_eq!(got, b"llo");
    let (result, sent, got) = run(b"502 no\r\n");
    assert_eq!(result, Err(ErrorKind::FtpCouldntUseRest), "{sent}");
    assert!(sent.ends_with("SIZE f\r\nREST 2\r\n"), "{sent}");
    assert_eq!(got, b"");
}

/// A download of a file the server has not got fails at `SIZE`'s 550
/// (`ftp_state_size_resp`).
#[test]
fn a_size_refused_fails_a_resumed_download() {
    let control = logged_in(&[
        b"229 Entering Extended Passive Mode (|||8022|)\r\n",
        b"200 binary\r\n",
        b"550 no such file\r\n",
    ]);
    let file = data(b"");
    let mut m = serving(&[&control], &[&file]);
    let (id, _, _) = added(&mut m, URL, |o| {
        o.resume = Some(crate::options::Resume::At(
            std::num::NonZeroU64::new(2).unwrap(),
        ));
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Err(ErrorKind::RemoteFileNotFound));
}

/// An upload resumed at the end asks the stored size: it appends what
/// is past it, or stores the whole body if the server has no size, a
/// 550 to `SIZE` only telling it which to do (`ftp_state_size_resp` for
/// `STOR_SIZE`).
#[test]
fn an_upload_resumed_at_the_end_appends_past_the_stored_size() {
    let run = |size: &'static [u8]| {
        let control = logged_in(&[
            b"229 Entering Extended Passive Mode (|||8022|)\r\n",
            b"200 binary\r\n",
            size,
            b"150 go on\r\n226 stored\r\n",
        ]);
        let file = Conversation::replies(&[], false);
        let mut m = serving(&[&control], &[&file]);
        let (id, _, text) = added(&mut m, URL, |o| {
            o.method = crate::options::Method::Upload;
            o.resume = Some(crate::options::Resume::AtEnd);
            o.upload = crate::options::UploadSource::Bytes(
                curl_alloc::TryArc::try_new(b"upload".to_vec()).unwrap(),
            );
        });
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()), "{}", text.text());
        (received(&control), file.received())
    };
    let (sent, stored) = run(b"213 2\r\n");
    assert!(sent.ends_with("SIZE f\r\nAPPE f\r\n"), "{sent}");
    assert_eq!(stored, b"load");
    let (sent, stored) = run(b"550 none\r\n");
    assert!(sent.ends_with("SIZE f\r\nSTOR f\r\n"), "{sent}");
    assert_eq!(stored, b"upload");
}

/// `PRET` names the listing's command, `NLST` only for names alone
/// (`ftp_state_prepare_transfer`).
#[test]
fn pret_names_the_listing_s_command() {
    let run = |list_only: bool| {
        let control = logged_in(&[
            b"250 there\r\n",
            b"200 pret\r\n",
            b"229 Entering Extended Passive Mode (|||8022|)\r\n",
            b"200 ascii\r\n",
            b"150 here\r\n226 done\r\n",
        ]);
        let list = data(LISTING);
        let mut m = serving(&[&control], &[&list]);
        let (id, _, text) = added(&mut m, "ftp://127.0.0.1:PORT/d/", |o| {
            let line = o.line.make_mut().unwrap();
            line.ftp.use_pret = true;
            line.list_only = list_only;
        });
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()), "{}", text.text());
        received(&control)
    };
    let sent = run(false);
    assert!(sent.contains("CWD d\r\nPRET LIST\r\nEPSV\r\n"), "{sent}");
    let sent = run(true);
    assert!(sent.contains("CWD d\r\nPRET NLST\r\nEPSV\r\n"), "{sent}");
}
