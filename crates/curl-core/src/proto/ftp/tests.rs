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
use crate::options::Options;
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
