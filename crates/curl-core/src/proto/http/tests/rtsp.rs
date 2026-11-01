//! RTSP's requests as C sends them, and its responses as C reads them:
//! the CSeq and session checked, the RTP the server interleaves taken
//! out for the interleave handler.

use super::*;
use crate::options::{RtspRequest, RtspSession};

/// Reads the transfer's sequence numbers from inside its write handler,
/// and sets the server's.
#[derive(Clone, Default)]
struct Numbers(Arc<Mutex<Vec<(u32, u32)>>>);

impl WriteHandler for Numbers {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
        let me = cx.me();
        let r = cx.rtsp(me).expect("in its multi");
        self.0
            .lock()
            .unwrap()
            .push((r.cseq_recv(), r.next_server_cseq()));
        cx.rtsp_mut(me).unwrap().unwrap().set_next_server_cseq(40);
        Write::Took(body.len())
    }
}

/// The RTP messages the interleave handler got, each whole.
#[derive(Clone, Default)]
struct Rtp(Arc<Mutex<Vec<Vec<u8>>>>);

impl WriteHandler for Rtp {
    fn write(&self, _: &mut TransferCx<'_>, message: &[u8]) -> Write {
        self.0.lock().unwrap().push(message.to_vec());
        Write::Accepted
    }
}

impl Rtp {
    fn got(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
}

/// A multi whose server at `PORT` replies `replies` in turn, `giving`
/// bytes a read at most, closing after them if `close`.
fn rtsp_server(replies: &[&[u8]], close: bool, giving: usize) -> (Multi, Conversation) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::replies(replies, close)
        .giving(std::num::NonZeroUsize::new(giving).expect("a read takes something"));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), talk)
}

/// A verbose RTSP request by `e` of `/s` on `m`, whose server is `talk`,
/// with the options `set` makes, its RTP to `rtp`.
fn request(
    m: &mut Multi,
    e: Easy,
    talk: Conversation,
    rtp: &Rtp,
    set: impl FnOnce(&mut Options),
) -> Ran {
    let interleave = rtp.clone();
    get_with(m, e, "/s", talk, |o| {
        let url = format!("rtsp://127.0.0.1:{PORT}/s");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.small.make_mut().unwrap().interleave = Some(Handler::write(interleave).unwrap());
        set(o);
    })
}

/// A verbose RTSP request by `e` from a server replying `replies`, as
/// `rtsp_server` makes it: what it came to, and the RTP delivered.
fn rtsp_with(
    e: Easy,
    replies: &[&[u8]],
    close: bool,
    giving: usize,
    set: impl FnOnce(&mut Options),
) -> (Ran, Rtp) {
    let (mut m, talk) = rtsp_server(replies, close, giving);
    let rtp = Rtp::default();
    let ran = request(&mut m, e, talk, &rtp, set);
    (ran, rtp)
}

fn rtsp(replies: &[&[u8]], set: impl FnOnce(&mut Options)) -> (Ran, Rtp) {
    rtsp_with(Easy::new(), replies, false, usize::MAX, set)
}

/// A response naming its channels, with a body that messages on them
/// come inside and after, as test 571's server sends one.
const INTERLEAVED: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\
Transport: RTP/AVP/TCP;interleaved=0-1\r\nContent-Length: 5\r\n\r\n\
$\x00\x00\x03abche$\x01\x00\x02XYllo$\x00\x00\x00$\x01\x00\x01Z";

/// An OPTIONS goes as C sends it: the request line naming the server,
/// its CSeq, the user agent; the next request on the handle is the next
/// CSeq.
#[test]
fn an_options_request_is_sent_as_c_sends_it() {
    let ok: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n";
    let (ran, _) = rtsp(&[ok], |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8_lossy(&ran.request),
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: curl/test\r\n\r\n"
    );
    assert_eq!(ran.easy.rtsp().next_client_cseq(), 2);
    assert_eq!(ran.easy.rtsp().cseq_recv(), 1);
}

/// Collects the multi's own trace.
#[derive(Clone, Default)]
struct Internal(Arc<Mutex<Vec<u8>>>);

impl crate::handler::TextSink for Internal {
    fn write(&self, text: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(text);
    }
}

/// RTSP has no goodbye of its own (C's `disconnect`), which C's debug
/// build says as the connection shuts down; the connection's shutdown
/// is said all the same.
#[test]
fn an_rtsp_connection_says_no_goodbye() {
    let ok: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n";
    let (mut m, talk) = rtsp_server(&[ok], false, usize::MAX);
    let internal = Internal::default();
    let components = crate::components::Components::new().unwrap();
    components.set(
        crate::components::Component::Multi,
        crate::components::Level::Info,
    );
    m.trace_internally_to(components, Handler::text(internal.clone()).unwrap());
    let ran = request(&mut m, Easy::new(), talk, &Rtp::default(), |_| {});
    assert_eq!(ran.result, Ok(()));
    drop(m);
    let said = String::from_utf8_lossy(&internal.0.lock().unwrap()).into_owned();
    assert!(!said.contains("shutdown protocol handler"), "{said}");
    if cfg!(feature = "debug-hooks") {
        assert!(said.contains("connection #0"), "{said}");
    }
}

/// The sequence numbers the application sets are the ones a request
/// goes with and expects (`CURLOPT_RTSP_CLIENT_CSEQ`,
/// `CURLOPT_RTSP_SERVER_CSEQ`), and read back as the request left them
/// (`CURLINFO_RTSP_*`).
#[test]
fn the_sequence_numbers_set_are_used_and_read_back() {
    let mut e = Easy::new();
    let state = e.rtsp_mut().unwrap();
    state.set_next_client_cseq(5);
    state.set_next_server_cseq(7);
    let ok: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 5\r\n\r\n";
    let (ran, _) = rtsp_with(e, &[ok], false, usize::MAX, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(
        String::from_utf8_lossy(&ran.request).contains("\r\nCSeq: 5\r\n"),
        "{}",
        String::from_utf8_lossy(&ran.request)
    );
    let after = ran.easy.rtsp();
    assert_eq!(after.next_client_cseq(), 6);
    assert_eq!(after.next_server_cseq(), 7);
    assert_eq!(after.cseq_recv(), 5);
}

/// An RTSP connection is reused only by a request with its login, as
/// C matches it (`url_match_auth`); HTTP's would be by any.
#[test]
fn an_rtsp_connection_is_reused_only_with_its_login() {
    let reused = |second: &[u8]| {
        let one: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n";
        let two: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n";
        let (mut m, talk) = rtsp_server(&[one, two], false, usize::MAX);
        let rtp = Rtp::default();
        let first = request(&mut m, Easy::new(), talk.clone(), &rtp, |o| {
            *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        });
        assert_eq!(first.result, Ok(()));
        let then = request(&mut m, first.easy, talk, &rtp, |o| {
            *o.login.make_mut().unwrap() = crate::options::Login::from_pair(second).unwrap();
        });
        then.seen
            .text()
            .iter()
            .any(|l| l.starts_with("Reusing existing rtsp: connection"))
    };
    assert!(reused(b"u:p"));
    assert!(!reused(b"v:p"));
}

/// A write handler reads the sequence numbers as the response left them,
/// and what it sets is the handle's.
#[test]
fn a_handler_reads_and_sets_the_sequence_numbers() {
    let ok: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 2\r\n\r\nhi";
    let numbers = Numbers::default();
    let seen = numbers.clone();
    let (ran, _) = rtsp(&[ok], |o| {
        o.small.make_mut().unwrap().rtsp_request = RtspRequest::Describe;
        o.callbacks.write = Some(Handler::write(seen).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(numbers.0.lock().unwrap()[0], (1, 1));
    assert_eq!(ran.easy.rtsp().next_server_cseq(), 40);
}

/// A request over a reused connection that died, with nothing back, is
/// made again on a fresh one only if the death did not end it (a reset,
/// not a close) and it awaits a body, as C's
/// `Curl_retry_request` has it for a protocol outside HTTP's; DONE's
/// complaint of the CSeq never answered is said and let go. Each as the
/// C build does it.
#[test]
fn only_a_request_cut_short_awaiting_a_body_is_made_again() {
    let retried = "Connection died, retrying a fresh connect (retry count: 1)\n";
    let unmatched = "The CSeq of this request 2 did not match the response 0\n";
    for (reset, kind, want) in [
        (false, RtspRequest::Describe, Err(ErrorKind::GotNothing)),
        (false, RtspRequest::Options, Err(ErrorKind::GotNothing)),
        (true, RtspRequest::Describe, Ok(())),
        // A heartbeat: nothing sent, no body awaited.
        (true, RtspRequest::GetParameter, Err(ErrorKind::RecvError)),
        (true, RtspRequest::Options, Err(ErrorKind::RecvError)),
    ] {
        let first = Conversation::new(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n", false);
        let first = if reset {
            first.resetting_unanswered()
        } else {
            first.hanging_up_unanswered()
        };
        // The request that died went as CSeq 2.
        let fresh = Conversation::new(
            b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nContent-Length: 0\r\n\r\n",
            false,
        );
        let mut m = serving(Peer::Accepts, &[&first, &fresh]);
        let rtp = Rtp::default();
        let one = request(&mut m, Easy::new(), first.clone(), &rtp, |_| {});
        assert_eq!(one.result, Ok(()), "{kind:?}");
        let two = request(&mut m, one.easy, fresh.clone(), &rtp, |o| {
            o.small.make_mut().unwrap().rtsp_request = kind;
        });
        let said = two.seen.text();
        let case = format!("{kind:?}, reset {reset}: {said:#?}");
        assert_eq!(two.result, want, "{case}");
        let at = said.iter().position(|l| l == retried);
        assert_eq!(at.is_some(), want.is_ok(), "{case}");
        if let Some(at) = at {
            assert_eq!(said[at + 1], unmatched, "{case}");
            let sent = String::from_utf8_lossy(&fresh.received()).into_owned();
            assert!(sent.contains("\r\nCSeq: 3\r\n"), "{sent}");
        }
    }
}

/// `RTSP/` inside a body still due, between interleaved messages, is
/// the body's, not the next response's start.
#[test]
fn rtsp_inside_a_body_is_the_body_s() {
    let reply: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\
Transport: RTP/AVP/TCP;interleaved=0-1\r\nContent-Length: 5\r\n\r\n\
$\x00\x00\x01ZRTSP/";
    let (ran, rtp) = rtsp(&[reply], |o| {
        o.small.make_mut().unwrap().rtsp_request = RtspRequest::Describe;
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(rtp.got(), [&b"$\x00\x00\x01Z"[..]]);
    assert_eq!(ran.seen.body(), b"RTSP/");
}

/// Messages on the channels the response's own `Transport:` named are
/// taken out of its body and after it, whether the head and they come
/// in one read or a byte at a time. Those a read past the body's end
/// did not bring stay on the connection, and the next request on it
/// takes them before its response, as C reads no further once the body
/// is whole.
#[test]
fn messages_after_the_head_that_named_their_channels_are_taken_out() {
    let all = [
        &b"$\x00\x00\x03abc"[..],
        b"$\x01\x00\x02XY",
        b"$\x00\x00\x00",
        b"$\x01\x00\x01Z",
    ];
    let (ran, rtp) = rtsp(&[INTERLEAVED], |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"hello");
    assert_eq!(rtp.got(), all, "one read");
    let next: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n";
    for giving in [1, 2, 3, 7, 64] {
        let (mut m, talk) = rtsp_server(&[INTERLEAVED, next], false, giving);
        let rtp = Rtp::default();
        let first = request(&mut m, Easy::new(), talk.clone(), &rtp, |_| {});
        assert_eq!(first.result, Ok(()), "giving {giving}");
        assert_eq!(first.seen.body(), b"hello", "giving {giving}");
        assert_eq!(rtp.got()[..2], all[..2], "giving {giving}");
        let second = request(&mut m, first.easy, talk, &rtp, |_| {});
        assert_eq!(second.result, Ok(()), "giving {giving}");
        assert_eq!(rtp.got(), all, "giving {giving}");
    }
}

/// Without an interleave handler, RTP goes to the write handler.
#[test]
fn without_an_interleave_handler_rtp_is_written() {
    let (ran, rtp) = rtsp(&[INTERLEAVED], |o| {
        o.small.make_mut().unwrap().interleave = None;
    });
    assert_eq!(ran.result, Ok(()));
    assert!(rtp.got().is_empty());
    assert_eq!(
        ran.seen.body(),
        b"$\x00\x00\x03abche$\x01\x00\x02XYllo$\x00\x00\x00$\x01\x00\x01Z"
    );
}

/// A response numbered other than its request fails it, once it is
/// read (`rtsp_done`).
#[test]
fn a_cseq_other_than_the_request_s_fails_it() {
    let (ran, _) = rtsp(&[b"RTSP/1.0 200 OK\r\nCSeq: 7\r\n\r\n"], |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RtspCseqError));
    assert!(
        ran.seen
            .text()
            .contains(&"The CSeq of this request 1 did not match the response 7\n".to_string()),
        "{:?}",
        ran.seen.text()
    );
    let (ran, _) = rtsp(&[b"RTSP/1.0 200 OK\r\nCSeq: x\r\n\r\n"], |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RtspCseqError));
    assert!(
        ran.seen
            .text()
            .contains(&"Unable to read the CSeq header: [CSeq: x\r\n]\n".to_string()),
        "{:?}",
        ran.seen.text()
    );
}

/// The session a response names is the handle's from then on, sent with
/// each request after; one naming another fails.
#[test]
fn a_session_named_is_kept_and_checked() {
    let first: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: abc;timeout=9\r\n\r\n";
    let (ran, _) = rtsp(&[first], |_| {});
    assert_eq!(ran.result, Ok(()));
    let session = ran
        .easy
        .options()
        .small
        .rtsp_session
        .as_ref()
        .map(RtspSession::id);
    assert_eq!(session, Some(&b"abc"[..]));
    // The same id again is the same session.
    let same: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: abc\r\n\r\n";
    let (ran, _) = rtsp_with(ran.easy, &[same], false, usize::MAX, |_| {});
    assert_eq!(ran.result, Ok(()));
    let other: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: xyz\r\n\r\n";
    let (ran, _) = rtsp_with(ran.easy, &[other], false, usize::MAX, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RtspSessionError));
    assert!(
        String::from_utf8_lossy(&ran.request).contains("CSeq: 3\r\nSession: abc\r\n"),
        "{:?}",
        String::from_utf8_lossy(&ran.request)
    );
    assert!(
        ran.seen
            .text()
            .contains(&"Got RTSP Session ID Line [xyz\r\n], but wanted ID [abc]\n".to_string()),
        "{:?}",
        ran.seen.text()
    );
}

/// A session a server named goes back only to its origin, unless
/// credentials may go anywhere; one the application set goes to any.
#[test]
fn a_session_goes_only_to_the_origin_that_named_it() {
    let ok: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n";
    let elsewhere = || {
        Some(crate::conn::Peer::new(
            crate::conn::Scheme::of("rtsp"),
            b"example.com".to_vec(),
            PORT,
            None,
        ))
    };
    for (origin, unrestricted, sent) in [
        (elsewhere(), false, false),
        (elsewhere(), true, true),
        (None, false, true),
    ] {
        let (ran, _) = rtsp(&[ok], |o| {
            o.http.unrestricted_auth = unrestricted;
            o.small.make_mut().unwrap().rtsp_session = Some(RtspSession {
                id: b"abc".to_vec(),
                origin,
            });
        });
        assert_eq!(ran.result, Ok(()));
        let request = String::from_utf8_lossy(&ran.request).into_owned();
        assert_eq!(request.contains("Session: abc\r\n"), sent, "{request}");
    }
}

/// The application's `Transport:` goes once, with its other headers. C
/// sends it twice, the first time without its line end, run into the
/// line after it (`rtsp_setup_request` keeps `Curl_checkheaders`'s line
/// as its own header): a clear bug, which this does not repeat.
#[test]
fn the_application_s_transport_goes_once() {
    let ok: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n";
    let (ran, _) = rtsp(&[ok], |o| {
        o.small.make_mut().unwrap().rtsp_request = RtspRequest::Setup;
        o.http.headers = UserHeaders::new([&b"Transport: foo"[..], b"Host: x"]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8_lossy(&ran.request),
        "SETUP * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: curl/test\r\nTransport: foo\r\nHost: x\r\n\r\n"
    );
}

/// A SETUP needs a transport, the option's or the application's; a
/// CSeq or a session among the application's headers is refused.
#[test]
fn what_a_request_cannot_go_without_or_with_is_refused() {
    let (ran, _) = rtsp(&[], |o| {
        o.small.make_mut().unwrap().rtsp_request = RtspRequest::Setup;
    });
    assert_eq!(ran.result, Err(ErrorKind::BadFunctionArgument));
    for (header, kind) in [
        (&b"CSeq: 3"[..], ErrorKind::RtspCseqError),
        (b"Session: s", ErrorKind::BadFunctionArgument),
    ] {
        let (ran, _) = rtsp(&[], |o| {
            o.http.headers = UserHeaders::new([header]).unwrap();
        });
        assert_eq!(ran.result, Err(kind), "{header:?}");
        assert!(ran.request.is_empty());
    }
}

/// A response with no `Content-Length:` has no body: what follows its
/// head that is no RTP is too much (RFC 2326, section 4.4).
#[test]
fn a_response_without_a_length_has_no_body() {
    // An OPTIONS has none anyway; a DESCRIBE has one only if sized.
    for request in [RtspRequest::Options, RtspRequest::Describe] {
        let (ran, _) = rtsp(&[b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\nxyz"], |o| {
            o.small.make_mut().unwrap().rtsp_request = request;
        });
        assert_eq!(ran.result, Ok(()), "{request:?}");
        assert_eq!(ran.seen.body(), b"", "{request:?}");
    }
}

/// A body cut short by the connection's end is a partial file; a head
/// cut short is not, its body never begun.
#[test]
fn a_body_cut_short_is_partial() {
    let short: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 10\r\n\r\nabc";
    let (ran, _) = rtsp_with(Easy::new(), &[short], true, usize::MAX, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::PartialFile));
    assert!(
        ran.seen
            .text()
            .contains(&"transfer closed with 7 bytes remaining to read\n".to_string())
    );
}

/// A RECEIVE sends nothing and reads what one read brings, RTP on the
/// handle's channels, its CSeq unchecked.
#[test]
fn a_receive_reads_rtp_alone() {
    let mut e = Easy::new();
    e.rtsp_mut().unwrap().add_channel(2);
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::new(b"$\x02\x00\x02hi$\x02\x00\x01!", false).greeting();
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let rtp = Rtp::default();
    let interleave = rtp.clone();
    let ran = get_with(&mut m, e, "/s", talk, |o| {
        let url = format!("rtsp://127.0.0.1:{PORT}/s");
        o.set_url(Some(url.as_bytes())).unwrap();
        let small = o.small.make_mut().unwrap();
        small.interleave = Some(Handler::write(interleave).unwrap());
        small.rtsp_request = RtspRequest::Receive;
    });
    assert_eq!(ran.result, Ok(()));
    assert!(ran.request.is_empty(), "nothing sent");
    assert_eq!(rtp.got(), [&b"$\x02\x00\x02hi"[..], b"$\x02\x00\x01!"]);
    // Said only of a receive that read no RTP (`rtp_channel` -1).
    assert!(
        !ran.seen
            .text()
            .iter()
            .any(|l| l.starts_with("Got an RTP Receive")),
        "{:?}",
        ran.seen.text()
    );
}

/// The options of each kind of request, and the request C's build sends
/// with them to a server answering each with its CSeq (requests checked
/// against the C build with the same options, no user agent).
type Setup = fn(&mut Options);

fn ok_for(cseq: u32) -> Vec<u8> {
    format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: 0\r\n\r\n").into_bytes()
}

/// `set`'s request, with no user agent: what it came to and what went.
fn sent(replies: &[&[u8]], set: impl FnOnce(&mut Options)) -> (Result<(), ErrorKind>, String) {
    let (ran, _) = rtsp(replies, |o| {
        o.http.user_agent = None;
        set(o);
    });
    (
        ran.result,
        String::from_utf8_lossy(&ran.request).into_owned(),
    )
}

fn kind(o: &mut Options, kind: RtspRequest) {
    o.small.make_mut().unwrap().rtsp_request = kind;
}

fn bytes(body: &[u8]) -> UploadSource {
    UploadSource::Bytes(curl_alloc::TryArc::try_new(body.to_vec()).unwrap())
}

fn read_sized(body: &[u8]) -> UploadSource {
    let UploadSource::Read { handler, .. } = pieces(&[body]) else {
        unreachable!("pieces are read by a handler");
    };
    UploadSource::Read {
        handler,
        rewind: None,
        size: Some(body.len() as u64),
    }
}

fn headers(lines: &[&[u8]]) -> UserHeaders {
    UserHeaders::new(lines.iter().copied()).unwrap()
}

/// A body goes with an ANNOUNCE, a GET_PARAMETER or a SET_PARAMETER, the
/// fields posted or an upload, typed by the kind unless the application
/// types it; its line ends as they are; with no other kind, and not when
/// empty (`rtsp_setup_body`).
#[test]
fn requests_with_bodies_are_sent_as_c_sends_them() {
    let ok = ok_for(1);
    let cases: [(&str, Setup, &str); 6] = [
        (
            "announce-read",
            |o| {
                kind(o, RtspRequest::Announce);
                o.small.make_mut().unwrap().rtsp_stream_uri = Some(b"rtsp://h/x".to_vec());
                o.method = Method::Upload;
                o.upload = read_sized(b"v=0\n");
            },
            "ANNOUNCE rtsp://h/x RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 4\r\n\
             Content-Type: application/sdp\r\n\r\nv=0\n",
        ),
        (
            "announce-fields",
            |o| {
                kind(o, RtspRequest::Announce);
                o.upload = bytes(b"a=b&c=d");
                o.http.headers = headers(&[b"Content-Type: posty goodness"]);
            },
            "ANNOUNCE * RTSP/1.0\r\nCSeq: 1\r\nContent-Type: posty goodness\r\n\
             Content-Length: 7\r\n\r\na=b&c=d",
        ),
        (
            "getparam-fields",
            |o| {
                kind(o, RtspRequest::GetParameter);
                o.upload = bytes(b"scale\nspeed\n");
            },
            "GET_PARAMETER * RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 12\r\n\
             Content-Type: text/parameters\r\n\r\nscale\nspeed\n",
        ),
        (
            "setparam-read-noupload",
            |o| {
                kind(o, RtspRequest::SetParameter);
                o.upload = read_sized(b"v=0\n");
            },
            "SET_PARAMETER * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        ),
        (
            "options-fields",
            |o| o.upload = bytes(b"x"),
            "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        ),
        (
            "getparam-empty",
            |o| {
                kind(o, RtspRequest::GetParameter);
                o.upload = bytes(b"");
            },
            "GET_PARAMETER * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        ),
    ];
    for (name, set, want) in cases {
        assert_eq!(sent(&[&ok], set), (Ok(()), want.to_string()), "{name}");
    }
}

/// A DESCRIBE asks for SDP and the codings, and only it and a SETUP go
/// with the time condition; a PLAY, PAUSE or RECORD with the range; each
/// unless the application sends its own (`rtsp_do`).
#[test]
fn each_kind_s_own_headers_are_sent_as_c_sends_them() {
    fn asks(o: &mut Options) {
        o.http.accept_encoding = Some(crate::coding::AcceptEncoding::Given(b"zz".to_vec()));
        o.time_condition = Some(crate::options::TimeCondition {
            when: crate::options::Condition::ModifiedSince,
            time: 1_000_000_000,
        });
    }
    fn ranged(o: &mut Options) {
        o.small.make_mut().unwrap().rtsp_session = Some(RtspSession {
            id: b"s1".to_vec(),
            origin: None,
        });
        o.range = Some(b"npt=0-".to_vec());
    }
    let ok = ok_for(1);
    let cases: [(&str, Setup, &str); 6] = [
        (
            "describe-all",
            |o| {
                kind(o, RtspRequest::Describe);
                asks(o);
            },
            "DESCRIBE * RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\
             Accept-Encoding: zz\r\nIf-Modified-Since: Sun, 09 Sep 2001 01:46:40 GMT\r\n\r\n",
        ),
        (
            "options-cond",
            asks,
            "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        ),
        (
            "describe-custom",
            |o| {
                kind(o, RtspRequest::Describe);
                asks(o);
                o.http.headers = headers(&[
                    b"If-Modified-Since: mine",
                    b"Accept: a/b",
                    b"Accept-Encoding: e",
                ]);
            },
            "DESCRIBE * RTSP/1.0\r\nCSeq: 1\r\nIf-Modified-Since: mine\r\nAccept: a/b\r\n\
             Accept-Encoding: e\r\n\r\n",
        ),
        (
            "play-range",
            |o| {
                kind(o, RtspRequest::Play);
                ranged(o);
            },
            "PLAY * RTSP/1.0\r\nCSeq: 1\r\nSession: s1\r\nRange: npt=0-\r\n\r\n",
        ),
        (
            "play-custom-range",
            |o| {
                kind(o, RtspRequest::Play);
                ranged(o);
                o.http.headers = headers(&[b"Range: x"]);
            },
            "PLAY * RTSP/1.0\r\nCSeq: 1\r\nSession: s1\r\nRange: x\r\n\r\n",
        ),
        (
            "options-range",
            ranged,
            "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nSession: s1\r\n\r\n",
        ),
    ];
    for (name, set, want) in cases {
        assert_eq!(sent(&[&ok], set), (Ok(()), want.to_string()), "{name}");
    }
}

/// The login goes as HTTP's does; a Digest answer goes alongside the
/// application's own `Authorization:`, which a Basic one gives way to.
/// The application's headers go but for its `Connection:` and those it
/// takes out.
#[test]
fn logins_and_the_application_s_headers_are_sent_as_c_sends_them() {
    fn login(o: &mut Options) {
        let login = o.login.make_mut().unwrap();
        login.user = Some(b"u".to_vec());
        login.password = Some(b"p".to_vec());
    }
    let ok = ok_for(1);
    assert_eq!(
        sent(&[&ok], login),
        (
            Ok(()),
            "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic dTpw\r\n\r\n".to_string()
        )
    );
    let challenge: &[u8] = b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\
WWW-Authenticate: Digest realm=\"r\", nonce=\"n\"\r\nContent-Length: 0\r\n\r\n";
    let (result, request) = sent(&[challenge, &ok_for(2)], |o| {
        login(o);
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
        o.http.headers = headers(&[b"Authorization: mine"]);
    });
    assert_eq!(result, Ok(()));
    assert_eq!(
        request,
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nAuthorization: mine\r\n\r\n\
         OPTIONS * RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Digest username=\"u\", realm=\"r\", \
         nonce=\"n\", uri=\"*\", response=\"5287c9fe806cea9c4ec0cb9d733228f9\"\r\n\
         Authorization: mine\r\n\r\n"
    );
    let (result, request) = sent(&[&ok], |o| {
        o.http.headers = headers(&[
            b"Connection: x",
            b"X-Gone:",
            b"X-Blank;",
            b"Content-Length: 0",
        ]);
    });
    assert_eq!(result, Ok(()));
    assert_eq!(
        request,
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nX-Blank:\r\nContent-Length: 0\r\n\r\n"
    );
}

/// Asked for Negotiate, a request sends its first token at once, as
/// HTTP's does (`Curl_http_output_auth`).
#[test]
fn a_negotiate_token_goes_with_the_request() {
    let gss = crate::gss::testing::Scripted::leaked();
    gss.then_token(b"first");
    let libraries = crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
        gss: Some(gss),
        ..crate::libraries::Libraries::NONE
    })
    .unwrap();
    let mut e = Easy::new();
    e.set_libraries(libraries);
    e.options_mut().http.auth = crate::options::HttpAuth(AuthMethods::NEGOTIATE);
    let ok = ok_for(1);
    let (ran, _) = rtsp_with(e, &[&ok], false, usize::MAX, |o| o.http.user_agent = None);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8_lossy(&ran.request),
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Negotiate Zmlyc3Q=\r\n\r\n"
    );
}

/// A request head may be 64 KiB but the byte C's buffer keeps for its
/// end; one larger is not sent (`DYN_RTSP_REQ_HEADER`).
#[test]
fn a_request_head_is_at_most_c_s_buffer() {
    let ok = ok_for(1);
    for (n, result) in [(65499, Ok(())), (65500, Err(ErrorKind::TooLarge))] {
        let line = [&b"X: "[..], &vec![b'a'; n]].concat();
        let (got, request) = sent(&[&ok], |o| o.http.headers = headers(&[&line]));
        assert_eq!(got, result, "{n}");
        assert_eq!(request.len(), if result.is_ok() { 65535 } else { 0 }, "{n}");
    }
}

/// The filter says what C's debug build says of each read and each
/// message, for test 571's response and for one whose head comes after
/// a message, junk and a `$` on no channel of the handle's (checked
/// against the C build's trace of the same bytes); the body goes as the
/// pieces between the messages.
#[test]
fn the_filter_says_what_c_s_debug_build_says() {
    let next: &[u8] = b"$\x00\x00\x01Axx$\x05\x00RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n";
    let (mut m, talk) = rtsp_server(&[INTERLEAVED, next], false, usize::MAX);
    let rtp = Rtp::default();
    let first = request(&mut m, Easy::new(), talk.clone(), &rtp, |o| {
        kind(o, RtspRequest::Describe);
    });
    assert_eq!(first.result, Ok(()));
    assert_eq!(first.seen.of("body"), [&b"he"[..], b"llo"]);
    let second = request(&mut m, first.easy, talk, &rtp, |o| {
        kind(o, RtspRequest::Options)
    });
    assert_eq!(second.result, Ok(()));
    assert_eq!(
        rtp.got().last().map(Vec::as_slice),
        Some(&b"$\x00\x00\x01A"[..])
    );
    assert!(second.seen.body().is_empty());
    if cfg!(feature = "debug-hooks") {
        assert_eq!(
            filter_said(&first.seen),
            [
                "rtsp_rtp_write_resp(len=114, in_header=0, eos=0)\n",
                "RTP write channel 0 rtp_len 7\n",
                "RTP write channel 1 rtp_len 6\n",
                "RTP write channel 0 rtp_len 4 (no payload)\n",
                "RTP write channel 1 rtp_len 5\n",
                "rtsp_rtp_write_resp(len=0, in_header=0, done=0, rtspc->state=0, req.size=5)\n",
            ]
        );
        assert_eq!(
            filter_said(&second.seen),
            [
                "rtsp_rtp_write_resp(len=38, in_header=0, eos=0)\n",
                "RTP write channel 0 rtp_len 5\n",
                "RTSP: invalid RTP channel 0, skipping\n",
                "RTP rtsp_filter_rtp[SKIP] RTSP/ prefix, skipping 10 bytes of junk\n",
                "rtsp_rtp_write_resp(len=0, in_header=0, done=0, rtspc->state=0, req.size=0)\n",
            ]
        );
    }
    // Read a byte at a time, a read can end in each state of a message,
    // said as C numbers them (`rtp_parse_st`).
    let (ran, _) = rtsp_with(Easy::new(), &[INTERLEAVED], false, 1, |o| {
        kind(o, RtspRequest::Describe);
    });
    assert_eq!(ran.result, Ok(()));
    if cfg!(feature = "debug-hooks") {
        let states: std::collections::BTreeSet<String> = filter_said(&ran.seen)
            .iter()
            .filter_map(|l| l.split("rtspc->state=").nth(1))
            .map(|rest| rest[..1].to_string())
            .collect();
        assert_eq!(states, ["0", "1", "2", "3"].map(String::from).into());
        // Nothing is left past a filter that took it all.
        assert!(
            !filter_said(&ran.seen)
                .iter()
                .any(|l| l.contains("possibly excess")),
            "{:?}",
            filter_said(&ran.seen)
        );
    }
}

/// A request's result, the pieces of its body, and what the filter said.
type Filtered = (Result<(), ErrorKind>, Vec<Vec<u8>>, Vec<String>);

/// What the filter says, as C's debug build says it, of each request's
/// response on one connection: replies to a DESCRIBE, then an OPTIONS;
/// the requests' results, the bodies and the lines said.
fn filtered(replies: [&[u8]; 2], rtp: &Rtp) -> [Filtered; 2] {
    let (mut m, talk) = rtsp_server(&replies, false, usize::MAX);
    let first = request(&mut m, Easy::new(), talk.clone(), rtp, |o| {
        kind(o, RtspRequest::Describe);
    });
    let one = (
        first.result,
        first.seen.of("body"),
        filter_said(&first.seen),
    );
    let second = request(&mut m, first.easy, talk, rtp, |o| {
        kind(o, RtspRequest::Options)
    });
    let two = (
        second.result,
        second.seen.of("body"),
        filter_said(&second.seen),
    );
    [one, two]
}

/// The lines of a trace the RTP filter says.
fn filter_said(seen: &Seen) -> Vec<String> {
    seen.of("text")
        .into_iter()
        .map(|l| String::from_utf8(l).unwrap())
        .filter(|l| l.contains("RTP") || l.starts_with("rtsp_rtp") || l.starts_with("RTSP:"))
        .collect()
}

/// A head's start inside a body is the body's, and a response past a
/// body's end is dropped, the next request reading its own; neither is
/// said to be excess (checked against the C build's trace of the same
/// bytes).
#[test]
fn what_follows_a_body_is_said_as_c_says_it() {
    let inbody: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\
Transport: RTP/AVP/TCP;interleaved=0-1\r\nContent-Length: 5\r\n\r\n$\x00\x00\x01ZRTSP/";
    let next: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n";
    let excess: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 2\r\n\r\n\
abRTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n";
    let rtp = Rtp::default();
    let [one, two] = filtered([inbody, next], &rtp);
    assert_eq!((one.0, one.1), (Ok(()), vec![b"RTSP/".to_vec()]));
    assert_eq!((two.0, two.1), (Ok(()), vec![]));
    assert_eq!(rtp.got(), [&b"$\x00\x00\x01Z"[..]]);
    let second_said = [
        "rtsp_rtp_write_resp(len=28, in_header=0, eos=0)\n",
        "rtsp_rtp_write_resp(len=0, in_header=0, done=0, rtspc->state=0, req.size=0)\n",
    ];
    if cfg!(feature = "debug-hooks") {
        assert_eq!(
            one.2,
            [
                "rtsp_rtp_write_resp(len=97, in_header=0, eos=0)\n",
                "RTP write channel 0 rtp_len 5\n",
                "rtsp_rtp_write_resp(len=0, in_header=0, done=0, rtspc->state=0, req.size=5)\n",
            ]
        );
        assert_eq!(two.2, second_said);
    }
    let [one, two] = filtered([excess, next], &Rtp::default());
    assert_eq!((one.0, one.1), (Ok(()), vec![b"ab".to_vec()]));
    assert_eq!((two.0, two.1), (Ok(()), vec![]));
    if cfg!(feature = "debug-hooks") {
        assert_eq!(
            one.2,
            [
                "rtsp_rtp_write_resp(len=77, in_header=0, eos=0)\n",
                "rtsp_rtp_write_resp(len=0, in_header=0, done=0, rtspc->state=0, req.size=2)\n",
            ]
        );
        assert_eq!(two.2, second_said);
    }
}

/// A body sized goes with any kind, an OPTIONS's too; the application
/// asking for none keeps an OPTIONS's out, and a DESCRIBE's not (checked
/// against the C build with the same replies).
#[test]
fn a_sized_body_is_read_as_c_reads_it() {
    let describe: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 3\r\n\r\nabc";
    let options: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 3\r\n\r\nxyz";
    for (nobody, second) in [(false, &b"xyz"[..]), (true, b"")] {
        let (mut m, talk) = rtsp_server(&[describe, options], false, usize::MAX);
        let rtp = Rtp::default();
        let set = |o: &mut Options| {
            if nobody {
                o.method = Method::Head;
            }
        };
        let first = request(&mut m, Easy::new(), talk.clone(), &rtp, |o| {
            kind(o, RtspRequest::Describe);
            set(o);
        });
        assert_eq!(
            (first.result, first.seen.body()),
            (Ok(()), b"abc".to_vec()),
            "{nobody}"
        );
        let next = request(&mut m, first.easy, talk, &rtp, |o| {
            kind(o, RtspRequest::Options);
            set(o);
        });
        assert_eq!(
            (next.result, next.seen.body()),
            (Ok(()), second.to_vec()),
            "{nobody}"
        );
    }
}

/// A connection closed during a DESCRIBE's response: a body short of its
/// size is partial, unless its size is ignored, and then it is none; a
/// head cut short has its last line unread, which may be its length or
/// its CSeq (checked against the C build with the same replies).
#[test]
fn a_response_cut_short_ends_as_c_ends_it() {
    for (reply, ignore, result, body) in [
        (
            &b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 10\r\n\r\nabc"[..],
            false,
            Err(ErrorKind::PartialFile),
            &b"abc"[..],
        ),
        (
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 10\r\n\r\nabc",
            true,
            Ok(()),
            b"",
        ),
        (
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 10\r\n",
            false,
            Ok(()),
            b"",
        ),
        (
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n",
            false,
            Err(ErrorKind::RtspCseqError),
            b"",
        ),
    ] {
        let (ran, _) = rtsp_with(Easy::new(), &[reply], true, usize::MAX, |o| {
            kind(o, RtspRequest::Describe);
            o.http.ignore_content_length = ignore;
        });
        let said = String::from_utf8_lossy(reply);
        assert_eq!(
            (ran.result, ran.seen.body()),
            (result, body.to_vec()),
            "{said:?} {ignore}"
        );
    }
    // C's debug build says a head still being read has no size (-1).
    let (ran, _) = rtsp_with(
        Easy::new(),
        &[b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 10\r\n"],
        true,
        usize::MAX,
        |o| kind(o, RtspRequest::Describe),
    );
    if cfg!(feature = "debug-hooks") {
        assert_eq!(
            filter_said(&ran.seen),
            [
                "rtsp_rtp_write_resp(len=46, in_header=0, eos=0)\n",
                "rtsp_rtp_write_resp(len=0, in_header=1, done=0, rtspc->state=0, req.size=-1)\n",
            ]
        );
    }
}

/// An interleave handler that takes `short` bytes fewer than it is given.
struct Takes(usize);

impl WriteHandler for Takes {
    fn write(&self, _: &mut TransferCx<'_>, message: &[u8]) -> Write {
        Write::Took(message.len() - self.0)
    }
}

/// A message the interleave handler takes whole is written; one it takes
/// in part fails the request (`rtp_client_write`).
#[test]
fn an_rtp_message_taken_in_part_fails_the_request() {
    for (short, result) in [(0, Ok(())), (1, Err(ErrorKind::WriteError))] {
        let (ran, _) = rtsp(&[INTERLEAVED], |o| {
            o.small.make_mut().unwrap().interleave = Some(Handler::write(Takes(short)).unwrap());
        });
        assert_eq!(ran.result, result, "{short}");
    }
    let (ran, _) = rtsp(&[INTERLEAVED], |o| {
        o.small.make_mut().unwrap().interleave = Some(Handler::write(Takes(1)).unwrap());
    });
    assert!(
        ran.seen
            .text()
            .contains(&"Failed writing RTP data\n".to_string()),
        "{:?}",
        ran.seen.text()
    );
}

const RESPONSES: &[&[u8]] = &[
    INTERLEAVED,
    b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: abc;timeout=9\r\n\r\n",
    b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\r\n",
    b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 3\r\n\r\n$\x05\x00\x01Q$\x01\x00\x01R",
];

proptest::proptest! {
    #![proptest_config(crate::untrusted::config(64))]

    /// Any response, read in any size of piece, ends the request with an
    /// answer or an error, never a panic.
    #[test]
    fn any_response_ends_the_request(
        reply in crate::untrusted::mutated(RESPONSES),
        giving in 1usize..16,
    ) {
        let (ran, _) = rtsp_with(Easy::new(), &[&reply], true, giving, |_| {});
        let _ended = ran.result;
    }
}
