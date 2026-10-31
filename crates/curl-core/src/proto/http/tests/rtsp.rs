//! RTSP's requests as C sends them, and its responses as C reads them:
//! the CSeq and session checked, the RTP the server interleaves taken
//! out for the interleave handler.

use super::*;
use crate::options::{RtspRequest, RtspSession};

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
    let other: &[u8] = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: xyz\r\n\r\n";
    let (ran, _) = rtsp_with(ran.easy, &[other], false, usize::MAX, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RtspSessionError));
    assert!(
        String::from_utf8_lossy(&ran.request).contains("CSeq: 2\r\nSession: abc\r\n"),
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
