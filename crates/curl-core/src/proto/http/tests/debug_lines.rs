//! The lines only C's debug build traces under plain verbose
//! (`DEBUGF(infof(...))` in `transfer.c`, `request.c` and `http.c`), each
//! where that build traces it, among the socket's sends and receives.
//! The sequences are the C debug build's for the same requests.

use super::*;
use crate::components::Components;

/// A handle tracing the socket.
fn tracing_tcp() -> Easy {
    let mut e = Easy::new();
    let c = Components::new().unwrap();
    c.configure(b"tcp");
    e.set_components(Some(c));
    e
}

/// The debug build's lines and the socket's sends and receives, with the
/// failures said, in order.
fn lines(ran: &Ran) -> Vec<String> {
    ran.seen
        .of("text")
        .into_iter()
        .filter(|l| {
            crate::trace::debug_only(l)
                || l.starts_with(b"[TCP] send(")
                || l.starts_with(b"[TCP] recv(")
                || l.starts_with(b"Send failure")
                || l.starts_with(b"Failure writing")
        })
        .map(|l| String::from_utf8(l).unwrap().trim_end().to_owned())
        .collect()
}

/// Whether `want` comes in `lines` in order, other lines between.
fn in_order(lines: &[String], want: &[&str]) -> bool {
    let mut at = lines.iter();
    want.iter().all(|w| at.any(|l| l == w))
}

/// A request without a body goes in one send, its last: said before the
/// send, which is said after the socket's trace (`xfer_send`,
/// `Curl_xfer_send`).
#[test]
fn a_get_is_said_as_its_last_send() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_tcp(), "/a", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let n = ran.request.len();
    assert_eq!(
        lines(&ran)[..3],
        [
            format!("sending last upload chunk of {n} bytes"),
            format!("[TCP] send(len={n}) -> 0, {n}"),
            format!("Curl_xfer_send(len={n}, eos=1) -> 0, {n}"),
        ]
    );
}

/// A body announced with `Expect: 100-continue` is asked for behind the
/// head, again as the wait starts, and passed through once the 100 has
/// come; its last send is the body's (`cr_exp100_read`).
#[test]
fn a_body_held_for_a_100_is_said_at_each_read() {
    let continued = [&b"HTTP/1.1 100 Continue\r\n\r\n"[..], OK_EMPTY].concat();
    let (mut m, talk, _) = server(&[&continued], false);
    let talk = talk.late_replies();
    let ran = get_with(&mut m, tracing_tcp(), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let head = ran.request.len() - 3;
    let lines = lines(&ran);
    let want = [
        "cr_exp100_read, request not full sent yet".to_owned(),
        format!("[TCP] send(len={head}) -> 0, {head}"),
        format!("Curl_xfer_send(len={head}, eos=0) -> 0, {head}"),
        "cr_exp100_read, start AWAITING_CONTINUE, timeout 1000ms".to_owned(),
        "cr_exp100_read, pass through".to_owned(),
        "sending last upload chunk of 3 bytes".to_owned(),
        "[TCP] send(len=3) -> 0, 3".to_owned(),
        "Curl_xfer_send(len=3, eos=1) -> 0, 3".to_owned(),
    ];
    let want: Vec<_> = want.iter().map(String::as_str).collect();
    assert!(in_order(&lines, &want), "{lines:?}");
}

/// A pass while the wait for a 100 runs asks for the body again, and is
/// told the wait has not run out: here the low-speed check's, a second
/// into a wait of three (`cr_exp100_read`'s `AWAITING_CONTINUE`).
#[test]
fn a_pass_during_the_wait_for_a_100_is_said() {
    let (mut m, talk, clock) = server(&[OK_EMPTY], false);
    let start = clock.now();
    let ran = get_with(&mut m, tracing_tcp(), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
        o.http.continue_wait = crate::options::ContinueWait(Duration::from_secs(3));
        o.flow.make_mut().unwrap().low_speed = Some(crate::options::LowSpeed {
            limit: NonZeroU64::new(1).unwrap(),
            time: std::num::NonZeroU16::new(10).unwrap(),
        });
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(clock.now().since(start), Duration::from_secs(3));
    let lines = lines(&ran);
    let want = [
        "cr_exp100_read, start AWAITING_CONTINUE, timeout 3000ms",
        "cr_exp100_read, AWAITING_CONTINUE, not expired",
        "cr_exp100_read, AWAITING_CONTINUE, not expired",
        "cr_exp100_read, pass through",
    ];
    assert!(in_order(&lines, &want), "{lines:?}");
}

/// The connection's end is said after its receive, and the body's end
/// is then traced as body of no bytes (`xfer_recv_resp`).
#[test]
fn the_connection_s_end_is_said_as_reading_is_done() {
    let (mut m, talk, _) = server(&[UNTIL_CLOSE], true);
    let ran = get_with(&mut m, tracing_tcp(), "/a", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let lines = lines(&ran);
    let at = lines
        .iter()
        .position(|l| l == "sendrecv_dl: we are done")
        .unwrap();
    assert_eq!(lines[at - 1], "[TCP] recv(len=16384) -> 0, 0");
    let after: Vec<_> = ran
        .seen
        .0
        .lock()
        .unwrap()
        .iter()
        .skip_while(|(_, l)| !l.starts_with(b"sendrecv_dl: we are done"))
        .skip(1)
        .take(1)
        .map(|(what, l)| (*what, l.len()))
        .collect();
    assert_eq!(after, [("data", 0)]);
}

/// A write the application refuses fails the reads, and then the pass
/// (`sendrecv_dl`, `Curl_sendrecv`).
#[test]
fn a_refused_write_fails_the_reads_and_the_pass() {
    struct Refuses;
    impl WriteHandler for Refuses {
        fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
            Write::Fail
        }
    }
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_tcp(), "/a", talk, |o| {
        o.callbacks.write = Some(Handler::write(Refuses).unwrap());
    });
    assert_eq!(ran.result, Err(ErrorKind::WriteError));
    let lines = lines(&ran);
    assert_eq!(
        lines[lines.len() - 2..],
        ["sendrecv_dl() -> 23", "Curl_sendrecv() -> 23"],
        "{:?}",
        ran.seen.text()
    );
}

/// A response cut short in its head fails the pass, not the reads:
/// `Curl_sendrecv` finds it after them.
#[test]
fn a_head_cut_short_fails_the_pass_alone() {
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nFunny-head: swsclose\r\n";
    let ran = run("/", reply, true, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::PartialFile));
    let said: Vec<_> = ran
        .seen
        .of("text")
        .into_iter()
        .filter(|l| crate::trace::debug_only(l))
        .map(|l| String::from_utf8(l).unwrap())
        .collect();
    assert!(
        said.contains(&"Curl_sendrecv() -> 18\n".to_owned()),
        "{said:?}"
    );
    assert!(
        !said.iter().any(|l| l.starts_with("sendrecv_dl()")),
        "{said:?}"
    );
}

/// A body's send that fails is said after the failure and the socket's
/// trace, and fails the pass (`cf_socket_send`, `Curl_xfer_send`,
/// `Curl_sendrecv`).
#[test]
fn a_failed_send_is_said_after_its_failure() {
    let (mut m, talk, _) = server(&[OK], false);
    let talk = talk.breaking_after(1);
    let ran = get_with(&mut m, tracing_tcp(), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(vec![b'x'; 200_000]).unwrap());
    });
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    let lines = lines(&ran);
    let at = lines
        .iter()
        .position(|l| l.starts_with("Send failure"))
        .unwrap();
    let len = lines[at + 1]
        .strip_prefix("[TCP] send(len=")
        .and_then(|l| l.strip_suffix(") -> 55, 0"))
        .unwrap_or_else(|| panic!("{lines:?}"));
    assert_eq!(
        lines[at + 2..],
        [
            format!("Curl_xfer_send(len={len}, eos=0) -> 55, 0"),
            "Curl_sendrecv() -> 55".to_owned(),
        ]
    );
}

/// A send that would block leaves what is buffered to the next pass
/// (`req_flush`).
#[test]
fn a_blocked_send_leaves_the_rest_buffered() {
    let (mut m, talk, _) = server(&[OK], false);
    let talk = talk.stalling_sends(1);
    let ran = get_with(&mut m, tracing_tcp(), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let n = ran.request.len();
    let lines = lines(&ran);
    // The next pass reads first, then sends what is left.
    assert_eq!(
        lines[..6],
        [
            format!("sending last upload chunk of {n} bytes"),
            format!("[TCP] send(len={n}) -> 81, 0"),
            format!("Curl_xfer_send(len={n}, eos=1) -> 0, 0"),
            format!("Curl_req_flush(len={n}) -> EAGAIN"),
            "[TCP] recv(len=16384) -> 81, 0".to_owned(),
            format!("sending last upload chunk of {n} bytes"),
        ]
    );
}
