//! Transfers over a fake server: the greeting and EHLO, HELO, the login,
//! a mail with its envelope and body, a command and its answer,
//! STARTTLS, the answer to the body awaited in DONE, and the connection's
//! QUIT.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::conn::io::{Conversation, FakeNet, Peer as Net};
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{DebugHandler, DebugKind, Handler, Write, WriteHandler};
use crate::id::ArenaPolicy;
use crate::libraries::{Libraries, Library, SharedLibraries};
use crate::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
use crate::options::{Method, Options, UploadSource, UseSsl};
use crate::time::ManualClock;
use crate::tls::fake::{self, FakeTls, WELCOME};

const PORT: u16 = 8025;

/// Collects the body.
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

impl DebugHandler for Text {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text {
            self.0.lock().unwrap().extend_from_slice(data);
        }
    }
}

/// A multi whose server at `PORT` takes `conversations` in turn.
fn serving(conversations: &[&Conversation]) -> Multi {
    clocked(conversations).0
}

/// `serving`'s multi, and the clock it runs on.
fn clocked(conversations: &[&Conversation]) -> (Multi, ManualClock) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let mut net = FakeNet::new(clock.clone()).with_peer(at, Net::Accepts);
    for c in conversations {
        net = net.with_conversation(at, (*c).clone());
    }
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), clock)
}

fn plain() -> SharedLibraries {
    SharedLibraries::new(Libraries::NONE).unwrap()
}

/// The fake TLS library's libraries.
fn with_tls() -> SharedLibraries {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap()
}

/// What came of a transfer.
struct Ran {
    result: Result<(), ErrorKind>,
    body: Vec<u8>,
    text: String,
    code: Option<u16>,
    /// How long it took, start to end.
    total: std::time::Duration,
}

/// A verbose transfer of `url` (`PORT` in it replaced) over `m`, set as
/// `set` says, the `components` named traced too.
fn tracing(
    m: &mut Multi,
    libraries: &SharedLibraries,
    url: &str,
    components: &[u8],
    set: impl FnOnce(&mut Options),
) -> Ran {
    let url = url.replace("PORT", &PORT.to_string());
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let traced = crate::components::Components::new().unwrap();
    traced.configure(components);
    e.set_components(Some(traced));
    let body = Arc::new(Mutex::new(Vec::new()));
    let text = Text::default();
    let o = e.options_mut();
    o.set_url(Some(url.as_bytes())).unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.output.verbose = true;
    o.callbacks.write = Some(Handler::write(Body(body.clone())).unwrap());
    o.callbacks.debug = Some(Handler::debug(text.clone()).unwrap());
    set(o);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(m, id, &mut NoEvents).unwrap();
    let removed = m.remove(id, &mut NoEvents).unwrap();
    let code = removed.easy.report().response_code();
    let total = removed.easy.report().timings().total();
    let body = body.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    Ran {
        result,
        body,
        text,
        code,
        total,
    }
}

fn transfer(m: &mut Multi, url: &str, set: impl FnOnce(&mut Options)) -> Ran {
    tracing(m, &plain(), url, b"", set)
}

const GREETING: &[u8] = b"220 hi\r\n";
const EHLO: &[u8] = b"250-hi there\r\n250-SIZE 1000\r\n250 8BITMIME\r\n";
const OK: &[u8] = b"250 ok\r\n";
const GO: &[u8] = b"354 go\r\n";

/// A server that takes a mail: its greeting, EHLO, MAIL, RCPT, DATA and
/// the body, then the replies `more`.
fn mailing(more: &[&[u8]]) -> Conversation {
    let mut replies = vec![GREETING, EHLO, OK, OK, GO, OK];
    replies.extend_from_slice(more);
    Conversation::replies(&replies, false).greeting()
}

const URL: &str = "smtp://127.0.0.1:PORT/900";

/// A mail is not made again on a fresh connection once its reused one
/// cannot send (`Curl_retry_request`, `state.upload`): the send's failure
/// stands.
#[test]
fn a_mail_a_reused_connection_cannot_send_is_not_retried() {
    let first = mailing(&[]).breaking_after(5);
    let fresh = mailing(&[]);
    let mut m = serving(&[&first, &fresh]);
    let ran = transfer(&mut m, URL, mail(b"hi\r\n"));
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let ran = transfer(&mut m, URL, mail(b"hi\r\n"));
    assert_eq!(ran.result, Err(ErrorKind::SendError), "{}", ran.text);
    assert_eq!(fresh.received(), b"");
    assert!(!ran.text.contains("Connection died"), "{}", ran.text);
}

/// A mail of `body` from `f@a` to `r@b`.
fn mail(body: &[u8]) -> impl FnOnce(&mut Options) {
    let body = body.to_vec();
    move |o: &mut Options| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(body).unwrap());
        let line = o.line.make_mut().unwrap();
        line.mail_from = Some(b"f@a".to_vec());
        line.mail_rcpt.set([&b"r@b"[..]]).unwrap();
    }
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

#[test]
fn a_mail_is_sent_with_its_envelope_and_its_end() {
    let talk = mailing(&[]);
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, URL, mail(b"hi\r\n.dot\r\n"));
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(
        received(&talk),
        "EHLO 900\r\nMAIL FROM:<f@a> SIZE=10\r\nRCPT TO:<r@b>\r\nDATA\r\n\
         hi\r\n..dot\r\n.\r\n"
    );
    assert!(ran.body.is_empty());
    // The answer to the body is the last reply's code.
    assert_eq!(ran.code, Some(250));
    // The connection says QUIT as it closes.
    drop(m);
    assert!(talk.received().ends_with(b".\r\nQUIT\r\n"));
}

/// A mail with no sender has the null reverse-path, and one to several
/// recipients a RCPT TO for each, their brackets and what follows them
/// kept.
#[test]
fn each_recipient_has_its_rcpt_to() {
    let replies = [GREETING, EHLO, OK, OK, OK, GO, OK];
    let talk = Conversation::replies(&replies, false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, URL, |o| {
        mail(b"x")(o);
        let line = o.line.make_mut().unwrap();
        line.mail_from = None;
        line.mail_rcpt
            .set([&b"<r@b> NOTIFY=NEVER"[..], b"local"])
            .unwrap();
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(
        received(&talk),
        "EHLO 900\r\nMAIL FROM:<> SIZE=1\r\nRCPT TO:<r@b> NOTIFY=NEVER\r\n\
         RCPT TO:<local>\r\nDATA\r\nx\r\n.\r\n"
    );
}

/// A recipient refused fails the mail, unless refused ones are let pass,
/// when it fails only if none was taken, with the last code.
#[test]
fn a_refused_recipient_fails_the_mail_unless_let_pass() {
    let two = |o: &mut Options| {
        mail(b"x")(o);
        let line = o.line.make_mut().unwrap();
        line.mail_rcpt.set([&b"a@b"[..], b"c@d"]).unwrap();
    };
    let refused: &[u8] = b"550 no\r\n";
    let talk = Conversation::replies(&[GREETING, EHLO, OK, refused], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, two);
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    assert!(ran.text.contains("RCPT failed: 550\n"), "{}", ran.text);
    assert!(received(&talk).ends_with("RCPT TO:<a@b>\r\n"));

    let talk = Conversation::replies(&[GREETING, EHLO, OK, refused, OK, GO, OK], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        two(o);
        o.line.make_mut().unwrap().mail_rcpt_allowfails = true;
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(received(&talk).contains("RCPT TO:<c@d>\r\nDATA\r\n"));

    let other: &[u8] = b"551 gone\r\n";
    let talk = Conversation::replies(&[GREETING, EHLO, OK, refused, other], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        two(o);
        o.line.make_mut().unwrap().mail_rcpt_allowfails = true;
    });
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    assert!(
        ran.text.contains("RCPT failed: 551 (last error)\n"),
        "{}",
        ran.text
    );
    assert!(!received(&talk).contains("DATA"));
}

/// MAIL and DATA refused fail the mail as C fails it.
#[test]
fn mail_and_data_refused_fail_the_send() {
    for (replies, said) in [
        (&[GREETING, EHLO, b"501 bad\r\n"][..], "MAIL failed: 501\n"),
        (
            &[GREETING, EHLO, OK, OK, b"451 later\r\n"],
            "DATA failed: 451\n",
        ),
    ] {
        let talk = Conversation::replies(replies, false).greeting();
        let ran = transfer(&mut serving(&[&talk]), URL, mail(b"x"));
        assert_eq!(ran.result, Err(ErrorKind::SendError), "{said}");
        assert!(ran.text.contains(said), "{}", ran.text);
    }
}

/// The answer to the body, read in DONE, fails the transfer unless it is
/// 250; the transfer ran to its end, so the connection is kept.
#[test]
fn the_answer_to_the_body_is_read_in_done() {
    let talk =
        Conversation::replies(&[GREETING, EHLO, OK, OK, GO, b"554 spam\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &plain(), URL, b"smtp,multi", mail(b"x"));
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply), "{}", ran.text);
    assert_eq!(ran.code, Some(554));
    let done = ran.text.find("multi_done").expect("DONE began");
    let postdata = ran
        .text
        .find("state change from STOP to POSTDATA")
        .expect("the answer was awaited");
    assert!(done < postdata, "{}", ran.text);
    assert!(
        ran.text
            .contains("[SMTP] smtp_done(status=0, premature=0) -> 8\n"),
        "{}",
        ran.text
    );
}

/// A mail's body with no line end at its end gets one before its dot, and
/// an empty one is the dot alone, without SIZE.
#[test]
fn a_body_is_ended_as_its_last_bytes_call_for() {
    for (body, sent) in [
        (
            &b"abc"[..],
            "SIZE=3\r\nRCPT TO:<r@b>\r\nDATA\r\nabc\r\n.\r\n",
        ),
        (b"", ">\r\nRCPT TO:<r@b>\r\nDATA\r\n.\r\n"),
        (b".", "SIZE=1\r\nRCPT TO:<r@b>\r\nDATA\r\n..\r\n.\r\n"),
    ] {
        let talk = mailing(&[]);
        let ran = transfer(&mut serving(&[&talk]), URL, mail(body));
        assert_eq!(ran.result, Ok(()), "{}", ran.text);
        assert!(received(&talk).ends_with(sent), "{}", received(&talk));
    }
}

/// The body's line ends are converted before its dots are looked at:
/// what `--crlf` makes a line's start is one.
#[test]
fn a_converted_body_s_dots_are_escaped() {
    let talk = mailing(&[]);
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        mail(b"a\n.b\n")(o);
        o.crlf = true;
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    // SIZE is the application's size, before the conversion.
    assert!(
        received(&talk).ends_with("SIZE=5\r\nRCPT TO:<r@b>\r\nDATA\r\na\r\n..b\r\n.\r\n"),
        "{}",
        received(&talk)
    );
}

/// The end-of-body stage traces as C's does.
#[test]
fn the_body_s_end_is_traced_as_c_s() {
    let talk = mailing(&[]);
    let ran = tracing(&mut serving(&[&talk]), &plain(), URL, b"smtp", mail(b"hi"));
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    for line in [
        "[SMTP] cr_eob_read, next_read(len=65536) -> 0, 2 eos=1\n",
        "[SMTP] auto-ending mail body with '\\r\\n.\\r\\n'\n",
        "[SMTP] mail body complete, returning EOS\n",
    ] {
        assert!(ran.text.contains(line), "{line}: {}", ran.text);
    }
    if cfg!(feature = "debug-hooks") {
        assert!(
            ran.text.contains("cr_eob_read(65536) -> 0, 7, 1\n"),
            "{}",
            ran.text
        );
    }
}

/// A body whose added dots outgrow a read is given over the reads
/// after, the source read again only once what was held is given, and
/// ended only once the source is: C's trace, read for read (measured
/// against the C build with the same body).
#[test]
fn a_body_s_added_dots_are_given_before_the_source_is_read_again() {
    let body = b".x\r\n".repeat(17500);
    let talk = mailing(&[]);
    let ran = tracing(&mut serving(&[&talk]), &plain(), URL, b"smtp", mail(&body));
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let sent = talk.received();
    let data = sent.windows(6).position(|w| w == b"DATA\r\n").unwrap() + 6;
    let mut want = b"..x\r\n".repeat(17500);
    want.extend_from_slice(b".\r\nQUIT\r\n");
    assert!(sent[data..] == want[..], "{} bytes sent", sent.len() - data);
    let eob: Vec<&str> = ran
        .text
        .lines()
        .filter(|l| l.contains("cr_eob") || l.contains("mail body"))
        .collect();
    let want: Vec<&str> = [
        "[SMTP] cr_eob_read, next_read(len=65536) -> 0, 65536 eos=0",
        "cr_eob_read(65536) -> 0, 65536, 0",
        "cr_eob_read(65536) -> 0, 16384, 0",
        "[SMTP] cr_eob_read, next_read(len=65536) -> 0, 4464 eos=1",
        "[SMTP] auto-ending mail body with '\\r\\n.\\r\\n'",
        "[SMTP] mail body complete, returning EOS",
        "cr_eob_read(65536) -> 0, 5583, 1",
    ]
    .into_iter()
    .filter(|l| cfg!(feature = "debug-hooks") || l.starts_with("[SMTP]"))
    .collect();
    assert_eq!(eob, want, "{}", ran.text);
}

/// An address with a line's end in it is refused before any command
/// goes with it.
#[test]
fn an_address_with_a_line_end_is_refused() {
    let talk = mailing(&[]);
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        mail(b"x")(o);
        o.line.make_mut().unwrap().mail_from = Some(b"f@a>\r\nRSET".to_vec());
    });
    assert_eq!(ran.result, Err(ErrorKind::BadFunctionArgument));
    assert!(
        ran.text
            .contains("Refusing to send email address with a CR or LF"),
        "{}",
        ran.text
    );
    assert_eq!(received(&talk), "EHLO 900\r\n");
}

/// The server's SMTPUTF8 is said for a mailbox in UTF-8, in the sender
/// or any recipient, and only where the server offers it.
#[test]
fn smtputf8_is_said_for_a_mailbox_in_utf8() {
    let utf8_ehlo: &[u8] = b"250-hi\r\n250 SMTPUTF8\r\n";
    for (from, rcpt, offered, says) in [
        ("f@a", "r@b", true, false),
        ("f\u{fc}@a", "r@b", true, true),
        ("f@a", "r@\u{fc}.b", true, true),
        ("f\u{fc}@a", "r@b", false, false),
    ] {
        let ehlo = if offered { utf8_ehlo } else { EHLO };
        let talk = Conversation::replies(&[GREETING, ehlo, OK, OK, GO, OK], false).greeting();
        let ran = transfer(&mut serving(&[&talk]), URL, |o| {
            mail(b"x")(o);
            let line = o.line.make_mut().unwrap();
            line.mail_from = Some(from.as_bytes().to_vec());
            line.mail_rcpt.set([rcpt.as_bytes()]).unwrap();
        });
        assert_eq!(ran.result, Ok(()), "{}", ran.text);
        let said = received(&talk);
        let mail = said.lines().find(|l| l.starts_with("MAIL")).unwrap();
        assert_eq!(mail.ends_with(" SMTPUTF8"), says, "{mail}");
    }
}

/// Without an upload, a command: VRFY of the recipient, the application's
/// command of it, or HELP; each line of its answer is the body.
#[test]
fn a_command_s_answer_is_the_body() {
    let answer: &[u8] = b"250-first\r\n250 last\r\n";
    let talk = Conversation::replies(&[GREETING, EHLO, answer], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        o.line
            .make_mut()
            .unwrap()
            .mail_rcpt
            .set([&b"<u@h> x"[..]])
            .unwrap();
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(received(&talk), "EHLO 900\r\nVRFY u@h\r\n");
    assert_eq!(ran.body, answer);

    let talk = Conversation::replies(&[GREETING, EHLO, OK, OK], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        let line = o.line.make_mut().unwrap();
        line.mail_rcpt.set([&b"list1"[..], b"list2"]).unwrap();
        o.http.custom.make_mut().unwrap().method = Some(b"EXPN".to_vec());
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(received(&talk), "EHLO 900\r\nEXPN list1\r\nEXPN list2\r\n");
    assert_eq!(ran.body, b"250 ok\r\n250 ok\r\n");

    let talk = Conversation::replies(&[GREETING, EHLO, b"214 help\r\n"], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(received(&talk), "EHLO 900\r\nHELP\r\n");
    assert_eq!(ran.body, b"214 help\r\n");

    // A recipient's 553 is an answer; anything else not 2xx fails.
    let talk = Conversation::replies(&[GREETING, EHLO, b"553 ambiguous\r\n"], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        o.line
            .make_mut()
            .unwrap()
            .mail_rcpt
            .set([&b"u"[..]])
            .unwrap();
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let talk = Conversation::replies(&[GREETING, EHLO, b"553 no\r\n"], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    assert!(ran.text.contains("Command failed: 553\n"), "{}", ran.text);
}

/// No body wanted, the command's answer is not written.
#[test]
fn a_command_wanting_no_body_writes_none() {
    let talk = Conversation::replies(&[GREETING, EHLO, b"214 help\r\n"], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |o| o.method = Method::Head);
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(ran.body.is_empty());
}

/// EHLO refused, HELO greets the server instead; HELO refused denies
/// access.
#[test]
fn helo_follows_a_refused_ehlo() {
    let refused: &[u8] = b"502 no\r\n";
    let talk = Conversation::replies(&[GREETING, refused, OK, b"214 help\r\n"], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(received(&talk), "EHLO 900\r\nHELO 900\r\nHELP\r\n");

    let talk = Conversation::replies(&[GREETING, refused, refused], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RemoteAccessDenied));
    assert!(
        ran.text.contains("Remote access denied: 502\n"),
        "{}",
        ran.text
    );

    // TLS only tried: HELO in the clear.
    let talk = Conversation::replies(&[GREETING, refused, OK, b"214 help\r\n"], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::Try;
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(received(&talk), "EHLO 900\r\nHELO 900\r\nHELP\r\n");

    // TLS required over a clear connection: no HELO.
    let talk = Conversation::replies(&[GREETING, refused], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::All;
    });
    assert_eq!(ran.result, Err(ErrorKind::RemoteAccessDenied));
    assert_eq!(received(&talk), "EHLO 900\r\n");
}

/// A greeting that is no 2xx fails the connect.
#[test]
fn a_bad_greeting_fails() {
    let talk = Conversation::replies(&[b"554 go away\r\n"], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    assert!(
        ran.text
            .contains("Got unexpected smtp-server response: 554\n"),
        "{}",
        ran.text
    );
}

/// A server offering AUTH logs the user in by SASL, the mechanism it
/// offers that is preferred; the submitter then goes with MAIL FROM.
#[test]
fn a_login_by_sasl_lets_the_submitter_go() {
    let ehlo: &[u8] = b"250-hi\r\n250 AUTH LOGIN PLAIN\r\n";
    let talk =
        Conversation::replies(&[GREETING, ehlo, b"235 in\r\n", OK, OK, GO, OK], false).greeting();
    let ran = transfer(
        &mut serving(&[&talk]),
        "smtp://u:p@127.0.0.1:PORT/900",
        |o| {
            mail(b"x")(o);
            o.line.make_mut().unwrap().mail_auth = Some(b"s@t".to_vec());
            o.line.make_mut().unwrap().sasl_ir = true;
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(
        received(&talk),
        "EHLO 900\r\nAUTH PLAIN AHUAcA==\r\nMAIL FROM:<f@a> AUTH=<s@t>\r\n\
         RCPT TO:<r@b>\r\nDATA\r\nx\r\n.\r\n"
    );
    // Not logged in, no AUTH= goes.
    let talk = mailing(&[]);
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        mail(b"x")(o);
        o.line.make_mut().unwrap().mail_auth = Some(b"s@t".to_vec());
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(received(&talk).contains("MAIL FROM:<f@a> SIZE=1\r\n"));
}

/// The SASL exchange goes on with a 334 and its challenge, and a refusal
/// fails the login.
#[test]
fn sasl_continues_on_334() {
    let ehlo: &[u8] = b"250-hi\r\n250 AUTH LOGIN\r\n";
    let replies = [
        GREETING,
        ehlo,
        b"334 VXNlcm5hbWU6\r\n",
        b"334 UGFzc3dvcmQ6\r\n",
        b"235 in\r\n",
        b"214 help\r\n",
    ];
    let talk = Conversation::replies(&replies, false).greeting();
    let ran = transfer(
        &mut serving(&[&talk]),
        "smtp://u:p@127.0.0.1:PORT/900",
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(
        received(&talk),
        "EHLO 900\r\nAUTH LOGIN\r\ndQ==\r\ncA==\r\nHELP\r\n"
    );
    let talk = Conversation::replies(&[GREETING, ehlo, b"535 bad\r\n"], false).greeting();
    let ran = transfer(
        &mut serving(&[&talk]),
        "smtp://u:p@127.0.0.1:PORT/900",
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
    // Refused after the whole login went with its first line.
    let plain_ehlo: &[u8] = b"250-hi\r\n250 AUTH PLAIN\r\n";
    let talk = Conversation::replies(&[GREETING, plain_ehlo, b"535 bad\r\n"], false).greeting();
    let ran = transfer(
        &mut serving(&[&talk]),
        "smtp://u:p@127.0.0.1:PORT/900",
        |o| o.line.make_mut().unwrap().sasl_ir = true,
    );
    assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
    assert_eq!(received(&talk), "EHLO 900\r\nAUTH PLAIN AHUAcA==\r\n");
}

/// Each change of SASL's state is said after the command that makes it,
/// as C changes it after sending (`Curl_sasl_start`,
/// `Curl_sasl_continue`).
#[test]
fn sasl_s_changes_of_state_follow_their_commands() {
    let ehlo: &[u8] = b"250-hi\r\n250 AUTH LOGIN\r\n";
    let replies = [
        GREETING,
        ehlo,
        b"334 VXNlcm5hbWU6\r\n",
        b"334 UGFzc3dvcmQ6\r\n",
        b"235 in\r\n",
        b"214 help\r\n",
    ];
    let talk = Conversation::replies(&replies, false).greeting();
    let said = crate::proto::pingpong::Said::default();
    let ran = transfer(
        &mut serving(&[&talk]),
        "smtp://u:p@127.0.0.1:PORT/900",
        |o| o.callbacks.debug = Some(Handler::debug(said.clone()).unwrap()),
    );
    assert_eq!(ran.result, Ok(()));
    let want: Vec<&str> = [
        "> EHLO 900",
        "> AUTH LOGIN",
        "SASL STOP to LOGIN",
        "> dQ==",
        "SASL LOGIN to LOGIN_PASSWD",
        "> cA==",
        "SASL LOGIN_PASSWD to FINAL",
        "SASL FINAL to STOP",
        "> HELP",
    ]
    .into_iter()
    .filter(|l| cfg!(feature = "debug-hooks") || !l.starts_with("SASL"))
    .collect();
    assert_eq!(said.sasl(), want);
}

/// A server that offers STARTTLS and says go ahead, `after` with it.
fn upgrading(after: &[u8]) -> Conversation {
    let mut go_ahead = b"220 go\r\n".to_vec();
    go_ahead.extend_from_slice(after);
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let replies = [
        GREETING.to_vec(),
        STARTTLS_EHLO.to_vec(),
        go_ahead,
        WELCOME.to_vec(),
        tls(EHLO),
        tls(b"214 help\r\n"),
    ];
    let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    Conversation::replies(&replies, false).greeting()
}

const STARTTLS_EHLO: &[u8] = b"250-hi\r\n250 STARTTLS\r\n";

/// STARTTLS upgrades the connection, and EHLO greets the server again
/// under TLS.
#[test]
fn starttls_upgrades_and_greets_again() {
    let talk = upgrading(b"");
    let ran = transfer_tls(&talk, UseSsl::All);
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(ran.body, b"214 help\r\n");
    let said = talk.received();
    assert!(
        said.starts_with(b"EHLO 900\r\nSTARTTLS\r\nFAKETLS HELLO"),
        "{said:?}"
    );
    let again = fake::records(b"EHLO 900\r\n").unwrap();
    assert!(said.windows(again.len()).any(|w| w == again), "{said:?}");
}

/// The TLS STARTTLS puts on is said as C says a filter put on top of
/// the chain, each call of its connect said; once its handshake is made
/// the connection is timed and said connected again, then its chain, as
/// C's `Curl_conn_connect` does each time the whole chain connects,
/// before EHLO greets the server again.
#[test]
fn starttls_is_timed_and_said_connected() {
    let talk = upgrading(b"");
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &with_tls(), URL, b"multi,ssl", |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::All;
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let next = "[PROTOCONNECTING] -> [DO]";
    crate::multi::state::tls::assert_upgraded_in_place(&ran.text, 0, next);
}

/// Bytes after the go-ahead were not sent under TLS: refused before the
/// upgrade (test 982's).
#[test]
fn bytes_after_the_starttls_go_ahead_are_refused() {
    let talk = upgrading(b"250 early\r\n");
    let ran = transfer_tls(&talk, UseSsl::All);
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    assert_eq!(talk.received(), b"EHLO 900\r\nSTARTTLS\r\n");
}

/// STARTTLS refused goes on in the clear where TLS is only tried, and
/// fails where it is required; not offered, the same.
#[test]
fn starttls_refused_or_not_offered() {
    let refused: &[u8] = b"454 no\r\n";
    let replies = [GREETING, STARTTLS_EHLO, refused, b"214 help\r\n"];
    let talk = Conversation::replies(&replies, false).greeting();
    let ran = transfer_tls(&talk, UseSsl::Try);
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(received(&talk), "EHLO 900\r\nSTARTTLS\r\nHELP\r\n");
    let talk = Conversation::replies(&[GREETING, STARTTLS_EHLO, refused], false).greeting();
    let ran = transfer_tls(&talk, UseSsl::All);
    assert_eq!(ran.result, Err(ErrorKind::UseSslFailed));
    assert!(
        ran.text.contains("STARTTLS denied, code 454\n"),
        "{}",
        ran.text
    );

    let talk = Conversation::replies(&[GREETING, EHLO], false).greeting();
    let ran = transfer_tls(&talk, UseSsl::All);
    assert_eq!(ran.result, Err(ErrorKind::UseSslFailed));
    assert!(
        ran.text.contains("STARTTLS not supported.\n"),
        "{}",
        ran.text
    );
    let talk = Conversation::replies(&[GREETING, EHLO, b"214 help\r\n"], false).greeting();
    let ran = transfer_tls(&talk, UseSsl::Try);
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(received(&talk), "EHLO 900\r\nHELP\r\n");
}

fn transfer_tls(talk: &Conversation, level: UseSsl) -> Ran {
    let mut m = serving(&[talk]);
    tracing(&mut m, &with_tls(), URL, b"", |o| {
        o.line.make_mut().unwrap().use_ssl = level;
    })
}

/// A reused connection greets no more: the second transfer's command is
/// the first thing it sends.
#[test]
fn a_reused_connection_greets_no_more() {
    let talk =
        Conversation::replies(&[GREETING, EHLO, b"214 a\r\n", b"214 b\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    assert_eq!(transfer(&mut m, URL, |_| {}).result, Ok(()));
    let ran = transfer(&mut m, URL, |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(ran.body, b"214 b\r\n");
    assert_eq!(received(&talk), "EHLO 900\r\nHELP\r\nHELP\r\n");
}

/// The DO phase's trace is C's: the SMTP component's lines for each
/// handler, and the state's changes.
#[test]
fn the_do_phase_is_traced_as_c_s() {
    let talk = Conversation::replies(&[GREETING, EHLO, b"214 help\r\n"], false).greeting();
    let ran = tracing(&mut serving(&[&talk]), &plain(), URL, b"smtp", |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let smtp: Vec<&str> = ran
        .text
        .lines()
        .filter_map(|l| l.strip_prefix("[SMTP] "))
        .collect();
    assert_eq!(
        smtp,
        [
            "smtp_setup_connection() -> 0",
            "state change from STOP to SERVERGREET",
            "state change from SERVERGREET to EHLO",
            "state change from EHLO to STOP",
            "smtp_perform(), start",
            "state change from STOP to COMMAND",
            "state change from COMMAND to STOP",
            "smtp_perform() -> 0, connected=1, done=1",
            "smtp_regular_transfer() -> 0, done=1",
            "smtp_do() -> 0, done=1",
            "smtp_done(status=0, premature=0) -> 0",
        ]
    );
}

/// The setup for the connection is said once the transfer is out of the
/// queue and before a connection is looked for, as C calls
/// `smtp_setup_connection` from `url_find_or_create_conn`, after
/// POSTQUEUE.
#[test]
fn the_setup_is_said_after_the_queue() {
    let talk = Conversation::replies(&[GREETING, EHLO, b"214 help\r\n"], false).greeting();
    let ran = tracing(&mut serving(&[&talk]), &plain(), URL, b"smtp,multi", |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let at = |what: &str| {
        ran.text
            .find(what)
            .unwrap_or_else(|| panic!("{what} in {}", ran.text))
    };
    let queued = at("[PGRS-POSTQUEUE] set");
    let set_up = at("[SMTP] smtp_setup_connection() -> 0");
    let pooled = at("[CPOOL] added connection");
    assert!(queued < set_up && set_up < pooled, "{}", ran.text);
}

/// A request that wrote nothing for the application says nothing of its
/// output's end, as C makes its chain of writers at the first write and
/// `Curl_cw_out_done` says nothing without one; one that wrote says it.
#[test]
fn an_end_with_nothing_written_says_nothing_of_the_output() {
    let talk = Conversation::replies(&[GREETING], false).greeting();
    let ran = tracing(
        &mut serving(&[&talk]),
        &plain(),
        "smtp://127.0.0.1:PORT/%00",
        b"write",
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::UrlMalformat));
    assert!(!ran.text.contains("[OUT] done"), "{}", ran.text);
    let ran = tracing(
        &mut serving(&[]),
        &plain(),
        "smtp://127.0.0.1:9/",
        b"write",
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert!(!ran.text.contains("[OUT] done"), "{}", ran.text);
    let talk = Conversation::replies(&[GREETING, EHLO, b"214 help\r\n"], false).greeting();
    let ran = tracing(&mut serving(&[&talk]), &plain(), URL, b"write", |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(
        ran.text
            .contains("[WRITE] [OUT] done\n[WRITE] client_flush() -> 0\n"),
        "{}",
        ran.text
    );
}

/// The lines of `text` from `what` on.
fn from<'t>(text: &'t str, what: &str) -> Vec<&'t str> {
    text.lines()
        .filter_map(|l| l.find(what).map(|at| &l[at..]))
        .collect()
}

/// A transfer that sets up nothing to move after its request leaves the
/// connection so, as C's `recv_idx` and `send_idx` stay on it: a command
/// after it goes from DID to DONE; one after a mail, to PERFORMING. The
/// second's needle connection is let go as C lets it go.
#[test]
fn what_the_last_transfer_set_up_stays_with_the_connection() {
    let help: &[u8] = b"214 help\r\n";
    let talk = Conversation::replies(&[GREETING, EHLO, help, help], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &plain(), URL, b"multi", |o| o.method = Method::Head);
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(
        from(&ran.text, "xfer_setup"),
        ["xfer_setup: recv_idx=-1, send_idx=-1"]
    );
    assert_eq!(from(&ran.text, "[DID] -> "), ["[DID] -> [DONE]"]);
    let ran = tracing(&mut m, &plain(), URL, b"multi,smtp", |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(ran.body, help);
    assert_eq!(from(&ran.text, "[DID] -> "), ["[DID] -> [DONE]"]);
    let reused = ran.text.find("Reusing existing smtp:").expect("reused");
    let let_go = ran
        .text
        .find("[SMTP] smtp_disconnect(), finished")
        .expect("the needle is let go");
    assert!(reused < let_go, "{}", ran.text);

    let talk = Conversation::replies(&[GREETING, EHLO, OK, OK, GO, OK, help], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &plain(), URL, b"multi", mail(b"x"));
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(
        from(&ran.text, "xfer_setup"),
        ["xfer_setup: recv_idx=-1, send_idx=0"]
    );
    let ran = tracing(&mut m, &plain(), URL, b"multi", |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(from(&ran.text, "[DID] -> "), ["[DID] -> [PERFORMING]"]);
    // A fresh connection has set up nothing yet.
    let talk = Conversation::replies(&[GREETING, EHLO, help], false).greeting();
    let ran = tracing(&mut serving(&[&talk]), &plain(), URL, b"multi,smtp", |_| {});
    assert_eq!(from(&ran.text, "[DID] -> "), ["[DID] -> [PERFORMING]"]);
    assert!(!ran.text.contains("smtp_disconnect"), "{}", ran.text);
}

/// A transfer added to `m`, its trace kept.
fn added(
    m: &mut Multi,
    url: &str,
    components: &[u8],
    set: impl FnOnce(&mut Options),
) -> (crate::multi::TransferId, Text) {
    added_writing(m, url, components, Body(Arc::default()), set)
}

/// A transfer added to `m`, its body given to `writer`, its trace kept.
fn added_writing(
    m: &mut Multi,
    url: &str,
    components: &[u8],
    writer: impl WriteHandler + 'static,
    set: impl FnOnce(&mut Options),
) -> (crate::multi::TransferId, Text) {
    let url = url.replace("PORT", &PORT.to_string());
    let mut e = Easy::new();
    e.set_libraries(plain());
    let traced = crate::components::Components::new().unwrap();
    traced.configure(components);
    e.set_components(Some(traced));
    let text = Text::default();
    let o = e.options_mut();
    o.set_url(Some(url.as_bytes())).unwrap();
    o.output.verbose = true;
    o.callbacks.write = Some(Handler::write(writer).unwrap());
    o.callbacks.debug = Some(Handler::debug(text.clone()).unwrap());
    set(o);
    (m.add(Box::new(e), (), &mut NoEvents).unwrap(), text)
}

/// The answer to a mail's body is awaited in DONE without stalling the
/// multi's other transfers. C reads it blocking in `smtp_done`, so a
/// transfer beside it waits for it: measured with `curl -Z` against a
/// server that answers the body a second late, C's `VRFY` beside the
/// mail, to a server greeting half a second late, took 1.005 s, ours
/// 0.504 s (DIVERGENCE.md).
#[test]
fn an_answer_awaited_in_done_stalls_no_other_transfer() {
    let mailer = mailing(&[]).held();
    mailer.allow(5);
    let vrfy = Conversation::replies(&[GREETING, EHLO, OK], false).greeting();
    let mut m = serving(&[&mailer, &vrfy]);
    let (sender, text) = added(&mut m, URL, b"multi", mail(b"hello"));
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert!(said.contains("[PERFORMING] -> [DONE]"), "{said}");
    assert!(m.info_read().is_none(), "the body's answer is awaited");
    let (verifier, _) = added(&mut m, URL, b"", |o| {
        o.line
            .make_mut()
            .unwrap()
            .mail_rcpt
            .set([&b"r@b"[..]])
            .unwrap();
    });
    let verified = drive_to_completion(&mut m, verifier, &mut NoEvents).unwrap();
    assert_eq!(verified, Ok(()));
    assert_eq!(received(&vrfy), "EHLO 900\r\nVRFY r@b\r\n");
    assert!(m.info_read().is_none(), "the mail still waits");
    mailer.allow(6);
    let sent = drive_to_completion(&mut m, sender, &mut NoEvents).unwrap();
    assert_eq!(sent, Ok(()));
}

/// `smtps` speaks TLS from the start and asks no STARTTLS of a server
/// that offers it.
#[test]
fn smtps_speaks_tls_from_the_start() {
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let replies = [
        WELCOME.to_vec(),
        tls(GREETING),
        tls(STARTTLS_EHLO),
        tls(b"214 help\r\n"),
    ];
    let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    let talk = Conversation::replies(&replies, false).per_send();
    let mut m = serving(&[&talk]);
    let ran = tracing(
        &mut m,
        &with_tls(),
        "smtps://127.0.0.1:PORT/900",
        b"",
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(ran.body, b"214 help\r\n");
    let said = talk.received();
    assert!(said.starts_with(b"FAKETLS HELLO"), "{said:?}");
    let help = tls(b"HELP\r\n");
    assert!(said.windows(help.len()).any(|w| w == help), "{said:?}");
    assert!(!said.windows(8).any(|w| w == b"STARTTLS"), "{said:?}");
}

/// Without a TLS library, `smtps` is a protocol the build leaves out.
#[test]
fn smtps_needs_a_tls_library() {
    let talk = Conversation::replies(&[GREETING], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, "smtps://127.0.0.1:PORT/900", |_| {});
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    assert_eq!(talk.received(), b"");
}

/// The server a command retried goes to the second time.
fn helping_again() -> Conversation {
    Conversation::replies(&[GREETING, EHLO, b"214 again\r\n"], false).greeting()
}

/// A server that helps once, gone after its second send.
fn helping_once() -> Conversation {
    Conversation::replies(&[GREETING, EHLO, b"214 help\r\n"], false)
        .greeting()
        .breaking_after(2)
}

/// A reused connection whose peer is gone fails the command's send: the
/// request, which nothing came back for, is made again on a fresh
/// connection, greeting anew (`Curl_retry_request`).
#[test]
fn a_command_a_reused_connection_cannot_send_is_retried() {
    let first = helping_once();
    let fresh = helping_again();
    let mut m = serving(&[&first, &fresh]);
    assert_eq!(transfer(&mut m, URL, |_| {}).result, Ok(()));
    let ran = transfer(&mut m, URL, |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(ran.body, b"214 again\r\n");
    assert_eq!(received(&fresh), "EHLO 900\r\nHELP\r\n");
    let retried = "Connection died, retrying a fresh connect (retry count: 1)";
    assert!(ran.text.contains(retried), "{}", ran.text);
}

/// No body wanted (`NOBODY`), a command a dead reused connection cannot
/// send is not made again.
#[test]
fn a_command_wanting_no_body_is_not_retried() {
    let first = helping_once();
    let fresh = helping_again();
    let mut m = serving(&[&first, &fresh]);
    assert_eq!(transfer(&mut m, URL, |_| {}).result, Ok(()));
    let ran = transfer(&mut m, URL, |o| o.method = Method::Head);
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    assert_eq!(fresh.received(), b"");
    assert!(!ran.text.contains("Connection died"), "{}", ran.text);
}

/// A mail whose envelope was answered over a reused connection that then
/// dies is not made again: something came back for it.
#[test]
fn a_mail_answered_before_its_connection_died_is_not_retried() {
    let first = mailing(&[OK, OK, GO]).breaking_after(8);
    let fresh = mailing(&[]);
    let mut m = serving(&[&first, &fresh]);
    assert_eq!(transfer(&mut m, URL, mail(b"x")).result, Ok(()));
    let ran = transfer(&mut m, URL, mail(b"x"));
    assert_eq!(ran.result, Err(ErrorKind::SendError), "{}", ran.text);
    assert_eq!(fresh.received(), b"");
    assert!(!ran.text.contains("Connection died"), "{}", ran.text);
}

/// The answer to a mail's body awaited in DONE that does not come in
/// time fails the transfer as C's blocking drive fails it, "server
/// response timeout".
#[test]
fn an_answer_awaited_in_done_times_out_as_the_server_s() {
    let mailer = mailing(&[]).held();
    mailer.allow(5);
    let mut m = serving(&[&mailer]);
    let ran = transfer(&mut m, URL, |o| {
        mail(b"hello")(o);
        o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(2500);
    });
    assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
    assert!(ran.text.contains("server response timeout"), "{}", ran.text);
    let total = ran.total.as_millis();
    assert!((2500..2600).contains(&total), "{total} ms");
}

/// Under a send limit, the body is read and sent a second's worth at a
/// time, the transfer waiting between.
#[test]
fn a_mail_s_body_keeps_to_the_send_limit() {
    let talk = mailing(&[]);
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &plain(), URL, b"multi", |o| {
        mail(&[b'x'; 2500])(o);
        o.flow.make_mut().unwrap().max_send_speed = std::num::NonZeroU64::new(1000);
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(talk.received().ends_with(b"xxx\r\n.\r\n"));
    assert!(ran.text.contains("[RLIMIT] waiting"), "{}", ran.text);
    assert!(ran.total.as_millis() >= 2000, "{:?}", ran.total);
}

/// What a request is set up to move once made is said as C's
/// `xfer_setup` says it: the body to send for a mail, its sending ending
/// in PERFORMING; a command sets up nothing, its sending over at DID.
#[test]
fn the_request_says_what_it_is_set_up_to_move() {
    let said = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|l| l.contains("xfer_setup") || l.contains("PGRS-POSTRANSFER"))
            .map(|l| l.split(" added ").next().unwrap().to_owned())
            .collect()
    };
    let talk = mailing(&[]);
    let ran = tracing(&mut serving(&[&talk]), &plain(), URL, b"multi", mail(b"x"));
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(
        said(&ran.text),
        [
            "[MULTI] [DOING] xfer_setup: recv_idx=-1, send_idx=0",
            "[MULTI] [PERFORMING] [PGRS-POSTRANSFER]",
        ],
        "{}",
        ran.text
    );
    let talk = Conversation::replies(&[GREETING, EHLO, b"252 maybe\r\n"], false).greeting();
    let ran = tracing(&mut serving(&[&talk]), &plain(), URL, b"multi", |o| {
        o.line
            .make_mut()
            .unwrap()
            .mail_rcpt
            .set([&b"r@b"[..]])
            .unwrap();
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(
        said(&ran.text),
        ["[MULTI] [DID] [PGRS-POSTRANSFER]"],
        "{}",
        ran.text
    );
}

/// A server that offers no AUTH is not logged in to, whatever
/// credentials the transfer has: the mail goes.
#[test]
fn credentials_without_auth_offered_log_in_nowhere() {
    let talk = mailing(&[]);
    let ran = transfer(
        &mut serving(&[&talk]),
        "smtp://u:p@127.0.0.1:PORT/900",
        mail(b"x"),
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(received(&talk).starts_with("EHLO 900\r\nMAIL FROM:"));
}

/// A reply and the next one in one read: the first transfer stops at its
/// answer, and what follows it waits for the next transfer over the
/// connection (`Curl_pp_moredata`).
#[test]
fn bytes_after_a_transfer_s_answer_wait_for_the_next() {
    let talk = Conversation::replies(&[GREETING, EHLO, b"214 a\r\n214 b\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let first = transfer(&mut m, URL, |_| {});
    assert_eq!(first.result, Ok(()), "{}", first.text);
    assert_eq!(first.body, b"214 a\r\n");
    let second = transfer(&mut m, URL, |_| {});
    assert_eq!(second.result, Ok(()), "{}", second.text);
    assert_eq!(second.body, b"214 b\r\n");
}

/// The answer to a mail's body that a layer holds, where a poll cannot
/// see it, is read on at once in DONE: C's blocking drive loops on what
/// is held (`Curl_conn_data_pending`), and no wait for the socket, which
/// has nothing more, comes between.
#[test]
fn an_answer_a_layer_holds_is_read_on_at_once_in_done() {
    use crate::conn::layer::testing::holdback;
    let talk = mailing(&[]);
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &plain(), URL, b"multi", |o| {
        mail(b"x")(o);
        o.layer = Some(holdback);
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(ran.code, Some(250));
    let done = &ran.text[ran.text.find("-> [DONE]").unwrap()..];
    assert!(done.contains("[DONE] -> [COMPLETED]"), "{}", ran.text);
    assert!(!done.contains("multi_wait"), "{}", ran.text);
}

/// Counts the calls of the progress handler.
#[derive(Clone, Default)]
struct ProgressCount(Arc<Mutex<usize>>);

impl crate::handler::ProgressHandler for ProgressCount {
    fn progress(
        &self,
        _: &mut TransferCx<'_>,
        _: crate::handler::ProgressNow,
    ) -> crate::handler::ProgressVerdict {
        *self.0.lock().unwrap() += 1;
        crate::handler::ProgressVerdict::Continue
    }
}

/// The transfer run again as DONE awaits its answer, before the poll
/// C's blocking drive makes is over and with nothing to read, goes on
/// waiting: the progress is checked once the poll ends, as C checks it
/// after each poll (`Curl_pp_statemach`), not each time it is run.
#[test]
fn an_answer_awaited_in_done_checks_the_progress_once_a_poll() {
    let mailer = mailing(&[]).held();
    mailer.allow(5);
    let mut m = serving(&[&mailer]);
    let calls = ProgressCount::default();
    let handler = calls.clone();
    let (_, text) = added(&mut m, URL, b"multi", |o| {
        mail(b"hello")(o);
        o.progress =
            crate::options::Progress::Handler(crate::handler::Handler::progress(handler).unwrap());
    });
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert!(said.contains("[PERFORMING] -> [DONE]"), "{said}");
    let before = *calls.0.lock().unwrap();
    assert!(before > 0, "the handler is called");
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    let after = *calls.0.lock().unwrap();
    assert_eq!(after, before);
}

/// An initial response the line has no room for (`AUTH `, the
/// mechanism, a space and CRLF in 512 bytes) waits for the server to ask
/// for it; one that fits goes with `AUTH`.
#[test]
fn an_initial_response_too_long_for_the_line_waits_to_be_asked() {
    let ehlo: &[u8] = b"250-hi\r\n250 AUTH PLAIN\r\n";
    for (user, asked) in [(70, false), (373, true)] {
        let mut replies = vec![GREETING, ehlo];
        if asked {
            replies.push(b"334 \r\n");
        }
        replies.extend_from_slice(&[b"235 in\r\n", b"214 help\r\n"]);
        let talk = Conversation::replies(&replies, false).greeting();
        let user = "u".repeat(user);
        let url = format!("smtp://{user}:ppp@127.0.0.1:PORT/900");
        let ran = transfer(&mut serving(&[&talk]), &url, |o| {
            o.line.make_mut().unwrap().sasl_ir = true;
        });
        assert_eq!(ran.result, Ok(()), "{}", ran.text);
        let mut plain = vec![0];
        plain.extend_from_slice(user.as_bytes());
        plain.push(0);
        plain.extend_from_slice(b"ppp");
        let mut initial = Vec::new();
        crate::base64::encode(plain.iter().copied(), plain.len(), &mut initial).unwrap();
        let initial = String::from_utf8(initial).unwrap();
        assert_eq!(initial.len(), if asked { 504 } else { 100 });
        let auth = if asked {
            format!("AUTH PLAIN\r\n{initial}\r\n")
        } else {
            format!("AUTH PLAIN {initial}\r\n")
        };
        assert_eq!(received(&talk), format!("EHLO 900\r\n{auth}HELP\r\n"));
    }
}

/// Takes the body, pausing at its first piece.
#[derive(Clone, Default)]
struct PausesOnce {
    got: Arc<Mutex<Vec<u8>>>,
    paused: Arc<crate::test_cell::Cell<bool>>,
}

impl WriteHandler for PausesOnce {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        if !self.paused.replace(true) {
            return Write::Pause;
        }
        self.got.lock().unwrap().extend_from_slice(body);
        Write::Took(body.len())
    }
}

/// A command's answer whose writer paused holds the transfer open until
/// it is delivered (`Curl_cwriter_is_paused`).
#[test]
fn a_paused_body_holds_the_transfer_open() {
    use crate::deliver::PauseRequest;
    let talk = Conversation::replies(&[GREETING, EHLO, b"214 help\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let writer = PausesOnce::default();
    let (id, _) = added_writing(&mut m, URL, b"", writer.clone(), |_| {});
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(writer.paused.get(), "paused");
    assert!(m.info_read().is_none(), "not over while output is held");
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(*writer.got.lock().unwrap(), b"214 help\r\n");
}

/// What the transfers of `m` wait for on their sockets.
fn waits(m: &mut Multi) -> Vec<crate::conn::io::Events> {
    let mut seen = Vec::new();
    m.sockets(&mut NoEvents, |_, events| seen.push(events))
        .unwrap();
    seen
}

/// A mail's body that the socket takes no more of waits to send, and
/// with its sending paused, on nothing.
#[test]
fn a_body_still_to_send_waits_on_its_socket_unless_paused() {
    use crate::conn::io::Events;
    use crate::deliver::PauseRequest;
    // EHLO, MAIL, RCPT and DATA go; the body does not.
    let talk = mailing(&[]).stalling_sends_after(4, usize::MAX);
    let mut m = serving(&[&talk]);
    let (id, _) = added(&mut m, URL, b"", mail(b"hello"));
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(received(&talk).ends_with("DATA\r\n"), "{}", received(&talk));
    assert_eq!(waits(&mut m), [Events::OUT]);
    m.pause(id, PauseRequest::SEND, &mut NoEvents).unwrap();
    assert_eq!(waits(&mut m), []);
}

/// A transfer taken out of the multi as DONE awaits its answer ends
/// there: the wait given up, and its connection, left within an answer,
/// closed rather than kept.
#[test]
fn a_transfer_removed_as_its_answer_is_awaited_closes_its_connection() {
    let mailer = mailing(&[]).held();
    mailer.allow(5);
    let mut m = serving(&[&mailer]);
    let (id, text) = added(&mut m, URL, b"", mail(b"hello"));
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(m.info_read().is_none(), "the answer is awaited");
    m.remove(id, &mut NoEvents).unwrap();
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert!(said.contains("closing connection #0"), "{said}");
}

/// A mail taken out of the multi with its body still to send ends
/// there: the answer `smtp_done` would await for it given up, its
/// connection, left within the body, closed.
#[test]
fn a_mail_removed_with_its_body_unsent_closes_its_connection() {
    let talk = mailing(&[]).stalling_sends_after(4, usize::MAX);
    let mut m = serving(&[&talk]);
    let (id, text) = added(&mut m, URL, b"", mail(b"hello"));
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(received(&talk).ends_with("DATA\r\n"), "{}", received(&talk));
    m.remove(id, &mut NoEvents).unwrap();
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert!(said.contains("closing connection #0"), "{said}");
    assert!(!received(&talk).ends_with(".\r\n"), "{}", received(&talk));
}

/// A timer handler that aborts the multi once told to.
#[derive(Default)]
struct AbortsTimer {
    armed: bool,
}

impl crate::multi::MultiEvents<crate::multi::NoHost> for AbortsTimer {
    fn timer(
        &mut self,
        _: &mut crate::multi::EventCx<'_, crate::multi::NoHost>,
        _: crate::multi::TimerChange,
    ) -> Result<(), crate::multi::Abort> {
        if self.armed {
            return Err(crate::multi::Abort);
        }
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }
}

/// A multi a callback aborts as a transfer's DONE awaits its answer
/// fails the transfer there: the wait given up, its connection, left
/// within an answer, closed.
#[test]
fn a_dead_multi_ends_an_answer_awaited_in_done() {
    let mailer = mailing(&[]).held();
    mailer.allow(5);
    let mut m = serving(&[&mailer]);
    let (id, text) = added(&mut m, URL, b"", mail(b"hello"));
    let mut ev = AbortsTimer::default();
    for _ in 0..20 {
        let _ = m.perform(&mut ev);
    }
    assert!(m.info_read().is_none(), "the answer is awaited");
    ev.armed = true;
    let ended = crate::multi::drive_within(&mut m, id, 10, &mut ev);
    ev.armed = false;
    let ended = match ended {
        Ok(ended) => ended,
        Err(_) => crate::multi::drive_within(&mut m, id, 10, &mut ev).unwrap(),
    };
    assert_eq!(ended, Err(ErrorKind::AbortedByCallback));
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert!(said.contains("closing connection #0"), "{said}");
}

/// EHLO without a domain in the URL's path gives the machine's name, up
/// to its first dot (`Curl_gethostname`).
#[test]
fn ehlo_without_a_path_gives_the_machine_s_name() {
    let mut buf = [0; 256];
    let name = curl_os::net::host_name(&mut buf).expect("the machine has a name");
    let name = String::from_utf8_lossy(name.split(|&b| b == b'.').next().unwrap()).into_owned();
    let talk = Conversation::replies(&[GREETING, EHLO, b"214 help\r\n"], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), "smtp://127.0.0.1:PORT", |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(received(&talk), format!("EHLO {name}\r\nHELP\r\n"));
}

/// VRFY says SMTPUTF8 for a mailbox whose host is in UTF-8 where the
/// server offers it; an application's command of the recipient says it
/// only for EXPN (`smtp_perform_command`).
#[test]
fn a_command_says_smtputf8_as_c_s_does() {
    let utf8_ehlo: &[u8] = b"250-hi\r\n250 SMTPUTF8\r\n";
    for (custom, rcpt, offered, sent) in [
        (None, "r@b", true, "VRFY r@b"),
        (None, "r@\u{fc}.b", true, "VRFY r@\u{fc}.b SMTPUTF8"),
        (None, "r@\u{fc}.b", false, "VRFY r@\u{fc}.b"),
        (Some("EXPN"), "list", true, "EXPN list SMTPUTF8"),
        (Some("EXPN"), "list", false, "EXPN list"),
        (Some("NOOP"), "list", true, "NOOP list"),
    ] {
        let ehlo = if offered { utf8_ehlo } else { EHLO };
        let talk = Conversation::replies(&[GREETING, ehlo, b"250 ok\r\n"], false).greeting();
        let ran = transfer(&mut serving(&[&talk]), URL, |o| {
            o.line
                .make_mut()
                .unwrap()
                .mail_rcpt
                .set([rcpt.as_bytes()])
                .unwrap();
            if let Some(custom) = custom {
                o.http.custom.make_mut().unwrap().method = Some(custom.as_bytes().to_vec());
            }
        });
        assert_eq!(ran.result, Ok(()), "{}", ran.text);
        assert_eq!(received(&talk), format!("EHLO 900\r\n{sent}\r\n"));
    }
}

/// The submitter's mailbox in UTF-8 has MAIL FROM say SMTPUTF8 where the
/// server offers it, though the sender's is in ASCII.
#[test]
fn a_submitter_in_utf8_says_smtputf8() {
    let ehlo: &[u8] = b"250-hi\r\n250-SMTPUTF8\r\n250 AUTH PLAIN\r\n";
    for (auth, says) in [("s@t", false), ("s@\u{fc}.t", true)] {
        let talk = Conversation::replies(&[GREETING, ehlo, b"235 in\r\n", OK, OK, GO, OK], false)
            .greeting();
        let ran = transfer(
            &mut serving(&[&talk]),
            "smtp://u:p@127.0.0.1:PORT/900",
            |o| {
                mail(b"x")(o);
                let line = o.line.make_mut().unwrap();
                line.mail_auth = Some(auth.as_bytes().to_vec());
                line.sasl_ir = true;
            },
        );
        assert_eq!(ran.result, Ok(()), "{}", ran.text);
        let said = received(&talk);
        let mail = said.lines().find(|l| l.starts_with("MAIL")).unwrap();
        assert_eq!(mail.ends_with(" SMTPUTF8"), says, "{mail}");
    }
}

/// A body's bare line ends go as they are unless conversion is asked
/// for.
#[test]
fn a_body_s_line_ends_are_converted_only_when_asked() {
    let talk = mailing(&[]);
    let ran = transfer(&mut serving(&[&talk]), URL, mail(b"a\n.b\n"));
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(
        received(&talk).ends_with("DATA\r\na\n.b\n\r\n.\r\n"),
        "{}",
        received(&talk)
    );
}

/// A MIME POST to recipients is a mail; a POST of bytes is a command
/// (`smtp_do`'s `state.upload || IS_MIME_POST`).
#[test]
fn only_a_mime_post_is_mailed() {
    use crate::mime::{Boundary, Content, Mime, Part};
    let rcpt = |o: &mut Options| {
        let line = o.line.make_mut().unwrap();
        line.mail_from = Some(b"f@a".to_vec());
        line.mail_rcpt.set([&b"r@b"[..]]).unwrap();
    };
    let talk = Conversation::replies(&[GREETING, EHLO, b"250 ok\r\n"], false).greeting();
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hello".to_vec()).unwrap());
        rcpt(o);
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(received(&talk), "EHLO 900\r\nVRFY r@b\r\n");

    let talk = mailing(&[]);
    let ran = transfer(&mut serving(&[&talk]), URL, |o| {
        let mut m = Mime::new(Boundary::draw(|| Ok::<_, std::convert::Infallible>(0)).unwrap());
        m.add(Part {
            content: Content::Bytes(curl_alloc::TryArc::try_new(b"hi".to_vec()).unwrap()),
            ..Part::default()
        })
        .unwrap();
        let tree = curl_alloc::TryArc::try_new(m).unwrap();
        o.method = Method::Post;
        o.upload = UploadSource::Mime(Handler::mime(crate::mime::Fixed::new(tree)).unwrap());
        rcpt(o);
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let said = received(&talk);
    assert!(said.contains("DATA\r\n"), "{said}");
    assert!(said.contains("Mime-Version: 1.0\r\n"), "{said}");
}

/// A command whose answer comes after DO's first look is done in DOING,
/// and a request that wants no body sets up nothing there, once, as C's
/// `smtp_dophase_done` runs only once the state stops.
#[test]
fn a_command_done_in_doing_says_so_once() {
    let talk = Conversation::replies(&[GREETING, EHLO, b"252 maybe\r\n"], false)
        .greeting()
        .late_replies();
    let ran = tracing(&mut serving(&[&talk]), &plain(), URL, b"multi,smtp", |o| {
        o.method = Method::Head;
        o.line
            .make_mut()
            .unwrap()
            .mail_rcpt
            .set([&b"r@b"[..]])
            .unwrap();
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let said: Vec<&str> = ran
        .text
        .lines()
        .filter(|l| l.contains("xfer_setup") || l.contains("smtp_doing") || l.contains("DO phase"))
        .collect();
    let end: Vec<&str> = [
        "[MULTI] [DOING] xfer_setup: recv_idx=-1, send_idx=-1",
        "DO phase is complete",
        "[SMTP] smtp_doing() -> 0, done=1",
    ]
    .into_iter()
    .filter(|l| cfg!(feature = "debug-hooks") || l.starts_with('['))
    .collect();
    let last = said.len().checked_sub(end.len()).expect("the end is said");
    assert!(
        said[..last]
            .iter()
            .all(|l| *l == "[SMTP] smtp_doing() -> 0, done=0"),
        "{}",
        ran.text
    );
    assert_eq!(said[last..], end, "{}", ran.text);
}

/// An answer awaited in DONE that goes on and on is read ten reads a
/// pass, the multi's other transfers going on between, as the answer
/// is awaited without stalling them (`MAX_READS`).
#[test]
fn an_endless_answer_in_done_is_read_ten_reads_a_pass() {
    let talk = Conversation::replies(&[GREETING, EHLO, OK, OK, GO, b"250-"], false)
        .greeting()
        .endless(std::time::Duration::from_millis(1));
    let mut m = serving(&[&talk]);
    let (_, text) = added(&mut m, URL, b"", mail(b"hello"));
    let mut passes = 0;
    while m.info_read().is_none() {
        let reads = talk.endless_reads();
        m.perform(&mut NoEvents).unwrap();
        let read = talk.endless_reads() - reads;
        assert!(read <= 10, "{read} reads in a pass");
        passes += 1;
        assert!(passes < 100, "the transfer ends");
    }
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert!(talk.endless_reads() > 10, "{said}");
}

/// A command whose answer has not come waits in DOING for its socket to
/// be readable (`smtp_pollset`).
#[test]
fn a_command_s_answer_to_come_waits_on_its_socket() {
    use crate::conn::io::Events;
    let talk = mailing(&[]).held();
    talk.allow(2);
    let mut m = serving(&[&talk]);
    let (_, text) = added(&mut m, URL, b"multi", mail(b"hello"));
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert!(said.contains("[DO] -> [DOING]"), "{said}");
    assert!(
        received(&talk).starts_with("EHLO 900\r\nMAIL FROM:"),
        "{said}"
    );
    assert_eq!(waits(&mut m), [Events::IN]);
}

/// The `QUIT` the connection says as it closes waits for its answer
/// before the socket closes, as C's `smtp_block_statemach` does in its
/// disconnect; a second at most with nothing of it coming, as the C build
/// lets a silent server go after 1.03 s. `quit` is the server's answer,
/// if it gives one: how long the multi's cleanup took, and how many
/// replies were read.
fn quit_answered(quit: Option<&[u8]>) -> (std::time::Duration, usize) {
    use crate::time::Clock as _;
    let talk = mailing(quit.as_slice());
    let (mut m, clock) = clocked(&[&talk]);
    let ran = transfer(&mut m, URL, mail(b"hi\r\n"));
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let before = clock.now();
    drop(m);
    assert!(talk.received().ends_with(b".\r\nQUIT\r\n"));
    (clock.now().since(before), talk.answered())
}

#[test]
fn quit_waits_a_second_for_its_answer() {
    // The greeting, EHLO, MAIL, RCPT, DATA, the body's, and QUIT's.
    assert_eq!(
        quit_answered(Some(b"221 bye\r\n")),
        (std::time::Duration::ZERO, 7)
    );
    assert_eq!(quit_answered(None), (std::time::Duration::from_secs(1), 6));
}

/// A connection closed as its transfer ends waits for its `QUIT`'s
/// answer with its socket polled for reading, as C's
/// `smtp_block_statemach` polls it (`Curl_pp_statemach`): the answer
/// wakes the multi's wait as it comes.
#[test]
fn quit_awaiting_its_answer_is_polled_for_it() {
    let talk = mailing(&[b"221 bye\r\n"]).held();
    talk.allow(6);
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, URL, |o| {
        mail(b"hi\r\n")(o);
        o.limits.reuse.forbid = true;
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(talk.received().ends_with(b".\r\nQUIT\r\n"));
    assert_eq!(talk.answered(), 6);
    talk.allow(7);
    let max = std::time::Duration::from_secs(1);
    let ready = m.wait(&mut [], max, crate::multi::WaitMode::Wait, &mut NoEvents);
    assert_eq!(ready, Ok(1));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(talk.answered(), 7);
}
