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
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let mut net = FakeNet::new(clock.clone()).with_peer(at, Net::Accepts);
    for c in conversations {
        net = net.with_conversation(at, (*c).clone());
    }
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
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
    let body = body.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    Ran {
        result,
        body,
        text,
        code,
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
    o.callbacks.write = Some(Handler::write(Body(Arc::default())).unwrap());
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
