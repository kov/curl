//! Transfers over a fake server: the login, the commands a URL asks
//! for, a literal's body, an APPEND, STARTTLS and the reuse of a
//! connection with its mailbox selected.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use crate::conn::io::{Conversation, FakeNet, Peer as Net};
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{DebugHandler, DebugKind, Handler, Write, WriteHandler};
use crate::id::ArenaPolicy;
use crate::libraries::{Libraries, Library, SharedLibraries};
use crate::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
use crate::options::{Method, Options, UploadFlags, UploadSource, UseSsl};
use crate::time::ManualClock;
use crate::tls::fake::{self, FakeTls, WELCOME};

const PORT: u16 = 8143;

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
    total: std::time::Duration,
}

/// A verbose transfer of `url` (`PORT` in it replaced) over `m`, set as
/// `set` says.
fn transfer(
    m: &mut Multi,
    libraries: &SharedLibraries,
    url: &str,
    set: impl FnOnce(&mut Options),
) -> Ran {
    tracing(m, libraries, url, b"", set)
}

/// The same, the `components` named traced too.
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
    let total = removed.easy.report().timings().total();
    let body = body.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    Ran {
        result,
        body,
        text,
        total,
    }
}

const GREETING: &[u8] = b"* OK ready\r\n";
const CAPABILITY: &[u8] = b"* CAPABILITY IMAP4rev1 STARTTLS\r\nA001 OK\r\n";
const LOGGED_IN: &[u8] = b"A002 OK\r\n";
const SELECTED: &[u8] = b"* OK [UIDVALIDITY 7] ok\r\nA003 OK\r\n";
const FETCHED: &[u8] = b"* 1 FETCH (BODY[] {11}\r\nhello world)\r\nA004 OK\r\n";

/// A server that logs the user in, selects INBOX and fetches message 1,
/// the replies after `FETCHED` answering the commands after it.
fn fetching(more: &[&[u8]]) -> Conversation {
    let mut replies = vec![GREETING, CAPABILITY, LOGGED_IN, SELECTED, FETCHED];
    replies.extend_from_slice(more);
    Conversation::replies(&replies, false).greeting()
}

const FETCH_URL: &str = "imap://u:p@127.0.0.1:PORT/INBOX;MAILINDEX=1";

/// A fetch's end is said through the writers' last, as C's build says it
/// (`Curl_cw_out_done`).
#[test]
fn a_fetch_ends_through_the_writers() {
    let talk = fetching(&[]);
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &plain(), FETCH_URL, b"write", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(
        ran.text.lines().any(|l| l == "[WRITE] [OUT] done"),
        "{}",
        ran.text
    );
}

#[test]
fn a_message_is_fetched_after_a_login_and_a_select() {
    let talk = fetching(&[]);
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), FETCH_URL, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.body, b"hello world");
    assert!(
        ran.text.contains("Found 11 bytes to download"),
        "{}",
        ran.text
    );
    assert!(
        ran.text
            .contains("Written 11 bytes, 0 bytes are left for transfer"),
        "{}",
        ran.text
    );
    assert_eq!(
        talk.received(),
        b"A001 CAPABILITY\r\nA002 LOGIN u p\r\nA003 SELECT INBOX\r\nA004 FETCH 1 BODY[]\r\n"
    );
    // The connection says LOGOUT as it closes.
    drop(m);
    assert!(
        talk.received()
            .ends_with(b"A004 FETCH 1 BODY[]\r\nA005 LOGOUT\r\n")
    );
}

/// The literal is read to its size and no further, whatever comes in
/// each read: the tagged answer after it is the transfer's end's.
#[test]
fn a_literal_split_across_reads_is_read_to_its_size() {
    for n in [1, 2, 5, 7, 64] {
        let talk = fetching(&[]).giving(NonZeroUsize::new(n).unwrap());
        let mut m = serving(&[&talk]);
        let ran = transfer(&mut m, &plain(), FETCH_URL, |_| {});
        assert_eq!(ran.result, Ok(()), "{n}");
        assert_eq!(ran.body, b"hello world", "{n}");
    }
}

/// The tagged answer after the literal failing fails the transfer
/// (`imap_state_fetch_final_resp`), which ran to its end: the connection
/// is kept, and says LOGOUT as it closes.
#[test]
fn a_fetch_s_final_answer_refused_fails_the_transfer() {
    let fetched = b"* 1 FETCH (BODY[] {5}\r\nhello)\r\nA004 NO gone\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, SELECTED, fetched], false)
        .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), FETCH_URL, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    assert_eq!(ran.body, b"hello");
    drop(m);
    assert!(talk.received().ends_with(b"A005 LOGOUT\r\n"));
}

/// A FETCH answered without a message fails as not found; a line with
/// no literal in it as weird.
#[test]
fn a_fetch_without_a_literal_fails() {
    for (answer, failure) in [
        (
            &b"A004 NO no such message\r\n"[..],
            ErrorKind::RemoteFileNotFound,
        ),
        (
            b"* 1 FETCH (FLAGS ())\r\nA004 OK\r\n",
            ErrorKind::WeirdServerReply,
        ),
    ] {
        let talk =
            Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, SELECTED, answer], false)
                .greeting();
        let mut m = serving(&[&talk]);
        let ran = transfer(&mut m, &plain(), FETCH_URL, |_| {});
        assert_eq!(ran.result, Err(failure));
        assert!(ran.body.is_empty());
    }
}

/// A second transfer of the mailbox selected on its connection fetches
/// without selecting it again; one of another UIDVALIDITY selects it
/// again and fails as it changed (`imap_perform`'s `selected`).
#[test]
fn the_selected_mailbox_is_kept_on_the_connection() {
    let again = b"* 1 FETCH (BODY[] {2}\r\nhi)\r\nA005 OK\r\n";
    let reselected = b"* OK [UIDVALIDITY 7] ok\r\nA006 OK\r\n";
    let talk = fetching(&[again, reselected]);
    let mut m = serving(&[&talk]);
    assert_eq!(transfer(&mut m, &plain(), FETCH_URL, |_| {}).result, Ok(()));
    let ran = transfer(&mut m, &plain(), FETCH_URL, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.body, b"hi");
    let url = "imap://u:p@127.0.0.1:PORT/INBOX;UIDVALIDITY=8;MAILINDEX=1";
    let ran = transfer(&mut m, &plain(), url, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RemoteFileNotFound));
    assert!(
        ran.text.contains("Mailbox UIDVALIDITY has changed"),
        "{}",
        ran.text
    );
    assert_eq!(
        talk.received(),
        b"A001 CAPABILITY\r\nA002 LOGIN u p\r\nA003 SELECT INBOX\r\nA004 FETCH 1 BODY[]\r\n\
          A005 FETCH 1 BODY[]\r\nA006 SELECT INBOX\r\nA007 LOGOUT\r\n"
    );
}

/// No mailbox: a LIST of the top, each untagged line its body.
#[test]
fn a_url_without_a_mailbox_lists() {
    let listed = b"* LIST () \"/\" INBOX\r\n* LIST () \"/\" \"a b\"\r\nA003 OK\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, listed], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        ran.body,
        b"* LIST () \"/\" INBOX\r\n* LIST () \"/\" \"a b\"\r\n"
    );
    assert!(talk.received().ends_with(b"A003 LIST \"\" *\r\n"));
}

/// A query searches the mailbox; a custom command is sent as given,
/// and a refusal of either is a quote error.
#[test]
fn a_search_and_a_custom_command() {
    let searched = b"* SEARCH 1 2\r\nA004 OK\r\n";
    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, SELECTED, searched],
        false,
    )
    .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(
        &mut m,
        &plain(),
        "imap://u:p@127.0.0.1:PORT/INBOX?NEW",
        |_| {},
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.body, b"* SEARCH 1 2\r\n");
    assert!(talk.received().ends_with(b"A004 SEARCH NEW\r\n"));

    let refused = b"A003 BAD what\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, refused], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |o| {
        o.http.custom.make_mut().unwrap().method = Some(b"EXAMINE INBOX".to_vec());
    });
    assert_eq!(ran.result, Err(ErrorKind::QuoteError));
    // The failed transfer closes its connection, which says LOGOUT.
    assert!(
        talk.received()
            .ends_with(b"A003 EXAMINE INBOX\r\nA004 LOGOUT\r\n"),
        "{:?}",
        String::from_utf8_lossy(&talk.received())
    );
}

/// A custom command answered with a literal has the line and the
/// literal for body, however they come, what is past the literal the
/// answer the transfer's end reads.
#[test]
fn a_custom_command_s_literal_is_its_body() {
    let answered = b"* 1 FETCH (BODY[] {10}\r\nhello worl)\r\nA003 OK\r\n";
    for n in [3, 30, 64] {
        let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, answered], false)
            .greeting()
            .giving(NonZeroUsize::new(n).unwrap());
        let mut m = serving(&[&talk]);
        let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |o| {
            o.http.custom.make_mut().unwrap().method = Some(b"FETCH 1 BODY[]".to_vec());
        });
        assert_eq!(ran.result, Ok(()), "{n}");
        assert_eq!(ran.body, b"* 1 FETCH (BODY[] {10}\r\nhello worl", "{n}");
        assert!(talk.received().ends_with(b"A003 FETCH 1 BODY[]\r\n"));
    }
}

/// A custom command's literal still to come when its line is read has
/// the answer after it read as the transfer ends, a refusal failing it;
/// one that came whole with its line has none read (`imap_done`'s
/// `maxdownload`).
#[test]
fn a_custom_command_s_answer_is_read_only_after_a_literal_still_to_come() {
    let answered = b"* 1 FETCH (BODY[] {10}\r\nhello worl)\r\nA003 NO later\r\n";
    for (n, result) in [(3, Err(ErrorKind::WeirdServerReply)), (64, Ok(()))] {
        let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, answered], false)
            .greeting()
            .giving(NonZeroUsize::new(n).unwrap());
        let mut m = serving(&[&talk]);
        let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |o| {
            o.http.custom.make_mut().unwrap().method = Some(b"FETCH 1 BODY[]".to_vec());
        });
        assert_eq!(ran.result, result, "{n}");
        assert_eq!(ran.body, b"* 1 FETCH (BODY[] {10}\r\nhello worl", "{n}");
    }
}

/// An upload APPENDs its body, its size and flags said, after the
/// server's go-ahead; an empty line ends it.
#[test]
fn an_upload_is_appended() {
    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"],
        false,
    )
    .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hello".to_vec()).unwrap());
        o.line.make_mut().unwrap().upload_flags = UploadFlags::SEEN.or(UploadFlags::DRAFT);
    });
    assert_eq!(ran.result, Ok(()));
    assert!(
        talk.received()
            .ends_with(b"A003 APPEND Sent (\\Draft \\Seen) {5}\r\nhello\r\n"),
        "{:?}",
        String::from_utf8_lossy(&talk.received())
    );
}

/// An upload is not made again on a fresh connection once its reused one
/// cannot send (`Curl_retry_request`, `state.upload`): the send's failure
/// stands.
#[test]
fn an_append_a_reused_connection_cannot_send_is_not_retried() {
    let appending = || {
        Conversation::replies(
            &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"],
            false,
        )
        .greeting()
    };
    let first = appending().breaking_after(5);
    let fresh = appending();
    let mut m = serving(&[&first, &fresh]);
    let append = |o: &mut Options| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hello".to_vec()).unwrap());
    };
    let url = "imap://u:p@127.0.0.1:PORT/Sent";
    let ran = transfer(&mut m, &plain(), url, append);
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let ran = transfer(&mut m, &plain(), url, append);
    assert_eq!(ran.result, Err(ErrorKind::SendError), "{}", ran.text);
    assert_eq!(fresh.received(), b"");
    assert!(!ran.text.contains("Connection died"), "{}", ran.text);
}

/// An APPEND refused, at once or after its body, fails the upload.
#[test]
fn a_refused_append_fails_the_upload() {
    for replies in [
        &[GREETING, CAPABILITY, LOGGED_IN, b"A003 NO full\r\n"][..],
        &[
            GREETING,
            CAPABILITY,
            LOGGED_IN,
            b"+ go\r\n",
            b"A003 NO full\r\n",
        ],
    ] {
        let talk = Conversation::replies(replies, false).greeting();
        let mut m = serving(&[&talk]);
        let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
            o.method = Method::Upload;
            o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hello".to_vec()).unwrap());
        });
        assert_eq!(ran.result, Err(ErrorKind::UploadFailed));
    }
}

/// An upload of a size not known cannot be appended.
#[test]
fn an_upload_of_unknown_size_is_refused() {
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a\nb".to_vec()).unwrap());
        o.crlf = true;
    });
    assert_eq!(ran.result, Err(ErrorKind::UploadFailed));
    assert!(
        ran.text
            .contains("Cannot APPEND with CRLF conversion making size unknown"),
        "{}",
        ran.text
    );
}

/// A greeting that says PREAUTH logs nobody in.
#[test]
fn a_preauthenticated_connection_does_not_log_in() {
    let talk = Conversation::replies(
        &[
            b"* PREAUTH hi\r\n",
            CAPABILITY,
            b"* LIST () \"/\" x\r\nA002 OK\r\n",
        ],
        false,
    )
    .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(talk.received(), b"A001 CAPABILITY\r\nA002 LIST \"\" *\r\n");
}

/// A login refused is denied; a greeting that is not OK is weird.
#[test]
fn a_refused_login_or_greeting_fails() {
    let talk = Conversation::replies(&[GREETING, CAPABILITY, b"A002 NO bad\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Err(ErrorKind::LoginDenied));

    let talk = Conversation::replies(&[b"* BYE\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
}

/// SASL PLAIN, its initial response with the command when the server
/// takes one; the user and password quoted for LOGIN when they must be.
#[test]
fn sasl_and_login_send_the_credentials_as_c_does() {
    let capability = b"* CAPABILITY IMAP4rev1 AUTH=PLAIN SASL-IR\r\nA001 OK\r\n";
    let talk = Conversation::replies(
        &[
            GREETING,
            capability,
            LOGGED_IN,
            b"* LIST () \"/\" x\r\nA003 OK\r\n",
        ],
        false,
    )
    .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(
        talk.received()
            .starts_with(b"A001 CAPABILITY\r\nA002 AUTHENTICATE PLAIN AHUAcA==\r\n"),
        "{:?}",
        String::from_utf8_lossy(&talk.received())
    );

    let talk =
        Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, b"A003 OK\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(
        &mut m,
        &plain(),
        "imap://a%20b:p%22q@127.0.0.1:PORT/",
        |_| {},
    );
    assert_eq!(ran.result, Ok(()));
    assert!(
        talk.received()
            .starts_with(b"A001 CAPABILITY\r\nA002 LOGIN \"a b\" \"p\\\"q\"\r\n"),
        "{:?}",
        String::from_utf8_lossy(&talk.received())
    );
}

/// A server that upgrades to TLS on `STARTTLS`, then asks its
/// capabilities again under it and lists.
fn upgrading(after: &[u8]) -> Conversation {
    let mut go_ahead = b"A002 OK\r\n".to_vec();
    go_ahead.extend_from_slice(after);
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let replies = [
        GREETING.to_vec(),
        CAPABILITY.to_vec(),
        go_ahead,
        WELCOME.to_vec(),
        tls(b"* CAPABILITY IMAP4rev1\r\nA003 OK\r\n"),
        tls(b"A004 OK\r\n"),
        tls(b"* LIST () \"/\" x\r\nA005 OK\r\n"),
    ];
    let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    Conversation::replies(&replies, false).greeting()
}

#[test]
fn starttls_upgrades_the_connection_before_the_login() {
    let talk = upgrading(b"");
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &with_tls(), "imap://u:p@127.0.0.1:PORT/", |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::All;
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.body, b"* LIST () \"/\" x\r\n");
    let said = talk.received();
    assert!(
        said.starts_with(b"A001 CAPABILITY\r\nA002 STARTTLS\r\nFAKETLS HELLO"),
        "{said:?}"
    );
    let login = fake::records(b"A004 LOGIN u p\r\n").unwrap();
    assert!(said.windows(login.len()).any(|w| w == login), "{said:?}");
}

/// The TLS STARTTLS puts on is said as C says a filter put on top of
/// the chain, each call of its connect said; once its handshake is made
/// the connection is timed and said connected again, then its chain, as
/// C's `Curl_conn_connect` does each time the whole chain connects,
/// before the capabilities are asked again.
#[test]
fn starttls_is_timed_and_said_connected() {
    let talk = upgrading(b"");
    let mut m = serving(&[&talk]);
    let ran = tracing(
        &mut m,
        &with_tls(),
        "imap://u:p@127.0.0.1:PORT/",
        b"multi,ssl",
        |o| {
            o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    crate::multi::state::tls::assert_upgraded_in_place(&ran.text, 0, "[PROTOCONNECTING] -> [DO]");
}

/// A STARTTLS handshake that fails is said as C's connect says its
/// filter's failure: the call's end, what the filter returned, and the
/// chain left, its TLS not connected.
#[test]
fn a_failed_starttls_is_said_as_c_s_connect_says_it() {
    let replies = [
        GREETING,
        CAPABILITY,
        b"A002 OK\r\n",
        b"FAKETLS REFUSED\r\n\r\n",
    ];
    let talk = Conversation::replies(&replies, false).greeting();
    let mut m = serving(&[&talk]);
    let ran = tracing(
        &mut m,
        &with_tls(),
        "imap://u:p@127.0.0.1:PORT/",
        b"multi,ssl",
        |o| {
            o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        },
    );
    assert_eq!(ran.result, Err(ErrorKind::SslConnectError), "{}", ran.text);
    let said = &ran.text;
    let at = |line: &str| {
        said.find(line)
            .unwrap_or_else(|| panic!("{line:?} in {said}"))
    };
    let ended = at("[SSL] Curl_conn_connect(block=0) -> 35, done=0\n");
    let returned = at("[SSL] Curl_conn_connect(), filter returned 35\n");
    let left = at("[MULTI] [PROTOCONNECTING] failed to connect [0][!SSL][TCP]\n");
    assert!(ended < returned && returned < left, "{said}");
}

/// Bytes after the go-ahead were not sent under TLS: refused before the
/// upgrade (test 981).
#[test]
fn bytes_after_the_starttls_go_ahead_are_refused() {
    let talk = upgrading(b"* OK pipelined\r\n");
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &with_tls(), "imap://u:p@127.0.0.1:PORT/", |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::All;
    });
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    assert_eq!(talk.received(), b"A001 CAPABILITY\r\nA002 STARTTLS\r\n");
}

/// TLS required of a server that does not offer it fails; tried, it
/// goes on in the clear.
#[test]
fn starttls_not_offered() {
    let capability = b"* CAPABILITY IMAP4rev1\r\nA001 OK\r\n";
    let talk = Conversation::replies(&[GREETING, capability], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &with_tls(), "imap://u:p@127.0.0.1:PORT/", |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::All;
    });
    assert_eq!(ran.result, Err(ErrorKind::UseSslFailed));
    assert!(ran.text.contains("STARTTLS not available."), "{}", ran.text);

    let talk =
        Conversation::replies(&[GREETING, capability, LOGGED_IN, b"A003 OK\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &with_tls(), "imap://u:p@127.0.0.1:PORT/", |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::Try;
    });
    assert_eq!(ran.result, Ok(()));
    assert!(
        talk.received()
            .starts_with(b"A001 CAPABILITY\r\nA002 LOGIN u p\r\n")
    );
}

/// A redirect from HTTP to another host takes the application's login
/// there only if it lets it go anywhere; the redirect's own user goes
/// all the same (tests 779 and 795, `Curl_auth_allowed_to_host`).
#[test]
fn the_application_s_login_stays_with_the_first_host() {
    use crate::options::{Follow, Login, Protocols};
    for unrestricted in [false, true] {
        let location = format!("imap://v@other.test:{PORT}/");
        let moved = format!(
            "HTTP/1.1 302 Moved\r\nLocation: {location}\r\nConnection: close\r\n\
             Content-Length: 0\r\n\r\n"
        );
        let http = Conversation::new(moved.as_bytes(), true);
        // The second connection: its tags are B's.
        let capability = b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nB001 OK\r\n";
        let imap = Conversation::replies(
            &[
                GREETING,
                capability,
                b"+\r\n",
                b"B002 OK\r\n",
                b"B003 OK\r\n",
            ],
            false,
        )
        .greeting();
        let mut m = serving(&[&http, &imap]);
        let entry = format!("other.test:{PORT}:127.0.0.1");
        let ran = transfer(&mut m, &plain(), "http://127.0.0.1:PORT/a", |o| {
            o.http.follow = Follow::All;
            o.http.unrestricted_auth = unrestricted;
            o.schemes.make_mut().unwrap().redirect = Protocols::of(&["imap"]).unwrap();
            o.resolve.set([entry.as_bytes()]).unwrap();
            *o.login.make_mut().unwrap() = Login::from_pair(b"user:secret").unwrap();
        });
        assert_eq!(ran.result, Ok(()), "{}", ran.text);
        let said = imap.received();
        // PLAIN: the authorization identity, the user and the password,
        // each after a zero byte.
        let (want, refused) = if unrestricted {
            ("AHVzZXIAc2VjcmV0", "AHYA")
        } else {
            ("AHYA", "AHVzZXIAc2VjcmV0")
        };
        let has = |what: &str| said.windows(what.len()).any(|w| w == what.as_bytes());
        assert!(
            has(want),
            "{unrestricted}: {}",
            String::from_utf8_lossy(&said)
        );
        assert!(!has(refused), "{unrestricted}");
    }
}

/// The server's time to answer is its own timer, `SERVER_RESPONSE`,
/// set as the greeting is awaited and each time the back and forth is
/// driven, and still armed as the transfer completes
/// (`Curl_pp_statemach`).
#[test]
fn the_server_s_time_to_answer_is_its_own_timer() {
    let talk =
        Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, b"A003 OK\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = tracing(
        &mut m,
        &plain(),
        "imap://u:p@127.0.0.1:PORT/",
        b"timer,multi",
        |o| {
            o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(2500);
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let text = &ran.text;
    // First as the greeting is awaited, with all of the time left.
    let first = text.lines().find(|l| l.contains("[SERVER_RESPONSE]"));
    let set = "[TIMER] [SERVER_RESPONSE] set for 2500000us";
    assert_eq!(first, Some(set), "{text}");
    assert!(
        text.contains("[TIMER] [SERVER_RESPONSE] expires in"),
        "{text}"
    );
    assert!(!text.contains("100_TIMEOUT"), "{text}");
    assert!(text.contains("[COMPLETED] [TIMEOUT] all cleared"), "{text}");
}

/// What the request is set up to move once made is said as C's
/// `xfer_setup` says it: nothing for a FETCH whose literal came whole
/// with its line, the body to send for an APPEND, nothing for a request
/// that wants no body. In DO or DOING, as the answer comes.
#[test]
fn the_request_says_what_it_is_set_up_to_move() {
    let setups = |text: &str| -> Vec<String> {
        text.lines()
            .filter_map(|l| l.find("xfer_setup").map(|at| l[at..].to_owned()))
            .collect()
    };
    let ran = tracing(
        &mut serving(&[&fetching(&[])]),
        &plain(),
        FETCH_URL,
        b"multi",
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(setups(&ran.text), ["xfer_setup: recv_idx=-1, send_idx=-1"]);
    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"],
        false,
    )
    .greeting();
    let ran = tracing(
        &mut serving(&[&talk]),
        &plain(),
        "imap://u:p@127.0.0.1:PORT/Sent",
        b"multi",
        |o| {
            o.method = Method::Upload;
            o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hi".to_vec()).unwrap());
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(setups(&ran.text), ["xfer_setup: recv_idx=-1, send_idx=0"]);
    let talk =
        Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, b"A003 OK\r\n"], false).greeting();
    let ran = tracing(
        &mut serving(&[&talk]),
        &plain(),
        "imap://u:p@127.0.0.1:PORT/",
        b"multi",
        |o| o.method = Method::Head,
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(setups(&ran.text), ["xfer_setup: recv_idx=-1, send_idx=-1"]);
}

/// A transfer goes from DID to PERFORMING while the connection has a
/// socket to exchange on, as C's `recv_idx` says: a FETCH whose literal
/// came whole sets up nothing and goes to DONE, which reads the answer
/// after it once `multi_done` has begun, as C's `imap_done` does; one
/// after it that sets up nothing goes to DONE too, one on a fresh
/// connection does not (`multistate_did`).
#[test]
fn a_transfer_after_one_that_set_up_nothing_goes_to_done() {
    let fetched = b"* 1 FETCH (BODY[] {2}\r\nhi)\r\nA004 OK\r\n";
    let listed = b"* LIST () \"/\" x\r\nA005 OK\r\n";
    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, SELECTED, fetched, listed],
        false,
    )
    .greeting();
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &plain(), FETCH_URL, b"multi", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.body, b"hi");
    let text = &ran.text;
    assert!(text.contains("[DID] -> [DONE]"), "{text}");
    assert!(!text.contains("[PERFORMING]"), "{text}");
    if cfg!(feature = "debug-hooks") {
        let done = text.find("[MULTI] [DONE] multi_done: status: 0 prem: 0 done: 0");
        let last = text.find("state change from STOP to FETCH_FINAL");
        let stop = text.find("state change from FETCH_FINAL to STOP");
        assert!(done.is_some() && last > done && stop > last, "{text}");
    }
    let list = "imap://u:p@127.0.0.1:PORT/";
    let ran = tracing(&mut m, &plain(), list, b"multi", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.body, b"* LIST () \"/\" x\r\n");
    assert!(ran.text.contains("[DID] -> [DONE]"), "{}", ran.text);
    assert!(!ran.text.contains("[PERFORMING]"), "{}", ran.text);

    let talk =
        Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, b"A003 OK\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &plain(), list, b"multi", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(ran.text.contains("[DID] -> [PERFORMING]"), "{}", ran.text);
}

/// `imaps` speaks TLS from the start, asks no STARTTLS of a server that
/// offers it, and offers nothing by ALPN, as only HTTP's schemes do
/// (`PROTOPT_ALPN`).
#[test]
fn imaps_speaks_tls_from_the_start() {
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let replies = [
        WELCOME.to_vec(),
        tls(GREETING),
        tls(CAPABILITY),
        tls(LOGGED_IN),
        tls(SELECTED),
        tls(FETCHED),
    ];
    let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
    let talk = Conversation::replies(&replies, false).per_send();
    let mut m = serving(&[&talk]);
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let url = "imaps://u:p@127.0.0.1:PORT/INBOX;MAILINDEX=1";
    let ran = transfer(&mut m, &libraries, url, |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::All;
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(ran.body, b"hello world");
    let said = talk.received();
    assert!(said.starts_with(b"FAKETLS HELLO"), "{said:?}");
    let login = fake::records(b"A002 LOGIN u p\r\n").unwrap();
    assert!(said.windows(login.len()).any(|w| w == login), "{said:?}");
    assert!(!said.windows(8).any(|w| w == b"STARTTLS"), "{said:?}");
    assert_eq!(backend.log().alpn, Some(crate::tls::Alpn::None));
}

/// Without a TLS library, `imaps` is a protocol the build leaves out.
#[test]
fn imaps_needs_a_tls_library() {
    let talk = Conversation::replies(&[GREETING], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imaps://u:p@127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    assert_eq!(talk.received(), b"");
}

/// A reused connection whose peer is gone fails the command's send: the
/// request, which nothing came back for, is made again on a fresh
/// connection, logged in and selecting anew (`Curl_retry_request`).
#[test]
fn a_command_a_reused_connection_cannot_send_is_retried() {
    let first = fetching(&[]).breaking_after(4);
    // The second connection: its tags are B's.
    let fresh = Conversation::replies(
        &[
            GREETING,
            b"* CAPABILITY IMAP4rev1\r\nB001 OK\r\n",
            b"B002 OK\r\n",
            b"* OK [UIDVALIDITY 7] ok\r\nB003 OK\r\n",
            b"* 1 FETCH (BODY[] {2}\r\nhi)\r\nB004 OK\r\n",
        ],
        false,
    )
    .greeting();
    let mut m = serving(&[&first, &fresh]);
    assert_eq!(transfer(&mut m, &plain(), FETCH_URL, |_| {}).result, Ok(()));
    let ran = transfer(&mut m, &plain(), FETCH_URL, |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(ran.body, b"hi");
    assert_eq!(
        fresh.received(),
        b"B001 CAPABILITY\r\nB002 LOGIN u p\r\nB003 SELECT INBOX\r\nB004 FETCH 1 BODY[]\r\n"
    );
    let retried = "Connection died, retrying a fresh connect (retry count: 1)";
    assert!(ran.text.contains(retried), "{}", ran.text);
}

/// Whether `needle` is among `hay`'s bytes.
fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A login the URL asks to make by SASL alone, or one the server has
/// disabled, is not made in the clear when SASL has no way
/// (`imap_perform_authentication`).
#[test]
fn a_login_only_by_sasl_or_disabled_is_not_made_in_clear() {
    for (url, capability) in [
        (
            "imap://u;AUTH=PLAIN:p@127.0.0.1:PORT/",
            &b"* CAPABILITY IMAP4rev1\r\nA001 OK\r\n"[..],
        ),
        (
            "imap://u:p@127.0.0.1:PORT/",
            b"* CAPABILITY IMAP4rev1 LOGINDISABLED\r\nA001 OK\r\n",
        ),
    ] {
        let talk = Conversation::replies(&[GREETING, capability], false).greeting();
        let mut m = serving(&[&talk]);
        let ran = transfer(&mut m, &plain(), url, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::LoginDenied), "{url}");
        let said = talk.received();
        assert!(said.starts_with(b"A001 CAPABILITY\r\n"), "{said:?}");
        assert!(!has(&said, b"LOGIN u"), "{said:?}");
    }
}

/// Each change of SASL's state is said after the command that makes it,
/// a cancel's too, as C changes it after sending (`Curl_sasl_start`,
/// `Curl_sasl_continue`).
#[test]
fn sasl_s_changes_of_state_follow_their_commands() {
    let cram = b"* CAPABILITY IMAP4rev1 AUTH=CRAM-MD5\r\nA001 OK\r\n";
    let replies: [&[u8]; 6] = [
        GREETING,
        cram,
        b"+ Rubbish\r\n",
        b"A002 NO cancelled\r\n",
        b"A003 OK\r\n",
        b"* LIST () \"/\" x\r\nA004 OK\r\n",
    ];
    let talk = Conversation::replies(&replies, false).greeting();
    let mut m = serving(&[&talk]);
    let said = crate::proto::pingpong::Said::default();
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |o| {
        o.callbacks.debug = Some(Handler::debug(said.clone()).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let want: Vec<&str> = [
        "> A001 CAPABILITY",
        "> A002 AUTHENTICATE CRAM-MD5",
        "SASL STOP to CRAMMD5",
        "> *",
        "SASL CRAMMD5 to CANCEL",
        "> A003 LOGIN u p",
        "> A004 LIST \"\" *",
    ]
    .into_iter()
    .filter(|l| cfg!(feature = "debug-hooks") || !l.starts_with("SASL"))
    .collect();
    assert_eq!(said.sasl(), want);
}

/// A mechanism cancelled with no other to try falls back to LOGIN,
/// unless the server has disabled it (`imap_state_auth_resp`).
#[test]
fn a_cancelled_mechanism_falls_back_to_the_login_unless_disabled() {
    let cram = b"* CAPABILITY IMAP4rev1 AUTH=CRAM-MD5\r\nA001 OK\r\n";
    let replies: [&[u8]; 6] = [
        GREETING,
        cram,
        b"+ Rubbish\r\n",
        b"A002 NO cancelled\r\n",
        b"A003 OK\r\n",
        b"* LIST () \"/\" x\r\nA004 OK\r\n",
    ];
    let talk = Conversation::replies(&replies, false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert_eq!(
        talk.received(),
        b"A001 CAPABILITY\r\nA002 AUTHENTICATE CRAM-MD5\r\n*\r\nA003 LOGIN u p\r\nA004 LIST \"\" *\r\n"
    );

    let disabled = b"* CAPABILITY IMAP4rev1 LOGINDISABLED AUTH=CRAM-MD5\r\nA001 OK\r\n";
    let talk =
        Conversation::replies(&[GREETING, disabled, replies[2], replies[3]], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
    assert!(
        ran.text.contains("Authentication cancelled"),
        "{}",
        ran.text
    );
    assert!(!has(&talk.received(), b"LOGIN u"));
}

/// The server's time to answer a command wakes the transfer as it runs
/// out, from the transfer's whole time once the request is being made
/// (`Curl_pp_state_timeleft_ms`).
#[test]
fn a_server_that_does_not_answer_in_time_times_out() {
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), FETCH_URL, |o| {
        o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(2500);
        o.limits.connect = crate::time::TimeLimit::from_millis(1000);
    });
    assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
    assert!(has(&talk.received(), b"A003 SELECT INBOX\r\n"));
    assert!(ran.text.contains("server response timeout"), "{}", ran.text);
    let total = ran.total.as_millis();
    assert!((2500..2600).contains(&total), "{total} ms");
}

/// The server a retried request goes to the second time: its tags are
/// connection #1's.
fn second_connection() -> Conversation {
    Conversation::replies(
        &[
            GREETING,
            b"* CAPABILITY IMAP4rev1\r\nB001 OK\r\n",
            b"B002 OK\r\n",
            b"* OK [UIDVALIDITY 7] ok\r\nB003 OK\r\n",
            b"* 1 FETCH (BODY[] {2}\r\nhi)\r\nB004 OK\r\n",
        ],
        false,
    )
    .greeting()
}

/// No body wanted (`NOBODY`), a command a dead reused connection cannot
/// send is not made again.
#[test]
fn a_command_wanting_no_body_is_not_retried() {
    let first = fetching(&[]).breaking_after(4);
    let fresh = second_connection();
    let mut m = serving(&[&first, &fresh]);
    assert_eq!(transfer(&mut m, &plain(), FETCH_URL, |_| {}).result, Ok(()));
    let ran = transfer(&mut m, &plain(), FETCH_URL, |o| o.method = Method::Head);
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    assert_eq!(fresh.received(), b"");
    assert!(!ran.text.contains("Connection died"), "{}", ran.text);
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

/// A transfer of `url` added to `m` and not driven, set as `set` says,
/// its body kept by `writer` and its trace's text, the `components`
/// named traced too, in the `Text`.
fn added(
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

/// What the transfers of `m` wait for on their sockets.
fn waits(m: &mut Multi) -> Vec<crate::conn::io::Events> {
    let mut seen = Vec::new();
    m.sockets(&mut NoEvents, |_, events| seen.push(events))
        .unwrap();
    seen
}

/// The trace's text so far.
fn text_of(text: &Text) -> String {
    String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned()
}

/// A body whose writer paused holds the transfer open until it is
/// delivered (`Curl_cwriter_is_paused`), though the FETCH's literal came
/// whole with its line. C then has nothing to exchange after DO
/// (`Curl_xfer_setup_nop`), goes from DID to DONE, and drops the held body:
/// the transfer succeeds with nothing written (DIVERGENCE.md).
#[test]
fn a_paused_body_holds_the_transfer_open() {
    use crate::deliver::PauseRequest;
    let talk = fetching(&[]);
    let mut m = serving(&[&talk]);
    let writer = PausesOnce::default();
    let (id, _) = added(&mut m, FETCH_URL, b"", writer.clone(), |_| {});
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(writer.paused.get(), "paused");
    assert!(m.info_read().is_none(), "not over while output is held");
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(*writer.got.lock().unwrap(), b"hello world");
}

/// A literal larger than any read, with no end in sight.
fn endless_literal() -> Conversation {
    Conversation::replies(
        &[
            GREETING,
            CAPABILITY,
            LOGGED_IN,
            SELECTED,
            b"* 1 FETCH (BODY[] {100000000}\r\n",
        ],
        false,
    )
    .greeting()
    .endless(std::time::Duration::from_millis(1))
}

const MARK_DIRTY: &str =
    "[MULTI] [PERFORMING] sendrecv_dl() no EAGAIN/pending data, mark as dirty\n";

/// A body step reads at most eleven times, and is run again at once
/// (`sendrecv_dl`'s `maxloops`).
#[test]
fn a_body_step_reads_eleven_times_at_most() {
    let talk = endless_literal();
    let mut m = serving(&[&talk]);
    let (_, text) = added(&mut m, FETCH_URL, b"multi", Body(Arc::default()), |_| {});
    while talk.endless_reads() == 0 {
        m.perform(&mut NoEvents).unwrap();
    }
    for _ in 0..3 {
        let reads = talk.endless_reads();
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(talk.endless_reads() - reads, 11);
        assert_eq!(m.timeout(), Some(std::time::Duration::ZERO));
    }
    // The body's first pass, and the three after it.
    let text = text_of(&text);
    assert_eq!(text.matches(MARK_DIRTY).count(), 4, "{text}");
}

/// Body bytes a layer holds, where a poll cannot see them, have the
/// step itself run the transfer again at once (`sendrecv_dl`'s
/// `data_pending`).
#[test]
fn body_bytes_a_layer_holds_are_read_without_waiting() {
    use crate::conn::layer::testing::holdback;
    let talk = endless_literal();
    let mut m = serving(&[&talk]);
    let (_, text) = added(&mut m, FETCH_URL, b"multi", Body(Arc::default()), |o| {
        o.layer = Some(holdback);
    });
    while talk.endless_reads() < 3 {
        m.perform(&mut NoEvents).unwrap();
    }
    let text = text_of(&text);
    assert!(text.contains(MARK_DIRTY), "{text}");
}

/// A literal not yet whole waits to read its socket, and paused, on
/// nothing.
#[test]
fn a_literal_to_come_waits_on_its_socket_unless_paused() {
    use crate::conn::io::Events;
    use crate::deliver::PauseRequest;
    let partly = b"* 1 FETCH (BODY[] {11}\r\nhel";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, SELECTED, partly], false)
        .greeting();
    let mut m = serving(&[&talk]);
    let (id, _) = added(&mut m, FETCH_URL, b"", Body(Arc::default()), |_| {});
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(has(&talk.received(), b"A004 FETCH 1 BODY[]\r\n"));
    assert_ne!(m.timeout(), Some(std::time::Duration::ZERO));
    assert_eq!(waits(&mut m), [Events::IN]);
    m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
    assert_eq!(waits(&mut m), []);
}

/// A literal's read that fails fails the transfer, said once: by the
/// socket, as C's socket filter says it, or else by the protocol, for a
/// layer that failed without saying why.
#[test]
fn a_literal_s_read_failure_is_said_once() {
    let partly: &[u8] = b"* 1 FETCH (BODY[] {11}\r\nhel";
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let mut body = tls(partly);
    body.extend_from_slice(b"not a record");
    let secure = [
        WELCOME.to_vec(),
        tls(GREETING),
        tls(CAPABILITY),
        tls(LOGGED_IN),
        tls(SELECTED),
        body,
    ];
    let secure: Vec<&[u8]> = secure.iter().map(Vec::as_slice).collect();
    let cases = [
        (
            Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, SELECTED, partly], false)
                .greeting()
                .resetting(),
            "imap",
        ),
        (Conversation::replies(&secure, false).per_send(), "imaps"),
    ];
    for (talk, scheme) in cases {
        let mut m = serving(&[&talk]);
        let url = format!("{scheme}://u:p@127.0.0.1:PORT/INBOX;MAILINDEX=1");
        let ran = transfer(&mut m, &with_tls(), &url, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::RecvError), "{}", ran.text);
        assert_eq!(ran.body, b"hel");
        let failures = ran
            .text
            .lines()
            .filter(|l| l.starts_with("Recv failure: "))
            .count();
        assert_eq!(failures, 1, "{scheme}: {}", ran.text);
    }
}

/// A literal the server ends the connection inside of is a partial
/// file: the literal's size is the response's (`Curl_xfer_setup_recv`).
#[test]
fn a_literal_cut_short_is_a_partial_file() {
    let partly: &[u8] = b"* 1 FETCH (BODY[] {11}\r\nhello";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, SELECTED, partly], true)
        .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), FETCH_URL, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::PartialFile), "{}", ran.text);
    assert!(
        ran.text.contains("end of response with 6 bytes missing"),
        "{}",
        ran.text
    );
}

/// STARTTLS refused fails a transfer requiring TLS; one only trying it
/// logs in in the clear (`imap_state_starttls_resp`).
#[test]
fn starttls_refused() {
    let no = b"A002 NO\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, no], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &with_tls(), "imap://u:p@127.0.0.1:PORT/", |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::All;
    });
    assert_eq!(ran.result, Err(ErrorKind::UseSslFailed));
    assert!(ran.text.contains("STARTTLS denied"), "{}", ran.text);

    let listed = b"* LIST () \"/\" x\r\nA004 OK\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, no, b"A003 OK\r\n", listed], false)
        .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &with_tls(), "imap://u:p@127.0.0.1:PORT/", |o| {
        o.line.make_mut().unwrap().use_ssl = UseSsl::Try;
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        talk.received(),
        b"A001 CAPABILITY\r\nA002 STARTTLS\r\nA003 LOGIN u p\r\nA004 LIST \"\" *\r\n"
    );
}

/// A continuation answers no command but AUTHENTICATE and APPEND; to
/// the application's command it is a line like any other
/// (`imap_endofresp`).
#[test]
fn a_continuation_answers_only_what_waits_for_one() {
    let talk =
        Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, b"+ what\r\n"], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    assert!(
        ran.text.contains("Unexpected continuation response"),
        "{}",
        ran.text
    );

    let noop = b"+ what\r\nA003 OK\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, noop], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/", |o| {
        o.http.custom.make_mut().unwrap().method = Some(b"NOOP".to_vec());
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(ran.body.is_empty());
}

/// The URL chooses the command: a mailbox alone lists it, a UID fetches
/// by it, and the application's command on a mailbox selects it first
/// (`imap_perform`); a custom FETCH of many messages writes none of
/// their lines (`is_custom_fetch_listing`).
#[test]
fn the_url_chooses_the_command() {
    let listed = b"* LIST () \"/\" INBOX/a\r\nA003 OK\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, listed], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/INBOX", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.body, b"* LIST () \"/\" INBOX/a\r\n");
    assert!(talk.received().ends_with(b"A003 LIST \"INBOX\" *\r\n"));

    let by_uid = b"* 1 FETCH (UID 1 BODY[] {2}\r\nhi)\r\nA004 OK\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, SELECTED, by_uid], false)
        .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(
        &mut m,
        &plain(),
        "imap://u:p@127.0.0.1:PORT/INBOX;UID=1",
        |_| {},
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.body, b"hi");
    assert!(
        talk.received()
            .ends_with(b"A003 SELECT INBOX\r\nA004 UID FETCH 1 BODY[]\r\n")
    );

    let flags = b"* 1 FETCH (FLAGS (\\Seen))\r\n* 2 FETCH (FLAGS ())\r\nA004 OK\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, SELECTED, flags], false)
        .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/INBOX", |o| {
        o.http.custom.make_mut().unwrap().method = Some(b"FETCH 1:2 (FLAGS)".to_vec());
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(ran.body.is_empty(), "{:?}", ran.body);
    assert!(
        talk.received()
            .ends_with(b"A003 SELECT INBOX\r\nA004 FETCH 1:2 (FLAGS)\r\n")
    );
}

/// The mailbox selected on a connection is known by its name, INBOX by
/// any case of it (`imap_perform`'s `selected`).
#[test]
fn the_selected_mailbox_is_known_by_name() {
    let again = |tag: &str| format!("* 1 FETCH (BODY[] {{2}}\r\nhi)\r\n{tag} OK\r\n").into_bytes();
    let (a005, a007, a008) = (again("A005"), again("A007"), again("A008"));
    let selected = b"* OK [UIDVALIDITY 7] ok\r\nA006 OK\r\n";
    let talk = fetching(&[&a005, selected, &a007, &a008]);
    let mut m = serving(&[&talk]);
    for mailbox in ["Sent", "Sent", "INBOX", "inbox"] {
        let url = format!("imap://u:p@127.0.0.1:PORT/{mailbox};MAILINDEX=1");
        let ran = transfer(&mut m, &plain(), &url, |_| {});
        assert_eq!(ran.result, Ok(()), "{mailbox}: {}", ran.text);
    }
    assert_eq!(
        talk.received(),
        b"A001 CAPABILITY\r\nA002 LOGIN u p\r\nA003 SELECT Sent\r\nA004 FETCH 1 BODY[]\r\n\
          A005 FETCH 1 BODY[]\r\nA006 SELECT INBOX\r\nA007 FETCH 1 BODY[]\r\nA008 FETCH 1 BODY[]\r\n"
    );
}

/// A tree of one part, its boundary all `A`s.
fn mail_tree() -> UploadSource {
    use crate::mime::{Boundary, Content, Mime, Part};
    let mut m = Mime::new(Boundary::draw(|| Ok::<_, std::convert::Infallible>(0)).unwrap());
    m.add(Part {
        content: Content::Bytes(curl_alloc::TryArc::try_new(b"hi".to_vec()).unwrap()),
        ..Part::default()
    })
    .unwrap();
    let tree = curl_alloc::TryArc::try_new(m).unwrap();
    UploadSource::Mime(Handler::mime(crate::mime::Fixed::new(tree)).unwrap())
}

/// A POST of bytes appends nothing; a MIME POST appends the tree as a
/// mail message (`imap_do`'s `state.upload || IS_MIME_POST`).
#[test]
fn only_a_mime_post_is_appended() {
    let listed = b"* LIST () \"/\" Sent/a\r\nA003 OK\r\n";
    let talk = Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, listed], false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hello".to_vec()).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    assert!(talk.received().ends_with(b"A003 LIST \"Sent\" *\r\n"));

    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"],
        false,
    )
    .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
        o.method = Method::Post;
        o.upload = mail_tree();
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let said = talk.received();
    assert!(has(&said, b"A003 APPEND Sent (\\Seen) {"), "{said:?}");
    assert!(has(&said, b"Mime-Version: 1.0\r\n"), "{said:?}");
}

/// An APPEND's body is sent as C's request sends it: each send traced,
/// one the socket refuses waiting, its end said, and the time the request
/// was sent taken then, not at DID; the server's answer after it starts
/// the response's time (`xfer_send`, `req_set_upload_done`).
#[test]
fn an_append_s_body_is_sent_and_timed_as_c_s() {
    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"],
        false,
    )
    .greeting()
    .stalling_sends_after(3, 1);
    let mut m = serving(&[&talk]);
    let ran = tracing(
        &mut m,
        &plain(),
        "imap://u:p@127.0.0.1:PORT/Sent",
        b"multi",
        |o| {
            o.method = Method::Upload;
            o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hello".to_vec()).unwrap());
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(
        talk.received()
            .ends_with(b"A003 APPEND Sent (\\Seen) {5}\r\nhello\r\n")
    );
    let text = &ran.text;
    if cfg!(feature = "debug-hooks") {
        let sends = "sending last upload chunk of 5 bytes\n\
                     Curl_xfer_send(len=5, eos=1) -> 0, 0\n\
                     Curl_req_flush(len=5) -> EAGAIN\n";
        assert!(text.contains(sends), "{text}");
        let sent = "sending last upload chunk of 5 bytes\n\
                    Curl_xfer_send(len=5, eos=1) -> 0, 5\n\
                    [MULTI] [PERFORMING] [PGRS-POSTRANSFER] added";
        assert!(text.contains(sent), "{text}");
    }
    // The answer is read in DONE, after `multi_done` begins, as C's
    // `imap_done` reads it: its first line starts the response's time.
    let sent = text.find("upload completely sent off: 5 bytes\n");
    let done = text.find("[MULTI] [DONE] multi_done: status: 0 prem: 0 done: 0");
    let started = text.find("[MULTI] [DONE] [PGRS-STARTTRANSFER]");
    assert!(sent.is_some() && done > sent && started > done, "{text}");
    assert!(!text.contains("[DID] [PGRS-POSTRANSFER]"), "{text}");
    if cfg!(feature = "debug-hooks") {
        let last = text.find("state change from STOP to APPEND_FINAL");
        assert!(last > done && started > last, "{text}");
    }

    // A FETCH sends nothing after DID, which takes the time.
    let talk = fetching(&[]);
    let mut m = serving(&[&talk]);
    let ran = tracing(&mut m, &plain(), FETCH_URL, b"multi", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(
        ran.text.contains("[DID] [PGRS-POSTRANSFER]"),
        "{}",
        ran.text
    );
}

/// An empty APPEND sends its end alone, and says the request is sent.
#[test]
fn an_empty_append_says_the_request_is_sent() {
    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"],
        false,
    )
    .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(Vec::new()).unwrap());
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(
        talk.received()
            .ends_with(b"A003 APPEND Sent (\\Seen) {0}\r\n\r\n")
    );
    if cfg!(feature = "debug-hooks") {
        let end = "sending last upload chunk of 0 bytes\nCurl_xfer_send(len=0, eos=1) -> 0, 0\n";
        assert!(ran.text.contains(end), "{}", ran.text);
    }
    assert!(
        ran.text.contains("Request completely sent off\n"),
        "{}",
        ran.text
    );
}

/// The debug build says each change of state, once, and the DO phase's
/// end as its state stops (`imap_state`, `imap_perform`).
#[test]
fn the_debug_build_says_each_change_of_state() {
    if !cfg!(feature = "debug-hooks") {
        return;
    }
    let talk = fetching(&[]);
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), FETCH_URL, |_| {});
    assert_eq!(ran.result, Ok(()));
    let changes: Vec<&str> = ran
        .text
        .lines()
        .filter_map(|l| l.split_once(" state change from ").map(|(_, c)| c))
        .collect();
    assert_eq!(
        changes,
        [
            "STOP to SERVERGREET",
            "SERVERGREET to CAPABILITY",
            "CAPABILITY to LOGIN",
            "LOGIN to STOP",
            "STOP to SELECT",
            "SELECT to FETCH",
            "FETCH to STOP",
            "STOP to FETCH_FINAL",
            "FETCH_FINAL to STOP",
        ]
    );
    assert_eq!(
        ran.text.matches("DO phase is complete\n").count(),
        1,
        "{}",
        ran.text
    );
}

/// A body larger than the upload buffer goes a buffer at a time, its
/// last send saying the end; a send the socket takes short of says what
/// is left and sends it after (`xfer_send`, `req_flush`).
#[test]
fn an_append_s_body_goes_a_buffer_and_a_send_at_a_time() {
    let replies: [&[u8]; 5] = [GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"];
    let big = vec![b'x'; 40_000];
    let talk = Conversation::replies(&replies, false).greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(big.clone()).unwrap());
        o.limits.upload_buffer = crate::options::UploadBufferSize::clamped(16_384);
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let mut want = b"A003 APPEND Sent (\\Seen) {40000}\r\n".to_vec();
    want.extend_from_slice(&big);
    want.extend_from_slice(b"\r\n");
    assert!(talk.received().ends_with(&want));
    if cfg!(feature = "debug-hooks") {
        let first = "Curl_xfer_send(len=16384, eos=0) -> 0, 16384\n";
        assert!(ran.text.contains(first), "{}", ran.text);
    }
    assert!(ran.text.contains("upload completely sent off: 40000 bytes"));

    let talk = Conversation::replies(&replies, false)
        .greeting()
        .taking(NonZeroUsize::new(2).unwrap());
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hello".to_vec()).unwrap());
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(
        talk.received()
            .ends_with(b"A003 APPEND Sent (\\Seen) {5}\r\nhello\r\n")
    );
    if cfg!(feature = "debug-hooks") {
        let short = "Curl_xfer_send(len=5, eos=1) -> 0, 2\nCurl_req_flush(len=3) -> EAGAIN\n";
        assert!(ran.text.contains(short), "{}", ran.text);
    }
}

/// Under a send limit, the body is read and sent a second's worth at a
/// time, the transfer waiting between (`Curl_client_read`, `xfer_send`,
/// `mspeed_check`).
#[test]
fn an_append_s_body_keeps_to_the_send_limit() {
    let replies: [&[u8]; 5] = [GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"];
    let talk = Conversation::replies(&replies, false).greeting();
    let mut m = serving(&[&talk]);
    let ran = tracing(
        &mut m,
        &plain(),
        "imap://u:p@127.0.0.1:PORT/Sent",
        b"multi",
        |o| {
            o.method = Method::Upload;
            o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(vec![b'x'; 2500]).unwrap());
            o.flow.make_mut().unwrap().max_send_speed = std::num::NonZeroU64::new(1000);
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    assert!(talk.received().ends_with(b"xxx\r\n"));
    if cfg!(feature = "debug-hooks") {
        let whole = "Curl_xfer_send(len=1000, eos=0) -> 0, 1000\n";
        assert_eq!(ran.text.matches(whole).count(), 2, "{}", ran.text);
        let last =
            "sending last upload chunk of 500 bytes\nCurl_xfer_send(len=500, eos=1) -> 0, 500\n";
        assert!(ran.text.contains(last), "{}", ran.text);
    }
    assert!(ran.text.contains("[RLIMIT] waiting"), "{}", ran.text);
    assert!(ran.total.as_millis() >= 2000, "{:?}", ran.total);
}

/// What the server says to an `APPEND` of "hello", its tagged answer the
/// fifth reply, which the held peer gives only once let.
fn appending() -> Conversation {
    Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"],
        false,
    )
    .greeting()
    .held()
}

fn hello(o: &mut Options) {
    o.method = Method::Upload;
    o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hello".to_vec()).unwrap());
}

/// An `APPEND`'s answer is awaited in DONE without stalling the multi's
/// other transfers. C reads it blocking in `imap_done`, so a transfer
/// beside it waits for it: measured with `curl -Z` against a server that
/// answers a second late, C's `LIST` beside the `APPEND` took 1.003 s,
/// ours 1.5 ms (DIVERGENCE.md). The same goes for a `FETCH` beside it.
#[test]
fn an_answer_awaited_in_done_stalls_no_other_transfer() {
    let append = appending();
    append.allow(4);
    // The second connection's tags are `B`'s.
    let list = second_connection();
    let mut m = serving(&[&append, &list]);
    let url = "imap://u:p@127.0.0.1:PORT/Sent";
    let (appender, text) = added(&mut m, url, b"multi", Body(Arc::default()), hello);
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert!(said.contains("[PERFORMING] -> [DONE]"), "{said}");
    assert!(m.info_read().is_none(), "the APPEND's answer is awaited");
    let (fetcher, _) = added(&mut m, FETCH_URL, b"", Body(Arc::default()), |_| {});
    let fetched = drive_to_completion(&mut m, fetcher, &mut NoEvents).unwrap();
    assert_eq!(fetched, Ok(()));
    assert!(m.info_read().is_none(), "the APPEND still waits");
    append.allow(5);
    let appended = drive_to_completion(&mut m, appender, &mut NoEvents).unwrap();
    assert_eq!(appended, Ok(()));
}

/// An answer awaited in DONE that does not come in time fails the
/// transfer as C's blocking drive fails it, "server response timeout".
#[test]
fn an_answer_awaited_in_done_times_out_as_the_server_s() {
    let append = appending();
    append.allow(4);
    let mut m = serving(&[&append]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
        hello(o);
        o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(2500);
    });
    assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
    assert!(ran.text.contains("server response timeout"), "{}", ran.text);
    let total = ran.total.as_millis();
    assert!((2500..2600).contains(&total), "{total} ms");
}

/// A transfer taken out of the multi as DONE awaits its answer ends
/// there: the wait given up, and its connection, left within an answer,
/// closed rather than kept.
#[test]
fn a_transfer_removed_as_its_answer_is_awaited_closes_its_connection() {
    let append = appending();
    append.allow(4);
    let mut m = serving(&[&append]);
    let url = "imap://u:p@127.0.0.1:PORT/Sent";
    let (id, text) = added(&mut m, url, b"", Body(Arc::default()), hello);
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(m.info_read().is_none(), "the answer is awaited");
    m.remove(id, &mut NoEvents).unwrap();
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert!(said.contains("closing connection #0"), "{said}");
}

/// Under a send limit, an `APPEND` of 5000 bytes at 1000 a second takes
/// C's 4 s: its answer is read in DONE, past the limit's last wait
/// (measured against the C build: 4.0 s).
#[test]
fn an_append_under_a_send_limit_takes_c_s_time() {
    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"],
        false,
    )
    .greeting();
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), "imap://u:p@127.0.0.1:PORT/Sent", |o| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(vec![b'x'; 5000]).unwrap());
        o.flow.make_mut().unwrap().max_send_speed = std::num::NonZeroU64::new(1000);
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let total = ran.total.as_millis();
    assert!((4000..4100).contains(&total), "{total} ms");
}

/// An `APPEND`'s answer that a layer holds, where a poll cannot see it,
/// is read on at once in DONE: C's blocking drive loops on what is held
/// (`Curl_conn_data_pending`), and no wait for the socket, which has
/// nothing more, comes between.
#[test]
fn an_answer_a_layer_holds_is_read_on_at_once_in_done() {
    use crate::conn::layer::testing::holdback;
    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"A003 OK\r\n"],
        false,
    )
    .greeting();
    let mut m = serving(&[&talk]);
    let url = "imap://u:p@127.0.0.1:PORT/Sent";
    let ran = tracing(&mut m, &plain(), url, b"multi", |o| {
        hello(o);
        o.layer = Some(holdback);
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let done = &ran.text[ran.text.find("-> [DONE]").unwrap()..];
    assert!(done.contains("[DONE] -> [COMPLETED]"), "{}", ran.text);
    assert!(!done.contains("multi_wait"), "{}", ran.text);
}

/// An APPEND's answer awaited in DONE that goes on and on is read ten
/// reads a pass, the multi's other transfers going on between, as the
/// answer is awaited without stalling them (`MAX_READS`).
#[test]
fn an_endless_answer_in_done_is_read_ten_reads_a_pass() {
    let talk = Conversation::replies(
        &[GREETING, CAPABILITY, LOGGED_IN, b"+ go\r\n", b"* "],
        false,
    )
    .greeting()
    .endless(std::time::Duration::from_millis(1));
    let mut m = serving(&[&talk]);
    let url = "imap://u:p@127.0.0.1:PORT/Sent";
    let (_, text) = added(&mut m, url, b"", Body(Arc::default()), hello);
    let mut passes = 0;
    while m.info_read().is_none() {
        let reads = talk.endless_reads();
        m.perform(&mut NoEvents).unwrap();
        let read = talk.endless_reads() - reads;
        assert!(read <= 10, "{read} reads in a pass");
        passes += 1;
        assert!(passes < 100, "the transfer ends");
    }
    let said = text_of(&text);
    assert!(talk.endless_reads() > 10, "{said}");
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
    let append = appending();
    append.allow(4);
    let mut m = serving(&[&append]);
    let url = "imap://u:p@127.0.0.1:PORT/Sent";
    let (id, text) = added(&mut m, url, b"", Body(Arc::default()), hello);
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

impl crate::handler::TextSink for Text {
    fn write(&self, text: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(text);
    }
}

/// The lines of the meter a transfer of `url` over `talk` draws.
fn meter(talk: &Conversation, url: &str) -> Vec<String> {
    let mut m = serving(&[talk]);
    let drawn = Text::default();
    let ran = transfer(&mut m, &plain(), url, |o| {
        o.progress = crate::options::Progress::Meter;
        o.callbacks.stderr = Some(Handler::text(drawn.clone()).unwrap());
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let drawn = String::from_utf8(drawn.0.lock().unwrap().clone()).unwrap();
    drawn
        .split(['\r', '\n'])
        .filter(|l| !l.is_empty())
        .skip(2)
        .map(str::to_owned)
        .collect()
}

/// The meter starts over as the request is made (`imap_regular_transfer`'s
/// `Curl_pgrsReset`), drawn again at once: a `LIST` draws C's five lines
/// of nothing (`curl -o /dev/null imap://...` against the C build), a
/// `FETCH` whose literal came whole, which goes from DID to DONE without
/// its request done, C's two.
#[test]
fn the_meter_starts_over_as_the_request_is_made() {
    let zeros = "  0      0   0      0   0      0      0      0                              0";
    let talk =
        Conversation::replies(&[GREETING, CAPABILITY, LOGGED_IN, b"A003 OK\r\n"], false).greeting();
    assert_eq!(meter(&talk, "imap://u:p@127.0.0.1:PORT/"), [zeros; 5]);
    assert_eq!(meter(&fetching(&[]), FETCH_URL), [zeros; 2]);
}

/// The `LOGOUT` the connection says as it closes waits for its tagged
/// answer before the socket closes, past the untagged `BYE` that comes
/// first, as C's `imap_block_statemach` reads on in `IMAP_LOGOUT`; a
/// second at most with nothing more coming, as the C build lets a silent
/// server go after 1.03 s. `answer` is the server's: how long the multi's
/// cleanup took, and how many replies were read.
fn logout_answered(answer: &[&[u8]]) -> (std::time::Duration, usize) {
    use crate::time::Clock as _;
    let talk = fetching(answer);
    let (mut m, clock) = clocked(&[&talk]);
    let ran = transfer(&mut m, &plain(), FETCH_URL, |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let before = clock.now();
    drop(m);
    let sent = String::from_utf8_lossy(&talk.received()).into_owned();
    assert!(sent.ends_with("A005 LOGOUT\r\n"), "{sent}");
    (clock.now().since(before), talk.answered())
}

#[test]
fn logout_waits_for_its_tagged_answer_past_its_bye() {
    let bye: &[u8] = b"* BYE bye\r\nA005 OK done\r\n";
    assert_eq!(logout_answered(&[bye]), (std::time::Duration::ZERO, 6));
    let untagged: &[u8] = b"* BYE bye\r\n";
    let second = std::time::Duration::from_secs(1);
    assert_eq!(logout_answered(&[untagged]), (second, 6));
}

/// A connection closed as its transfer ends waits for its `LOGOUT`'s
/// answer with its socket polled for reading, as C's
/// `imap_block_statemach` polls it (`Curl_pp_statemach`): the answer
/// wakes the multi's wait as it comes.
#[test]
fn logout_awaiting_its_answer_is_polled_for_it() {
    let talk = fetching(&[b"* BYE bye\r\nA005 OK done\r\n"]).held();
    talk.allow(5);
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, &plain(), FETCH_URL, |o| {
        o.limits.reuse.forbid = true;
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.text);
    let sent = String::from_utf8_lossy(&talk.received()).into_owned();
    assert!(sent.ends_with("A005 LOGOUT\r\n"), "{sent}");
    assert_eq!(talk.answered(), 5);
    talk.allow(6);
    let max = std::time::Duration::from_secs(1);
    let ready = m.wait(&mut [], max, crate::multi::WaitMode::Wait, &mut NoEvents);
    assert_eq!(ready, Ok(1));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(talk.answered(), 6);
}
