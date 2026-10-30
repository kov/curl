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
    m.remove(id, &mut NoEvents).unwrap();
    let body = body.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    Ran { result, body, text }
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

/// A transfer goes from DID to PERFORMING while the connection has a
/// socket to exchange on, as C's `recv_idx` says: one after a transfer
/// that set up nothing (a FETCH whose literal came whole) goes to DONE,
/// one on a fresh connection does not (`multistate_did`).
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
    // The answer after the literal is read in PERFORMING, where C goes
    // to DONE and reads it there, blocking (DIVERGENCE.md).
    assert!(ran.text.contains("[DID] -> [PERFORMING]"), "{}", ran.text);
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
