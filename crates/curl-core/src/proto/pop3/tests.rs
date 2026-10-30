use super::*;

/// What `Eob::write` delivers of `pieces`, written one after another
/// after a `+OK` line, and whether the body ended.
fn body_of(pieces: &[&[u8]]) -> (Vec<u8>, bool) {
    let mut eob = Eob::after_ok();
    let mut out = Vec::new();
    let mut ended = false;
    for piece in pieces {
        ended = eob
            .write(piece, &mut |b| {
                out.extend_from_slice(b);
                Ok(())
            })
            .unwrap();
    }
    (out, ended)
}

#[test]
fn the_body_ends_at_a_line_of_a_single_dot() {
    let (out, ended) = body_of(&[b"Hello\r\nworld\r\n.\r\n"]);
    assert_eq!(out, b"Hello\r\nworld\r\n");
    assert!(ended);
}

#[test]
fn an_empty_body_is_its_dot_alone() {
    let (out, ended) = body_of(&[b".\r\n"]);
    assert_eq!(out, b"\r\n");
    assert!(ended);
}

#[test]
fn a_stuffed_dot_is_taken_out() {
    // test 857's
    let (out, ended) = body_of(&[b"line\r\n..dot\r\n.\r\n"]);
    assert_eq!(out, b"line\r\n.dot\r\n");
    assert!(ended);
}

#[test]
fn the_marker_may_come_a_byte_at_a_time() {
    let whole: &[u8] = b"a\r\nb.\r\n..c\r\n.\r\n";
    let pieces: Vec<&[u8]> = whole.chunks(1).collect();
    let (out, ended) = body_of(&pieces);
    assert_eq!(out, b"a\r\nb.\r\n.c\r\n");
    assert!(ended);
}

#[test]
fn a_body_cut_short_has_not_ended() {
    let (out, ended) = body_of(&[b"a\r\nb\r\n."]);
    assert_eq!(out, b"a\r\nb");
    assert!(!ended);
}

#[test]
fn commands_with_lines_are_c_s() {
    assert!(is_multiline(b"RETR"));
    assert!(is_multiline(b"LIST"));
    assert!(!is_multiline(b"LIST 1"));
    assert!(is_multiline(b"TOP 1 0"));
    assert!(!is_multiline(b"DELE"));
    assert!(!is_multiline(b"stat"));
    assert!(is_multiline(b"UIDL"));
    // Unknown, and one that runs on: taken to have lines.
    assert!(is_multiline(b"FOO"));
    assert!(is_multiline(b"DELEX"));
}

#[test]
fn a_sasl_message_is_the_line_s_text() {
    assert_eq!(server_message(b"+ abc \r\n"), b"abc");
    assert_eq!(server_message(b"+\r\n"), b"");
    assert_eq!(server_message(b"+ \r\n"), b"");
    assert_eq!(server_message(b"+\n"), b"");
}

/// The connection's state as a transfer's login options leave it: what
/// the options prefer, and what SASL does.
fn options(given: &[u8]) -> Result<(AuthTypes, Mechs), ErrorKind> {
    use crate::time::Clock as _;
    let now = crate::time::ManualClock::new().unwrap().now();
    let mut pc = Pop3Conn {
        pp: Pingpong::new(now),
        state: State::Stop,
        sasl: Sasl::new(&SASL, crate::options::AuthMethods::BASIC),
        apop: None,
        offered: AuthTypes::NONE,
        preferred: AuthTypes::ANY,
        tls_offered: false,
        cold: None,
    };
    parse_options(&mut pc, given).map(|()| (pc.preferred, pc.sasl.preferred()))
}

/// `AUTH=` takes a SASL mechanism, `*` for any, or `+APOP` or a prefix
/// of it; each `AUTH=` after the first adds to the mechanisms; any other
/// option is malformed (`pop3_parse_url_options`).
#[test]
fn the_login_options_choose_how_to_log_in() {
    assert_eq!(options(b""), Ok((AuthTypes::ANY, Mechs::DEFAULT)));
    assert_eq!(options(b"AUTH=*"), Ok((AuthTypes::ANY, Mechs::DEFAULT)));
    assert_eq!(options(b"auth=plain"), Ok((AuthTypes::SASL, Mechs::PLAIN)));
    assert_eq!(
        options(b"AUTH=PLAIN;AUTH=LOGIN;"),
        Ok((AuthTypes::SASL, Mechs::PLAIN.or(Mechs::LOGIN)))
    );
    assert_eq!(options(b"AUTH=+APOP"), Ok((AuthTypes::APOP, Mechs::NONE)));
    assert_eq!(options(b"AUTH=+ap"), Ok((AuthTypes::APOP, Mechs::NONE)));
    for bad in [
        &b"AUTH=+APOPX"[..],
        b"AUTH=",
        b"AUTH=XYZ",
        b"AUTH",
        b"AUT",
        b"FOO=1",
        b"AUTH=PLAIN;FOO",
    ] {
        assert_eq!(options(bad), Err(ErrorKind::UrlMalformat), "{bad:?}");
    }
}

/// The states are named as C's debug build names them.
#[test]
fn the_states_have_c_s_names() {
    let names = [
        (State::Stop, "STOP"),
        (State::ServerGreet, "SERVERGREET"),
        (State::Capa, "CAPA"),
        (State::StartTls, "STARTTLS"),
        (State::UpgradeTls, "UPGRADETLS"),
        (State::Auth, "AUTH"),
        (State::Apop, "APOP"),
        (State::User, "USER"),
        (State::Pass, "PASS"),
        (State::Command, "COMMAND"),
    ];
    for (state, name) in names {
        assert_eq!(state.name(), name);
    }
    assert_eq!(AuthTypes::CLEARTEXT.0, 1);
    assert_eq!(AuthTypes::APOP.0, 2);
    assert_eq!(AuthTypes::SASL.0, 4);
    assert_eq!(
        [Pop3Reply::Ok, Pop3Reply::Err, Pop3Reply::More].map(char_of),
        ['+', '-', '*']
    );
}

mod over_the_wire {
    //! Transfers over a fake server: the back and forth, STARTTLS, and
    //! which connections a transfer may reuse.

    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use crate::conn::io::{Conversation, FakeNet, Peer as Net};
    use crate::easy::Easy;
    use crate::error::ErrorKind;
    use crate::handler::{
        DebugHandler, DebugKind, Handler, HeaderHandler, HeaderOrigin, Write, WriteHandler,
    };
    use crate::id::ArenaPolicy;
    use crate::libraries::{Libraries, Library, SharedLibraries};
    use crate::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
    use crate::options::{Options, UseSsl};
    use crate::time::ManualClock;
    use crate::tls::fake::{self, FakeTls, WELCOME};

    const PORT: u16 = 8995;

    /// Collects the body.
    struct Body(Arc<Mutex<Vec<u8>>>);

    impl WriteHandler for Body {
        fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
            self.0.lock().unwrap().extend_from_slice(body);
            Write::Took(body.len())
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

    /// The fake TLS library's libraries.
    fn with_tls() -> SharedLibraries {
        let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
        SharedLibraries::new(Libraries {
            tls: Some(Library::Static(backend)),
            ..Libraries::NONE
        })
        .unwrap()
    }

    /// What a transfer's handlers were given: the header lines and the
    /// trace's text.
    #[derive(Clone, Default)]
    struct Seen(Arc<Mutex<(Vec<u8>, Vec<u8>)>>);

    impl HeaderHandler for Seen {
        fn header(&self, _: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
            self.0.lock().unwrap().0.extend_from_slice(line);
            Write::Took(line.len())
        }
    }

    impl DebugHandler for Seen {
        fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
            if kind == DebugKind::Text {
                self.0.lock().unwrap().1.extend_from_slice(data);
            }
        }
    }

    /// What came of a transfer.
    struct Ran {
        result: Result<(), ErrorKind>,
        body: Vec<u8>,
        headers: Vec<u8>,
        text: String,
    }

    /// A verbose transfer of `url` over `m`, set as `set` says.
    fn transfer(
        m: &mut Multi,
        libraries: &SharedLibraries,
        url: &str,
        set: impl FnOnce(&mut Options),
    ) -> Ran {
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        let body = Arc::new(Mutex::new(Vec::new()));
        let seen = Seen::default();
        let o = e.options_mut();
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.output.verbose = true;
        o.callbacks.write = Some(Handler::write(Body(body.clone())).unwrap());
        o.callbacks.header = Some(Handler::header(seen.clone()).unwrap());
        o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
        set(o);
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        let result = drive_to_completion(m, id, &mut NoEvents).unwrap();
        m.remove(id, &mut NoEvents).unwrap();
        let body = body.lock().unwrap().clone();
        let (headers, text) = seen.0.lock().unwrap().clone();
        Ran {
            result,
            body,
            headers,
            text: String::from_utf8_lossy(&text).into_owned(),
        }
    }

    /// Retrieve message 1 as `u:p` over `m`, set as `set` says: what
    /// came of it, and the body.
    fn retrieve(
        m: &mut Multi,
        libraries: &SharedLibraries,
        set: impl FnOnce(&mut Options),
    ) -> (Result<(), ErrorKind>, Vec<u8>) {
        let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
        let ran = transfer(m, libraries, &url, set);
        (ran.result, ran.body)
    }

    fn plain() -> SharedLibraries {
        SharedLibraries::new(Libraries::NONE).unwrap()
    }

    /// One transfer of `url` against a server answering `replies`, after
    /// its greeting, one to each command: what it was sent, and what came
    /// of it.
    fn against(replies: &[&[u8]], url: &str, set: impl FnOnce(&mut Options)) -> (Vec<u8>, Ran) {
        let talk = Conversation::replies(replies, false).greeting();
        let mut m = serving(&[&talk]);
        let url = url.replace("PORT", &PORT.to_string());
        let ran = transfer(&mut m, &plain(), &url, set);
        (talk.received(), ran)
    }

    const GREETING: &[u8] = b"+OK ready\r\n";
    const CAPA: &[u8] = b"+OK\r\nUSER\r\nSTLS\r\n.\r\n";
    const OK: &[u8] = b"+OK\r\n";
    const MESSAGE: &[u8] = b"+OK 9 octets\r\nhello\r\n..dot\r\n.\r\n";

    /// A server that logs the user in in the clear and gives message 1.
    fn in_the_clear() -> Conversation {
        Conversation::replies(&[GREETING, CAPA, OK, OK, MESSAGE], false).greeting()
    }

    #[test]
    fn a_message_is_retrieved_after_a_clear_text_login() {
        let talk = in_the_clear();
        let mut m = serving(&[&talk]);
        let (result, body) = retrieve(
            &mut m,
            &SharedLibraries::new(Libraries::NONE).unwrap(),
            |_| {},
        );
        assert_eq!(result, Ok(()));
        assert_eq!(body, b"hello\r\n.dot\r\n");
        assert_eq!(talk.received(), b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
    }

    /// A server that upgrades to TLS on `STLS`, then logs the user in
    /// and gives message 1 under it; `after` follows its go-ahead in the
    /// same read.
    fn upgrading(after: &[u8]) -> Conversation {
        let mut go_ahead = OK.to_vec();
        go_ahead.extend_from_slice(after);
        let tls = |plain: &[u8]| fake::records(plain).unwrap();
        let replies = [
            GREETING.to_vec(),
            CAPA.to_vec(),
            go_ahead,
            WELCOME.to_vec(),
            tls(b"+OK\r\nUSER\r\n.\r\n"),
            tls(OK),
            tls(OK),
            tls(MESSAGE),
        ];
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        Conversation::replies(&replies, false).greeting()
    }

    #[test]
    fn stls_upgrades_the_connection_before_the_login() {
        let talk = upgrading(b"");
        let mut m = serving(&[&talk]);
        let (result, body) = retrieve(&mut m, &with_tls(), |o| {
            o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        });
        assert_eq!(result, Ok(()));
        assert_eq!(body, b"hello\r\n.dot\r\n");
        let said = talk.received();
        assert!(
            said.starts_with(b"CAPA\r\nSTLS\r\nFAKETLS HELLO"),
            "{said:?}"
        );
        let user = fake::records(b"USER u\r\n").unwrap();
        assert!(said.windows(user.len()).any(|w| w == user), "{said:?}");
        assert!(
            !said.windows(6).any(|w| w == b"USER u"),
            "the login goes under TLS"
        );
    }

    /// Bytes after the go-ahead were not sent under TLS: refused before
    /// the upgrade (test 982).
    #[test]
    fn bytes_after_the_stls_go_ahead_are_refused() {
        let talk = upgrading(b"+OK pipelined\r\n");
        let mut m = serving(&[&talk]);
        let (result, _) = retrieve(&mut m, &with_tls(), |o| {
            o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        });
        assert_eq!(result, Err(ErrorKind::WeirdServerReply));
        assert_eq!(talk.received(), b"CAPA\r\nSTLS\r\n");
    }

    /// A connection logged in as one user serves no transfer of another,
    /// and one in the clear none that requires TLS; one logged in as the
    /// same user is reused.
    #[test]
    fn a_connection_is_reused_only_by_the_same_login_and_tls() {
        let first =
            Conversation::replies(&[GREETING, CAPA, OK, OK, MESSAGE, MESSAGE], false).greeting();
        let other_user = in_the_clear();
        let tls = upgrading(b"");
        let mut m = serving(&[&first, &other_user, &tls]);
        let libraries = with_tls();
        assert_eq!(retrieve(&mut m, &libraries, |_| {}).0, Ok(()));
        // The same login: the connection is reused, no login again.
        assert_eq!(retrieve(&mut m, &libraries, |_| {}).0, Ok(()));
        assert_eq!(
            first.received(),
            b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\nRETR 1\r\n"
        );
        // Another user: a connection of its own.
        let url = format!("pop3://v:p@127.0.0.1:{PORT}/1");
        let (result, _) = retrieve(&mut m, &libraries, |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
        });
        assert_eq!(result, Ok(()));
        assert_eq!(
            other_user.received(),
            b"CAPA\r\nUSER v\r\nPASS p\r\nRETR 1\r\n"
        );
        // TLS required: not over either connection in the clear.
        let (result, _) = retrieve(&mut m, &libraries, |o| {
            o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        });
        assert_eq!(result, Ok(()));
        assert!(tls.received().starts_with(b"CAPA\r\nSTLS\r\n"));
        assert_eq!(
            first.received(),
            b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\nRETR 1\r\n"
        );
    }

    /// The capabilities of a server that takes a user and password.
    const CAPA_USER: &[u8] = b"+OK\r\nUSER\r\n.\r\n";
    /// RFC 1939's APOP example: its greeting, and mrose's digest of it.
    const GREET_APOP: &[u8] = b"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>\r\n";
    const APOP_URL: &str = "pop3://mrose:tanstaaf@127.0.0.1:PORT/1";
    const URL: &str = "pop3://u:p@127.0.0.1:PORT/1";

    /// The greeting's timestamp logs in by APOP, before clear text.
    #[test]
    fn the_greeting_s_timestamp_logs_in_by_apop() {
        let (sent, ran) = against(&[GREET_APOP, CAPA_USER, OK, MESSAGE], APOP_URL, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(
            sent,
            b"CAPA\r\nAPOP mrose c4c9334bac560ecc979e58001b3e22fb\r\nRETR 1\r\n"
        );
        assert_eq!(ran.body, b"hello\r\n.dot\r\n");
        // Each line the server says goes to the header handler.
        let mut lines = GREET_APOP.to_vec();
        lines.extend_from_slice(CAPA_USER);
        lines.extend_from_slice(OK);
        lines.extend_from_slice(b"+OK 9 octets\r\n");
        assert_eq!(ran.headers, lines);
        // The debug build says each change of state, once.
        if cfg!(feature = "debug-hooks") {
            let changes: Vec<&str> = ran
                .text
                .lines()
                .filter_map(|l| l.split_once(" state change from ").map(|(_, c)| c))
                .collect();
            assert_eq!(
                changes,
                [
                    "STOP to SERVERGREET",
                    "SERVERGREET to CAPA",
                    "CAPA to APOP",
                    "APOP to STOP",
                    "STOP to COMMAND",
                    "COMMAND to STOP"
                ],
                "{}",
                ran.text
            );
        }
        let (_, ran) = against(&[GREET_APOP, CAPA_USER, b"-ERR no\r\n"], APOP_URL, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
        assert!(
            ran.text.contains("Authentication failed: -"),
            "{}",
            ran.text
        );
    }

    /// A timestamp is the first bracketed word, and only one with an `@`.
    #[test]
    fn a_greeting_s_first_bracket_without_a_mailbox_offers_no_apop() {
        let greet = b"+OK ready <abc> <1896.697170952@dbc.mtview.ca.us>\r\n";
        let (sent, ran) = against(&[greet, CAPA_USER, OK, OK, MESSAGE], APOP_URL, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(sent, b"CAPA\r\nUSER mrose\r\nPASS tanstaaf\r\nRETR 1\r\n");
        let (sent, ran) = against(&[b"-ERR go away\r\n"], URL, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
        assert!(ran.text.contains("Got unexpected pop3-server response"));
        assert_eq!(sent, b"");
    }

    /// The SASL mechanisms CAPA names, each a word whole, are offered;
    /// a line too short to name a capability is passed over.
    #[test]
    fn the_capabilities_name_the_sasl_mechanisms() {
        let capa = b"+OK\r\nX\r\nSASL  PLAINx\tLOGIN\r\nUSER\r\n.\r\n";
        let replies: [&[u8]; 6] = [
            GREETING,
            capa,
            b"+ VXNlcm5hbWU6\r\n",
            b"+ UGFzc3dvcmQ6\r\n",
            OK,
            MESSAGE,
        ];
        let (sent, ran) = against(&replies, URL, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(sent, b"CAPA\r\nAUTH LOGIN\r\ndQ==\r\ncA==\r\nRETR 1\r\n");
    }

    /// The first response goes with `AUTH` when asked for, acting for
    /// the identity given.
    #[test]
    fn an_initial_response_acts_for_the_identity_given() {
        let capa = b"+OK\r\nSASL PLAIN\r\n.\r\n";
        let (sent, ran) = against(&[GREETING, capa, OK, MESSAGE], URL, |o| {
            o.line.make_mut().unwrap().sasl_ir = true;
            o.login.make_mut().unwrap().authzid = Some(b"boss".to_vec());
        });
        assert_eq!(ran.result, Ok(()));
        assert_eq!(sent, b"CAPA\r\nAUTH PLAIN Ym9zcwB1AHA=\r\nRETR 1\r\n");
    }

    /// A mechanism cancelled with nothing to fall back on fails the
    /// login.
    #[test]
    fn a_cancelled_mechanism_with_nothing_after_it_is_denied() {
        let capa = b"+OK\r\nSASL CRAM-MD5\r\n.\r\n";
        let replies: [&[u8]; 4] = [GREETING, capa, b"+ Rubbish\r\n", b"-ERR\r\n"];
        let (sent, ran) = against(&replies, URL, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
        assert_eq!(sent, b"CAPA\r\nAUTH CRAM-MD5\r\n*\r\n");
        assert!(
            ran.text.contains("Authentication cancelled"),
            "{}",
            ran.text
        );
    }

    /// A server that refuses CAPA is taken to log users in in the clear;
    /// one whose CAPA offers no way leaves nothing to log in with.
    #[test]
    fn a_server_without_capa_takes_clear_text() {
        let (sent, ran) = against(&[GREETING, b"-ERR\r\n", OK, OK, MESSAGE], URL, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(sent, b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
        let (sent, ran) = against(&[GREETING, b"+OK\r\n.\r\n"], URL, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
        assert_eq!(sent, b"CAPA\r\n");
        assert!(
            ran.text
                .contains("SASL: no auth mechanism was offered or recognized")
        );
    }

    /// A user or a password refused is access denied.
    #[test]
    fn a_refused_user_or_password_is_denied() {
        let (sent, ran) = against(&[GREETING, CAPA_USER, b"-ERR\r\n"], URL, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
        assert_eq!(sent, b"CAPA\r\nUSER u\r\n");
        assert!(ran.text.contains("Access denied. -"));
        let (sent, ran) = against(&[GREETING, CAPA_USER, OK, b"-ERR\r\n"], URL, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
        assert_eq!(sent, b"CAPA\r\nUSER u\r\nPASS p\r\n");
    }

    /// TLS tried for goes on in the clear where the server has no `STLS`
    /// or refuses it; TLS required fails there.
    #[test]
    fn tls_tried_for_falls_back_and_tls_required_fails() {
        let tried = |o: &mut Options| o.line.make_mut().unwrap().use_ssl = UseSsl::Try;
        let required = |o: &mut Options| o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        let (sent, ran) = against(&[GREETING, CAPA_USER, OK, OK, MESSAGE], URL, tried);
        assert_eq!(ran.result, Ok(()));
        assert_eq!(sent, b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
        let (sent, ran) = against(&[GREETING, b"-ERR\r\n"], URL, required);
        assert_eq!(ran.result, Err(ErrorKind::UseSslFailed));
        assert_eq!(sent, b"CAPA\r\n");
        assert!(ran.text.contains("STLS not supported."));
        let refused: [&[u8]; 6] = [GREETING, CAPA, b"-ERR\r\n", OK, OK, MESSAGE];
        let (sent, ran) = against(&refused, URL, tried);
        assert_eq!(ran.result, Ok(()));
        assert_eq!(sent, b"CAPA\r\nSTLS\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
        let (sent, ran) = against(&refused[..3], URL, required);
        assert_eq!(ran.result, Err(ErrorKind::UseSslFailed));
        assert_eq!(sent, b"CAPA\r\nSTLS\r\n");
        assert!(ran.text.contains("STARTTLS denied"));
    }

    /// No message is a listing; a message's listing, for a list only, is
    /// one line, no body; the application's command replaces either, its
    /// body as the command's.
    #[test]
    fn the_command_is_a_listing_a_retrieval_or_the_application_s() {
        let login: [&[u8]; 4] = [GREETING, CAPA_USER, OK, OK];
        let with = |last: &'static [u8]| {
            let mut r = login.to_vec();
            r.push(last);
            r
        };
        let listing = b"+OK 2 messages\r\n1 10\r\n2 20\r\n.\r\n";
        let (sent, ran) = against(&with(listing), "pop3://u:p@127.0.0.1:PORT/", |_| {});
        assert_eq!(ran.result, Ok(()));
        assert!(sent.ends_with(b"PASS p\r\nLIST\r\n"));
        assert_eq!(ran.body, b"1 10\r\n2 20\r\n");
        let (sent, ran) = against(&with(b"+OK 1 10\r\n"), URL, |o| {
            o.line.make_mut().unwrap().list_only = true;
        });
        assert_eq!(ran.result, Ok(()));
        assert!(sent.ends_with(b"PASS p\r\nLIST 1\r\n"));
        assert_eq!(ran.body, b"");
        let (sent, ran) = against(&with(OK), URL, |o| {
            o.http.custom.make_mut().unwrap().method = Some(b"DELE".to_vec());
        });
        assert_eq!(ran.result, Ok(()));
        assert!(sent.ends_with(b"PASS p\r\nDELE 1\r\n"));
        assert_eq!(ran.body, b"");
        let (sent, ran) = against(&with(MESSAGE), URL, |o| {
            o.http.custom.make_mut().unwrap().method = Some(Vec::new());
        });
        assert_eq!(ran.result, Ok(()));
        assert!(sent.ends_with(b"PASS p\r\nRETR 1\r\n"));
        assert_eq!(ran.body, b"hello\r\n.dot\r\n");
        let (_, ran) = against(&with(b"-ERR no such message\r\n"), URL, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    }

    /// A body that comes a few bytes a read is read on to its end; sends
    /// the connection refuses for a while go once it takes them.
    #[test]
    fn a_slow_server_is_waited_for_both_ways() {
        let replies: [&[u8]; 5] = [GREETING, CAPA_USER, OK, OK, MESSAGE];
        let talk = Conversation::replies(&replies, false)
            .greeting()
            .giving(std::num::NonZeroUsize::new(3).unwrap());
        let mut m = serving(&[&talk]);
        let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
        let ran = transfer(&mut m, &plain(), &url, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(ran.body, b"hello\r\n.dot\r\n");
        let talk = Conversation::replies(&replies, false)
            .greeting()
            .stalling_sends_after(1, 2);
        let mut m = serving(&[&talk]);
        let ran = transfer(&mut m, &plain(), &url, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(talk.received(), b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
    }

    /// A server that does not answer in time fails the transfer.
    #[test]
    fn a_server_that_does_not_answer_times_out() {
        let (sent, ran) = against(&[GREETING], URL, |o| {
            o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(1000);
        });
        assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
        assert_eq!(sent, b"CAPA\r\n");
        assert!(ran.text.contains("server response timeout"), "{}", ran.text);
    }

    /// `pop3s` speaks TLS from the start.
    #[test]
    fn pop3s_speaks_tls_from_the_start() {
        let tls = |plain: &[u8]| fake::records(plain).unwrap();
        let replies = [
            WELCOME.to_vec(),
            tls(GREETING),
            tls(CAPA_USER),
            tls(OK),
            tls(OK),
            tls(MESSAGE),
        ];
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let talk = Conversation::replies(&replies, false).per_send();
        let mut m = serving(&[&talk]);
        let url = format!("pop3s://u:p@127.0.0.1:{PORT}/1");
        let ran = transfer(&mut m, &with_tls(), &url, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(ran.body, b"hello\r\n.dot\r\n");
        assert!(talk.received().starts_with(b"FAKETLS HELLO"));
    }

    /// A connection upgraded by STLS serves a transfer requiring TLS made
    /// with the same settings, without a login again, and not one whose
    /// TLS would be made otherwise.
    #[test]
    fn an_upgraded_connection_serves_only_the_same_tls_settings() {
        let tls = |plain: &[u8]| fake::records(plain).unwrap();
        let replies = [
            GREETING.to_vec(),
            CAPA.to_vec(),
            OK.to_vec(),
            WELCOME.to_vec(),
            tls(b"+OK\r\nUSER\r\n.\r\n"),
            tls(OK),
            tls(OK),
            tls(MESSAGE),
            tls(MESSAGE),
        ];
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let upgraded = Conversation::replies(&replies, false).greeting();
        let other = upgrading(b"");
        let mut m = serving(&[&upgraded, &other]);
        let libraries = with_tls();
        let required = |o: &mut Options| o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        assert_eq!(retrieve(&mut m, &libraries, required).0, Ok(()));
        let before = upgraded.received().len();
        assert_eq!(
            retrieve(&mut m, &libraries, required),
            (Ok(()), b"hello\r\n.dot\r\n".to_vec())
        );
        let retr = tls(b"RETR 1\r\n");
        assert_eq!(upgraded.received()[before..], retr[..], "reused, logged in");
        assert_eq!(other.received(), b"");
        let (result, _) = retrieve(&mut m, &libraries, |o| {
            required(o);
            o.tls.verify_peer = false;
        });
        assert_eq!(result, Ok(()));
        assert!(other.received().starts_with(b"CAPA\r\nSTLS\r\n"));
    }

    /// A connection over TLS from the start serves a transfer of its
    /// family that may reuse TLS, and asks for it.
    #[test]
    fn a_pop3s_connection_serves_a_pop3_transfer() {
        let tls = |plain: &[u8]| fake::records(plain).unwrap();
        let replies = [
            WELCOME.to_vec(),
            tls(GREETING),
            tls(CAPA_USER),
            tls(OK),
            tls(OK),
            tls(MESSAGE),
            tls(MESSAGE),
        ];
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let secure = Conversation::replies(&replies, false).per_send();
        let mut m = serving(&[&secure]);
        let libraries = with_tls();
        let url = format!("pop3s://u:p@127.0.0.1:{PORT}/1");
        assert_eq!(transfer(&mut m, &libraries, &url, |_| {}).result, Ok(()));
        let before = secure.received().len();
        let (result, body) = retrieve(&mut m, &libraries, |o| {
            o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        });
        assert_eq!(result, Ok(()));
        assert_eq!(body, b"hello\r\n.dot\r\n");
        assert_eq!(secure.received()[before..], tls(b"RETR 1\r\n")[..]);
    }

    /// A connection that logged in as no one serves no transfer with
    /// credentials.
    #[test]
    fn a_connection_without_a_login_serves_none_with_one() {
        let anonymous = Conversation::replies(&[GREETING, CAPA_USER, MESSAGE], false).greeting();
        let named = in_the_clear();
        let mut m = serving(&[&anonymous, &named]);
        let url = format!("pop3://127.0.0.1:{PORT}/1");
        assert_eq!(transfer(&mut m, &plain(), &url, |_| {}).result, Ok(()));
        assert_eq!(anonymous.received(), b"CAPA\r\nRETR 1\r\n");
        assert_eq!(retrieve(&mut m, &plain(), |_| {}).0, Ok(()));
        assert_eq!(named.received(), b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
    }

    /// A `.netrc` entry logs in where the URL names no one, but not one
    /// with a control byte, which POP3 takes in no credentials.
    #[test]
    fn a_netrc_entry_logs_in_without_control_bytes() {
        use crate::options::NetrcMode;
        let path =
            std::env::temp_dir().join(format!("curl-core-pop3-netrc-{}", std::process::id()));
        let file = path.as_os_str().as_encoded_bytes().to_vec();
        let netrc = |o: &mut Options| {
            o.netrc.make_mut().unwrap().mode = NetrcMode::Required;
            o.netrc.make_mut().unwrap().file = Some(file.clone());
        };
        let anonymous = "pop3://127.0.0.1:PORT/1";
        std::fs::write(&path, b"machine 127.0.0.1 login nu password np\n").unwrap();
        let (sent, ran) = against(&[GREETING, CAPA_USER, OK, OK, MESSAGE], anonymous, netrc);
        assert_eq!(ran.result, Ok(()));
        assert_eq!(sent, b"CAPA\r\nUSER nu\r\nPASS np\r\nRETR 1\r\n");
        for entry in [
            &b"machine 127.0.0.1 login nu password \"n\\rp\"\n"[..],
            b"machine 127.0.0.1 login \"n\\ru\" password np\n",
        ] {
            std::fs::write(&path, entry).unwrap();
            let (sent, ran) = against(&[GREETING], anonymous, netrc);
            assert_eq!(ran.result, Err(ErrorKind::ReadError));
            assert_eq!(sent, b"");
            assert!(
                ran.text
                    .contains("control code detected in .netrc credentials"),
                "{}",
                ran.text
            );
        }
        std::fs::remove_file(&path).unwrap();
    }

    /// Without a TLS library, `pop3s` is a protocol the build leaves out.
    #[test]
    fn pop3s_needs_a_tls_library() {
        let (sent, ran) = against(&[GREETING], "pop3s://u:p@127.0.0.1:PORT/1", |_| {});
        assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
        assert_eq!(sent, b"");
    }
}
