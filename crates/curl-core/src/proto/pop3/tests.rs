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
        /// How long it took, start to end.
        total: std::time::Duration,
    }

    /// A verbose transfer of `url` over `m`, set as `set` says.
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
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        let traced = crate::components::Components::new().unwrap();
        traced.configure(components);
        e.set_components(Some(traced));
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
        let removed = m.remove(id, &mut NoEvents).unwrap();
        let total = removed.easy.report().timings().total();
        let body = body.lock().unwrap().clone();
        let (headers, text) = seen.0.lock().unwrap().clone();
        Ran {
            result,
            body,
            headers,
            text: String::from_utf8_lossy(&text).into_owned(),
            total,
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

    /// The server's time to answer is its own timer, `SERVER_RESPONSE`,
    /// set for what is left of it each time the back and forth is
    /// driven, and still armed as the transfer completes, as C's
    /// `Curl_pp_statemach` sets it and never clears it.
    #[test]
    fn the_server_s_time_to_answer_is_its_own_timer() {
        let talk = in_the_clear();
        let mut m = serving(&[&talk]);
        let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
        let ran = tracing(&mut m, &plain(), &url, b"timer,multi", |o| {
            o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(2500);
        });
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
        // The connection says QUIT as it closes.
        drop(m);
        assert_eq!(
            talk.received(),
            b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\nQUIT\r\n"
        );
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

    /// One transfer of `URL` against a server answering `replies`, after
    /// its greeting: what it was sent once the multi is gone, its
    /// connection's goodbye included, and what came of it.
    fn against_to_the_end(replies: &[&[u8]], set: impl FnOnce(&mut Options)) -> (Vec<u8>, Ran) {
        let talk = Conversation::replies(replies, false).greeting();
        let mut m = serving(&[&talk]);
        let url = URL.replace("PORT", &PORT.to_string());
        let ran = transfer(&mut m, &plain(), &url, set);
        drop(m);
        (talk.received(), ran)
    }

    /// A server that does not answer the login in time fails the
    /// transfer, cut short in PROTOCONNECTING: its connection is closed
    /// without a `QUIT` (`multistate_protoconnecting`'s premature
    /// `multi_done`), as the C build does.
    #[test]
    fn a_server_that_does_not_answer_times_out() {
        let (sent, ran) = against_to_the_end(&[GREETING], |o| {
            o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(1000);
        });
        assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
        assert_eq!(sent, b"CAPA\r\n");
        assert!(ran.text.contains("server response timeout"), "{}", ran.text);
        assert!(ran.text.contains("closing connection #0"), "{}", ran.text);
    }

    /// The transfer's own time running out while the command waits for
    /// its answer cuts it short: no `QUIT` (`multi_handle_timeout`'s
    /// premature `multi_done`), as the C build does.
    #[test]
    fn a_transfer_out_of_time_says_no_quit() {
        let (sent, ran) = against_to_the_end(&[GREETING, CAPA_USER, OK, OK], |o| {
            o.limits.total = crate::time::TimeLimit::from_millis(1000);
        });
        assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
        assert_eq!(sent, b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
        assert!(ran.text.contains("closing connection #0"), "{}", ran.text);
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

    /// `AUTH`, the mechanism, a space, the initial response and CRLF fit
    /// POP3's line of 255: a response that would not goes after the
    /// server's prompt.
    #[test]
    fn an_initial_response_fits_pop3_s_line() {
        let capa = b"+OK\r\nSASL PLAIN\r\n.\r\n";
        let auth_line = |user_len: usize| {
            let url = format!("pop3://{}:@127.0.0.1:PORT/1", "u".repeat(user_len));
            let (sent, _) = against(&[GREETING, capa, OK, MESSAGE], &url, |o| {
                o.line.make_mut().unwrap().sasl_ir = true;
            });
            let line = sent.split(|&b| b == b'\n').nth(1).unwrap().to_vec();
            String::from_utf8(line).unwrap()
        };
        // Two zero bytes and 178: 180 bytes, 240 encoded, 245 with PLAIN.
        assert_eq!(auth_line(178).len(), "AUTH PLAIN ".len() + 240 + 1);
        // 183 bytes, 244 encoded: 249, over 247.
        assert_eq!(auth_line(181), "AUTH PLAIN\r");
    }

    /// A server that does not answer the command in time fails it too,
    /// in DOING, which is not cut short: the connection is shut down
    /// with a `QUIT` (`multistate_doing`'s `multi_done`, not premature),
    /// as the C build does.
    #[test]
    fn a_server_that_does_not_answer_the_command_times_out() {
        let (sent, ran) = against_to_the_end(&[GREETING, CAPA_USER, OK, OK], |o| {
            o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(1000);
        });
        assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
        assert_eq!(sent, b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\nQUIT\r\n");
        assert!(ran.text.contains("server response timeout"), "{}", ran.text);
        assert!(
            ran.text.contains("shutting down connection #0"),
            "{}",
            ran.text
        );
    }

    /// A server that closes before it answers fails the read, said as C
    /// says it.
    #[test]
    fn a_server_that_closes_fails_the_read() {
        let talk = Conversation::replies(&[GREETING], true).greeting();
        let mut m = serving(&[&talk]);
        let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
        let ran = transfer(&mut m, &plain(), &url, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::RecvError));
        assert!(
            ran.text.contains("response reading failed (errno: 0)"),
            "{}",
            ran.text
        );
    }

    /// Retrieve message 1 twice over `m`, the second set as `set` says:
    /// what came of the second.
    fn twice(m: &mut Multi, set: impl FnOnce(&mut Options)) -> Ran {
        let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
        let first = transfer(m, &plain(), &url, |_| {});
        assert_eq!(first.result, Ok(()));
        transfer(m, &plain(), &url, set)
    }

    /// A server whose connection breaks once the first transfer is over:
    /// a send after its first four fails.
    fn breaking() -> Conversation {
        Conversation::replies(&[GREETING, CAPA_USER, OK, OK, MESSAGE], false)
            .greeting()
            .breaking_after(4)
    }

    /// A reused connection whose peer is gone fails the command's send:
    /// the request, which nothing came back for, is made again on a fresh
    /// connection, as a retry of a protocol without HTTP's follow is,
    /// nothing said of another request (`multistate_do`,
    /// `Curl_retry_request`, `multi_follow`).
    #[test]
    fn a_command_a_reused_connection_cannot_send_is_retried() {
        let first = breaking();
        let fresh = in_the_clear();
        let mut m = serving(&[&first, &fresh]);
        let ran = twice(&mut m, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(ran.body, b"hello\r\n.dot\r\n");
        assert_eq!(fresh.received(), b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
        let retried = "Connection died, retrying a fresh connect (retry count: 1)";
        assert!(ran.text.contains(retried), "{}", ran.text);
        assert!(!ran.text.contains("Issue another request"), "{}", ran.text);
    }

    /// No body wanted (`NOBODY`), the request is not made again: C's
    /// `req.no_body` stands until the command is sent.
    #[test]
    fn a_command_wanting_no_body_is_not_retried() {
        let first = breaking();
        let fresh = in_the_clear();
        let mut m = serving(&[&first, &fresh]);
        let ran = twice(&mut m, |o| o.method = crate::options::Method::Head);
        assert_eq!(ran.result, Err(ErrorKind::SendError));
        assert_eq!(fresh.received(), b"");
        assert!(!ran.text.contains("Connection died"), "{}", ran.text);
    }

    /// A reused connection reset once the command's answer came, before
    /// any of its body: the answer's line was read (`headerbytecount`),
    /// so the request is not made again, and the read's failure stands.
    #[test]
    fn a_reset_after_the_answer_is_not_retried() {
        let replies: [&[u8]; 6] = [GREETING, CAPA_USER, OK, OK, MESSAGE, b"+OK 9 octets\r\n"];
        let first = Conversation::replies(&replies, false)
            .greeting()
            .resetting();
        let fresh = in_the_clear();
        let mut m = serving(&[&first, &fresh]);
        let ran = twice(&mut m, |_| {});
        assert_eq!(ran.result, Err(ErrorKind::RecvError));
        assert_eq!(fresh.received(), b"");
        assert!(!ran.text.contains("Connection died"), "{}", ran.text);
    }

    /// A read that fails, during the login or the body, fails the
    /// transfer, said once: by the socket, as C's socket filter says it,
    /// or else by the protocol, for a layer that failed without saying
    /// why (the fake TLS library's record it cannot read).
    #[test]
    fn a_read_failure_is_said_once() {
        let tls = |plain: &[u8]| fake::records(plain).unwrap();
        let garbage: &[u8] = b"not a record";
        let mut body = tls(b"+OK 9 octets\r\nhel");
        body.extend_from_slice(garbage);
        let secure = [
            WELCOME.to_vec(),
            tls(GREETING),
            tls(CAPA_USER),
            tls(OK),
            tls(OK),
            body,
        ];
        let secure: Vec<&[u8]> = secure.iter().map(Vec::as_slice).collect();
        let mut login = secure[..2].to_vec();
        login.push(garbage);
        let plain_body: [&[u8]; 5] = [GREETING, CAPA_USER, OK, OK, b"+OK 9 octets\r\nhel"];
        let cases = [
            (
                Conversation::replies(&[GREETING], false)
                    .greeting()
                    .resetting(),
                "pop3",
                false,
            ),
            (
                Conversation::replies(&plain_body, false)
                    .greeting()
                    .resetting(),
                "pop3",
                true,
            ),
            (
                Conversation::replies(&login, false).per_send(),
                "pop3s",
                false,
            ),
            (
                Conversation::replies(&secure, false).per_send(),
                "pop3s",
                true,
            ),
        ];
        for (talk, scheme, has_body) in cases {
            let mut m = serving(&[&talk]);
            let url = format!("{scheme}://u:p@127.0.0.1:{PORT}/1");
            let ran = transfer(&mut m, &with_tls(), &url, |_| {});
            assert_eq!(ran.result, Err(ErrorKind::RecvError), "{}", ran.text);
            let body: &[u8] = if has_body { b"hel" } else { b"" };
            assert_eq!(ran.body, body);
            let failures = ran
                .text
                .lines()
                .filter(|l| l.starts_with("Recv failure: "))
                .count();
            assert_eq!(failures, 1, "{scheme}: {}", ran.text);
            // A body's read failing ends its pass of `sendrecv_dl`, as C's
            // debug build says.
            let said = ran.text.contains("sendrecv_dl() -> 56\n");
            let debug = cfg!(feature = "debug-hooks");
            assert_eq!(said, has_body && debug, "{scheme}: {}", ran.text);
        }
    }

    /// A connection upgraded by STLS serves a transfer that does not ask
    /// for TLS, of its family, only if that transfer would make TLS with
    /// the same settings (`url_match_ssl_use`'s
    /// `Curl_ssl_conn_config_match`).
    #[test]
    fn an_upgraded_connection_serves_a_transfer_not_asking_for_tls_alike() {
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
        let clear = in_the_clear();
        let mut m = serving(&[&upgraded, &clear]);
        let libraries = with_tls();
        let required = |o: &mut Options| o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        assert_eq!(retrieve(&mut m, &libraries, required).0, Ok(()));
        let before = upgraded.received().len();
        assert_eq!(
            retrieve(&mut m, &libraries, |_| {}),
            (Ok(()), b"hello\r\n.dot\r\n".to_vec())
        );
        assert_eq!(upgraded.received()[before..], tls(b"RETR 1\r\n")[..]);
        assert_eq!(clear.received(), b"");
        let (result, _) = retrieve(&mut m, &libraries, |o| o.tls.verify_peer = false);
        assert_eq!(result, Ok(()));
        assert_eq!(clear.received(), b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
    }

    /// A POP3 transfer through an HTTP proxy tunnels: an HTTP proxy
    /// cannot be handed a POP3 request (`Curl_init_proxy`).
    #[test]
    fn pop3_tunnels_through_an_http_proxy() {
        let mut tunnel = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
        tunnel.extend_from_slice(GREETING);
        let replies: [&[u8]; 5] = [&tunnel, CAPA_USER, OK, OK, MESSAGE];
        let talk = Conversation::replies(&replies, false).per_send();
        let mut m = serving(&[&talk]);
        let url = format!("pop3://u:p@pop.example:{PORT}/1");
        let ran = transfer(&mut m, &plain(), &url, |o| {
            o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        });
        assert_eq!(ran.result, Ok(()), "{}", ran.text);
        assert_eq!(ran.body, b"hello\r\n.dot\r\n");
        let sent = talk.received();
        let connect = format!("CONNECT pop.example:{PORT} HTTP/1.1\r\n");
        assert!(sent.starts_with(connect.as_bytes()), "{sent:?}");
        let commands = b"\r\n\r\nCAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n";
        assert!(sent.ends_with(commands), "{sent:?}");
    }

    /// Each line the server says is written to the application as
    /// information, not a header (`CLIENTWRITE_INFO`, type 2), as the C
    /// build's write trace has it.
    #[test]
    fn the_server_s_lines_are_written_as_information() {
        let talk = in_the_clear();
        let mut m = serving(&[&talk]);
        let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
        let ran = tracing(&mut m, &plain(), &url, b"write", |_| {});
        assert_eq!(ran.result, Ok(()));
        for line in [
            "[WRITE] download_write header(type=2, blen=11) -> 0",
            "[WRITE] client_write(type=2, len=11) -> 0",
            "[WRITE] client_write(type=2, len=14) -> 0",
        ] {
            assert!(ran.text.lines().any(|l| l == line), "{line}: {}", ran.text);
        }
    }

    /// The server's lines start no response's time: a command answered
    /// with no body marks none, where a body marks it as it comes, as the
    /// C build's `-w %{time_starttransfer}` has it (`cw_download_write`,
    /// with `upload_done` never set).
    #[test]
    fn only_a_body_starts_the_response_s_time() {
        let marked = |custom: &[u8], last: &[u8]| {
            let talk =
                Conversation::replies(&[GREETING, CAPA_USER, OK, OK, last], false).greeting();
            let mut m = serving(&[&talk]);
            let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
            let ran = tracing(&mut m, &plain(), &url, b"multi", |o| {
                o.http.custom.make_mut().unwrap().method = Some(custom.to_vec());
            });
            assert_eq!(ran.result, Ok(()), "{}", ran.text);
            assert!(
                ran.text.contains("[MULTI] [DID] -> [PERFORMING]"),
                "{}",
                ran.text
            );
            ran.text.contains("[PGRS-STARTTRANSFER]")
        };
        assert!(!marked(b"DELE", OK));
        assert!(marked(b"RETR", MESSAGE));
    }

    /// The back and forth reads only once the socket says something
    /// came: a server that has said nothing is not read (C's
    /// `Curl_socket_check` before `Curl_pp_readresp`).
    #[test]
    fn a_silent_server_is_not_read() {
        let talk = Conversation::replies(&[GREETING], false).greeting().held();
        let mut m = serving(&[&talk]);
        let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
        let ran = tracing(&mut m, &plain(), &url, b"tcp", |o| {
            o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(1000);
        });
        assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
        assert!(ran.text.contains("server response timeout"), "{}", ran.text);
        assert!(!ran.text.contains("[TCP] recv("), "{}", ran.text);
    }

    /// The server's time to answer wakes the transfer as it runs out,
    /// and runs from the transfer's whole time once the request is being
    /// made, not from the connect's (`Curl_pp_state_timeleft_ms`,
    /// `Curl_timeleft_ms`).
    #[test]
    fn the_time_to_answer_wakes_the_transfer_and_outlives_the_connect_s() {
        let (sent, ran) = against(&[GREETING, CAPA_USER, OK, OK], URL, |o| {
            o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(2500);
            o.limits.connect = crate::time::TimeLimit::from_millis(1000);
        });
        assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
        assert!(sent.ends_with(b"RETR 1\r\nQUIT\r\n"), "{sent:?}");
        assert!(ran.text.contains("server response timeout"), "{}", ran.text);
        let total = ran.total.as_millis();
        assert!((2500..2600).contains(&total), "{total} ms");
    }

    /// A transfer of message 1 as `u:p` added to `m` and not driven, set
    /// as `set` says, its body kept by `writer` and its trace's text in
    /// the `Seen`.
    fn added(
        m: &mut Multi,
        libraries: &SharedLibraries,
        components: &[u8],
        writer: impl WriteHandler + 'static,
        set: impl FnOnce(&mut Options),
    ) -> (crate::multi::TransferId, Seen) {
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        let traced = crate::components::Components::new().unwrap();
        traced.configure(components);
        e.set_components(Some(traced));
        let seen = Seen::default();
        let o = e.options_mut();
        let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
        o.callbacks.write = Some(Handler::write(writer).unwrap());
        o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
        set(o);
        (m.add(Box::new(e), (), &mut NoEvents).unwrap(), seen)
    }

    /// What the transfers of `m` wait for on their sockets.
    fn waits(m: &mut Multi) -> Vec<crate::conn::io::Events> {
        let mut seen = Vec::new();
        m.sockets(&mut NoEvents, |_, events| seen.push(events))
            .unwrap();
        seen
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

    /// Lines past the end of a reply wait for the next command, which
    /// takes the first of them as its answer: the state machine stops at
    /// the reply that ends its state, and the next step runs on what it
    /// holds without waiting on the socket (`pop3_statemachine`'s loop,
    /// `Curl_pp_moredata`). The phase is said done as its state stops,
    /// the answer refused (`pop3_perform`).
    #[test]
    fn lines_past_a_reply_answer_the_next_command() {
        let (sent, ran) = against(
            &[GREETING, CAPA_USER, OK, b"+OK\r\n-ERR early\r\n"],
            URL,
            |_| {},
        );
        assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply), "{}", ran.text);
        assert!(sent.ends_with(b"PASS p\r\nRETR 1\r\nQUIT\r\n"), "{sent:?}");
        // As C's debug build says it.
        if cfg!(feature = "debug-hooks") {
            let after = ran
                .text
                .split("DO phase starts\n")
                .nth(1)
                .unwrap_or_default();
            assert!(
                after.contains("to STOP\nDO phase is complete\n"),
                "{}",
                ran.text
            );
        }
        assert!(
            !ran.text.contains("server response timeout"),
            "{}",
            ran.text
        );
    }

    /// An answer is read 900 bytes at a time, at most ten reads a pass,
    /// and a read that comes short ends the pass without another
    /// (`Curl_pp_readresp`): the reads the C build traces for a password's
    /// answer after many lines that end no reply.
    #[test]
    fn a_long_answer_is_read_ten_reads_a_pass() {
        let mut pass = Vec::new();
        for i in 0..120 {
            pass.extend_from_slice(format!("X-JUNK-{i:03} {}\r\n", "y".repeat(85)).as_bytes());
        }
        pass.extend_from_slice(OK);
        let replies: [&[u8]; 5] = [GREETING, CAPA_USER, OK, &pass, b"+OK deleted\r\n"];
        let talk = Conversation::replies(&replies, false).greeting();
        let mut m = serving(&[&talk]);
        let (id, seen) = added(&mut m, &plain(), b"tcp", Body(Arc::default()), |o| {
            o.http.custom.make_mut().unwrap().method = Some(b"DELE".to_vec());
        });
        let reads = |seen: &Seen| {
            let text = seen.0.lock().unwrap().1.clone();
            String::from_utf8_lossy(&text)
                .matches("[TCP] recv(")
                .count()
        };
        let mut passes = Vec::new();
        for _ in 0..100 {
            let before = reads(&seen);
            m.perform(&mut NoEvents).unwrap();
            passes.push(reads(&seen) - before);
            if m.info_read().is_some() {
                break;
            }
        }
        assert!(passes.contains(&10), "{passes:?}");
        assert!(passes.iter().all(|&n| n <= 10), "{passes:?}");
        m.remove(id, &mut NoEvents).unwrap();
        let text = seen.0.lock().unwrap().1.clone();
        let reads: Vec<&str> = std::str::from_utf8(&text)
            .unwrap()
            .lines()
            .filter_map(|l| l.strip_prefix("[TCP] recv("))
            .collect();
        let mut want = vec!["len=900) -> 0, 11", "len=900) -> 0, 14", "len=900) -> 0, 5"];
        want.extend(std::iter::repeat_n("len=900) -> 0, 900", 13));
        want.extend(["len=900) -> 0, 65", "len=900) -> 0, 13"]);
        assert_eq!(reads, want);
    }

    /// A body step reads at most eleven times, and is run again at once,
    /// as C's debug build says (`sendrecv_dl`'s `maxloops`).
    #[test]
    fn a_body_step_reads_eleven_times_at_most() {
        let talk = Conversation::replies(&[GREETING, CAPA_USER, OK, OK, OK], false)
            .greeting()
            .endless(std::time::Duration::from_millis(1));
        let mut m = serving(&[&talk]);
        let (_, seen) = added(&mut m, &plain(), b"multi", Body(Arc::default()), |_| {});
        while talk.endless_reads() == 0 {
            m.perform(&mut NoEvents).unwrap();
        }
        for _ in 0..3 {
            let reads = talk.endless_reads();
            m.perform(&mut NoEvents).unwrap();
            assert_eq!(talk.endless_reads() - reads, 11);
            assert_eq!(m.timeout(), Some(std::time::Duration::ZERO));
        }
        let text = String::from_utf8(seen.0.lock().unwrap().1.clone()).unwrap();
        let line = "[MULTI] [PERFORMING] sendrecv_dl() no EAGAIN/pending data, mark as dirty\n";
        // The body's first pass, and the three after it.
        assert_eq!(text.matches(line).count(), 4, "{text}");
    }

    /// A body not yet whole waits to read its socket, and paused, on
    /// nothing (`Curl_pp_pollset`'s body half, `KEEP_RECV`).
    #[test]
    fn a_body_to_come_waits_on_its_socket_unless_paused() {
        use crate::conn::io::Events;
        use crate::deliver::PauseRequest;
        let talk =
            Conversation::replies(&[GREETING, CAPA_USER, OK, OK, b"+OK\r\nhel"], false).greeting();
        let mut m = serving(&[&talk]);
        let (id, _) = added(&mut m, &plain(), b"", Body(Arc::default()), |_| {});
        for _ in 0..20 {
            m.perform(&mut NoEvents).unwrap();
        }
        assert_eq!(talk.received(), b"CAPA\r\nUSER u\r\nPASS p\r\nRETR 1\r\n");
        assert_ne!(m.timeout(), Some(std::time::Duration::ZERO));
        assert_eq!(waits(&mut m), [Events::IN]);
        m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
        assert_eq!(waits(&mut m), []);
    }

    /// Body bytes a layer holds, where a poll cannot see them, have the
    /// step itself run the transfer again at once, as C's debug build
    /// says, not only the pollset that finds them after
    /// (`sendrecv_dl`'s `data_pending`, and `multi_adjust_pollset`'s).
    #[test]
    fn body_bytes_a_layer_holds_are_read_without_waiting() {
        use crate::conn::layer::testing::holdback;
        let talk = Conversation::replies(&[GREETING, CAPA_USER, OK, OK, OK], false)
            .greeting()
            .endless(std::time::Duration::from_millis(1));
        let mut m = serving(&[&talk]);
        let (_, seen) = added(&mut m, &plain(), b"multi", Body(Arc::default()), |o| {
            o.layer = Some(holdback);
        });
        while talk.endless_reads() < 3 {
            m.perform(&mut NoEvents).unwrap();
        }
        let text = String::from_utf8(seen.0.lock().unwrap().1.clone()).unwrap();
        let line = "[MULTI] [PERFORMING] sendrecv_dl() no EAGAIN/pending data, mark as dirty\n";
        assert!(text.contains(line), "{text}");
    }

    /// A body whose writer paused holds the transfer open until it is
    /// delivered (`Curl_cwriter_is_paused`).
    #[test]
    fn a_paused_body_holds_the_transfer_open() {
        use crate::deliver::PauseRequest;
        let talk = in_the_clear();
        let mut m = serving(&[&talk]);
        let writer = PausesOnce::default();
        let (id, _) = added(&mut m, &plain(), b"", writer.clone(), |_| {});
        for _ in 0..20 {
            m.perform(&mut NoEvents).unwrap();
        }
        assert!(writer.paused.get(), "paused");
        assert!(m.info_read().is_none(), "not over while output is held");
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(*writer.got.lock().unwrap(), b"hello\r\n.dot\r\n");
    }

    /// POP3S offers nothing by ALPN: only HTTP's schemes do
    /// (`PROTOPT_ALPN`).
    #[test]
    fn pop3s_offers_no_alpn() {
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
        let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
        let libraries = SharedLibraries::new(Libraries {
            tls: Some(Library::Static(backend)),
            ..Libraries::NONE
        })
        .unwrap();
        let url = format!("pop3s://u:p@127.0.0.1:{PORT}/1");
        let ran = transfer(&mut m, &libraries, &url, |_| {});
        assert_eq!(ran.result, Ok(()));
        assert_eq!(backend.log().alpn, Some(crate::tls::Alpn::None));
    }

    /// A redirect from HTTP to another host takes the application's
    /// login there only if it lets it go anywhere; the redirect's own
    /// user goes all the same (`Curl_auth_allowed_to_host`).
    #[test]
    fn the_application_s_login_stays_with_the_first_host() {
        use crate::options::{Follow, Login, Protocols};
        for unrestricted in [false, true] {
            let location = format!("pop3://v@other.test:{PORT}/1");
            let moved = format!(
                "HTTP/1.1 302 Moved\r\nLocation: {location}\r\nConnection: close\r\n\
                 Content-Length: 0\r\n\r\n"
            );
            let http = Conversation::new(moved.as_bytes(), true);
            let capa = b"+OK\r\nSASL PLAIN\r\n.\r\n";
            let pop3 =
                Conversation::replies(&[GREETING, capa, b"+ \r\n", OK, MESSAGE], false).greeting();
            let mut m = serving(&[&http, &pop3]);
            let entry = format!("other.test:{PORT}:127.0.0.1");
            let url = format!("http://127.0.0.1:{PORT}/a");
            let ran = transfer(&mut m, &plain(), &url, |o| {
                o.http.follow = Follow::All;
                o.http.unrestricted_auth = unrestricted;
                o.schemes.make_mut().unwrap().redirect = Protocols::of(&["pop3"]).unwrap();
                o.resolve.set([entry.as_bytes()]).unwrap();
                *o.login.make_mut().unwrap() = Login::from_pair(b"user:secret").unwrap();
            });
            assert_eq!(ran.result, Ok(()), "{}", ran.text);
            assert_eq!(ran.body, b"hello\r\n.dot\r\n");
            let said = pop3.received();
            // PLAIN: the authorization identity, the user and the
            // password, each after a zero byte.
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

    /// Takes what the meter draws.
    #[derive(Clone, Default)]
    struct Drawn(Arc<Mutex<Vec<u8>>>);

    impl crate::handler::TextSink for Drawn {
        fn write(&self, text: &[u8]) {
            self.0.lock().unwrap().extend_from_slice(text);
        }
    }

    /// The meter starts over as the request is made
    /// (`pop3_regular_transfer`'s `Curl_pgrsReset`), drawn again at once:
    /// a `RETR` draws C's two lines of nothing, then its three with the
    /// body (`curl -o /dev/null pop3://...` against the C build).
    #[test]
    fn the_meter_starts_over_as_the_request_is_made() {
        // The body comes after the request is made, as from C's server.
        let talk = in_the_clear().late_replies();
        let mut m = serving(&[&talk]);
        let drawn = Drawn::default();
        let (result, _) = retrieve(&mut m, &plain(), |o| {
            o.progress = crate::options::Progress::Meter;
            o.callbacks.stderr = Some(Handler::text(drawn.clone()).unwrap());
        });
        assert_eq!(result, Ok(()));
        let drawn = String::from_utf8(drawn.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = drawn
            .split(['\r', '\n'])
            .filter(|l| !l.is_empty())
            .skip(2)
            .collect();
        let zeros = "  0      0   0      0   0      0      0      0                              0";
        assert_eq!(lines.len(), 5, "{lines:?}");
        assert_eq!(lines[..2], [zeros; 2]);
        assert!(lines[2..].iter().all(|l| l.starts_with("100")), "{lines:?}");
    }
}
