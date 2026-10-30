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

mod over_the_wire {
    //! Transfers over a fake server: the back and forth, STARTTLS, and
    //! which connections a transfer may reuse.

    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use crate::conn::io::{Conversation, FakeNet, Peer as Net};
    use crate::easy::Easy;
    use crate::error::ErrorKind;
    use crate::handler::{Handler, Write, WriteHandler};
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

    /// Retrieve message 1 as `u:p` over `m`, set as `set` says: what
    /// came of it, and the body.
    fn retrieve(
        m: &mut Multi,
        libraries: &SharedLibraries,
        set: impl FnOnce(&mut Options),
    ) -> (Result<(), ErrorKind>, Vec<u8>) {
        let mut e = Easy::new();
        e.set_libraries(libraries.clone());
        let body = Arc::new(Mutex::new(Vec::new()));
        let o = e.options_mut();
        let url = format!("pop3://u:p@127.0.0.1:{PORT}/1");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.total = crate::time::TimeLimit::from_millis(10_000);
        o.callbacks.write = Some(Handler::write(Body(body.clone())).unwrap());
        set(o);
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        let result = drive_to_completion(m, id, &mut NoEvents).unwrap();
        m.remove(id, &mut NoEvents).unwrap();
        let body = body.lock().unwrap().clone();
        (result, body)
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
}
