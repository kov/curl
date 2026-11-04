use super::*;
use crate::conn::io::Conversation;
use crate::proto::raw::wire::{against, serving, transfer};

fn asked(path: &[u8]) -> Option<(String, bool)> {
    request_of(path)
        .unwrap()
        .map(|(r, missing)| (String::from_utf8(r).unwrap(), missing))
}

fn sent(path: &str) -> Option<String> {
    asked(path.as_bytes()).map(|(r, _)| r)
}

/// The answer's end goes through the writers.
#[test]
fn a_lookup_ends_through_the_writers() {
    let talk = Conversation::new(b"151 x\r\n.\r\n", true).per_send();
    crate::proto::raw::wire::ends_through_the_writers(&talk, "dict://127.0.0.1:PORT/d:x");
}

/// `MATCH`'s word, database and strategy are the path's fields, each
/// missing one C's default; a fifth field is cut off.
#[test]
fn a_match_takes_its_fields_from_the_path() {
    assert_eq!(
        sent("/MATCH:word:db:strat:5").as_deref(),
        Some("MATCH db strat word")
    );
    assert_eq!(sent("/m:word").as_deref(), Some("MATCH ! . word"));
    assert_eq!(sent("/find:word::").as_deref(), Some("MATCH ! . word"));
    assert_eq!(sent("/M:word:db").as_deref(), Some("MATCH db . word"));
    assert_eq!(asked(b"/m:"), Some(("MATCH ! . default".into(), true)));
    assert_eq!(asked(b"/m"), Some(("m".into(), false)));
}

/// `DEFINE`'s word and database are the path's fields; a third is cut
/// off.
#[test]
fn a_define_takes_its_fields_from_the_path() {
    assert_eq!(sent("/DEFINE:word:db:3").as_deref(), Some("DEFINE db word"));
    assert_eq!(sent("/d:basic").as_deref(), Some("DEFINE ! basic"));
    assert_eq!(sent("/lookup:a:").as_deref(), Some("DEFINE ! a"));
    assert_eq!(asked(b"/D:"), Some(("DEFINE ! default".into(), true)));
}

/// Any other path is sent as it is, past its slash, its colons spaces.
#[test]
fn another_path_is_sent_as_a_command() {
    assert_eq!(sent("/SHOW:DB").as_deref(), Some("SHOW DB"));
    assert_eq!(sent("/").as_deref(), Some(""));
    assert_eq!(sent("/a/b:c").as_deref(), Some("a/b c"));
    assert_eq!(sent("nothing"), None);
}

/// RFC 2229's bytes are escaped with a backslash in a word.
#[test]
fn a_word_s_special_bytes_are_escaped() {
    assert_eq!(
        sent("/d:a b'\"\\\x7f\x01c").as_deref(),
        Some("DEFINE ! a\\ b\\'\\\"\\\\\\\x7f\\\x01c")
    );
    // As C's `char` reads it: below space if it is signed.
    let high = request_of(b"/d:\xe9").unwrap().unwrap().0;
    if std::ffi::c_char::MIN == 0 {
        assert_eq!(high, b"DEFINE ! \xe9");
    } else {
        assert_eq!(high, b"DEFINE ! \\\xe9");
    }
}

/// A word escaped past C's buffer fails as its allocation does.
#[test]
fn a_word_past_the_buffer_fails() {
    let word = |n: usize| {
        let mut p = b"/d:".to_vec();
        p.extend(std::iter::repeat_n(b'a', n));
        request_of(&p).map(|r| r.map(|(r, _)| r.len()))
    };
    assert_eq!(word(9999), Ok(Some(9999 + 9)));
    assert_eq!(word(10000), Err(ErrorKind::OutOfMemory));
    let spaces = |n: usize| {
        let mut p = b"/d:".to_vec();
        p.extend(std::iter::repeat_n(b' ', n));
        request_of(&p).map(|r| r.map(|(r, _)| r.len()))
    };
    assert_eq!(spaces(4999), Ok(Some(9998 + 9)));
    assert_eq!(spaces(5000), Err(ErrorKind::OutOfMemory));
}

const ANSWER: &[u8] = b"220 hello\r\n150 1 definitions\r\n.\r\n250 ok\r\n221 bye\r\n";

/// A lookup sends the client's name, the command and `QUIT`, traced as
/// data sent, and its answer is the body, read until the server closes.
#[test]
fn a_lookup_reads_its_answer_to_the_close() {
    let talk = Conversation::new(ANSWER, true).per_send();
    let (said, ran) = against(talk, "dict://127.0.0.1:PORT/d:basic", |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    let version = crate::version::version().version;
    let want = format!("CLIENT libcurl {version}\r\nDEFINE ! basic\r\nQUIT\r\n");
    assert_eq!(String::from_utf8_lossy(&said), want);
    assert_eq!(String::from_utf8_lossy(&ran.data_out), want);
    assert_eq!(ran.body, ANSWER);
    assert!(ran.headers.is_empty());
    assert!(!ran.text.contains("lookup word is missing"), "{}", ran.text);
}

/// A missing word is said, and `default` looked up.
#[test]
fn a_missing_word_is_said() {
    let talk = Conversation::new(ANSWER, true).per_send();
    let (said, ran) = against(talk, "dict://127.0.0.1:PORT/m:", |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert!(
        ran.text.contains("lookup word is missing\n"),
        "{}",
        ran.text
    );
    assert!(said.ends_with(b"MATCH ! . default\r\nQUIT\r\n"));
}

/// A request the connection takes a piece at a time is sent whole, each
/// piece traced as it goes, before its answer is read.
#[test]
fn a_request_taken_in_pieces_is_sent_whole() {
    let five = std::num::NonZeroUsize::new(5).unwrap();
    let talk = Conversation::new(ANSWER, true)
        .per_send()
        .stalling_sends_after(1, 2)
        .taking(five);
    let (said, ran) = against(talk, "dict://127.0.0.1:PORT/d:basic", |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert!(
        said.ends_with(b"\r\nDEFINE ! basic\r\nQUIT\r\n"),
        "{said:?}"
    );
    assert_eq!(ran.data_out, said);
    assert_eq!(ran.body, ANSWER);
}

/// A control byte in the decoded path fails the transfer as a malformed
/// URL, nothing sent.
#[test]
fn a_control_byte_in_the_path_is_refused() {
    let talk = Conversation::new(ANSWER, true).per_send();
    let (said, ran) = against(talk, "dict://127.0.0.1:PORT/d:a%0d", |_| {});
    assert_eq!(ran.result, Some(Err(ErrorKind::UrlMalformat)));
    assert!(said.is_empty());
}

/// Each lookup has a connection of its own: DICT's are not kept.
#[test]
fn a_connection_is_not_reused() {
    let one = Conversation::new(ANSWER, true).per_send();
    let two = Conversation::new(ANSWER, true).per_send();
    let mut m = serving(&[&one, &two]);
    for _ in 0..2 {
        let ran = transfer(&mut m, "dict://127.0.0.1:PORT/d:x", |_| {});
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    }
    drop(m);
    assert!(!one.received().is_empty());
    assert!(!two.received().is_empty());
}

/// A lookup added to `m`, its trace kept.
fn looked_up(
    m: &mut crate::multi::Multi,
    set: impl FnOnce(&mut crate::options::Options),
) -> std::sync::Arc<std::sync::Mutex<String>> {
    use crate::handler::{DebugHandler, DebugKind, Handler};
    use crate::libraries::{Libraries, SharedLibraries};
    use crate::multi::{NoEvents, TransferCx};
    #[derive(Clone, Default)]
    struct Text(std::sync::Arc<std::sync::Mutex<String>>);
    impl DebugHandler for Text {
        fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
            if kind == DebugKind::Text {
                self.0
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(data));
            }
        }
    }
    let text = Text::default();
    let mut e = crate::easy::Easy::new();
    e.set_libraries(SharedLibraries::new(Libraries::NONE).unwrap());
    let traced = crate::components::Components::new().unwrap();
    traced.configure(b"multi");
    e.set_components(Some(traced));
    let o = e.options_mut();
    let url = format!("dict://127.0.0.1:{}/d:basic", crate::proto::raw::wire::PORT);
    o.set_url(Some(url.as_bytes())).unwrap();
    o.output.verbose = true;
    o.callbacks.debug = Some(Handler::debug(text.clone()).unwrap());
    set(o);
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    text.0
}

const DIRTY: &str = "[MULTI] [PERFORMING] sendrecv_dl() no EAGAIN/pending data, mark as dirty\n";

/// An answer that never ends is read a pass of C's reads at a time, the
/// transfer then run again at once, as C's debug build says.
#[test]
fn an_endless_answer_is_read_a_pass_at_a_time() {
    use crate::multi::NoEvents;
    let talk = Conversation::new(b"", false)
        .per_send()
        .endless(std::time::Duration::from_millis(1));
    let mut m = serving(&[&talk]);
    let text = looked_up(&mut m, |_| {});
    while talk.endless_reads() < 3 {
        m.perform(&mut NoEvents).unwrap();
    }
    let reads = talk.endless_reads();
    assert!(reads <= crate::proto::http::MAX_READS, "{reads}");
    let text = text.lock().unwrap();
    assert!(text.contains(DIRTY), "{text}");
}

/// Bytes a layer holds, where a poll cannot see them, are read without
/// waiting on the socket; a socket with nothing to read, and no layer
/// holding any, is waited on.
#[test]
fn held_bytes_are_read_and_an_empty_socket_waited_on() {
    use crate::multi::NoEvents;
    let talk = Conversation::new(ANSWER, true).per_send();
    let ran = transfer(
        &mut serving(&[&talk]),
        "dict://127.0.0.1:PORT/d:basic",
        |o| {
            o.layer = Some(crate::conn::layer::testing::holdback);
        },
    );
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(ran.body, ANSWER);
    // Run again at once, as C's debug build says.
    let talk = Conversation::new(b"partial", false).per_send();
    let mut m = serving(&[&talk]);
    let text = looked_up(&mut m, |o| {
        o.layer = Some(crate::conn::layer::testing::holdback);
    });
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    let text = text.lock().unwrap().clone();
    assert!(text.contains(DIRTY), "{text}");
    let talk = Conversation::new(b"partial", false).per_send();
    let mut m = serving(&[&talk]);
    let text = looked_up(&mut m, |_| {});
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert_ne!(m.timeout(), Some(std::time::Duration::ZERO));
    let text = text.lock().unwrap();
    assert!(!text.contains(DIRTY), "{text}");
}

/// A connection reset while the answer is read fails the transfer, said
/// as the socket says it.
#[test]
fn a_reset_answer_fails_with_the_socket_s_reason() {
    let talk = Conversation::new(b"part", false).per_send().resetting();
    let (_, ran) = against(talk, "dict://127.0.0.1:PORT/d:basic", |_| {});
    assert_eq!(ran.result, Some(Err(ErrorKind::RecvError)), "{}", ran.text);
    // Said once, by the layer that saw it.
    #[cfg(unix)]
    let said = ran.text.matches("Recv failure: Connection reset by peer\n");
    // Winsock's words, from C's table (`get_winsock_error`).
    #[cfg(windows)]
    let said = ran.text.matches("Recv failure: Connection was reset\n");
    assert_eq!(said.count(), 1, "{}", ran.text);
}

/// A request the connection takes a piece at a time goes whole in one
/// pass, while the connection takes it.
#[test]
fn a_request_in_pieces_goes_in_one_pass() {
    use crate::multi::NoEvents;
    let five = std::num::NonZeroUsize::new(5).unwrap();
    let talk = Conversation::new(b"", false).per_send().taking(five);
    let mut m = serving(&[&talk]);
    looked_up(&mut m, |_| {});
    let version = crate::version::version().version;
    let want = format!("CLIENT libcurl {version}\r\nDEFINE ! basic\r\nQUIT\r\n");
    for _ in 0..3 {
        m.perform(&mut NoEvents).unwrap();
        if !talk.received().is_empty() {
            break;
        }
    }
    assert_eq!(String::from_utf8_lossy(&talk.received()), want);
}

proptest::proptest! {
    #![proptest_config(crate::untrusted::config(512))]

    /// Any path makes a request or fails, as C's would.
    #[test]
    fn any_path_makes_a_request_or_fails(
        path in crate::untrusted::soup(
            &[b"/", b":", b"m:", b"/MATCH:", b"/d:", b"/DEFINE:", b"\\", b"'", b" "],
            12,
        ),
    ) {
        let _ = request_of(&path);
    }
}

/// A paused writer holds the answer until it is taken.
#[test]
fn a_paused_answer_is_held_until_taken() {
    let talk = Conversation::new(ANSWER, true).per_send();
    let took = crate::proto::raw::wire::paused_then_taken(&talk, "dict://127.0.0.1:PORT/d:basic");
    assert_eq!(took, ANSWER);
}

/// While the request goes, the transfer waits for room to send it; then
/// for the answer.
#[test]
fn the_request_waits_for_room_then_for_the_answer() {
    use crate::conn::io::Events;
    use crate::multi::NoEvents;
    use crate::proto::raw::wire::{added, waits};
    for stalled in [true, false] {
        let mut talk = Conversation::new(b"", false).per_send();
        if stalled {
            talk = talk.stalling_sends_after(0, 1000);
        }
        let mut m = serving(&[&talk]);
        added(&mut m, "dict://127.0.0.1:PORT/d:basic", |_| {});
        for _ in 0..5 {
            m.perform(&mut NoEvents).unwrap();
        }
        let want = if stalled { Events::OUT } else { Events::IN };
        assert_eq!(waits(&mut m), [want], "stalled {stalled}");
    }
}

/// A URL without a port goes to the scheme's.
#[test]
fn a_url_without_a_port_goes_to_the_scheme_s() {
    let talk = Conversation::new(b"", true).per_send();
    let (said, ran) = against(talk, "dict://127.0.0.1/d:basic", |_| {});
    assert_eq!(
        ran.result,
        Some(Err(ErrorKind::CouldntConnect)),
        "{}",
        ran.text
    );
    assert!(said.is_empty());
    assert!(ran.text.contains("port 2628"), "{}", ran.text);
}
