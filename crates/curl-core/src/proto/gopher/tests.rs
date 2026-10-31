use super::*;
use crate::conn::io::Conversation;
use crate::proto::raw::wire::against;

fn selector(path: &str, query: Option<&str>) -> Result<Vec<u8>, Refused> {
    selector_of(path.as_bytes(), query.map(str::as_bytes))
}

/// The selector is the path past its slash and item type, with the query
/// after a `?`, decoded; `/` and `/1` ask for none.
#[test]
fn the_selector_is_the_path_past_its_type() {
    assert_eq!(selector("/", None), Ok(b"".to_vec()));
    assert_eq!(selector("/1", None), Ok(b"".to_vec()));
    assert_eq!(selector("/1/foo", None), Ok(b"/foo".to_vec()));
    assert_eq!(selector("/7/s", Some("q")), Ok(b"/s?q".to_vec()));
    assert_eq!(selector("/", Some("q")), Ok(b"q".to_vec()));
    assert_eq!(selector("/1", Some("")), Ok(b"?".to_vec()));
    assert_eq!(selector("/0a%20b%09c", None), Ok(b"a b\tc".to_vec()));
}

/// A zero byte, CR or LF decoded into the selector refuses it.
#[test]
fn a_zero_cr_or_lf_is_refused() {
    assert_eq!(selector("/0a%00", None), Err(Refused::Malformed));
    assert_eq!(selector("/0a%0d", None), Err(Refused::LineEnd));
    assert_eq!(selector("/0a", Some("%0a")), Err(Refused::LineEnd));
}

const MENU: &[u8] = b"iMenu results\t\terror.host\t1\r\n.\r\n";

/// The selector goes with a CRLF; the application has it, and the CRLF,
/// as header bytes, and the answer to the server's close as the body.
#[test]
fn a_menu_is_read_to_the_close() {
    let talk = Conversation::new(MENU, true).per_send();
    let (said, ran) = against(talk, "gopher://127.0.0.1:PORT/1/1200", |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(said, b"/1200\r\n");
    assert_eq!(ran.headers, b"/1200\r\n");
    assert_eq!(ran.body, MENU);
    // Not kept for the headers API: C collects HTTP's only.
    assert!(!ran.stored_headers);
}

/// An empty selector is a lone CRLF; only that CRLF is a header.
#[test]
fn the_root_sends_a_lone_crlf() {
    let talk = Conversation::new(MENU, true).per_send();
    let (said, ran) = against(talk, "gopher://127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(said, b"\r\n");
    assert_eq!(ran.headers, b"\r\n");
}

/// A selector the connection takes a piece at a time goes whole, each
/// piece of it a header as it goes, the CRLF after.
#[test]
fn a_selector_taken_in_pieces_is_sent_whole() {
    let three = std::num::NonZeroUsize::new(3).unwrap();
    let talk = Conversation::new(MENU, true)
        .per_send()
        .stalling_sends_after(1, 2)
        .taking(three);
    let (said, ran) = against(talk, "gopher://127.0.0.1:PORT/0/a/long/selector", |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(said, b"/a/long/selector\r\n");
    assert_eq!(ran.headers, b"/a/long/selector\r\n");
    assert_eq!(ran.body, MENU);
}

/// A CR or LF in the selector fails as C fails it, nothing sent.
#[test]
fn a_line_end_in_the_selector_fails_the_transfer() {
    let talk = Conversation::new(MENU, true).per_send();
    let (said, ran) = against(talk, "gopher://127.0.0.1:PORT/0a%0d%0aRSET", |_| {});
    assert_eq!(ran.result, Some(Err(ErrorKind::UrlMalformat)));
    assert!(
        ran.text
            .contains("Bad gopher selector, CR or LF not allowed\n"),
        "{}",
        ran.text
    );
    assert!(said.is_empty());
}

proptest::proptest! {
    #![proptest_config(crate::untrusted::config(512))]

    /// Any path and query make a selector or are refused.
    #[test]
    fn any_url_makes_a_selector_or_is_refused(
        path in crate::untrusted::soup(&[b"/", b"%", b"%0d", b"%00", b"1", b"?"], 10),
        query in proptest::option::of(crate::untrusted::soup(&[b"%0a", b"%", b"x"], 6)),
    ) {
        let _ = selector_of(&path, query.as_deref());
    }
}
