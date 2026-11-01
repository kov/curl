use super::*;

/// A parameter's name and value, as the path reader says them.
type Said = (Vec<u8>, Vec<u8>);

/// What a URL's path asks for, and the parameters it was said to name.
fn path(text: &[u8]) -> (Result<Asked, ErrorKind>, Vec<Said>) {
    let mut asked = Asked::default();
    let mut said = Vec::new();
    let result = parse_path(text, &mut asked, &mut |n, v| {
        said.push((n.to_vec(), v.to_vec()));
    });
    (result.map(|()| asked), said)
}

/// The mailbox, then `;NAME=VALUE` parameters, a trailing slash off each;
/// the first of each kept, any unknown or a second UIDVALIDITY malformed,
/// as is anything after them (`imap_parse_url_path`).
#[test]
fn the_path_names_a_mailbox_and_a_message() {
    let (asked, said) = path(b"/INBOX/;UIDVALIDITY=7/;UID=3/;SECTION=1.2/;PARTIAL=0.10");
    let asked = asked.unwrap();
    assert_eq!(asked.mailbox.as_deref(), Some(&b"INBOX"[..]));
    assert_eq!(asked.uidvalidity, Some(7));
    assert_eq!(asked.uid.as_deref(), Some(&b"3"[..]));
    assert_eq!(asked.section.as_deref(), Some(&b"1.2"[..]));
    assert_eq!(asked.partial.as_deref(), Some(&b"0.10"[..]));
    assert_eq!(asked.mindex, None);
    // Said as decoded, before the slash comes off.
    assert_eq!(said[0], (b"UIDVALIDITY".to_vec(), b"7/".to_vec()));
    assert_eq!(said.len(), 4);

    let (asked, _) = path(b"/a%20box;mailindex=2;uid=5");
    let asked = asked.unwrap();
    assert_eq!(asked.mailbox.as_deref(), Some(&b"a box"[..]));
    assert_eq!(asked.mindex.as_deref(), Some(&b"2"[..]));
    assert_eq!(asked.uid.as_deref(), Some(&b"5"[..]));

    // No mailbox, and an empty value is passed over.
    let (asked, _) = path(b"/;UID=");
    let asked = asked.unwrap();
    assert_eq!(asked.mailbox, None);
    assert_eq!(asked.uid, None);
    // A UIDVALIDITY that is no number is not set, and may come again.
    let (asked, _) = path(b"/;UIDVALIDITY=x;UIDVALIDITY=4294967295");
    assert_eq!(asked.unwrap().uidvalidity, Some(u32::MAX));

    for bad in [
        &b"/INBOX;FOO=1"[..],
        b"/INBOX;UID",
        b"/;UIDVALIDITY=1;UIDVALIDITY=2",
        b"/INBOX;UID=1;UID=2",
        b"/IN\"BOX",
        b"/INBOX;UID=1\"",
        b"/a%0Ab",
    ] {
        assert_eq!(path(bad).0.err(), Some(ErrorKind::UrlMalformat), "{bad:?}");
    }
}

/// An atom is quoted, its quotes and backslashes escaped, when it holds
/// any of `() {%*]\"` (`imap_atom`).
#[test]
fn atoms_are_quoted_as_c_quotes_them() {
    assert_eq!(atom(b"user", false).unwrap(), b"user");
    assert_eq!(atom(b"", false).unwrap(), b"");
    assert_eq!(atom(b"a b", false).unwrap(), b"\"a b\"");
    assert_eq!(atom(b"a\"b", false).unwrap(), b"\"a\\\"b\"");
    assert_eq!(atom(b"a\\b", false).unwrap(), b"\"a\\\\b\"");
    assert_eq!(atom(b"[x]", false).unwrap(), b"\"[x]\"");
    assert_eq!(atom(b"[x", false).unwrap(), b"[x");
    for special in *b"(){%*]" {
        let text = [b'a', special];
        assert_eq!(atom(&text, false).unwrap(), [b'"', b'a', special, b'"']);
    }
    // Escaped only, for a LIST's quotes.
    assert_eq!(atom(b"a \"b", true).unwrap(), b"a \\\"b");
}

/// The connection's state as login options leave it.
fn options(given: &[u8]) -> Result<(AuthTypes, Mechs), ErrorKind> {
    use crate::time::Clock as _;
    let now = crate::time::ManualClock::new().unwrap().now();
    let mut pc = ImapConn {
        pp: Pingpong::new(now),
        state: State::Stop,
        sasl: Sasl::new(&SASL, crate::options::AuthMethods::BASIC),
        number: ConnNumber::for_tests(0),
        tag: Tag::GREETING,
        cmdid: 0,
        mailbox: None,
        uidvalidity: None,
        preferred: AuthTypes::ANY,
        preauth: false,
        tls_offered: false,
        login_disabled: false,
        ir_offered: false,
        no_socket: false,
        cold: None,
    };
    parse_options(&mut pc, given).map(|()| (pc.preferred, pc.sasl.preferred()))
}

/// `AUTH=+LOGIN` prefers clear text, `AUTH=` otherwise a SASL mechanism
/// or `*`; anything else is malformed (`imap_parse_url_options`).
#[test]
fn the_login_options_choose_how_to_log_in() {
    assert_eq!(options(b""), Ok((AuthTypes::ANY, Mechs::DEFAULT)));
    assert_eq!(options(b"AUTH=*"), Ok((AuthTypes::ANY, Mechs::DEFAULT)));
    assert_eq!(options(b"auth=plain"), Ok((AuthTypes::SASL, Mechs::PLAIN)));
    assert_eq!(
        options(b"AUTH=PLAIN;AUTH=LOGIN"),
        Ok((AuthTypes::SASL, Mechs::PLAIN.or(Mechs::LOGIN)))
    );
    assert_eq!(
        options(b"AUTH=+LOGIN"),
        Ok((AuthTypes::CLEARTEXT, Mechs::NONE))
    );
    // Its name is matched as a prefix (`strncasecompare`).
    assert_eq!(
        options(b"auth=+loginx"),
        Ok((AuthTypes::CLEARTEXT, Mechs::NONE))
    );
    for bad in [
        &b"AUTH="[..],
        b"AUTH=XYZ",
        b"AUTH",
        b"FOO=1",
        b"AUTH=PLAIN;FOO",
    ] {
        assert_eq!(options(bad), Err(ErrorKind::UrlMalformat), "{bad:?}");
    }
}

/// The flags an APPEND gives, in C's order, none when none is set.
#[test]
fn upload_flags_are_listed_in_c_s_order() {
    assert_eq!(flags_of(UploadFlags::SEEN).unwrap(), b" (\\Seen)");
    assert_eq!(flags_of(UploadFlags::NONE).unwrap(), b"");
    // Bits C knows no flag for are kept and never said.
    assert_eq!(flags_of(UploadFlags::from_bits(0xe0)).unwrap(), b"");
    let all = UploadFlags::from_bits(0xff);
    assert_eq!(
        flags_of(all).unwrap(),
        b" (\\Answered \\Deleted \\Draft \\Flagged \\Seen)"
    );
    assert_eq!(
        flags_of(UploadFlags::DRAFT.or(UploadFlags::ANSWERED)).unwrap(),
        b" (\\Answered \\Draft)"
    );
}

/// A custom `FETCH` or `UID FETCH` of a range or a list of messages is
/// a listing (`is_custom_fetch_listing`).
#[test]
fn a_custom_fetch_of_many_messages_is_a_listing() {
    let listing = |custom: &[u8], params: Option<&[u8]>| {
        let request = Request {
            asked: Box::new(Asked {
                custom: Some(custom.to_vec()),
                custom_params: params.map(<[u8]>::to_vec),
                ..Asked::default()
            }),
            ..request()
        };
        request.custom_fetch_listing()
    };
    assert!(listing(b"FETCH", Some(b" 1:* (FLAGS)")));
    assert!(listing(b"fetch", Some(b" 1,2 (FLAGS)")));
    assert!(listing(b"UID", Some(b" FETCH 1:* (FLAGS)")));
    assert!(listing(b"FETCH", Some(b" :")));
    assert!(!listing(b"FETCH", Some(b" 1 (FLAGS)")));
    assert!(!listing(b"FETCH", Some(b" 12")));
    assert!(!listing(b"FETCH", Some(b"1:*")));
    assert!(!listing(b"FETCH", None));
    assert!(!listing(b"UID", Some(b" STORE 1:*")));
    assert!(!listing(b"SEARCH", Some(b" 1:*")));
}

/// A request asking nothing, for the tests of its parts.
fn request() -> Request {
    let url = Url::parse(b"imap://h/", crate::url::ParseOptions::NONE).unwrap();
    let scheme = Scheme::named(b"imap").unwrap();
    Request {
        pipeline: Pipeline::new(Reach::Network),
        peer: super::super::url_peer((scheme, b"h".to_vec(), 143), &url, None, None).unwrap(),
        credentials: None,
        path: Vec::new(),
        query: None,
        url_options: None,
        asked: Box::default(),
        no_body: false,
        nothing_after: false,
        receive: super::Receive::default(),
        sending: None,
        last: Final::None,
        round: drive::Blocking::default(),
        upload_done: false,
        due: None,
        in_place: Default::default(),
        header_bytes: 0,
    }
}

/// The states are named as C's debug build names them, and a reply's
/// code printed as C prints it.
#[test]
fn the_states_have_c_s_names() {
    let names = [
        (State::Stop, "STOP"),
        (State::ServerGreet, "SERVERGREET"),
        (State::Capability, "CAPABILITY"),
        (State::StartTls, "STARTTLS"),
        (State::UpgradeTls, "UPGRADETLS"),
        (State::Authenticate, "AUTHENTICATE"),
        (State::Login, "LOGIN"),
        (State::List, "LIST"),
        (State::Select, "SELECT"),
        (State::Fetch, "FETCH"),
        (State::FetchFinal, "FETCH_FINAL"),
        (State::Append, "APPEND"),
        (State::AppendFinal, "APPEND_FINAL"),
        (State::Search, "SEARCH"),
    ];
    for (state, name) in names {
        assert_eq!(state.name(), name);
    }
    assert_eq!(
        [ImapReply::Ok, ImapReply::NotOk, ImapReply::Preauth].map(code_number),
        ['\u{1}', '\u{2}', '\u{3}']
    );
    assert_eq!(code_number(ImapReply::Untagged), '*');
    assert_eq!(code_number(ImapReply::Continuation), '+');
}

/// A number no larger than its limit, from the digits a text starts with.
#[test]
fn numbers_are_read_as_c_reads_them() {
    assert_eq!(number(b"42]", 100), Some(42));
    assert_eq!(
        number(b"4294967295", u64::from(u32::MAX)),
        Some(u64::from(u32::MAX))
    );
    assert_eq!(number(b"4294967296", u64::from(u32::MAX)), None);
    assert_eq!(number(b"x1", 100), None);
    assert_eq!(number(b"", 100), None);
    assert_eq!(number(b"99999999999999999999999", u64::MAX), None);
}

mod over_the_wire;
