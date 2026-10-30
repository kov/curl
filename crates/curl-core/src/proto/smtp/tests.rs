use super::*;

fn parts(given: &[u8], idn: Option<&dyn Idn>) -> (Vec<u8>, Option<Vec<u8>>, bool, Vec<u8>) {
    let m = mailbox(given, idn).unwrap();
    (m.local, m.host, m.converted, m.suffix)
}

/// A mailbox loses its brackets, keeps what follows the closing one, and
/// splits at its first `@` (`smtp_parse_address`).
#[test]
fn a_mailbox_is_read_as_c_reads_it() {
    let s = |b: &[u8]| b.to_vec();
    assert_eq!(parts(b"a@b", None), (s(b"a"), Some(s(b"b")), false, s(b"")));
    assert_eq!(
        parts(b"<a@b>", None),
        (s(b"a"), Some(s(b"b")), false, s(b""))
    );
    assert_eq!(
        parts(b"<a@b> NOTIFY=x", None),
        (s(b"a"), Some(s(b"b")), false, s(b" NOTIFY=x"))
    );
    // The last `>` closes, the first `@` splits.
    assert_eq!(
        parts(b"<a@b@c>d>e", None),
        (s(b"a"), Some(s(b"b@c>d")), false, s(b"e"))
    );
    // Without an opening bracket, only a last `>` is taken off.
    assert_eq!(
        parts(b"a@b>>", None),
        (s(b"a"), Some(s(b"b>")), false, s(b""))
    );
    assert_eq!(parts(b"local", None), (s(b"local"), None, false, s(b"")));
    assert_eq!(parts(b"<local", None), (s(b"local"), None, false, s(b"")));
    assert_eq!(parts(b"", None), (s(b""), None, false, s(b"")));
    // A line's end in it is refused, wherever it is.
    for bad in [&b"a@b\r\nRSET"[..], b"<a\n@b>", b"\r"] {
        assert_eq!(
            mailbox(bad, None).unwrap_err(),
            AddressError::LineEnd,
            "{bad:?}"
        );
    }
}

/// A host in Unicode goes in ASCII where the IDN library converts it, and
/// as it is where it cannot; either way the mailbox is in UTF-8.
#[test]
fn a_mailbox_s_host_is_converted_where_it_can_be() {
    let idn = crate::idn::FakeIdn;
    let idn: Option<&dyn Idn> = Some(&idn);
    let m = mailbox("u@åäö.test".as_bytes(), idn).unwrap();
    assert_eq!(m.host.as_deref(), Some(&b"xn--4cab6c.test"[..]));
    assert!(m.converted && m.in_utf8());
    assert_eq!(m.bracketed().unwrap(), b"<u@xn--4cab6c.test>");
    let m = mailbox("u@ünknown.test".as_bytes(), idn).unwrap();
    assert_eq!(m.host.as_deref(), Some("ünknown.test".as_bytes()));
    assert!(!m.converted && m.in_utf8());
    let m = mailbox("u@åäö.test".as_bytes(), None).unwrap();
    assert!(!m.converted && m.in_utf8());
    let m = mailbox("ü@b".as_bytes(), idn).unwrap();
    assert!(m.in_utf8());
    assert!(!mailbox(b"<u@b> x", idn).unwrap().in_utf8());
    assert_eq!(
        mailbox(b"<local> x", None).unwrap().bracketed().unwrap(),
        b"<local> x"
    );
}

/// The message of a SASL answer starts after the code and its blanks,
/// and ends before the line's blanks and end (`smtp_get_message`).
#[test]
fn a_sasl_message_is_the_reply_s_text() {
    assert_eq!(server_message(b"334 \t abc= \r\n"), b"abc=");
    assert_eq!(server_message(b"334 x\n"), b"x");
    assert_eq!(server_message(b"334 \r\n"), b"");
    assert_eq!(server_message(b"334\r\n"), b"");
    assert_eq!(server_message(b"334 "), b"");
}

/// Only `AUTH=` and a mechanism, or `*`, are login options; anything else
/// is malformed (`smtp_parse_url_options`).
#[test]
fn the_login_options_name_mechanisms() {
    let parsed = |given: &[u8]| {
        let mut sasl = Sasl::new(&SASL, crate::options::AuthMethods::BASIC);
        parse_options(&mut sasl, given).map(|()| sasl.preferred())
    };
    assert_eq!(parsed(b""), Ok(Mechs::DEFAULT));
    assert_eq!(parsed(b"AUTH=*"), Ok(Mechs::DEFAULT));
    assert_eq!(parsed(b"AUTH=PLAIN"), Ok(Mechs::PLAIN));
    assert_eq!(
        parsed(b"auth=PLAIN;AUTH=LOGIN"),
        Ok(Mechs::PLAIN.or(Mechs::LOGIN))
    );
    for bad in [
        &b"AUTH="[..],
        b"AUTH=BOGUS",
        b"X=1",
        b"AUTH=PLAIN;X=1",
        b"+LOGIN",
    ] {
        assert_eq!(parsed(bad), Err(ErrorKind::UrlMalformat), "{bad:?}");
    }
}

/// The EHLO domain is the URL's path after its slash, decoded, a control
/// byte refused; with none, the machine's name.
#[test]
fn the_domain_is_the_url_s_path() {
    assert_eq!(domain(b"/900").unwrap(), b"900");
    assert_eq!(domain(b"/a%20b").unwrap(), b"a b");
    assert_eq!(domain(b"/a%0Db"), Err(ErrorKind::UrlMalformat));
    let mut buf = [0u8; HOSTNAME_MAX + 1];
    let name = host_name(&mut buf).map_or(b"localhost".to_vec(), <[u8]>::to_vec);
    assert!(!name.contains(&b'.'), "{name:?}");
    assert_eq!(domain(b"/").unwrap(), name);
    assert_eq!(machine(b"box.example.com"), b"box");
    assert_eq!(machine(b"box"), b"box");
    assert_eq!(machine(b".x"), b"");
}

#[test]
fn the_states_have_c_s_names() {
    let names = [
        (State::Stop, "STOP"),
        (State::ServerGreet, "SERVERGREET"),
        (State::Ehlo, "EHLO"),
        (State::Helo, "HELO"),
        (State::StartTls, "STARTTLS"),
        (State::UpgradeTls, "UPGRADETLS"),
        (State::Auth, "AUTH"),
        (State::Command, "COMMAND"),
        (State::Mail, "MAIL"),
        (State::Rcpt, "RCPT"),
        (State::Data, "DATA"),
        (State::PostData, "POSTDATA"),
    ];
    for (state, name) in names {
        assert_eq!(state.name(), name);
    }
}

/// A name the debug build's `CURL_GETHOSTNAME` forces is taken while it
/// leaves room for C's NUL in the buffer it is read into.
#[cfg(feature = "debug-hooks")]
#[test]
fn a_forced_host_name_fits_its_buffer_or_is_none() {
    let longest = [b'h'; HOSTNAME_MAX];
    assert_eq!(fits(&longest), Some(&longest[..]));
    assert_eq!(fits(&[b'h'; HOSTNAME_MAX + 1]), None);
}

/// The domain EHLO gives is the machine's name, up to its first dot,
/// when the URL's path names none.
#[test]
fn the_domain_is_the_machine_s_name_without_a_path() {
    assert_eq!(machine(b"box.example.com"), b"box");
    assert_eq!(machine(b"box"), b"box");
}

mod over_the_wire;
