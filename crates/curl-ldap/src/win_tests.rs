use super::*;
use crate::ber::*;

/// The elements of a BER sequence's `content`: each its tag and content.
fn elements(mut content: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut all = Vec::new();
    while !content.is_empty() {
        let tag = content[0];
        let (len, head) = if content[1] < 0x80 {
            (usize::from(content[1]), 2)
        } else {
            let n = usize::from(content[1] & 0x7f);
            let len = content[2..2 + n]
                .iter()
                .fold(0, |a, &b| a << 8 | usize::from(b));
            (len, 2 + n)
        };
        all.push((tag, content[head..head + len].to_vec()));
        content = &content[head + len..];
    }
    all
}

/// A request's operation, past its message id: its elements.
fn operation(message: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let parts = elements(message);
    assert_eq!(parts.len(), 2, "an id and an operation");
    elements(&parts[1].1)
}

/// A bind request as a test reads it: its version, its name, and its
/// authentication, the simple password or the SASL mechanism.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Sent {
    Simple(u8, Vec<u8>, Vec<u8>),
    Sasl(u8, Vec<u8>, Vec<u8>),
    /// Another authentication, by its tag: Microsoft's NTLM bind
    /// (`sicily`, 0x8a and on) among them.
    Other(u8, Vec<u8>, u8),
}

fn bind_of(message: &[u8]) -> Sent {
    let op = operation(message);
    let version = op[0].1[0];
    let name = op[1].1.clone();
    match op[2].0 {
        0x80 => Sent::Simple(version, name, op[2].1.clone()),
        0xa3 => Sent::Sasl(version, name, elements(&op[2].1)[0].1.clone()),
        tag => Sent::Other(version, name, tag),
    }
}

/// WinLDAP through its ANSI calls, as a build without `UNICODE` drives
/// it, and through its wide ones, as the Unicode build does.
const ANSI: WinLdap = WinLdap { wide: false };
const WIDE: WinLdap = WinLdap { wide: true };

/// A session of `library`'s own, of WinLDAP's kind, to `port`, for TLS if
/// `secured`.
fn open_with(library: &WinLdap, port: u16, secured: bool) -> Box<dyn WinLdapSession> {
    let LocalSession::Windows(session) = library.open(b"127.0.0.1", port, secured).unwrap() else {
        panic!("WinLDAP's session is WinLDAP's");
    };
    session
}

/// A session of the build's own WinLDAP to `port`, for TLS if `secured`.
fn open(port: u16, secured: bool) -> Box<dyn WinLdapSession> {
    open_with(&WINLDAP, port, secured)
}

fn search() -> Search {
    Search {
        dn: Some(b"dc=x".to_vec()),
        scope: Scope::Subtree,
        filter: Some(b"(objectClass=*)".to_vec()),
        attrs: Some(vec![b"cn".to_vec(), b"photo".to_vec()]),
    }
}

/// A session of the library's own reaches the host and port it is
/// given, binds in the version it is set to and searches there, each call
/// waiting for its answer; the entries of the answer are read in turn with
/// their attributes and values, and the session unbinds as it is dropped.
#[test]
fn a_session_binds_and_searches_on_a_connection_of_its_own() {
    let (port, server) = serve(|op, id| finds_two(op, id, 0));
    let mut session = open(port, false);
    session.set_version(Version::V3);
    session.set_no_referrals();
    let simple = WinBind::Simple {
        user: b"cn=me",
        password: b"pw",
    };
    assert_eq!(session.bind(simple), Code::SUCCESS);
    let (code, mut found) = session.search(&search()).unwrap();
    assert_eq!(code, Code::SUCCESS);
    assert!(found.next_entry());
    assert_eq!(found.dn().unwrap(), b"cn=a,dc=x");
    let a = found.next_attribute().unwrap().unwrap();
    assert_eq!(
        (a.name, a.values),
        (&b"cn"[..], Some(vec![&b"a"[..], b"b"]))
    );
    let a = found.next_attribute().unwrap().unwrap();
    assert_eq!(a.name, b"sn");
    assert!(
        a.values.is_none_or(|v| v.is_empty()),
        "an attribute without values"
    );
    assert!(found.next_attribute().unwrap().is_none());
    assert!(found.next_entry());
    assert_eq!(found.dn().unwrap(), b"cn=c,dc=x");
    let a = found.next_attribute().unwrap().unwrap();
    assert_eq!(
        (a.name, a.values),
        (&b"photo"[..], Some(vec![&b"\x00\x01"[..]]))
    );
    assert!(found.next_attribute().unwrap().is_none());
    assert!(!found.next_entry());
    assert!(!found.next_entry(), "and none after");
    drop(found);
    drop(session);
    let got = server.join().unwrap();
    // The bind, the search, the unbind.
    assert_eq!(ops(&got), [0x60, 0x63, 0x42]);
    assert_eq!(
        bind_of(&got[0].1),
        Sent::Simple(3, b"cn=me".to_vec(), b"pw".to_vec())
    );
    // The search's base, scope and filter's type, and its attributes.
    let search = operation(&got[1].1);
    assert_eq!(search[0].1, b"dc=x");
    assert_eq!(search[1], (0x0a, vec![2]));
    assert_eq!(search[3], (0x02, vec![0]), "no size limit");
    let attrs: Vec<_> = elements(&search[7].1).into_iter().map(|(_, a)| a).collect();
    assert_eq!(attrs, [b"cn".to_vec(), b"photo".to_vec()]);
}

/// Version 2 when set; an empty login is a bind as no one; a search of every
/// attribute asks for none by name, and a base search is one.
#[test]
fn a_session_binds_as_it_is_set_to() {
    let (port, server) = serve(|op, id| finds_two(op, id, 0));
    let mut session = open(port, false);
    session.set_version(Version::V2);
    let anonymous = WinBind::Simple {
        user: b"",
        password: b"",
    };
    assert_eq!(session.bind(anonymous), Code::SUCCESS);
    let every = Search {
        dn: None,
        scope: Scope::Base,
        filter: None,
        attrs: None,
    };
    let (_, found) = session.search(&every).unwrap();
    drop(found);
    drop(session);
    let got = server.join().unwrap();
    assert_eq!(bind_of(&got[0].1), Sent::Simple(2, Vec::new(), Vec::new()));
    let search = operation(&got[1].1);
    assert_eq!(search[0].1, b"");
    assert_eq!(search[1], (0x0a, vec![0]));
    assert!(elements(&search[7].1).is_empty());
}

/// A search cut short by the size limit gives what came and says so; a
/// bind the server refuses is its code, as is a search it refuses.
#[test]
fn the_server_s_codes_are_given() {
    let (port, server) = serve(|op, id| finds_two(op, id, 4));
    let mut session = open(port, false);
    session.set_version(Version::V3);
    let anonymous = WinBind::Simple {
        user: b"",
        password: b"",
    };
    assert_eq!(session.bind(anonymous), Code::SUCCESS);
    let (code, mut found) = session.search(&search()).unwrap();
    assert_eq!(code, Code::SIZELIMIT_EXCEEDED);
    assert!(found.next_entry());
    assert!(found.next_entry());
    assert!(!found.next_entry());
    drop(found);
    drop(session);
    server.join().unwrap();

    let (port, server) = serve(|op, id| match op {
        0x60 => vec![ldap_message(id, &result_op(0x61, 49, b""))],
        _ => Vec::new(),
    });
    let mut session = open(port, false);
    session.set_version(Version::V3);
    assert_eq!(session.bind(anonymous), Code::INVALID_CREDENTIALS);
    drop(session);
    server.join().unwrap();

    let (port, server) = serve(|op, id| match op {
        0x60 => vec![ldap_message(id, &result_op(0x61, 0, b""))],
        0x63 => vec![ldap_message(id, &result_op(0x65, 32, b""))],
        _ => Vec::new(),
    });
    let mut session = open(port, false);
    session.set_version(Version::V3);
    assert_eq!(session.bind(anonymous), Code::SUCCESS);
    assert_eq!(session.search(&search()).err(), Some(Code(32)));
    drop(session);
    server.join().unwrap();
}

/// Binds by SSPI ask the server's root for its mechanisms first; with
/// none named, Negotiate binds as Microsoft's NTLM bind does (`sicily`),
/// with the login or as the process's user, and Digest makes no bind at
/// all, as C's build does against the same server.
#[test]
fn an_sspi_bind_is_made_with_its_method() {
    let answers = |op: u8, id: u8| match op {
        0x60 => vec![ldap_message(id, &result_op(0x61, 49, b""))],
        0x63 => vec![ldap_message(id, &result_op(0x65, 0, b""))],
        _ => Vec::new(),
    };
    for library in [&ANSI, &WIDE] {
        let sent = |how: WinBind<'_>| {
            let (port, server) = serve(answers);
            let mut session = open_with(library, port, false);
            session.set_version(Version::V3);
            let code = session.bind(how);
            drop(session);
            let got = server.join().unwrap();
            let binds: Vec<Sent> = got
                .iter()
                .filter(|(op, _)| *op == 0x60)
                .map(|(_, m)| bind_of(m))
                .collect();
            let searches = got.iter().filter(|(op, _)| *op == 0x63).count();
            (code, searches, binds)
        };
        let ntlm = Sent::Other(3, b"NTLM".to_vec(), 0x8a);
        let (code, searches, binds) = sent(WinBind::Sspi {
            method: SspiMethod::Negotiate,
            user: b"DOM\\me",
            password: b"pw",
        });
        assert_ne!(code, Code::SUCCESS);
        assert!(searches > 0, "the root's mechanisms are asked for");
        assert_eq!(binds, core::slice::from_ref(&ntlm));
        let (code, searches, binds) = sent(WinBind::CurrentUser);
        assert_ne!(code, Code::SUCCESS);
        assert!(searches > 0);
        assert_eq!(binds, [ntlm]);
        let (code, searches, binds) = sent(WinBind::Sspi {
            method: SspiMethod::Digest,
            user: b"me",
            password: b"pw",
        });
        assert_ne!(code, Code::SUCCESS);
        assert!(searches > 0);
        assert_eq!(binds, []);
    }
}

/// The TLS options take; a session for TLS is made.
#[test]
fn the_tls_options_take() {
    let mut session = open(9, true);
    session.set_ssl();
    session.accept_any_cert();
}

/// An SSPI identity names the domain before a `\`, or else a `/`, and
/// the user after it; the password whole, up to a NUL; each with its
/// length, in the ANSI code page or, for the wide calls, in UTF-16 units.
#[test]
fn an_identity_is_made_as_c_makes_it() {
    fn show<T: Copy>(p: *mut T, len: u32) -> Vec<T> {
        // SAFETY: one of the identity's strings and its length.
        unsafe { core::slice::from_raw_parts(p, len as usize) }.to_vec()
    }
    let utf16 = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
    for (given, domain, user) in [
        ("DOM\\me", "DOM", "me"),
        ("DOM/me", "DOM", "me"),
        ("a/b\\c", "a/b", "c"),
        ("me", "", "me"),
        ("me@dom", "", "me@dom"),
        ("DÖM\\mé", "DÖM", "mé"),
    ] {
        let mut id = Identity::new(given.as_bytes(), b"pw\0more").unwrap();
        let c = id.ansi();
        assert_eq!(show(c.Domain, c.DomainLength), domain.as_bytes());
        assert_eq!(show(c.User, c.UserLength), user.as_bytes());
        assert_eq!(show(c.Password, c.PasswordLength), b"pw");
        assert_eq!(c.Flags, IDENTITY_ANSI);
        assert_eq!(c.Version, 0x200);
        assert_eq!(c.Length as usize, size_of_val(&c));

        let mut id = Identity::new(&utf16(given), &utf16("pé")).unwrap();
        let c = id.wide();
        assert_eq!(show(c.Domain, c.DomainLength), utf16(domain));
        assert_eq!(show(c.User, c.UserLength), utf16(user));
        assert_eq!(show(c.Password, c.PasswordLength), utf16("pé"));
        assert_eq!(c.Flags, IDENTITY_UNICODE);
        assert_eq!(c.Version, 0x200);
        assert_eq!(c.Length as usize, size_of_val(&c));
    }
}

/// The answers of a server whose entry and attribute are named outside
/// ASCII, in UTF-8 as LDAP has them: a bind taken, then the entry and a
/// result.
fn finds_one_named_in_utf8(op: u8, id: u8) -> Vec<Vec<u8>> {
    match op {
        0x60 => vec![ldap_message(id, &result_op(0x61, 0, b""))],
        0x63 => vec![
            ldap_message(
                id,
                &entry_op(
                    "cn=é,dc=x".as_bytes(),
                    &[("naïve".as_bytes(), &["é".as_bytes()])],
                ),
            ),
            ldap_message(id, &result_op(0x65, 0, b"")),
        ],
        _ => Vec::new(),
    }
}

/// Through the wide calls, as C's Unicode build makes them, the login,
/// the base, the filter and the attributes asked for are UTF-8 on the
/// wire, and the entry's name and its attributes' types come back as
/// UTF-8, the values as they are.
#[test]
fn the_wide_calls_speak_utf8() {
    let (port, server) = serve(finds_one_named_in_utf8);
    let mut session = open_with(&WIDE, port, false);
    session.set_version(Version::V3);
    let login = WinBind::Simple {
        user: "cn=é".as_bytes(),
        password: "pé".as_bytes(),
    };
    assert_eq!(session.bind(login), Code::SUCCESS);
    let search = Search {
        dn: Some("dc=café".as_bytes().to_vec()),
        scope: Scope::Subtree,
        filter: Some("(cn=é)".as_bytes().to_vec()),
        attrs: Some(vec!["naïve".as_bytes().to_vec()]),
    };
    let (code, mut found) = session.search(&search).unwrap();
    assert_eq!(code, Code::SUCCESS);
    assert!(found.next_entry());
    assert_eq!(found.dn().unwrap(), "cn=é,dc=x".as_bytes());
    let a = found.next_attribute().unwrap().unwrap();
    assert_eq!(
        (a.name, a.values),
        ("naïve".as_bytes(), Some(vec!["é".as_bytes()]))
    );
    assert!(found.next_attribute().unwrap().is_none());
    assert!(!found.next_entry());
    drop(found);
    drop(session);
    let got = server.join().unwrap();
    assert_eq!(ops(&got), [0x60, 0x63, 0x42]);
    assert_eq!(
        bind_of(&got[0].1),
        Sent::Simple(3, "cn=é".as_bytes().to_vec(), "pé".as_bytes().to_vec())
    );
    let sent = operation(&got[1].1);
    assert_eq!(sent[0].1, "dc=café".as_bytes());
    let attrs: Vec<_> = elements(&sent[7].1).into_iter().map(|(_, a)| a).collect();
    assert_eq!(attrs, ["naïve".as_bytes().to_vec()]);
    // The filter's equality match: its type and its value.
    let filter = elements(&sent[6].1);
    assert_eq!(filter[1].1, "é".as_bytes());
}

/// Through the wide calls a part of a simple bind that is not UTF-8 is
/// handed over as NULL, as C's Unicode build hands it: a user so is a
/// bind with no name.
#[test]
fn the_wide_calls_bind_with_no_name_for_a_user_that_is_not_utf8() {
    let (port, server) = serve(|op, id| finds_two(op, id, 0));
    let mut session = open_with(&WIDE, port, false);
    session.set_version(Version::V3);
    let login = WinBind::Simple {
        user: b"cn=\xe9",
        password: b"pw",
    };
    assert_eq!(session.bind(login), Code::SUCCESS);
    drop(session);
    let got = server.join().unwrap();
    assert_eq!(ops(&got), [0x60, 0x42]);
    assert_eq!(
        bind_of(&got[0].1),
        Sent::Simple(3, Vec::new(), b"pw".to_vec())
    );
}

/// The library names itself, its vendor and its codes as C's build has
/// them; C's parser's errors are the library's codes.
#[test]
fn the_library_names_itself_as_c_s_build_does() {
    assert_eq!(version(), "WinLDAP");
    assert_eq!(WINLDAP.vendor(), ("Microsoft Corporation.", 510));
    assert_eq!(WINLDAP.describe(Code::SUCCESS), b"Success");
    let url = LocalUrl {
        text: b"ldap://h/?a?nonsuch",
        path: b"/",
        query: Some(b"a?nonsuch"),
    };
    let bad = WINLDAP.parse_url(&url).unwrap_err();
    assert_eq!(bad, UrlError(0x15));
    assert_eq!(WINLDAP.describe(Code(bad.0)), b"Invalid Syntax");
    let url = LocalUrl {
        text: b"ldap://h/dc=%00",
        path: b"/dc=%00",
        query: None,
    };
    assert_eq!(WINLDAP.parse_url(&url), Err(UrlError(0x5a)));
    // A part that is not UTF-8 is refused as the wide calls cannot take
    // it, and taken as it is by the ANSI ones.
    let url = LocalUrl {
        text: b"ldap://h/dc=%e9",
        path: b"/dc=%e9",
        query: None,
    };
    assert_eq!(WIDE.parse_url(&url), Err(UrlError(0x5a)));
    assert_eq!(
        ANSI.parse_url(&url).map(|s| s.dn),
        Ok(Some(b"dc=\xe9".to_vec()))
    );
    assert_eq!(WINLDAP.wide, curl_os::UNICODE);
}
