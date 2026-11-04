use super::*;
use crate::ber::*;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::thread;

/// One LDAP message read off `s`: its operation's tag and the whole
/// message; none at the end.
fn read_message(s: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    if s.read_exact(&mut head).is_err() {
        return None;
    }
    assert_eq!(head[0], 0x30, "a message");
    let len = if head[1] < 0x80 {
        usize::from(head[1])
    } else {
        let mut n = vec![0u8; usize::from(head[1] & 0x7f)];
        s.read_exact(&mut n).unwrap();
        n.iter().fold(0, |a, &b| a << 8 | usize::from(b))
    };
    let mut content = vec![0u8; len];
    s.read_exact(&mut content).unwrap();
    // The message id, an integer, then the operation.
    let id_len = usize::from(content[1]);
    let op = content[2 + id_len];
    Some((op, content))
}

/// The id of the message `content` is.
fn id_of(content: &[u8]) -> u8 {
    assert_eq!((content[0], content[1]), (0x02, 1), "a one-byte id");
    content[2]
}

/// A server on a port of its own that answers each request as `answer`
/// says, a message for each, and gives the operations it was sent.
fn serve(answer: fn(u8, u8) -> Vec<Vec<u8>>) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut ops = Vec::new();
        while let Some((op, content)) = read_message(&mut s) {
            ops.push(op);
            for m in answer(op, id_of(&content)) {
                s.write_all(&m).unwrap();
            }
        }
        ops
    });
    (port, server)
}

/// The answers of a server that finds two entries: a bind taken, then
/// the search's entries and its result, `code`.
fn finds_two(op: u8, id: u8, code: u8) -> Vec<Vec<u8>> {
    match op {
        0x60 => vec![ldap_message(id, &result_op(0x61, 0, b""))],
        0x63 => vec![
            ldap_message(
                id,
                &entry_op(b"cn=a,dc=x", &[(b"cn", &[b"a", b"b"]), (b"sn", &[])]),
            ),
            ldap_message(id, &entry_op(b"cn=c,dc=x", &[(b"photo", &[b"\x00\x01"])])),
            ldap_message(id, &result_op(0x65, code, b"")),
        ],
        _ => Vec::new(),
    }
}

fn search() -> Search {
    LEGACY
        .parse_url(b"ldap://h/dc=x??sub?(objectClass=*)")
        .unwrap()
}

/// A session of the library's own reaches the host and port it is
/// given, binds and searches there, each call waiting for its answer;
/// the entries of the answer are read in turn with their attributes and
/// values, and the session unbinds as it is dropped.
#[test]
fn a_session_binds_and_searches_on_a_connection_of_its_own() {
    let (port, server) = serve(|op, id| finds_two(op, id, 0));
    let mut session = LEGACY.open(b"127.0.0.1", port).unwrap();
    session.set_network_timeout(Duration::from_secs(10));
    session.set_version(Version::V3);
    session.set_no_referrals();
    assert_eq!(session.bind(None, None), Code::SUCCESS);
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
    // The bind, the search, the unbind.
    assert_eq!(server.join().unwrap(), [0x60, 0x63, 0x42]);
}

/// A search cut short by the size limit gives what came and says so.
#[test]
fn a_search_cut_short_gives_what_came() {
    let (port, server) = serve(|op, id| finds_two(op, id, 4));
    let mut session = LEGACY.open(b"127.0.0.1", port).unwrap();
    session.set_version(Version::V3);
    assert_eq!(session.bind(None, None), Code::SUCCESS);
    let (code, mut found) = session.search(&search()).unwrap();
    assert_eq!(code, Code::SIZELIMIT_EXCEEDED);
    assert!(found.next_entry());
    assert!(found.next_entry());
    assert!(!found.next_entry());
    drop(found);
    drop(session);
    server.join().unwrap();
}

/// A bind the server refuses is its code, as is a search it refuses.
#[test]
fn refusals_are_the_server_s_codes() {
    let (port, server) = serve(|op, id| match op {
        0x60 => vec![ldap_message(id, &result_op(0x61, 49, b""))],
        _ => Vec::new(),
    });
    let mut session = LEGACY.open(b"127.0.0.1", port).unwrap();
    session.set_version(Version::V3);
    assert_eq!(
        session.bind(Some(b"cn=me"), Some(b"pw")),
        Code::INVALID_CREDENTIALS
    );
    drop(session);
    server.join().unwrap();

    let (port, server) = serve(|op, id| match op {
        0x60 => vec![ldap_message(id, &result_op(0x61, 0, b""))],
        0x63 => vec![ldap_message(id, &result_op(0x65, 32, b""))],
        _ => Vec::new(),
    });
    let mut session = LEGACY.open(b"127.0.0.1", port).unwrap();
    session.set_version(Version::V3);
    assert_eq!(session.bind(None, None), Code::SUCCESS);
    assert_eq!(session.search(&search()).err(), Some(Code(32)));
    drop(session);
    server.join().unwrap();
}

/// The TLS options `lib/ldap.c` sets are taken, but for a CA file on
/// macOS: Apple's library refuses one whatever it names
/// (`LDAP_OPT_ERROR`), so C's `ldaps:` with the peer verified fails
/// there, as ours does with the library's answer.
#[test]
fn the_tls_options_are_taken() {
    let mut session = LEGACY.open(b"127.0.0.1", 9).unwrap();
    let ca = session.set_ca_file(b"/nonexistent/ca.pem");
    if cfg!(target_vendor = "apple") {
        assert_eq!(ca, Err(Code(-1)));
    } else {
        assert_eq!(ca, Ok(()));
    }
    assert_eq!(session.set_require_cert(RequireCert::Demand), Ok(()));
    assert_eq!(session.set_require_cert(RequireCert::Never), Ok(()));
    assert_eq!(session.set_tls_hard(), Ok(()));
    assert_eq!(LEGACY.tls(), LocalTls::OpenLdap);
}

/// The vendor is the headers' and the version the library's, Apple's
/// marked as C marks it.
#[test]
fn the_vendor_and_version_are_the_library_s() {
    let (name, number) = LEGACY.vendor();
    assert!(!name.is_empty());
    assert!(number >= 20000, "{number}");
    let v = version();
    let (vendor, rest) = v.split_once('/').expect(v);
    assert_eq!(vendor, name, "{v}");
    let apple = cfg!(target_vendor = "apple");
    assert_eq!(rest.ends_with("/Apple"), apple, "{v}");
    let number = rest.trim_end_matches("/Apple");
    let parts: Vec<u32> = number.split('.').map(|p| p.parse().unwrap()).collect();
    assert_eq!(parts.len(), 3, "{v}");
    assert_eq!(LEGACY.bind_call(), "ldap_simple_bind_s");
}
