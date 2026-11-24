use super::*;
use crate::ber::*;
use curl_core::ldap::{Scope, Transport};
use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

/// The version is the vendor's name and its number, as C prints it.
#[test]
fn the_version_is_the_vendor_and_its_number() {
    let v = version();
    let (vendor, number) = v.split_once('/').expect(v);
    assert_eq!(vendor, "OpenLDAP");
    let parts: Vec<u32> = number.split('.').map(|p| p.parse().unwrap()).collect();
    assert_eq!(parts.len(), 3, "{v}");
    assert!(parts[0] >= 2, "{v}");
}

/// A socket with no descriptor is one libldap cannot be given a copy of.
#[test]
fn a_socket_without_a_descriptor_makes_no_session() {
    let made = LIBLDAP.session(Transport::Bare(None), b"ldap", b"ldap://h:389");
    assert_eq!(made.err(), Some(SessionFailed::NoCopy));
}

/// A wire of bytes: what the session sends is kept, what it reads is
/// given from `incoming`.
#[derive(Default)]
struct Bytes {
    sent: Vec<u8>,
    incoming: Vec<u8>,
    reads: usize,
    /// It says it holds input it does not.
    claims: bool,
    /// Its sends would block.
    blocks: bool,
}

impl Wire for Bytes {
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        if self.incoming.is_empty() {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let n = buf.len().min(self.incoming.len());
        buf[..n].copy_from_slice(&self.incoming[..n]);
        self.incoming.drain(..n);
        Ok(n)
    }

    fn send(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.blocks {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        self.sent.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn pending(&mut self) -> bool {
        self.claims || !self.incoming.is_empty()
    }
}

/// A session made over a socket under layers is on the wire from the
/// start: its bind goes out on the wire, none of it on the socket, and
/// its unbind too as it is dropped.
#[test]
fn a_session_made_wired_says_nothing_on_its_socket() {
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    let mut session = LIBLDAP
        .session(
            Transport::Wired(Some(ours.as_fd())),
            b"ldap",
            b"ldap://h:389",
        )
        .unwrap();
    drop(ours);
    assert!(session.uses_wire());
    session.set_version(Version::V3);
    let mut wire = Bytes::default();
    let id = session
        .bind(&mut wire, Some(b"cn=me"), Mech::Simple, Some(b"pw"))
        .unwrap();
    let mut bind = ber(0x02, &[3]);
    bind.extend_from_slice(&ber(0x04, b"cn=me"));
    bind.extend_from_slice(&ber(0x80, b"pw"));
    assert_eq!(wire.sent, ldap_message(id.0 as u8, &ber(0x60, &bind)));
    wire.sent.clear();
    session.unbind(&mut wire);
    assert!(!wire.sent.is_empty(), "the unbind goes on the wire");
    drop(session);
    // The session's copy closed with it, the socket said nothing.
    let mut heard = Vec::new();
    theirs.read_to_end(&mut heard).unwrap();
    assert!(heard.is_empty(), "{heard:?}");
}

/// A session over the connection's layers sends and reads through the
/// wire each call is handed, and nothing through its socket: a bind is
/// answered, a search's entries are read with their attributes and its
/// result with the server's words, and its unbind goes out on the wire.
#[test]
fn a_session_over_a_wire_reads_and_writes_through_it() {
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    let mut session = LIBLDAP
        .session(
            Transport::Bare(Some(ours.as_fd())),
            b"ldap",
            b"ldap://h:389",
        )
        .unwrap();
    drop(ours);
    session.set_version(Version::V3);
    session.set_no_referrals();
    assert_eq!(session.set_max_incoming(256 * 1024), Ok(()));
    assert!(!session.uses_wire());
    assert_eq!(session.use_wire(), Ok(()));
    assert!(session.uses_wire());
    let mut wire = Bytes::default();
    let id = session
        .bind(&mut wire, Some(b"cn=me"), Mech::Simple, Some(b"pw"))
        .unwrap();
    // The bind: version 3, the name and the password, simple.
    let mut bind = ber(0x02, &[3]);
    bind.extend_from_slice(&ber(0x04, b"cn=me"));
    bind.extend_from_slice(&ber(0x80, b"pw"));
    assert_eq!(wire.sent, ldap_message(id.0 as u8, &ber(0x60, &bind)));
    // Nothing yet: the socket below is quiet, and the wire holds nothing,
    // so the layer is not read.
    assert!(
        session.result(&mut wire, id).unwrap().is_none(),
        "nothing yet"
    );
    assert_eq!(wire.reads, 0);
    wire.incoming = ldap_message(id.0 as u8, &result_op(0x61, 0, b""));
    let mut msg = session.result(&mut wire, id).unwrap().expect("answered");
    assert_eq!(msg.kind(), Kind::Bind);
    assert_eq!(msg.result().unwrap(), (Code::SUCCESS, None));
    assert_eq!(msg.bind_result().unwrap(), None);
    drop(msg);
    wire.sent.clear();
    let search = Search {
        dn: Some(b"dc=x".to_vec()),
        scope: Scope::Subtree,
        filter: Some(b"(cn=*)".to_vec()),
        attrs: Some(vec![b"cn".to_vec()]),
    };
    let id = session.search(&mut wire, &search).unwrap();
    // The request's base, then its scope: the subtree's, 2.
    let mut base_scope = ber(0x04, b"dc=x");
    base_scope.extend_from_slice(&ber(0x0a, &[2]));
    assert!(
        wire.sent.windows(base_scope.len()).any(|w| w == base_scope),
        "{:02x?}",
        wire.sent
    );
    let n = id.0 as u8;
    wire.incoming = ldap_message(
        n,
        &entry_op(b"cn=a,dc=x", &[(b"cn", &[b"a", b"b"]), (b"sn", &[])]),
    );
    wire.incoming
        .extend_from_slice(&ldap_message(n, &result_op(0x65, 4, b"too many")));
    let mut entry = session.result(&mut wire, id).unwrap().expect("an entry");
    assert_eq!(entry.kind(), Kind::SearchEntry);
    assert_eq!(entry.dn().unwrap(), b"cn=a,dc=x");
    let a = entry.next_attribute().unwrap().unwrap();
    assert_eq!(
        (a.name, a.values),
        (&b"cn"[..], Some(vec![&b"a"[..], b"b"]))
    );
    let a = entry.next_attribute().unwrap().unwrap();
    assert_eq!(a.name, b"sn");
    assert!(
        a.values.is_none_or(|v| v.is_empty()),
        "an attribute without values"
    );
    assert!(entry.next_attribute().unwrap().is_none());
    drop(entry);
    let mut done = session.result(&mut wire, id).unwrap().expect("the result");
    assert_eq!(done.kind(), Kind::SearchResult);
    assert_eq!(
        done.result().unwrap(),
        (Code::SIZELIMIT_EXCEEDED, Some(b"too many".to_vec()))
    );
    drop(done);
    wire.sent.clear();
    session.unbind(&mut wire);
    assert_eq!(wire.sent, ldap_message(n + 1, &ber(0x42, b"")));
    drop(session);
    // Nothing went through the socket, and the session's copy of it is
    // closed: the other end reads its end.
    theirs.set_nonblocking(false).unwrap();
    let mut rest = Vec::new();
    theirs.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "{rest:?}");
}

/// After a send over the layers that would block, the unbind is not
/// sent: the TLS below takes nothing but the blocked bytes again; one
/// whose sends went says its unbind (`oldap_disconnect`, upstream
/// 19216baa04).
#[test]
fn an_unbind_after_a_blocked_send_is_not_sent() {
    for blocked in [true, false] {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let mut session = LIBLDAP
            .session(
                Transport::Bare(Some(ours.as_fd())),
                b"ldap",
                b"ldap://h:389",
            )
            .unwrap();
        drop(ours);
        session.set_version(Version::V3);
        assert_eq!(session.use_wire(), Ok(()));
        let mut wire = Bytes {
            blocks: blocked,
            ..Bytes::default()
        };
        // Blocked, the bind is held to be sent again or fails; what it
        // says then does not matter here, only that its send blocked.
        let bound = session.bind(&mut wire, Some(b"cn=me"), Mech::Simple, Some(b"pw"));
        if !blocked {
            bound.expect("a bind whose send went");
        }
        let mut wire = Bytes::default();
        session.unbind(&mut wire);
        if blocked {
            assert_eq!(wire.sent, b"", "nothing after a blocked send");
        } else {
            assert!(
                wire.sent.windows(2).any(|w| w == [0x42, 0x00]),
                "the unbind: {:02x?}",
                wire.sent
            );
        }
    }
}

/// A session over its socket reads and writes the socket itself; a
/// failed read is the library's code.
#[test]
fn a_session_over_its_socket_uses_it() {
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    let mut session = LIBLDAP
        .session(
            Transport::Bare(Some(ours.as_fd())),
            b"ldap",
            b"ldap://h:389",
        )
        .unwrap();
    let mut unused = Bytes::default();
    let id = session
        .bind(&mut unused, None, Mech::Simple, Some(b""))
        .unwrap();
    assert!(unused.sent.is_empty());
    let mut got = [0u8; 64];
    let n = theirs.read(&mut got).unwrap();
    assert_eq!(got[0], 0x30, "{:?}", &got[..n]);
    theirs
        .write_all(&ldap_message(id.0 as u8, &result_op(0x61, 49, b"")))
        .unwrap();
    // The answer comes on the socket; a read that finds nothing is none.
    let msg = loop {
        if let Some(msg) = session.result(&mut unused, id).unwrap() {
            break msg;
        }
    };
    let mut msg = msg;
    assert_eq!(msg.result().unwrap().0, Code::INVALID_CREDENTIALS);
    drop(msg);
    drop(theirs);
    let failed = loop {
        match session.result(&mut unused, MsgId(-1)) {
            Ok(None) => continue,
            Ok(Some(_)) => panic!("no message"),
            Err(code) => break code,
        }
    };
    assert!(failed.0 < 0, "{failed:?}");
    assert_eq!(unused.reads, 0);
    drop(ours);
}

/// The notices a server sends unasked, message id 0, are let go as each
/// read takes them, so a server cannot grow what libldap keeps of them
/// without end (`oldap_result`): asked for after the search is read,
/// there is none left. The search's own messages are read as before.
#[test]
fn notices_sent_unasked_are_let_go() {
    let mut session = wired();
    let mut wire = Bytes::default();
    let search = Search {
        dn: Some(b"dc=x".to_vec()),
        scope: Scope::Subtree,
        filter: None,
        attrs: None,
    };
    let id = session.search(&mut wire, &search).unwrap();
    let n = id.0 as u8;
    // An extended response naming a notice other than the one of
    // disconnection, which the library acts on itself.
    let mut notice = result_op(0x78, 0, b"").split_off(2);
    notice.extend_from_slice(&ber(0x8a, b"1.3.6.1.4.1.99999.1"));
    let notice = ldap_message(0, &ber(0x78, &notice));
    for _ in 0..3 {
        wire.incoming.extend_from_slice(&notice);
    }
    wire.incoming
        .extend_from_slice(&ldap_message(n, &entry_op(b"cn=a,dc=x", &[])));
    wire.incoming.extend_from_slice(&notice);
    wire.incoming
        .extend_from_slice(&ldap_message(n, &result_op(0x65, 0, b"")));
    let kinds: Vec<Kind> = (0..2)
        .map(|_| session.result(&mut wire, id).unwrap().expect("read").kind())
        .collect();
    assert_eq!(kinds, [Kind::SearchEntry, Kind::SearchResult]);
    assert!(wire.incoming.is_empty(), "all read");
    let left = session
        .result(&mut wire, MsgId(0))
        .unwrap()
        .map(|m| m.kind());
    assert_eq!(left, None, "a notice kept");
}

/// A session over a wire, as the connect leaves it.
fn wired() -> Box<dyn Session> {
    let (ours, _theirs) = UnixStream::pair().unwrap();
    let mut session = LIBLDAP
        .session(
            Transport::Bare(Some(ours.as_fd())),
            b"ldap",
            b"ldap://h:389",
        )
        .unwrap();
    drop(ours);
    session.set_version(Version::V3);
    session.set_no_referrals();
    assert_eq!(session.use_wire(), Ok(()));
    session
}

/// An answer larger than the most the session takes is refused; a read
/// of the layer that finds nothing yet is no answer, not the end; a bind
/// answer's credentials are the server's; an abandon is sent.
#[test]
fn a_wired_session_s_limits_and_answers_are_the_library_s() {
    let search = Search {
        dn: Some(b"dc=x".to_vec()),
        scope: Scope::Subtree,
        filter: None,
        attrs: None,
    };
    let big = |n: u8| ldap_message(n, &entry_op(b"cn=a,dc=x", &[(b"cn", &[&[b'a'; 100]])]));
    for (max, taken) in [(64, false), (1024, true)] {
        let mut session = wired();
        assert_eq!(session.set_max_incoming(max), Ok(()));
        let mut wire = Bytes::default();
        let id = session.search(&mut wire, &search).unwrap();
        wire.incoming = big(id.0 as u8);
        let got = session.result(&mut wire, id).map(|m| m.is_some());
        assert_eq!(got.is_ok(), taken, "{max}: {got:?}");
    }
    let mut session = wired();
    let mut wire = Bytes {
        claims: true,
        ..Bytes::default()
    };
    let id = session
        .bind(&mut wire, None, Mech::Simple, Some(b""))
        .unwrap();
    assert!(session.result(&mut wire, id).unwrap().is_none());
    assert!(wire.reads > 0, "the layer was read");
    let mut op = ber(0x0a, &[14]);
    op.extend_from_slice(&ber(0x04, b""));
    op.extend_from_slice(&ber(0x04, b""));
    op.extend_from_slice(&ber(0x87, b"chal"));
    wire.incoming = ldap_message(id.0 as u8, &ber(0x61, &op));
    let mut msg = session.result(&mut wire, id).unwrap().expect("answered");
    assert_eq!(msg.bind_result(), Ok(Some(b"chal".to_vec())));
    drop(msg);
    wire.sent.clear();
    session.abandon(&mut wire, MsgId(5));
    assert_eq!(wire.sent, ldap_message(id.0 as u8 + 1, &ber(0x50, &[5])));
}

/// A session dropped unbinds over its socket, and closes it.
#[test]
fn a_session_dropped_says_goodbye_and_closes() {
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    let session = LIBLDAP
        .session(
            Transport::Bare(Some(ours.as_fd())),
            b"ldap",
            b"ldap://h:389",
        )
        .unwrap();
    drop(ours);
    drop(session);
    theirs
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut got = Vec::new();
    theirs.read_to_end(&mut got).unwrap();
    assert_eq!(got, ldap_message(1, &ber(0x42, b"")));
}

/// A search's answer as a server might send it, every kind of message
/// the session reads.
fn answer(n: u8) -> Vec<u8> {
    let mut a = ldap_message(
        n,
        &entry_op(b"cn=a,dc=x", &[(b"cn", &[b"a", b"b"]), (b"sn", &[])]),
    );
    a.extend_from_slice(&ldap_message(
        n,
        &ber(0x73, &ber(0x04, b"ldap://elsewhere/")),
    ));
    a.extend_from_slice(&ldap_message(
        n,
        &entry_op(b"", &[(b"x;binary", &[b"\x00\xff"])]),
    ));
    a.extend_from_slice(&ldap_message(n, &result_op(0x65, 0, b"done")));
    a
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..proptest::prelude::ProptestConfig::default()
    })]

    /// Any bytes in answer to a search, a server's or mangled: each
    /// message is read with every accessor, or refused with a code, and
    /// nothing panics, however the reads cut them.
    #[test]
    fn any_answer_is_read_or_refused(
        edits in proptest::collection::vec((proptest::num::usize::ANY, proptest::num::u8::ANY, 0u8..3), 0..6),
        cut in proptest::option::of(proptest::num::usize::ANY),
        chunk in 1usize..64,
    ) {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let mut session = LIBLDAP
            .session(Transport::Bare(Some(ours.as_fd())), b"ldap", b"ldap://h:389")
            .unwrap();
        drop(ours);
        session.set_version(Version::V3);
        // As the connect sets it: with referrals chased, the library
        // would connect to whatever host a mangled answer named.
        session.set_no_referrals();
        assert_eq!(session.set_max_incoming(256 * 1024), Ok(()));
        assert_eq!(session.use_wire(), Ok(()));
        let mut wire = Bytes::default();
        let search = Search { dn: Some(b"dc=x".to_vec()), scope: Scope::Subtree, filter: None, attrs: None };
        let id = session.search(&mut wire, &search).unwrap();
        let mut bytes = answer(id.0 as u8);
        for (at, byte, how) in edits {
            let at = at % (bytes.len() + 1);
            match how {
                0 if at < bytes.len() => bytes[at] = byte,
                1 => bytes.insert(at, byte),
                _ if at < bytes.len() => {
                    bytes.remove(at);
                }
                _ => {}
            }
        }
        if let Some(cut) = cut {
            bytes.truncate(cut % (bytes.len() + 1));
        }
        let mut rest = &bytes[..];
        // Each round hands the library a chunk more, until it has all and
        // gives nothing more, or a result.
        for _ in 0..(bytes.len() / chunk + 16) {
            let (now, later) = rest.split_at(chunk.min(rest.len()));
            wire.incoming.extend_from_slice(now);
            rest = later;
            match session.result(&mut wire, id) {
                Err(_) => break,
                Ok(None) if rest.is_empty() && wire.incoming.is_empty() => break,
                Ok(None) => {}
                Ok(Some(mut msg)) => {
                    let kind = msg.kind();
                    let _ = msg.result();
                    let _ = msg.bind_result();
                    if kind == Kind::SearchEntry && msg.dn().is_ok() {
                        let mut attrs = 0;
                        while let Ok(Some(attr)) = msg.next_attribute() {
                            let seen: usize = attr.values.iter().flatten().map(|b| b.len()).sum();
                            proptest::prop_assert!(seen <= bytes.len());
                            attrs += 1;
                            proptest::prop_assert!(attrs < 64, "the attributes end");
                        }
                    }
                    if kind == Kind::SearchResult {
                        break;
                    }
                }
            }
        }
    }
}
