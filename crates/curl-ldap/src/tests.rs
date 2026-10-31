use super::*;
use std::io::{Read as _, Write as _};
use std::mem::{offset_of, size_of};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;

/// The values and layouts `sys.rs` declares are the headers', in
/// `csrc/layout.c`'s order: a value or field out of step reads or writes
/// the wrong bytes, which no other test would see.
#[test]
fn the_declarations_are_the_headers() {
    use sys::*;
    let n = |v: usize| i64::try_from(v).unwrap();
    let ours: [i64; LAYOUT_LEN] = [
        LDAP_SUCCESS.into(),
        LDAP_OPT_SUCCESS.into(),
        LDAP_OPT_API_INFO.into(),
        LDAP_OPT_REFERRALS.into(),
        LDAP_OPT_PROTOCOL_VERSION.into(),
        LDAP_OPT_SOCKBUF.into(),
        LDAP_API_INFO_VERSION.into(),
        LDAP_MSG_ONE.into(),
        LDAP_RES_BIND.into(),
        LDAP_RES_SEARCH_ENTRY.into(),
        LDAP_RES_SEARCH_REFERENCE.into(),
        LDAP_RES_SEARCH_RESULT.into(),
        LDAP_RES_EXTENDED.into(),
        LBER_SB_OPT_DATA_READY.into(),
        LBER_SB_OPT_SET_MAX_INCOMING.into(),
        LBER_SBIOD_LEVEL_TRANSPORT.into(),
        LDAP_URL_SUCCESS.into(),
        LDAP_URL_ERR_MEM.into(),
        n(size_of::<berval>()),
        n(offset_of!(berval, bv_len)),
        n(offset_of!(berval, bv_val)),
        n(size_of::<ber_len_t>()),
        n(size_of::<ber_slen_t>()),
        n(size_of::<ber_socket_t>()),
        n(size_of::<LDAPURLDesc>()),
        n(offset_of!(LDAPURLDesc, lud_next)),
        n(offset_of!(LDAPURLDesc, lud_scheme)),
        n(offset_of!(LDAPURLDesc, lud_host)),
        n(offset_of!(LDAPURLDesc, lud_port)),
        n(offset_of!(LDAPURLDesc, lud_dn)),
        n(offset_of!(LDAPURLDesc, lud_attrs)),
        n(offset_of!(LDAPURLDesc, lud_scope)),
        n(offset_of!(LDAPURLDesc, lud_filter)),
        n(offset_of!(LDAPURLDesc, lud_exts)),
        n(offset_of!(LDAPURLDesc, lud_crit_exts)),
        n(size_of::<LDAPAPIInfo>()),
        n(offset_of!(LDAPAPIInfo, ldapai_info_version)),
        n(offset_of!(LDAPAPIInfo, ldapai_api_version)),
        n(offset_of!(LDAPAPIInfo, ldapai_protocol_version)),
        n(offset_of!(LDAPAPIInfo, ldapai_extensions)),
        n(offset_of!(LDAPAPIInfo, ldapai_vendor_name)),
        n(offset_of!(LDAPAPIInfo, ldapai_vendor_version)),
        n(size_of::<Sockbuf_IO_Desc>()),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_level)),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_sb)),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_io)),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_pvt)),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_next)),
        n(size_of::<Sockbuf_IO>()),
        n(offset_of!(Sockbuf_IO, sbi_setup)),
        n(offset_of!(Sockbuf_IO, sbi_remove)),
        n(offset_of!(Sockbuf_IO, sbi_ctrl)),
        n(offset_of!(Sockbuf_IO, sbi_read)),
        n(offset_of!(Sockbuf_IO, sbi_write)),
        n(offset_of!(Sockbuf_IO, sbi_close)),
        Code::PROTOCOL_ERROR.0.into(),
        Code::SIZELIMIT_EXCEEDED.0.into(),
        Code::SASL_BIND_IN_PROGRESS.0.into(),
        Code::INVALID_CREDENTIALS.0.into(),
        Code::INSUFFICIENT_ACCESS.0.into(),
        Code::NO_MEMORY.0.into(),
        Code::NO_RESULTS_RETURNED.0.into(),
        UrlError::BAD_URL.0.into(),
    ];
    // SAFETY: a table of `LAYOUT_LEN` numbers C defines, read only.
    let theirs = unsafe { curl_ldap_values };
    for (i, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
        assert_eq!(o, t, "entry {i} of csrc/layout.c");
    }
}

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

/// A URL's search is the library's reading of it; a bad one is the
/// library's number for what is wrong.
#[test]
fn a_url_names_its_search() {
    let s = LIBLDAP
        .parse_url(b"ldap://h:389/dc=example,dc=com?cn,mail?sub?(cn=a*)")
        .unwrap();
    assert_eq!(s.dn.as_deref(), Some(&b"dc=example,dc=com"[..]));
    assert_eq!(s.scope, 2);
    assert_eq!(s.filter.as_deref(), Some(&b"(cn=a*)"[..]));
    assert_eq!(s.attrs, Some(vec![b"cn".to_vec(), b"mail".to_vec()]));
    let base = LIBLDAP.parse_url(b"ldap://h/").unwrap();
    assert_eq!((base.attrs, base.scope), (None, 0));
    assert_eq!(LIBLDAP.parse_url(b"http://h/"), Err(UrlError(3)));
    assert_eq!(LIBLDAP.parse_url(b"ldap://h/?a?nonsuch"), Err(UrlError(8)));
    assert_eq!(LIBLDAP.parse_url(b"ldap://h/\0x"), Err(UrlError::BAD_URL));
}

/// The library's words for a code are its own.
#[test]
fn a_code_is_described_in_the_library_s_words() {
    assert_eq!(LIBLDAP.describe(Code::SUCCESS), b"Success");
    assert_eq!(
        LIBLDAP.describe(Code::INVALID_CREDENTIALS),
        b"Invalid credentials"
    );
}

/// A wire of bytes: what the session sends is kept, what it reads is
/// given from `incoming`.
#[derive(Default)]
struct Bytes {
    sent: Vec<u8>,
    incoming: Vec<u8>,
    reads: usize,
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
        self.sent.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn pending(&mut self) -> bool {
        !self.incoming.is_empty()
    }
}

/// A BER element: `tag`, its length and `content`.
fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    if content.len() < 128 {
        v.push(content.len() as u8);
    } else {
        v.push(0x82);
        v.extend_from_slice(&(content.len() as u16).to_be_bytes());
    }
    v.extend_from_slice(content);
    v
}

/// An LDAP message of `id` holding `op`.
fn ldap_message(id: u8, op: &[u8]) -> Vec<u8> {
    let mut content = ber(0x02, &[id]);
    content.extend_from_slice(op);
    ber(0x30, &content)
}

/// A result operation of `tag`: `code`, an empty matched name and `info`.
fn result_op(tag: u8, code: u8, info: &[u8]) -> Vec<u8> {
    let mut content = ber(0x0a, &[code]);
    content.extend_from_slice(&ber(0x04, b""));
    content.extend_from_slice(&ber(0x04, info));
    ber(tag, &content)
}

/// An entry named `dn` with `attrs`, each its type and values.
fn entry_op(dn: &[u8], attrs: &[(&[u8], &[&[u8]])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (name, values) in attrs {
        let mut set = Vec::new();
        for v in *values {
            set.extend_from_slice(&ber(0x04, v));
        }
        let mut a = ber(0x04, name);
        a.extend_from_slice(&ber(0x31, &set));
        list.extend_from_slice(&ber(0x30, &a));
    }
    let mut content = ber(0x04, dn);
    content.extend_from_slice(&ber(0x30, &list));
    ber(0x64, &content)
}

/// A session over the connection's layers sends and reads through the
/// wire each call is handed, and nothing through its socket: a bind is
/// answered, a search's entries are read with their attributes and its
/// result with the server's words, and its unbind goes out on the wire.
#[test]
fn a_session_over_a_wire_reads_and_writes_through_it() {
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    let mut session = LIBLDAP
        .session(ours.as_raw_fd(), b"ldap", b"ldap://h:389")
        .unwrap()
        .unwrap();
    drop(ours);
    session.set_version(3);
    session.set_no_referrals();
    assert!(session.set_max_incoming(256 * 1024));
    assert!(!session.uses_wire());
    assert!(session.use_wire());
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
        scope: 2,
        filter: Some(b"(cn=*)".to_vec()),
        attrs: Some(vec![b"cn".to_vec()]),
    };
    let id = session.search(&mut wire, &search).unwrap();
    assert!(!wire.sent.is_empty());
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

/// A session over its socket reads and writes the socket itself; a
/// failed read is the library's code.
#[test]
fn a_session_over_its_socket_uses_it() {
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    let mut session = LIBLDAP
        .session(ours.as_raw_fd(), b"ldap", b"ldap://h:389")
        .unwrap()
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
            .session(ours.as_raw_fd(), b"ldap", b"ldap://h:389")
            .unwrap()
            .unwrap();
        drop(ours);
        session.set_version(3);
        // As the connect sets it: with referrals chased, the library
        // would connect to whatever host a mangled answer named.
        session.set_no_referrals();
        assert!(session.set_max_incoming(256 * 1024));
        assert!(session.use_wire());
        let mut wire = Bytes::default();
        let search = Search { dn: Some(b"dc=x".to_vec()), scope: 2, filter: None, attrs: None };
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
