use super::*;
use crate::ldap::Attribute;
use crate::options::AuthMethods;

/// An attribute's type and its values, if it came with any.
type Attr = (Vec<u8>, Option<Vec<Vec<u8>>>);

/// The same, borrowed.
type AttrRef<'a> = (&'a [u8], Option<&'a [&'a [u8]]>);

/// An entry the fake server finds: its name and attributes.
type Found = (Vec<u8>, Vec<(Vec<u8>, Vec<Vec<u8>>)>);

/// An entry as a library would read it: its name, or the code it could
/// not be read with, and its attributes, each a type and its values.
struct Entry {
    dn: Result<Vec<u8>, Code>,
    attrs: Vec<Attr>,
    next: usize,
}

impl Entry {
    fn new(dn: &[u8], attrs: &[AttrRef<'_>]) -> Entry {
        Entry {
            dn: Ok(dn.to_vec()),
            attrs: attrs
                .iter()
                .map(|(n, v)| {
                    (
                        n.to_vec(),
                        v.map(|v| v.iter().map(|b| b.to_vec()).collect()),
                    )
                })
                .collect(),
            next: 0,
        }
    }
}

impl Message for Entry {
    fn kind(&self) -> Kind {
        Kind::SearchEntry
    }

    fn result(&mut self) -> Result<(Code, Option<Vec<u8>>), Code> {
        Err(Code::NO_RESULTS_RETURNED)
    }

    fn bind_result(&mut self) -> Result<Option<Vec<u8>>, Code> {
        Ok(None)
    }

    fn dn(&mut self) -> Result<&[u8], Code> {
        self.dn.as_deref().map_err(|&c| c)
    }

    fn next_attribute(&mut self) -> Result<Option<Attribute<'_>>, curl_alloc::OutOfMemory> {
        let Some((name, values)) = self.attrs.get(self.next) else {
            return Ok(None);
        };
        self.next += 1;
        Ok(Some(Attribute {
            name,
            values: values
                .as_ref()
                .map(|v| v.iter().map(Vec::as_slice).collect()),
        }))
    }
}

/// The LDIF of `entry`, and the writes it was made of.
fn written(entry: &mut Entry) -> (Result<(), Ldif>, Vec<Vec<u8>>) {
    let mut writes = Vec::new();
    let r = ldif(entry, &mut |b| {
        writes.push(b.to_vec());
        Ok(())
    });
    (r, writes)
}

/// A string is LDIF's as it is only where RFC 2849 says it is safe: not
/// starting with `:`, `<` or a blank, not ending with a blank, every byte
/// printable; the empty string is safe.
#[test]
fn only_a_safe_string_goes_as_it_is() {
    for safe in [&b""[..], b"a", b"cn=Bob,dc=x", b"a b", b"a:b", b"a<b", b"~"] {
        assert!(!needs_base64(safe), "{safe:?}");
    }
    for not in [
        &b":a"[..],
        b"<a",
        b" a",
        b"\ta",
        b"a ",
        b"a\t",
        b"a\r\nb",
        b"\x7f",
        b"\x00",
        b"\xc3\xa9",
        b" ",
    ] {
        assert!(needs_base64(not), "{not:?}");
    }
}

/// An entry is written as C writes it: its name, each value after its
/// type, a binary type's and an unsafe value in base64, a type without
/// values alone, a blank line after each attribute and the entry; each
/// part a write of its own.
#[test]
fn an_entry_is_written_as_c_writes_it() {
    let mut e = Entry::new(
        b"cn=a,dc=x",
        &[
            (b"cn", Some(&[b"a", b"b"])),
            (b"description", Some(&[b" lead"])),
            (b"cert;binary", Some(&[b"ok", b""])),
            (b"empty", None),
            (b"sn", Some(&[b""])),
        ],
    );
    let (r, writes) = written(&mut e);
    assert_eq!(r, Ok(()));
    let all: Vec<u8> = writes.concat();
    assert_eq!(
        String::from_utf8(all).unwrap(),
        "DN: cn=a,dc=x\n\tcn: a\n\tcn: b\n\n\tdescription:: IGxlYWQ=\n\n\
         \tcert;binary:: b2s=\n\tcert;binary::\n\n\tempty:\n\tsn:\n\n\n"
    );
    // The writes C makes: an empty value's prefix loses its blank, and
    // the value is written empty; an empty binary value is not written.
    let ws: Vec<&[u8]> = writes.iter().map(Vec::as_slice).collect();
    assert_eq!(&ws[..3], [&b"DN: "[..], b"cn=a,dc=x", b"\n"]);
    let sn = ws.iter().rposition(|w| *w == b"sn").unwrap();
    assert_eq!(
        &ws[sn - 1..sn + 5],
        [&b"\t"[..], b"sn", b":", b"", b"", b"\n"]
    );
    let empty_binary = ws.iter().rposition(|w| *w == b"cert;binary").unwrap();
    assert_eq!(
        &ws[empty_binary + 1..empty_binary + 4],
        [&b":"[..], b":", b"\n"]
    );
}

/// A name that would break the LDIF is given in base64.
#[test]
fn an_unsafe_name_is_given_in_base64() {
    let mut e = Entry::new(b"cn=a\r\ndn: evil", &[]);
    let (r, writes) = written(&mut e);
    assert_eq!(r, Ok(()));
    assert_eq!(writes.concat(), b"DN:: Y249YQ0KZG46IGV2aWw=\n\n");
}

/// A type that would break the LDIF is refused, as LDIF has no base64
/// for one; a name the library cannot read is a failed read; a failed
/// write stops the entry.
#[test]
fn an_entry_that_cannot_be_written_safely_is_refused() {
    let mut e = Entry::new(b"cn=a", &[(b"cn", Some(&[b"a"])), (b"x\ny", Some(&[b"b"]))]);
    let (r, writes) = written(&mut e);
    assert_eq!(r, Err(Ldif::IllegalType));
    assert!(!writes.concat().windows(3).any(|w| w == b"x\ny"));
    let mut e = Entry::new(b"", &[]);
    e.dn = Err(Code(-1));
    assert_eq!(written(&mut e).0, Err(Ldif::Name));
    let mut e = Entry::new(b"cn=a", &[(b"cn", Some(&[b"a"]))]);
    let mut n = 0;
    let r = ldif(&mut e, &mut |_| {
        n += 1;
        if n == 4 {
            Err(ErrorKind::WriteError)
        } else {
            Ok(())
        }
    });
    assert_eq!((r, n), (Err(Ldif::Write(ErrorKind::WriteError)), 4));
}

/// The mechanisms an entry offers are those its values name whole; an
/// entry whose name cannot be read is the library's code.
#[test]
fn the_mechanisms_offered_are_named_whole() {
    let mut e = Entry::new(
        b"",
        &[(
            b"supportedSASLMechanisms",
            Some(&[b"PLAIN", b"CRAM-MD5", b"LOGINX", b"GSSAPI", b"DIGEST"]),
        )],
    );
    let m = mechanisms(&mut e).unwrap();
    assert!(m.has(Mechs::PLAIN) && m.has(Mechs::CRAM_MD5) && m.has(Mechs::GSSAPI));
    assert!(!m.has(Mechs::LOGIN) && !m.has(Mechs::DIGEST_MD5));
    let mut e = Entry::new(b"", &[(b"supportedSASLMechanisms", None)]);
    assert_eq!(mechanisms(&mut e), Ok(Mechs::NONE));
    e.dn = Err(Code(-7));
    e.next = 0;
    assert_eq!(mechanisms(&mut e), Err(Code(-7)));
}

/// The login options are `AUTH=` and a mechanism each, `*` for any:
/// anything else is a syntax error, as C reports it.
#[test]
fn the_login_options_name_mechanisms() {
    let parse = |o: &[u8]| {
        let mut sasl = Sasl::new(&SASL, AuthMethods::BASIC);
        parse_login_options(&mut sasl, o).map(|()| sasl.preferred())
    };
    assert_eq!(parse(b""), Ok(Mechs::NONE));
    assert_eq!(parse(b"AUTH=PLAIN"), Ok(Mechs::PLAIN));
    assert_eq!(parse(b"auth=plain"), Ok(Mechs::PLAIN));
    assert_eq!(
        parse(b"AUTH=PLAIN;AUTH=LOGIN"),
        Ok(Mechs::PLAIN.or(Mechs::LOGIN))
    );
    assert_eq!(parse(b"AUTH=*"), Ok(Mechs::DEFAULT));
    for bad in [
        &b"AUTH=NOSUCH"[..],
        b"FOO=bar",
        b"AUTH",
        b"AUTH=",
        b"AUTH=PLAIN;x",
    ] {
        assert_eq!(parse(bad), Err(ErrorKind::SetoptOptionSyntax), "{bad:?}");
    }
}

/// A mechanism from the application's HTTP methods, as C's SASL takes
/// them unless they are Basic's alone: LDAP then asks for mechanisms.
#[test]
fn the_http_methods_choose_mechanisms() {
    assert_eq!(
        Sasl::new(&SASL, AuthMethods::BASIC).preferred(),
        Mechs::NONE
    );
    assert!(
        Sasl::new(&SASL, AuthMethods::DIGEST)
            .preferred()
            .has(Mechs::DIGEST_MD5)
    );
}

/// The codes are the library's numbers, as its header has them (the
/// binding's tests compare them with it).
#[test]
fn the_codes_are_the_library_s_numbers() {
    let codes = [
        Code::SUCCESS,
        Code::PROTOCOL_ERROR,
        Code::SIZELIMIT_EXCEEDED,
        Code::SASL_BIND_IN_PROGRESS,
        Code::INVALID_CREDENTIALS,
        Code::INSUFFICIENT_ACCESS,
        Code::NO_MEMORY,
        Code::NO_RESULTS_RETURNED,
    ];
    assert_eq!(codes.map(|c| c.0), [0, 2, 4, 14, 49, 50, -10, -14]);
    assert_eq!((UrlError::MEM.0, UrlError::BAD_URL.0), (1, 5));
}

/// The codes C maps are mapped; any other is the caller's error.
#[test]
fn library_codes_map_as_c_maps_them() {
    let other = ErrorKind::LdapCannotBind;
    assert_eq!(map_error(Code::NO_MEMORY, other), ErrorKind::OutOfMemory);
    assert_eq!(
        map_error(Code::INVALID_CREDENTIALS, other),
        ErrorKind::LoginDenied
    );
    assert_eq!(
        map_error(Code::PROTOCOL_ERROR, other),
        ErrorKind::UnsupportedProtocol
    );
    assert_eq!(
        map_error(Code::INSUFFICIENT_ACCESS, other),
        ErrorKind::RemoteAccessDenied
    );
    assert_eq!(map_error(Code(32), other), other);
}

const NAMES: &[&[u8]] = &[
    b"cn=Bob,ou=people,dc=example,dc=com",
    b"",
    b" x",
    b"a\r\nb",
    b":colon",
    b"\xc3\xa9",
];
const VALUES: &[&[u8]] = &[
    b"Bob",
    b"",
    b" lead",
    b"two\r\nlines",
    b"<lt",
    b"\x00\x01\xff",
    b"ok;binary",
];
const TYPES: &[&[u8]] = &[
    b"cn",
    b"userCertificate;binary",
    b"x;BINARY",
    b";binary",
    b"a\nb",
    b"  ",
];

proptest::proptest! {
    #![proptest_config(crate::untrusted::config(512))]

    /// Any name, types and values a server sends: the entry is written or
    /// refused, never a panic; once written, every line is a name, a
    /// value after its type or a blank, so the server could add no line
    /// of its own; and each value is there, as it is or in base64.
    #[test]
    fn any_entry_is_written_safely_or_refused(
        dn in crate::untrusted::mutated(NAMES),
        attrs in proptest::collection::vec(
            (
                crate::untrusted::mutated(TYPES),
                proptest::option::of(proptest::collection::vec(crate::untrusted::mutated(VALUES), 0..4)),
            ),
            0..4,
        ),
    ) {
        let mut e = Entry {
            dn: Ok(dn.clone()),
            attrs: attrs.clone(),
            next: 0,
        };
        let (r, writes) = written(&mut e);
        let text = writes.concat();
        match r {
            Err(Ldif::IllegalType) => {
                proptest::prop_assert!(attrs.iter().any(|(n, _)| needs_base64(n)));
            }
            Err(other) => proptest::prop_assert!(false, "{other:?}"),
            Ok(()) => {
                proptest::prop_assert!(text.ends_with(b"\n\n"));
                let mut lines = text.split(|&b| b == b'\n');
                let first = lines.next().unwrap();
                proptest::prop_assert!(first.starts_with(b"DN: ") || first.starts_with(b"DN:: ") || first == b"DN:");
                for line in lines {
                    proptest::prop_assert!(
                        line.is_empty() || line.starts_with(b"\t"),
                        "{:?}", String::from_utf8_lossy(line)
                    );
                }
                for (name, values) in &attrs {
                    for v in values.iter().flatten() {
                        let binary = name.len() > 7
                            && name[name.len() - 7..].eq_ignore_ascii_case(b";binary");
                        let shown = if binary || needs_base64(v) {
                            base64(v).unwrap()
                        } else {
                            v.clone()
                        };
                        proptest::prop_assert!(
                            text.windows(shown.len().max(1)).any(|w| shown.is_empty() || w == &shown[..])
                        );
                    }
                }
            }
        }
    }

    /// Any login options are read or refused as a syntax error.
    #[test]
    fn any_login_options_are_read_or_refused(
        options in crate::untrusted::mutated(&[b"AUTH=PLAIN", b"AUTH=*;AUTH=LOGIN", b"AUTH=", b"X=1"]),
    ) {
        let mut sasl = Sasl::new(&SASL, AuthMethods::BASIC);
        let r = parse_login_options(&mut sasl, &options);
        proptest::prop_assert!(matches!(r, Ok(()) | Err(ErrorKind::SetoptOptionSyntax)));
    }
}

// Transfers over a fake LDAP library, whose server answers each message
// as its `World` says: the connect's binds, simple and SASL, the version 2
// fallback, STARTTLS refused, the search and its result.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::conn::io::{Conversation, FakeNet, Peer as Net};
use crate::easy::Easy;
use crate::handler::DebugKind;
use crate::handler::{DebugHandler, Write as Writes, WriteHandler};
use crate::id::ArenaPolicy;
use crate::ldap::{Ldap, Refused};
use crate::libraries::{Libraries, SharedLibraries};
use crate::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
use crate::options::Options;
use crate::time::ManualClock;

const PORT: u16 = 8389;

/// What the fake server answers, and the calls it was made.
#[derive(Debug)]
struct World {
    calls: Vec<String>,
    /// Each simple bind's answer in turn, success past the last.
    binds: VecDeque<Code>,
    /// Each SASL bind's answer in turn: its code and credentials.
    sasl: VecDeque<(Code, Option<Vec<u8>>)>,
    /// The mechanisms the server's root lists.
    mechs: Vec<Vec<u8>>,
    /// The entries a search finds, each a name and attributes.
    entries: Vec<Found>,
    /// A search's result.
    found: Code,
    /// STARTTLS's answer.
    starttls: Code,
    /// The library makes no session, this its code.
    refuse: Option<Code>,
    /// STARTTLS is not sent, this the library's code.
    starttls_unsent: Option<Code>,
    /// The root's entry's code, and the result of the search for it.
    root: Code,
    root_found: Code,
    /// So many asks for an answer find none yet.
    late: usize,
    /// So many asks for a search's entry find none yet.
    late_entry: usize,
    /// The trace says the writers' lines.
    trace_write: bool,
}

impl Default for World {
    fn default() -> World {
        World {
            calls: Vec::new(),
            binds: VecDeque::new(),
            sasl: VecDeque::new(),
            mechs: Vec::new(),
            entries: Vec::new(),
            found: Code::SUCCESS,
            starttls: Code::SUCCESS,
            refuse: None,
            starttls_unsent: None,
            root: Code::NO_RESULTS_RETURNED,
            root_found: Code::SUCCESS,
            late: 0,
            late_entry: 0,
            trace_write: false,
        }
    }
}

#[derive(Debug)]
struct FakeLdap(Arc<Mutex<World>>);

impl Ldap for FakeLdap {
    fn parse_url(&self, url: &[u8]) -> Result<Search, UrlError> {
        // `ldap://host:port/dn?attrs?scope?filter`, undecoded.
        let text = std::str::from_utf8(url).map_err(|_| UrlError::BAD_URL)?;
        let rest = text.split_once("://").ok_or(UrlError::BAD_URL)?.1;
        let path = rest.split_once('/').map_or("", |(_, p)| p);
        let mut parts = path.split('?');
        let some = |s: Option<&str>| s.filter(|s| !s.is_empty()).map(|s| s.as_bytes().to_vec());
        let dn = some(parts.next());
        let attrs =
            some(parts.next()).map(|a| a.split(|&b| b == b',').map(<[u8]>::to_vec).collect());
        let scope = match parts.next() {
            Some("one") => Scope::OneLevel,
            Some("sub") => Scope::Subtree,
            Some("children") => Scope::Subordinate,
            _ => Scope::Base,
        };
        let filter = some(parts.next());
        Ok(Search {
            dn,
            scope,
            filter,
            attrs,
        })
    }

    fn session(
        &self,
        _: Option<curl_os::socket::BorrowedSocket<'_>>,
        scheme: &[u8],
        url: &[u8],
    ) -> Result<Box<dyn Session>, SessionFailed> {
        let mut w = self.0.lock().unwrap();
        w.calls.push(format!(
            "session {} {}",
            String::from_utf8_lossy(scheme),
            String::from_utf8_lossy(url)
        ));
        if let Some(code) = w.refuse {
            return Err(SessionFailed::Library(code));
        }
        Ok(Box::new(FakeSession {
            world: self.0.clone(),
            next: 1,
            answers: VecDeque::new(),
            wired: false,
        }))
    }

    fn describe(&self, code: Code) -> &'static [u8] {
        match code {
            Code::SUCCESS => b"Success",
            Code::INVALID_CREDENTIALS => b"Invalid credentials",
            _ => b"Other",
        }
    }
}

#[derive(Debug)]
struct FakeSession {
    world: Arc<Mutex<World>>,
    next: i32,
    /// The messages answering what was sent, each with its id.
    answers: VecDeque<(MsgId, Answer)>,
    wired: bool,
}

#[derive(Debug, Clone)]
struct Answer {
    kind: Kind,
    code: Code,
    cred: Option<Vec<u8>>,
    /// Its credentials cannot be read, the library's code: a failed
    /// simple bind's, as libldap reads one.
    unread: Option<Code>,
    dn: Vec<u8>,
    attrs: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
    at: usize,
}

impl Answer {
    fn of(kind: Kind, code: Code) -> Answer {
        Answer {
            kind,
            code,
            cred: None,
            unread: None,
            dn: Vec::new(),
            attrs: Vec::new(),
            at: 0,
        }
    }
}

impl FakeSession {
    fn call(&self, said: String) {
        self.world.lock().unwrap().calls.push(said);
    }

    /// Once wired, each message goes through the wire as a line, as
    /// the library's would.
    fn put(&self, wire: &mut dyn Wire, said: &str) {
        if !self.wired {
            return;
        }
        let line = format!("{said}\n");
        let mut rest = line.as_bytes();
        while !rest.is_empty() {
            match wire.send(rest) {
                Ok(0) => return self.call("sent none".into()),
                Ok(n) => rest = &rest[n..],
                Err(e) => return self.call(format!("send failed {:?}", e.kind())),
            }
        }
    }

    fn sent(&mut self, answers: Vec<Answer>) -> MsgId {
        let id = MsgId(self.next);
        self.next += 1;
        self.answers.extend(answers.into_iter().map(|a| (id, a)));
        id
    }
}

fn shown(b: Option<&[u8]>) -> String {
    b.map_or("-".into(), |b| {
        String::from_utf8_lossy(b).replace('\0', "\\0")
    })
}

impl Session for FakeSession {
    fn set_version(&mut self, version: Version) {
        let number = match version {
            Version::V2 => 2,
            Version::V3 => 3,
        };
        self.call(format!("version {number}"));
    }

    fn set_no_referrals(&mut self) {
        self.call("no referrals".into());
    }

    fn set_max_incoming(&mut self, max: usize) -> Result<(), Refused> {
        self.call(format!("max {max}"));
        Ok(())
    }

    fn use_wire(&mut self) -> Result<(), Refused> {
        self.wired = true;
        Ok(())
    }

    fn uses_wire(&self) -> bool {
        self.wired
    }

    fn bind(
        &mut self,
        wire: &mut dyn Wire,
        dn: Option<&[u8]>,
        mech: Mech<'_>,
        cred: Option<&[u8]>,
    ) -> Result<MsgId, Code> {
        let (said, answer) = match mech {
            Mech::Simple => {
                let code = self
                    .world
                    .lock()
                    .unwrap()
                    .binds
                    .pop_front()
                    .unwrap_or(Code::SUCCESS);
                let mut a = Answer::of(Kind::Bind, code);
                a.unread = (code != Code::SUCCESS).then_some(code);
                ("simple".to_string(), a)
            }
            Mech::Null => ("null".to_string(), Answer::of(Kind::Bind, Code(0x07))),
            Mech::Sasl(m) => {
                let next = self.world.lock().unwrap().sasl.pop_front();
                let (code, cred) = next.unwrap_or((Code::SUCCESS, None));
                let mut a = Answer::of(Kind::Bind, code);
                a.cred = cred;
                (format!("sasl {}", String::from_utf8_lossy(m)), a)
            }
        };
        let said = format!("bind {} {said} {}", shown(dn), shown(cred));
        self.put(wire, &said);
        self.call(said);
        Ok(self.sent(vec![answer]))
    }

    fn search(&mut self, wire: &mut dyn Wire, search: &Search) -> Result<MsgId, Code> {
        let said = format!(
            "search {} {} {} {:?}",
            shown(search.dn.as_deref()),
            search.scope as u8,
            shown(search.filter.as_deref()),
            search.attrs.as_ref().map(|a| a
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>()),
        );
        self.put(wire, &said);
        self.call(said);
        let w = self.world.lock().unwrap();
        let mut answers = Vec::new();
        let asks_mechs =
            search.attrs.as_deref() == Some(&[b"supportedSASLMechanisms".to_vec()][..]);
        if asks_mechs {
            let mut root = Answer::of(Kind::SearchEntry, w.root);
            root.attrs = vec![(b"supportedSASLMechanisms".to_vec(), w.mechs.clone())];
            answers.push(root);
            answers.push(Answer::of(Kind::SearchResult, w.root_found));
        } else {
            for (dn, attrs) in &w.entries {
                let mut e = Answer::of(Kind::SearchEntry, Code::NO_RESULTS_RETURNED);
                e.dn = dn.clone();
                e.attrs = attrs.clone();
                answers.push(e);
            }
            answers.push(Answer::of(Kind::SearchResult, w.found));
        }
        drop(w);
        Ok(self.sent(answers))
    }

    fn start_tls(&mut self, wire: &mut dyn Wire) -> Result<MsgId, Code> {
        if let Some(code) = self.world.lock().unwrap().starttls_unsent {
            return Err(code);
        }
        self.put(wire, "starttls");
        self.call("starttls".into());
        let code = self.world.lock().unwrap().starttls;
        Ok(self.sent(vec![Answer::of(Kind::Extended, code)]))
    }

    fn result<'s>(
        &'s mut self,
        wire: &mut dyn Wire,
        id: MsgId,
    ) -> Result<Option<Box<dyn Message + 's>>, Code> {
        {
            let mut w = self.world.lock().unwrap();
            if w.late > 0 {
                w.late -= 1;
                return Ok(None);
            }
            let entry = self
                .answers
                .front()
                .is_some_and(|(_, a)| a.kind == Kind::SearchEntry);
            if entry && w.late_entry > 0 {
                w.late_entry -= 1;
                return Ok(None);
            }
        }
        match self.answers.front() {
            Some((at, _)) if *at == id => {
                // Once wired, each answer is a byte `A` the server sent,
                // read through the wire.
                if self.wired {
                    let pending = wire.pending();
                    let mut byte = [0];
                    match wire.recv(&mut byte) {
                        Ok(1) if byte == *b"A" => self.call(format!("read, pending {pending}")),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
                        other => {
                            self.call(format!("read {other:?} {byte:?}"));
                            return Err(Code(-1));
                        }
                    }
                }
                let (_, a) = self.answers.pop_front().unwrap();
                Ok(Some(Box::new(a)))
            }
            _ => Ok(None),
        }
    }

    fn abandon(&mut self, _: &mut dyn Wire, id: MsgId) {
        self.call(format!("abandon {}", id.0));
        self.answers.retain(|(at, _)| *at != id);
    }

    fn unbind(&mut self, wire: &mut dyn Wire) {
        self.put(wire, "unbind");
        self.call("unbind".into());
    }
}

impl Message for Answer {
    fn kind(&self) -> Kind {
        self.kind
    }

    fn result(&mut self) -> Result<(Code, Option<Vec<u8>>), Code> {
        Ok((self.code, None))
    }

    fn bind_result(&mut self) -> Result<Option<Vec<u8>>, Code> {
        match self.unread {
            Some(code) => Err(code),
            None => Ok(self.cred.clone()),
        }
    }

    fn dn(&mut self) -> Result<&[u8], Code> {
        Ok(&self.dn)
    }

    fn next_attribute(&mut self) -> Result<Option<Attribute<'_>>, curl_alloc::OutOfMemory> {
        let Some((name, values)) = self.attrs.get(self.at) else {
            return Ok(None);
        };
        self.at += 1;
        Ok(Some(Attribute {
            name,
            values: Some(values.iter().map(Vec::as_slice).collect()),
        }))
    }
}

#[derive(Clone, Default)]
struct Body(Arc<Mutex<Vec<u8>>>);

impl WriteHandler for Body {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Writes {
        self.0.lock().unwrap().extend_from_slice(body);
        Writes::Took(body.len())
    }
}

/// Refuses every write.
struct Refuses;

impl WriteHandler for Refuses {
    fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Writes {
        Writes::Took(0)
    }
}

#[derive(Clone, Default)]
struct Text(Arc<Mutex<Vec<u8>>>);

impl DebugHandler for Text {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text {
            self.0.lock().unwrap().extend_from_slice(data);
        }
    }
}

/// What a transfer came to: its result, body, trace and the library's
/// calls.
struct Ran {
    result: Result<(), ErrorKind>,
    body: Vec<u8>,
    said: String,
    /// The multi's own trace, as its connections shut down.
    internal: String,
    calls: Vec<String>,
}

/// Collects the multi's own trace.
#[derive(Clone, Default)]
struct Internal(Arc<Mutex<Vec<u8>>>);

impl crate::handler::TextSink for Internal {
    fn write(&self, text: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(text);
    }
}

/// Run `url` over a world `world` sets, the transfer as `set` sets it.
fn run(url: &str, world: impl FnOnce(&mut World), set: impl FnOnce(&mut Options)) -> Ran {
    // A peer that speaks first, unread: the socket stays readable, as
    // the fake library reads none of it.
    let talk = Conversation::replies(&[b"unread"], false).greeting();
    run_over(url, None, talk, world, set)
}

/// The same with `tls` as the TLS library, the peer `talk`.
fn run_over(
    url: &str,
    tls: Option<crate::libraries::Library<dyn crate::tls::TlsBackend>>,
    talk: Conversation,
    world: impl FnOnce(&mut World),
    set: impl FnOnce(&mut Options),
) -> Ran {
    run_driven(url, tls, talk, world, set, |m, id| {
        drive_to_completion(m, id, &mut NoEvents).unwrap()
    })
}

/// The same, the transfer driven by `drive` to its result.
fn run_driven(
    url: &str,
    tls: Option<crate::libraries::Library<dyn crate::tls::TlsBackend>>,
    talk: Conversation,
    world: impl FnOnce(&mut World),
    set: impl FnOnce(&mut Options),
    drive: impl FnOnce(&mut Multi, crate::multi::TransferId) -> Result<(), ErrorKind>,
) -> Ran {
    let mut w = World::default();
    world(&mut w);
    let trace_write = w.trace_write;
    let w = Arc::new(Mutex::new(w));
    let ldap: &'static FakeLdap = Box::leak(Box::new(FakeLdap(w.clone())));
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Net::Accepts)
        .with_conversation(at, talk);
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let internal = Internal::default();
    let components = crate::components::Components::new().unwrap();
    components.set(
        crate::components::Component::Multi,
        crate::components::Level::Info,
    );
    m.trace_internally_to(
        components,
        crate::handler::Handler::text(internal.clone()).unwrap(),
    );
    let mut e = Easy::new();
    if trace_write {
        let c = crate::components::Components::new().unwrap();
        c.configure(b"write");
        e.set_components(Some(c));
    }
    e.set_libraries(
        SharedLibraries::new(Libraries {
            ldap: Some(LdapLibrary::Fd(ldap)),
            tls,
            ..Libraries::NONE
        })
        .unwrap(),
    );
    let body = Body::default();
    let text = Text::default();
    let o = e.options_mut();
    o.set_url(Some(url.replace("PORT", &PORT.to_string()).as_bytes()))
        .unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.output.verbose = true;
    o.callbacks.write = Some(crate::handler::Handler::write(body.clone()).unwrap());
    o.callbacks.debug = Some(crate::handler::Handler::debug(text.clone()).unwrap());
    set(o);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive(&mut m, id);
    m.remove(id, &mut NoEvents).unwrap();
    drop(m);
    let calls = w.lock().unwrap().calls.clone();
    let body = body.0.lock().unwrap().clone();
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    let internal = String::from_utf8_lossy(&internal.0.lock().unwrap()).into_owned();
    Ran {
        result,
        body,
        said,
        internal,
        calls,
    }
}

fn credentials(o: &mut Options, pair: &[u8]) {
    let (user, password) = pair.split_at(pair.iter().position(|&b| b == b':').unwrap());
    let login = o.login.make_mut().unwrap();
    login.user = Some(user.to_vec());
    login.password = Some(password[1..].to_vec());
}

fn login_options(o: &mut Options, options: &[u8]) {
    o.line.make_mut().unwrap().login_options = Some(options.to_vec());
}

fn use_ssl(o: &mut Options, use_ssl: UseSsl) {
    o.line.make_mut().unwrap().use_ssl = use_ssl;
}

const URL: &str = "ldap://127.0.0.1:PORT/dc=x?cn?sub?(cn=*)";

/// `said` has `line`, a line only C's debug build traces, where the
/// build is that one.
fn debug_said(said: &str, line: &str) {
    if cfg!(feature = "debug-hooks") {
        assert!(said.contains(line), "{line}: {said}");
    }
}

fn one_entry(w: &mut World) {
    w.entries = vec![(
        b"cn=a,dc=x".to_vec(),
        vec![(b"cn".to_vec(), vec![b"a".to_vec()])],
    )];
}

/// An anonymous search: version 3, no referrals, a simple bind as no one
/// with an empty password, the URL's search, its entries as LDIF; the
/// session unbinds as the connection closes.
#[test]
fn an_anonymous_search_binds_as_no_one() {
    let ran = run(URL, one_entry, |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(
        ran.calls,
        [
            "session ldap ldap://127.0.0.1:8389",
            "version 3",
            "no referrals",
            "max 262144",
            "bind - simple ",
            "search dc=x 2 (cn=*) Some([\"cn\"])",
            "unbind",
        ]
    );
    assert_eq!(ran.body, b"DN: cn=a,dc=x\n\tcn: a\n\n\n");
    debug_said(&ran.internal, "shutdown protocol handler (aborted=0)");
    debug_said(&ran.said, "state change from STOP to BIND");
    debug_said(&ran.said, "state change from BIND to STOP");
}

/// The user binds simply with the password, cut at a NUL as C's string.
#[test]
fn a_user_binds_with_the_password() {
    let ran = run(URL, one_entry, |o| credentials(o, b"cn=me:pw"));
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(ran.calls[4], "bind cn=me simple pw");
}

/// A refused bind is the login's failure with credentials, a bind's
/// without; nothing is searched.
#[test]
fn a_refused_bind_fails_the_transfer() {
    let ran = run(
        URL,
        |w| w.binds = [Code::INVALID_CREDENTIALS].into(),
        |o| credentials(o, b"u:p"),
    );
    assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
    assert!(
        !ran.calls.iter().any(|c| c.starts_with("search")),
        "{:?}",
        ran.calls
    );
    let ran = run(URL, |w| w.binds = [Code(53)].into(), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::LdapCannotBind));
}

/// A server without version 3 is bound to again in version 2, once.
#[test]
fn a_protocol_error_binds_again_in_version_2() {
    let ran = run(
        URL,
        |w| {
            one_entry(w);
            w.binds = [Code::PROTOCOL_ERROR].into()
        },
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(
        &ran.calls[4..7],
        ["bind - simple ", "version 2", "bind - simple "]
    );
    debug_said(&ran.said, "state change from BIND to BINDV2");
    let ran = run(
        URL,
        |w| w.binds = [Code::PROTOCOL_ERROR, Code::PROTOCOL_ERROR].into(),
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    assert_eq!(
        ran.calls.iter().filter(|c| c.starts_with("bind")).count(),
        2
    );
}

/// `AUTH=PLAIN`: the mechanisms are asked of the root, then PLAIN's bind
/// goes with its message raw, the initial response always sent.
#[test]
fn a_sasl_bind_asks_for_the_mechanisms_first() {
    let ran = run(
        URL,
        |w| {
            one_entry(w);
            w.mechs = vec![b"PLAIN".to_vec(), b"LOGIN".to_vec()]
        },
        |o| {
            credentials(o, b"u:p");
            login_options(o, b"AUTH=PLAIN")
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(
        &ran.calls[4..7],
        [
            "search  0 (objectclass=*) Some([\"supportedSASLMechanisms\"])",
            "bind - sasl PLAIN \\0u\\0p",
            "search dc=x 2 (cn=*) Some([\"cn\"])",
        ]
    );
    debug_said(&ran.said, "state change from STOP to MECHS");
    debug_said(&ran.said, "state change from MECHS to SASL");
}

/// A challenge is answered raw in a bind of the same mechanism; an
/// answer without the challenge the mechanism needs is refused.
#[test]
fn a_sasl_challenge_is_answered_in_another_bind() {
    let ran = run(
        URL,
        |w| {
            one_entry(w);
            w.mechs = vec![b"CRAM-MD5".to_vec()];
            w.sasl = [(Code::SASL_BIND_IN_PROGRESS, Some(b"<1.2@h>".to_vec()))].into();
        },
        |o| {
            credentials(o, b"u:p");
            login_options(o, b"AUTH=CRAM-MD5")
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    let binds: Vec<_> = ran.calls.iter().filter(|c| c.starts_with("bind")).collect();
    assert_eq!(binds.len(), 2, "{:?}", ran.calls);
    assert_eq!(binds[0], "bind - sasl CRAM-MD5 -");
    assert!(
        binds[1].starts_with("bind - sasl CRAM-MD5 u "),
        "{}",
        binds[1]
    );
    assert_eq!(binds[1].len(), "bind - sasl CRAM-MD5 u ".len() + 32);
    let ran = run(
        URL,
        |w| {
            w.mechs = vec![b"CRAM-MD5".to_vec()];
            w.sasl = [(Code::SASL_BIND_IN_PROGRESS, None)].into();
        },
        |o| {
            credentials(o, b"u:p");
            login_options(o, b"AUTH=CRAM-MD5")
        },
    );
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
}

/// A SASL bind refused is the login's failure, and no version 2 bind
/// follows a protocol error.
#[test]
fn a_refused_sasl_bind_fails_the_login() {
    for code in [Code::INVALID_CREDENTIALS, Code::PROTOCOL_ERROR] {
        let ran = run(
            URL,
            |w| {
                w.mechs = vec![b"PLAIN".to_vec()];
                w.sasl = [(code, None)].into()
            },
            |o| {
                credentials(o, b"u:p");
                login_options(o, b"AUTH=PLAIN")
            },
        );
        assert_eq!(ran.result, Err(ErrorKind::LoginDenied), "{code:?}");
        assert!(
            !ran.calls.iter().any(|c| c.starts_with("version 2")),
            "{:?}",
            ran.calls
        );
    }
}

/// No mechanism both ends allow, or nothing to log in with: the login
/// fails, said as C says it, without a bind.
#[test]
fn no_mechanism_to_use_fails_the_login() {
    let ran = run(
        URL,
        |w| w.mechs = vec![b"GSSAPI".to_vec()],
        |o| {
            credentials(o, b"u:p");
            login_options(o, b"AUTH=PLAIN")
        },
    );
    assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
    assert!(
        ran.said
            .contains("SASL: no overlap between offered and configured auth mechanisms"),
        "{}",
        ran.said
    );
    assert!(
        !ran.calls.iter().any(|c| c.starts_with("bind")),
        "{:?}",
        ran.calls
    );
    let ran = run(
        URL,
        |w| w.mechs = vec![b"PLAIN".to_vec()],
        |o| login_options(o, b"AUTH=PLAIN"),
    );
    assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
    assert!(
        !ran.calls.iter().any(|c| c.starts_with("bind")),
        "{:?}",
        ran.calls
    );
}

/// STARTTLS refused: with `--ssl` the bind goes on in the clear, with
/// `--ssl-reqd` the transfer fails.
#[test]
fn a_refused_starttls_goes_on_only_if_tls_was_tried() {
    // Unwilling to perform: a protocol error would bind in version 2.
    let refused = Code(53);
    let ran = run(
        URL,
        |w| {
            one_entry(w);
            w.starttls = refused
        },
        |o| use_ssl(o, UseSsl::Try),
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(&ran.calls[4..6], ["starttls", "bind - simple "]);
    let ran = run(URL, |w| w.starttls = refused, |o| use_ssl(o, UseSsl::All));
    assert_eq!(ran.result, Err(ErrorKind::UseSslFailed));
    assert!(
        !ran.calls.iter().any(|c| c.starts_with("bind")),
        "{:?}",
        ran.calls
    );
}

/// A search's result other than success fails it, in the server's words;
/// the size limit says how many entries came, and succeeds.
#[test]
fn a_search_s_result_is_the_transfer_s() {
    let ran = run(URL, |w| w.found = Code(32), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::LdapSearchFailed));
    assert!(
        ran.said.contains("LDAP remote: search failed Other"),
        "{}",
        ran.said
    );
    let ran = run(
        URL,
        |w| {
            one_entry(w);
            w.found = Code::SIZELIMIT_EXCEEDED
        },
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert!(
        ran.said.contains("There are more than 1 entries"),
        "{}",
        ran.said
    );
}

/// A search's end is said through the writers' last, as C's build says
/// it for any protocol (`Curl_cw_out_done`).
#[test]
fn a_search_ends_through_the_writers() {
    let ran = run(
        URL,
        |w| {
            one_entry(w);
            w.trace_write = true;
        },
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert!(
        ran.said.lines().any(|l| l == "[WRITE] [OUT] done"),
        "{}",
        ran.said
    );
}

/// A transfer that ends before the search's result gives the search up.
#[test]
fn a_search_cut_short_is_abandoned() {
    let ran = run(URL, one_entry, |o| {
        o.callbacks.write = Some(crate::handler::Handler::write(Refuses).unwrap());
    });
    assert_eq!(ran.result, Err(ErrorKind::WriteError));
    let search = ran
        .calls
        .iter()
        .position(|c| c.starts_with("search"))
        .unwrap();
    assert!(
        ran.calls[search + 1..]
            .iter()
            .any(|c| c.starts_with("abandon")),
        "{:?}",
        ran.calls
    );
}

/// A session the library would not make fails the connect, in its words.
#[test]
fn a_session_not_made_fails_the_connect() {
    let ran = run(URL, |w| w.refuse = Some(Code(-1)), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert!(
        ran.said
            .contains("LDAP local: Cannot connect to ldap://127.0.0.1:8389, Other"),
        "{}",
        ran.said
    );
}

/// `ldaps:` needs a TLS library as well as LDAP's: without one it is
/// disabled; with one the session is made once TLS is on, for `ldaps`.
#[test]
fn ldaps_wants_a_tls_library_too() {
    let ran = run("ldaps://127.0.0.1:PORT/dc=x", |_| {}, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
    assert!(
        ran.said.contains("Protocol \"ldaps\" is disabled"),
        "{}",
        ran.said
    );
    use crate::tls::fake::FakeTls;
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let tls = crate::libraries::Library::Static(backend as &dyn crate::tls::TlsBackend);
    // The bind's answer and the search's result, through TLS.
    let ran = run_over(
        "ldaps://127.0.0.1:PORT/dc=x",
        Some(tls),
        welcome_then(2),
        |_| {},
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(backend.log().handshakes, 1, "the connection's TLS");
    assert_eq!(ran.calls[0], "session ldaps ldaps://127.0.0.1:8389");
    assert!(
        ran.calls.iter().any(|c| c.starts_with("search")),
        "{:?}",
        ran.calls
    );
}

/// The server's answers in fake TLS records, `n` answers of a byte `A`
/// each, sent right after its handshake's.
fn welcome_then(n: usize) -> Conversation {
    use crate::tls::fake::{WELCOME, records};
    let answers = records(&vec![b'A'; n]).unwrap();
    Conversation::replies(&[&[WELCOME, &answers[..]].concat()], false).per_send()
}

fn fake_tls() -> (
    &'static crate::tls::fake::FakeTls,
    crate::libraries::Library<dyn crate::tls::TlsBackend>,
) {
    let backend: &'static crate::tls::fake::FakeTls =
        Box::leak(Box::new(crate::tls::fake::FakeTls::new().unwrap()));
    (
        backend,
        crate::libraries::Library::Static(backend as &dyn crate::tls::TlsBackend),
    )
}

/// Over TLS the session reads and writes through the connection's
/// layers: what it sends reaches the server through TLS, each answer
/// is read back through it, and bytes TLS holds are said pending.
#[test]
fn over_tls_the_session_uses_the_connection_s_layers() {
    let (_, tls) = fake_tls();
    let talk = welcome_then(3);
    let ran = run_over(
        URL.replace("ldap:", "ldaps:").as_str(),
        Some(tls),
        talk.clone(),
        one_entry,
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(ran.body, b"DN: cn=a,dc=x\n\tcn: a\n\n\n");
    let reads: Vec<_> = ran.calls.iter().filter(|c| c.starts_with("read")).collect();
    // The first read finds nothing in TLS yet; the record it decrypts
    // holds the answers after.
    assert_eq!(
        reads,
        [
            "read, pending false",
            "read, pending true",
            "read, pending true"
        ]
    );
    let sent = crate::tls::fake::read_client(&talk.received()).unwrap();
    let sent = String::from_utf8_lossy(&sent);
    assert!(
        sent.contains("bind - simple \nsearch dc=x 2 (cn=*)"),
        "{sent}"
    );
}

/// STARTTLS accepted: the connection is upgraded, said established again
/// as C says it, and the session then works through TLS, binding only
/// with credentials.
#[test]
fn an_accepted_starttls_upgrades_the_connection() {
    for (login, answers) in [(false, 2), (true, 3)] {
        let (backend, tls) = fake_tls();
        let ran = run_over(URL, Some(tls), welcome_then(answers), one_entry, |o| {
            use_ssl(o, UseSsl::All);
            if login {
                credentials(o, b"u:p");
            }
        });
        assert_eq!(ran.result, Ok(()), "{}", ran.said);
        assert_eq!(backend.log().handshakes, 1);
        assert_eq!(
            ran.said.matches("Established connection").count(),
            2,
            "{}",
            ran.said
        );
        let binds = ran.calls.iter().filter(|c| c.starts_with("bind")).count();
        assert_eq!(binds, usize::from(login), "{:?}", ran.calls);
        // STARTTLS's own answer came in the clear.
        let reads = ran.calls.iter().filter(|c| c.starts_with("read")).count();
        assert_eq!(reads, answers, "{:?}", ran.calls);
        assert_eq!(ran.body, b"DN: cn=a,dc=x\n\tcn: a\n\n\n");
        debug_said(&ran.said, "state change from STARTTLS to TLS");
    }
}

/// Pauses its first write, then takes them all.
#[derive(Clone, Default)]
struct PausesFirst {
    took: Arc<Mutex<Vec<u8>>>,
    paused: Arc<Mutex<bool>>,
}

impl WriteHandler for PausesFirst {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Writes {
        if !std::mem::replace(&mut *self.paused.lock().unwrap(), true) {
            return Writes::Pause;
        }
        self.took.lock().unwrap().extend_from_slice(body);
        Writes::Took(body.len())
    }
}

/// A paused write holds the entry: the transfer waits on nothing and
/// does not end while it is held, and once unpaused delivers it whole.
#[test]
fn a_paused_write_holds_the_answer() {
    use crate::deliver::PauseRequest;
    let writer = PausesFirst::default();
    let w = writer.clone();
    let ran = run_driven(
        URL,
        None,
        Conversation::replies(&[b"unread"], false).greeting(),
        one_entry,
        |o| o.callbacks.write = Some(crate::handler::Handler::write(w).unwrap()),
        |m, id| {
            for _ in 0..10 {
                m.perform(&mut NoEvents).unwrap();
            }
            assert!(m.info_read().is_none(), "not over while output is held");
            let mut waits = Vec::new();
            m.sockets(&mut NoEvents, |_, events| waits.push(events))
                .unwrap();
            assert!(
                waits.iter().all(|e| *e == crate::conn::io::Events::NONE),
                "{waits:?}"
            );
            m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
            drive_to_completion(m, id, &mut NoEvents).unwrap()
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(
        *writer.took.lock().unwrap(),
        b"DN: cn=a,dc=x\n\tcn: a\n\n\n"
    );
}

/// STARTTLS the library could not send: with `--ssl` the bind goes on in
/// the clear, with `--ssl-reqd` the transfer fails.
#[test]
fn an_unsent_starttls_goes_on_only_if_tls_was_tried() {
    let ran = run(
        URL,
        |w| {
            one_entry(w);
            w.starttls_unsent = Some(Code(-1))
        },
        |o| use_ssl(o, UseSsl::Try),
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert!(
        ran.calls.iter().any(|c| c.starts_with("bind")),
        "{:?}",
        ran.calls
    );
    let ran = run(
        URL,
        |w| w.starttls_unsent = Some(Code(-1)),
        |o| use_ssl(o, UseSsl::All),
    );
    assert_eq!(ran.result, Err(ErrorKind::UseSslFailed));
    assert!(
        !ran.calls.iter().any(|c| c.starts_with("bind")),
        "{:?}",
        ran.calls
    );
}

/// The root's entry is taken with no results or success said of it,
/// refused with any other; its search's size limit is said, as too many
/// mechanisms, and the login goes on.
#[test]
fn the_root_s_answer_is_checked_as_c_checks_it() {
    let sasl = |o: &mut Options| {
        credentials(o, b"u:p");
        login_options(o, b"AUTH=PLAIN")
    };
    for (root, want) in [
        (Code::NO_RESULTS_RETURNED, Ok(())),
        (Code::SUCCESS, Ok(())),
        (Code(1), Err(ErrorKind::LoginDenied)),
    ] {
        let ran = run(
            URL,
            |w| {
                w.mechs = vec![b"PLAIN".to_vec()];
                w.root = root
            },
            sasl,
        );
        assert_eq!(ran.result, want, "{root:?}: {}", ran.said);
    }
    let ran = run(
        URL,
        |w| {
            w.mechs = vec![b"PLAIN".to_vec()];
            w.root_found = Code::SIZELIMIT_EXCEEDED
        },
        sasl,
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert!(
        ran.said.contains("Too many authentication mechanisms"),
        "{}",
        ran.said
    );
    let ran = run(URL, |w| w.mechs = vec![b"PLAIN".to_vec()], sasl);
    assert!(
        !ran.said.contains("Too many authentication mechanisms"),
        "{}",
        ran.said
    );
}

/// A failed simple bind's answer is not read for credentials: its code
/// is the failure, as C's.
#[test]
fn a_failed_bind_s_answer_is_not_read() {
    let ran = run(URL, |w| w.binds = [Code(53)].into(), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::LdapCannotBind));
    assert!(
        !ran.said.contains("ldap_parse_sasl_bind_result"),
        "{}",
        ran.said
    );
}

/// An answer not come yet leaves the connect waiting on its socket.
#[test]
fn an_answer_not_come_waits_on_the_socket() {
    let ran = run_driven(
        URL,
        None,
        Conversation::replies(&[b"unread"], false).greeting(),
        |w| {
            one_entry(w);
            w.late = 3
        },
        |_| {},
        |m, id| {
            // Each pass asks once: past the TCP connect, it waits to read.
            let mut seen = Vec::new();
            for _ in 0..3 {
                m.perform(&mut NoEvents).unwrap();
                m.sockets(&mut NoEvents, |_, events| seen.push(events))
                    .unwrap();
            }
            assert!(seen.contains(&crate::conn::io::Events::IN), "{seen:?}");
            drive_to_completion(m, id, &mut NoEvents).unwrap()
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
}

/// A search's answer not come yet leaves the transfer waiting to read its
/// socket.
#[test]
fn a_search_s_answer_not_come_waits_to_read() {
    let ran = run_driven(
        URL,
        None,
        Conversation::replies(&[b"unread"], false).greeting(),
        |w| {
            one_entry(w);
            w.late_entry = 6
        },
        |_| {},
        |m, id| {
            let mut last = None;
            for _ in 0..6 {
                m.perform(&mut NoEvents).unwrap();
                last = None;
                m.sockets(&mut NoEvents, |_, events| last = Some(events))
                    .unwrap();
            }
            assert_eq!(last, Some(crate::conn::io::Events::IN));
            drive_to_completion(m, id, &mut NoEvents).unwrap()
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
}

/// STARTTLS done, a mechanism asked for: the mechanisms are asked
/// through TLS before SASL's bind.
#[test]
fn after_starttls_sasl_asks_for_the_mechanisms() {
    let (_, tls) = fake_tls();
    // The root's entry and result, the bind's answer, the entry and result.
    let ran = run_over(
        URL,
        Some(tls),
        welcome_then(5),
        |w| {
            one_entry(w);
            w.mechs = vec![b"PLAIN".to_vec()]
        },
        |o| {
            use_ssl(o, UseSsl::All);
            credentials(o, b"u:p");
            login_options(o, b"AUTH=PLAIN");
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    let after: Vec<_> = ran
        .calls
        .iter()
        .skip_while(|c| *c != "starttls")
        .filter(|c| !c.starts_with("read"))
        .take(4)
        .collect();
    assert_eq!(
        after,
        [
            "starttls",
            "search  0 (objectclass=*) Some([\"supportedSASLMechanisms\"])",
            "bind - sasl PLAIN \\0u\\0p",
            "search dc=x 2 (cn=*) Some([\"cn\"])",
        ]
    );
}
