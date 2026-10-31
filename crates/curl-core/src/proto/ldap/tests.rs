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
use crate::ldap::{Ldap, NoCopy};
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
            Some("one") => 1,
            Some("sub") => 2,
            _ => 0,
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
        _: i32,
        scheme: &[u8],
        url: &[u8],
    ) -> Result<Result<Box<dyn Session>, Code>, NoCopy> {
        let mut w = self.0.lock().unwrap();
        w.calls.push(format!(
            "session {} {}",
            String::from_utf8_lossy(scheme),
            String::from_utf8_lossy(url)
        ));
        if let Some(code) = w.refuse {
            return Ok(Err(code));
        }
        Ok(Ok(Box::new(FakeSession {
            world: self.0.clone(),
            next: 1,
            answers: VecDeque::new(),
            wired: false,
        })))
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
    fn set_version(&mut self, version: i32) {
        self.call(format!("version {version}"));
    }

    fn set_no_referrals(&mut self) {
        self.call("no referrals".into());
    }

    fn set_max_incoming(&mut self, _: usize) -> bool {
        true
    }

    fn use_wire(&mut self) -> bool {
        self.wired = true;
        true
    }

    fn uses_wire(&self) -> bool {
        self.wired
    }

    fn bind(
        &mut self,
        _: &mut dyn Wire,
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
                ("simple".to_string(), Answer::of(Kind::Bind, code))
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
        self.call(format!("bind {} {said} {}", shown(dn), shown(cred)));
        Ok(self.sent(vec![answer]))
    }

    fn search(&mut self, _: &mut dyn Wire, search: &Search) -> Result<MsgId, Code> {
        self.call(format!(
            "search {} {} {} {:?}",
            shown(search.dn.as_deref()),
            search.scope,
            shown(search.filter.as_deref()),
            search.attrs.as_ref().map(|a| a
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>()),
        ));
        let w = self.world.lock().unwrap();
        let mut answers = Vec::new();
        let asks_mechs =
            search.attrs.as_deref() == Some(&[b"supportedSASLMechanisms".to_vec()][..]);
        if asks_mechs {
            let mut root = Answer::of(Kind::SearchEntry, Code::NO_RESULTS_RETURNED);
            root.attrs = vec![(b"supportedSASLMechanisms".to_vec(), w.mechs.clone())];
            answers.push(root);
            answers.push(Answer::of(Kind::SearchResult, Code::SUCCESS));
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

    fn start_tls(&mut self, _: &mut dyn Wire) -> Result<MsgId, Code> {
        self.call("starttls".into());
        let code = self.world.lock().unwrap().starttls;
        Ok(self.sent(vec![Answer::of(Kind::Extended, code)]))
    }

    fn result<'s>(
        &'s mut self,
        _: &mut dyn Wire,
        id: MsgId,
    ) -> Result<Option<Box<dyn Message + 's>>, Code> {
        match self.answers.front() {
            Some((at, _)) if *at == id => {
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

    fn unbind(&mut self, _: &mut dyn Wire) {
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
        Ok(self.cred.clone())
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
    calls: Vec<String>,
}

/// Run `url` over a world `world` sets, the transfer as `set` sets it.
fn run(url: &str, world: impl FnOnce(&mut World), set: impl FnOnce(&mut Options)) -> Ran {
    let mut w = World::default();
    world(&mut w);
    let w = Arc::new(Mutex::new(w));
    let ldap: &'static FakeLdap = Box::leak(Box::new(FakeLdap(w.clone())));
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    // A peer that speaks first, unread: the socket stays readable, as
    // the fake library reads none of it.
    let talk = Conversation::replies(&[b"unread"], false).greeting();
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
    let mut e = Easy::new();
    e.set_libraries(
        SharedLibraries::new(Libraries {
            ldap: Some(ldap),
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
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    drop(m);
    let calls = w.lock().unwrap().calls.clone();
    let body = body.0.lock().unwrap().clone();
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    Ran {
        result,
        body,
        said,
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
            "bind - simple ",
            "search dc=x 2 (cn=*) Some([\"cn\"])",
            "unbind",
        ]
    );
    assert_eq!(ran.body, b"DN: cn=a,dc=x\n\tcn: a\n\n\n");
    debug_said(&ran.said, "state change from STOP to BIND");
    debug_said(&ran.said, "state change from BIND to STOP");
}

/// The user binds simply with the password, cut at a NUL as C's string.
#[test]
fn a_user_binds_with_the_password() {
    let ran = run(URL, one_entry, |o| credentials(o, b"cn=me:pw"));
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(ran.calls[3], "bind cn=me simple pw");
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
        &ran.calls[3..6],
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
        &ran.calls[3..6],
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
    assert_eq!(&ran.calls[3..5], ["starttls", "bind - simple "]);
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
