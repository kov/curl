use curl_alloc::Lock;
use std::net::SocketAddr;
use std::sync::Arc;

use super::*;
use crate::conn::io::{Conversation, FakeNet, Peer as Net};
use crate::easy::Easy;
use crate::handler::{DebugHandler, DebugKind, Write as Writes, WriteHandler};
use crate::id::ArenaPolicy;
use crate::ldap::{Attribute, LdapLibrary, LocalCalls, Scope, Search};
use crate::libraries::{Libraries, SharedLibraries};
use crate::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
use crate::options::AuthMethods;
use crate::options::Options;
use crate::time::ManualClock;

const PORT: u16 = 8389;

/// An attribute's type and its values, none where the library reads none.
type Attr = (Vec<u8>, Option<Vec<Vec<u8>>>);

/// An entry the fake library finds: its name, none for none, and its
/// attributes.
type Found = (Option<Vec<u8>>, Vec<Attr>);

/// What the fake library answers, and the calls it was made.
#[derive(Debug)]
struct World {
    open: bool,
    /// The binds' answers, in turn; success past the last.
    binds: Vec<Code>,
    search: Result<Code, Code>,
    entries: Vec<Found>,
    url: Result<Search, UrlError>,
    /// The kind of session the library makes.
    kind: Kind,
    /// The URL's path and query, as the library was handed them.
    url_parts: Option<(Vec<u8>, Option<Vec<u8>>)>,
    calls: Vec<String>,
}

impl Default for World {
    fn default() -> World {
        World {
            open: true,
            binds: Vec::new(),
            search: Ok(Code::SUCCESS),
            entries: Vec::new(),
            url: Ok(Search {
                dn: Some(b"dc=x".to_vec()),
                scope: Scope::Subtree,
                filter: Some(b"(cn=*)".to_vec()),
                attrs: None,
            }),
            kind: Kind::OpenLdap,
            url_parts: None,
            calls: Vec::new(),
        }
    }
}

/// The library a fake one is: the kind of session it makes.
#[derive(Clone, Copy, Debug)]
enum Kind {
    OpenLdap,
    Windows,
}

#[derive(Debug)]
struct FakeLocal(Arc<Lock<World>>);

impl Local for FakeLocal {
    fn vendor(&self) -> (&'static str, i32) {
        ("Fake", 20428)
    }

    fn parse_url(&self, url: &LocalUrl<'_>) -> Result<Search, UrlError> {
        let mut w = self.0.lock().unwrap();
        w.calls
            .push(format!("parse {}", String::from_utf8_lossy(url.text)));
        w.url_parts = Some((url.path.to_vec(), url.query.map(<[u8]>::to_vec)));
        w.url.clone()
    }

    fn describe(&self, code: Code) -> &'static [u8] {
        match code.0 {
            0 => b"Success",
            4 => b"Size limit exceeded",
            5 => b"Compare False",
            0x31 => b"Invalid credentials",
            _ => b"Other",
        }
    }

    fn open(&self, host: &[u8], port: u16, secured: bool) -> Result<LocalSession, Opened> {
        let mut w = self.0.lock().unwrap();
        let tls = if secured { " secured" } else { "" };
        w.calls.push(format!(
            "open {}:{port}{tls}",
            String::from_utf8_lossy(host)
        ));
        if !w.open {
            return Err(Opened::Refused);
        }
        let session = FakeSession(self.0.clone());
        Ok(match w.kind {
            Kind::OpenLdap => LocalSession::OpenLdap(Box::new(session)),
            Kind::Windows => LocalSession::Windows(Box::new(session)),
        })
    }
}

#[derive(Debug)]
struct FakeSession(Arc<Lock<World>>);

impl FakeSession {
    fn call(&self, call: String) {
        self.0.lock().unwrap().calls.push(call);
    }

    /// The bind `call` made: the next answer, success past the last.
    fn bind_call(&self, call: String) -> Code {
        let mut w = self.0.lock().unwrap();
        w.calls.push(call);
        if w.binds.is_empty() {
            Code::SUCCESS
        } else {
            w.binds.remove(0)
        }
    }
}

/// A login as a call shows it.
fn shown(v: Option<&[u8]>) -> Option<String> {
    v.map(|v| String::from_utf8_lossy(v).into_owned())
}

impl OpenLdapSession for FakeSession {
    fn set_network_timeout(&mut self, timeout: Duration) {
        self.call(format!("timeout {}", timeout.as_secs()));
    }

    fn set_ca_file(&mut self, path: &[u8]) -> Result<(), Code> {
        self.call(format!("ca {}", String::from_utf8_lossy(path)));
        Ok(())
    }

    fn set_require_cert(&mut self, require: RequireCert) -> Result<(), Code> {
        self.call(format!("require {require:?}"));
        Ok(())
    }

    fn set_tls_hard(&mut self) -> Result<(), Code> {
        self.call("tls hard".into());
        Ok(())
    }

    fn simple_bind(&mut self, user: Option<&[u8]>, password: Option<&[u8]>) -> Code {
        self.bind_call(format!("bind {:?} {:?}", shown(user), shown(password)))
    }
}

impl WinLdapSession for FakeSession {
    fn set_ssl(&mut self) {
        self.call("ssl".into());
    }

    fn accept_any_cert(&mut self) {
        self.call("accept any".into());
    }

    fn bind(&mut self, how: WinBind<'_>) -> Code {
        let call = match how {
            WinBind::Simple { user, password } => {
                format!("bind {:?} {:?}", shown(Some(user)), shown(Some(password)))
            }
            WinBind::Sspi {
                method,
                user,
                password,
            } => format!(
                "sspi {method:?} {:?} {:?}",
                shown(Some(user)).unwrap(),
                shown(Some(password)).unwrap()
            ),
            WinBind::CurrentUser => "bind as the process".to_owned(),
        };
        self.bind_call(call)
    }
}

impl LocalCalls for FakeSession {
    fn set_version(&mut self, version: Version) {
        self.call(format!("version {version:?}"));
    }

    fn set_no_referrals(&mut self) {
        self.call("no referrals".into());
    }

    fn search(&mut self, search: &Search) -> Result<(Code, Box<dyn Entries + '_>), Code> {
        let mut w = self.0.lock().unwrap();
        w.calls.push(format!("search {search:?}"));
        let code = w.search?;
        let entries = std::mem::take(&mut w.entries);
        Ok((
            code,
            Box::new(FakeEntries {
                entries,
                at: None,
                attr: 0,
            }),
        ))
    }
}

impl Drop for FakeSession {
    fn drop(&mut self) {
        self.call("unbind".into());
    }
}

struct FakeEntries {
    entries: Vec<Found>,
    at: Option<usize>,
    attr: usize,
}

impl Entries for FakeEntries {
    fn next_entry(&mut self) -> bool {
        let next = self.at.map_or(0, |i| i + 1);
        self.at = Some(next);
        self.attr = 0;
        next < self.entries.len()
    }

    fn dn(&mut self) -> Result<&[u8], NoName> {
        let at = self.at.unwrap();
        self.entries[at].0.as_deref().ok_or(NoName::Missing)
    }

    fn next_attribute(&mut self) -> Result<Option<Attribute<'_>>, curl_alloc::OutOfMemory> {
        let at = self.at.unwrap();
        let Some((name, values)) = self.entries[at].1.get(self.attr) else {
            return Ok(None);
        };
        self.attr += 1;
        Ok(Some(Attribute {
            name,
            values: values
                .as_ref()
                .map(|v| v.iter().map(Vec::as_slice).collect()),
        }))
    }
}

#[derive(Clone, Default)]
struct Body(Arc<Lock<Vec<u8>>>);

impl WriteHandler for Body {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Writes {
        self.0.lock().unwrap().extend_from_slice(body);
        Writes::Took(body.len())
    }
}

#[derive(Clone, Default)]
struct Text(Arc<Lock<Vec<u8>>>);

impl DebugHandler for Text {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text {
            self.0.lock().unwrap().extend_from_slice(data);
        }
    }
}

/// What a transfer came to.
struct Ran {
    result: Result<(), ErrorKind>,
    body: Vec<u8>,
    said: String,
    calls: Vec<String>,
    url_parts: Option<(Vec<u8>, Option<Vec<u8>>)>,
}

/// Run `url` with the fake library as `world` sets it, the transfer as
/// `set` sets it, over a fake TLS library where `tls` asks for one.
fn run(
    url: &str,
    tls: bool,
    world: impl FnOnce(&mut World),
    set: impl FnOnce(&mut Options),
) -> Ran {
    let mut w = World::default();
    world(&mut w);
    let w = Arc::new(Lock::new(w));
    let ldap: &'static FakeLocal = Box::leak(Box::new(FakeLocal(w.clone())));
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = if tls {
        Conversation::replies(&[crate::tls::fake::WELCOME], false).per_send()
    } else {
        Conversation::replies(&[], false)
    };
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
    let tls = tls.then(|| {
        let backend: &'static crate::tls::fake::FakeTls =
            Box::leak(Box::new(crate::tls::fake::FakeTls::new().unwrap()));
        crate::libraries::Library::Static(backend as &dyn crate::tls::TlsBackend)
    });
    e.set_libraries(
        SharedLibraries::new(Libraries {
            ldap: Some(LdapLibrary::Local(ldap)),
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
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    drop(m);
    let calls = w.lock().unwrap().calls.clone();
    let url_parts = w.lock().unwrap().url_parts.clone();
    let body = body.0.lock().unwrap().clone();
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    Ran {
        result,
        body,
        said,
        calls,
        url_parts,
    }
}

const URL: &str = "ldap://127.0.0.1:PORT/dc=x??sub?(cn=*)";

/// An attribute as a test gives it.
type AttrRef<'a> = (&'a [u8], Option<&'a [&'a [u8]]>);

fn entry(dn: &[u8], attrs: &[AttrRef<'_>]) -> Found {
    (
        Some(dn.to_vec()),
        attrs
            .iter()
            .map(|(n, v)| {
                (
                    n.to_vec(),
                    v.map(|v| v.iter().map(|b| b.to_vec()).collect()),
                )
            })
            .collect(),
    )
}

/// An anonymous search over a session of the library's own to the host
/// and port the connection reached: version 3, no referrals, a ten
/// second connect, a bind as no one, the URL's search and its entries as
/// `lib/ldap.c` writes LDIF; the session unbinds and the connection is
/// not kept.
#[test]
fn an_anonymous_search_runs_over_a_session_of_the_librarys_own() {
    let ran = run(
        URL,
        false,
        |w| {
            w.entries = vec![
                entry(
                    b"cn=a,dc=x",
                    &[(b"cn", Some(&[b"a"])), (b"sn", Some(&[b"b", b"c"]))],
                ),
                entry(b"cn=d,dc=x", &[(b"cn", Some(&[b"d"]))]),
            ];
        },
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(
        ran.calls,
        [
            "parse ldap://127.0.0.1:8389/dc=x??sub?(cn=*)",
            "open 127.0.0.1:8389",
            "timeout 10",
            "version V3",
            "no referrals",
            "bind None None",
            "search Search { dn: Some([100, 99, 61, 120]), scope: Subtree, filter: Some([40, 99, 110, 61, 42, 41]), attrs: None }",
            "unbind",
        ]
    );
    assert_eq!(
        String::from_utf8_lossy(&ran.body),
        "DN: cn=a,dc=x\n\tcn: a\n\n\tsn: b\n\tsn: c\n\nDN: cn=d,dc=x\n\tcn: d\n\n"
    );
    for line in [
        "LDAP local: LDAP Vendor = Fake ; LDAP Version = 20428\n",
        "LDAP local: ldap://127.0.0.1:8389/dc=x??sub?(cn=*)\n",
        "LDAP local: trying to establish cleartext connection\n",
    ] {
        assert!(ran.said.contains(line), "{line}: {}", ran.said);
    }
    // Not kept: C's `connclose`.
    assert!(
        ran.said.contains("shutting down connection #0\n") && !ran.said.contains("left intact"),
        "{}",
        ran.said
    );
}

/// The URL's and the application's login is what the bind is made as.
#[test]
fn the_bind_is_made_as_the_login() {
    let ran = run("ldap://u:p@127.0.0.1:PORT/dc=x", false, |_| {}, |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert!(
        ran.calls
            .contains(&r#"bind Some("u") Some("p")"#.to_owned()),
        "{:?}",
        ran.calls
    );
}

/// A bind refused in the clear is made again in version 2; refused again,
/// it fails the transfer naming the library's call and its words.
#[test]
fn a_bind_refused_in_the_clear_is_tried_in_version_2() {
    let ran = run(
        URL,
        false,
        |w| w.binds = vec![Code::INVALID_CREDENTIALS, Code::INVALID_CREDENTIALS],
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::LdapCannotBind));
    let at = ran.calls.iter().position(|c| c == "version V2").unwrap();
    assert_eq!(ran.calls[at + 1], "bind None None");
    assert_eq!(ran.calls.last().unwrap(), "unbind");
    assert!(!ran.calls.iter().any(|c| c.starts_with("search")));
    assert!(
        ran.said
            .contains("LDAP local: bind via ldap_simple_bind_s Invalid credentials\n"),
        "{}",
        ran.said
    );
    // Taken in version 2, it searches.
    let ran = run(URL, false, |w| w.binds = vec![Code::PROTOCOL_ERROR], |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert!(ran.calls.iter().any(|c| c.starts_with("search")));
}

/// Over `ldaps:` the session speaks TLS from the start, trusting the
/// connection's CA file and demanding the peer's certificate verify; a
/// refused bind is not tried in version 2.
#[test]
fn an_ldaps_session_speaks_tls_from_the_start() {
    let ran = run(
        "ldaps://127.0.0.1:PORT/dc=x",
        true,
        |w| w.binds = vec![Code::INVALID_CREDENTIALS],
        |o| {
            o.tls.options.make_mut().unwrap().ca_file =
                crate::options::CaSetting::Given(b"/ca.pem".to_vec());
        },
    );
    assert_eq!(ran.result, Err(ErrorKind::LdapCannotBind), "{}", ran.said);
    let at = ran.calls.iter().position(|c| c == "no referrals").unwrap();
    assert_eq!(
        ran.calls[at + 1..],
        [
            "ca /ca.pem",
            "require Demand",
            "tls hard",
            "bind None None",
            "unbind"
        ]
    );
    for line in [
        "LDAP local: trying to establish encrypted connection\n",
        "LDAP local: using PEM CA cert: /ca.pem\n",
    ] {
        assert!(ran.said.contains(line), "{line}: {}", ran.said);
    }
}

/// Without peer verification no CA file is set and the certificate is
/// never checked; with it, a certificate type other than PEM, or no CA
/// file, fails before anything is set.
#[test]
fn an_ldaps_session_checks_the_peer_as_the_options_say() {
    let ran = run(
        "ldaps://127.0.0.1:PORT/dc=x",
        true,
        |_| {},
        |o| o.tls.verify_peer = false,
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert!(ran.calls.contains(&"require Never".to_owned()));
    assert!(!ran.calls.iter().any(|c| c.starts_with("ca ")));

    let ran = run(
        "ldaps://127.0.0.1:PORT/dc=x",
        true,
        |_| {},
        |o| {
            let t = o.tls.options.make_mut().unwrap();
            t.cert_type = Some(b"DER".to_vec());
            t.ca_file = crate::options::CaSetting::Given(b"/ca.pem".to_vec());
        },
    );
    assert_eq!(ran.result, Err(ErrorKind::SslCertproblem));
    assert!(
        ran.said
            .contains("LDAP local: ERROR OpenLDAP only supports PEM cert-type\n"),
        "{}",
        ran.said
    );
    assert!(!ran.calls.iter().any(|c| c.starts_with("bind")));

    let ran = run(
        "ldaps://127.0.0.1:PORT/dc=x",
        true,
        |_| {},
        |o| o.tls.options.make_mut().unwrap().ca_file = crate::options::CaSetting::Unset,
    );
    assert_eq!(ran.result, Err(ErrorKind::SslCertproblem));
    assert!(
        ran.said.contains("LDAP local: ERROR PEM CA cert not set\n"),
        "{}",
        ran.said
    );
}

/// TLS asked for over `ldap:` is not built in.
#[test]
fn tls_asked_for_over_ldap_is_not_built_in() {
    let ran = run(
        URL,
        false,
        |_| {},
        |o| {
            o.line.make_mut().unwrap().use_ssl = UseSsl::All;
        },
    );
    assert_eq!(ran.result, Err(ErrorKind::NotBuiltIn));
    assert!(
        ran.said
            .contains("LDAP local: explicit TLS not supported\n"),
        "{}",
        ran.said
    );
    assert!(!ran.calls.iter().any(|c| c.starts_with("bind")));
    // Required for the commands alone, as for everything.
    let ran = run(
        URL,
        false,
        |_| {},
        |o| {
            o.line.make_mut().unwrap().use_ssl = UseSsl::Control;
        },
    );
    assert_eq!(ran.result, Err(ErrorKind::NotBuiltIn));
    // Tried only, it goes on in the clear.
    let ran = run(
        URL,
        false,
        |_| {},
        |o| {
            o.line.make_mut().unwrap().use_ssl = UseSsl::Try;
        },
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
}

/// A URL the library cannot read fails the transfer, its number named as
/// the library names its codes, before a session is made.
#[test]
fn a_bad_url_is_named_as_the_library_names_codes() {
    let ran = run(URL, false, |w| w.url = Err(UrlError::BAD_URL), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::UrlMalformat));
    assert!(
        ran.said.contains("Bad LDAP URL: Compare False\n"),
        "{}",
        ran.said
    );
    assert!(!ran.calls.iter().any(|c| c.starts_with("open")));
}

/// A session the library cannot make fails the connect.
#[test]
fn a_session_not_made_fails_the_connect() {
    let ran = run(URL, false, |w| w.open = false, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert!(
        ran.said
            .contains("LDAP: cannot setup connect to 127.0.0.1:8389\n"),
        "{}",
        ran.said
    );
}

/// A search the server refuses fails the transfer with its words; one cut
/// short by the size limit writes what came and says there were more.
#[test]
fn a_search_ends_as_its_code_says() {
    let ran = run(
        URL,
        false,
        |w| w.search = Err(Code::INSUFFICIENT_ACCESS),
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::LdapSearchFailed));
    assert!(ran.said.contains("LDAP remote: Other\n"), "{}", ran.said);
    assert_eq!(ran.calls.last().unwrap(), "unbind");

    let ran = run(
        URL,
        false,
        |w| {
            w.search = Ok(Code::SIZELIMIT_EXCEEDED);
            w.entries = vec![entry(b"cn=a", &[]), entry(b"cn=b", &[])];
        },
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(String::from_utf8_lossy(&ran.body), "DN: cn=a\nDN: cn=b\n");
    assert!(
        ran.said.contains("There are more than 2 entries\n"),
        "{}",
        ran.said
    );
}

/// LDIF as `lib/ldap.c` writes it: a name or a value not safe as it is
/// in base64, a `;binary` attribute's values in base64 whatever they are,
/// an empty one as nothing, and an attribute the library gives no values
/// for an empty line alone.
#[test]
fn values_not_safe_in_ldif_are_written_in_base64() {
    let ran = run(
        URL,
        false,
        |w| {
            w.entries = vec![entry(
                b"cn=a\nb",
                &[
                    (b"cn", Some(&[b" lead", b"plain"])),
                    (b"photo;binary", Some(&[b"x", b""])),
                    (b"none", None),
                    (b"sn", Some(&[b""])),
                ],
            )];
        },
        |_| {},
    );
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert_eq!(
        String::from_utf8_lossy(&ran.body),
        "DN:: Y249YQpi\n\tcn:: IGxlYWQ=\n\tcn: plain\n\n\tphoto;binary:: eA==\n\tphoto;binary:: \n\n\n\tsn: \n\n"
    );
}

/// An attribute type with values that is not safe in LDIF fails the
/// transfer, nothing of it written; one with no values is passed over, as
/// C checks a type only as it writes its values.
#[test]
fn an_unsafe_attribute_type_fails_the_transfer() {
    let ran = run(
        URL,
        false,
        |w| {
            w.entries = vec![entry(
                b"cn=a",
                &[
                    (b"bad\ntype", None),
                    (b"cn", Some(&[b"a"])),
                    (b"bad\nagain", Some(&[b"v"])),
                ],
            )];
        },
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    assert_eq!(
        String::from_utf8_lossy(&ran.body),
        "DN: cn=a\n\n\tcn: a\n\n"
    );
    assert!(
        ran.said
            .contains("LDAP local: attribute type contains illegal bytes\n"),
        "{}",
        ran.said
    );
}

/// An entry the library gives no name fails the transfer.
#[test]
fn an_entry_with_no_name_fails_the_transfer() {
    let ran = run(URL, false, |w| w.entries = vec![(None, Vec::new())], |_| {});
    assert_eq!(ran.result, Err(ErrorKind::FailedInit));
    assert_eq!(ran.calls.last().unwrap(), "unbind");
}

/// The library is handed the URL's text, its path as it is encoded and
/// its query, an empty one kept, as C's own parser reads them.
#[test]
fn the_library_is_handed_the_urls_path_and_query() {
    for (url, path, query) in [
        (
            "ldap://127.0.0.1:PORT/dc=x%2c?cn?sub",
            &b"/dc=x%2C"[..],
            Some(&b"cn?sub"[..]),
        ),
        ("ldap://127.0.0.1:PORT/dc=x?", b"/dc=x", Some(b"")),
        ("ldap://127.0.0.1:PORT/dc=x", b"/dc=x", None),
        ("ldap://127.0.0.1:PORT", b"/", None),
    ] {
        let ran = run(url, false, |_| {}, |_| {});
        assert_eq!(ran.result, Ok(()), "{url}: {}", ran.said);
        assert_eq!(
            ran.url_parts,
            Some((path.to_vec(), query.map(<[u8]>::to_vec))),
            "{url}"
        );
    }
}

/// WinLDAP's way over `ldaps:`: the session made for TLS, TLS turned on,
/// the peer left to the system's store; told not to check the peer, any
/// certificate is accepted, but not where the name alone is to be
/// checked, which C's build cannot do.
#[test]
fn a_windows_ldaps_session_checks_the_peer_as_c_s_does() {
    let windows = |w: &mut World| w.kind = Kind::Windows;
    let ran = run("ldaps://127.0.0.1:PORT/dc=x", true, windows, |_| {});
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    assert!(
        ran.calls
            .contains(&"open 127.0.0.1:8389 secured".to_owned()),
        "{:?}",
        ran.calls
    );
    // WinLDAP has no connect timeout to set.
    assert_eq!(ran.calls[2], "version V3", "{:?}", ran.calls);
    let at = ran.calls.iter().position(|c| c == "no referrals").unwrap();
    assert_eq!(ran.calls[at + 1], "ssl");
    assert!(ran.calls[at + 2].starts_with("bind"), "{:?}", ran.calls);

    let ran = run("ldaps://127.0.0.1:PORT/dc=x", true, windows, |o| {
        o.tls.verify_peer = false;
        o.tls.verify_host = false;
    });
    assert_eq!(ran.result, Ok(()), "{}", ran.said);
    let at = ran.calls.iter().position(|c| c == "ssl").unwrap();
    assert_eq!(ran.calls[at + 1], "accept any");

    let ran = run("ldaps://127.0.0.1:PORT/dc=x", true, windows, |o| {
        o.tls.verify_peer = false;
    });
    assert_eq!(ran.result, Err(ErrorKind::NotBuiltIn));
    assert!(
        ran.said.contains(
            "LDAP local: host verification cannot be enabled when peer verification is \
             disabled for Windows native LDAP\n"
        ),
        "{}",
        ran.said
    );
    assert!(ran.calls.contains(&"ssl".to_owned()));
    assert!(!ran.calls.iter().any(|c| c.starts_with("bind")));

    // In the clear, nothing of it.
    let ran = run(URL, false, windows, |_| {});
    assert!(ran.calls.contains(&"open 127.0.0.1:8389".to_owned()));
    assert!(!ran.calls.contains(&"ssl".to_owned()));
}

/// WinLDAP's binds: simple with a login where Basic is asked for, which
/// it is unless set; by SSPI with the login as Negotiate or Digest where
/// asked; as the process's user without a login, or with no SSPI method
/// asked; and the same bind again in version 2.
#[test]
fn a_windows_bind_is_made_as_ldap_win_bind_makes_it() {
    let windows = |w: &mut World| {
        w.kind = Kind::Windows;
        w.binds = vec![Code::INVALID_CREDENTIALS];
    };
    let binds = |url: &str, auth: Option<AuthMethods>| {
        let ran = run(url, false, windows, |o| {
            if let Some(auth) = auth {
                o.http.auth = crate::options::HttpAuth(auth);
            }
        });
        assert_eq!(ran.result, Ok(()), "{}", ran.said);
        let made: Vec<String> = ran
            .calls
            .iter()
            .filter(|c| c.starts_with("bind") || c.starts_with("sspi"))
            .cloned()
            .collect();
        assert_eq!(made.len(), 2, "{made:?}");
        assert_eq!(made[0], made[1]);
        made[0].clone()
    };
    let login = "ldap://u:p@127.0.0.1:PORT/dc=x";
    assert_eq!(binds(login, None), r#"bind Some("u") Some("p")"#);
    assert_eq!(binds(URL, None), "bind as the process");
    assert_eq!(
        binds(login, Some(AuthMethods::NEGOTIATE)),
        r#"sspi Negotiate "u" "p""#
    );
    assert_eq!(
        binds(login, Some(AuthMethods::DIGEST)),
        r#"sspi Digest "u" "p""#
    );
    assert_eq!(
        binds(login, Some(AuthMethods::NEGOTIATE | AuthMethods::DIGEST)),
        r#"sspi Negotiate "u" "p""#
    );
    assert_eq!(
        binds(login, Some(AuthMethods::BEARER)),
        "bind as the process"
    );
    assert_eq!(
        binds(URL, Some(AuthMethods::NEGOTIATE)),
        "bind as the process"
    );

    // Refused in both versions, it fails naming C's call.
    let refused = |w: &mut World| {
        w.kind = Kind::Windows;
        w.binds = vec![Code::INVALID_CREDENTIALS, Code::INVALID_CREDENTIALS];
    };
    let ran = run(URL, false, refused, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::LdapCannotBind));
    assert!(
        ran.said
            .contains("LDAP local: bind via ldap_win_bind Invalid credentials\n"),
        "{}",
        ran.said
    );
}
