//! A request reads a `.netrc` once, whatever its scheme, by the origin's
//! name (`url_set_data_creds_netrc`, which C calls from one place): every
//! scheme libcurl knows, made into a request or not.

use super::*;
use crate::components::Components;
use crate::conn::io::Peer;
use crate::idn::FakeIdn;
use crate::ldap::{Code, Ldap, Search, Session as LdapSession, SessionFailed, UrlError};
use crate::libraries::{Libraries, Library, SharedLibraries};
use crate::options::{NetrcMode, Protocols};
use crate::ssh::{Session as SshSession, Ssh};
use crate::tls::fake::FakeTls;
use crate::url::schemes::KNOWN;

/// An SSH library no connection reaches: the connection is refused.
#[derive(Debug)]
struct NoSsh;

impl Ssh for NoSsh {
    fn session(&self) -> Option<Box<dyn SshSession>> {
        None
    }
}

/// An LDAP library no connection reaches, nor any URL gets past.
#[derive(Debug)]
struct NoLdap;

impl Ldap for NoLdap {
    fn parse_url(&self, _: &[u8]) -> Result<Search, UrlError> {
        Err(UrlError::BAD_URL)
    }

    fn session(
        &self,
        _: Option<curl_os::socket::BorrowedSocket<'_>>,
        _: &[u8],
        _: &[u8],
    ) -> Result<Box<dyn LdapSession>, SessionFailed> {
        Err(SessionFailed::NoCopy)
    }

    fn describe(&self, _: Code) -> &'static [u8] {
        b""
    }
}

/// Libraries for every protocol the build can speak.
fn every_library() -> SharedLibraries {
    let tls: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    SharedLibraries::new(Libraries {
        tls: Some(Library::Static(tls)),
        ssh: Some(crate::ssh::SshLibrary::Libssh(&NoSsh)),
        ldap: Some(crate::ldap::LdapLibrary::Fd(&NoLdap)),
        ..Libraries::NONE
    })
    .unwrap()
}

/// What `url` traced and how it ended, on a handle with `libraries`, with
/// a `.netrc` of no entries that is optional; its connection refused.
fn run(
    url: &str,
    libraries: Option<SharedLibraries>,
    netrc: &[u8],
    mode: NetrcMode,
    set: impl FnOnce(&mut Options),
) -> Ran {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let net = FakeNet::new(clock.clone()).with_peer(at, Peer::Refuses);
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::with_env(env).unwrap();
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"multi");
    e.set_components(Some(components));
    if let Some(libraries) = libraries {
        e.set_libraries(libraries);
    }
    get_with(&mut m, e, "/", Conversation::replies(&[], true), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.netrc.make_mut().unwrap().mode = mode;
        o.netrc.make_mut().unwrap().file = Some(netrc.to_vec());
        set(o);
    })
}

/// A file of no entries, gone when dropped.
struct Empty(std::path::PathBuf);

impl Empty {
    fn new(name: &str) -> Empty {
        let path =
            std::env::temp_dir().join(format!("curl-core-netrc-{name}-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        Empty(path)
    }

    fn name(&self) -> &[u8] {
        self.0.as_os_str().as_encoded_bytes()
    }
}

impl Drop for Empty {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

/// `{scheme}` of each row of libcurl's table, to a port that refuses.
fn urls() -> impl Iterator<Item = (&'static str, String)> {
    KNOWN.iter().map(|row| {
        let url = match row.flags.no_network {
            true => format!("{}:///nonexistent-netrc-reads", row.name),
            false => format!("{}://127.0.0.1:{PORT}/a/b", row.name),
        };
        (row.name, url)
    })
}

/// The lines of a read in `ran`, each once.
fn read_once(ran: &Ran, what: &str) {
    let text = ran.seen.text();
    for needle in [
        "Could not find host ",
        "[NETRC] scanning",
        "transfer credentials",
    ] {
        let count = text.iter().filter(|l| l.contains(needle)).count();
        assert_eq!(count, 1, "{what}: {needle:?} in {text:?}");
    }
}

/// With its library, each scheme this build speaks is made into a
/// request; a scheme it leaves out is refused, having read the file.
#[test]
fn each_scheme_reads_a_netrc_once() {
    let file = Empty::new("each");
    for (name, url) in urls() {
        let ran = run(
            &url,
            Some(every_library()),
            file.name(),
            NetrcMode::Optional,
            |_| {},
        );
        read_once(&ran, &url);
        // A row not built is refused in words this test leaves alone; it
        // has read the file all the same.
        let disabled = format!("Protocol \"{name}\" is disabled");
        let refused = ran.seen.text().iter().any(|l| l.starts_with(&disabled));
        let built = KNOWN.iter().any(|row| row.name == name && row.built);
        assert!(!built || !refused, "{url}: {:?}", ran.seen.text());
    }
}

/// Without the libraries the schemes that need one have no request to
/// read it, and read it all the same.
#[test]
fn a_scheme_without_its_library_reads_a_netrc_once() {
    let file = Empty::new("nolib");
    for (_, url) in urls() {
        let ran = run(&url, None, file.name(), NetrcMode::Optional, |_| {});
        read_once(&ran, &url);
    }
}

/// A scheme the application does not allow reads it as well.
#[test]
fn a_scheme_refused_reads_a_netrc_once() {
    let file = Empty::new("refused");
    for (name, url) in urls() {
        let ran = run(
            &url,
            Some(every_library()),
            file.name(),
            NetrcMode::Optional,
            |o| o.schemes.make_mut().unwrap().allowed = Protocols::NONE,
        );
        read_once(&ran, &url);
        assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol), "{name}");
    }
}

/// Whether or not a request is made, the host is the origin's name: a name
/// in Unicode in ASCII, an IPv6 address with neither brackets nor zone.
#[test]
fn a_netrc_is_read_for_the_origin_s_name() {
    static CONVERTING: Libraries = Libraries {
        idn: Some(&FakeIdn),
        ..Libraries::NONE
    };
    let file = Empty::new("host");
    let name = String::from_utf8_lossy(file.name()).into_owned();
    let unicode = format!("www.åäö.se:{PORT}/");
    let scoped = format!("[fe80::1%25lo]:{PORT}/");
    for (host, want) in [(&unicode, "www.xn--4cab6c.se"), (&scoped, "fe80::1")] {
        for scheme in ["http", "mqtt", "dict", "ldap"] {
            for allowed in [Protocols::ALL, Protocols::NONE] {
                let url = format!("{scheme}://{host}");
                let libraries = SharedLibraries::of_static(&CONVERTING);
                let ran = run(
                    &url,
                    Some(libraries),
                    file.name(),
                    NetrcMode::Optional,
                    |o| o.schemes.make_mut().unwrap().allowed = allowed,
                );
                let line =
                    format!("Could not find host {want} in the {name} file; using defaults\n");
                let text = ran.seen.text();
                assert!(text.contains(&line), "{url} {allowed:?}: {text:?}");
            }
        }
    }
}

/// What is wrong with the origin fails first, a required file not looked
/// for, as C makes the origin before it reads for it
/// (`url_set_data_origin_and_creds`), whether the scheme is allowed or not.
#[test]
fn a_bad_origin_fails_before_a_netrc_is_read() {
    let missing = b"/nonexistent-netrc-reads";
    let long = "a".repeat(0x10000);
    for scheme in ["http", "dict", "mqtt"] {
        for allowed in [Protocols::ALL, Protocols::NONE] {
            let url = format!("{scheme}://{long}/");
            let ran = run(&url, None, missing, NetrcMode::Required, |o| {
                o.schemes.make_mut().unwrap().allowed = allowed;
            });
            assert_eq!(ran.result, Err(ErrorKind::UrlMalformat), "{scheme}");
            let text = ran.seen.text();
            let line = "Too long hostname (maximum is 65535)\n".to_string();
            assert!(text.contains(&line), "{scheme}: {text:?}");
            assert!(!text.iter().any(|l| l.contains("netrc")), "{text:?}");
        }
    }
}
