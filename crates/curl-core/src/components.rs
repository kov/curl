//! Which parts of the library trace what they do (`curl_global_trace`,
//! `Curl_trc_opt`): a level per component, set from a configuration such
//! as `all,-dns` and read at each trace point, so a change takes effect
//! in the transfers already running.
//!
//! The setting is a shared handle the application owns and gives to each
//! `Easy` it wants traced; the C ABI keeps one for the whole process.

use std::sync::atomic::{AtomicBool, Ordering};

use curl_alloc::{OutOfMemory, TryArc};

/// A part of the library that traces on its own: one of C's trace
/// features (`curl_trc_feat`) or connection filter types (`Curl_cftype`).
/// C's DNS feature and DNS filter share a name, so a configuration never
/// sets one without the other: here they are one component.
///
/// Every component C knows is here, so a configuration names the same
/// ones; those the library has no counterpart for yet trace nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Component {
    /// The transfer and connection ids before each line (`LIB-IDS`).
    Ids,
    Multi,
    Read,
    Write,
    /// Name resolution, and the filter that waits for it.
    Dns,
    Doh,
    Timer,
    Threads,
    Ftp,
    Smtp,
    Ssls,
    Ssh,
    Ws,
    Tcp,
    Udp,
    Unix,
    TcpAccept,
    HappyEyeballs,
    Recvbuf,
    Setup,
    Http2,
    Ssl,
    SslProxy,
    H1Proxy,
    H2Proxy,
    H3Proxy,
    HttpProxy,
    Haproxy,
    Socks,
    Http3,
    HttpsConnect,
}

/// The groups a configuration can name at once (C's `TRC_CT_*`): `all`
/// names every component, whatever its category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Category {
    /// Named only by `all` or its own name.
    Plain,
    Protocol,
    Network,
    Proxy,
    Internals,
}

impl Component {
    /// Every component, in the order C's tables list them.
    pub const ALL: [Component; 31] = [
        Component::Ids,
        Component::Multi,
        Component::Read,
        Component::Write,
        Component::Dns,
        Component::Doh,
        Component::Timer,
        Component::Threads,
        Component::Ftp,
        Component::Smtp,
        Component::Ssls,
        Component::Ssh,
        Component::Ws,
        Component::Tcp,
        Component::Udp,
        Component::Unix,
        Component::TcpAccept,
        Component::HappyEyeballs,
        Component::Recvbuf,
        Component::Setup,
        Component::Http2,
        Component::Ssl,
        Component::SslProxy,
        Component::H1Proxy,
        Component::H2Proxy,
        Component::H3Proxy,
        Component::HttpProxy,
        Component::Haproxy,
        Component::Socks,
        Component::Http3,
        Component::HttpsConnect,
    ];

    /// The name a configuration gives it, compared without case, and
    /// that its lines start with.
    pub fn name(self) -> &'static str {
        match self {
            Component::Ids => "LIB-IDS",
            Component::Multi => "MULTI",
            Component::Read => "READ",
            Component::Write => "WRITE",
            Component::Dns => "DNS",
            Component::Doh => "DoH",
            Component::Timer => "TIMER",
            Component::Threads => "THREADS",
            Component::Ftp => "FTP",
            Component::Smtp => "SMTP",
            Component::Ssls => "SSLS",
            Component::Ssh => "SSH",
            Component::Ws => "WS",
            Component::Tcp => "TCP",
            Component::Udp => "UDP",
            Component::Unix => "UNIX",
            Component::TcpAccept => "TCP-ACCEPT",
            Component::HappyEyeballs => "HAPPY-EYEBALLS",
            Component::Recvbuf => "RECVBUF",
            Component::Setup => "SETUP",
            Component::Http2 => "HTTP/2",
            Component::Ssl => "SSL",
            Component::SslProxy => "SSL-PROXY",
            Component::H1Proxy => "H1-PROXY",
            Component::H2Proxy => "H2-PROXY",
            Component::H3Proxy => "H3-PROXY",
            Component::HttpProxy => "HTTP-PROXY",
            Component::Haproxy => "HAPROXY",
            Component::Socks => "SOCKS",
            Component::Http3 => "HTTP/3",
            Component::HttpsConnect => "HTTPS-CONNECT",
        }
    }

    fn category(self) -> Category {
        match self {
            Component::Ids => Category::Internals,
            Component::Read | Component::Write | Component::Threads => Category::Plain,
            Component::Multi
            | Component::Dns
            | Component::Doh
            | Component::Timer
            | Component::Ssls
            | Component::Tcp
            | Component::Udp
            | Component::Unix
            | Component::TcpAccept
            | Component::HappyEyeballs
            | Component::Ssl => Category::Network,
            Component::Ftp
            | Component::Smtp
            | Component::Ssh
            | Component::Ws
            | Component::Recvbuf
            | Component::Setup
            | Component::Http2
            | Component::Http3
            | Component::HttpsConnect => Category::Protocol,
            Component::SslProxy
            | Component::H1Proxy
            | Component::H2Proxy
            | Component::H3Proxy
            | Component::HttpProxy
            | Component::Haproxy
            | Component::Socks => Category::Proxy,
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// How much a component traces (C's `CURL_LOG_LVL_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Level {
    #[default]
    None,
    Info,
}

/// The longest name a configuration may give: a longer one ends the
/// configuration there (`curlx_str_until`'s limit in `trc_opt`).
const NAME_MAX: usize = 32;

/// A level for each component, every one at `Level::None` to begin with.
/// A process that keeps one for good, as the C ABI does, can make it a
/// `static`; `Components` shares one.
pub struct Levels([AtomicBool; Component::ALL.len()]);

impl Levels {
    pub const fn new() -> Levels {
        Levels([const { AtomicBool::new(false) }; Component::ALL.len()])
    }
}

impl Default for Levels {
    fn default() -> Levels {
        Levels::new()
    }
}

/// The levels handles trace by, shared by every handle given a copy: a
/// copy is the same setting, not a snapshot of it.
#[derive(Clone)]
pub struct Components(Backing);

#[derive(Clone)]
enum Backing {
    Shared(TryArc<Levels>),
    Static(&'static Levels),
}

impl std::fmt::Debug for Components {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_set();
        for c in Component::ALL {
            if self.traces(c) {
                list.entry(&c);
            }
        }
        list.finish()
    }
}

impl Components {
    /// Levels of their own, every component at `Level::None`.
    pub fn new() -> Result<Components, OutOfMemory> {
        Ok(Components(Backing::Shared(TryArc::try_new(Levels::new())?)))
    }

    /// The levels a process keeps for good.
    pub fn of_static(levels: &'static Levels) -> Components {
        Components(Backing::Static(levels))
    }

    fn levels(&self) -> &Levels {
        match &self.0 {
            Backing::Shared(shared) => shared,
            Backing::Static(levels) => levels,
        }
    }

    pub fn level(&self, component: Component) -> Level {
        match self.levels().0[component.index()].load(Ordering::Relaxed) {
            true => Level::Info,
            false => Level::None,
        }
    }

    /// Whether `component` traces (`log_level >= CURL_LOG_LVL_INFO`).
    pub fn traces(&self, component: Component) -> bool {
        self.level(component) == Level::Info
    }

    pub fn set(&self, component: Component, level: Level) {
        self.levels().0[component.index()].store(level == Level::Info, Ordering::Relaxed);
    }

    /// Apply a configuration (`trc_opt`): names separated by commas, each
    /// turned on, or off after a `-` (`+` is the same as nothing). A name
    /// is a component's, compared without case, or `all`, `protocol`,
    /// `network` or `proxy` for the components of that kind. A name not
    /// known is passed over; an empty or overlong one, or anything but a
    /// comma after a name, ends the configuration there.
    pub fn configure(&self, config: &[u8]) {
        let mut rest = config;
        loop {
            let len = rest.iter().position(|&b| b == b',').unwrap_or(rest.len());
            if len == 0 || len > NAME_MAX {
                return;
            }
            let (token, after) = rest.split_at(len);
            let (level, name) = match token {
                [b'-', name @ ..] => (Level::None, name),
                [b'+', name @ ..] => (Level::Info, name),
                name => (Level::Info, name),
            };
            let category = match name {
                n if n.eq_ignore_ascii_case(b"all") => Some(None),
                n if n.eq_ignore_ascii_case(b"protocol") => Some(Some(Category::Protocol)),
                n if n.eq_ignore_ascii_case(b"network") => Some(Some(Category::Network)),
                n if n.eq_ignore_ascii_case(b"proxy") => Some(Some(Category::Proxy)),
                _ => None,
            };
            for c in Component::ALL {
                let named = match category {
                    Some(None) => true,
                    Some(Some(kind)) => c.category() == kind,
                    None => name.eq_ignore_ascii_case(c.name().as_bytes()),
                };
                if named {
                    self.set(c, level);
                }
            }
            match after {
                [b',', next @ ..] => rest = next,
                _ => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(config: &[&[u8]]) -> Vec<&'static str> {
        let c = Components::new().unwrap();
        for one in config {
            c.configure(one);
        }
        Component::ALL
            .into_iter()
            .filter(|&x| c.traces(x))
            .map(Component::name)
            .collect()
    }

    #[test]
    fn names_turn_components_on_and_off() {
        assert_eq!(on(&[b"write,Read"]), ["READ", "WRITE"]);
        assert_eq!(on(&[b"write,+dns", b"-WRITE"]), ["DNS"]);
        assert_eq!(on(&[b"http/2,tcp"]), ["TCP", "HTTP/2"]);
        // Names not known, the tool's among them, are passed over.
        assert_eq!(on(&[b"ids,time,nope,write"]), ["WRITE"]);
        // `-` or `+` alone names nothing, and the rest is still read.
        assert_eq!(on(&[b"-,+,write"]), ["WRITE"]);
    }

    /// Shown, a set lists the components it traces, and only those.
    #[test]
    fn a_set_shows_the_components_it_traces() {
        let c = Components::new().unwrap();
        assert_eq!(format!("{c:?}"), "{}");
        c.configure(b"read,tcp");
        assert_eq!(format!("{c:?}"), "{Read, Tcp}");
    }

    #[test]
    fn categories_name_their_components() {
        assert_eq!(on(&[b"all"]).len(), Component::ALL.len());
        assert_eq!(on(&[b"all,-lib-ids"]).len(), Component::ALL.len() - 1);
        assert_eq!(
            on(&[b"proxy"]),
            [
                "SSL-PROXY",
                "H1-PROXY",
                "H2-PROXY",
                "H3-PROXY",
                "HTTP-PROXY",
                "HAPROXY",
                "SOCKS"
            ]
        );
        assert_eq!(
            on(&[b"protocol"]),
            [
                "FTP",
                "SMTP",
                "SSH",
                "WS",
                "RECVBUF",
                "SETUP",
                "HTTP/2",
                "HTTP/3",
                "HTTPS-CONNECT"
            ]
        );
        assert_eq!(
            on(&[b"NETWORK"]),
            [
                "MULTI",
                "DNS",
                "DoH",
                "TIMER",
                "SSLS",
                "TCP",
                "UDP",
                "UNIX",
                "TCP-ACCEPT",
                "HAPPY-EYEBALLS",
                "SSL"
            ]
        );
        assert_eq!(
            on(&[b"all,-network,-protocol,-proxy"]),
            ["LIB-IDS", "READ", "WRITE", "THREADS"]
        );
    }

    /// An empty name, one past 32 bytes or a configuration that does not
    /// go on with a comma ends it, as `curlx_str_until` does in C.
    #[test]
    fn a_bad_name_ends_the_configuration() {
        assert_eq!(on(&[b"write,,read"]), ["WRITE"]);
        assert_eq!(on(&[b",write"]), Vec::<&str>::new());
        assert_eq!(on(&[b"write,"]), ["WRITE"]);
        let long = [&b"-"[..], &[b'x'; 32], b",write"].concat();
        assert_eq!(on(&[&long]), Vec::<&str>::new());
        let fits = [&[b'x'; 32][..], b",write"].concat();
        assert_eq!(on(&[&fits]), ["WRITE"]);
        // Spaces are part of a name.
        assert_eq!(on(&[b"read, write"]), ["READ"]);
    }

    /// A copy is the same setting: a change shows through every copy.
    #[test]
    fn copies_share_the_setting() {
        let a = Components::new().unwrap();
        let b = a.clone();
        a.configure(b"write");
        assert_eq!(b.level(Component::Write), Level::Info);
        b.set(Component::Write, Level::None);
        assert!(!a.traces(Component::Write));
        static KEPT: Levels = Levels::new();
        let c = Components::of_static(&KEPT);
        c.configure(b"read");
        assert!(Components::of_static(&KEPT).traces(Component::Read));
    }
}
