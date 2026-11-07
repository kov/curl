//! The resolve the race went on beside, still going on as the race is won:
//! kept until the chain below the name's DNS filter connects, which for an
//! `https` origin is after its TLS handshake, its answer still taken and
//! said meanwhile, as C's filter keeps it (`cf_dns_connect`'s
//! `Curl_resolv_destroy`). Each of the three backends: DoH, a resolver
//! library standing for c-ares, and the network's resolver, which says its
//! lines as C's threaded resolver does. C's debug builds over c-ares, the
//! threaded resolver and DoH, with AAAA answered late against an `https`
//! origin whose handshake is slower still, say the same lines.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::conn::io::{Conversation, FakeNet, Peer, SharedNet};
use crate::time::ManualClock;
use crate::tls::fake;

const ORIGIN: &str = "https://late.test/x";
const DOH: ([u8; 4], u16) = ([127, 0, 0, 1], 53);

/// Keeps the trace's text lines.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<String>>>);

impl crate::handler::DebugHandler for Lines {
    fn debug(&self, _: &mut TransferCx<'_>, kind: crate::handler::DebugKind, data: &[u8]) {
        if kind == crate::handler::DebugKind::Text {
            let line = String::from_utf8_lossy(data).trim_end().to_owned();
            self.0.lock().unwrap().push(line);
        }
    }
}

/// What answers the name, A at once and AAAA once the test opens `aaaa`.
enum Backend {
    /// A DoH server.
    Doh,
    /// A resolver library, as c-ares; its resolve, made once, is there
    /// while `alive` says so, counts its runs in `runs` and waits on the
    /// socket numbered `fd`, which closes as it goes.
    Library {
        alive: Arc<AtomicBool>,
        runs: Arc<AtomicU32>,
        fd: Arc<AtomicU64>,
    },
    /// The network's resolver, which says its lines as C's threaded one.
    Resolver,
}

/// A gate the test opens.
#[derive(Clone, Default)]
struct Gate(Arc<AtomicBool>);

impl Gate {
    fn open(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// A resolve of the library [`Library`] stands for: 127.0.0.1 at once,
/// ::1 too once its gate opens, waiting on its socket meanwhile, closed as
/// it goes, as c-ares's `ares_destroy` closes its channel's; no record.
#[derive(Debug)]
struct LibraryResolve {
    record: bool,
    aaaa: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    runs: Arc<AtomicU32>,
    wants: Vec<(Box<dyn crate::conn::io::Socket>, Events)>,
    closed: crate::conn::io::SocketsClosed,
}

impl LibraryResolve {
    fn answered(&self) -> bool {
        self.aaaa.load(Ordering::Relaxed)
    }
    fn addrs(&self) -> Vec<IpAddr> {
        let mut addrs = Vec::new();
        if self.answered() {
            addrs.push(Ipv6Addr::LOCALHOST.into());
        }
        addrs.push([127, 0, 0, 1].into());
        addrs
    }
}

impl Drop for LibraryResolve {
    fn drop(&mut self) {
        if !self.record {
            self.alive.store(false, Ordering::Relaxed);
        }
        for (socket, _) in &self.wants {
            self.closed.said(socket.key()).unwrap();
        }
    }
}

impl crate::conn::io::DnsResolve for LibraryResolve {
    fn perform(&mut self) -> Result<(), curl_alloc::OutOfMemory> {
        if !self.record {
            self.runs.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
    fn wants(&self) -> &[(Box<dyn crate::conn::io::Socket>, Events)] {
        match self.answered() {
            true => &[],
            false => &self.wants,
        }
    }
    fn due(&self, within: Duration) -> Duration {
        within
    }
    fn partial(&self) -> Result<crate::conn::io::Partial, curl_alloc::OutOfMemory> {
        Ok(crate::conn::io::Partial {
            addrs: self.addrs(),
            v6_answered: self.answered(),
            v4_answered: true,
        })
    }
    fn ongoing(&self) -> (u32, &'static str) {
        match (self.record, self.answered()) {
            (true, _) => (0, "-"),
            (false, false) => (1, "A"),
            (false, true) => (0, "A+AAAA"),
        }
    }
    fn answer(&mut self) -> Option<Result<Vec<IpAddr>, crate::conn::io::ResolveFailure>> {
        self.answered().then(|| Ok(self.addrs()))
    }
    fn record(&mut self) -> Option<crate::doh::RecordAnswer> {
        Some(crate::doh::RecordAnswer::NoSuchName)
    }
    fn explain(&self) -> Option<&'static str> {
        None
    }
    fn status(&self) -> i32 {
        0
    }
}

/// A resolver library standing for c-ares, its resolves answering AAAA
/// once `aaaa` opens, the addresses' waiting on `socket`.
#[derive(Debug)]
struct Library {
    aaaa: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    runs: Arc<AtomicU32>,
    socket: Mutex<Option<Box<dyn crate::conn::io::Socket>>>,
}

impl crate::conn::io::DnsLibrary for Library {
    fn resolve(
        &self,
        ask: crate::conn::io::DnsAsk<'_>,
        _: &mut crate::conn::io::DnsSay<'_>,
    ) -> Result<Box<dyn crate::conn::io::DnsResolve>, crate::conn::io::DnsRefused> {
        let record = ask.family.is_none();
        let mut wants = Vec::new();
        if !record {
            self.alive.store(true, Ordering::Relaxed);
            let socket = self.socket.lock().unwrap().take().expect("one resolve");
            wants.push((socket, Events::IN));
        }
        Ok(Box::new(LibraryResolve {
            record,
            aaaa: self.aaaa.clone(),
            alive: self.alive.clone(),
            runs: self.runs.clone(),
            wants,
            closed: ask.closed.clone(),
        }))
    }
}

/// A DNS message answering `qtype` for `late.test` with `rdata`, none if
/// it is empty; an HTTPS question's no such name.
fn dns(qtype: u8, rdata: &[u8]) -> Vec<u8> {
    let (flags, ancount) = match (qtype, rdata.is_empty()) {
        (65, _) => (0x83, 0),
        (_, true) => (0x80, 0),
        (_, false) => (0x80, 1),
    };
    let mut m = vec![0, 0, 0x81, flags, 0, 1, 0, ancount, 0, 0, 0, 0];
    m.extend_from_slice(b"\x04late\x04test\x00\x00");
    m.extend_from_slice(&[qtype, 0, 1]);
    if !rdata.is_empty() {
        m.extend_from_slice(b"\xc0\x0c\x00");
        m.extend_from_slice(&[qtype, 0, 1, 0, 0, 0, 0x37, 0, rdata.len() as u8]);
        m.extend_from_slice(rdata);
    }
    let mut reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", m.len()).into_bytes();
    reply.extend_from_slice(&m);
    reply
}

/// The lines of a transfer of [`ORIGIN`] through `backend`, the race won
/// on A's answer and the TLS handshake held: AAAA answered while it is
/// held if `aaaa_meanwhile`, never otherwise. `held` is told how it stands
/// while the handshake is held, and `done` once the transfer is.
fn transfer(
    backend: &Backend,
    aaaa_meanwhile: bool,
    held: impl FnOnce(&Multi, &FakeNetCheck),
    done: impl FnOnce(&Multi, &FakeNetCheck),
) -> Vec<String> {
    let clock = ManualClock::new().unwrap();
    let response = fake::records(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
    let origin = Conversation::replies(&[fake::WELCOME, &response], false).held();
    let gate = Gate::default();
    let late = crate::conn::io::Late::new();
    let aaaa_probe = Conversation::new(&dns(28, &Ipv6Addr::LOCALHOST.octets()), false).held();
    let mut net = FakeNet::new(clock.clone())
        .with_peer(SocketAddr::from(([127, 0, 0, 1], 443)), Peer::Accepts)
        .with_conversation(SocketAddr::from(([127, 0, 0, 1], 443)), origin.clone());
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(ORIGIN.as_bytes())).unwrap();
    let mut library = None;
    match backend {
        Backend::Doh => {
            o.doh.make_mut().unwrap().url = Some(b"http://127.0.0.1:53/dns".to_vec());
            net = net
                .with_peer(DOH.into(), Peer::Accepts)
                .with_conversation(DOH.into(), Conversation::new(&dns(65, &[]), false))
                .with_conversation(DOH.into(), aaaa_probe.clone())
                .with_conversation(
                    DOH.into(),
                    Conversation::new(&dns(1, &[127, 0, 0, 1]), false),
                );
        }
        Backend::Library { alive, runs, fd } => {
            // Its socket is the library's own, from a network of its own.
            let to = SocketAddr::from(([127, 0, 0, 1], 53));
            let own = Box::leak(Box::new(
                FakeNet::new(clock.clone()).with_peer(to, Peer::Silent),
            ));
            let open = |own: &mut FakeNet| {
                own.open(
                    &crate::conn::io::Remote::Inet(to),
                    crate::conn::io::SocketKind::Datagram,
                )
                .unwrap()
            };
            // Numbered past the connection's, which the transfer's
            // network numbers from the same first number.
            std::mem::forget(open(own));
            let socket = open(own);
            fd.store(
                u64::try_from(socket.key().get()).unwrap(),
                Ordering::Relaxed,
            );
            let lib: &'static Library = Box::leak(Box::new(Library {
                aaaa: gate.0.clone(),
                alive: alive.clone(),
                runs: runs.clone(),
                socket: Mutex::new(Some(socket)),
            }));
            library = Some(lib as &'static dyn crate::conn::io::DnsLibrary);
        }
        Backend::Resolver => {
            net = net
                .with_late_name(
                    "late.test",
                    &[[127, 0, 0, 1].into(), Ipv6Addr::LOCALHOST.into()],
                    &late,
                )
                .with_v4_first();
        }
    }
    let shared = Arc::new(Mutex::new(net));
    let mut m = Multi::new(Env {
        clock: Box::new(clock.clone()),
        net: Box::new(SharedNet(shared.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    })
    .unwrap();
    let tls: &'static fake::FakeTls = Box::leak(Box::new(fake::FakeTls::new().unwrap()));
    easy.set_libraries(
        crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
            tls: Some(crate::libraries::Library::Static(tls)),
            dns: library,
            ..crate::libraries::Libraries::NONE
        })
        .unwrap(),
    );
    let lines = Lines::default();
    let o = easy.options_mut();
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    let c = crate::components::Components::new().unwrap();
    c.configure(b"dns,happy-eyeballs,multi,ssl,tcp");
    easy.set_components(Some(c));
    m.add(Box::new(easy), (), &mut NoEvents).unwrap();
    let run = |m: &mut Multi| {
        for _ in 0..60 {
            m.perform(&mut NoEvents).unwrap();
            // Each pass's pollsets traced, as `curl_multi_fdset` traces them.
            m.sockets(&mut NoEvents, |_, _| {}).unwrap();
            clock.advance(Duration::from_millis(1));
        }
    };
    run(&mut m);
    assert!(origin.received().starts_with(fake::HELLO), "the race won");
    if aaaa_meanwhile {
        gate.open();
        late.release();
        aaaa_probe.allow(1);
        run(&mut m);
    }
    let check = FakeNetCheck(shared);
    held(&m, &check);
    origin.allow(2);
    run(&mut m);
    assert_eq!(m.info_read().map(|msg| msg.result), Some(Ok(())));
    done(&m, &check);
    lines.0.lock().unwrap().clone()
}

/// What a test reads of the fake network.
struct FakeNetCheck(Arc<Mutex<FakeNet>>);

impl FakeNetCheck {
    fn resolving(&self) -> usize {
        self.0.lock().unwrap().resolving()
    }
}

/// Where `want` is first said, at or past `from`.
fn at(said: &[String], from: usize, want: &str) -> usize {
    said[from..]
        .iter()
        .position(|l| l == want)
        .map(|i| from + i)
        .unwrap_or_else(|| panic!("{want} past {from}: {said:#?}"))
}

/// The lines every backend says of a resolve answered once the race is
/// won: looked at again in each pass of the handshake, as C's filter does
/// above it, then its answer kept and said, with no attempt to the
/// address that came, and its record let go of as the chain connects.
fn answered_meanwhile_is_said(said: &[String]) {
    let won = at(said, 0, "[HAPPY-EYEBALLS] connect attempt #0 successful");
    let looked = at(
        said,
        won,
        "[DNS] [A+AAAA] resolve incomplete, responses=A, ongoing=1 for late.test:443",
    );
    let complete = at(
        said,
        looked,
        "[DNS] [A+AAAA] resolve complete for late.test:443",
    );
    let cached = at(
        said,
        complete,
        "[DNS] cached entry for late.test:443 queries=A+AAAA",
    );
    let host = at(said, cached, "Host late.test:443 was resolved.");
    assert_eq!(
        said[host + 1..host + 3],
        ["IPv6: ::1", "IPv4: 127.0.0.1"],
        "{said:#?}"
    );
    let connected = at(said, host, "[DNS] connected filter chain below");
    assert!(
        said[connected + 1].ends_with("] destroy async"),
        "{said:#?}"
    );
    assert_ne!(said[connected + 2], "[DNS] [DoH] probe done", "{said:#?}");
    let attempts = said
        .iter()
        .filter(|l| l.contains(" attempt for ipv"))
        .count();
    assert_eq!(
        attempts, 1,
        "the address that came started nothing: {said:#?}"
    );
}

/// The resolve still going on is looked at in each pass of the handshake,
/// as C's filter does above it: A's answer and AAAA's not.
fn looked_at_through_the_handshake(said: &[String]) -> usize {
    let won = at(said, 0, "[HAPPY-EYEBALLS] connect attempt #0 successful");
    let looked = at(
        said,
        won,
        "[DNS] [A+AAAA] resolve incomplete, responses=A, ongoing=1 for late.test:443",
    );
    assert!(
        !said
            .iter()
            .any(|l| l.starts_with("Host late.test:443 was resolved")),
        "{said:#?}"
    );
    let connected = at(said, looked, "[DNS] connected filter chain below");
    assert!(
        said[connected + 1].ends_with("] destroy async"),
        "{said:#?}"
    );
    connected + 1
}

/// Over DoH, AAAA answered during the handshake is kept and said, its
/// probes done as it is taken.
#[test]
fn over_doh_an_answer_during_the_handshake_is_kept() {
    let said = transfer(&Backend::Doh, true, |_, _| {}, |_, _| {});
    answered_meanwhile_is_said(&said);
    let done = said
        .iter()
        .filter(|l| *l == "[DNS] [DoH] probe done")
        .count();
    assert_eq!(done, 4, "the record's two, the addresses' two: {said:#?}");
}

/// Over DoH, AAAA still unanswered as the chain connects goes with the
/// name's filter, its probe said done right after its record goes, as C's
/// `Curl_resolv_destroy` closes it (`doh_close`).
#[test]
fn over_doh_a_probe_still_out_goes_as_the_chain_connects() {
    let said = transfer(
        &Backend::Doh,
        false,
        |m, _| assert_eq!(m.census().counts.current, 3, "the AAAA probe runs"),
        |m, _| assert_eq!(m.census().counts.current, 1, "the probes went"),
    );
    let destroyed = looked_at_through_the_handshake(&said);
    assert_eq!(said[destroyed + 1], "[DNS] [DoH] probe done", "{said:#?}");
    let done = said
        .iter()
        .filter(|l| *l == "[DNS] [DoH] probe done")
        .count();
    assert_eq!(done, 3, "the record's two, the addresses' one: {said:#?}");
}

/// Through a resolver library, as c-ares, AAAA answered during the
/// handshake is kept and said.
#[test]
fn through_a_library_an_answer_during_the_handshake_is_kept() {
    let fd = Arc::new(AtomicU64::new(0));
    let backend = Backend::Library {
        alive: Arc::default(),
        runs: Arc::default(),
        fd: fd.clone(),
    };
    let said = transfer(&backend, true, |_, _| {}, |_, _| {});
    answered_meanwhile_is_said(&said);
    polled_as_the_resolver_s(&said, fd.load(Ordering::Relaxed));
    let taken = at(
        &said,
        0,
        "[DNS] [A+AAAA] ares_take_result, result=0, ares_result=0, ares_status=0, dns=found",
    );
    assert_eq!(
        said[taken + 1],
        "[DNS] [A+AAAA] resolve complete for late.test:443"
    );
}

/// Through a resolver library, the resolve still going on as the chain
/// connects is run through the handshake and let go of then.
#[test]
fn through_a_library_a_resolve_still_going_on_goes_as_the_chain_connects() {
    let (alive, runs) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicU32::new(0)),
    );
    let fd = Arc::new(AtomicU64::new(0));
    let backend = Backend::Library {
        alive: alive.clone(),
        runs: runs.clone(),
        fd: fd.clone(),
    };
    let ran = Arc::new(AtomicU32::new(0));
    let said = transfer(
        &backend,
        false,
        |_, _| {
            assert!(alive.load(Ordering::Relaxed), "kept through the handshake");
            ran.store(runs.load(Ordering::Relaxed), Ordering::Relaxed);
        },
        |_, _| assert!(!alive.load(Ordering::Relaxed), "let go of"),
    );
    let destroyed = looked_at_through_the_handshake(&said);
    assert!(
        runs.load(Ordering::Relaxed) > ran.load(Ordering::Relaxed),
        "run again as the handshake goes on"
    );
    let fd = fd.load(Ordering::Relaxed);
    let closed = format!("[MULTI] [CONNECTING] Curl_multi_will_close fd={fd}");
    assert_eq!(said[destroyed + 1], closed, "{said:#?}");
    polled_as_the_resolver_s(&said, fd);
}

/// The library's socket `fd` is in the pollset through the handshake, as
/// C's DNS filter puts it in (`Curl_resolv_pollset`), and said as no
/// socket filter's: the TLS filter's line names the connection's.
fn polled_as_the_resolver_s(said: &[String], fd: u64) {
    let won = at(said, 0, "[HAPPY-EYEBALLS] connect attempt #0 successful");
    let shaking = said[won..]
        .iter()
        .position(|l| l.starts_with("[SSL] adjust_pollset, POLLIN fd="))
        .map(|i| won + i)
        .unwrap_or_else(|| panic!("{said:#?}"));
    let set = said[shaking..]
        .iter()
        .find(|l| l.starts_with("[MULTI] [CONNECTING] pollset["))
        .unwrap_or_else(|| panic!("{said:#?}"));
    assert!(set.contains(&format!("fd={fd} IN")), "{said:#?}");
    let own = format!("fd={fd}");
    assert!(
        !said
            .iter()
            .any(|l| l.contains("] adjust_pollset, ") && l.ends_with(&own)),
        "{said:#?}"
    );
}

/// Through the network's resolver, said as C's threaded resolver says it,
/// AAAA answered during the handshake is kept and said, its addresses as
/// they are taken.
#[test]
fn through_the_resolver_an_answer_during_the_handshake_is_kept() {
    let said = transfer(&Backend::Resolver, true, |_, _| {}, |_, _| {});
    answered_meanwhile_is_said(&said);
    let came = at(&said, 0, "[DNS] Host late.test:443 resolved IPv6: ::1");
    assert_eq!(
        said[came + 1],
        "[DNS] [A+AAAA] resolve complete for late.test:443"
    );
}

/// Through the network's resolver, the resolve still going on as the
/// chain connects is kept in the resolver through the handshake and let
/// go of there then.
#[test]
fn through_the_resolver_a_resolve_still_going_on_goes_as_the_chain_connects() {
    let said = transfer(
        &Backend::Resolver,
        false,
        |_, net| assert_eq!(net.resolving(), 1, "kept through the handshake"),
        |_, net| assert_eq!(net.resolving(), 0, "let go of"),
    );
    looked_at_through_the_handshake(&said);
}
