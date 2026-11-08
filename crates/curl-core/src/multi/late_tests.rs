//! The resolve the race went on beside, still going on as the race is won:
//! kept until the chain below the name's DNS filter connects, which for an
//! `https` origin is after its TLS handshake, its answer still taken and
//! said meanwhile, as C's filter keeps it (`cf_dns_connect`'s
//! `Curl_resolv_destroy`). Each of the three backends: DoH, a resolver
//! library standing for c-ares, and the network's resolver, which says its
//! lines as C's threaded resolver does. C's debug builds over c-ares, the
//! threaded resolver and DoH, with AAAA answered late against an `https`
//! origin whose handshake is slower still, say the same lines.

use curl_alloc::Lock;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use super::*;
use crate::conn::io::{Conversation, FakeNet, Peer, SharedNet};
use crate::time::ManualClock;
use crate::tls::fake;

const ORIGIN: &str = "https://late.test/x";
const DOH: ([u8; 4], u16) = ([127, 0, 0, 1], 53);

/// Keeps the trace's text lines.
#[derive(Clone, Default)]
struct Lines(Arc<Lock<Vec<String>>>);

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
/// once `aaaa` opens, the addresses' each waiting on the next of
/// `sockets`, and counted in `made`.
#[derive(Debug)]
struct Library {
    aaaa: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    runs: Arc<AtomicU32>,
    made: Arc<AtomicU32>,
    sockets: Lock<Vec<Box<dyn crate::conn::io::Socket>>>,
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
            self.made.fetch_add(1, Ordering::Relaxed);
            let mut sockets = self.sockets.lock().unwrap();
            assert!(!sockets.is_empty(), "a socket for each resolve");
            wants.push((sockets.remove(0), Events::IN));
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
    transfer_ending(backend, aaaa_meanwhile, None, held, done)
}

/// The same, the handshake held for good if `limit`, the connect limit
/// in milliseconds, is given, for the transfer to time out.
fn transfer_ending(
    backend: &Backend,
    aaaa_meanwhile: bool,
    limit: Option<u64>,
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
    if let Some(ms) = limit {
        o.limits.connect = crate::time::TimeLimit::from_millis(ms);
    }
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
            fd.store(socket_number(socket.key()), Ordering::Relaxed);
            let lib: &'static Library = Box::leak(Box::new(Library {
                aaaa: gate.0.clone(),
                alive: alive.clone(),
                runs: runs.clone(),
                made: Arc::default(),
                sockets: Lock::new(vec![socket]),
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
    let shared = Arc::new(Lock::new(net));
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
    c.configure(b"dns,happy-eyeballs,multi,ssl,tcp,timer");
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
    if limit.is_some() {
        run(&mut m);
        run(&mut m);
        let ended = m.info_read().map(|msg| msg.result);
        assert_eq!(ended, Some(Err(ErrorKind::OperationTimedout)));
    } else {
        // The handshake ends, and the response is held a while: the
        // transfer waits for it in PERFORMING.
        origin.allow(1);
        run(&mut m);
        origin.allow(2);
        run(&mut m);
        assert_eq!(m.info_read().map(|msg| msg.result), Some(Ok(())));
    }
    done(&m, &check);
    lines.0.lock().unwrap().clone()
}

/// What a test reads of the fake network.
struct FakeNetCheck(Arc<Lock<FakeNet>>);

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
        said[came + 2],
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

/// A connect that runs out during the handshake with the name's resolve
/// still going on times out as "Resolving", as C names it while the DNS
/// filter has not announced the name resolved (`bits.dns_resolved`); once
/// the answer has come, as "Connection". C's tool says the same against
/// an `https` origin holding its first flight, AAAA answered after the
/// limit and before it.
#[test]
fn a_handshake_timed_out_beside_the_resolve_times_out_as_resolving() {
    let said = |aaaa_meanwhile| {
        let lines = transfer_ending(
            &Backend::Resolver,
            aaaa_meanwhile,
            Some(150),
            |_, _| {},
            |_, _| {},
        );
        at(&lines, 0, "[HAPPY-EYEBALLS] connect attempt #0 successful");
        let failed: Vec<String> = lines
            .iter()
            .filter(|l| l.contains(" timed out after "))
            .cloned()
            .collect();
        assert_eq!(failed.len(), 1, "{lines:#?}");
        failed[0].split(" after ").next().unwrap().to_owned()
    };
    assert_eq!(said(false), "Resolving timed out");
    assert_eq!(said(true), "Connection timed out");
}

/// Whether the name's timer is armed as each of the transfer's pollsets
/// is said in `state`, past line `from`: the timers armed are said right
/// after it.
fn name_timer_in(said: &[String], from: usize, state: &str) -> Vec<bool> {
    let head = format!("[MULTI] [{state}] pollset[");
    let mut armed = Vec::new();
    for (i, l) in said.iter().enumerate().skip(from) {
        if !l.starts_with(&head) {
            continue;
        }
        let name = said[i + 1..]
            .iter()
            .take_while(|l| l.starts_with("[TIMER] "))
            .any(|l| l.starts_with("[TIMER] [ASYNC_NAME] expires in "));
        armed.push(name);
    }
    armed
}

/// Through a resolver library, as c-ares, the resolve answered during the
/// handshake goes on arming the name's timer, for its time left, while its
/// record is kept, and the timer stays armed once the record goes: C's
/// channel, still open, arms it in each pollset (`Curl_async_pollset`),
/// and nothing disarms it. C's debug build over c-ares says
/// `timeouts=1` through the rest of the handshake and in PERFORMING, the
/// name's timer the one armed.
#[test]
fn through_a_library_the_name_timer_stays_armed_once_answered() {
    let backend = Backend::Library {
        alive: Arc::default(),
        runs: Arc::default(),
        fd: Arc::default(),
    };
    let said = transfer(&backend, true, |_, _| {}, |_, _| {});
    let complete = at(
        &said,
        0,
        "[DNS] [A+AAAA] resolve complete for late.test:443",
    );
    let connecting = name_timer_in(&said, complete, "CONNECTING");
    assert!(!connecting.is_empty(), "{said:#?}");
    assert!(connecting.iter().all(|&armed| armed), "{said:#?}");
    let connected = at(&said, complete, "[DNS] connected filter chain below");
    let performing = name_timer_in(&said, connected, "PERFORMING");
    assert!(!performing.is_empty(), "{said:#?}");
    assert!(performing.iter().all(|&armed| armed), "{said:#?}");
}

/// Through the network's resolver, said as C's threaded resolver says it,
/// the resolve still going on beside the handshake arms the name's timer
/// for its time left, and its answer disarms it, said between the
/// answers' lines and the resolve's end: C's threaded build says
/// `timeouts=1` through the handshake with AAAA still out,
/// `[TIMER] [ASYNC_NAME] cleared` as it takes the answer, and
/// `timeouts=0` once it has come (`Curl_async_pollset`,
/// `Curl_expire_clear`).
#[test]
fn through_the_resolver_the_name_timer_is_armed_until_the_answer() {
    let said = transfer(&Backend::Resolver, true, |_, _| {}, |_, _| {});
    let won = at(&said, 0, "[HAPPY-EYEBALLS] connect attempt #0 successful");
    let complete = at(
        &said,
        won,
        "[DNS] [A+AAAA] resolve complete for late.test:443",
    );
    let v6 = at(&said, won, "[DNS] Host late.test:443 resolved IPv6: ::1");
    assert_eq!(
        said[v6 + 1..complete],
        ["[TIMER] [ASYNC_NAME] cleared"],
        "{said:#?}"
    );
    let shaking = name_timer_in(&said[..complete], won, "CONNECTING");
    assert!(!shaking.is_empty(), "{said:#?}");
    assert!(shaking.iter().all(|&armed| armed), "{said:#?}");
    let answered = name_timer_in(&said, complete, "CONNECTING");
    assert!(!answered.is_empty(), "{said:#?}");
    assert!(answered.iter().all(|&armed| !armed), "{said:#?}");
}

/// Over DoH, nothing arms the name's timer: the probes are transfers of
/// their own, which wake the multi (`Curl_resolv_pollset` passes DoH by).
#[test]
fn over_doh_the_name_timer_is_never_armed() {
    let said = transfer(&Backend::Doh, true, |_, _| {}, |_, _| {});
    let armed = name_timer_in(&said, 0, "CONNECTING");
    assert!(!armed.is_empty(), "{said:#?}");
    assert!(armed.iter().all(|&armed| !armed), "{said:#?}");
}

/// What an FTPS download over a resolver library said, and the number
/// of the socket its data connection's resolve waits on.
struct FtpOverLibrary {
    said: Vec<String>,
    data_fd: u64,
}

/// When the library's AAAA comes for an FTPS download's names.
#[derive(Clone, Copy, PartialEq)]
enum Aaaa {
    Never,
    /// As the data connection races, its first attempt waiting.
    Racing,
    /// During the data connection's TLS handshake.
    Shaking,
}

/// An FTPS download of `ftps://ftp.example:8021/f` over `--connect-to
/// ::late.test:8021`, both of its connections' names resolved by a
/// resolver library whose AAAA comes once its gate opens, as `aaaa`
/// says; the server holds the data connection's TLS handshake. Its data
/// peer accepts 50 ms after it is dialed. `held` is told, while the handshake is held, what was said,
/// whether in each pass the data connection's resolve ran its socket was
/// waited on and whether the TLS had started, and where in what was said
/// the data connection was dialed and its TLS started.
fn ftp_over_a_library(
    aaaa: Aaaa,
    held: impl FnOnce(&[String], &[(bool, bool)], usize, usize),
) -> FtpOverLibrary {
    let clock = ManualClock::new().unwrap();
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let control = [
        fake::WELCOME.to_vec(),
        tls(b"220 hi\r\n"),
        tls(b"331 password?\r\n"),
        tls(b"230 in\r\n"),
        tls(b"200 PBSZ\r\n"),
        tls(b"200 PROT\r\n"),
        tls(b"257 \"/\" is it\r\n"),
        tls(b"229 Entering Extended Passive Mode (|||8022|)\r\n"),
        tls(b"200 binary\r\n"),
        tls(b"213 5\r\n"),
        tls(b"150 here\r\n226 done\r\n"),
    ];
    let control: Vec<&[u8]> = control.iter().map(Vec::as_slice).collect();
    let control = Conversation::replies(&control, false).per_send();
    let file = [fake::WELCOME.to_vec(), tls(b"hello")];
    let file: Vec<&[u8]> = file.iter().map(Vec::as_slice).collect();
    let file = Conversation::replies(&file, true).per_send().held();
    let (control_at, data_at) = (
        SocketAddr::from(([127, 0, 0, 1], 8021)),
        SocketAddr::from(([127, 0, 0, 1], 8022)),
    );
    let net = FakeNet::new(clock.clone())
        .with_peer(control_at, Peer::Accepts)
        .with_conversation(control_at, control)
        .with_peer(data_at, Peer::AcceptsAfter(Duration::from_millis(50)))
        .with_conversation(data_at, file.clone());
    // The library's sockets, the control connection's resolve's and the
    // data connection's, numbered past the transfer's own.
    let to = SocketAddr::from(([127, 0, 0, 1], 53));
    let own = Box::leak(Box::new(
        FakeNet::new(clock.clone()).with_peer(to, Peer::Silent),
    ));
    let mut open = || {
        own.open(
            &crate::conn::io::Remote::Inet(to),
            crate::conn::io::SocketKind::Datagram,
        )
        .unwrap()
    };
    for _ in 0..8 {
        std::mem::forget(open());
    }
    let sockets = vec![open(), open()];
    let data_resolve = sockets[1].key();
    let gate = Gate::default();
    let made = Arc::new(AtomicU32::new(0));
    let lib: &'static Library = Box::leak(Box::new(Library {
        aaaa: gate.0.clone(),
        alive: Arc::default(),
        runs: Arc::default(),
        made: made.clone(),
        sockets: Lock::new(sockets),
    }));
    let mut m = Multi::new(Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    })
    .unwrap();
    let backend: &'static fake::FakeTls = Box::leak(Box::new(fake::FakeTls::ticketing().unwrap()));
    let mut easy = Easy::new();
    easy.set_libraries(
        crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
            tls: Some(crate::libraries::Library::Static(backend)),
            dns: Some(lib as &'static dyn crate::conn::io::DnsLibrary),
            ..crate::libraries::Libraries::NONE
        })
        .unwrap(),
    );
    let lines = Lines::default();
    let o = easy.options_mut();
    o.set_url(Some(b"ftps://ftp.example:8021/f")).unwrap();
    o.connect_to.set([&b"::late.test:8021"[..]]).unwrap();
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    let c = crate::components::Components::new().unwrap();
    c.configure(b"dns,multi,timer");
    easy.set_components(Some(c));
    m.add(Box::new(easy), (), &mut NoEvents).unwrap();
    let mut passes: Vec<(bool, bool)> = Vec::new();
    let shaking_from = std::cell::Cell::new(None);
    let run = |m: &mut Multi, passes: &mut Vec<(bool, bool)>| {
        for _ in 0..300 {
            m.perform(&mut NoEvents).unwrap();
            let mut waited = false;
            m.sockets(&mut NoEvents, |key, events| {
                waited |= key == data_resolve && events.contains(Events::IN);
            })
            .unwrap();
            let dialed = || {
                lines
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|l| l == "  Trying 127.0.0.1:8022...")
            };
            if aaaa == Aaaa::Racing && dialed() {
                gate.open();
            }
            if made.load(Ordering::Relaxed) == 2 {
                let shaking = !file.received().is_empty();
                passes.push((waited, shaking));
                if shaking && shaking_from.get().is_none() {
                    shaking_from.set(Some(lines.0.lock().unwrap().len()));
                }
            }
            clock.advance(Duration::from_millis(1));
        }
    };
    run(&mut m, &mut passes);
    let said = lines.0.lock().unwrap().clone();
    let dialed = at(&said, 0, "  Trying 127.0.0.1:8022...");
    let shaking = shaking_from.get().expect("its TLS started");
    held(&said, &passes, dialed, shaking);
    if aaaa == Aaaa::Shaking {
        gate.open();
        run(&mut m, &mut passes);
    }
    file.allow(2);
    run(&mut m, &mut passes);
    let said = lines.0.lock().unwrap().clone();
    assert_eq!(
        m.info_read().map(|msg| msg.result),
        Some(Ok(())),
        "{said:#?}"
    );
    FtpOverLibrary {
        said,
        data_fd: socket_number(data_resolve),
    }
}

/// FTP's data connection, its name resolved through `--connect-to` by a
/// resolver library, waits on the library's socket while the name is
/// still resolving, both before the connection is up and through its TLS
/// handshake, and arms the name's timer for it, as C's DNS filter heading
/// the data connection's chain does in its pollset
/// (`Curl_resolv_pollset`); and the answer that comes meanwhile is kept
/// and said.
#[test]
fn ftp_s_data_connection_waits_on_its_late_resolve_s_socket() {
    let ran = ftp_over_a_library(Aaaa::Shaking, |said, passes, dialed, shaking| {
        let armed = |lines: &[String]| {
            lines
                .iter()
                .any(|l| l.starts_with("[TIMER] [ASYNC_NAME] set for "))
        };
        assert!(armed(&said[dialed..shaking]), "racing: {said:#?}");
        assert!(armed(&said[shaking..]), "through its TLS: {said:#?}");
        let before: Vec<bool> = passes.iter().filter(|p| !p.1).map(|p| p.0).collect();
        let tls: Vec<bool> = passes.iter().filter(|p| p.1).map(|p| p.0).collect();
        assert!(!before.is_empty() && !tls.is_empty(), "{said:#?}");
        assert!(
            before.iter().all(|w| *w),
            "before it is up: {before:?} {said:#?}"
        );
        assert!(tls.iter().all(|w| *w), "through its TLS: {tls:?} {said:#?}");
    });
    let said = &ran.said;
    let host = at(said, 0, "Host late.test:8022 was resolved.");
    let connected = at(said, host, "[DNS-1] connected filter chain below");
    assert!(
        said[connected + 1].ends_with("] destroy async"),
        "{said:#?}"
    );
}

/// The data connection's resolve still going on as it races is looked at
/// in each call of its connect, as the name's filter heading its chain
/// looks (`cf_dns_connect`): AAAA answered meanwhile is taken and said
/// before its TLS starts. Answered, the library's record still arms the
/// name's timer through the TLS, until it goes as the chain connects, as
/// C's c-ares channel arms it in each pollset while it is open
/// (`Curl_async_pollset`).
#[test]
fn ftp_s_data_connection_takes_an_answer_as_it_races() {
    let ran = ftp_over_a_library(Aaaa::Racing, |said, _, dialed, shaking| {
        let host = at(said, dialed, "Host late.test:8022 was resolved.");
        assert!(host < shaking, "before its TLS: {said:#?}");
        assert!(
            said[shaking..]
                .iter()
                .any(|l| l.starts_with("[TIMER] [ASYNC_NAME] set for ")),
            "armed through its TLS: {said:#?}"
        );
    });
    let said = &ran.said;
    let connected = at(said, 0, "[DNS-1] connected filter chain below");
    assert!(
        said[connected + 1].ends_with("] destroy async"),
        "{said:#?}"
    );
}

/// The data connection's resolve still going on as all of its chain
/// connects, its TLS too, goes with the name's filter: its library's
/// socket closed right after its record's `destroy async`
/// (`cf_dns_connect`'s `Curl_resolv_destroy`).
#[test]
fn ftp_s_data_connection_lets_go_of_its_late_resolve_as_its_chain_connects() {
    let ran = ftp_over_a_library(Aaaa::Never, |_, _, _, _| {});
    let said = &ran.said;
    assert!(
        !said
            .iter()
            .any(|l| l.starts_with("Host late.test:8022 was resolved")),
        "{said:#?}"
    );
    let connected = at(said, 0, "[DNS-1] connected filter chain below");
    assert!(
        said[connected + 1].ends_with("] destroy async"),
        "{said:#?}"
    );
    let closed = format!(
        "[MULTI] [DOING_MORE] Curl_multi_will_close fd={}",
        ran.data_fd
    );
    assert_eq!(said[connected + 2], closed, "{said:#?}");
}

/// A proxy that closes the connection as it asks for credentials is
/// dialed again (`cf_setup_connect` discards the chain below the name's
/// filter), and the resolve of its name still going on goes on above
/// it: an answer that comes while the second `CONNECT` waits is kept and
/// said, as C's filter, left as it is by the redial, says it.
#[test]
fn a_late_resolve_lives_on_through_a_redial_for_the_proxy_s_407() {
    let clock = ManualClock::new().unwrap();
    let challenge: &[u8] = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Basic realm=\"p\"\r\nProxy-Connection: close\r\n\
        Content-Length: 0\r\n\r\n";
    let first = Conversation::replies(&[challenge], true);
    let second = Conversation::replies(
        &[
            b"HTTP/1.1 200 Fine\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ],
        false,
    )
    .held();
    let at_proxy = SocketAddr::from(([127, 0, 0, 1], 8080));
    let late = crate::conn::io::Late::new();
    let net = FakeNet::new(clock.clone())
        .with_peer(at_proxy, Peer::Accepts)
        .with_conversation(at_proxy, first.clone())
        .with_conversation(at_proxy, second.clone())
        .with_late_name(
            "proxy.test",
            &[[127, 0, 0, 1].into(), Ipv6Addr::LOCALHOST.into()],
            &late,
        )
        .with_v4_first();
    let mut m = Multi::new(Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    })
    .unwrap();
    let mut easy = Easy::new();
    let lines = Lines::default();
    let o = easy.options_mut();
    o.set_url(Some(b"http://origin.example/a")).unwrap();
    let proxy = o.proxy.make_mut().unwrap();
    proxy.url = Some(b"proxy.test:8080".to_vec());
    proxy.tunnel = true;
    proxy.user = Some(b"u".to_vec());
    proxy.password = Some(b"p".to_vec());
    proxy.auth = crate::options::HttpAuth(crate::options::AuthMethods::ANY);
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    let c = crate::components::Components::new().unwrap();
    c.configure(b"dns");
    easy.set_components(Some(c));
    m.add(Box::new(easy), (), &mut NoEvents).unwrap();
    let run = |m: &mut Multi| {
        for _ in 0..100 {
            m.perform(&mut NoEvents).unwrap();
            clock.advance(Duration::from_millis(1));
        }
    };
    run(&mut m);
    assert!(
        String::from_utf8_lossy(&second.received()).starts_with("CONNECT "),
        "dialed again: {:#?}",
        lines.0.lock().unwrap()
    );
    late.release();
    run(&mut m);
    second.allow(2);
    run(&mut m);
    assert_eq!(m.info_read().map(|msg| msg.result), Some(Ok(())));
    let said = lines.0.lock().unwrap().clone();
    let again = at(&said, 0, "Connect me again please");
    let host = at(&said, again, "Host proxy.test:8080 was resolved.");
    assert_eq!(
        said[host + 1..host + 3],
        ["IPv6: ::1", "IPv4: 127.0.0.1"],
        "{said:#?}"
    );
    let connected = at(&said, host, "[DNS] connected filter chain below");
    assert!(
        said[connected + 1].ends_with("] destroy async"),
        "{said:#?}"
    );
}

/// Beside a QUIC first attempt that never answers, a TCP second started
/// at the soft timeout wins: the resolve of the name still going on,
/// which the first holds, goes as the chain connects, its library's
/// socket closed right after its record's `destroy async`, as C's DNS
/// filter above both attempts lets go of it (`cf_dns_connect`).
#[test]
fn a_first_attempt_lost_to_the_second_lets_go_of_its_resolve_with_the_chain() {
    let (said, fd) = lost_to_the_second(b"dns,multi,https-connect", false);
    let second = said
        .iter()
        .position(|l| l.contains("starting h1"))
        .unwrap_or_else(|| panic!("the second started: {said:#?}"));
    let connected = at(&said, second, "[DNS] connected filter chain below");
    assert!(
        said[connected + 1].ends_with("] destroy async"),
        "{said:#?}"
    );
    assert_eq!(
        said[connected + 2],
        format!("[MULTI] [CONNECTING] Curl_multi_will_close fd={fd}"),
        "{said:#?}"
    );
}

/// The race of a QUIC first attempt and the TCP second that leads it, the
/// trace's components on as `config` says: what the transfer traced and
/// the number of the library's socket.
fn lost_to_the_second(config: &[u8], by_events: bool) -> (Vec<String>, u64) {
    let clock = ManualClock::new().unwrap();
    let at_origin = SocketAddr::from(([127, 0, 0, 1], 443));
    let quic_talk = Conversation::replies(&[], false).per_send();
    let response = fake::records(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
    let tcp_talk = Conversation::replies(&[fake::WELCOME, &response], false).per_send();
    let net = FakeNet::new(clock.clone())
        .with_peer(at_origin, Peer::AcceptsAfter(Duration::from_millis(50)))
        .with_datagram_peer(at_origin, Peer::Silent)
        .with_conversation(at_origin, quic_talk)
        .with_conversation(at_origin, tcp_talk.clone());
    // The library's socket, numbered past the transfer's own.
    let to = SocketAddr::from(([127, 0, 0, 1], 53));
    let own = Box::leak(Box::new(
        FakeNet::new(clock.clone()).with_peer(to, Peer::Silent),
    ));
    let mut open = || {
        own.open(
            &crate::conn::io::Remote::Inet(to),
            crate::conn::io::SocketKind::Datagram,
        )
        .unwrap()
    };
    for _ in 0..8 {
        std::mem::forget(open());
    }
    let socket = open();
    let fd = socket_number(socket.key());
    let alive = Arc::new(AtomicBool::new(false));
    let lib: &'static Library = Box::leak(Box::new(Library {
        aaaa: Arc::default(),
        alive: alive.clone(),
        runs: Arc::default(),
        made: Arc::default(),
        sockets: Lock::new(vec![socket]),
    }));
    let script = crate::http3::fake::Script::new();
    script
        .lock()
        .unwrap()
        .out
        .extend([vec![1; 1200], vec![2; 1200], vec![]]);
    let h3: &'static crate::http3::fake::FakeHttp3 =
        Box::leak(Box::new(crate::http3::fake::FakeHttp3::new(script)));
    let tls: &'static fake::FakeTls = Box::leak(Box::new(fake::FakeTls::agreeing().unwrap()));
    let mut m: Multi = Multi::new(Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    })
    .unwrap();
    let mut easy = Easy::new();
    easy.set_libraries(
        crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
            tls: Some(crate::libraries::Library::Static(tls)),
            h3: Some(h3),
            dns: Some(lib as &'static dyn crate::conn::io::DnsLibrary),
            ..crate::libraries::Libraries::NONE
        })
        .unwrap(),
    );
    let lines = Lines::default();
    let o = easy.options_mut();
    o.set_url(Some(ORIGIN.as_bytes())).unwrap();
    o.http.version = crate::options::HttpVersion::Http3;
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    let c = crate::components::Components::new().unwrap();
    c.configure(config);
    easy.set_components(Some(c));
    let mut ended = None;
    if by_events {
        let id = m.add(Box::new(easy), (), &mut Watching).unwrap();
        ended = Some(crate::multi::drive_by_events(&mut m, id).unwrap());
    } else {
        m.add(Box::new(easy), (), &mut NoEvents).unwrap();
        for _ in 0..3000 {
            m.perform(&mut NoEvents).unwrap();
            if let Some(msg) = m.info_read() {
                ended = Some(msg.result);
                break;
            }
            clock.advance(Duration::from_millis(1));
        }
    }
    let said = lines.0.lock().unwrap().clone();
    assert_eq!(ended, Some(Ok(())), "{said:#?}");
    assert!(!alive.load(Ordering::Relaxed), "let go of");
    (said, fd)
}

/// An application that runs the multi by its events.
struct Watching;

impl crate::multi::MultiEvents<crate::multi::NoHost> for Watching {
    fn wants_timer(&self) -> bool {
        true
    }

    fn wants_sockets(&self) -> bool {
        true
    }
}

/// Once the TCP second races the QUIC first, the pollset trace names the
/// first's socket as its UDP filter's and counts the resolve's socket the
/// first holds among the first attempt's, then the second's own on top,
/// as C's happy eyeballs filters say them (`cf_ip_happy_adjust_pollset`).
#[test]
fn the_race_s_pollset_counts_the_first_s_resolve_among_its_sockets() {
    let (said, _) = lost_to_the_second(b"dns,multi,https-connect,udp,happy-eyeballs", true);
    let second = said
        .iter()
        .position(|l| l.contains("starting h1"))
        .unwrap_or_else(|| panic!("the second started: {said:#?}"));
    let udp = at(
        &said,
        second,
        "[UDP] adjust_pollset, !active, POLLIN fd=1000",
    );
    assert_eq!(
        said[udp + 1..udp + 4],
        [
            "[HAPPY-EYEBALLS] adjust_pollset -> 0, 2 socks",
            "[HAPPY-EYEBALLS] adjust_pollset -> 0, 3 socks",
            "[HTTPS-CONNECT] adjust_pollset -> 0, 3 socks",
        ],
        "{said:#?}"
    );
}

/// A socket's number as the trace prints it: a `RawSocket` is an `i32` on
/// Unix and already a `u64` on Windows, where the conversion is a no-op.
#[allow(clippy::useless_conversion)]
fn socket_number(key: crate::conn::io::SocketKey) -> u64 {
    u64::try_from(key.get()).expect("a socket's number is not negative")
}
