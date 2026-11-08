//! DoH's probes as transfers of the multi's: what they send, what their end
//! does to the master, and that none outlives what it was started for.

use std::cell::Cell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use super::*;
use crate::conn::io::{Conversation, FakeNet, Peer};
use crate::time::ManualClock;

const SERVER: ([u8; 4], u16) = ([127, 0, 0, 1], 53);
const URL: &[u8] = b"http://127.0.0.1:53/dns";

fn at(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn multi_over(net: FakeNet, clock: &ManualClock) -> Multi {
    Multi::new(Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    })
    .unwrap()
}

/// A handle for `url` with its names resolved at `URL`.
fn asking(url: &str) -> Box<Easy> {
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(url.as_bytes())).unwrap();
    o.doh.make_mut().unwrap().url = Some(URL.to_vec());
    Box::new(easy)
}

/// A response carrying the DNS message `body`.
fn http(body: &[u8]) -> Vec<u8> {
    let mut reply =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    reply.extend_from_slice(body);
    reply
}

/// The answer naming `addr` for a question of A.
fn a_answer() -> Vec<u8> {
    let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    m.extend_from_slice(b"\x03foo\x04test\x00\x00\x01\x00\x01");
    m.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x37\x00\x04\x7f\x00\x00\x01");
    m
}

/// An answer without records, for any question.
fn no_records() -> Vec<u8> {
    let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(b"\x03foo\x04test\x00\x00\x1c\x00\x01");
    m
}

/// An answer with `rcode` and nothing else.
fn rcode(rcode: u8) -> Vec<u8> {
    vec![0, 0, 0x81, 0x80 | rcode, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// How many passes a test waits for something that needs no time to pass.
fn run(m: &mut Multi, clock: &ManualClock) {
    for _ in 0..40 {
        m.perform(&mut NoEvents).unwrap();
        clock.advance(Duration::from_millis(1));
    }
}

fn message(m: &mut Multi) -> Option<Result<(), ErrorKind>> {
    m.info_read().map(|msg| msg.result)
}

/// A name answered: two probes post C's bytes, AAAA's first, without a
/// `User-Agent`, leave no message, and go as the master gets on with its
/// transfer to the address found.
#[test]
fn a_name_resolves_over_doh() {
    let clock = ManualClock::new().unwrap();
    let aaaa = Conversation::new(&http(&no_records()), false);
    let a = Conversation::new(&http(&a_answer()), false);
    let target = Conversation::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", false);
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_peer(at(80), Peer::Accepts)
        .with_conversation(SERVER.into(), aaaa.clone())
        .with_conversation(SERVER.into(), a.clone())
        .with_conversation(at(80), target.clone());
    let mut m = multi_over(net, &clock);
    let id = m
        .add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    // As C's handles: the master's two sub transfers count.
    assert_eq!(m.census().counts.current, 3);
    assert_eq!(
        m.next_transfer(Some(id)),
        None,
        "the application sees its own"
    );
    run(&mut m, &clock);
    assert_eq!(message(&mut m), Some(Ok(())));
    assert_eq!(message(&mut m), None, "a probe leaves no message");
    assert_eq!(m.census().counts.current, 1, "the probes went");
    let head = "POST /dns HTTP/1.1\r\nHost: 127.0.0.1:53\r\nAccept: */*\r\n\
                Content-Type: application/dns-message\r\nContent-Length: 26\r\n\r\n";
    let query = |kind: u8| {
        let mut q = head.as_bytes().to_vec();
        q.extend_from_slice(b"\0\0\x01\0\0\x01\0\0\0\0\0\0\x03foo\x04test\0\0");
        q.extend_from_slice(&[kind, 0, 1]);
        q
    };
    assert_eq!(aaaa.received(), query(28));
    assert_eq!(a.received(), query(1));
    assert!(
        target
            .received()
            .starts_with(b"GET /x HTTP/1.1\r\nHost: foo.test\r\n"),
        "{:?}",
        String::from_utf8_lossy(&target.received())
    );
    let removed = m.remove(id, &mut NoEvents).unwrap();
    assert_eq!(removed.status, Ok(()));
    assert_eq!(m.census().counts.current, 0);
}

/// Its master removed while they run, the probes go with it, and what was
/// its row names another transfer: none reaches that one.
#[test]
fn a_masters_removal_takes_its_probes() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Silent)
        .with_name("other.test", &[[127, 0, 0, 1].into()]);
    let mut m = multi_over(net, &clock);
    let id = m
        .add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.census().counts.current, 3);
    assert!(m.remove(id, &mut NoEvents).is_some());
    assert_eq!(m.census().counts.current, 0, "no probe remains");
    assert_eq!(m.census().counts.running, 0);
    let next = m.add(Box::new(Easy::new()), (), &mut NoEvents).unwrap();
    assert_eq!(
        next.index(),
        id.index() + 3,
        "rows go on from the last used"
    );
    assert_eq!(m.census().counts.current, 1);
}

/// A probe is the multi's: the application cannot take it out.
#[test]
fn a_probe_is_not_the_applications_to_remove() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone()).with_peer(SERVER.into(), Peer::Silent);
    let mut m = multi_over(net, &clock);
    let id = m
        .add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    let probe = m.slots.next_after(Some(id)).expect("a probe");
    assert!(m.remove(probe, &mut NoEvents).is_none());
    assert_eq!(m.census().counts.current, 3);
    assert_eq!(m.owners().count(), 1, "`curl_multi_get_handles` skips them");
}

/// The master timing out ends the resolve: its probes go as it fails, not
/// as their own time runs out.
#[test]
fn a_master_timing_out_takes_its_probes() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone()).with_peer(SERVER.into(), Peer::Silent);
    let mut m = multi_over(net, &clock);
    let mut easy = asking("http://foo.test/x");
    easy.options_mut().limits.total = crate::time::TimeLimit::from_millis(50);
    m.add(easy, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.census().counts.current, 3);
    clock.advance(Duration::from_millis(60));
    run(&mut m, &clock);
    assert!(matches!(message(&mut m), Some(Err(_))));
    assert_eq!(m.census().counts.current, 1, "no probe remains");
}

/// Dropped with its probes running, the multi is simply gone.
#[test]
fn a_multi_goes_with_its_probes_running() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone()).with_peer(SERVER.into(), Peer::Silent);
    let mut m = multi_over(net, &clock);
    m.add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    drop(m);
}

/// A name that does not exist is kept as such, if every query said so;
/// the next asks nobody.
#[test]
fn no_such_name_is_kept() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_conversation(SERVER.into(), Conversation::new(&http(&rcode(3)), false))
        .with_conversation(SERVER.into(), Conversation::new(&http(&rcode(3)), false));
    let mut m = multi_over(net, &clock);
    let id = m
        .add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    run(&mut m, &clock);
    assert_eq!(message(&mut m), Some(Err(ErrorKind::CouldntResolveHost)));
    m.remove(id, &mut NoEvents).unwrap();
    m.add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        m.census().counts.current,
        1,
        "the cache answered: no probes"
    );
    assert_eq!(message(&mut m), Some(Err(ErrorKind::CouldntResolveHost)));
}

/// A server's failure says nothing of the name, nor does an answer that
/// cannot be read: nothing is kept, and the next transfer asks again.
#[test]
fn a_failure_is_not_kept_as_no_such_name() {
    let clock = ManualClock::new().unwrap();
    for (one, other) in [
        (http(&rcode(3)), http(&rcode(2))),
        (http(&rcode(3)), http(b"\x00\x01garbage")),
        (
            http(&rcode(3)),
            b"HTTP/1.1 500 no\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        // A failed status says nothing, whatever its body says.
        (http(&rcode(3)), {
            let mut failed = b"HTTP/1.1 500 no\r\nContent-Length: 12\r\n\r\n".to_vec();
            failed.extend_from_slice(&rcode(3));
            failed
        }),
    ] {
        let net = FakeNet::new(clock.clone())
            .with_peer(SERVER.into(), Peer::Accepts)
            .with_conversation(SERVER.into(), Conversation::new(&one, false))
            .with_conversation(SERVER.into(), Conversation::new(&other, false));
        let mut m = multi_over(net, &clock);
        let id = m
            .add(asking("http://foo.test/x"), (), &mut NoEvents)
            .unwrap();
        run(&mut m, &clock);
        assert_eq!(message(&mut m), Some(Err(ErrorKind::CouldntResolveHost)));
        m.remove(id, &mut NoEvents).unwrap();
        m.add(asking("http://foo.test/x"), (), &mut NoEvents)
            .unwrap();
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(m.census().counts.current, 3, "asked again");
    }
}

/// An answer of more than C keeps is a failure of that probe, not of
/// memory.
#[test]
fn an_answer_too_long_fails_its_probe() {
    let clock = ManualClock::new().unwrap();
    let huge = http(&vec![0; super::doh::MAX_RESPONSE + 1]);
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_conversation(SERVER.into(), Conversation::new(&huge, false))
        .with_conversation(SERVER.into(), Conversation::new(&huge, false));
    let mut m = multi_over(net, &clock);
    m.add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    run(&mut m, &clock);
    assert_eq!(message(&mut m), Some(Err(ErrorKind::CouldntResolveHost)));
}

/// An address or `localhost` needs no server.
#[test]
fn the_shortcuts_go_before_doh() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone()).with_peer(at(80), Peer::Silent);
    let mut m = multi_over(net, &clock);
    m.add(asking("http://127.0.0.1/x"), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.census().counts.current, 1);
}

/// A name that cannot go in a query fails as C fails it.
#[test]
fn a_name_for_no_query_fails_as_out_of_memory() {
    let clock = ManualClock::new().unwrap();
    let mut m = multi_over(FakeNet::new(clock.clone()), &clock);
    let label = "a".repeat(64);
    m.add(asking(&format!("http://{label}.test/x")), (), &mut NoEvents)
        .unwrap();
    run(&mut m, &clock);
    assert_eq!(message(&mut m), Some(Err(ErrorKind::OutOfMemory)));
}

/// What a probe has of its master's: only C's list.
#[test]
fn a_probe_inherits_only_cs_list() {
    let mut master = Easy::new();
    let o = master.options_mut();
    o.set_url(Some(b"https://secret.test/")).unwrap();
    o.doh.make_mut().unwrap().url = Some(b"https://dns.test/".to_vec());
    o.doh.make_mut().unwrap().verify_peer = false;
    o.doh.make_mut().unwrap().verify_host = false;
    o.doh.make_mut().unwrap().verify_status = true;
    o.proxy.make_mut().unwrap().url = Some(b"http://proxy.test/".to_vec());
    o.http.user_agent = Some(b"agent".to_vec());
    let t = o.tls.options.make_mut().unwrap();
    t.ca_blob = crate::options::CaSetting::Given(b"blob".to_vec());
    t.crl_file = Some(b"crl".to_vec());
    t.ssl_options =
        crate::options::SslOptions::AUTO_CLIENT_CERT | crate::options::SslOptions::NO_REVOKE;
    t.cert = Some(b"client".to_vec());
    let body = crate::handler::Handler::write(Dropped).unwrap();
    let probe = master
        .doh_probe(b"query", body, Some(Duration::from_millis(1234)))
        .unwrap();
    let p = probe.options();
    assert_eq!(p.url(), Some(&b"https://dns.test/"[..]));
    assert_eq!(p.default_protocol(), Some(&b"https"[..]));
    assert!(p.proxy.url.is_none(), "not the proxy");
    assert!(p.http.user_agent.is_none(), "not the agent");
    assert_eq!(p.http.version, crate::options::HttpVersion::Http2Tls);
    assert!(p.http.pipewait);
    assert_eq!(p.limits.total, crate::time::TimeLimit::from_millis(1234));
    assert!(!p.tls.verify_peer);
    assert!(!p.tls.verify_host);
    assert!(p.tls.options.verify_status);
    assert_eq!(
        p.tls.options.ca_blob,
        crate::options::CaSetting::Given(b"blob".to_vec())
    );
    assert_eq!(p.tls.options.crl_file.as_deref(), Some(&b"crl"[..]));
    assert!(p.tls.options.cert.is_none(), "not the client's certificate");
    assert_eq!(
        p.tls.options.ssl_options,
        crate::options::SslOptions::NO_REVOKE,
        "not to pick a client certificate on its own"
    );
    assert_eq!(probe.doing(), Some(crate::components::Component::Doh));
    // Over clear text, TLS's settings and HTTP/2's are not asked for.
    let o = master.options_mut();
    o.doh.make_mut().unwrap().url = Some(b"HTTP://dns.test/".to_vec());
    let body = crate::handler::Handler::write(Dropped).unwrap();
    let probe = master.doh_probe(b"query", body, None).unwrap();
    let p = probe.options();
    assert_eq!(p.http.version, crate::options::HttpVersion::Any);
    assert!(p.tls.verify_peer, "its own default");
    assert!(p.limits.total.is_none());
}

struct Dropped;

impl crate::handler::WriteHandler for Dropped {
    fn write(&self, _: &mut crate::multi::TransferCx<'_>, _: &[u8]) -> crate::handler::Write {
        crate::handler::Write::Accepted
    }
}

/// A handle the library makes for a transfer's own, a DoH probe or a
/// pushed stream, joins the transfer's share as `CURLOPT_SHARE` joins it
/// (`Curl_share_easy_link`, from `doh_probe_run` and `h2_duphandle`): it
/// takes up the share's jar, off, as C leaves its `cookie_engine` unset,
/// and the share's HSTS cache, on.
#[test]
fn a_handle_made_for_a_transfer_takes_up_its_share_s_cookies_and_hsts() {
    use crate::share::{Kind, Share};
    let share = Share::new().unwrap();
    share.keep(Kind::Cookies).unwrap();
    share.keep(Kind::Hsts).unwrap();
    let mut master = Easy::new();
    master.set_share(Some(share.clone())).unwrap();
    master
        .add_cookie(b"example.com\tFALSE\t/\tFALSE\t0\tshared\t1", |_| {})
        .unwrap();
    master.options_mut().doh.make_mut().unwrap().url = Some(b"https://dns.test/".to_vec());
    let body = crate::handler::Handler::write(Dropped).unwrap();
    let probe = master.doh_probe(b"query", body, None).unwrap();
    for mut made in [master.pushed(), probe] {
        assert!(!made.jar.is_on(), "its jar off");
        assert!(made.hsts_enabled(), "the share's HSTS cache");
        assert_eq!(made.cookie_list().unwrap().len(), 1, "the share's jar");
        // Turned on, it is the share's jar that is on.
        made.enable_cookies().unwrap();
        assert!(made.jar.is_on());
        assert_eq!(made.cookie_list().unwrap().len(), 1, "still the share's");
    }
}

/// A host that names its transfers: every probe has a value of its own,
/// made once and given back once, whichever way the probe goes.
#[test]
fn a_hosts_value_for_a_probe_comes_back() {
    struct Named;
    impl Host for Named {
        type Transfer = u32;
        type Socket = ();
    }
    #[derive(Default)]
    struct Ev {
        made: Rc<Cell<u32>>,
        gone: Rc<Cell<u32>>,
    }
    impl MultiEvents<Named> for Ev {
        fn internal(
            &mut self,
            cx: &mut EventCx<'_, Named>,
            master: TransferId,
            easy: Box<Easy>,
        ) -> Result<(Box<Easy>, Option<u32>), OutOfMemory> {
            assert_eq!(cx.owner(master), Some(&7), "named by its master's");
            self.made.set(self.made.get() + 1);
            Ok((easy, Some(100 + self.made.get())))
        }
        fn internal_gone(&mut self, _: Box<Easy>, host: u32) {
            assert!(host > 100);
            self.gone.set(self.gone.get() + 1);
        }
    }
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone()).with_peer(SERVER.into(), Peer::Silent);
    let mut m: Multi<Named> = Multi::new(Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    })
    .unwrap();
    let mut ev = Ev::default();
    let id = m.add(asking("http://foo.test/x"), 7, &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    assert_eq!(ev.made.get(), 2);
    let probe = m.slots.next_after(Some(id)).expect("a probe");
    assert_eq!(m.owner(probe), Some(&101), "callbacks name it by its own");
    assert_eq!(m.owners().collect::<Vec<_>>(), [&7]);
    let removed = m.remove(id, &mut ev).unwrap();
    assert_eq!(removed.owner, 7);
    assert_eq!(ev.gone.get(), 2);
}

/// Once its lookup goes, what a probe still has running goes nowhere, and
/// says it is to be taken out. Whatever row its master's was, the state it
/// holds is that lookup's alone.
#[test]
fn a_stale_probe_reaches_nothing() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone()).with_peer(SERVER.into(), Peer::Silent);
    let mut m = multi_over(net, &clock);
    m.add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    let (lookup, probe) = super::doh::orphan_for_test();
    assert!(!probe.orphaned());
    drop(lookup);
    assert!(probe.orphaned(), "said as the lookup goes, on any path");
    assert!(!probe.accepts(b"answer"), "its writes fail");
    m.perform(&mut NoEvents).unwrap();
}

/// Keeps the trace's text lines.
#[derive(Clone, Default)]
struct Lines(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl crate::handler::DebugHandler for Lines {
    fn debug(
        &self,
        _: &mut crate::multi::TransferCx<'_>,
        kind: crate::handler::DebugKind,
        data: &[u8],
    ) {
        if kind == crate::handler::DebugKind::Text {
            let line = String::from_utf8_lossy(data).into_owned();
            self.0.lock().unwrap().push(line);
        }
    }
}

/// The trace of `url`'s transfer, its handle's components on as `config`
/// says, over a server that says the name does not exist.
fn traced(url: &str, config: &[u8]) -> Vec<String> {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_conversation(SERVER.into(), Conversation::new(&http(&rcode(3)), false))
        .with_conversation(SERVER.into(), Conversation::new(&http(&rcode(3)), false));
    traced_over(net, &clock, url, config)
}

/// The same over `net`.
fn traced_over(net: FakeNet, clock: &ManualClock, url: &str, config: &[u8]) -> Vec<String> {
    let mut m = multi_over(net, clock);
    let mut easy = asking(url);
    let lines = Lines::default();
    let o = easy.options_mut();
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    let components = crate::components::Components::new().unwrap();
    components.configure(config);
    easy.set_components(Some(components));
    m.add(easy, (), &mut NoEvents).unwrap();
    run(&mut m, clock);
    assert!(message(&mut m).expect("it ended").is_err());
    lines.0.lock().unwrap().clone()
}

/// A probe whose own transfer fails says the transfer's error, not a
/// status it never had (`doh_probe_done`'s `[DoH] [%s] error: %s`).
#[test]
fn a_probe_s_failed_transfer_says_its_error() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone()).with_peer(SERVER.into(), Peer::Refuses);
    let lines = traced_over(net, &clock, "http://nx.test/", b"doh");
    let has = |want: &str| lines.iter().filter(|l| l.trim_end() == want).count();
    for name in ["A", "AAAA"] {
        assert_eq!(
            has(&format!(
                "[DoH] [DoH] [{name}] error: Could not connect to server"
            )),
            1,
            "{lines:?}"
        );
    }
    assert!(
        !lines.iter().any(|l| l.contains("HTTP status")),
        "{lines:?}"
    );
}

/// A probe's lines are said only with DoH's trace on, and each begins with
/// `[DoH]`, its own trace and C's double one included; the failure is said
/// once for the resolve, as C's one `failf` says it, then for the name.
#[test]
fn a_probes_lines_say_whose_they_are() {
    let quiet = traced("http://nx.test/", b"");
    assert!(!quiet.iter().any(|l| l.contains("DoH")), "{quiet:?}");
    let lines = traced("http://nx.test/", b"doh");
    let has = |want: &str| lines.iter().filter(|l| l.trim_end() == want).count();
    assert_eq!(
        has("[DoH] [DoH] [AAAA] error decoding response: No such name"),
        1,
        "{lines:?}"
    );
    assert_eq!(
        has("[DoH] [DoH] [A] error decoding response: No such name"),
        1,
        "{lines:?}"
    );
    assert_eq!(has("Could not resolve host: nx.test"), 1, "{lines:?}");
    assert_eq!(has("Could not resolve: nx.test:80"), 1, "{lines:?}");
    let too_long = format!("http://{}.test/", "a".repeat(64));
    let name = &too_long[7..too_long.len() - 1];
    let lines = traced(&too_long, b"doh");
    let has = |want: &str| lines.iter().filter(|l| l.trim_end() == want).count();
    assert_eq!(has("Failed to encode DoH packet [1]"), 1, "{lines:?}");
    assert_eq!(
        has(&format!("Error 27 resolving {name}:80")),
        1,
        "{lines:?}"
    );
    assert_eq!(has(&format!("Could not resolve: {name}")), 1, "{lines:?}");
}

/// With A's answer in and AAAA's not, the transfer connects once the wait
/// for AAAA is over, as C does, and the rest does not matter once it has.
#[test]
fn what_came_is_connected_to_after_a_wait_for_aaaa() {
    let clock = ManualClock::new().unwrap();
    let target = Conversation::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", false);
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_peer(at(80), Peer::Accepts)
        .with_conversation(SERVER.into(), Conversation::replies(&[], false))
        .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false))
        .with_conversation(at(80), target.clone());
    let mut m = multi_over(net, &clock);
    m.add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    // Less than the wait.
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
        clock.advance(Duration::from_millis(1));
    }
    assert!(target.received().is_empty(), "AAAA is waited for");
    run(&mut m, &clock);
    assert_eq!(message(&mut m), Some(Ok(())));
    assert!(target.received().starts_with(b"GET /x"));
    assert_eq!(m.census().counts.current, 1, "the probes went with it");
}

/// A destination a SOCKS proxy is told as an address is asked of the DoH
/// server, while the transfer waits: nothing of it goes to the system's
/// resolver, and the handshake carries the address found.
#[test]
fn a_socks_destination_goes_over_doh() {
    let clock = ManualClock::new().unwrap();
    let proxy = Conversation::new(&[0, 90, 0, 0, 0, 0, 0, 0], false);
    let net = FakeNet::new(clock.clone())
        .with_peer(at(1080), Peer::Accepts)
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_conversation(at(1080), proxy.clone())
        // SOCKS4 has room for IPv4 alone: one query.
        .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false));
    let mut m = multi_over(net, &clock);
    let mut easy = asking("http://foo.test/x");
    easy.options_mut().proxy.make_mut().unwrap().url = Some(b"socks4://127.0.0.1:1080".to_vec());
    m.add(easy, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert!(proxy.received().is_empty(), "the name is awaited");
    run(&mut m, &clock);
    let sent = proxy.received();
    assert_eq!(&sent[..8], &[4, 1, 0, 80, 127, 0, 0, 1], "{sent:?}");
}

/// An answer past C's limit that would otherwise read well fails its
/// probe: the name does not resolve, for all the addresses it holds.
#[test]
fn an_answer_too_long_is_not_read() {
    let clock = ManualClock::new().unwrap();
    let mut long = vec![0, 0, 0x81, 0x80, 0, 1];
    let records: u16 = 200;
    long.extend_from_slice(&records.to_be_bytes());
    long.extend_from_slice(&[0, 0, 0, 0]);
    long.extend_from_slice(b"\x03foo\x04test\x00\x00\x01\x00\x01");
    for _ in 0..records {
        long.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x37\x00\x04\x7f\x00\x00\x01");
    }
    assert!(long.len() > super::doh::MAX_RESPONSE);
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_conversation(
            SERVER.into(),
            Conversation::new(&http(&no_records()), false),
        )
        .with_conversation(SERVER.into(), Conversation::new(&http(&long), false));
    let mut m = multi_over(net, &clock);
    m.add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    run(&mut m, &clock);
    assert_eq!(message(&mut m), Some(Err(ErrorKind::CouldntResolveHost)));
}

/// Once the answer is had, the probes go, though the master goes on.
#[test]
fn the_probes_go_as_the_answer_comes() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_peer(at(80), Peer::Silent)
        .with_conversation(
            SERVER.into(),
            Conversation::new(&http(&no_records()), false),
        )
        .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false));
    let mut m = multi_over(net, &clock);
    m.add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    run(&mut m, &clock);
    assert_eq!(message(&mut m), None, "still connecting");
    assert_eq!(m.census().counts.current, 1);
}

/// All that came refused, with AAAA still to come: the setup waits for it
/// rather than fail or run out of addresses.
#[test]
fn a_race_out_of_addresses_waits_for_the_rest() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_peer(at(80), Peer::Refuses)
        .with_conversation(SERVER.into(), Conversation::replies(&[], false))
        .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false));
    let mut m = multi_over(net, &clock);
    m.add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    run(&mut m, &clock);
    assert_eq!(message(&mut m), None);
    assert_eq!(m.census().counts.current, 3);
}

/// An HTTPS record for an `https` origin: asked for first, under the name
/// with its port, and its versions tried in the order it gives.
#[test]
fn an_origins_record_is_asked_for_and_its_versions_chosen() {
    let clock = ManualClock::new().unwrap();
    // `h2` alone, as the record's data has it, in an answer for the question.
    let mut m_ = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    m_.extend_from_slice(b"\x05_8443\x06_https\x03foo\x04test\x00\x00\x41\x00\x01");
    m_.extend_from_slice(b"\xc0\x0c\x00\x41\x00\x01\x00\x00\x00\x37\x00\x0a");
    m_.extend_from_slice(b"\x00\x01\x00\x00\x01\x00\x03\x02h2");
    let https = Conversation::new(&http(&m_), false);
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_peer(at(8443), Peer::Silent)
        .with_conversation(SERVER.into(), https.clone())
        .with_conversation(
            SERVER.into(),
            Conversation::new(&http(&no_records()), false),
        )
        .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false));
    let mut m = multi_over(net, &clock);
    let mut easy = asking("https://foo.test:8443/x");
    let tls = Box::leak(Box::new(crate::tls::fake::FakeTls::new().unwrap()));
    easy.set_libraries(
        crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
            tls: Some(crate::libraries::Library::Static(tls)),
            ..crate::libraries::Libraries::NONE
        })
        .unwrap(),
    );
    let lines = Lines::default();
    let o = easy.options_mut();
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    m.add(easy, (), &mut NoEvents).unwrap();
    run(&mut m, &clock);
    let got = https.received();
    let wire = b"\x05_8443\x06_https\x03foo\x04test\x00\x00\x41\x00\x01";
    assert!(
        got.windows(wire.len()).any(|w| w == wire),
        "{:?}",
        String::from_utf8_lossy(&got)
    );
    let said = lines.0.lock().unwrap().clone();
    assert!(
        said.iter()
            .any(|l| l.trim_end() == "HTTPS-RR foo.test:8443: 1 . alpn=h2"),
        "{said:?}"
    );
}

/// A record answered before the addresses chooses the first attempt, as
/// C's `connect, init` takes what the DNS filter has: its probe ends first.
#[test]
fn a_record_answered_first_chooses_the_first_attempt() {
    let clock = ManualClock::new().unwrap();
    let mut answer = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    answer.extend_from_slice(b"\x03foo\x04test\x00\x00\x41\x00\x01");
    answer.extend_from_slice(b"\xc0\x0c\x00\x41\x00\x01\x00\x00\x00\x37\x00\x10");
    answer.extend_from_slice(b"\x00\x01\x00\x00\x01\x00\x09\x08http/1.1");
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_peer(at(443), Peer::Silent)
        .with_conversation(SERVER.into(), Conversation::new(&http(&answer), false))
        .with_conversation(
            SERVER.into(),
            Conversation::new(&http(&no_records()), false),
        )
        .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false));
    let mut m = multi_over(net, &clock);
    let mut easy = asking("https://foo.test/x");
    let tls = Box::leak(Box::new(crate::tls::fake::FakeTls::new().unwrap()));
    easy.set_libraries(
        crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
            tls: Some(crate::libraries::Library::Static(tls)),
            ..crate::libraries::Libraries::NONE
        })
        .unwrap(),
    );
    let lines = Lines::default();
    let o = easy.options_mut();
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    let c = crate::components::Components::new().unwrap();
    c.configure(b"https-connect");
    easy.set_components(Some(c));
    m.add(easy, (), &mut NoEvents).unwrap();
    run(&mut m, &clock);
    let said = lines.0.lock().unwrap().clone();
    let at = |want: &str| said.iter().position(|l| l.trim_end() == want);
    let init = at("[HTTPS-CONNECT] connect, init").expect("init");
    assert_eq!(
        said.get(init + 1..init + 3).map(|l| l.join("")),
        Some("[HTTPS-CONNECT] HTTPS-RR available\n[HTTPS-CONNECT] 1st attempt uses h1 from HTTPS-RR\n".to_owned()),
        "{said:?}"
    );
}

/// What an HTTPS query's end leaves in the cache: a server's no such name
/// and its answer without a record are kept, anything else says nothing
/// of the name. A server's failure ends the probe all the same.
#[test]
fn only_an_answer_about_the_name_is_kept_of_its_record() {
    let line = |rcode: u8, what: &[u8], ancount: u8| {
        let clock = ManualClock::new().unwrap();
        let mut reply = vec![0, 0, 0x81, 0x80 | rcode, 0, 1, 0, ancount, 0, 0, 0, 0];
        reply.extend_from_slice(b"\x03foo\x04test\x00\x00\x41\x00\x01");
        reply.extend_from_slice(what);
        let net = FakeNet::new(clock.clone())
            .with_peer(SERVER.into(), Peer::Accepts)
            .with_peer(at(443), Peer::Silent)
            .with_conversation(SERVER.into(), Conversation::new(&http(&reply), false))
            .with_conversation(
                SERVER.into(),
                Conversation::new(&http(&no_records()), false),
            )
            .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false));
        let mut m = multi_over(net, &clock);
        let mut easy = asking("https://foo.test/x");
        let tls = Box::leak(Box::new(crate::tls::fake::FakeTls::new().unwrap()));
        easy.set_libraries(
            crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
                tls: Some(crate::libraries::Library::Static(tls)),
                ..crate::libraries::Libraries::NONE
            })
            .unwrap(),
        );
        let lines = Lines::default();
        let o = easy.options_mut();
        o.output.verbose = true;
        o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
        let c = crate::components::Components::new().unwrap();
        c.configure(b"dns");
        easy.set_components(Some(c));
        m.add(easy, (), &mut NoEvents).unwrap();
        run(&mut m, &clock);
        let said = lines.0.lock().unwrap().clone();
        (
            said.iter()
                .any(|l| l.contains("cache negative") && l.contains("HTTPS")),
            said.iter()
                .any(|l| l.contains("[HTTPS] no record available")),
            said.iter()
                .filter(|l| l.contains("[DoH] probe done"))
                .count(),
        )
    };
    let (negative, no_record, ended) = line(3, b"", 0);
    assert_eq!((negative, no_record), (true, false), "no such name");
    let (negative, no_record, _) = line(0, b"", 0);
    assert_eq!((negative, no_record), (false, true), "no record");
    assert_eq!(line(2, b"", 0), (false, false, ended), "a server's failure");
    let a = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x37\x00\x04\x7f\x00\x00\x01";
    let (negative, no_record, _) = line(0, a, 1);
    assert_eq!(
        (negative, no_record),
        (false, false),
        "another type of record"
    );
}

/// Exactly when the wait for AAAA ends what came is connected to.
#[test]
fn the_wait_for_aaaa_ends_at_its_very_end() {
    let clock = ManualClock::new().unwrap();
    let target = Conversation::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", false);
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_peer(at(80), Peer::Accepts)
        .with_conversation(SERVER.into(), Conversation::replies(&[], false))
        .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false))
        .with_conversation(at(80), target.clone());
    let mut m = multi_over(net, &clock);
    m.add(asking("http://foo.test/x"), (), &mut NoEvents)
        .unwrap();
    for _ in 0..6 {
        m.perform(&mut NoEvents).unwrap();
    }
    clock.advance(Duration::from_millis(25));
    for _ in 0..6 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(
        target.received().starts_with(b"GET /x"),
        "connected at 25 ms"
    );
}

/// The lines of the names' and the record's resolves over DoH, as C's.
#[test]
fn the_resolves_lines_are_c_s() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_peer(at(443), Peer::Silent)
        .with_conversation(SERVER.into(), Conversation::new(&http(&rcode(3)), false))
        .with_conversation(
            SERVER.into(),
            Conversation::new(&http(&no_records()), false),
        )
        .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false));
    let mut m = multi_over(net, &clock);
    let mut easy = asking("https://foo.test/x");
    let tls = Box::leak(Box::new(crate::tls::fake::FakeTls::new().unwrap()));
    easy.set_libraries(
        crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
            tls: Some(crate::libraries::Library::Static(tls)),
            ..crate::libraries::Libraries::NONE
        })
        .unwrap(),
    );
    let lines = Lines::default();
    let o = easy.options_mut();
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    let c = crate::components::Components::new().unwrap();
    c.configure(b"dns");
    easy.set_components(Some(c));
    m.add(easy, (), &mut NoEvents).unwrap();
    run(&mut m, &clock);
    let said = lines.0.lock().unwrap().clone();
    let has = |want: &str| said.iter().filter(|l| l.trim_end() == want).count();
    for want in [
        "[DNS] cache lookup foo.test:443 queries=HTTPS -> 0 not found",
        "[DNS] cache lookup foo.test:443 queries=A+AAAA -> 0 not found",
        "[DNS] cached entry for foo.test:443 queries=A+AAAA",
        "[DNS] cache negative name resolve for foo.test:443 type=HTTPS",
        "[DNS] [A+AAAA] resolve complete for foo.test:443",
    ] {
        assert!(has(want) >= 1, "{want}: {said:?}");
    }
    assert_eq!(has("[DNS] [DoH] probe done"), 4, "{said:?}");
    // Its probes started, each filter's resolve is looked at again at
    // once, as `cf_dns_connect` takes the answer right after its start.
    for (queries, ongoing) in [("HTTPS", 1), ("A+AAAA", 2)] {
        let started = format!("[DNS] [{queries}] hostip_resolv started -> 81");
        let started = said
            .iter()
            .position(|l| l.trim_end() == started)
            .expect("started");
        let next: Vec<&str> = said[started + 1..started + 3]
            .iter()
            .map(|l| l.trim_end())
            .collect();
        assert_eq!(
            next,
            [
                format!("[DNS] cache lookup foo.test:443 queries={queries} -> 0 not found"),
                format!(
                    "[DNS] [{queries}] resolve incomplete, responses=-, \
                     ongoing={ongoing} for foo.test:443"
                ),
            ],
            "{said:?}"
        );
    }
    // The answer's entry is said between the two lines of its probe's end,
    // as `Curl_dnscache_add` says it inside C's.
    let at = said
        .iter()
        .position(|l| l.trim_end() == "[DNS] cached entry for foo.test:443 queries=A+AAAA")
        .expect("said");
    for near in [&said[at - 1], &said[at + 1]] {
        assert_eq!(near.trim_end(), "[DNS] [DoH] probe done", "{said:?}");
    }
}

/// The lines of an `https` transfer's setup connecting with its record's
/// probe unanswered, on the components `config` turns on: the origin's
/// TLS made at once, the record's server silent.
fn record_unanswered(config: &[u8]) -> Vec<String> {
    use crate::tls::fake;
    let clock = ManualClock::new().unwrap();
    let response = fake::records(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
    let origin = Conversation::replies(&[fake::WELCOME, &response], false);
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Accepts)
        .with_peer(at(443), Peer::Accepts)
        .with_conversation(SERVER.into(), Conversation::replies(&[], false))
        .with_conversation(
            SERVER.into(),
            Conversation::new(&http(&no_records()), false),
        )
        .with_conversation(SERVER.into(), Conversation::new(&http(&a_answer()), false))
        .with_conversation(at(443), origin.clone());
    let mut m = multi_over(net, &clock);
    let mut easy = asking("https://foo.test/x");
    let tls = Box::leak(Box::new(fake::FakeTls::new().unwrap()));
    easy.set_libraries(
        crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
            tls: Some(crate::libraries::Library::Static(tls)),
            ..crate::libraries::Libraries::NONE
        })
        .unwrap(),
    );
    let lines = Lines::default();
    let o = easy.options_mut();
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    let c = crate::components::Components::new().unwrap();
    c.configure(config);
    easy.set_components(Some(c));
    m.add(easy, (), &mut NoEvents).unwrap();
    run(&mut m, &clock);
    assert_eq!(message(&mut m), Some(Ok(())));
    assert!(
        origin.received().starts_with(fake::HELLO),
        "the setup connected"
    );
    assert_eq!(m.census().counts.current, 1, "the probe went with it");
    lines.0.lock().unwrap().clone()
}

/// The record's probe still running as the chain connects goes with its
/// filter's resolve, said right after the resolve's record goes, as C's
/// `Curl_resolv_destroy` removes the probe and says so (`doh_close`).
#[test]
fn a_record_still_asked_for_goes_as_the_chain_connects() {
    let said = record_unanswered(b"dns");
    let at = said
        .iter()
        .position(|l| l.trim_end() == "[DNS] [1] destroy async")
        .expect("the record's resolve goes");
    let near: Vec<&str> = said[at - 3..at + 2].iter().map(|l| l.trim_end()).collect();
    assert_eq!(
        near,
        [
            "[DNS] connected filter chain below",
            "[DNS] [2] destroy async",
            "[DNS] connected filter chain below",
            "[DNS] [1] destroy async",
            "[DNS] [DoH] probe done",
        ],
        "{said:?}"
    );
    let done = said
        .iter()
        .filter(|l| l.trim_end() == "[DNS] [DoH] probe done")
        .count();
    assert_eq!(
        done, 3,
        "two for the addresses, one for the record: {said:?}"
    );
}

/// The probe so removed is taken out of the multi after the step it went
/// in, not inside it as C's is: its own lines of its end come after
/// `[DoH] probe done`, not before, and the master's next step does not
/// say the multi changed (DIVERGENCE.md, "Probes C removes inside their
/// master's step").
#[test]
fn a_probe_removed_as_its_master_connects_ends_after_the_step() {
    let said = record_unanswered(b"all");
    let at = |want: &str| {
        said.iter()
            .position(|l| l.trim_end().ends_with(want))
            .unwrap_or_else(|| panic!("{want}: {said:?}"))
    };
    let done = at("[DNS] [1] destroy async") + 1;
    assert_eq!(
        said[done].trim_end(),
        "[0-0] [DNS] [DoH] probe done",
        "{said:?}"
    );
    let premature = at("premature=1, conn_multiplex=0");
    let removed = at("removed from multi, mid=2, running=1, total=2");
    assert!(done < premature && premature < removed, "{said:?}");
    assert!(
        !said.iter().any(|l| l.contains("check CONNECT_PEND queue")),
        "{said:?}"
    );
}

/// What a probe's own handlers, the socket callback and the multi answer
/// for a probe: nothing but its owner, as C's API refuses an internal
/// handle (`Curl_eapi_enter`); nor is the host told its id as it is added.
/// Each table says what each call came to. `tls_native` and `easy_ssls_going_out` are not asked: a probe here
/// speaks no TLS and keeps no sessions, so they answer nothing either way.
#[test]
fn no_call_reaches_a_probe() {
    use std::sync::{Arc, Mutex};
    type Seen = Arc<Mutex<Vec<(&'static str, bool)>>>;
    struct Named;
    impl Host for Named {
        type Transfer = u32;
        type Socket = ();
    }
    /// Its own handler's calls, on itself and on its master.
    struct Own {
        master: Arc<Mutex<Option<TransferId>>>,
        seen: Seen,
    }
    impl crate::handler::DebugHandler for Own {
        fn debug(&self, cx: &mut TransferCx<'_>, _: crate::handler::DebugKind, _: &[u8]) {
            let me = cx.me();
            let Some(master) = *self.master.lock().unwrap() else {
                return;
            };
            if me == master {
                return;
            }
            let calls = [
                ("master's options", cx.options(master).is_some()),
                ("options", cx.options(me).is_none()),
                ("info", cx.info(me).is_none()),
                ("options_mut", cx.options_mut(me).is_none()),
                ("rtsp", cx.rtsp(me).is_none()),
                ("rtsp_mut", cx.rtsp_mut(me).is_none()),
                ("duplicate", cx.duplicate(me).is_none()),
                (
                    "duplicate_with",
                    cx.duplicate_with(me, &mut |_| Ok(())).is_none(),
                ),
                (
                    "pause",
                    cx.pause(me, PauseRequest::CONT) == Err(ErrorKind::BadFunctionArgument),
                ),
            ];
            self.seen.lock().unwrap().extend(calls);
        }
    }
    #[derive(Default)]
    struct Ev {
        master: Option<TransferId>,
        seen: Vec<(&'static str, bool)>,
        added: Vec<u32>,
    }
    impl MultiEvents<Named> for Ev {
        fn added(&mut self, _: TransferId, owner: &u32) {
            self.added.push(*owner);
        }
        fn internal(
            &mut self,
            _: &mut EventCx<'_, Named>,
            _: TransferId,
            easy: Box<Easy>,
        ) -> Result<(Box<Easy>, Option<u32>), OutOfMemory> {
            Ok((easy, Some(100)))
        }
        fn wants_sockets(&self) -> bool {
            true
        }
        fn socket(
            &mut self,
            cx: &mut EventCx<'_, Named>,
            who: SocketFor,
            _: SocketKey,
            _: SocketWhat,
            _: Option<()>,
        ) -> Result<(), Abort> {
            let (SocketFor::Transfer(id), Some(master)) = (who, self.master) else {
                return Ok(());
            };
            if id == master {
                return Ok(());
            }
            let calls = [
                ("socket's master's options", cx.options(master).is_some()),
                ("socket's owner", cx.owner(id) == Some(&100)),
                ("socket's options", cx.options(id).is_none()),
                ("socket's info", cx.info(id).is_none()),
                ("socket's options_mut", cx.options_mut(id).is_none()),
                ("socket's rtsp", cx.rtsp(id).is_none()),
                ("socket's rtsp_mut", cx.rtsp_mut(id).is_none()),
                ("socket's duplicate", cx.duplicate(id).is_none()),
            ];
            self.seen.extend(calls);
            Ok(())
        }
    }
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone()).with_peer(SERVER.into(), Peer::Silent);
    let mut m: Multi<Named> = Multi::new(Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    })
    .unwrap();
    let mut easy = asking("http://foo.test/x");
    let master = Arc::new(Mutex::new(None));
    let seen = Seen::default();
    let own = Own {
        master: master.clone(),
        seen: seen.clone(),
    };
    let o = easy.options_mut();
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(own).unwrap());
    let components = crate::components::Components::new().unwrap();
    components.configure(b"doh");
    easy.set_components(Some(components));
    let mut ev = Ev::default();
    let id = m.add(easy, 7, &mut ev).unwrap();
    *master.lock().unwrap() = Some(id);
    ev.master = Some(id);
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    let mut cursor = None;
    let probe = loop {
        let p = m.slots.next_after(cursor).expect("a probe");
        cursor = Some(p);
        if m.slots.get(p).unwrap().owner.is_internal() {
            break p;
        }
    };
    let share = crate::share::Share::new().unwrap();
    let told = crate::share::Told::new(&share);
    let mut buf = [0; 4];
    let mut notes = |_: crate::handler::DebugKind, _: &[u8]| {};
    let done = m
        .ssls_export(id)
        .expect("the master's")
        .expect("room for its mark")
        .deliver(&mut |_| Err(()));
    let calls = [
        ("master's easy", m.easy(id).is_some()),
        ("owner", m.owner(probe) == Some(&100)),
        ("easy", m.easy(probe).is_none()),
        ("easy_mut", m.easy_mut(probe).is_none()),
        ("holds_connection", !m.holds_connection(probe)),
        ("set_share", m.set_share(probe, None).is_none()),
        (
            "set_share_watched",
            m.set_share_watched(probe, share.clone(), told.handler())
                .is_none(),
        ),
        ("leave_share", m.leave_share(probe).is_none()),
        (
            "pause",
            m.pause(probe, PauseRequest::CONT, &mut ev) == Err(ErrorKind::BadFunctionArgument),
        ),
        ("upkeep", m.upkeep(probe, &mut ev).is_none()),
        (
            "recv_raw",
            m.recv_raw(probe, &mut buf, &mut notes).is_none(),
        ),
        ("send_raw", m.send_raw(probe, b"x", &mut notes).is_none()),
        ("active_socket", m.active_socket(probe).is_none()),
        (
            "ws",
            m.ws(probe, crate::ws::Call::Recv(&mut buf), &mut notes)
                .is_none(),
        ),
        (
            "ssls_import",
            m.ssls_import(probe, crate::tls::SessionFor::Key(b"k"), b"", &mut notes)
                .is_none(),
        ),
        ("ssls_export", m.ssls_export(probe).is_none()),
        (
            "ssls_export_end",
            m.ssls_export_end(probe, done, &mut notes).is_none(),
        ),
        (
            "drive_within",
            super::wait::drive_within(&mut m, probe, 1, &mut ev)
                == Err(MultiErrorKind::BadEasyHandle),
        ),
        ("remove", m.remove(probe, &mut ev).is_none()),
        ("still there", m.owner(probe).is_some()),
    ];
    let wrong = |seen: &[(&str, bool)]| -> Vec<String> {
        seen.iter()
            .filter(|(_, ok)| !ok)
            .map(|(what, _)| (*what).to_owned())
            .collect()
    };
    assert_eq!(wrong(&calls), Vec::<String>::new());
    assert_eq!(ev.added, [7], "told of the master alone");
    assert!(!ev.seen.is_empty(), "the probe's socket was told");
    assert_eq!(wrong(&ev.seen), Vec::<String>::new());
    let own = seen.lock().unwrap().clone();
    assert!(!own.is_empty(), "the probe's handler was called");
    assert_eq!(wrong(&own), Vec::<String>::new());
}

/// The multi looks through its transfers for probes to take out only once
/// a lookup has dropped: the steps while the probes are wanted look for
/// none, however many transfers there are, and the master's end looks
/// once.
#[test]
fn probes_are_looked_for_only_once_a_lookup_drops() {
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone())
        .with_peer(SERVER.into(), Peer::Silent)
        .with_peer(at(80), Peer::Silent)
        .with_name("other.test", &[[127, 0, 0, 1].into()]);
    let mut m = multi_over(net, &clock);
    let mut easy = asking("http://foo.test/x");
    easy.options_mut().limits.total = crate::time::TimeLimit::from_millis(50);
    m.add(easy, (), &mut NoEvents).unwrap();
    for _ in 0..3 {
        let mut other = Box::new(Easy::new());
        other
            .options_mut()
            .set_url(Some(b"http://other.test/"))
            .unwrap();
        m.add(other, (), &mut NoEvents).unwrap();
    }
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
        clock.advance(Duration::from_millis(1));
    }
    assert_eq!(m.census().counts.current, 6, "the probes run");
    assert!(
        m.reaping.asked >= 4,
        "steps were taken: {}",
        m.reaping.asked
    );
    assert_eq!(m.reaping.looked, 0, "with every lookup still wanted");
    clock.advance(Duration::from_millis(40));
    run(&mut m, &clock);
    assert!(matches!(message(&mut m), Some(Err(_))));
    assert_eq!(m.census().counts.current, 4, "the probes went");
    assert_eq!(m.reaping.looked, 1, "once, as the lookup dropped");
}
