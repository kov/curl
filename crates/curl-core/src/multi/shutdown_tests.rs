//! Connections shutting down in the multi's set (`lib/cshutdn.c`), armed
//! by a test layer whose shutdown waits, as TLS's close_notify will. The
//! oracle is the reference build's lib758 sequence: a connection entering
//! shutdown keeps its socket registered with no socket callback, its
//! transfer gone from it, and the callback hears REMOVE, from the multi's
//! internal handle, only when the set closes it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::*;
use crate::conn::io::{Conversation, FakeNet, Peer, PollFd, Resolver, Sock, SocketPoll};
use crate::conn::layer::Linger;
use crate::time::ManualClock;

/// One call of the multi's callbacks: whom a socket was for (None for the
/// multi's own), the socket, what it was told; or the timer's change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Socket(Option<u32>, i32, SocketWhat),
    Timer(TimerChange),
}

#[derive(Default)]
struct Rec(Vec<Call>);

impl MultiEvents<NoHost> for Rec {
    fn socket(
        &mut self,
        _: &mut EventCx<'_, NoHost>,
        who: SocketFor,
        s: SocketKey,
        what: SocketWhat,
        _: Option<()>,
    ) -> Result<(), Abort> {
        let who = match who {
            SocketFor::Transfer(id) => Some(id.index()),
            SocketFor::Multi => None,
        };
        self.0.push(Call::Socket(who, s.get(), what));
        Ok(())
    }

    fn wants_sockets(&self) -> bool {
        true
    }

    fn timer(&mut self, _: &mut EventCx<'_, NoHost>, change: TimerChange) -> Result<(), Abort> {
        self.0.push(Call::Timer(change));
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }
}

impl Rec {
    fn sockets(&self) -> Vec<Call> {
        self.0
            .iter()
            .copied()
            .filter(|c| matches!(c, Call::Socket(..)))
            .collect()
    }

    fn timers(&self) -> Vec<TimerChange> {
        self.0
            .iter()
            .filter_map(|c| match c {
                Call::Timer(t) => Some(*t),
                Call::Socket(..) => None,
            })
            .collect()
    }
}

/// The fake network, reachable by the test while a multi holds it, the
/// sockets it closes recorded in order.
#[derive(Clone)]
struct Wire(Arc<Mutex<Wired>>);

struct Wired {
    net: FakeNet,
    closed: Vec<i32>,
    /// How long each close takes of the clock, if any time.
    close_takes: Option<(ManualClock, Duration)>,
}

impl Wire {
    fn closed(&self) -> Vec<i32> {
        self.0.lock().unwrap().closed.clone()
    }

    fn hang_up(&self, fd: i32) {
        self.0.lock().unwrap().net.hang_up(SocketKey::new(fd));
    }

    fn open(&self) -> usize {
        self.0.lock().unwrap().net.open_sockets()
    }

    /// From now on each close moves `clock` on by `takes`.
    fn slow_closes(&self, clock: &ManualClock, takes: Duration) {
        self.0.lock().unwrap().close_takes = Some((clock.clone(), takes));
    }
}

impl Net for Wire {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.lock().unwrap().net.poll(sockets, fds, timeout)
    }

    fn open(&mut self, addr: &crate::conn::io::Remote) -> std::io::Result<Box<dyn Socket>> {
        self.0.lock().unwrap().net.open(addr)
    }

    fn close(&mut self, socket: Sock) {
        let mut w = self.0.lock().unwrap();
        w.closed.push(socket.key().get());
        w.net.close(socket);
        if let Some((clock, takes)) = &w.close_takes {
            clock.advance(*takes);
        }
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
        self.0.lock().unwrap().net.with_resolver(f);
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        None
    }

    fn interface_address(
        &mut self,
        _: &[u8],
        _: bool,
        _: crate::conn::io::Ipv6Scope,
        _: u32,
    ) -> crate::conn::io::InterfaceAddress {
        crate::conn::io::InterfaceAddress::NotFound
    }
}

/// What each server answers, and keeps the connection open after.
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

/// A multi over servers at ports 1 and 2 answering `OK` on each of
/// `talks` connections, and at port 3 one that never answers; each
/// connection given a layer whose shutdown waits as `linger` says.
fn lingering(linger: Linger) -> (Multi, Wire, ManualClock) {
    served(linger, 4)
}

fn served(linger: Linger, talks: usize) -> (Multi, Wire, ManualClock) {
    let clock = ManualClock::new().unwrap();
    let mut fake = FakeNet::new(clock.clone());
    for port in 1..=3 {
        let at = SocketAddr::from(([127, 0, 0, 1], port));
        fake = fake.with_peer(at, Peer::Accepts);
        if port < 3 {
            for _ in 0..talks {
                // Answered a poll after the request, as a server does: the
                // transfer waits to read first.
                let talk = Conversation::new(OK, false).late_replies();
                fake = fake.with_conversation(at, talk);
            }
        }
    }
    let wire = Wire(Arc::new(Mutex::new(Wired {
        net: fake,
        closed: Vec::new(),
        close_takes: None,
    })));
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(wire.clone()),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    m.linger_connections(Some(linger));
    (m, wire, clock)
}

/// A transfer to `port` whose connection is closed once it is done
/// (`CURLOPT_FORBID_REUSE`), as one marked to close is.
fn closing(port: u16) -> Box<Easy> {
    let mut e = Easy::new();
    let url = format!("http://127.0.0.1:{port}/");
    e.options_mut().set_url(Some(url.as_bytes())).unwrap();
    e.options_mut().limits.reuse.forbid = true;
    Box::new(e)
}

/// Run `m` by `socket_action`, on the socket `fd` of transfer `id`,
/// until it completes.
fn by_events(m: &mut Multi, id: TransferId, fd: i32, ev: &mut dyn MultiEvents<NoHost>) {
    m.socket_action(SocketEvent::Timeout, ev).unwrap();
    for _ in 0..10 {
        if m.state_of(id).is_completed() {
            return;
        }
        m.socket_action(SocketEvent::Socket(SocketKey::new(fd)), ev)
            .unwrap();
    }
    panic!("the transfer did not complete");
}

/// Run `m` by `perform` until transfer `id` completes.
fn by_perform(m: &mut Multi, id: TransferId, ev: &mut dyn MultiEvents<NoHost>) {
    for _ in 0..10 {
        m.perform(ev).unwrap();
        if m.state_of(id).is_completed() {
            return;
        }
    }
    panic!("the transfer did not complete");
}

/// lib758's sequence: a connection whose shutdown waits leaves its pool
/// for the multi's set, its socket kept registered and owned by the
/// connection, the transfer gone from it and the callback not called;
/// when its peer answers, the set closes it, and the callback hears
/// REMOVE as the multi's (C's internal handle), before the socket closes.
#[test]
fn a_closing_connection_owns_its_socket_until_the_set_closes_it() {
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    let mut ev = Rec::default();
    let id = m.add(closing(1), (), &mut ev).unwrap();
    by_events(&mut m, id, 1000, &mut ev);
    let t = Some(id.index());
    assert_eq!(
        ev.sockets(),
        [
            Call::Socket(t, 1000, SocketWhat::Out),
            Call::Socket(t, 1000, SocketWhat::In)
        ],
        "no REMOVE as the transfer leaves it"
    );
    assert_eq!(m.shutdowns.len(), 1, "the set holds it");
    assert_eq!(m.caches.pool.len(), 0, "out of the pool");
    let users: Vec<_> = m.sockets.users(SocketKey::new(1000)).collect();
    assert!(
        matches!(users[..], [SocketOwner::Conn(_)]),
        "owned by the connection: {users:?}"
    );
    assert_eq!(wire.closed(), [], "still open");
    // Waited on by `fdset` and `waitfds` as the set's.
    let mut waited = Vec::new();
    m.sockets(&mut NoEvents, |k, e| waited.push((k.get(), e)));
    assert_eq!(waited, [(1000, Events::IN)]);
    // Its peer answers: the set runs on the event, and closes it.
    m.remove(id, &mut ev).unwrap();
    wire.hang_up(1000);
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert_eq!(
        ev.sockets()[2..],
        [Call::Socket(None, 1000, SocketWhat::Remove)]
    );
    assert_eq!(wire.closed(), [1000]);
    assert_eq!(m.shutdowns.len(), 0);
}

/// A connection is not shut down for a transfer that ended before its
/// time, as the server might take the end for a success: it is closed at
/// once, and never joins the set (`cpool_discard_conn`).
#[test]
fn an_aborted_transfer_s_connection_closes_at_once() {
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    let mut ev = Rec::default();
    // An answer that never comes: the transfer is taken out as it waits.
    let id = m.add(closing(3), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert!(!m.state_of(id).is_completed());
    assert_eq!(
        ev.sockets().last(),
        Some(&Call::Socket(Some(id.index()), 1000, SocketWhat::In)),
        "connected, and waiting"
    );
    m.remove(id, &mut ev).unwrap();
    assert_eq!(m.shutdowns.len(), 0, "never in the set");
    assert_eq!(wire.closed(), [1000]);
    assert_eq!(wire.open(), 0);
}

/// The set's deadline is the multi's own (C's EXPIRE_SHUTDOWN on its
/// internal handle): armed only when the set runs, never as a connection
/// joins, at the time left of its 2 s, counted from the first try as the
/// pool let it go. The timer callback hears it, and the connection is
/// closed once its time is up.
#[test]
fn the_shutdown_deadline_is_the_multi_s_own_row() {
    let (mut m, wire, clock) = lingering(Linger::UntilPeer);
    let mut ev = Rec::default();
    let id = m.add(closing(1), (), &mut ev).unwrap();
    by_perform(&mut m, id, &mut ev);
    let released = clock.now();
    assert_eq!(m.shutdowns.len(), 1);
    assert_eq!(m.timeout(), None, "not armed as it joins");
    assert_eq!(ev.timers().last(), Some(&TimerChange::Clear));
    m.remove(id, &mut ev).unwrap();
    clock.advance(Duration::from_millis(500));
    ev.0.clear();
    m.perform(&mut ev).unwrap();
    assert_eq!(m.timeout(), Some(Duration::from_millis(1500)));
    assert_eq!(ev.timers(), [TimerChange::Set(Duration::from_millis(1500))]);
    // Its deadline wakes the set, as a transfer's timer wakes it.
    clock.advance(Duration::from_millis(1499));
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(wire.closed(), [], "1 ms left");
    assert_eq!(m.timeout(), Some(Duration::from_millis(1)));
    clock.advance(Duration::from_millis(1));
    assert_eq!(clock.now().since(released), Duration::from_secs(2));
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(wire.closed(), [1000], "out of time");
    assert_eq!(m.shutdowns.len(), 0);
}

/// A shutdown that finishes in a later pass closes its connection then;
/// `perform` drives the set each time it runs, before the transfers
/// (`Curl_cshutdn_perform` on the internal handle, whose row is first).
#[test]
fn perform_moves_each_shutdown_on() {
    let (mut m, wire, _clock) = lingering(Linger::Passes(2));
    let mut ev = Rec::default();
    let id = m.add(closing(1), (), &mut ev).unwrap();
    by_perform(&mut m, id, &mut ev);
    // One pass waited as the pool let it go.
    assert_eq!(m.shutdowns.len(), 1);
    m.perform(&mut ev).unwrap();
    assert_eq!(wire.closed(), [], "one more to wait");
    m.perform(&mut ev).unwrap();
    assert_eq!(wire.closed(), [1000]);
    assert_eq!(m.shutdowns.len(), 0);
}

/// A connection shutting down counts toward the multi's limits as an open
/// one does; one that would pass a limit is closed to make room, the
/// oldest to the same host first, then any (`cpool_check_limits`), so the
/// new transfer has its connection without waiting. Its socket is the
/// multi's, though the new transfer's setup closes it.
#[test]
fn closing_connections_count_toward_the_limits() {
    for (host, total, port) in [(Some(1), None, 1), (None, Some(1), 2)] {
        let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
        let limits = m.conn_limits_mut();
        limits.max_host = host.and_then(NonZeroU32::new);
        limits.max_total = total.and_then(NonZeroU32::new);
        let mut ev = Rec::default();
        let a = m.add(closing(1), (), &mut ev).unwrap();
        by_events(&mut m, a, 1000, &mut ev);
        assert_eq!(m.shutdowns.len(), 1);
        m.remove(a, &mut ev).unwrap();
        ev.0.clear();
        let b = m.add(closing(port), (), &mut ev).unwrap();
        m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
        assert_eq!(wire.closed(), [1000], "closed to make room");
        assert!(
            !matches!(m.state_of(b), state::TransferState::Pending(_)),
            "not waiting"
        );
        assert_eq!(m.shutdowns.len(), 0);
        assert_eq!(
            ev.sockets(),
            [
                Call::Socket(None, 1000, SocketWhat::Remove),
                Call::Socket(Some(b.index()), 1000, SocketWhat::Out),
            ]
        );
    }
}

/// A closing connection to another host does not count toward the limit
/// on one host, and stays.
#[test]
fn a_closing_connection_counts_only_toward_its_own_host() {
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    m.conn_limits_mut().max_host = NonZeroU32::new(1);
    let mut ev = Rec::default();
    let a = m.add(closing(1), (), &mut ev).unwrap();
    by_perform(&mut m, a, &mut ev);
    let b = m.add(closing(2), (), &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    assert_eq!(wire.closed(), [], "to another host");
    assert_eq!(m.shutdowns.len(), 1);
    assert!(
        !matches!(m.state_of(b), state::TransferState::Pending(_)),
        "not waiting for room"
    );
}

/// With no limit set, the set keeps at most 128 (a quarter of the pool,
/// if more): past that, the oldest is closed for the newest
/// (`Curl_cshutdn_add`).
#[test]
fn a_full_set_closes_its_oldest() {
    let (mut m, wire, _clock) = served(Linger::UntilPeer, 129);
    let mut ev = NoEvents;
    let mut first = None;
    for n in 0..=128 {
        let id = m.add(closing(1), (), &mut ev).unwrap();
        for _ in 0..10 {
            m.perform(&mut ev).unwrap();
            if m.state_of(id).is_completed() {
                break;
            }
        }
        assert!(m.state_of(id).is_completed());
        m.remove(id, &mut ev).unwrap();
        if n == 0 {
            first = m.shutdowns.pollsets().next().map(|(s, _)| s.key().get());
        }
        let held = (n + 1).min(128);
        assert_eq!(m.shutdowns.len(), held, "after {n}");
    }
    assert_eq!(wire.closed(), [first.unwrap()], "the oldest went");
}

/// The multi's cleanup gives its connections one shutdown pass, then
/// closes them, those idle and those already shutting down, each through
/// the closer of the transfer that made it, though that transfer is gone
/// (`Curl_cpool_destroy`, `Curl_cshutdn_destroy`); the socket callback
/// hears of each as the multi's.
#[test]
fn cleanup_closes_every_connection_through_its_own_closer() {
    struct Told(Arc<Mutex<Vec<i32>>>);
    impl crate::handler::SocketCloser for Told {
        fn close(&self, socket: SocketKey) {
            self.0.lock().unwrap().push(socket.get());
        }
    }
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    let told = Arc::new(Mutex::new(Vec::new()));
    let mut ev = Rec::default();
    let mut e = closing(1);
    let closer = crate::handler::Handler::socket_closer(Told(told.clone())).unwrap();
    e.options_mut().sockets.make_mut().unwrap().close = Some(closer);
    let id = m.add(e, (), &mut ev).unwrap();
    by_events(&mut m, id, 1000, &mut ev);
    // Kept idle, this one, until the cleanup.
    let mut idle = closing(2);
    idle.options_mut().limits.reuse.forbid = false;
    let kept = m.add(idle, (), &mut ev).unwrap();
    by_events(&mut m, kept, 1001, &mut ev);
    let gone = m.remove(id, &mut ev).unwrap();
    drop(gone);
    m.remove(kept, &mut ev).unwrap();
    assert_eq!((m.shutdowns.len(), m.caches.pool.len()), (1, 1));
    ev.0.clear();
    m.close_connections(&mut ev);
    assert_eq!(*told.lock().unwrap(), [1000], "through the maker's closer");
    assert_eq!(wire.closed(), [1000, 1001]);
    assert_eq!(wire.open(), 0);
    // The idle one is told as it joins, then both as they close.
    assert_eq!(
        ev.sockets(),
        [
            Call::Socket(None, 1001, SocketWhat::In),
            Call::Socket(None, 1000, SocketWhat::Remove),
            Call::Socket(None, 1001, SocketWhat::Remove),
        ]
    );
    assert_eq!(ev.timers(), [], "the cleanup tells no timer");
}

/// A share's connection whose shutdown waits goes to the multi of the
/// transfer that let it go, as C's does (conncache.c:242): the share's
/// pool holds it no longer, and the multi's set owns it and its socket.
#[test]
fn a_share_s_closing_connection_joins_the_releasing_multi_s_set() {
    use crate::share::{Kind, Share};
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    let share = Share::with_net(Box::new(wire.clone())).unwrap();
    share.keep(Kind::Connections).unwrap();
    let mut ev = Rec::default();
    let mut e = closing(1);
    e.set_share(Some(share.clone()));
    let id = m.add(e, (), &mut ev).unwrap();
    by_events(&mut m, id, 1000, &mut ev);
    assert_eq!(share.pool().len(), 0, "out of the share's pool");
    assert_eq!(m.shutdowns.len(), 1, "in the multi's set");
    let users: Vec<_> = m.sockets.users(SocketKey::new(1000)).collect();
    assert!(matches!(users[..], [SocketOwner::Conn(_)]), "{users:?}");
    m.remove(id, &mut ev).unwrap();
    drop(share);
    assert_eq!(wire.closed(), [], "the share no longer has it");
    m.close_connections(&mut ev);
    assert_eq!(wire.closed(), [1000]);
}

/// An idle connection a pool evicts for room is discarded as any other:
/// a multi's joins the set when its shutdown waits, but a share's, which
/// no multi owns, is closed after its one try (`cpool_evict_conn`).
#[test]
fn an_evicted_connection_shuts_down_where_its_pool_lets_it() {
    use crate::share::{Kind, Share};
    for shared in [false, true] {
        let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
        m.conn_limits_mut().max_connects = NonZeroU32::new(1);
        let share = Share::with_net(Box::new(wire.clone())).unwrap();
        share.keep(Kind::Connections).unwrap();
        let mut ev = Rec::default();
        for (port, fd) in [(1, 1000), (2, 1001)] {
            let mut e = closing(port);
            e.options_mut().limits.reuse.forbid = false;
            if shared {
                e.set_share(Some(share.clone()));
            }
            let id = m.add(e, (), &mut ev).unwrap();
            by_events(&mut m, id, fd, &mut ev);
            m.remove(id, &mut ev).unwrap();
        }
        if shared {
            assert_eq!(wire.closed(), [1000], "closed by the share's pool");
            assert_eq!(m.shutdowns.len(), 0);
        } else {
            assert_eq!(wire.closed(), [], "shutting down in the set");
            assert_eq!(m.shutdowns.len(), 1);
        }
    }
}

/// Making room under a host's limit closes the oldest closing connection
/// to that host, not an older one to another (`Curl_cshutdn_close_oldest`
/// with the destination).
#[test]
fn room_for_a_host_closes_that_host_s_closing_connection() {
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    m.conn_limits_mut().max_host = NonZeroU32::new(1);
    let mut ev = Rec::default();
    for (port, fd) in [(1, 1000), (2, 1001)] {
        let id = m.add(closing(port), (), &mut ev).unwrap();
        by_events(&mut m, id, fd, &mut ev);
        m.remove(id, &mut ev).unwrap();
    }
    assert_eq!(m.shutdowns.len(), 2);
    let b = m.add(closing(2), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(wire.closed(), [1001], "the one to port 2");
    assert_eq!(m.shutdowns.len(), 1, "the one to port 1 stays");
    assert!(!matches!(m.state_of(b), state::TransferState::Pending(_)));
}

/// A multi over a server at port 4 holding `talk`, and the fake TLS
/// library a handle speaks to it with.
fn over_tls(talk: &Conversation) -> (Multi, Wire, &'static crate::tls::fake::FakeTls) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], 4));
    let fake = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let wire = Wire(Arc::new(Mutex::new(Wired {
        net: fake,
        closed: Vec::new(),
        close_takes: None,
    })));
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(wire.clone()),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let backend = Box::leak(Box::new(crate::tls::fake::FakeTls::new().unwrap()));
    (Multi::new(env).unwrap(), wire, backend)
}

/// An HTTPS transfer to port 4 by the TLS library `tls`, whose
/// connection is closed once it is done.
fn closing_tls(tls: &'static crate::tls::fake::FakeTls) -> Box<Easy> {
    let libraries = crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
        tls: Some(crate::libraries::Library::Static(tls)),
        ..crate::libraries::Libraries::NONE
    })
    .unwrap();
    let mut e = Easy::new();
    e.set_libraries(libraries);
    e.options_mut()
        .set_url(Some(b"https://127.0.0.1:4/"))
        .unwrap();
    e.options_mut().limits.reuse.forbid = true;
    Box::new(e)
}

/// The server's side of an HTTPS exchange that ends in its goodbye.
fn tls_talk() -> Conversation {
    use crate::tls::fake::{CLOSE, WELCOME, records};
    Conversation::replies(&[WELCOME, &records(OK).unwrap(), CLOSE], false)
}

/// A TLS connection closed after its transfer says goodbye first, and
/// is closed as soon as its peer says it back: here at once, in the
/// pool's one try, so it never joins the set.
#[test]
fn a_tls_connection_says_goodbye_as_it_closes() {
    let talk = tls_talk();
    let (mut m, wire, tls) = over_tls(&talk);
    let mut ev = Rec::default();
    let id = m.add(closing_tls(tls), (), &mut ev).unwrap();
    by_perform(&mut m, id, &mut ev);
    assert!(talk.received().ends_with(crate::tls::fake::CLOSE));
    assert_eq!((tls.log().closes_sent, tls.log().closes_heard), (1, 1));
    assert_eq!(m.shutdowns.len(), 0);
    assert_eq!(wire.closed(), [1000]);
}

/// A goodbye the peer has not said back yet waits in the multi's set,
/// reading for it, until the peer says it.
#[test]
fn a_tls_goodbye_waits_in_the_set_for_the_peer_s() {
    let talk = tls_talk().held();
    talk.allow(2);
    let (mut m, wire, tls) = over_tls(&talk);
    let mut ev = Rec::default();
    let id = m.add(closing_tls(tls), (), &mut ev).unwrap();
    by_perform(&mut m, id, &mut ev);
    assert_eq!((tls.log().closes_sent, tls.log().closes_heard), (1, 0));
    assert_eq!(m.shutdowns.len(), 1);
    let mut waited = Vec::new();
    m.sockets(&mut NoEvents, |k, e| waited.push((k.get(), e)));
    assert_eq!(waited, [(1000, Events::IN)]);
    assert_eq!(wire.closed(), []);
    talk.allow(3);
    m.perform(&mut ev).unwrap();
    assert_eq!(tls.log().closes_heard, 1);
    assert_eq!(m.shutdowns.len(), 0);
    assert_eq!(wire.closed(), [1000]);
}

/// The text written to it.
#[derive(Clone, Default)]
struct Written(Arc<Mutex<Vec<u8>>>);

impl crate::handler::TextSink for Written {
    fn write(&self, text: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(text);
    }
}

impl Written {
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// The multi's internal trace, on as C's debug build makes its internal
/// handle verbose under `CURL_DEBUG`, says the shutdown as C's does: a
/// goodbye left waiting for the peer's joins the set; each perform and
/// each pass of the set is said, and each pollset asked for; once the
/// peer says it back, the connection closes, its socket goes and a
/// transfer waiting for room may look (pytest test_19_04's lines, the
/// TLS library's own apart).
#[test]
fn the_internal_trace_says_a_shutdown_as_c_does() {
    use crate::components::{Component, Components, Level};
    let talk = tls_talk().held();
    talk.allow(2);
    let (mut m, _wire, tls) = over_tls(&talk);
    let components = Components::new().unwrap();
    components.set(Component::Multi, Level::Info);
    components.set(Component::Ssl, Level::Info);
    let written = Written::default();
    m.trace_internally_to(
        components,
        crate::handler::Handler::text(written.clone()).unwrap(),
    );
    let mut ev = Rec::default();
    let id = m.add(closing_tls(tls), (), &mut ev).unwrap();
    by_perform(&mut m, id, &mut ev);
    // Its pollset asked for, as `curl_multi_fdset` asks.
    m.sockets(&mut ev, |_, _| ());
    talk.allow(3);
    m.perform(&mut ev).unwrap();
    assert_eq!(m.shutdowns.len(), 0);
    assert_eq!(
        written.lines(),
        [
            "* [MULTI] multi_perform(running=1)",
            "* [MULTI] multi_perform(running=1)",
            "* [MULTI] shutdown start on connection",
            "* [SSL] cf_shutdown -> 0, done=0",
            "* [SSL] shut down not done yet",
            "* [MULTI] [SHUTDOWN] shutdown, done=0",
            "* [MULTI] [SHUTDOWN] added #0 to shutdowns, now 1 conns in shutdown",
            // Its chain asked as the socket callback is told of it.
            "* [SSL] adjust_pollset, POLLIN fd=1000",
            // The pollsets, the internal handle's first, then each
            // closing chain's.
            "* [MULTI] pollset[], timeouts=0, paused 0/0 (r/w)",
            "* [SSL] adjust_pollset, POLLIN fd=1000",
            "* [MULTI] multi_perform(running=0)",
            "* [MULTI] [SHUTDOWN] perform on 1 connections",
            "* [SSL] cf_shutdown -> 0, done=1",
            "* [SSL] shut down successfully",
            "* [MULTI] [SHUTDOWN] shutdown, done=1",
            "* [MULTI] [SHUTDOWN] closing connection #0",
            "* [MULTI] Curl_multi_will_close fd=1000",
            "* [MULTI] [SHUTDOWN] trigger multi connchanged",
        ]
    );
}

/// A handle's own multi driven by events keeps its callbacks as it
/// goes: a connection still closing then is closed in its cleanup, and
/// the callback says its socket's REMOVE on the internal trace, as C's
/// `curl_easy_perform_ev` says it on the internal handle (test_19_05);
/// the cleanup is said as C's `curl_multi_cleanup` says it, once.
#[test]
fn a_handle_s_own_multi_says_its_cleanup_s_removes() {
    use crate::components::{Component, Components, Level};
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    let components = Components::new().unwrap();
    components.set(Component::Multi, Level::Info);
    let written = Written::default();
    m.trace_internally_to(
        components,
        crate::handler::Handler::text(written.clone()).unwrap(),
    );
    let id = m.add(closing(1), (), &mut NoEvents).unwrap();
    let mut table = super::EventTable::default();
    assert_eq!(
        super::drive_by_events_with(&mut m, id, &mut table),
        Ok(Ok(()))
    );
    m.remove(id, &mut NoEvents).unwrap();
    assert_eq!(m.shutdowns.len(), 1, "still closing");
    drop(crate::easy::Private {
        multi: m,
        events: Some(table),
    });
    assert_eq!(wire.closed(), [1000]);
    let lines = written.lines();
    let from = lines
        .iter()
        .position(|l| l.contains("[CPOOL]"))
        .unwrap_or_else(|| panic!("{lines:#?}"));
    assert_eq!(
        lines[from..],
        [
            "* [MULTI] [CPOOL] destroy, 0 connections",
            "* [MULTI] [SHUTDOWN] destroy, 1 connections, timeout=0ms",
            "* [MULTI] [SHUTDOWN] shutdown all",
            "* [MULTI] [SHUTDOWN] perform on 1 connections",
            "* [MULTI] [SHUTDOWN] shutdown, done=0",
            "* [MULTI] [SHUTDOWN] shutdown finished, best effort done",
            "* [MULTI] [SHUTDOWN] force closing connection #0",
            "* [MULTI] Curl_multi_will_close fd=1000",
            "* socket cb: socket 1000 REMOVED",
            "* [MULTI] [SHUTDOWN] trigger multi connchanged",
            "* [MULTI] multi_cleanup, closing admin handle, done",
        ],
        "{lines:#?}"
    );
    assert_eq!(
        lines[..2],
        [
            "* call curl_multi_socket_action(socket 1000)",
            "* call curl_multi_socket_action(socket 1000)",
        ]
    );
}

/// Asked to, a multi traces its internal handle's work (as C's debug
/// build does under `CURL_DEBUG`), to standard error.
#[test]
fn a_multi_traces_internally_when_asked() {
    let (mut m, _wire, _clock) = lingering(Linger::UntilPeer);
    assert!(m.shutdowns.internal().is_none());
    m.trace_internally(crate::components::Components::new().unwrap());
    assert!(m.shutdowns.internal().is_some());
}

/// Work done for no transfer is verbose only while the internal trace is
/// on, and says its `infof` lines there, as C's internal handle does.
#[test]
fn work_for_no_transfer_is_said_only_on_the_internal_trace() {
    use crate::conn::layer::LayerCx;
    use crate::time::Clock;
    let now = ManualClock::new().unwrap().now();
    let mut silent = crate::trace::InternalCx { now, trace: None };
    assert!(!silent.verbose());
    silent.info(format_args!("lost"));
    let written = Written::default();
    let trace = crate::trace::Internal::to(
        crate::components::Components::new().unwrap(),
        crate::handler::Handler::text(written.clone()).unwrap(),
    );
    let mut said = crate::trace::InternalCx {
        now,
        trace: Some(&trace),
    };
    assert!(said.verbose());
    said.info(format_args!("said"));
    assert_eq!(written.lines(), ["* said"]);
}

/// What a transfer's debug handler reaches as it hears the socket
/// callback's lines, outside the transfer's step: its options, and
/// whether it could pause it.
#[derive(Clone, Default)]
struct Reached(Arc<Mutex<Vec<(bool, bool)>>>);

impl crate::handler::DebugHandler for Reached {
    fn debug(&self, cx: &mut TransferCx<'_>, kind: crate::handler::DebugKind, data: &[u8]) {
        if kind == crate::handler::DebugKind::Text && data.starts_with(b"socket cb:") {
            let me = cx.me();
            let options = cx.options_mut(me).is_some();
            let paused = cx.pause(me, crate::deliver::PauseRequest::SEND).is_ok();
            self.0.lock().unwrap().push((options, paused));
        }
    }
}

/// A transfer's handlers, called as the event drive's socket callback
/// traces on it, reach its options, but cannot pause it, as only its
/// step may.
#[test]
fn a_handler_hearing_the_socket_callback_reaches_its_transfer() {
    let talk = tls_talk();
    let (mut m, _wire, tls) = over_tls(&talk);
    let mut e = closing_tls(tls);
    let reached = Reached::default();
    e.options_mut().output.verbose = true;
    e.options_mut().callbacks.debug =
        Some(crate::handler::Handler::debug(reached.clone()).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    assert_eq!(super::drive_by_events(&mut m, id), Ok(Ok(())));
    let reached = reached.0.lock().unwrap().clone();
    assert!(!reached.is_empty());
    assert!(
        reached.iter().all(|&(options, paused)| options && !paused),
        "{reached:?}"
    );
}

/// A multi with no internal trace says nothing of a shutdown, its
/// transfer's own lines apart.
#[test]
fn a_multi_without_its_internal_trace_says_no_shutdown() {
    let talk = tls_talk();
    let (mut m, _wire, tls) = over_tls(&talk);
    let mut ev = Rec::default();
    let mut e = closing_tls(tls);
    let written = Written::default();
    e.options_mut().output.verbose = true;
    e.options_mut().callbacks.stderr =
        Some(crate::handler::Handler::text(written.clone()).unwrap());
    let id = m.add(e, (), &mut ev).unwrap();
    by_perform(&mut m, id, &mut ev);
    let lines = written.lines();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("shutting down connection #0")),
        "{lines:#?}"
    );
    assert!(!lines.iter().any(|l| l.contains("SHUTDOWN")), "{lines:#?}");
}

/// A transfer taken out before its end says no goodbye: its connection
/// is closed at once (`cpool_discard_conn`), so the server cannot take
/// the end for a complete one.
#[test]
fn an_aborted_tls_transfer_says_no_goodbye() {
    use crate::tls::fake::WELCOME;
    let talk = Conversation::replies(&[WELCOME], false);
    let (mut m, wire, tls) = over_tls(&talk);
    let mut ev = Rec::default();
    let id = m.add(closing_tls(tls), (), &mut ev).unwrap();
    for _ in 0..5 {
        m.perform(&mut ev).unwrap();
    }
    assert!(!m.state_of(id).is_completed());
    assert_eq!(tls.log().handshakes, 1, "its TLS up, its answer awaited");
    m.remove(id, &mut ev).unwrap();
    assert_eq!(tls.log().closes_sent, 0);
    assert!(!talk.received().ends_with(crate::tls::fake::CLOSE));
    assert_eq!(m.shutdowns.len(), 0);
    assert_eq!(wire.closed(), [1000]);
}

/// Room under a limit closes only as many closing connections as the new
/// one needs, the oldest first (`cpool_check_limits`: those over
/// `live + shutdowns - max + 1`): three shutting down under a limit of
/// three, on one host or in all, lose one to a fourth transfer. Under the
/// limit, each joined with none closed.
#[test]
fn room_closes_only_as_many_closing_connections_as_it_needs() {
    for (host, total) in [(Some(3), None), (None, Some(3))] {
        let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
        let limits = m.conn_limits_mut();
        limits.max_host = host.and_then(NonZeroU32::new);
        limits.max_total = total.and_then(NonZeroU32::new);
        let mut ev = Rec::default();
        for fd in 1000..1003 {
            let id = m.add(closing(1), (), &mut ev).unwrap();
            by_events(&mut m, id, fd, &mut ev);
            m.remove(id, &mut ev).unwrap();
        }
        assert_eq!(wire.closed(), [], "each had room");
        assert_eq!(m.shutdowns.len(), 3);
        let id = m.add(closing(1), (), &mut ev).unwrap();
        m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
        assert_eq!(wire.closed(), [1000], "the oldest alone");
        assert_eq!(m.shutdowns.len(), 2);
        assert!(!matches!(m.state_of(id), state::TransferState::Pending(_)));
    }
}

/// Past a limit that the busy connections alone reach, every closing
/// connection goes, though fewer than the count over it, and the new
/// transfer still waits (`cpool_check_limits`).
#[test]
fn busy_connections_past_the_limit_close_every_closing_one() {
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    let mut ev = Rec::default();
    let a = m.add(closing(1), (), &mut ev).unwrap();
    by_events(&mut m, a, 1000, &mut ev);
    m.remove(a, &mut ev).unwrap();
    let busy = m.add(closing(3), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(m.shutdowns.len(), 1);
    m.conn_limits_mut().max_total = NonZeroU32::new(1);
    let waiting = m.add(closing(2), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(wire.closed(), [1000]);
    assert_eq!(m.shutdowns.len(), 0);
    // Its close lets the new one look again, to find the limit still
    // reached.
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert!(matches!(
        m.state_of(waiting),
        state::TransferState::Pending(_)
    ));
    assert!(!m.state_of(busy).is_completed());
}

/// The set's deadline is the least time left of its connections
/// (`cshutdn_perform`), each counted in whole milliseconds since its
/// connection was made, as C's `start_ms` is: of three released at 1.0,
/// 1.2 and 1.4 ms, made at 0, 0.5 and 1.3 ms, the middle one has spent a
/// millisecond by 1.5 ms, the others none.
#[test]
fn the_set_s_deadline_is_its_least_time_left() {
    let (mut m, _wire, clock) = lingering(Linger::UntilPeer);
    let mut ev = Rec::default();
    let at = |clock: &ManualClock, us: u64, start: Instant| {
        clock.advance(start.after(Duration::from_micros(us)).since(clock.now()));
    };
    let start = clock.now();
    let a = m.add(closing(1), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    at(&clock, 500, start);
    let b = m.add(closing(2), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    at(&clock, 1000, start);
    by_events(&mut m, a, 1000, &mut ev);
    at(&clock, 1200, start);
    by_events(&mut m, b, 1001, &mut ev);
    at(&clock, 1300, start);
    let c = m.add(closing(1), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    at(&clock, 1400, start);
    by_events(&mut m, c, 1002, &mut ev);
    assert_eq!(m.shutdowns.len(), 3);
    at(&clock, 1500, start);
    m.perform(&mut ev).unwrap();
    assert_eq!(m.timeout(), Some(Duration::from_millis(1999)));
}

/// The multi's socket callback, refusing to watch the socket `fd` for the
/// multi itself.
struct Refusing {
    rec: Rec,
    fd: i32,
}

impl MultiEvents<NoHost> for Refusing {
    fn socket(
        &mut self,
        cx: &mut EventCx<'_, NoHost>,
        who: SocketFor,
        s: SocketKey,
        what: SocketWhat,
        p: Option<()>,
    ) -> Result<(), Abort> {
        let multi = matches!(who, SocketFor::Multi);
        self.rec.socket(cx, who, s, what, p)?;
        if multi && s.get() == self.fd && what != SocketWhat::Remove {
            return Err(Abort);
        }
        Ok(())
    }

    fn wants_sockets(&self) -> bool {
        true
    }
}

/// A connection the socket callback refuses to watch as it joins the set
/// is closed at once, and only that one (`Curl_cshutdn_add`, "update
/// events failed"): the idle one joining at the cleanup goes before the
/// one already shutting down, which the cleanup closes after its pass.
#[test]
fn a_connection_the_callback_refuses_is_closed_alone() {
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    let mut ev = Refusing {
        rec: Rec::default(),
        fd: 1001,
    };
    let a = m.add(closing(1), (), &mut ev).unwrap();
    by_events(&mut m, a, 1000, &mut ev);
    let mut idle = closing(2);
    idle.options_mut().limits.reuse.forbid = false;
    let b = m.add(idle, (), &mut ev).unwrap();
    by_events(&mut m, b, 1001, &mut ev);
    m.remove(a, &mut ev).unwrap();
    m.remove(b, &mut ev).unwrap();
    assert_eq!((m.shutdowns.len(), m.caches.pool.len()), (1, 1));
    m.close_connections(&mut ev);
    assert!(
        ev.rec
            .sockets()
            .contains(&Call::Socket(None, 1001, SocketWhat::In)),
        "asked to watch it"
    );
    assert_eq!(wire.closed(), [1001, 1000]);
}

/// An event on a closing connection's socket runs the set once: what is
/// still shutting down then waits for the set's deadline, not at once.
#[test]
fn an_event_runs_the_set_once() {
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    let mut ev = Rec::default();
    let id = m.add(closing(1), (), &mut ev).unwrap();
    by_events(&mut m, id, 1000, &mut ev);
    m.remove(id, &mut ev).unwrap();
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert_eq!(wire.closed(), [], "its peer said nothing");
    assert_eq!(m.timeout(), Some(Duration::from_secs(2)));
}

/// The trace lines of a transfer, as its debug callback has them.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<String>>>);

impl crate::handler::DebugHandler for Lines {
    fn debug(&self, _: &mut TransferCx<'_>, kind: crate::handler::DebugKind, data: &[u8]) {
        if kind == crate::handler::DebugKind::Text {
            let line = String::from_utf8_lossy(data).into_owned();
            self.0.lock().unwrap().push(line);
        }
    }
}

/// A closing connection that closes lets a transfer waiting for room try
/// again (`Curl_cshutdn_terminate` calling `Curl_multi_connchanged`), as
/// its limit may no longer hold: one waiting on a busy host looks again,
/// and waits again, when a connection to another host closes.
#[test]
fn a_closed_connection_lets_a_waiting_transfer_look_again() {
    let (mut m, wire, _clock) = lingering(Linger::UntilPeer);
    m.conn_limits_mut().max_host = NonZeroU32::new(1);
    let mut ev = Rec::default();
    let a = m.add(closing(1), (), &mut ev).unwrap();
    by_events(&mut m, a, 1000, &mut ev);
    m.remove(a, &mut ev).unwrap();
    // A transfer to the host that never answers, and one waiting for it.
    let busy = m.add(closing(3), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    let lines = Lines::default();
    let mut e = closing(3);
    e.options_mut().output.verbose = true;
    e.options_mut().callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    let waiting = m.add(e, (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert!(matches!(
        m.state_of(waiting),
        state::TransferState::Pending(_)
    ));
    let refused = "No more connections allowed to host\n";
    let refusals = |lines: &Lines| {
        lines
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|l| *l == refused)
            .count()
    };
    assert_eq!(refusals(&lines), 1);
    wire.hang_up(1000);
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert_eq!(wire.closed(), [1000]);
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(refusals(&lines), 2, "{:?}", lines.0.lock().unwrap());
    assert!(!m.state_of(busy).is_completed());
}

/// Running the set takes time, as running a transfer does: the timers
/// that came due meanwhile run in the same call (`multi_socket`, its
/// internal handle counted among those run). A transfer whose time runs
/// out as a closing connection closes is done by the call's end.
#[test]
fn the_set_s_run_counts_as_a_run() {
    let (mut m, wire, clock) = lingering(Linger::UntilPeer);
    let mut ev = Rec::default();
    let a = m.add(closing(1), (), &mut ev).unwrap();
    by_events(&mut m, a, 1000, &mut ev);
    m.remove(a, &mut ev).unwrap();
    let mut e = closing(3);
    e.options_mut().limits.total = crate::time::TimeLimit::from_millis(50);
    let late = m.add(e, (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert!(!m.state_of(late).is_completed());
    wire.slow_closes(&clock, Duration::from_millis(100));
    wire.hang_up(1000);
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert_eq!(wire.closed()[0], 1000);
    assert!(m.state_of(late).is_completed(), "run in the same call");
    let done: Vec<_> = std::iter::from_fn(|| m.info_read().map(|msg| msg.result)).collect();
    assert_eq!(done, [Err(ErrorKind::OperationTimedout)]);
}

/// A search of a share's pool may close each of the multi's closing
/// connections under the share's lock: room to hold every one of their
/// sockets until the lock is let go is made first, more than a lease
/// given back closes. Eight shutting down are all closed for a transfer
/// under a total limit of one.
#[test]
fn a_share_s_search_holds_every_closing_socket_it_closes() {
    use crate::share::{Kind, Share};
    let (mut m, wire, _clock) = served(Linger::UntilPeer, 9);
    let share = Share::with_net(Box::new(wire.clone())).unwrap();
    share.keep(Kind::Connections).unwrap();
    let mut ev = Rec::default();
    for fd in 1000..1008 {
        let mut e = closing(1);
        e.set_share(Some(share.clone()));
        let id = m.add(e, (), &mut ev).unwrap();
        by_events(&mut m, id, fd, &mut ev);
        m.remove(id, &mut ev).unwrap();
    }
    assert_eq!(m.shutdowns.len(), 8);
    m.conn_limits_mut().max_total = NonZeroU32::new(1);
    let mut e = closing(1);
    e.set_share(Some(share.clone()));
    let id = m.add(e, (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(wire.closed(), (1000..1008).collect::<Vec<_>>());
    assert_eq!(m.shutdowns.len(), 0);
    assert!(!matches!(m.state_of(id), state::TransferState::Pending(_)));
}

/// The debug build's cleanup lets its connections shut down for as long
/// as `CURL_GRACEFUL_SHUTDOWN` says (`Curl_cshutdn_destroy`), in waits of
/// at most a second (`cshutdn_wait`), and not at all with none shutting
/// down; read in a child of this binary given it, as the environment is
/// the whole process's. C reads `1500ms` as 1500.
#[cfg(feature = "debug-hooks")]
#[test]
fn the_debug_build_s_cleanup_waits_as_told() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "multi::shutdown_tests::graceful_cleanup_in_a_child",
            "--test-threads=1",
        ])
        .env("CURL_CORE_CHILD", "graceful")
        .env("CURL_GRACEFUL_SHUTDOWN", "1500ms")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The child of `the_debug_build_s_cleanup_waits_as_told`.
#[cfg(feature = "debug-hooks")]
#[test]
fn graceful_cleanup_in_a_child() {
    if std::env::var_os("CURL_CORE_CHILD").is_none_or(|m| m != "graceful") {
        return;
    }
    // None shutting down: nothing to wait for.
    let (mut m, _wire, clock) = lingering(Linger::UntilPeer);
    let start = clock.now();
    m.close_connections(&mut NoEvents);
    assert_eq!(clock.now(), start, "no wait");
    // One whose peer never answers: closed once the time is spent, after
    // waits of 1 s and 0.5 s.
    let (mut m, wire, clock) = lingering(Linger::UntilPeer);
    let mut ev = Rec::default();
    let id = m.add(closing(1), (), &mut ev).unwrap();
    by_events(&mut m, id, 1000, &mut ev);
    m.remove(id, &mut ev).unwrap();
    let start = clock.now();
    m.close_connections(&mut ev);
    assert_eq!(clock.now().since(start), Duration::from_millis(1500));
    assert_eq!(wire.closed(), [1000]);
}

/// `CURL_GRACEFUL_SHUTDOWN` is read as `curlx_str_number` reads it: its
/// leading digits, what follows them ignored, up to `INT_MAX`; with no
/// digit first there is no number.
#[cfg(feature = "debug-hooks")]
#[test]
fn the_graceful_time_is_read_as_c_reads_it() {
    assert_eq!(leading_ms(b"1500"), Some(1500));
    assert_eq!(leading_ms(b"1500ms"), Some(1500));
    assert_eq!(leading_ms(b"007"), Some(7));
    assert_eq!(leading_ms(b"2147483647"), Some(2147483647));
    assert_eq!(leading_ms(b"2147483648"), None);
    assert_eq!(leading_ms(b"99999999999"), None);
    for none in [&b""[..], b"+5", b" 5", b"-1", b"x1"] {
        assert_eq!(
            leading_ms(none),
            None,
            "{:?}",
            String::from_utf8_lossy(none)
        );
    }
}
