//! Connections shutting down in the multi's set (`lib/cshutdn.c`), armed
//! by a test layer whose shutdown waits, as TLS's close_notify will. The
//! oracle is the reference build's lib758 sequence: a connection entering
//! shutdown keeps its socket registered with no socket callback, its
//! transfer gone from it, and the callback hears REMOVE, from the multi's
//! internal handle, only when the set closes it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::*;
use crate::conn::io::{
    Conversation, FakeNet, Family, Peer, PollFd, ResolveFailure, Sock, SocketPoll,
};
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
struct Wire(Arc<Mutex<(FakeNet, Vec<i32>)>>);

impl Wire {
    fn closed(&self) -> Vec<i32> {
        self.0.lock().unwrap().1.clone()
    }

    fn hang_up(&self, fd: i32) {
        self.0.lock().unwrap().0.hang_up(SocketKey::new(fd));
    }

    fn open(&self) -> usize {
        self.0.lock().unwrap().0.open_sockets()
    }
}

impl Net for Wire {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.lock().unwrap().0.poll(sockets, fds, timeout)
    }

    fn open(&mut self, addr: SocketAddr) -> std::io::Result<Box<dyn Socket>> {
        self.0.lock().unwrap().0.open(addr)
    }

    fn close(&mut self, socket: Sock) {
        let mut w = self.0.lock().unwrap();
        w.1.push(socket.key().get());
        w.0.close(socket);
    }

    fn resolve(
        &mut self,
        name: &[u8],
        family: Family,
    ) -> Result<Vec<std::net::IpAddr>, ResolveFailure> {
        self.0.lock().unwrap().0.resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        None
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
    let wire = Wire(Arc::new(Mutex::new((fake, Vec::new()))));
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
fn by_events(m: &mut Multi, id: TransferId, fd: i32, ev: &mut Rec) {
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
fn by_perform(m: &mut Multi, id: TransferId, ev: &mut Rec) {
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
    m.sockets(&mut NoEvents, |s, e| waited.push((s.key().get(), e)));
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
