//! The socket callback, as `lib/multi_ev.c` calls it.

use crate::test_cell::Cell;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use super::*;
use crate::conn::io::Resolver as _;
use crate::conn::io::{FakeNet, Peer, PollFd, SocketPoll};
use crate::conn::threaded::{ResolverThreads, ThreadedResolver, Threads};
use crate::time::ManualClock;

/// A multi whose sockets the application tags with a number.
struct Tagged;

impl Host for Tagged {
    type Transfer = ();
    type Socket = u32;
}

/// One call of the socket callback: the transfer's row, the socket, what
/// it was told, the value assigned, and how many sockets had closed.
type Call = (u32, i32, SocketWhat, Option<u32>, u32);

/// Logs each socket call; tags each socket on its first call with the
/// next number, and aborts the call numbered `abort_at` (from 1).
#[derive(Default)]
struct Sockets {
    calls: Vec<Call>,
    closed: Arc<Cell<u32>>,
    tag: u32,
    abort_at: Option<usize>,
    /// Whether the timer callback aborts.
    abort_timer: bool,
    /// What `assign` gave inside each notification.
    assigned_in_notify: Vec<Result<(), UnknownSocket>>,
}

impl MultiEvents<Tagged> for Sockets {
    fn socket(
        &mut self,
        cx: &mut EventCx<'_, Tagged>,
        who: SocketFor,
        s: SocketKey,
        what: SocketWhat,
        assigned: Option<u32>,
    ) -> Result<(), Abort> {
        let who = match who {
            SocketFor::Transfer(id) => id.index(),
            SocketFor::Multi => u32::MAX,
        };
        self.calls
            .push((who, s.get(), what, assigned, self.closed.get()));
        if assigned.is_none() && what != SocketWhat::Remove {
            self.tag += 1;
            cx.assign(s, Some(self.tag)).unwrap();
        }
        if Some(self.calls.len()) == self.abort_at {
            return Err(Abort);
        }
        Ok(())
    }

    fn wants_sockets(&self) -> bool {
        true
    }

    fn timer(&mut self, _: &mut EventCx<'_, Tagged>, _: TimerChange) -> Result<(), Abort> {
        if self.abort_timer {
            return Err(Abort);
        }
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }

    fn notify(&mut self, cx: &mut NotifyCx<'_, Tagged>, _: Notification) {
        self.assigned_in_notify
            .push(cx.assign(SocketKey::new(7), Some(0)));
    }
}

/// A network that counts the sockets it closes.
struct Counting(FakeNet, Arc<Cell<u32>>);

impl Net for Counting {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.poll(sockets, fds, timeout)
    }

    fn open(
        &mut self,
        addr: &crate::conn::io::Remote,
    ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
        self.0.open(addr)
    }

    fn close(&mut self, socket: crate::conn::io::Sock) {
        self.1.set(self.1.get() + 1);
        self.0.close(socket);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn crate::conn::io::Resolver)) {
        self.0.with_resolver(f);
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.0.link_local_scope()
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: crate::conn::io::Ipv6Scope,
        scope_id: u32,
    ) -> crate::conn::io::InterfaceAddress {
        self.0.interface_address(name, v6, remote_scope, scope_id)
    }
}

/// A multi over peers that refuse (port 2), stay silent (3) and accept
/// after 5 ms (4), and the events that count its closes.
fn networked() -> (Multi<Tagged>, ManualClock, Sockets) {
    let clock = ManualClock::new().unwrap();
    let at = |port| SocketAddr::from(([127, 0, 0, 1], port));
    let closed = Arc::new(Cell::new(0));
    let net = FakeNet::new(clock.clone())
        .with_peer(at(2), Peer::Refuses)
        .with_peer(at(3), Peer::Silent)
        .with_peer(at(4), Peer::AcceptsAfter(Duration::from_millis(5)))
        .with_peer(at(5), Peer::RefusesAfter(Duration::from_millis(5)));
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(Counting(net, closed.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let ev = Sockets {
        closed,
        ..Sockets::default()
    };
    (Multi::new(env).unwrap(), clock, ev)
}

fn easy(url: &str) -> Easy {
    let mut easy = Easy::new();
    easy.options_mut().set_url(Some(url.as_bytes())).unwrap();
    easy
}

use SocketWhat::{Out, Remove};

/// A setup's socket is announced once the transfer has run in
/// `socket_action`, with what it waits for; the transfer runs when its
/// socket is ready, and the socket is removed once no transfer waits on
/// it, though its connection stays open for the next.
#[test]
fn a_transfer_s_socket_is_announced_and_removed() {
    let (mut m, clock, mut ev) = networked();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:4/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.calls, [(id.index(), 1000, Out, None, 0)]);
    // Unknown, so nothing runs; the same, so nothing is told.
    m.socket_action(SocketEvent::Socket(SocketKey::new(7)), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.calls.len(), 1);
    clock.advance(Duration::from_millis(5));
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert_eq!(m.counts().running, 0);
    assert_eq!(
        ev.calls[1..],
        [(id.index(), 1000, Remove, Some(1), 0)],
        "removed with its tag, and left open"
    );
    assert_eq!(m.assign(SocketKey::new(1000), Some(9)), Err(UnknownSocket));
}

/// `perform` runs transfers without telling the socket callback, so one
/// it ran is announced only when it next runs in `socket_action`.
#[test]
fn perform_tells_the_socket_callback_nothing() {
    let (mut m, _clock, mut ev) = networked();
    m.add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut ev)
        .unwrap();
    m.perform(&mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.calls, [], "not due, so not run");
}

/// An attempt that fails once announced is removed, as its setup is
/// driven, before its socket closes (`Curl_multi_will_close`).
#[test]
fn an_attempt_failing_in_a_drive_is_removed_before_it_closes() {
    let (mut m, clock, mut ev) = networked();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:5/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    clock.advance(Duration::from_millis(5));
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert_eq!(
        ev.calls,
        [
            (id.index(), 1000, Out, None, 0),
            (id.index(), 1000, Remove, Some(1), 0),
        ]
    );
    assert_eq!(ev.closed.get(), 1);
}

/// An attempt's connect under way is polled at the transfer's next run,
/// not in the run that started it (`cf_tcp_connect` returns at once on
/// `EINPROGRESS`): even a peer that refuses at once has its socket
/// announced, then removed as the next run finds it refused.
#[test]
fn a_refused_attempt_is_announced_before_it_is_found_refused() {
    let (mut m, _clock, mut ev) = networked();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:2/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(m.counts().running, 1);
    assert_eq!(ev.calls, [(id.index(), 1000, Out, None, 0)]);
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert_eq!(m.counts().running, 0);
    assert_eq!(ev.calls[1..], [(id.index(), 1000, Remove, Some(1), 0)]);
    assert_eq!(ev.closed.get(), 1);
}

/// Taking a transfer out mid-connect removes its socket before the
/// socket closes (`Curl_multi_will_close`).
#[test]
fn a_socket_is_removed_before_it_closes() {
    let (mut m, _clock, mut ev) = networked();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    m.remove(id, &mut ev).unwrap();
    assert_eq!(
        ev.calls,
        [
            (id.index(), 1000, Out, None, 0),
            (id.index(), 1000, Remove, Some(1), 0),
        ]
    );
    assert_eq!(ev.closed.get(), 1);
}

/// A pause that leaves a setup waiting on nothing removes its socket; an
/// unpause announces it again, untagged as a new entry is.
#[test]
fn a_pause_is_heard_inside_the_call() {
    let (mut m, _clock, mut ev) = networked();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    m.pause(id, PauseRequest::RECV, &mut ev).unwrap();
    m.pause(id, PauseRequest::RECV, &mut ev).unwrap();
    m.pause(id, PauseRequest::CONT, &mut ev).unwrap();
    assert_eq!(
        ev.calls,
        [
            (id.index(), 1000, Out, None, 0),
            (id.index(), 1000, Remove, Some(1), 0),
            (id.index(), 1000, Out, None, 0),
        ],
        "the second pause changed nothing"
    );
}

/// A socket callback that aborts ends `socket_action` with the abort,
/// and the multi fails its transfers from then on.
#[test]
fn an_aborting_socket_callback_kills_the_multi() {
    let (mut m, _clock, mut ev) = networked();
    ev.abort_at = Some(1);
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut ev)
        .unwrap();
    assert_eq!(
        m.socket_action(SocketEvent::Timeout, &mut ev),
        Err(MultiErrorKind::AbortedByCallback)
    );
    // A dead multi fails each transfer it runs.
    m.perform(&mut ev).unwrap();
    let msg = m.info_read().unwrap();
    assert_eq!(
        (msg.id, msg.result),
        (id, Err(ErrorKind::AbortedByCallback))
    );
}

/// The handlers of a socket callback see the multi's transfers.
#[test]
fn the_socket_callback_sees_the_transfers() {
    struct Owners(Arc<Mutex<Vec<Option<u8>>>>);
    struct Host8;
    impl Host for Host8 {
        type Transfer = u8;
        type Socket = ();
    }
    impl MultiEvents<Host8> for Owners {
        fn socket(
            &mut self,
            cx: &mut EventCx<'_, Host8>,
            who: SocketFor,
            _: SocketKey,
            _: SocketWhat,
            _: Option<()>,
        ) -> Result<(), Abort> {
            let owner = match who {
                SocketFor::Transfer(id) => cx.owner(id).copied(),
                SocketFor::Multi => None,
            };
            self.0.lock().unwrap().push(owner);
            Ok(())
        }
        fn wants_sockets(&self) -> bool {
            true
        }
    }
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], 3));
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock).with_peer(at, Peer::Silent)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi<Host8> = Multi::new(env).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut ev = Owners(seen.clone());
    m.add(Box::new(easy("tcp://127.0.0.1:3/")), 42, &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(*seen.lock().unwrap(), [Some(42)]);
}

/// A transfer `perform` completed was never assessed after, so the table
/// still lists it; its removal takes it off (`Curl_multi_ev_xfer_done`).
#[test]
fn a_removed_transfer_leaves_its_sockets() {
    let (mut m, clock, mut ev) = networked();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:4/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    clock.advance(Duration::from_millis(5));
    m.perform(&mut ev).unwrap();
    assert_eq!(m.counts().running, 0);
    assert_eq!(ev.calls.len(), 1, "perform tells nothing");
    m.remove(id, &mut ev).unwrap();
    assert_eq!(
        ev.calls[1..],
        [(id.index(), 1000, Remove, Some(1), 0)],
        "the connection stays open"
    );
}

/// Without a socket callback the multi records no socket, as C keeps
/// none, so there is none to assign a value to.
#[test]
fn without_a_socket_callback_no_socket_is_recorded() {
    let (mut m, _clock, _) = networked();
    m.add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut NoEvents)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut NoEvents)
        .unwrap();
    assert_eq!(m.assign(SocketKey::new(1000), Some(1)), Err(UnknownSocket));
}

/// A timer callback that aborts inside a pause ends it before the socket
/// callback hears of the change (easy.c:1233).
#[test]
fn a_timer_abort_inside_a_pause_tells_the_sockets_nothing() {
    let (mut m, _clock, mut ev) = networked();
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:3/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    ev.abort_timer = true;
    assert_eq!(
        m.pause(id, PauseRequest::RECV, &mut ev),
        Err(ErrorKind::AbortedByCallback)
    );
    assert_eq!(ev.calls, [(id.index(), 1000, Out, None, 0)]);
}

/// A notification's handler assigns through its context, as anywhere.
#[test]
fn a_notification_assigns_as_the_multi_does() {
    let (mut m, _clock, mut ev) = networked();
    m.set_notify(NotifyKind::EasyDone, true);
    m.add(Box::new(easy("tcp://127.0.0.1:2/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert_eq!(ev.assigned_in_notify, [Err(UnknownSocket)]);
}

/// A resolver lent with a wake of its own, as the threaded resolver's,
/// answering through the fake network's.
struct Woken<'r>(
    &'r mut dyn crate::conn::io::Resolver,
    TryArc<Waker>,
    Option<ResolverThreads>,
);

impl crate::conn::io::Resolver for Woken<'_> {
    fn start(
        &mut self,
        name: &[u8],
        family: crate::conn::io::Family,
        waiter: crate::conn::io::Waiter,
    ) -> Result<crate::conn::io::Resolve, crate::conn::io::ResolveFailure> {
        self.0.start(name, family, waiter)
    }

    fn answer(
        &mut self,
        id: crate::conn::io::ResolveId,
    ) -> Option<Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure>> {
        self.0.answer(id)
    }

    fn wait(
        &mut self,
        id: crate::conn::io::ResolveId,
    ) -> Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure> {
        self.0.wait(id)
    }

    fn cancel(&mut self, id: crate::conn::io::ResolveId) {
        self.0.cancel(id);
    }

    fn answered(
        &mut self,
        each: &mut dyn FnMut(crate::conn::io::Waiter, crate::conn::io::ResolveId),
    ) {
        self.0.answered(each);
    }

    fn waker(&self) -> Option<TryArc<Waker>> {
        Some(self.1.clone())
    }

    fn explain(&self, why: crate::conn::io::ResolveFailure) -> Option<&'static str> {
        self.0.explain(why)
    }

    fn pool(&self) -> Option<ResolverThreads> {
        self.2.clone()
    }
}

/// The fake network, its resolver woken by `.1`.
struct Waking(FakeNet, TryArc<Waker>, Option<ResolverThreads>);

impl Net for Waking {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.poll(sockets, fds, timeout)
    }

    fn open(
        &mut self,
        addr: &crate::conn::io::Remote,
    ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
        self.0.open(addr)
    }

    fn close(&mut self, socket: crate::conn::io::Sock) {
        self.0.close(socket);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn crate::conn::io::Resolver)) {
        let waker = self.1.clone();
        let pool = self.2.clone();
        self.0
            .with_resolver(&mut |r| f(&mut Woken(r, waker.clone(), pool.clone())));
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.0.link_local_scope()
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: crate::conn::io::Ipv6Scope,
        scope_id: u32,
    ) -> crate::conn::io::InterfaceAddress {
        self.0.interface_address(name, v6, remote_scope, scope_id)
    }
}

/// With a resolver that answers later, the multi listens on its wake
/// while a transfer is alive, as its own (C's admin handle and
/// `multi_assess_wakeup`): told to the socket callback as the first
/// transfer comes alive, before that transfer's sockets, and removed as
/// the last is done; `multi_wait` counts it among its descriptors.
#[test]
fn the_resolver_s_wake_is_listened_on_while_a_transfer_is_alive() {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], 4));
    let net =
        FakeNet::new(clock.clone()).with_peer(at, Peer::AcceptsAfter(Duration::from_millis(5)));
    let waker = TryArc::try_new(Waker::new().unwrap()).unwrap();
    let wake = std::os::fd::AsRawFd::as_raw_fd(&waker.fd());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(Waking(net, waker.clone(), None)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi<Tagged> = Multi::new(env).unwrap();
    let mut ev = Sockets::default();
    let mut keys = Vec::new();
    m.sockets(&mut ev, |k, _| keys.push(k.get()));
    assert_eq!(keys, [], "no transfer alive");
    let id = m
        .add(Box::new(easy("tcp://127.0.0.1:4/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(
        ev.calls,
        [
            (u32::MAX, wake, SocketWhat::In, None, 0),
            (id.index(), 1000, Out, None, 0)
        ]
    );
    let mut keys = Vec::new();
    m.sockets(&mut ev, |k, _| keys.push(k.get()));
    assert_eq!(keys, [wake, 1000], "the resolver's first");
    clock.advance(Duration::from_millis(5));
    m.socket_action(SocketEvent::Socket(SocketKey::new(1000)), &mut ev)
        .unwrap();
    assert_eq!(m.counts().running, 0);
    assert!(
        ev.calls.contains(&(u32::MAX, wake, Remove, Some(1), 0)),
        "{:?}",
        ev.calls
    );
    let mut keys = Vec::new();
    m.sockets(&mut ev, |k, _| keys.push(k.get()));
    assert_eq!(keys, [], "none alive");
}

/// The resolver's settings reach the pool it answers from, from the
/// multi and from inside its callbacks (`CURLMOPT_RESOLVE_THREADS_MAX`,
/// `CURLMOPT_QUICK_EXIT`).
#[test]
fn the_resolver_s_settings_reach_its_pool() {
    /// Sets from the first timer callback, and from each notification.
    struct Setting(bool);
    impl MultiEvents<Tagged> for Setting {
        fn wants_timer(&self) -> bool {
            true
        }
        fn timer(&mut self, cx: &mut EventCx<'_, Tagged>, _: TimerChange) -> Result<(), Abort> {
            if !std::mem::replace(&mut self.0, true) {
                cx.set_resolve_threads_max(NonZeroU32::new(7).unwrap());
                cx.set_quick_exit(false);
            }
            Ok(())
        }
        fn notify(&mut self, cx: &mut NotifyCx<'_, Tagged>, _: Notification) {
            cx.set_resolve_threads_max(NonZeroU32::new(5).unwrap());
            cx.set_quick_exit(true);
        }
    }
    let threaded = ThreadedResolver::new(Threads::MULTI).unwrap();
    let pool = threaded.pool().unwrap();
    let clock = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(Waking(
            FakeNet::new(clock),
            threaded.waker().unwrap(),
            Some(pool.clone()),
        )),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi<Tagged> = Multi::new(env).unwrap();
    assert_eq!(pool.settings(), (20, true));
    m.set_resolve_threads_max(NonZeroU32::new(3).unwrap());
    m.set_quick_exit(true);
    assert_eq!(pool.settings(), (3, false));
    m.set_notify(NotifyKind::EasyDone, true);
    let mut ev = Setting(false);
    m.add(Box::new(easy("tcp://127.0.0.1:4/")), (), &mut ev)
        .unwrap();
    assert_eq!(pool.settings(), (7, true), "set inside the timer callback");
    // No peer listens: the transfer is done as it runs.
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(pool.settings(), (5, false), "set inside the notification");
}

/// An easy handle's quick exit is its multi's as `curl_easy_perform`
/// runs it there (`CURLOPT_QUICK_EXIT`).
#[test]
fn an_easy_handle_s_quick_exit_is_its_multi_s() {
    let threaded = ThreadedResolver::new(Threads::EASY).unwrap();
    let pool = threaded.pool().unwrap();
    let clock = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(Waking(
            FakeNet::new(clock),
            threaded.waker().unwrap(),
            Some(pool.clone()),
        )),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let mut e = easy("tcp://127.0.0.1:1/");
    e.options_mut().quick_exit = true;
    // No peer listens: the transfer fails, its multi set first.
    assert!(e.perform_in(&mut m, crate::easy::Drive::Waits).is_err());
    assert_eq!(pool.settings(), (2, false));
    e.options_mut().quick_exit = false;
    assert!(e.perform_in(&mut m, crate::easy::Drive::Waits).is_err());
    assert_eq!(pool.settings(), (2, true));
}

/// A resolver whose queries wait for a thread it could not start: it
/// tells no answer, and asks to be tried again in 100 ms.
struct Stalled<'r>(&'r mut dyn crate::conn::io::Resolver);

impl crate::conn::io::Resolver for Stalled<'_> {
    fn start(
        &mut self,
        name: &[u8],
        family: crate::conn::io::Family,
        waiter: crate::conn::io::Waiter,
    ) -> Result<crate::conn::io::Resolve, crate::conn::io::ResolveFailure> {
        self.0.start(name, family, waiter)
    }

    fn answer(
        &mut self,
        id: crate::conn::io::ResolveId,
    ) -> Option<Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure>> {
        self.0.answer(id)
    }

    fn wait(
        &mut self,
        id: crate::conn::io::ResolveId,
    ) -> Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure> {
        self.0.wait(id)
    }

    fn cancel(&mut self, id: crate::conn::io::ResolveId) {
        self.0.cancel(id);
    }

    fn answered(&mut self, _: &mut dyn FnMut(crate::conn::io::Waiter, crate::conn::io::ResolveId)) {
    }

    fn waker(&self) -> Option<TryArc<Waker>> {
        None
    }

    fn explain(&self, why: crate::conn::io::ResolveFailure) -> Option<&'static str> {
        self.0.explain(why)
    }

    fn retry(&self) -> Option<Duration> {
        Some(Duration::from_millis(100))
    }
}

/// The fake network, its resolver `Stalled`.
struct Stalling(Arc<Mutex<FakeNet>>);

impl Net for Stalling {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.lock().unwrap().poll(sockets, fds, timeout)
    }

    fn open(
        &mut self,
        addr: &crate::conn::io::Remote,
    ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
        self.0.lock().unwrap().open(addr)
    }

    fn close(&mut self, socket: crate::conn::io::Sock) {
        self.0.lock().unwrap().close(socket);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn crate::conn::io::Resolver)) {
        self.0
            .lock()
            .unwrap()
            .with_resolver(&mut |r| f(&mut Stalled(r)));
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.0.lock().unwrap().link_local_scope()
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: crate::conn::io::Ipv6Scope,
        scope_id: u32,
    ) -> crate::conn::io::InterfaceAddress {
        self.0
            .lock()
            .unwrap()
            .interface_address(name, v6, remote_scope, scope_id)
    }
}

/// A resolve whose queries wait for a thread is tried again by the
/// transfer's own timer, 100 ms on (`EXPIRE_ASYNC_NAME`), though nothing
/// tells of an answer: the timer runs the transfer, which takes it.
#[test]
fn a_stalled_resolve_is_tried_again_by_its_timer() {
    use crate::conn::io::Late;
    let clock = ManualClock::new().unwrap();
    let late = Late::new();
    let at = SocketAddr::from(([127, 0, 0, 1], 4));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_late_name("late.test", &[[127, 0, 0, 1].into()], &late);
    let net = Arc::new(Mutex::new(net));
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(Stalling(net.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi<Tagged> = Multi::new(env).unwrap();
    let mut ev = Sockets::default();
    m.add(Box::new(easy("tcp://late.test:4/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(m.timeout(), Some(Duration::from_millis(100)));
    assert_eq!(net.lock().unwrap().resolving(), 1);
    late.release();
    // Not yet due: the transfer is not run, the answer not taken.
    clock.advance(Duration::from_millis(99));
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(net.lock().unwrap().resolving(), 1);
    clock.advance(Duration::from_millis(1));
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(net.lock().unwrap().resolving(), 0, "the timer took it");
}

/// Driven by its events alone (`easy_events`), a transfer whose multi
/// listens on the resolver's wake polls the wake with its own sockets: it
/// is the multi's, in no transfer's pollset, and was told as one.
#[test]
fn a_transfer_driven_by_events_polls_the_resolver_s_wake() {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], 4));
    let net =
        FakeNet::new(clock.clone()).with_peer(at, Peer::AcceptsAfter(Duration::from_millis(5)));
    let waker = TryArc::try_new(Waker::new().unwrap()).unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(Waking(net, waker.clone(), None)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi<Tagged> = Multi::new(env).unwrap();
    let id = m
        .add(
            Box::new(easy("tcp://127.0.0.1:4/")),
            (),
            &mut Sockets::default(),
        )
        .unwrap();
    let start = crate::time::Clock::now(&clock);
    assert_eq!(super::wait::drive_by_events(&mut m, id), Ok(Ok(())));
    let spent = crate::time::Clock::now(&clock).since(start);
    assert_eq!(spent, Duration::from_millis(5), "waited for the connect");
}

/// `multi_wait` polls the resolver's wake only while a transfer is alive,
/// and counts it among the descriptors ready, as C's admin handle's
/// pollset; a transfer waiting on its resolve alone has the wake to wait
/// on.
#[test]
fn a_wait_polls_the_resolver_s_wake_while_a_transfer_is_alive() {
    use crate::conn::io::Late;
    let clock = ManualClock::new().unwrap();
    let late = Late::new();
    let net =
        FakeNet::new(clock.clone()).with_late_name("late.test", &[[127, 0, 0, 1].into()], &late);
    let wake = TryArc::try_new(Waker::new().unwrap()).unwrap();
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(Waking(net, wake.clone(), None)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi<Tagged> = Multi::new(env).unwrap();
    let mut ev = Sockets::default();
    wake.wake().unwrap();
    let wait = |m: &mut Multi<Tagged>, ev: &mut Sockets| {
        m.wait(&mut [], Duration::ZERO, WaitMode::Wait, ev)
    };
    assert_eq!(wait(&mut m, &mut ev), Ok(0), "none alive: not polled");
    m.add(Box::new(easy("tcp://late.test:4/")), (), &mut ev)
        .unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(wait(&mut m, &mut ev), Ok(1), "polled, and ready");
    wake.drain().unwrap();
    assert_eq!(wait(&mut m, &mut ev), Ok(0), "polled, not ready");
}
