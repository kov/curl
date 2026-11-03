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
        kind: crate::conn::io::SocketKind,
    ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
        self.0.open(addr, kind)
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
        kind: crate::conn::io::SocketKind,
    ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
        self.0.open(addr, kind)
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
    m.sockets(&mut ev, |k, _| keys.push(k.get())).unwrap();
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
    m.sockets(&mut ev, |k, _| keys.push(k.get())).unwrap();
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
    m.sockets(&mut ev, |k, _| keys.push(k.get())).unwrap();
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
        kind: crate::conn::io::SocketKind,
    ) -> std::io::Result<Box<dyn crate::conn::io::Socket>> {
        self.0.lock().unwrap().open(addr, kind)
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

/// A resolver library whose socket closes and whose next one has the same
/// number: what the application registered is gone, so it is told Remove
/// first (`sock_state_cb`, `Curl_multi_will_close`), and then told of the
/// new one, not left believing nothing changed.
#[test]
fn a_library_s_socket_closing_is_removed_though_its_number_comes_back() {
    #[derive(Debug)]
    struct Reopening {
        wants: Vec<(Box<dyn Socket>, Events)>,
        performed: u32,
        closed: crate::conn::io::SocketsClosed,
    }

    impl crate::conn::io::DnsResolve for Reopening {
        fn perform(&mut self) -> Result<(), curl_alloc::OutOfMemory> {
            self.performed += 1;
            // Past the looks at it as it starts.
            if self.performed == 3 {
                self.closed.said(self.wants[0].0.key())?;
            }
            Ok(())
        }
        fn wants(&self) -> &[(Box<dyn Socket>, Events)] {
            &self.wants
        }
        fn due(&self, within: Duration) -> Duration {
            within
        }
        fn partial(&self) -> Result<crate::conn::io::Partial, curl_alloc::OutOfMemory> {
            Ok(crate::conn::io::Partial {
                addrs: Vec::new(),
                v6_answered: false,
                v4_answered: false,
            })
        }
        fn ongoing(&self) -> (u32, &'static str) {
            (2, "-")
        }
        fn answer(
            &mut self,
        ) -> Option<Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure>> {
            None
        }
        fn record(&mut self) -> Option<crate::doh::RecordAnswer> {
            None
        }
        fn explain(&self) -> Option<&'static str> {
            None
        }
        fn status(&self) -> i32 {
            0
        }
    }

    #[derive(Debug)]
    struct Library(Mutex<Option<Box<dyn Socket>>>);

    impl crate::conn::io::DnsLibrary for Library {
        fn resolve(
            &self,
            ask: crate::conn::io::DnsAsk<'_>,
            _: &mut crate::conn::io::DnsSay<'_>,
        ) -> Result<Box<dyn crate::conn::io::DnsResolve>, crate::conn::io::DnsRefused> {
            let socket = self.0.lock().unwrap().take().unwrap();
            Ok(Box::new(Reopening {
                wants: vec![(socket, Events::IN)],
                performed: 0,
                closed: ask.closed.clone(),
            }))
        }
    }

    let (mut m, clock, mut ev) = networked();
    let mut own =
        FakeNet::new(clock).with_peer(SocketAddr::from(([127, 0, 0, 1], 3)), Peer::Silent);
    let socket = own
        .open(
            &crate::conn::io::Remote::Inet(SocketAddr::from(([127, 0, 0, 1], 3))),
            crate::conn::io::SocketKind::Stream,
        )
        .unwrap();
    let key = socket.key().get();
    let library: &'static Library = Box::leak(Box::new(Library(Mutex::new(Some(socket)))));
    let libraries = crate::libraries::Libraries {
        dns: Some(library),
        ..crate::libraries::Libraries::NONE
    };
    let mut e = easy("http://name.test:80/");
    e.set_libraries(crate::libraries::SharedLibraries::new(libraries).unwrap());
    let id = m.add(Box::new(e), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    m.socket_action(SocketEvent::Socket(SocketKey::new(key)), &mut ev)
        .unwrap();
    assert_eq!(
        ev.calls,
        [
            (id.index(), key, SocketWhat::In, None, 0),
            (id.index(), key, Remove, Some(1), 0),
            (id.index(), key, SocketWhat::In, None, 0),
        ]
    );
    m.remove(id, &mut ev).unwrap();
}

/// A resolver library's resolve that never answers, waiting on a socket
/// that closes as the resolve is dropped, as c-ares's `ares_destroy` closes
/// its channel's.
#[derive(Debug)]
struct Closing {
    wants: Vec<(Box<dyn Socket>, Events)>,
    closed: crate::conn::io::SocketsClosed,
}

impl Drop for Closing {
    fn drop(&mut self) {
        for (socket, _) in &self.wants {
            self.closed.said(socket.key()).unwrap();
        }
    }
}

impl crate::conn::io::DnsResolve for Closing {
    fn perform(&mut self) -> Result<(), curl_alloc::OutOfMemory> {
        Ok(())
    }
    fn wants(&self) -> &[(Box<dyn Socket>, Events)] {
        &self.wants
    }
    fn due(&self, within: Duration) -> Duration {
        within
    }
    fn partial(&self) -> Result<crate::conn::io::Partial, curl_alloc::OutOfMemory> {
        Ok(crate::conn::io::Partial {
            addrs: Vec::new(),
            v6_answered: false,
            v4_answered: false,
        })
    }
    fn ongoing(&self) -> (u32, &'static str) {
        (2, "-")
    }
    fn answer(&mut self) -> Option<Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure>> {
        None
    }
    fn record(&mut self) -> Option<crate::doh::RecordAnswer> {
        None
    }
    fn explain(&self) -> Option<&'static str> {
        None
    }
    fn status(&self) -> i32 {
        0
    }
}

/// A resolver library handing each resolve the next of its sockets, and
/// keeping the family each was asked in.
#[derive(Debug)]
struct ClosingLibrary {
    sockets: Mutex<Vec<Box<dyn Socket>>>,
    asked: Mutex<Vec<crate::conn::io::Family>>,
}

impl crate::conn::io::DnsLibrary for ClosingLibrary {
    fn resolve(
        &self,
        ask: crate::conn::io::DnsAsk<'_>,
        _: &mut crate::conn::io::DnsSay<'_>,
    ) -> Result<Box<dyn crate::conn::io::DnsResolve>, crate::conn::io::DnsRefused> {
        self.asked
            .lock()
            .unwrap()
            .push(ask.family.unwrap_or(crate::conn::io::Family::Any));
        let socket = self.sockets.lock().unwrap().remove(0);
        Ok(Box::new(Closing {
            wants: vec![(socket, Events::IN)],
            closed: ask.closed.clone(),
        }))
    }
}

/// A library of `n` silent sockets over `clock`, their keys, and the
/// libraries a transfer is given to use it.
fn closing_library(
    clock: &ManualClock,
    n: usize,
) -> (
    &'static ClosingLibrary,
    Vec<i32>,
    crate::libraries::SharedLibraries,
) {
    let at = SocketAddr::from(([127, 0, 0, 1], 3));
    let mut own = FakeNet::new(clock.clone()).with_peer(at, Peer::Silent);
    let sockets: Vec<_> = (0..n)
        .map(|_| {
            own.open(
                &crate::conn::io::Remote::Inet(at),
                crate::conn::io::SocketKind::Stream,
            )
            .unwrap()
        })
        .collect();
    let keys = sockets.iter().map(|s| s.key().get()).collect();
    let library: &'static ClosingLibrary = Box::leak(Box::new(ClosingLibrary {
        sockets: Mutex::new(sockets),
        asked: Mutex::new(Vec::new()),
    }));
    let libraries = crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
        dns: Some(library),
        ..crate::libraries::Libraries::NONE
    })
    .unwrap();
    (library, keys, libraries)
}

/// A resolver library's resolve whose socket closes as it is dropped:
/// wherever the transfer lets it go, as it times out or as the application
/// removes it, the close is said (`Curl_multi_will_close`), once.
#[test]
fn a_library_s_resolve_dropped_anywhere_says_its_socket_closed() {
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

    let (mut m, clock, mut ev) = networked();
    let (_, keys, libraries) = closing_library(&clock, 2);
    let told = |ev: &Sockets, key, what| ev.calls.iter().any(|c| c.1 == key && c.2 == what);
    let lines = Lines::default();
    let traced = |url: &str| {
        let mut e = easy(url);
        e.set_libraries(libraries.clone());
        let o = e.options_mut();
        o.output.verbose = true;
        o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
        let c = crate::components::Components::new().unwrap();
        c.configure(b"multi");
        e.set_components(Some(c));
        e
    };
    let closes = |key: i32| {
        let said = format!("Curl_multi_will_close fd={key}");
        let lines = lines.0.lock().unwrap();
        lines.iter().filter(|l| l.contains(&said)).count()
    };

    // Timed out: the step that fails it lets the resolve go.
    let mut e = traced("http://one.test:80/");
    e.options_mut().limits.total = crate::time::TimeLimit::from_millis(50);
    m.add(Box::new(e), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert!(told(&ev, keys[0], SocketWhat::In), "{:?}", ev.calls);
    assert!(!told(&ev, keys[0], Remove), "{:?}", ev.calls);
    clock.advance(Duration::from_millis(50));
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert!(told(&ev, keys[0], Remove), "timed out: {:?}", ev.calls);
    assert_eq!(closes(keys[0]), 1, "timed out");

    // Removed by the application while it resolves.
    let e = traced("http://two.test:80/");
    let two = m.add(Box::new(e), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert!(told(&ev, keys[1], SocketWhat::In), "{:?}", ev.calls);
    m.remove(two, &mut ev).unwrap();
    assert!(told(&ev, keys[1], Remove), "removed: {:?}", ev.calls);
    assert_eq!(closes(keys[1]), 1, "removed");
}

/// A resolve that finds no name: AAAA answers first, the race begun
/// without an address, and then A.
#[derive(Debug)]
struct NoSuchName {
    performed: u32,
}

impl crate::conn::io::DnsResolve for NoSuchName {
    fn perform(&mut self) -> Result<(), curl_alloc::OutOfMemory> {
        self.performed += 1;
        Ok(())
    }
    fn wants(&self) -> &[(Box<dyn Socket>, Events)] {
        &[]
    }
    fn due(&self, within: Duration) -> Duration {
        within.min(Duration::from_millis(100))
    }
    fn partial(&self) -> Result<crate::conn::io::Partial, curl_alloc::OutOfMemory> {
        Ok(crate::conn::io::Partial {
            addrs: Vec::new(),
            v6_answered: self.performed >= 2,
            v4_answered: false,
        })
    }
    fn ongoing(&self) -> (u32, &'static str) {
        match self.performed {
            0 | 1 => (2, "-"),
            2..=4 => (1, "AAAA"),
            _ => (0, "A+AAAA"),
        }
    }
    fn answer(&mut self) -> Option<Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure>> {
        (self.performed > 4).then_some(Err(crate::conn::io::ResolveFailure::NotFound))
    }
    fn record(&mut self) -> Option<crate::doh::RecordAnswer> {
        None
    }
    fn explain(&self) -> Option<&'static str> {
        None
    }
    fn status(&self) -> i32 {
        4
    }
}

#[derive(Debug)]
struct NoSuchNames(Mutex<u32>);

impl crate::conn::io::DnsLibrary for NoSuchNames {
    fn resolve(
        &self,
        _: crate::conn::io::DnsAsk<'_>,
        _: &mut crate::conn::io::DnsSay<'_>,
    ) -> Result<Box<dyn crate::conn::io::DnsResolve>, crate::conn::io::DnsRefused> {
        *self.0.lock().unwrap() += 1;
        Ok(Box::new(NoSuchName { performed: 0 }))
    }
}

/// A resolver library that finds no name, AAAA's answer first, counting
/// what it is asked; and the libraries a handle uses it through.
fn no_such_names() -> (&'static NoSuchNames, crate::libraries::SharedLibraries) {
    let library: &'static NoSuchNames = Box::leak(Box::new(NoSuchNames(Mutex::new(0))));
    let libraries = crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
        dns: Some(library),
        ..crate::libraries::Libraries::NONE
    })
    .unwrap();
    (library, libraries)
}

/// A name a resolver library says does not exist is kept as such in the
/// share the transfer keeps its names in, as the tool's transfers do,
/// however its answer came: AAAA's first, the race begun without an
/// address, and then A's. The next transfer to the name, of another multi
/// with the same share, finds the negative entry and asks no one
/// (`Curl_dnscache_add_negative`).
#[test]
fn a_name_found_not_to_exist_after_the_race_began_is_kept_negative() {
    let (library, libraries) = no_such_names();
    let share = crate::share::Share::new().unwrap();
    share.keep(crate::share::Kind::Names).unwrap();
    for n in 1..=2 {
        let (mut m, _clock, _ev) = networked();
        let mut e = easy("http://nx.test:80/");
        e.set_libraries(libraries.clone());
        e.set_share(Some(share.clone())).unwrap();
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        assert_eq!(
            crate::multi::wait::drive_by_events(&mut m, id),
            Ok(Err(crate::error::ErrorKind::CouldntResolveHost)),
            "transfer {n}"
        );
        m.remove(id, &mut NoEvents).unwrap();
        assert_eq!(*library.0.lock().unwrap(), 1, "asked once, by transfer 1");
    }
}

/// A share's names are kept by the share's clock, whichever multi uses
/// them: an answer kept under a multi whose time is far on goes stale once
/// the share's time passes its timeout, though the next multi's is behind;
/// and one kept under a multi whose time is behind stays good however far
/// the next multi's time goes, while the share's stands still.
#[test]
fn a_share_s_names_age_by_the_share_s_clock_whichever_multi_uses_them() {
    const TIMEOUT: Duration = Duration::from_secs(60);
    let (library, libraries) = no_such_names();
    let kept_by = ManualClock::new().unwrap();
    let share = crate::share::Share::with_env(crate::share::Env {
        clock: Box::new(kept_by.clone()),
        net: Box::new(crate::conn::io::SystemNet::default()),
    })
    .unwrap();
    share.keep(crate::share::Kind::Names).unwrap();
    let (mut late, late_clock, _late_ev) = networked();
    let (mut early, early_clock, _early_ev) = networked();
    late_clock.advance(Duration::from_secs(1000));
    let fetch_from = |m: &mut Multi<Tagged>, url: &str| {
        let mut e = easy(url);
        e.set_libraries(libraries.clone());
        e.set_share(Some(share.clone())).unwrap();
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        assert_eq!(
            crate::multi::wait::drive_by_events(m, id),
            Ok(Err(crate::error::ErrorKind::CouldntResolveHost))
        );
        m.remove(id, &mut NoEvents).unwrap();
        *library.0.lock().unwrap()
    };
    let fetch = |m: &mut Multi<Tagged>| fetch_from(m, "http://nx.test:80/");
    assert_eq!(fetch(&mut late), 1, "asked, and kept");
    assert_eq!(
        fetch(&mut early),
        1,
        "kept, though this multi's time is behind"
    );
    // A negative answer ages twice as fast: half the timeout is all of it.
    kept_by.advance(TIMEOUT / 2);
    assert_eq!(fetch(&mut early), 2, "stale by the share's time");
    // Another name, kept under the multi that is behind: both multis'
    // time running on leaves it good.
    let other = |m: &mut Multi<Tagged>| fetch_from(m, "http://other.test:80/");
    assert_eq!(other(&mut early), 3, "asked, and kept");
    late_clock.advance(TIMEOUT * 100);
    early_clock.advance(TIMEOUT * 100);
    assert_eq!(other(&mut late), 3, "good by the share's time");
}

/// A resolver library is asked only for the families the system can use:
/// IPv4 alone for any where IPv6 does not work (`Curl_async_getaddrinfo`'s
/// `PF_INET`), and not at all for IPv6 alone there.
#[test]
fn a_library_is_asked_for_the_families_the_system_can_use() {
    use crate::conn::io::Family;
    use crate::options::IpVersion;
    for (ipv6, ip, asked) in [
        (true, IpVersion::Any, Some(Family::Any)),
        (true, IpVersion::V6, Some(Family::V6)),
        (true, IpVersion::V4, Some(Family::V4)),
        (false, IpVersion::Any, Some(Family::V4)),
        (false, IpVersion::V4, Some(Family::V4)),
        (false, IpVersion::V6, None),
    ] {
        let clock = ManualClock::new().unwrap();
        let net = FakeNet::new(clock.clone());
        let net = if ipv6 { net } else { net.without_ipv6() };
        let env = Env {
            clock: Box::new(clock.clone()),
            net: Box::new(net),
            arena: ArenaPolicy::new(16, 0).unwrap(),
            waker: None,
        };
        let mut m: Multi<Tagged> = Multi::new(env).unwrap();
        let mut ev = Sockets::default();
        let (library, _, libraries) = closing_library(&clock, 1);
        let mut e = easy("http://name.test:80/");
        e.set_libraries(libraries);
        e.options_mut().ip_version = ip;
        m.add(Box::new(e), (), &mut ev).unwrap();
        m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
        let got = library.asked.lock().unwrap().first().copied();
        assert_eq!(got, asked, "IPv6 works: {ipv6}, {ip:?}");
    }
}

/// A blocking resolve, an interface's name, tells the application of the
/// transfer's progress as it waits, which may stop it (`Curl_async_await`'s
/// `Curl_pgrsUpdate`): the wait ends after its first turn, not at the
/// transfer's limit. How it ended is not the caller's to hear, as C's
/// binding ignores it: the interface is not bound either way.
#[test]
fn a_blocking_resolve_may_be_stopped_by_the_progress_handler() {
    struct Stop;

    impl crate::handler::ProgressHandler for Stop {
        fn progress(
            &self,
            _: &mut TransferCx<'_>,
            _: crate::handler::ProgressNow,
        ) -> crate::handler::ProgressVerdict {
            crate::handler::ProgressVerdict::Abort
        }
    }

    let (mut m, clock, _ev) = networked();
    let (_, _, libraries) = closing_library(&clock, 1);
    let mut e = easy("http://127.0.0.1:3/");
    e.set_libraries(libraries);
    let o = e.options_mut();
    o.limits.total = crate::time::TimeLimit::from_millis(3000);
    o.progress =
        crate::options::Progress::Handler(crate::handler::Handler::progress(Stop).unwrap());
    o.sockets.make_mut().unwrap().local.interface =
        Some(crate::options::Interface::Host(b"bind.test".to_vec()));
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let start = clock.now();
    assert_eq!(
        crate::multi::wait::drive_by_events(&mut m, id),
        Ok(Err(crate::error::ErrorKind::InterfaceFailed))
    );
    // One turn of the wait, a second on the fake clock: not the 3 s limit.
    assert_eq!(clock.now().since(start), Duration::from_secs(1));
}

/// A blocking resolve, an interface's name, lets go of its record as its
/// wait ends, before the transfer is done, rather than with the transfer
/// (`Curl_resolv_blocking`'s `Curl_resolv_destroy`); C's tool binding to
/// `host!NAME` says its `destroy async` there.
#[test]
fn a_blocking_resolve_lets_go_of_its_record_as_its_wait_ends() {
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

    let (mut m, clock, _ev) = networked();
    let (_, _, libraries) = closing_library(&clock, 1);
    let lines = Lines::default();
    let mut e = easy("http://127.0.0.1:3/");
    e.set_libraries(libraries);
    let o = e.options_mut();
    o.limits.total = crate::time::TimeLimit::from_millis(3000);
    o.output.verbose = true;
    o.callbacks.debug = Some(crate::handler::Handler::debug(lines.clone()).unwrap());
    o.sockets.make_mut().unwrap().local.interface =
        Some(crate::options::Interface::Host(b"bind.test".to_vec()));
    let c = crate::components::Components::new().unwrap();
    c.configure(b"dns,multi");
    e.set_components(Some(c));
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    // The library never answers: the bind fails as the wait times out.
    let ended = crate::multi::wait::drive_by_events(&mut m, id);
    assert!(matches!(ended, Ok(Err(_))), "{ended:?}");
    drop(m.remove(id, &mut NoEvents).unwrap());
    let lines = lines.0.lock().unwrap();
    let said: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|l| l.ends_with(" async") || l.contains("multi_done: status"))
        .collect();
    assert_eq!(said.len(), 2, "{lines:#?}");
    assert_eq!(said[0], "[DNS] [1] destroy async", "{lines:#?}");
    assert!(said[1].contains("multi_done: status"), "{lines:#?}");
}

/// A resolver library's resolve that waits on no socket is run again when
/// the library says, whatever stage it holds: resolving, beside a race
/// begun on AAAA's answer, or as the origin's record (`Curl_async_pollset`'s
/// `EXPIRE_ASYNC_NAME`). The multi's timer is that soon, not later.
#[test]
fn a_library_s_resolve_is_run_again_when_it_says() {
    use crate::conn::io::{DnsAsk, DnsLibrary, DnsRefused, DnsResolve, DnsSay, Partial};
    use std::net::IpAddr;

    // Sooner than any other timer of the setup: the wait for AAAA, the
    // race's next attempt.
    const DUE: Duration = Duration::from_millis(10);

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Case {
        Resolving,
        Racing,
        Record,
    }

    #[derive(Debug)]
    struct Waits {
        case: Case,
        record: bool,
    }

    impl DnsResolve for Waits {
        fn perform(&mut self) -> Result<(), curl_alloc::OutOfMemory> {
            Ok(())
        }
        fn wants(&self) -> &[(Box<dyn Socket>, Events)] {
            &[]
        }
        fn due(&self, within: Duration) -> Duration {
            within.min(DUE)
        }
        fn partial(&self) -> Result<Partial, curl_alloc::OutOfMemory> {
            let racing = self.case == Case::Racing;
            let mut addrs = Vec::new();
            if racing {
                addrs.push(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]));
            }
            Ok(Partial {
                addrs,
                v6_answered: racing,
                v4_answered: false,
            })
        }
        fn ongoing(&self) -> (u32, &'static str) {
            (1, "-")
        }
        fn answer(&mut self) -> Option<Result<Vec<IpAddr>, crate::conn::io::ResolveFailure>> {
            (self.case == Case::Record && !self.record)
                .then(|| Ok(vec![IpAddr::from([127, 0, 0, 1])]))
        }
        fn record(&mut self) -> Option<crate::doh::RecordAnswer> {
            None
        }
        fn explain(&self) -> Option<&'static str> {
            None
        }
        fn status(&self) -> i32 {
            0
        }
    }

    #[derive(Debug)]
    struct Library(Case);

    impl DnsLibrary for Library {
        fn resolve(
            &self,
            ask: DnsAsk<'_>,
            _: &mut DnsSay<'_>,
        ) -> Result<Box<dyn DnsResolve>, DnsRefused> {
            Ok(Box::new(Waits {
                case: self.0,
                record: ask.family.is_none(),
            }))
        }
    }

    for case in [Case::Resolving, Case::Racing, Case::Record] {
        let clock = ManualClock::new().unwrap();
        let net = FakeNet::new(clock.clone())
            .with_peer("[::1]:80".parse().unwrap(), crate::conn::io::Peer::Silent)
            .with_peer(
                "127.0.0.1:443".parse().unwrap(),
                crate::conn::io::Peer::Silent,
            );
        let env = Env {
            clock: Box::new(clock.clone()),
            net: Box::new(net),
            arena: ArenaPolicy::new(16, 0).unwrap(),
            waker: None,
        };
        let mut m: Multi<Tagged> = Multi::new(env).unwrap();
        let mut ev = Sockets::default();
        let library: &'static Library = Box::leak(Box::new(Library(case)));
        let tls = Box::leak(Box::new(crate::tls::fake::FakeTls::new().unwrap()));
        let libraries = crate::libraries::SharedLibraries::new(crate::libraries::Libraries {
            dns: Some(library),
            tls: Some(crate::libraries::Library::Static(tls)),
            ..crate::libraries::Libraries::NONE
        })
        .unwrap();
        let url = match case {
            Case::Record => "https://name.test/",
            Case::Resolving | Case::Racing => "http://name.test/",
        };
        let mut e = easy(url);
        e.set_libraries(libraries);
        m.add(Box::new(e), (), &mut ev).unwrap();
        m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
        assert_eq!(m.timeout(), Some(DUE), "{case:?}");
    }
}
