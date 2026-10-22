//! The socket callback, as `lib/multi_ev.c` calls it.

use crate::test_cell::Cell;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use super::*;
use crate::conn::io::{Connect, FakeNet, Peer, PollFd, SocketPoll};
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
        who: TransferId,
        s: SocketKey,
        what: SocketWhat,
        assigned: Option<u32>,
    ) -> Result<(), Abort> {
        self.calls
            .push((who.index(), s.get(), what, assigned, self.closed.get()));
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

    fn connect(&mut self, addr: SocketAddr) -> std::io::Result<(Box<dyn Socket>, Connect)> {
        self.0.connect(addr)
    }

    fn close(&mut self, socket: Box<dyn Socket>) {
        self.1.set(self.1.get() + 1);
        self.0.close(socket);
    }

    fn resolve(
        &mut self,
        name: &[u8],
        family: crate::conn::io::Family,
    ) -> Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure> {
        self.0.resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.0.link_local_scope()
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
        .with_peer(at(4), Peer::AcceptsAfter(Duration::from_millis(5)));
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
    let id = m.add(easy("tcp://127.0.0.1:4/"), (), &mut ev).unwrap();
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
    m.add(easy("tcp://127.0.0.1:3/"), (), &mut ev).unwrap();
    m.perform(&mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.calls, [], "not due, so not run");
}

/// A refused attempt's socket closes before the transfer is assessed, so
/// the application never hears of it.
#[test]
fn a_socket_closed_within_a_run_is_never_announced() {
    let (mut m, _clock, mut ev) = networked();
    m.add(easy("tcp://127.0.0.1:2/"), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(m.counts().running, 0);
    assert_eq!((ev.calls.len(), ev.closed.get()), (0, 1));
}

/// Taking a transfer out mid-connect removes its socket before the
/// socket closes (`Curl_multi_will_close`).
#[test]
fn a_socket_is_removed_before_it_closes() {
    let (mut m, _clock, mut ev) = networked();
    let id = m.add(easy("tcp://127.0.0.1:3/"), (), &mut ev).unwrap();
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
    let id = m.add(easy("tcp://127.0.0.1:3/"), (), &mut ev).unwrap();
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
    let id = m.add(easy("tcp://127.0.0.1:3/"), (), &mut ev).unwrap();
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
            who: TransferId,
            _: SocketKey,
            _: SocketWhat,
            _: Option<()>,
        ) -> Result<(), Abort> {
            self.0.lock().unwrap().push(cx.owner(who).copied());
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
    m.add(easy("tcp://127.0.0.1:3/"), 42, &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(*seen.lock().unwrap(), [Some(42)]);
}

/// A transfer `perform` completed was never assessed after, so the table
/// still lists it; its removal takes it off (`Curl_multi_ev_xfer_done`).
#[test]
fn a_removed_transfer_leaves_its_sockets() {
    let (mut m, clock, mut ev) = networked();
    let id = m.add(easy("tcp://127.0.0.1:4/"), (), &mut ev).unwrap();
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
    m.add(easy("tcp://127.0.0.1:3/"), (), &mut NoEvents)
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
    let id = m.add(easy("tcp://127.0.0.1:3/"), (), &mut ev).unwrap();
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
    m.add(easy("tcp://127.0.0.1:2/"), (), &mut ev).unwrap();
    m.socket_action(SocketEvent::Timeout, &mut ev).unwrap();
    assert_eq!(ev.assigned_in_notify, [Err(UnknownSocket)]);
}
