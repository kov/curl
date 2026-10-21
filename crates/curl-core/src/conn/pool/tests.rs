use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::conn::io::{FakeNet, Peer};
use crate::conn::{Destination, Scheme};
use crate::time::{Clock as _, ManualClock};

const TCP: Scheme = Scheme {
    name: "tcp",
    reuse: true,
};

const RULES: ReuseRules = ReuseRules {
    max_idle: Some(Duration::from_secs(118)),
    max_age: Some(Duration::from_secs(24 * 3600)),
};

fn net() -> (FakeNet, ManualClock) {
    let clock = ManualClock::new().unwrap();
    let at = |port| SocketAddr::from(([127, 0, 0, 1], port));
    let net = FakeNet::new(clock.clone())
        .with_peer(at(1), Peer::Accepts)
        .with_peer(at(2), Peer::Refuses)
        .with_peer(at(3), Peer::Silent)
        .with_peer(at(4), Peer::Accepts);
    (net, clock)
}

fn tcp(port: u16) -> Route {
    Route::Tcp(TCP, Destination::new(b"127.0.0.1", port).unwrap())
}

/// A connection for `route`, which must be new; the search says nothing.
fn new(pool: &mut Pool, route: Route, net: &mut FakeNet, now: Instant) -> ConnLease {
    let mut notes = Vec::new();
    let Acquired::New(lease) = pool.acquire(route, RULES, net, now, &mut notes).unwrap() else {
        panic!("reused");
    };
    assert_eq!(notes, []);
    lease
}

/// Connect `lease`, whose peer accepts.
fn up(pool: &mut Pool, lease: &ConnLease, net: &mut FakeNet, now: Instant) {
    pool.connect(lease, net, now).unwrap();
    let established = pool.connect(lease, net, now).unwrap();
    assert!(matches!(established, Connected::Established { .. }));
}

fn socket(pool: &Pool, lease: &ConnLease) -> Option<i32> {
    pool.socket(lease).map(|s| s.key().get())
}

#[test]
fn local_connections_are_numbered_and_closed_when_released() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let a = new(&mut pool, Route::Local, &mut net, now);
    let b = new(&mut pool, Route::Local, &mut net, now);
    assert_ne!(a.id(), b.id(), "a local connection is never shared");
    assert_eq!(pool.get(&a).number.to_string(), "#0");
    assert_eq!(pool.get(&b).number.to_string(), "#1");
    assert_eq!(pool.len(), 2);
    let a_id = a.id();
    assert_eq!(
        pool.release(a, Finish::default(), &mut net, now),
        Released::Closed(ConnNumber(0))
    );
    assert!(pool.get_conn(a_id).is_none());
    assert_eq!(pool.get_conn(b.id()).map(|c| c.number), Some(ConnNumber(1)));
    let premature = Finish { premature: true };
    assert_eq!(
        pool.release(b, premature, &mut net, now),
        Released::Terminated(ConnNumber(1))
    );
    assert_eq!(pool.len(), 0);
    // Numbers are never reused.
    let c = new(&mut pool, Route::Local, &mut net, now);
    assert_eq!(pool.get(&c).number.to_string(), "#2");
    assert_eq!(
        pool.release(c, Finish::default(), &mut net, now),
        Released::Closed(ConnNumber(2))
    );
}

/// A setup tries its address, waits, and is established in the slot it
/// started in; its socket is the pool's to wait on until then.
#[test]
fn a_tcp_connection_is_set_up_in_its_slot() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let lease = new(&mut pool, tcp(1), &mut net, now);
    let id = lease.id();
    assert_eq!(
        socket(&pool, &lease),
        None,
        "nothing open before the first drive"
    );
    let tried = pool.connect(&lease, &mut net, now).unwrap();
    let to = SocketAddr::from(([127, 0, 0, 1], 1));
    assert!(matches!(tried, Connected::Connecting(Progress::Trying(a)) if a == to));
    assert_eq!(socket(&pool, &lease), Some(1000), "the attempt's");
    assert!(pool.get_conn(id).is_none(), "not up yet");
    let up = pool.connect(&lease, &mut net, now).unwrap();
    let Connected::Established { remote, local, at } = up else {
        panic!("{up:?}");
    };
    assert_eq!((remote, at), (to, now));
    assert_eq!(local, Some(SocketAddr::from(([127, 0, 0, 1], 40000))));
    assert_eq!(pool.get_conn(id).map(|c| c.number), Some(ConnNumber(0)));
    assert!(matches!(
        pool.connect(&lease, &mut net, now),
        Ok(Connected::AlreadyUp)
    ));
    assert_eq!(socket(&pool, &lease), Some(1000), "kept once up");
    let premature = Finish { premature: true };
    assert_eq!(
        pool.release(lease, premature, &mut net, now),
        Released::Terminated(ConnNumber(0))
    );
    assert_eq!(net.open_sockets(), 0, "its socket was closed");
}

/// A refused attempt closes its socket and says from where it tried; a
/// silent one waits.
#[test]
fn refused_and_silent_attempts() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let refused = new(&mut pool, tcp(2), &mut net, now);
    pool.connect(&refused, &mut net, now).unwrap();
    let err = pool.connect(&refused, &mut net, now).unwrap_err();
    let ConnectError::Attempt {
        remote,
        local,
        error,
    } = err
    else {
        panic!("{err:?}");
    };
    assert_eq!(remote.port(), 2);
    assert_eq!(local.map(|l| l.port()), Some(40000));
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert_eq!(
        net.open_sockets(),
        0,
        "the failed attempt's socket is closed"
    );
    let silent = new(&mut pool, tcp(3), &mut net, now);
    pool.connect(&silent, &mut net, now).unwrap();
    for _ in 0..3 {
        let waiting = pool.connect(&silent, &mut net, now).unwrap();
        assert!(matches!(waiting, Connected::Connecting(Progress::Waiting)));
    }
    assert_eq!(net.open_sockets(), 1);
    let premature = Finish { premature: true };
    assert_eq!(
        pool.release(refused, premature, &mut net, now),
        Released::Terminated(ConnNumber(0))
    );
    assert_eq!(
        pool.release(silent, premature, &mut net, now),
        Released::Terminated(ConnNumber(1))
    );
    assert_eq!(net.open_sockets(), 0);
}

/// A name with no address, and an address with no peer, fail before any
/// socket is polled.
#[test]
fn unresolved_names_and_immediate_failures() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let named = Route::Tcp(TCP, Destination::new(b"example.com", 80).unwrap());
    let named = new(&mut pool, named, &mut net, now);
    let err = pool.connect(&named, &mut net, now).unwrap_err();
    assert!(matches!(err, ConnectError::Unresolved), "{err:?}");
    let nobody = new(&mut pool, tcp(9), &mut net, now);
    let err = pool.connect(&nobody, &mut net, now).unwrap_err();
    assert!(
        matches!(err, ConnectError::Immediate { remote, .. } if remote.port() == 9),
        "{err:?}"
    );
    let premature = Finish { premature: true };
    for lease in [named, nobody] {
        assert!(matches!(
            pool.release(lease, premature, &mut net, now),
            Released::Terminated(_)
        ));
    }
    assert_eq!(pool.len(), 0);
}

/// A connection given back whole is kept idle and reused by an equal
/// route only; one cut short is closed.
#[test]
fn a_finished_connection_is_kept_for_an_equal_route() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let first = new(&mut pool, tcp(1), &mut net, now);
    up(&mut pool, &first, &mut net, now);
    let id = first.id();
    assert_eq!(
        pool.release(first, Finish::default(), &mut net, now),
        Released::Idle(ConnNumber(0))
    );
    assert_eq!(net.open_sockets(), 1, "kept open");
    // Another port is another route.
    let other = new(&mut pool, tcp(4), &mut net, now);
    assert_ne!(other.id(), id);
    let mut notes = Vec::new();
    let again = pool
        .acquire(tcp(1), RULES, &mut net, now, &mut notes)
        .unwrap();
    let Acquired::Reused(again) = again else {
        panic!("{again:?}");
    };
    assert_eq!((again.id(), notes), (id, vec![]));
    // Leased again: a third transfer cannot have it.
    let third = new(&mut pool, tcp(1), &mut net, now);
    let premature = Finish { premature: true };
    for lease in [other, third] {
        pool.release(lease, premature, &mut net, now);
    }
    assert_eq!(
        pool.release(again, premature, &mut net, now),
        Released::Terminated(ConnNumber(0))
    );
    assert_eq!((pool.len(), net.open_sockets()), (0, 0));
    // A protocol that keeps no connection closes it.
    let once = Scheme {
        name: "once",
        reuse: false,
    };
    let route = Route::Tcp(once, Destination::new(b"127.0.0.1", 1).unwrap());
    let lease = new(&mut pool, route, &mut net, now);
    up(&mut pool, &lease, &mut net, now);
    assert!(matches!(
        pool.release(lease, Finish::default(), &mut net, now),
        Released::Closed(_)
    ));
}

/// An idle connection with something to read, or idle or alive too long,
/// is closed when a search meets it; the search goes on to the next.
#[test]
fn a_search_closes_what_it_must_not_reuse() {
    let (mut net, clock) = net();
    let mut pool = Pool::new().unwrap();
    let key = |pool: &mut Pool, lease: &ConnLease| match &pool.get(lease).transport {
        Transport::Tcp(s) => s.key(),
        Transport::Local => unreachable!(),
    };
    let kept = |pool: &mut Pool, net: &mut FakeNet| {
        let now = clock.now();
        let lease = new(pool, tcp(1), net, now);
        up(pool, &lease, net, now);
        pool.release(lease, Finish::default(), net, now);
    };
    let search = |pool: &mut Pool, net: &mut FakeNet, rules| {
        let mut notes = Vec::new();
        let got = pool
            .acquire(tcp(1), rules, net, clock.now(), &mut notes)
            .unwrap();
        (got, notes)
    };
    // Three idle connections, made while each other was leased.
    let now = clock.now();
    let leases = [0, 1, 2].map(|_| {
        let lease = new(&mut pool, tcp(1), &mut net, now);
        up(&mut pool, &lease, &mut net, now);
        lease
    });
    let keys = leases.each_ref().map(|l| key(&mut pool, l));
    for lease in leases {
        pool.release(lease, Finish::default(), &mut net, now);
    }
    // The first search prunes, and finds all healthy; the first is taken.
    let (got, notes) = search(&mut pool, &mut net, RULES);
    let Acquired::Reused(lease) = got else {
        panic!("{got:?}");
    };
    assert_eq!((pool.get(&lease).number, notes), (ConnNumber(0), vec![]));
    pool.release(lease, Finish::default(), &mut net, clock.now());
    // Hung up while idle: found dead by the next search, which does not
    // prune within a second of the last.
    net.hang_up(keys[0]);
    net.hang_up(keys[1]);
    clock.advance(Duration::from_millis(10));
    let (got, notes) = search(&mut pool, &mut net, RULES);
    assert!(matches!(got, Acquired::Reused(_)), "{got:?}");
    assert_eq!(
        notes,
        [
            PoolNote::Dead(ConnNumber(0)),
            PoolNote::Closed(ConnNumber(0)),
            PoolNote::Dead(ConnNumber(1)),
            PoolNote::Closed(ConnNumber(1)),
        ]
    );
    let Acquired::Reused(lease) = got else {
        unreachable!()
    };
    assert_eq!(pool.get(&lease).number, ConnNumber(2));
    pool.release(lease, Finish::default(), &mut net, clock.now());
    // Idle too long, by the transfer's rule.
    clock.advance(Duration::from_millis(500));
    let short = ReuseRules {
        max_idle: Some(Duration::from_millis(400)),
        max_age: None,
    };
    let (got, notes) = search(&mut pool, &mut net, short);
    assert!(matches!(got, Acquired::New(_)), "{got:?}");
    assert_eq!(
        notes,
        [
            PoolNote::IdleTooLong {
                idle_ms: 500,
                max_ms: 400
            },
            PoolNote::Dead(ConnNumber(2)),
            PoolNote::Closed(ConnNumber(2)),
        ]
    );
    let Acquired::New(lease) = got else {
        unreachable!()
    };
    pool.release(lease, Finish { premature: true }, &mut net, clock.now());
    // Alive too long is passed over without a word but its end.
    kept(&mut pool, &mut net);
    clock.advance(Duration::from_millis(10));
    let young = ReuseRules {
        max_idle: None,
        max_age: Some(Duration::from_millis(5)),
    };
    let (got, notes) = search(&mut pool, &mut net, young);
    assert!(matches!(got, Acquired::New(_)), "{got:?}");
    assert_eq!(notes, [PoolNote::Closed(ConnNumber(4))]);
    let Acquired::New(lease) = got else {
        unreachable!()
    };
    pool.release(lease, Finish { premature: true }, &mut net, clock.now());
    assert_eq!(net.open_sockets(), 0);
}

/// The prune closes idle connections not healthy without a word, at most
/// once a second.
#[test]
fn a_search_prunes_once_a_second() {
    let (mut net, clock) = net();
    let mut pool = Pool::new().unwrap();
    let now = clock.now();
    let lease = new(&mut pool, tcp(1), &mut net, now);
    up(&mut pool, &lease, &mut net, now);
    let key = match &pool.get(&lease).transport {
        Transport::Tcp(s) => s.key(),
        Transport::Local => unreachable!(),
    };
    pool.release(lease, Finish::default(), &mut net, now);
    net.hang_up(key);
    let mut notes = Vec::new();
    // The search for the first connection pruned; the next prune is a
    // second on.
    let got = pool
        .acquire(tcp(4), RULES, &mut net, now, &mut notes)
        .unwrap();
    assert_eq!(net.open_sockets(), 1, "not pruned within the second");
    let Acquired::New(other) = got else {
        panic!("{got:?}")
    };
    pool.release(other, Finish { premature: true }, &mut net, now);
    clock.advance(Duration::from_secs(1));
    let now = clock.now();
    let got = pool
        .acquire(tcp(4), RULES, &mut net, now, &mut notes)
        .unwrap();
    assert_eq!(notes, [], "pruned: the match never saw it");
    assert_eq!(net.open_sockets(), 0);
    let Acquired::New(lease) = got else {
        panic!("{got:?}")
    };
    pool.release(lease, Finish { premature: true }, &mut net, now);
}

/// The pool's lock is taken at the four places C takes it, one critical
/// section each: SHARE and CONNECT as test 1554 records them for one
/// transfer, a new connection and its return, then the next transfer
/// reusing it.
#[test]
fn the_lock_is_taken_where_c_takes_it() {
    #[derive(Clone, Default)]
    struct Recording(Rc<RefCell<Vec<&'static str>>>);
    impl Lock for Recording {
        fn lock(&self) {
            self.0.borrow_mut().push("lock");
        }
        fn unlock(&self) {
            self.0.borrow_mut().push("unlock");
        }
    }
    let (mut net, clock) = net();
    let now = clock.now();
    let log = Recording::default();
    let mut pool = Pool::with_lock(Box::new(log.clone())).unwrap();
    let sections = |log: &Recording| {
        let taken = std::mem::take(&mut *log.0.borrow_mut());
        assert!(
            taken.chunks(2).all(|c| c == ["lock", "unlock"]),
            "{taken:?}"
        );
        taken.len() / 2
    };
    // The first transfer: added, searched, a connection added.
    pool.xfer_init();
    let lease = new(&mut pool, tcp(1), &mut net, now);
    assert_eq!(sections(&log), 3);
    up(&mut pool, &lease, &mut net, now);
    assert_eq!(sections(&log), 0, "the setup takes no lock");
    pool.release(lease, Finish::default(), &mut net, now);
    assert_eq!(sections(&log), 1);
    // The next one: added, and finds it.
    pool.xfer_init();
    let mut notes = Vec::new();
    let got = pool
        .acquire(tcp(1), RULES, &mut net, now, &mut notes)
        .unwrap();
    assert_eq!(sections(&log), 2);
    let Acquired::Reused(lease) = got else {
        panic!("{got:?}")
    };
    pool.release(lease, Finish::default(), &mut net, now);
    assert_eq!(sections(&log), 1);
    // A networkless connection is added without a search.
    let local = new(&mut pool, Route::Local, &mut net, now);
    assert_eq!(sections(&log), 1);
    pool.release(local, Finish::default(), &mut net, now);
    pool.close_idle(&mut net);
    assert_eq!((pool.len(), net.open_sockets()), (0, 0));
}

#[test]
#[cfg(debug_assertions)]
#[should_panic = "dropped, not released"]
fn a_dropped_lease_is_caught() {
    let (mut net, clock) = net();
    let mut pool = Pool::new().unwrap();
    drop(new(&mut pool, Route::Local, &mut net, clock.now()));
}
