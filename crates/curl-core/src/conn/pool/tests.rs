use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::conn::io::{Conversation, Events, FakeNet, Peer, Readiness, Recv, Sent};
use crate::conn::{DnsCache, Failure, Limit, Scheme, Setup, Tcp};

use crate::options::IpVersion;
use crate::time::{Clock as _, ManualClock};
use curl_alloc::TryRc;

/// No limit: with no transfers, nothing to guess one from.
const UNLIMITED: Limit = Limit {
    max: None,
    attached: 0,
};

const TCP: Scheme = Scheme {
    name: "tcp",
    reuse: true,
};

/// Drive the setup of `lease` with C's happy eyeballs delay and nothing
/// kept from before.
fn connect(
    pool: &mut Pool,
    lease: &ConnLease,
    net: &mut FakeNet,
    now: Instant,
) -> Result<Connected, ConnectError> {
    let setup = Setup {
        dns: &mut DnsCache::default(),
        wildcard: false,
        delay: Duration::from_millis(200),
    };
    pool.connect(lease, net, now, setup)
}

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
        .with_peer(at(4), Peer::Accepts)
        .with_peer("[::ffff:7f00:1]:5".parse().unwrap(), Peer::Accepts);
    (net, clock)
}

fn tcp(port: u16) -> Route {
    to(TCP, b"127.0.0.1", port)
}

fn to(scheme: Scheme, host: &[u8], port: u16) -> Route {
    let peer = crate::conn::Peer::new(scheme, host.to_vec(), port, None);
    Route::Tcp(Tcp {
        origin: TryRc::try_new(peer).unwrap(),
        via: None,
        ip: IpVersion::Any,
    })
}

/// Drive the setup of `lease` past its name, which must resolve.
fn resolved(pool: &mut Pool, lease: &ConnLease, net: &mut FakeNet, now: Instant) {
    let got = connect(pool, lease, net, now).unwrap();
    assert!(
        matches!(got, Connected::Connecting(Progress::Resolved(_))),
        "{got:?}"
    );
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
    resolved(pool, lease, net, now);
    connect(pool, lease, net, now).unwrap();
    let established = connect(pool, lease, net, now).unwrap();
    assert!(matches!(established, Connected::Established { .. }));
}

fn socket(pool: &Pool, lease: &ConnLease) -> Option<i32> {
    pool.sockets(lease).next().map(|s| s.key().get())
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
        pool.release(a, Finish::default(), UNLIMITED, &mut net, now),
        Released::Closed(ConnNumber(0))
    );
    assert!(pool.get_conn(a_id).is_none());
    assert_eq!(pool.get_conn(b.id()).map(|c| c.number), Some(ConnNumber(1)));
    let premature = Finish { premature: true };
    assert_eq!(
        pool.release(b, premature, UNLIMITED, &mut net, now),
        Released::Terminated(ConnNumber(1))
    );
    assert_eq!(pool.len(), 0);
    // Numbers are never reused.
    let c = new(&mut pool, Route::Local, &mut net, now);
    assert_eq!(pool.get(&c).number.to_string(), "#2");
    assert_eq!(
        pool.release(c, Finish::default(), UNLIMITED, &mut net, now),
        Released::Closed(ConnNumber(2))
    );
}

/// Past its limit when one goes idle, the pool closes the idle connection
/// longest unused (`cpool_conn_now_idle`): another, or the one released.
/// Without a limit it keeps twice the transfers, and closes only one idle
/// for a second.
#[test]
fn a_full_pool_closes_its_oldest_idle_connection() {
    let (mut net, clock) = net();
    let mut pool = Pool::new().unwrap();
    let open = |pool: &mut Pool, net: &mut FakeNet, port| {
        let lease = new(pool, tcp(port), net, clock.now());
        up(pool, &lease, net, clock.now());
        lease
    };
    let ms = Duration::from_millis(1);
    let full = Some(Full { conns: 3, max: 2 });
    let two = Limit {
        max: NonZeroU32::new(2),
        attached: 1,
    };
    let a = open(&mut pool, &mut net, 1);
    let b = open(&mut pool, &mut net, 4);
    let c = open(&mut pool, &mut net, 1);
    // The only idle one is the one released.
    assert_eq!(
        pool.release(a, Finish::default(), two, &mut net, clock.now()),
        Released::Evicted(Full { conns: 3, max: 2 })
    );
    clock.advance(ms);
    assert_eq!(
        pool.release(b, Finish::default(), two, &mut net, clock.now()),
        Released::Idle {
            number: ConnNumber(1),
            full: None
        }
    );
    let d = open(&mut pool, &mut net, 1);
    clock.advance(ms);
    assert_eq!(
        pool.release(c, Finish::default(), two, &mut net, clock.now()),
        Released::Idle {
            number: ConnNumber(2),
            full
        },
        "#1, idle longer, is closed"
    );
    assert_eq!(pool.len(), 2);
    let guess = Limit {
        max: None,
        attached: 1,
    };
    let e = open(&mut pool, &mut net, 4);
    clock.advance(ms);
    assert_eq!(
        pool.release(d, Finish::default(), guess, &mut net, clock.now()),
        Released::Idle {
            number: ConnNumber(3),
            full
        },
    );
    assert_eq!(pool.len(), 3, "none idle for a second");
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        pool.release(e, Finish::default(), guess, &mut net, clock.now()),
        Released::Idle {
            number: ConnNumber(4),
            full
        },
    );
    assert_eq!(pool.len(), 2, "#2 is closed");
    // The one left to port 1 is #3.
    let mut notes = Vec::new();
    let got = pool.acquire(tcp(1), RULES, &mut net, clock.now(), &mut notes);
    let Ok(Acquired::Reused(kept)) = got else {
        panic!("{got:?}");
    };
    assert_eq!(pool.get(&kept).number, ConnNumber(3));
    pool.release(kept, Finish::default(), UNLIMITED, &mut net, clock.now());
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
    resolved(&mut pool, &lease, &mut net, now);
    let tried = connect(&mut pool, &lease, &mut net, now).unwrap();
    let to = SocketAddr::from(([127, 0, 0, 1], 1));
    assert!(matches!(tried, Connected::Connecting(Progress::Trying(a)) if a == to));
    assert_eq!(socket(&pool, &lease), Some(1000), "the attempt's");
    assert!(pool.get_conn(id).is_none(), "not up yet");
    let up = connect(&mut pool, &lease, &mut net, now).unwrap();
    let Connected::Established { remote, local, at } = up else {
        panic!("{up:?}");
    };
    assert_eq!((remote, at), (to, now));
    assert_eq!(local, Some(SocketAddr::from(([127, 0, 0, 1], 40000))));
    assert_eq!(pool.get_conn(id).map(|c| c.number), Some(ConnNumber(0)));
    assert!(matches!(
        connect(&mut pool, &lease, &mut net, now),
        Ok(Connected::AlreadyUp)
    ));
    assert_eq!(socket(&pool, &lease), Some(1000), "kept once up");
    let premature = Finish { premature: true };
    assert_eq!(
        pool.release(lease, premature, UNLIMITED, &mut net, now),
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
    resolved(&mut pool, &refused, &mut net, now);
    connect(&mut pool, &refused, &mut net, now).unwrap();
    let err = connect(&mut pool, &refused, &mut net, now).unwrap_err();
    let ConnectError::Failed(Failure::Attempt {
        remote,
        local,
        error,
    }) = err
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
    resolved(&mut pool, &silent, &mut net, now);
    connect(&mut pool, &silent, &mut net, now).unwrap();
    for _ in 0..3 {
        let waiting = connect(&mut pool, &silent, &mut net, now).unwrap();
        assert!(matches!(
            waiting,
            Connected::Connecting(Progress::Waiting { .. })
        ));
    }
    assert_eq!(net.open_sockets(), 1);
    let premature = Finish { premature: true };
    assert_eq!(
        pool.release(refused, premature, UNLIMITED, &mut net, now),
        Released::Terminated(ConnNumber(0))
    );
    assert_eq!(
        pool.release(silent, premature, UNLIMITED, &mut net, now),
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
    let named = to(TCP, b"example.com", 80);
    let named = new(&mut pool, named, &mut net, now);
    let err = connect(&mut pool, &named, &mut net, now).unwrap_err();
    assert!(matches!(err, ConnectError::Unresolved), "{err:?}");
    let nobody = new(&mut pool, tcp(9), &mut net, now);
    resolved(&mut pool, &nobody, &mut net, now);
    let err = connect(&mut pool, &nobody, &mut net, now).unwrap_err();
    assert!(
        matches!(err, ConnectError::Failed(Failure::Immediate { remote, .. }) if remote.port() == 9),
        "{err:?}"
    );
    let premature = Finish { premature: true };
    for lease in [named, nobody] {
        assert!(matches!(
            pool.release(lease, premature, UNLIMITED, &mut net, now),
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
        pool.release(first, Finish::default(), UNLIMITED, &mut net, now),
        Released::Idle {
            number: ConnNumber(0),
            full: None
        }
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
        pool.release(lease, premature, UNLIMITED, &mut net, now);
    }
    assert_eq!(
        pool.release(again, premature, UNLIMITED, &mut net, now),
        Released::Terminated(ConnNumber(0))
    );
    assert_eq!((pool.len(), net.open_sockets()), (0, 0));
    // A protocol that keeps no connection closes it.
    let once = Scheme {
        name: "once",
        reuse: false,
    };
    let route = to(once, b"127.0.0.1", 1);
    let lease = new(&mut pool, route, &mut net, now);
    up(&mut pool, &lease, &mut net, now);
    assert!(matches!(
        pool.release(lease, Finish::default(), UNLIMITED, &mut net, now),
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
        pool.release(lease, Finish::default(), UNLIMITED, net, now);
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
        pool.release(lease, Finish::default(), UNLIMITED, &mut net, now);
    }
    // The first search prunes, and finds all healthy; the first is taken.
    let (got, notes) = search(&mut pool, &mut net, RULES);
    let Acquired::Reused(lease) = got else {
        panic!("{got:?}");
    };
    assert_eq!((pool.get(&lease).number, notes), (ConnNumber(0), vec![]));
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, clock.now());
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
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, clock.now());
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
    pool.release(
        lease,
        Finish { premature: true },
        UNLIMITED,
        &mut net,
        clock.now(),
    );
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
    pool.release(
        lease,
        Finish { premature: true },
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    assert_eq!(net.open_sockets(), 0);
}

/// The limits are counted in whole milliseconds, and a connection at its
/// limit is within it, for the search and for the prune alike.
#[test]
fn a_limit_is_passed_a_whole_millisecond_after_it() {
    let (mut net, clock) = net();
    let mut pool = Pool::new().unwrap();
    let start = clock.now();
    let lease = new(&mut pool, tcp(1), &mut net, start);
    up(&mut pool, &lease, &mut net, start);
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, start);
    let ms = Duration::from_millis;
    let search = |pool: &mut Pool, net: &mut FakeNet, rules| {
        let mut notes = Vec::new();
        let got = pool
            .acquire(tcp(1), rules, net, clock.now(), &mut notes)
            .unwrap();
        let reused = match got {
            Acquired::Reused(lease) => {
                pool.release(lease, Finish::default(), UNLIMITED, net, clock.now());
                true
            }
            Acquired::New(lease) => {
                pool.release(
                    lease,
                    Finish { premature: true },
                    UNLIMITED,
                    net,
                    clock.now(),
                );
                false
            }
        };
        (reused, notes)
    };
    // Idle: 400.5 ms is 400 whole ones, at the limit; 401 is past it. The
    // first search prunes, and its limit keeps the connection too.
    let idle = |max| ReuseRules {
        max_idle: Some(max),
        max_age: None,
    };
    clock.advance(Duration::from_micros(400_500));
    assert_eq!(search(&mut pool, &mut net, idle(ms(400))), (true, vec![]));
    clock.advance(ms(401));
    let (reused, notes) = search(&mut pool, &mut net, idle(ms(400)));
    assert!(!reused);
    assert_eq!(
        notes[0],
        PoolNote::IdleTooLong {
            idle_ms: 401,
            max_ms: 400
        }
    );
    // Alive: a new connection, at its limit when the prune is due.
    let born = clock.now();
    let lease = new(&mut pool, tcp(1), &mut net, born);
    up(&mut pool, &lease, &mut net, born);
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, born);
    let age = |max| ReuseRules {
        max_idle: None,
        max_age: Some(max),
    };
    clock.advance(Duration::from_micros(1_000_500));
    assert_eq!(
        search(&mut pool, &mut net, age(ms(1000))),
        (true, vec![]),
        "neither the prune nor the search passes it over"
    );
    // A second on, past it: the prune closes it without a word.
    clock.advance(ms(1000));
    assert_eq!(search(&mut pool, &mut net, age(ms(1000))), (false, vec![]));
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
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, now);
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
    pool.release(other, Finish { premature: true }, UNLIMITED, &mut net, now);
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
    pool.release(lease, Finish { premature: true }, UNLIMITED, &mut net, now);
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
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, now);
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
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, now);
    assert_eq!(sections(&log), 1);
    // A networkless connection is added without a search.
    let local = new(&mut pool, Route::Local, &mut net, now);
    assert_eq!(sections(&log), 1);
    pool.release(local, Finish::default(), UNLIMITED, &mut net, now);
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

/// A connection sends and reads behind what waits; its
/// peer replies to a request's head, then closes.
#[test]
fn a_connection_moves_bytes_both_ways() {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], 1));
    let talk = Conversation::new(b"HTTP/1.1 200 OK\r\n\r\nhi", true);
    let mut net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let lease = new(&mut pool, tcp(1), &mut net, now);
    up(&mut pool, &lease, &mut net, now);
    let readable = |pool: &Pool| match pool.sockets(&lease).next().unwrap().readiness() {
        Readiness::Known { now, .. } => now.contains(Events::IN),
        Readiness::Poll(_) => unreachable!("a fake socket"),
    };
    assert!(!readable(&pool), "no request yet");
    let conn = pool.get(&lease);
    assert!(
        matches!(conn.recv(64).unwrap(), Recv::WouldBlock),
        "no request yet"
    );
    let sent = conn.send(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    assert!(matches!(sent, Sent::Bytes(n) if n.get() == 18));
    assert_eq!(talk.received(), b"GET / HTTP/1.1\r\n\r\n");
    assert!(readable(&pool), "a reply waits");
    let conn = pool.get(&lease);
    assert!(matches!(conn.recv(10).unwrap(), Recv::Data(n) if n.get() == 10));
    assert!(matches!(conn.recv(64).unwrap(), Recv::Data(n) if n.get() == 11));
    assert_eq!(conn.rx_mut().filled(), b"HTTP/1.1 200 OK\r\n\r\nhi");
    assert!(matches!(conn.recv(64).unwrap(), Recv::Eof));
    assert_eq!(conn.rx_mut().filled().len(), 21, "the end adds nothing");
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, now);
}

/// Without a conversation, a peer says nothing and takes what it is sent.
#[test]
fn a_silent_peer_takes_what_it_is_sent() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let lease = new(&mut pool, tcp(1), &mut net, now);
    up(&mut pool, &lease, &mut net, now);
    let conn = pool.get(&lease);
    let sent = conn.send(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    assert!(matches!(sent, Sent::Bytes(n) if n.get() == 18));
    assert!(matches!(conn.recv(64).unwrap(), Recv::WouldBlock));
    assert_eq!(conn.rx_mut().filled(), b"");
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, now);
}

/// A connection serves a route to the same peer however its host is
/// written: an IPv6 address in capitals is the same address.
#[test]
fn a_host_in_capitals_reuses_the_connection() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let lease = new(&mut pool, to(TCP, b"[::ffff:7f00:1]", 5), &mut net, now);
    up(&mut pool, &lease, &mut net, now);
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, now);
    let mut notes = Vec::new();
    let route = to(TCP, b"[::FFFF:7F00:1]", 5);
    let got = pool
        .acquire(route, RULES, &mut net, now, &mut notes)
        .unwrap();
    let Acquired::Reused(lease) = got else {
        panic!("{got:?}");
    };
    pool.release(lease, Finish::default(), UNLIMITED, &mut net, now);
}
