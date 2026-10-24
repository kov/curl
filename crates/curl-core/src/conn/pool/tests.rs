use super::*;
use crate::conn::connect::Plain;
use crate::conn::io::{Conversation, Events, FakeNet, Peer, Readiness, Recv, Remote, Sent};
use crate::conn::layer::Silent;
use crate::conn::{DnsCache, Limit, Scheme, Setup, Tcp};

use crate::options::IpVersion;
use crate::time::{Clock as _, ManualClock};
use curl_alloc::TryArc;

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
    lease: &mut ConnLease,
    net: &mut FakeNet,
    now: Instant,
) -> Result<Connected, ConnectError> {
    let setup = Setup {
        wildcard: false,
        max_age: Some(Duration::from_secs(60)),
        delay: Duration::from_millis(200),
        scope: None,
        socket: crate::conn::SocketSetup::PLAIN,
        haproxy: false,
        layer: None,
        linger: None,
    };
    let mut cx = Plain {
        net,
        dns: &mut DnsCache::default(),
        now,
    };
    lease.connect(&mut cx, setup)
}

const RULES: ReuseRules = ReuseRules {
    max_idle: Some(Duration::from_secs(118)),
    max_age: Some(Duration::from_secs(24 * 3600)),
    fresh: false,
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
        origin: TryArc::try_new(peer).unwrap(),
        via: None,
        ip: IpVersion::Any,
        proxy: None,
        tls: None,
        local: None,
    })
}

/// Drive the setup of `lease` past its name, which must resolve.
fn resolved(lease: &mut ConnLease, net: &mut FakeNet, now: Instant) {
    let got = connect(lease, net, now).unwrap();
    assert!(
        matches!(got, Connected::Connecting(Progress::Resolved(_))),
        "{got:?}"
    );
}

/// A connection for `route`, which must be new; the search says nothing.
fn new(pool: &mut Pool, here: &Home, route: Route, net: &mut FakeNet, now: Instant) -> ConnLease {
    let mut notes = Vec::new();
    let Acquired::New(lease) = pool
        .acquire(
            here,
            route,
            RULES,
            AddLimits::default(),
            net,
            now,
            &mut notes,
        )
        .unwrap()
    else {
        panic!("reused");
    };
    assert_eq!(notes, []);
    lease
}

/// Connect `lease`, whose peer accepts.
fn up(lease: &mut ConnLease, net: &mut FakeNet, now: Instant) {
    resolved(lease, net, now);
    connect(lease, net, now).unwrap();
    let established = connect(lease, net, now).unwrap();
    assert!(matches!(established, Connected::Established { .. }));
}

/// The connection `id` names, if it is still in the pool and idle.
fn idle_conn(pool: &Pool, id: ConnId) -> Option<&Conn> {
    pool.conns.get(id)?.idle()
}

fn socket(lease: &ConnLease) -> Option<i32> {
    lease.sockets().next().map(|s| s.key().get())
}

#[test]
fn local_connections_are_numbered_and_closed_when_released() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let a = new(&mut pool, &Home::Multi, Route::Local, &mut net, now);
    let b = new(&mut pool, &Home::Multi, Route::Local, &mut net, now);
    assert_ne!(a.id(), b.id(), "a local connection is never shared");
    assert_eq!(a.conn().number.to_string(), "#0");
    assert_eq!(b.conn().number.to_string(), "#1");
    assert_eq!(pool.len(), 2);
    let a_id = a.id();
    assert_eq!(
        pool.release(&Home::Multi, a, Finish::default(), UNLIMITED, &mut net, now),
        Released::Closed(ConnNumber(0))
    );
    assert!(idle_conn(&pool, a_id).is_none());
    // A leased connection is its lease's, not the pool's to show.
    assert!(idle_conn(&pool, b.id()).is_none());
    assert_eq!(b.conn().number, ConnNumber(1));
    let premature = Finish {
        premature: true,
        forbid_reuse: false,
    };
    assert_eq!(
        pool.release(&Home::Multi, b, premature, UNLIMITED, &mut net, now),
        Released::Terminated(ConnNumber(1))
    );
    assert_eq!(pool.len(), 0);
    // Numbers are never reused.
    let c = new(&mut pool, &Home::Multi, Route::Local, &mut net, now);
    assert_eq!(c.conn().number.to_string(), "#2");
    assert_eq!(
        pool.release(&Home::Multi, c, Finish::default(), UNLIMITED, &mut net, now),
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
        let mut lease = new(pool, &Home::Multi, tcp(port), net, clock.now());
        up(&mut lease, net, clock.now());
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
        pool.release(
            &Home::Multi,
            a,
            Finish::default(),
            two,
            &mut net,
            clock.now()
        ),
        Released::Evicted(Full { conns: 3, max: 2 })
    );
    clock.advance(ms);
    let b_id = b.id();
    assert_eq!(
        pool.release(
            &Home::Multi,
            b,
            Finish::default(),
            two,
            &mut net,
            clock.now()
        ),
        Released::Idle {
            number: ConnNumber(1),
            full: None
        }
    );
    assert_eq!(
        idle_conn(&pool, b_id).map(|c| c.number),
        Some(ConnNumber(1)),
        "idle, the pool's to show"
    );
    let d = open(&mut pool, &mut net, 1);
    clock.advance(ms);
    assert_eq!(
        pool.release(
            &Home::Multi,
            c,
            Finish::default(),
            two,
            &mut net,
            clock.now()
        ),
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
        pool.release(
            &Home::Multi,
            d,
            Finish::default(),
            guess,
            &mut net,
            clock.now()
        ),
        Released::Idle {
            number: ConnNumber(3),
            full
        },
    );
    assert_eq!(pool.len(), 3, "none idle for a second");
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        pool.release(
            &Home::Multi,
            e,
            Finish::default(),
            guess,
            &mut net,
            clock.now()
        ),
        Released::Idle {
            number: ConnNumber(4),
            full
        },
    );
    assert_eq!(pool.len(), 2, "#2 is closed");
    // The one left to port 1 is #3.
    let mut notes = Vec::new();
    let got = pool.acquire(
        &Home::Multi,
        tcp(1),
        RULES,
        AddLimits::default(),
        &mut net,
        clock.now(),
        &mut notes,
    );
    let Ok(Acquired::Reused(kept)) = got else {
        panic!("{got:?}");
    };
    assert_eq!(kept.conn().number, ConnNumber(3));
    pool.release(
        &Home::Multi,
        kept,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    pool.close_idle(&mut net, clock.now());
}

/// A new connection is made within the host and total limits, closing
/// the idle one longest unused to make room, first among those to the
/// same destination whatever their scheme (`cpool_check_limits`); with
/// no room, there is none.
#[test]
fn a_new_connection_waits_for_room_within_the_limits() {
    let (mut net, clock) = net();
    let mut pool = Pool::new().unwrap();
    let ms = Duration::from_millis(1);
    let limits = |max_host, max_total| AddLimits {
        max_host: NonZeroU32::new(max_host),
        max_total: NonZeroU32::new(max_total),
    };
    let try_new = |pool: &mut Pool, net: &mut FakeNet, route, limits| {
        let mut notes = Vec::new();
        let got = pool.acquire(
            &Home::Multi,
            route,
            RULES,
            limits,
            net,
            clock.now(),
            &mut notes,
        );
        assert_eq!(notes, []);
        got.unwrap()
    };
    let mut a = new(&mut pool, &Home::Multi, tcp(1), &mut net, clock.now());
    up(&mut a, &mut net, clock.now());
    let got = try_new(&mut pool, &mut net, tcp(1), limits(1, 0));
    assert!(
        matches!(got, Acquired::Wait(WaitReason::HostLimit)),
        "{got:?}"
    );
    let mut b = new(&mut pool, &Home::Multi, tcp(4), &mut net, clock.now());
    up(&mut b, &mut net, clock.now());
    let got = try_new(&mut pool, &mut net, tcp(3), limits(1, 2));
    let two = NonZeroU32::new(2).unwrap();
    assert!(
        matches!(got, Acquired::Wait(WaitReason::TotalLimit(n)) if n == two),
        "{got:?}"
    );
    // #0 idle makes room for one more.
    pool.release(
        &Home::Multi,
        a,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    clock.advance(ms);
    let Acquired::New(c) = try_new(&mut pool, &mut net, tcp(3), limits(1, 2)) else {
        panic!("no room made");
    };
    assert_eq!(pool.len(), 2, "#0 closed");
    // To #1's destination by another scheme: one connection to the host.
    pool.release(
        &Home::Multi,
        b,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    let other = Scheme {
        name: "other",
        reuse: true,
    };
    let Acquired::New(d) = try_new(
        &mut pool,
        &mut net,
        to(other, b"127.0.0.1", 4),
        limits(1, 0),
    ) else {
        panic!("no room made");
    };
    assert_eq!(pool.len(), 2, "#1 closed");
    pool.release(
        &Home::Multi,
        c,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    pool.release(
        &Home::Multi,
        d,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
}

/// Room is made by closing the connection idle longest, the first of
/// those idle as long (`cpool_get_oldest_idle`).
#[test]
fn room_is_made_by_the_connection_idle_longest() {
    let (mut net, clock) = net();
    let mut pool = Pool::new().unwrap();
    let mapped = || to(TCP, b"[::ffff:7f00:1]", 5);
    let routes = [tcp(1), tcp(4), mapped()];
    let leases: Vec<ConnLease> = routes
        .into_iter()
        .map(|r| {
            let mut l = new(&mut pool, &Home::Multi, r, &mut net, clock.now());
            up(&mut l, &mut net, clock.now());
            l
        })
        .collect();
    let [a, b, c] = <[ConnLease; 3]>::try_from(leases).unwrap();
    // #0 and #1 idle as long, #2 less.
    pool.release(
        &Home::Multi,
        a,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    pool.release(
        &Home::Multi,
        b,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    clock.advance(Duration::from_millis(5));
    pool.release(
        &Home::Multi,
        c,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    clock.advance(Duration::from_millis(5));
    let limits = AddLimits {
        max_host: None,
        max_total: NonZeroU32::new(3),
    };
    let mut notes = Vec::new();
    let got = pool.acquire(
        &Home::Multi,
        tcp(3),
        RULES,
        limits,
        &mut net,
        clock.now(),
        &mut notes,
    );
    let Ok(Acquired::New(d)) = got else {
        panic!("no room made: {got:?}");
    };
    pool.release(
        &Home::Multi,
        d,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    let mut kept = |route| {
        let got = pool.acquire(
            &Home::Multi,
            route,
            RULES,
            AddLimits::default(),
            &mut net,
            clock.now(),
            &mut notes,
        );
        let (reused, lease) = match got {
            Ok(Acquired::Reused(lease)) => (true, lease),
            Ok(Acquired::New(lease)) => (false, lease),
            got => panic!("{got:?}"),
        };
        pool.release(
            &Home::Multi,
            lease,
            Finish::default(),
            UNLIMITED,
            &mut net,
            clock.now(),
        );
        reused
    };
    assert_eq!(
        [kept(tcp(1)), kept(tcp(4)), kept(mapped())],
        [false, true, true]
    );
    pool.close_idle(&mut net, clock.now());
}

/// A setup tries its address, waits, and is established in the slot it
/// started in; its socket is the pool's to wait on until then.
#[test]
fn a_tcp_connection_is_set_up_in_its_slot() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let mut lease = new(&mut pool, &Home::Multi, tcp(1), &mut net, now);
    let id = lease.id();
    assert_eq!(socket(&lease), None, "nothing open before the first drive");
    resolved(&mut lease, &mut net, now);
    let tried = connect(&mut lease, &mut net, now).unwrap();
    let to = SocketAddr::from(([127, 0, 0, 1], 1));
    assert!(
        matches!(tried, Connected::Connecting(Progress::Trying { remote, .. }) if remote == Remote::Inet(to))
    );
    assert_eq!(socket(&lease), Some(1000), "the attempt's");
    assert!(idle_conn(&pool, id).is_none(), "leased");
    let up = connect(&mut lease, &mut net, now).unwrap();
    let Connected::Established {
        remote, local, at, ..
    } = up
    else {
        panic!("{up:?}");
    };
    assert_eq!((remote, at), (Remote::Inet(to), now));
    assert_eq!(local, Some(SocketAddr::from(([127, 0, 0, 1], 40000))));
    assert_eq!(lease.conn().number, ConnNumber(0));
    assert!(matches!(
        connect(&mut lease, &mut net, now),
        Ok(Connected::AlreadyUp { .. })
    ));
    assert_eq!(socket(&lease), Some(1000), "kept once up");
    let premature = Finish {
        premature: true,
        forbid_reuse: false,
    };
    assert_eq!(
        pool.release(&Home::Multi, lease, premature, UNLIMITED, &mut net, now),
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
    let mut refused = new(&mut pool, &Home::Multi, tcp(2), &mut net, now);
    resolved(&mut refused, &mut net, now);
    connect(&mut refused, &mut net, now).unwrap();
    let err = connect(&mut refused, &mut net, now).unwrap_err();
    let ConnectError::Failed(error, _) = err else {
        panic!("{err:?}");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert_eq!(
        net.open_sockets(),
        0,
        "the failed attempt's socket is closed"
    );
    let mut silent = new(&mut pool, &Home::Multi, tcp(3), &mut net, now);
    resolved(&mut silent, &mut net, now);
    connect(&mut silent, &mut net, now).unwrap();
    for _ in 0..3 {
        let waiting = connect(&mut silent, &mut net, now).unwrap();
        assert!(matches!(
            waiting,
            Connected::Connecting(Progress::Waiting { .. })
        ));
    }
    assert_eq!(net.open_sockets(), 1);
    let premature = Finish {
        premature: true,
        forbid_reuse: false,
    };
    assert_eq!(
        pool.release(&Home::Multi, refused, premature, UNLIMITED, &mut net, now),
        Released::Terminated(ConnNumber(0))
    );
    assert_eq!(
        pool.release(&Home::Multi, silent, premature, UNLIMITED, &mut net, now),
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
    let mut named = new(&mut pool, &Home::Multi, named, &mut net, now);
    let err = connect(&mut named, &mut net, now).unwrap_err();
    assert!(matches!(err, ConnectError::Unresolved(_)), "{err:?}");
    let mut nobody = new(&mut pool, &Home::Multi, tcp(9), &mut net, now);
    resolved(&mut nobody, &mut net, now);
    let err = connect(&mut nobody, &mut net, now).unwrap_err();
    assert!(
        matches!(&err, ConnectError::Failed(e, _) if e.kind() == std::io::ErrorKind::ConnectionRefused),
        "{err:?}"
    );
    let premature = Finish {
        premature: true,
        forbid_reuse: false,
    };
    for lease in [named, nobody] {
        assert!(matches!(
            pool.release(&Home::Multi, lease, premature, UNLIMITED, &mut net, now),
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
    let mut first = new(&mut pool, &Home::Multi, tcp(1), &mut net, now);
    up(&mut first, &mut net, now);
    let id = first.id();
    assert_eq!(
        pool.release(
            &Home::Multi,
            first,
            Finish::default(),
            UNLIMITED,
            &mut net,
            now
        ),
        Released::Idle {
            number: ConnNumber(0),
            full: None
        }
    );
    assert_eq!(net.open_sockets(), 1, "kept open");
    // Another port is another route.
    let other = new(&mut pool, &Home::Multi, tcp(4), &mut net, now);
    assert_ne!(other.id(), id);
    let mut notes = Vec::new();
    let again = pool
        .acquire(
            &Home::Multi,
            tcp(1),
            RULES,
            AddLimits::default(),
            &mut net,
            now,
            &mut notes,
        )
        .unwrap();
    let Acquired::Reused(again) = again else {
        panic!("{again:?}");
    };
    assert_eq!((again.id(), notes), (id, vec![]));
    // Leased again: a third transfer cannot have it.
    let third = new(&mut pool, &Home::Multi, tcp(1), &mut net, now);
    let premature = Finish {
        premature: true,
        forbid_reuse: false,
    };
    for lease in [other, third] {
        pool.release(&Home::Multi, lease, premature, UNLIMITED, &mut net, now);
    }
    assert_eq!(
        pool.release(&Home::Multi, again, premature, UNLIMITED, &mut net, now),
        Released::Terminated(ConnNumber(0))
    );
    assert_eq!((pool.len(), net.open_sockets()), (0, 0));
    // A protocol that keeps no connection closes it.
    let once = Scheme {
        name: "once",
        reuse: false,
    };
    let route = to(once, b"127.0.0.1", 1);
    let mut lease = new(&mut pool, &Home::Multi, route, &mut net, now);
    up(&mut lease, &mut net, now);
    assert!(matches!(
        pool.release(
            &Home::Multi,
            lease,
            Finish::default(),
            UNLIMITED,
            &mut net,
            now
        ),
        Released::Closed(_)
    ));
}

/// An idle connection with something to read, or idle or alive too long,
/// is closed when a search meets it; the search goes on to the next.
#[test]
fn a_search_closes_what_it_must_not_reuse() {
    let (mut net, clock) = net();
    let mut pool = Pool::new().unwrap();
    let key = |lease: &ConnLease| match &lease.conn().transport {
        Transport::Tcp(s) => s.socket().key(),
        Transport::Local => unreachable!(),
    };
    let kept = |pool: &mut Pool, net: &mut FakeNet| {
        let now = clock.now();
        let mut lease = new(pool, &Home::Multi, tcp(1), net, now);
        up(&mut lease, net, now);
        pool.release(&Home::Multi, lease, Finish::default(), UNLIMITED, net, now);
    };
    let search = |pool: &mut Pool, net: &mut FakeNet, rules| {
        let mut notes = Vec::new();
        let got = pool
            .acquire(
                &Home::Multi,
                tcp(1),
                rules,
                AddLimits::default(),
                net,
                clock.now(),
                &mut notes,
            )
            .unwrap();
        (got, notes)
    };
    // Three idle connections, made while each other was leased.
    let now = clock.now();
    let leases = [0, 1, 2].map(|_| {
        let mut lease = new(&mut pool, &Home::Multi, tcp(1), &mut net, now);
        up(&mut lease, &mut net, now);
        lease
    });
    let keys = leases.each_ref().map(key);
    for lease in leases {
        pool.release(
            &Home::Multi,
            lease,
            Finish::default(),
            UNLIMITED,
            &mut net,
            now,
        );
    }
    // The first search prunes, and finds all healthy; the first is taken.
    let (got, notes) = search(&mut pool, &mut net, RULES);
    let Acquired::Reused(lease) = got else {
        panic!("{got:?}");
    };
    assert_eq!((lease.conn().number, notes), (ConnNumber(0), vec![]));
    pool.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
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
    assert_eq!(lease.conn().number, ConnNumber(2));
    pool.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        clock.now(),
    );
    // Idle too long, by the transfer's rule.
    clock.advance(Duration::from_millis(500));
    let short = ReuseRules {
        max_idle: Some(Duration::from_millis(400)),
        max_age: None,
        fresh: false,
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
        &Home::Multi,
        lease,
        Finish {
            premature: true,
            forbid_reuse: false,
        },
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
        fresh: false,
    };
    let (got, notes) = search(&mut pool, &mut net, young);
    assert!(matches!(got, Acquired::New(_)), "{got:?}");
    assert_eq!(notes, [PoolNote::Closed(ConnNumber(4))]);
    let Acquired::New(lease) = got else {
        unreachable!()
    };
    pool.release(
        &Home::Multi,
        lease,
        Finish {
            premature: true,
            forbid_reuse: false,
        },
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
    let mut lease = new(&mut pool, &Home::Multi, tcp(1), &mut net, start);
    up(&mut lease, &mut net, start);
    pool.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        start,
    );
    let ms = Duration::from_millis;
    let search = |pool: &mut Pool, net: &mut FakeNet, rules| {
        let mut notes = Vec::new();
        let got = pool
            .acquire(
                &Home::Multi,
                tcp(1),
                rules,
                AddLimits::default(),
                net,
                clock.now(),
                &mut notes,
            )
            .unwrap();
        let reused = match got {
            Acquired::Reused(lease) => {
                pool.release(
                    &Home::Multi,
                    lease,
                    Finish::default(),
                    UNLIMITED,
                    net,
                    clock.now(),
                );
                true
            }
            Acquired::New(lease) => {
                pool.release(
                    &Home::Multi,
                    lease,
                    Finish {
                        premature: true,
                        forbid_reuse: false,
                    },
                    UNLIMITED,
                    net,
                    clock.now(),
                );
                false
            }
            Acquired::Wait(_) => unreachable!("no limits"),
        };
        (reused, notes)
    };
    // Idle: 400.5 ms is 400 whole ones, at the limit; 401 is past it. The
    // first search prunes, and its limit keeps the connection too.
    let idle = |max| ReuseRules {
        max_idle: Some(max),
        max_age: None,
        fresh: false,
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
    let mut lease = new(&mut pool, &Home::Multi, tcp(1), &mut net, born);
    up(&mut lease, &mut net, born);
    pool.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        born,
    );
    let age = |max| ReuseRules {
        max_idle: None,
        max_age: Some(max),
        fresh: false,
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
    let mut lease = new(&mut pool, &Home::Multi, tcp(1), &mut net, now);
    up(&mut lease, &mut net, now);
    let key = match &lease.conn().transport {
        Transport::Tcp(s) => s.socket().key(),
        Transport::Local => unreachable!(),
    };
    pool.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        now,
    );
    net.hang_up(key);
    let mut notes = Vec::new();
    // The search for the first connection pruned; the next prune is a
    // second on.
    let got = pool
        .acquire(
            &Home::Multi,
            tcp(4),
            RULES,
            AddLimits::default(),
            &mut net,
            now,
            &mut notes,
        )
        .unwrap();
    assert_eq!(net.open_sockets(), 1, "not pruned within the second");
    let Acquired::New(other) = got else {
        panic!("{got:?}")
    };
    pool.release(
        &Home::Multi,
        other,
        Finish {
            premature: true,
            forbid_reuse: false,
        },
        UNLIMITED,
        &mut net,
        now,
    );
    clock.advance(Duration::from_secs(1));
    let now = clock.now();
    let got = pool
        .acquire(
            &Home::Multi,
            tcp(4),
            RULES,
            AddLimits::default(),
            &mut net,
            now,
            &mut notes,
        )
        .unwrap();
    assert_eq!(notes, [], "pruned: the match never saw it");
    assert_eq!(net.open_sockets(), 0);
    let Acquired::New(lease) = got else {
        panic!("{got:?}")
    };
    pool.release(
        &Home::Multi,
        lease,
        Finish {
            premature: true,
            forbid_reuse: false,
        },
        UNLIMITED,
        &mut net,
        now,
    );
}

#[test]
#[cfg(debug_assertions)]
#[should_panic = "dropped, not released"]
fn a_dropped_lease_is_caught() {
    let (mut net, clock) = net();
    let mut pool = Pool::new().unwrap();
    drop(new(
        &mut pool,
        &Home::Multi,
        Route::Local,
        &mut net,
        clock.now(),
    ));
}

/// A lease goes back only to the pool it is from: a share's lease given
/// to a multi's pool, whose ids it may well share, is a bug.
#[test]
#[should_panic = "given back to Multi"]
fn a_lease_goes_back_only_to_its_home() {
    let (mut net, clock) = net();
    let share = crate::share::Share::new().unwrap();
    let home = Home::Share(share.clone());
    let lease = new(
        &mut share.pool(),
        &home,
        Route::Local,
        &mut net,
        clock.now(),
    );
    let mut multi = Pool::new().unwrap();
    // The two tables hand out the same id first.
    let theirs = new(
        &mut multi,
        &Home::Multi,
        Route::Local,
        &mut net,
        clock.now(),
    );
    assert_eq!(lease.id(), theirs.id());
    let now = clock.now();
    multi.release(
        &Home::Multi,
        theirs,
        Finish::default(),
        UNLIMITED,
        &mut net,
        now,
    );
    multi.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        now,
    );
}

/// Nor is a share's lease taken back by another share's pool: shares are
/// told apart by identity, not by being shares.
#[test]
#[should_panic = "given back to Share"]
fn a_share_s_lease_goes_back_only_to_that_share() {
    let (mut net, clock) = net();
    let mine = crate::share::Share::new().unwrap();
    let other = crate::share::Share::new().unwrap();
    let lease = new(
        &mut mine.pool(),
        &Home::Share(mine.clone()),
        Route::Local,
        &mut net,
        clock.now(),
    );
    // A pool of the other share's, outside its lock, which the panic
    // would poison; its table hands out the same id first.
    let there = Home::Share(other);
    let mut pool = Pool::new().unwrap();
    let theirs = new(&mut pool, &there, Route::Local, &mut net, clock.now());
    assert_eq!(lease.id(), theirs.id());
    let now = clock.now();
    pool.release(&there, theirs, Finish::default(), UNLIMITED, &mut net, now);
    pool.release(&there, lease, Finish::default(), UNLIMITED, &mut net, now);
}

/// A connection closed cleanly first reads up to 1 KB of what its peer
/// sent, as C's socket shutdown does: given back to be closed, and idle
/// when the pool closes; one whose transfer was aborted is closed
/// without a read.
#[test]
fn a_clean_close_drains_the_socket_first() {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], 1));
    let talks = [(); 3].map(|()| Conversation::new(b"x", false));
    let mut net = FakeNet::new(clock.clone()).with_peer(at, Peer::Accepts);
    for talk in &talks {
        net = net.with_conversation(at, talk.clone());
    }
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let mut leases = [(); 3].map(|()| {
        let mut lease = new(&mut pool, &Home::Multi, tcp(1), &mut net, now);
        up(&mut lease, &mut net, now);
        lease
    });
    assert_eq!(talks.each_ref().map(Conversation::reads), [(0, 0); 3]);
    leases[0].get().mark_close();
    let [closed, aborted, idle] = leases;
    let premature = Finish {
        premature: true,
        ..Finish::default()
    };
    let released = [
        pool.release(
            &Home::Multi,
            closed,
            Finish::default(),
            UNLIMITED,
            &mut net,
            now,
        ),
        pool.release(&Home::Multi, aborted, premature, UNLIMITED, &mut net, now),
        pool.release(
            &Home::Multi,
            idle,
            Finish::default(),
            UNLIMITED,
            &mut net,
            now,
        ),
    ];
    assert!(matches!(
        released,
        [
            Released::Closed(_),
            Released::Terminated(_),
            Released::Idle { .. }
        ]
    ));
    let reads = || talks.each_ref().map(Conversation::reads);
    assert_eq!(reads(), [(1, 1024), (0, 0), (0, 0)]);
    pool.close_idle(&mut net, now);
    assert_eq!(reads(), [(1, 1024), (0, 0), (1, 1024)]);
    assert_eq!(net.open_sockets(), 0);
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
    let mut lease = new(&mut pool, &Home::Multi, tcp(1), &mut net, now);
    up(&mut lease, &mut net, now);
    let readable = |lease: &ConnLease| match lease.sockets().next().unwrap().readiness() {
        Readiness::Known { now, .. } => now.contains(Events::IN),
        Readiness::Poll(_) => unreachable!("a fake socket"),
    };
    assert!(!readable(&lease), "no request yet");
    let conn = lease.get();
    assert!(
        matches!(conn.recv(&mut Silent(now), 64).unwrap(), Recv::WouldBlock),
        "no request yet"
    );
    let sent = conn
        .send(&mut Silent(now), b"GET / HTTP/1.1\r\n\r\n")
        .unwrap();
    assert!(matches!(sent, Sent::Bytes(n) if n.get() == 18));
    assert_eq!(talk.received(), b"GET / HTTP/1.1\r\n\r\n");
    assert!(readable(&lease), "a reply waits");
    let conn = lease.get();
    assert!(!conn.data_pending());
    assert!(matches!(conn.recv(&mut Silent(now), 10).unwrap(), Recv::Data(n) if n.get() == 10));
    assert!(conn.data_pending(), "bytes received and not used");
    // What was received and not used comes first, the socket not asked.
    assert!(matches!(conn.recv(&mut Silent(now), 64).unwrap(), Recv::Data(n) if n.get() == 10));
    assert_eq!(conn.rx_mut().filled(), b"HTTP/1.1 2");
    conn.rx_mut().consume(10);
    assert!(!conn.data_pending());
    assert!(matches!(conn.recv(&mut Silent(now), 64).unwrap(), Recv::Data(n) if n.get() == 11));
    assert_eq!(conn.rx_mut().filled(), b"00 OK\r\n\r\nhi");
    conn.rx_mut().consume(11);
    assert!(matches!(
        conn.recv(&mut Silent(now), 64).unwrap(),
        Recv::Eof
    ));
    assert_eq!(conn.rx_mut().filled(), b"", "the end adds nothing");
    pool.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        now,
    );
}

/// Without a conversation, a peer says nothing and takes what it is sent.
#[test]
fn a_silent_peer_takes_what_it_is_sent() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let mut lease = new(&mut pool, &Home::Multi, tcp(1), &mut net, now);
    up(&mut lease, &mut net, now);
    let conn = lease.get();
    let sent = conn
        .send(&mut Silent(now), b"GET / HTTP/1.1\r\n\r\n")
        .unwrap();
    assert!(matches!(sent, Sent::Bytes(n) if n.get() == 18));
    assert!(matches!(
        conn.recv(&mut Silent(now), 64).unwrap(),
        Recv::WouldBlock
    ));
    assert_eq!(conn.rx_mut().filled(), b"");
    pool.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        now,
    );
    pool.close_idle(&mut net, now);
}

/// A connection serves a route to the same peer however its host is
/// written: an IPv6 address in capitals is the same address.
#[test]
fn a_host_in_capitals_reuses_the_connection() {
    let (mut net, clock) = net();
    let now = clock.now();
    let mut pool = Pool::new().unwrap();
    let mut lease = new(
        &mut pool,
        &Home::Multi,
        to(TCP, b"[::ffff:7f00:1]", 5),
        &mut net,
        now,
    );
    up(&mut lease, &mut net, now);
    pool.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        now,
    );
    let mut notes = Vec::new();
    let route = to(TCP, b"[::FFFF:7F00:1]", 5);
    let got = pool
        .acquire(
            &Home::Multi,
            route,
            RULES,
            AddLimits::default(),
            &mut net,
            now,
            &mut notes,
        )
        .unwrap();
    let Acquired::Reused(lease) = got else {
        panic!("{got:?}");
    };
    pool.release(
        &Home::Multi,
        lease,
        Finish::default(),
        UNLIMITED,
        &mut net,
        now,
    );
    pool.close_idle(&mut net, now);
}
