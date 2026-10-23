//! The trace of a wait (`multi_wait`): each transfer's pollset as it is
//! collected (`Curl_multi_pollset`), the socket filter's part in it while
//! the connection is set up, the transfer's timers, the timer the multi
//! waits for (`multi_timeout`), and the wait. Each expected sequence is
//! the C build's for the same transfer, its descriptors and times the
//! fakes'. The multi has a waker, and the transfer no limit of its own,
//! as the tool's have.

use std::net::IpAddr;

use super::*;
use crate::components::Components;
use crate::conn::io::Waker;

/// A handle tracing the multi, the timers and the socket.
fn tracing_wait() -> Easy {
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"multi,timer,tcp");
    e.set_components(Some(components));
    e
}

/// The lines of a run about its waits.
fn wait_lines(ran: &Ran) -> Vec<String> {
    ran.seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            l.contains("] pollset[")
                || l.contains("] multi_wait(")
                || l.starts_with("[TCP] adjust_pollset")
                || (l.starts_with("[TIMER] ")
                    && (l.contains(" expires in ") || l.contains(" gives multi timeout ")))
        })
        .collect()
}

fn expect(lines: &str) -> Vec<String> {
    lines
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A multi with a waker, over a network where each of `peers` is at
/// `PORT`, those that accept holding `talk`, and `name` is their
/// addresses.
fn waking(name: &str, peers: &[(IpAddr, Peer)], talk: &Conversation) -> Multi {
    let clock = ManualClock::new().unwrap();
    let addrs: Vec<IpAddr> = peers.iter().map(|&(ip, _)| ip).collect();
    let mut net = FakeNet::new(clock.clone()).with_name(name, &addrs);
    for &(ip, peer) in peers {
        let at = SocketAddr::new(ip, PORT);
        net = net.with_peer(at, peer);
        if matches!(peer, Peer::Accepts | Peer::AcceptsAfter(_)) {
            net = net.with_conversation(at, talk.clone());
        }
    }
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: Some(curl_alloc::TryArc::try_new(Waker::new().unwrap()).unwrap()),
    };
    Multi::new(env).unwrap()
}

/// A GET of `name` by `m`, over `talk`, with the options `set` makes: no
/// limit on the whole transfer unless `set` gives one.
fn get_of(m: &mut Multi, name: &str, talk: Conversation, set: impl FnOnce(&mut Options)) -> Ran {
    get_with(m, tracing_wait(), "/", talk, |o| {
        let url = format!("http://{name}:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.limits.total = None;
        set(o);
    })
}

fn local() -> IpAddr {
    IpAddr::from([127, 0, 0, 1])
}

/// Before its first step the transfer waits on nothing, and the multi not
/// at all, as it is to run; then on its socket to connect, then to read
/// the answer.
#[test]
fn a_request_s_waits_are_traced_as_c() {
    let talk = Conversation::replies(&[OK], false).late_replies();
    let mut m = waking("one.example", &[(local(), Peer::Accepts)], &talk);
    let ran = get_of(&mut m, "one.example", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        wait_lines(&ran),
        expect(
            "[MULTI] [INIT] pollset[], timeouts=0, paused 0/0 (r/w)
            [MULTI] [INIT] multi_wait(fds=1, timeout=0) tinternal=0
            [TCP] adjust_pollset, !connected, POLLOUT fd=1000
            [MULTI] [CONNECTING] pollset[fd=1000 OUT], timeouts=0
            [MULTI] [CONNECTING] multi_wait(fds=2, timeout=1000) tinternal=-1
            [MULTI] [PERFORMING] pollset[fd=1000 IN], timeouts=0
            [MULTI] [PERFORMING] multi_wait(fds=2, timeout=1000) tinternal=-1"
        )
    );
}

/// A connect that does not finish: the wait is for the connect's limit,
/// which the transfer's timers name and the multi waits for.
#[test]
fn a_connect_limit_is_waited_for_as_c() {
    let talk = Conversation::replies(&[], false);
    let silent = IpAddr::from([192, 0, 2, 1]);
    let mut m = waking("silent.example", &[(silent, Peer::Silent)], &talk);
    let ran = get_of(&mut m, "silent.example", talk, |o| {
        o.limits.connect = crate::time::TimeLimit::from_millis(1000);
    });
    assert_eq!(ran.result, Err(ErrorKind::OperationTimedout));
    assert_eq!(
        wait_lines(&ran),
        expect(
            "[MULTI] [INIT] pollset[], timeouts=0, paused 0/0 (r/w)
            [MULTI] [INIT] multi_wait(fds=1, timeout=0) tinternal=0
            [TCP] adjust_pollset, !connected, POLLOUT fd=1000
            [MULTI] [CONNECTING] pollset[fd=1000 OUT], timeouts=1
            [TIMER] [CONNECTTIMEOUT] expires in 1000000us
            [TIMER] [CONNECTTIMEOUT] gives multi timeout in 1000ms
            [MULTI] [CONNECTING] multi_wait(fds=2, timeout=1000) tinternal=1000"
        )
    );
}

/// An attempt that has not connected when the eyeballs delay runs out:
/// the wait is for the next attempt's start; then on both attempts.
#[test]
fn a_race_s_waits_are_traced_as_c() {
    let talk = Conversation::replies(&[OK], false).late_replies();
    let silent = IpAddr::from([192, 0, 2, 1]);
    let mut m = waking(
        "two.example",
        &[
            (silent, Peer::Silent),
            (local(), Peer::AcceptsAfter(Duration::from_millis(1))),
        ],
        &talk,
    );
    let ran = get_of(&mut m, "two.example", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        wait_lines(&ran),
        expect(
            "[MULTI] [INIT] pollset[], timeouts=0, paused 0/0 (r/w)
            [MULTI] [INIT] multi_wait(fds=1, timeout=0) tinternal=0
            [TCP] adjust_pollset, !connected, POLLOUT fd=1000
            [MULTI] [CONNECTING] pollset[fd=1000 OUT], timeouts=1
            [TIMER] [HAPPY_EYEBALLS] expires in 200000us
            [TIMER] [HAPPY_EYEBALLS] gives multi timeout in 200ms
            [MULTI] [CONNECTING] multi_wait(fds=2, timeout=200) tinternal=200
            [TCP] adjust_pollset, !connected, POLLOUT fd=1000
            [TCP] adjust_pollset, !connected, POLLOUT fd=1001
            [MULTI] [CONNECTING] pollset[fd=1000 OUT, fd=1001 OUT], timeouts=0
            [MULTI] [CONNECTING] multi_wait(fds=3, timeout=1000) tinternal=-1
            [MULTI] [PERFORMING] pollset[fd=1001 IN], timeouts=0
            [MULTI] [PERFORMING] multi_wait(fds=2, timeout=1000) tinternal=-1"
        )
    );
}

/// An application that runs the multi by its events: it watches the
/// sockets and the timer.
struct Watching;

impl crate::multi::MultiEvents<crate::multi::NoHost> for Watching {
    fn wants_timer(&self) -> bool {
        true
    }

    fn wants_sockets(&self) -> bool {
        true
    }
}

/// Run by its events, a transfer is traced as each dirty one runs, and its
/// pollset as event handling assesses it: after each run, the last one
/// done, and once more as it is taken out.
#[test]
fn a_transfer_run_by_events_is_traced_as_c() {
    let talk = Conversation::replies(&[OK], false);
    let mut m = waking("one.example", &[(local(), Peer::Accepts)], &talk);
    let mut e = tracing_wait();
    let seen = Seen::default();
    let o = e.options_mut();
    let url = format!("http://one.example:{PORT}/");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.output.verbose = true;
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    let id = m.add(Box::new(e), (), &mut Watching).unwrap();
    let result = crate::multi::drive_by_events(&mut m, id).unwrap();
    assert_eq!(result, Ok(()));
    m.remove(id, &mut Watching).unwrap();
    let lines: Vec<String> = seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            l.contains("] pollset[")
                || l.contains("] multi_run_dirty")
                || l.contains(" multi, mid=")
                || l.starts_with("[TCP] adjust_pollset")
                || l.contains(" gives multi timeout ")
        })
        .collect();
    assert_eq!(
        lines,
        expect(
            "[MULTI] [INIT] added to multi, mid=1, running=1, total=2
            [MULTI] [INIT] multi_run_dirty
            [TCP] adjust_pollset, !connected, POLLOUT fd=1000
            [MULTI] [CONNECTING] pollset[fd=1000 OUT], timeouts=0
            [MULTI] [CONNECTING] multi_run_dirty
            [MULTI] [MSGSENT] pollset[], timeouts=0, paused 0/0 (r/w)
            [MULTI] [COMPLETED] pollset[], timeouts=0, paused 0/0 (r/w)
            [MULTI] [COMPLETED] removed from multi, mid=1, running=0, total=1"
        )
    );
}

/// Through a proxy's tunnel: the wait for the answer to `CONNECT` is on
/// the socket the handshake runs over, which waits to read as C's socket
/// filter, connected but not yet in use, adds.
#[test]
fn a_tunnel_s_waits_are_traced_as_c() {
    let talk = Conversation::replies(&[TUNNEL_UP, OK], false).late_replies();
    let mut m = waking("unused.example", &[(local(), Peer::Accepts)], &talk);
    let ran = get_of(&mut m, "unused.example", talk, tunneled);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        wait_lines(&ran),
        expect(
            "[MULTI] [INIT] pollset[], timeouts=0, paused 0/0 (r/w)
            [MULTI] [INIT] multi_wait(fds=1, timeout=0) tinternal=0
            [TCP] adjust_pollset, !connected, POLLOUT fd=1000
            [MULTI] [CONNECTING] pollset[fd=1000 OUT], timeouts=0
            [MULTI] [CONNECTING] multi_wait(fds=2, timeout=1000) tinternal=-1
            [TCP] adjust_pollset, !active, POLLIN fd=1000
            [MULTI] [CONNECTING] pollset[fd=1000 IN], timeouts=0
            [MULTI] [CONNECTING] multi_wait(fds=2, timeout=1000) tinternal=-1
            [MULTI] [PERFORMING] pollset[fd=1000 IN], timeouts=0
            [MULTI] [PERFORMING] multi_wait(fds=2, timeout=1000) tinternal=-1"
        )
    );
}
