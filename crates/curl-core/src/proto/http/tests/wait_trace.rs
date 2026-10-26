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
use crate::conn::io::{Events, PollFd, Waker};
use crate::multi::{TransferId, WaitMode};

/// A handle tracing the multi, the timers and the socket.
fn tracing_wait() -> Easy {
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"multi,timer,tcp");
    e.set_components(Some(components));
    e
}

/// The lines of a run about its waits.
fn wait_lines(seen: &Seen) -> Vec<String> {
    seen.text()
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
        wait_lines(&ran.seen),
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
        wait_lines(&ran.seen),
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
        wait_lines(&ran.seen),
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
/// done, and once more as it is taken out; each change the socket
/// callback hears follows its pollset, as C's `curl_easy_perform_ev`
/// says it.
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
                || l.starts_with("socket cb:")
        })
        .collect();
    assert_eq!(
        lines,
        expect(
            "[MULTI] [INIT] added to multi, mid=1, running=1, total=2
            [MULTI] [INIT] multi_run_dirty
            [TCP] adjust_pollset, !connected, POLLOUT fd=1000
            [MULTI] [CONNECTING] pollset[fd=1000 OUT], timeouts=0
            socket cb: socket 1000 ADDED as OUT
            [MULTI] [CONNECTING] multi_run_dirty
            [MULTI] [MSGSENT] pollset[], timeouts=0, paused 0/0 (r/w)
            socket cb: socket 1000 REMOVED
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
        wait_lines(&ran.seen),
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

/// A GET of `ip`'s `PORT` added to `m`, tracing as `tracing_wait` does
/// into `seen`, its connect limited to `connect_ms` if given.
fn add_get(m: &mut Multi, ip: IpAddr, connect_ms: Option<u64>, seen: &Seen) -> TransferId {
    let mut e = tracing_wait();
    let o = e.options_mut();
    let url = format!("http://{}/", SocketAddr::new(ip, PORT));
    o.set_url(Some(url.as_bytes())).unwrap();
    o.output.verbose = true;
    o.limits.total = None;
    if let Some(ms) = connect_ms {
        o.limits.connect = crate::time::TimeLimit::from_millis(ms);
    }
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    m.add(Box::new(e), (), &mut NoEvents).unwrap()
}

/// The wait lines `seen` has from line `from` on.
fn wait_lines_from(seen: &Seen, from: usize) -> Vec<String> {
    let ran = Ran {
        result: Ok(()),
        request: Vec::new(),
        seen: seen.clone(),
        easy: Easy::new(),
    };
    wait_lines(&ran.seen).split_off(from)
}

/// `curl_multi_wait` waits on the waker only when it waits on something
/// else, a transfer's socket or the application's descriptor, where
/// `curl_multi_poll` always does; the count says so. The C build's lines
/// for the same calls, a transfer before its first step and then
/// connecting.
#[test]
fn a_wait_counts_the_waker_only_when_it_waits_as_c() {
    let talk = Conversation::replies(&[], false);
    let silent = IpAddr::from([192, 0, 2, 1]);
    let mut m = waking("unused.example", &[(silent, Peer::Silent)], &talk);
    let seen = Seen::default();
    add_get(&mut m, silent, None, &seen);
    let (_keep, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mine = || [PollFd::new(std::os::fd::AsFd::as_fd(&theirs), Events::IN)];
    let ms = Duration::from_millis(10);
    let waits = |m: &mut Multi, extra: &mut [PollFd<'_>], mode| {
        m.wait(extra, ms, mode, &mut NoEvents).unwrap();
    };
    waits(&mut m, &mut [], WaitMode::Wait);
    waits(&mut m, &mut mine(), WaitMode::Wait);
    m.perform(&mut NoEvents).unwrap();
    waits(&mut m, &mut [], WaitMode::Wait);
    waits(&mut m, &mut mine(), WaitMode::Wait);
    waits(&mut m, &mut [], WaitMode::Poll);
    let lines: Vec<String> = wait_lines_from(&seen, 0)
        .into_iter()
        .filter(|l| l.contains("multi_wait("))
        .collect();
    assert_eq!(
        lines,
        expect(
            "[MULTI] [INIT] multi_wait(fds=0, timeout=0) tinternal=0
            [MULTI] [INIT] multi_wait(fds=2, timeout=0) tinternal=0
            [MULTI] [CONNECTING] multi_wait(fds=2, timeout=10) tinternal=-1
            [MULTI] [CONNECTING] multi_wait(fds=3, timeout=10) tinternal=-1
            [MULTI] [CONNECTING] multi_wait(fds=2, timeout=10) tinternal=-1"
        )
    );
}

/// A multi without a waker counts none, even polling.
#[test]
fn a_multi_without_a_waker_counts_none() {
    let clock = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let seen = Seen::default();
    add_get(&mut m, IpAddr::from([192, 0, 2, 1]), None, &seen);
    m.wait(
        &mut [],
        Duration::from_millis(10),
        WaitMode::Poll,
        &mut NoEvents,
    )
    .unwrap();
    let lines = wait_lines_from(&seen, 0);
    assert_eq!(
        lines.last().unwrap(),
        "[MULTI] [INIT] multi_wait(fds=0, timeout=0) tinternal=0"
    );
}

/// A transfer done is not waited on, only those still at work (C's
/// `process` set); the multi's timeout, asked for, is traced on the
/// transfer whose timer gives it. The C build's lines for the same calls,
/// its times the fake clock's.
#[test]
fn only_transfers_at_work_are_waited_on_as_c() {
    let talk = Conversation::replies(&[OK], false);
    let silent = IpAddr::from([192, 0, 2, 1]);
    let mut m = waking(
        "unused.example",
        &[(local(), Peer::Accepts), (silent, Peer::Silent)],
        &talk,
    );
    let seen = Seen::default();
    add_get(&mut m, local(), None, &seen);
    add_get(&mut m, silent, Some(3000), &seen);
    while m.info_read().is_none() {
        m.perform(&mut NoEvents).unwrap();
    }
    let from = wait_lines_from(&seen, 0).len();
    m.wait(
        &mut [],
        Duration::from_millis(10),
        WaitMode::Wait,
        &mut NoEvents,
    )
    .unwrap();
    let timeout = m.timeout_traced(&mut NoEvents);
    assert_eq!(timeout, Some(Duration::from_millis(2990)));
    assert_eq!(
        wait_lines_from(&seen, from),
        expect(
            "[TCP] adjust_pollset, !connected, POLLOUT fd=1001
            [MULTI] [CONNECTING] pollset[fd=1001 OUT], timeouts=1
            [TIMER] [CONNECTTIMEOUT] expires in 3000000us
            [TIMER] [CONNECTTIMEOUT] gives multi timeout in 3000ms
            [MULTI] [CONNECTING] multi_wait(fds=2, timeout=10) tinternal=3000
            [TIMER] [CONNECTTIMEOUT] gives multi timeout in 2990ms"
        )
    );
}
