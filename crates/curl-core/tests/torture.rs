//! The multi under allocation failure: each scenario run once for every
//! allocation it makes, each run with that allocation and every later one
//! refused (`ENGINE.md` 8.2). Every run must end cleanly, with refusals
//! reported as `OutOfMemory` where an operation can allocate, and leave
//! nothing allocated behind it.
//!
//! The tracker's limit is process-wide, so this is its own test binary
//! without the libtest harness.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::cell::Cell;
use std::time::Duration;

use curl_alloc::track::{self, Tracker};
use curl_alloc::{OutOfMemory, TryArc, TryRc, try_box};
use curl_core::conn::io::{Conversation, FakeNet, Net, Peer, Waker};
use curl_core::easy::Easy;
use curl_core::error::{ErrorKind, MultiErrorKind};
use curl_core::handler::{
    Handler, HeaderHandler, HeaderOrigin, ProgressHandler, ProgressNow, ProgressVerdict, Write,
    WriteHandler,
};
use curl_core::id::ArenaPolicy;
use curl_core::multi::Multi;
use curl_core::multi::{
    Abort, AddError, Env, EventCx, MultiEvents, NoEvents, NoHost, Notification, NotifyCx,
    NotifyKind, PauseRequest, SocketEvent, TimerChange, TransferCx, WaitMode,
};
use curl_core::options::script::{Piece, Script};
use curl_core::options::{Progress, UploadSource};
use curl_core::time::{Clock, ManualClock, TimeLimit};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker;

fn main() {
    for (name, test) in [
        (
            "add_perform_remove_survives_every_allocation_failing",
            add_perform_remove_survives_every_allocation_failing as fn(),
        ),
        (
            "pausing_and_replaying_survives_every_allocation_failing",
            pausing_and_replaying_survives_every_allocation_failing,
        ),
        (
            "a_get_survives_every_allocation_failing",
            a_get_survives_every_allocation_failing,
        ),
        (
            "a_get_takes_no_refusal_for_success",
            a_get_takes_no_refusal_for_success,
        ),
        (
            "a_get_with_credentials_takes_no_refusal_for_success",
            a_get_with_credentials_takes_no_refusal_for_success,
        ),
        (
            "a_get_stays_within_its_allocation_budget",
            a_get_stays_within_its_allocation_budget,
        ),
    ] {
        // Reported as libtest does, the name before the run, so that a run
        // that aborts still shows which test it was in.
        track::untracked(|| {
            use std::io::Write as _;
            print!("test {name} ... ");
            std::io::stdout().flush().unwrap();
        });
        test();
        track::untracked(|| println!("ok"));
    }
}

/// More transfers than the arena's first 16 rows, so it grows.
const TRANSFERS: usize = 20;

#[derive(Default)]
struct Events {
    timer_calls: u32,
    notified: u32,
}

impl MultiEvents<NoHost> for Events {
    fn timer(&mut self, _: &mut EventCx<'_, NoHost>, _: TimerChange) -> Result<(), Abort> {
        self.timer_calls += 1;
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }

    fn notify(&mut self, _: &mut NotifyCx<'_, NoHost>, _: Notification) {
        self.notified += 1;
    }
}

/// What a run got through.
#[derive(Debug, Default, PartialEq, Eq)]
struct Outcome {
    added: usize,
    messages: usize,
    removed: usize,
}

/// Add transfers that complete, fail and time out, drive them, read them
/// and take them out. `Err` where setting up refused; an add refused for
/// memory skips that transfer; nothing after the adds may allocate.
fn scenario() -> Result<Outcome, OutOfMemory> {
    let clock = ManualClock::new()?;
    let boxed: Box<dyn Clock> = try_box(clock.clone())?;
    let net: Box<dyn Net> = try_box(fake_net(&clock))?;
    let waker = TryArc::try_new(Waker::new().expect("a socket pair"))?;
    let env = Env {
        clock: boxed,
        net,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: Some(waker),
    };
    let mut m: Multi = Multi::new(env)?;
    match m.wait(&mut [], Duration::ZERO, WaitMode::Poll) {
        Ok(0) | Err(MultiErrorKind::OutOfMemory) => {}
        other => panic!("an idle wait got {other:?}"),
    }
    m.set_notify(NotifyKind::InfoRead, true);
    m.set_notify(NotifyKind::EasyDone, true);
    let mut ev = Events::default();
    let mut out = Outcome::default();
    let mut ids = [None; TRANSFERS];
    for (i, id) in ids.iter_mut().enumerate() {
        let mut easy = Easy::new();
        let url: &[u8] = match i % 3 {
            0 => b"null://a",
            1 => b"stall://a",
            _ => b"nope://a",
        };
        if easy.options_mut().set_url(Some(url)).is_err() {
            continue;
        }
        easy.options_mut().limits.total = TimeLimit::from_millis(1000);
        match m.add(easy, (), &mut ev) {
            Ok(added) => {
                *id = Some(added);
                out.added += 1;
            }
            Err(AddError {
                kind: MultiErrorKind::OutOfMemory,
                ..
            }) => {}
            Err(e) => panic!("add refused with {:?}, not for memory", e.kind),
        }
    }
    m.perform(&mut ev).expect("a pass allocates nothing");
    m.socket_action(SocketEvent::Timeout, &mut ev)
        .expect("a pass allocates nothing");
    clock.advance(Duration::from_millis(1000));
    let running = m
        .socket_action(SocketEvent::Timeout, &mut ev)
        .expect("a pass allocates nothing");
    assert_eq!(running, 0, "every transfer has completed or timed out");
    while m.info_read().is_some() {
        out.messages += 1;
    }
    assert_eq!(out.messages, out.added);
    for id in ids.into_iter().flatten() {
        let removed = m.remove(id, &mut ev).expect("in the multi");
        removed.status.expect("the timer callback never aborts");
        out.removed += 1;
    }
    assert!(ev.notified > 0 || out.added == 0);
    Ok(out)
}

fn add_perform_remove_survives_every_allocation_failing() {
    let full = Outcome {
        added: TRANSFERS,
        messages: TRANSFERS,
        removed: TRANSFERS,
    };
    torture(scenario, Ok(full));
}

/// A network over `clock`, made untracked: the test's fake is not the
/// library's to account for.
fn fake_net(clock: &ManualClock) -> FakeNet {
    track::untracked(|| FakeNet::new(clock.clone()))
}

/// Run `scenario` once for each allocation it makes, that one and every
/// later one refused, until a run that refuses nothing gives `full`.
fn torture<T: PartialEq + std::fmt::Debug>(scenario: fn() -> T, full: T) {
    let mut limit = 0;
    loop {
        let live = track::live_tracked();
        let (outcome, refused) = track::fail_after(limit, scenario);
        assert_eq!(
            track::live_tracked(),
            live,
            "a run allowed {limit} allocations left blocks behind"
        );
        if !refused {
            assert_eq!(outcome, full, "a run with nothing refused");
            // Every allocation of the scenario has been refused in turn.
            assert!(limit > 0, "the scenario allocates nothing");
            track::untracked(|| eprintln!("torture: {limit} allocations, each refused in turn"));
            return;
        }
        limit += 1;
        assert!(limit < 100_000, "the scenario never ran to the end");
    }
}

/// What the pausing transfer's handlers took.
#[derive(Default)]
struct Taken {
    calls: Cell<u32>,
    body: Cell<u64>,
    headers: Cell<u64>,
}

/// Pauses every third call of either handler; takes the rest.
struct Pauser(TryRc<Taken>);

impl Pauser {
    fn take(&self, n: usize, into: &Cell<u64>) -> Write {
        let call = self.0.calls.get();
        self.0.calls.set(call + 1);
        if call.is_multiple_of(3) {
            return Write::Pause;
        }
        into.set(into.get() + n as u64);
        Write::Accepted
    }
}

impl WriteHandler for Pauser {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.take(body.len(), &self.0.body)
    }
}

impl HeaderHandler for Pauser {
    fn header(&self, _: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        self.take(line.len(), &self.0.headers)
    }
}

struct GoOn;

impl ProgressHandler for GoOn {
    fn progress(&self, _: &mut TransferCx<'_>, _: ProgressNow) -> ProgressVerdict {
        ProgressVerdict::Continue
    }
}

const STATUS: &[u8] = b"HTTP/1.1 200 OK\r\n";
const HEADER: &[u8] = b"A: 1\r\n";
const BODY: usize = 40000;

/// What the pause scenario got through: its result, what its handlers
/// took and what it sent.
#[derive(Debug, PartialEq, Eq)]
struct Paused {
    result: Result<(), ErrorKind>,
    body: u64,
    headers: u64,
    sent: u64,
}

/// A transfer whose handlers pause again and again, its output held and
/// replayed by unpauses from outside, while it also sends a body and
/// reports progress. `Err` where setting up refused; the transfer itself
/// may fail for memory, and nothing else.
fn pause_scenario() -> Result<Paused, OutOfMemory> {
    let clock = ManualClock::new()?;
    let env = Env {
        clock: try_box(clock.clone())?,
        net: try_box(fake_net(&clock))?,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::new(env)?;
    let mut easy = Easy::new();
    easy.options_mut().set_url(Some(b"script://a"))?;
    easy.options_mut().output.include_header = true;
    let taken = TryRc::try_new(Taken::default())?;
    let cb = &mut easy.options_mut().callbacks;
    cb.write = Some(Handler::write(Pauser(taken.clone()))?);
    cb.header = Some(Handler::header(Pauser(taken.clone()))?);
    easy.options_mut().progress = Progress::Handler(Handler::progress(GoOn)?);
    let mut upload = Vec::new();
    upload.try_reserve_exact(300).map_err(|_| OutOfMemory)?;
    upload.resize(300, b'u');
    easy.options_mut().upload = UploadSource::Bytes(TryRc::try_new(upload)?);
    let pieces = |n: usize| -> Result<Vec<u8>, OutOfMemory> {
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| OutOfMemory)?;
        v.resize(n, b'x');
        Ok(v)
    };
    let mut script = Vec::new();
    script.try_reserve_exact(9).map_err(|_| OutOfMemory)?;
    script.push(Piece::Send(100));
    script.push(Piece::Status(STATUS.to_vec_fallible()?));
    script.push(Piece::Header(HEADER.to_vec_fallible()?));
    script.push(Piece::Header(b"\r\n".to_vec_fallible()?));
    script.push(Piece::Body(pieces(BODY)?));
    script.push(Piece::Yield);
    script.push(Piece::SendAll);
    script.push(Piece::Body(pieces(10)?));
    easy.options_mut().script = Some(Script::new(script)?);
    let id = match m.add(easy, (), &mut NoEvents) {
        Ok(id) => id,
        Err(AddError {
            kind: MultiErrorKind::OutOfMemory,
            ..
        }) => return Err(OutOfMemory),
        Err(e) => panic!("add refused with {:?}, not for memory", e.kind),
    };
    let mut result = None;
    for _ in 0..100 {
        m.perform(&mut NoEvents).expect("a pass allocates nothing");
        if let Some(msg) = m.info_read() {
            result = Some(msg.result);
            break;
        }
        match m.pause(id, PauseRequest::CONT, &mut NoEvents) {
            Ok(()) => {}
            Err(e) => panic!("an unpause failed with {e:?}"),
        }
    }
    let result = result.expect("the transfer ends");
    assert!(
        matches!(result, Ok(()) | Err(ErrorKind::OutOfMemory)),
        "{result:?}"
    );
    let sent = m.easy(id).expect("in the multi").report().sizes().upload();
    m.remove(id, &mut NoEvents).expect("in the multi");
    Ok(Paused {
        result,
        body: taken.body.get(),
        headers: taken.headers.get(),
        sent,
    })
}

trait ToVecFallible {
    fn to_vec_fallible(&self) -> Result<Vec<u8>, OutOfMemory>;
}

impl ToVecFallible for [u8] {
    fn to_vec_fallible(&self) -> Result<Vec<u8>, OutOfMemory> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.len()).map_err(|_| OutOfMemory)?;
        v.extend_from_slice(self);
        Ok(v)
    }
}

fn pausing_and_replaying_survives_every_allocation_failing() {
    let head = (STATUS.len() + HEADER.len() + 2) as u64;
    let full = Paused {
        result: Ok(()),
        // With the headers included, the write handler takes them too.
        body: head + BODY as u64 + 10,
        headers: head,
        sent: 300,
    };
    torture(pause_scenario, Ok(full));
}

/// Test 1's reply.
const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nDate: Tue, 09 Nov 2010 14:49:00 GMT\r\n\
Server: test-server/fake\r\nContent-Length: 6\r\nContent-Type: text/html\r\n\r\n-foo-\n";

/// What a GET got through: its result, and what its handlers took.
#[derive(Debug, PartialEq, Eq)]
struct Got {
    result: Result<(), ErrorKind>,
    body: u64,
    headers: u64,
}

/// What a handler took.
#[derive(Default)]
struct Took {
    body: Cell<u64>,
    headers: Cell<u64>,
}

struct Taker(TryRc<Took>);

impl WriteHandler for Taker {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.body.set(self.0.body.get() + body.len() as u64);
        Write::Accepted
    }
}

impl HeaderHandler for Taker {
    fn header(&self, _: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        self.0.headers.set(self.0.headers.get() + line.len() as u64);
        Write::Accepted
    }
}

/// The GET's URL, and the request it sends.
const URL: &[u8] = b"http://127.0.0.1/1?q";
const REQUEST: &[u8] =
    b"GET /1?q HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n";

/// The same with the URL's credentials, sent as Basic.
const AUTHED_URL: &[u8] = b"http://u:p@127.0.0.1/1?q";
const AUTHED_REQUEST: &[u8] = b"GET /1?q HTTP/1.1\r\nHost: 127.0.0.1\r\n\
    Authorization: Basic dTpw\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n";

/// A network with a server at port 80 answering test 1's reply, and the
/// server, made untracked: the test's peer is not the library's to
/// account for.
fn test_1_server() -> (ManualClock, FakeNet, Conversation) {
    track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
        let talk = Conversation::new(REPLY, false);
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        (clock, net, talk)
    })
}

/// A plain GET over `net` to `talk`, from a new multi to its removal.
/// `Err` where setting up refused; the transfer itself may fail for
/// memory, and nothing else, and when it succeeds it sent the whole
/// request.
fn get(clock: ManualClock, net: FakeNet, talk: &Conversation) -> Result<Got, OutOfMemory> {
    get_of(clock, net, talk, URL, REQUEST)
}

/// A GET of `url` that sends `request`, as `get`.
fn get_of(
    clock: ManualClock,
    net: FakeNet,
    talk: &Conversation,
    url: &[u8],
    request: &[u8],
) -> Result<Got, OutOfMemory> {
    let env = Env {
        clock: try_box(clock)?,
        net: try_box(net)?,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::new(env)?;
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(url))?;
    o.http.user_agent = Some(b"curl/test".to_vec_fallible()?);
    let took = TryRc::try_new(Took::default())?;
    o.callbacks.write = Some(Handler::write(Taker(took.clone()))?);
    o.callbacks.header = Some(Handler::header(Taker(took.clone()))?);
    let id = match m.add(easy, (), &mut NoEvents) {
        Ok(id) => id,
        Err(AddError {
            kind: MultiErrorKind::OutOfMemory,
            ..
        }) => return Err(OutOfMemory),
        Err(e) => panic!("add refused with {:?}, not for memory", e.kind),
    };
    let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents)
        .expect("the transfer is in the multi");
    if !matches!(result, Ok(()) | Err(ErrorKind::OutOfMemory)) {
        track::untracked(|| panic!("the GET ended with {result:?}"));
    }
    if result.is_ok() {
        track::untracked(|| assert_eq!(talk.received(), request, "the request sent"));
    }
    m.remove(id, &mut NoEvents).expect("in the multi");
    Ok(Got {
        result,
        body: took.body.get(),
        headers: took.headers.get(),
    })
}

fn get_scenario() -> Result<Got, OutOfMemory> {
    let (clock, net, talk) = test_1_server();
    get(clock, net, &talk)
}

fn a_get_survives_every_allocation_failing() {
    let full = Got {
        result: Ok(()),
        body: 6,
        headers: REPLY.len() as u64 - 6,
    };
    torture(get_scenario, Ok(full));
}

/// Run `scenario` once for each allocation it makes, that one alone
/// refused, until a run that refuses nothing: each run with a refusal
/// must have `failed`, for a refusal taken for success is a failure
/// swallowed.
fn refused_alone<T: std::fmt::Debug>(scenario: fn() -> T, failed: fn(&T) -> bool) {
    let mut limit = 0;
    loop {
        let live = track::live_tracked();
        let (outcome, refused) = track::fail_once_after(limit, scenario);
        assert_eq!(
            track::live_tracked(),
            live,
            "a run refusing allocation {limit} left blocks behind"
        );
        if !refused {
            assert!(limit > 0, "the scenario allocates nothing");
            track::untracked(|| eprintln!("torture: {limit} allocations, each refused alone"));
            return;
        }
        if !failed(&outcome) {
            track::untracked(|| panic!("a run refusing allocation {limit} alone gave {outcome:?}"));
        }
        limit += 1;
        assert!(limit < 100_000, "the scenario never ran to the end");
    }
}

/// A refusal while taking the URL's credentials fails the transfer: it
/// never goes without them.
fn a_get_with_credentials_takes_no_refusal_for_success() {
    fn scenario() -> Result<Got, OutOfMemory> {
        let (clock, net, talk) = test_1_server();
        get_of(clock, net, &talk, AUTHED_URL, AUTHED_REQUEST)
    }
    refused_alone(scenario, |got| {
        matches!(
            got,
            Err(OutOfMemory)
                | Ok(Got {
                    result: Err(ErrorKind::OutOfMemory),
                    ..
                })
        )
    });
}

fn a_get_takes_no_refusal_for_success() {
    refused_alone(get_scenario, |got| {
        matches!(
            got,
            Err(OutOfMemory)
                | Ok(Got {
                    result: Err(ErrorKind::OutOfMemory),
                    ..
                })
        )
    });
}

/// What a plain GET with a query allocates, from a new multi to its
/// removal (`ENGINE.md` 8.1): the multi; the easy's URL, user agent and
/// handlers; the transfer's place in the multi; then the URL as fetched
/// and its parts, the URL read back once parsed (as C reads it back), the
/// target grown by its query, the protocol's state, the peer, the
/// effective URL kept for the report, the answer for the host kept in the
/// DNS cache (its name, its addresses, the answer shared, the cache's
/// table), the list of connect attempts, the socket, the request head, the
/// receive buffer, the head parser's line, the header store and the
/// content type.
const GET_BUDGET: u64 = 45;

fn a_get_stays_within_its_allocation_budget() {
    let (clock, net, talk) = test_1_server();
    let (got, n) = track::count_allocations(|| get(clock, net, &talk));
    assert_eq!(got.expect("nothing refused").result, Ok(()));
    track::untracked(|| eprintln!("budget: a plain GET made {n} allocations"));
    assert!(
        n <= GET_BUDGET,
        "a plain GET made {n} allocations, over its {GET_BUDGET}"
    );
}
