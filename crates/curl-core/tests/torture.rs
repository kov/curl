//! The multi under allocation failure: each scenario run once for every
//! allocation it makes, each run with that allocation and every later one
//! refused (`ENGINE.md` 8.2). Every run must end cleanly, with refusals
//! reported as `OutOfMemory` where an operation can allocate, and leave
//! nothing allocated behind it.
//!
//! The tracker's limit is process-wide, so this is its own test binary
//! without the libtest harness.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::time::Duration;

use curl_alloc::track::{self, Tracker};
use curl_alloc::{OutOfMemory, TryArc, try_box};
use curl_core::conn::io::{Conversation, FakeNet, Net, Peer, Waker};
use curl_core::easy::Easy;
use curl_core::error::{ErrorKind, MultiErrorKind};
use curl_core::handler::{
    DebugHandler, DebugKind, Handler, HeaderHandler, HeaderOrigin, ProgressHandler, ProgressNow,
    ProgressVerdict, Write, WriteHandler,
};
use curl_core::id::ArenaPolicy;
use curl_core::libraries::{Libraries, Library, SharedLibraries};
use curl_core::multi::Multi;
use curl_core::multi::{
    Abort, AddError, Env, EventCx, MultiEvents, NoEvents, NoHost, Notification, NotifyCx,
    NotifyKind, PauseRequest, SocketEvent, TimerChange, TransferCx, WaitMode,
};
use curl_core::options::script::{Piece, Script};
use curl_core::options::{Options, Progress, UploadSource};
use curl_core::time::{Clock, ManualClock, TimeLimit};
use curl_core::tls::fake::{self, FakeTls};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker;

fn main() {
    let wanted: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
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
            "a_refused_connect_survives_every_allocation_failing",
            a_refused_connect_survives_every_allocation_failing,
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
            "a_tunneled_get_takes_no_refusal_for_success",
            a_tunneled_get_takes_no_refusal_for_success,
        ),
        (
            "a_digest_get_takes_no_refusal_for_success",
            a_digest_get_takes_no_refusal_for_success,
        ),
        (
            "a_get_stays_within_its_allocation_budget",
            a_get_stays_within_its_allocation_budget,
        ),
        (
            "an_https_get_survives_every_allocation_failing",
            an_https_get_survives_every_allocation_failing,
        ),
        (
            "an_https_get_takes_no_refusal_for_success",
            an_https_get_takes_no_refusal_for_success,
        ),
        (
            "an_https_get_stays_within_its_allocation_budget",
            an_https_get_stays_within_its_allocation_budget,
        ),
        (
            "a_share_s_connection_survives_every_allocation_failing",
            a_share_s_connection_survives_every_allocation_failing,
        ),
        (
            "a_lost_trailer_line_fails_the_request",
            a_lost_trailer_line_fails_the_request,
        ),
        (
            "a_cold_group_is_made_or_refused_at_its_first_set",
            a_cold_group_is_made_or_refused_at_its_first_set,
        ),
        (
            "a_file_part_s_long_name_is_read_without_a_copy",
            a_file_part_s_long_name_is_read_without_a_copy,
        ),
    ] {
        // The tests whose names hold a filter given, if any is, as libtest.
        if !wanted.is_empty() && !wanted.iter().any(|w| name.contains(w.as_str())) {
            continue;
        }
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
    let net: Box<dyn Net + Send> = try_box(fake_net(&clock))?;
    let waker = TryArc::try_new(Waker::new().expect("an eventfd"))?;
    let env = Env {
        clock: boxed,
        net,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: Some(waker),
    };
    let mut m: Multi = Multi::new(env)?;
    match m.wait(&mut [], Duration::ZERO, WaitMode::Poll, &mut NoEvents) {
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
        let Ok(easy) = try_box(easy) else {
            continue;
        };
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
struct Pauser(TryArc<Taken>);

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
    let taken = TryArc::try_new(Taken::default())?;
    let cb = &mut easy.options_mut().callbacks;
    cb.write = Some(Handler::write(Pauser(taken.clone()))?);
    cb.header = Some(Handler::header(Pauser(taken.clone()))?);
    easy.options_mut().progress = Progress::Handler(Handler::progress(GoOn)?);
    let mut upload = Vec::new();
    upload.try_reserve_exact(300).map_err(|_| OutOfMemory)?;
    upload.resize(300, b'u');
    easy.options_mut().upload = UploadSource::Bytes(TryArc::try_new(upload)?);
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
    let id = match m.add(try_box(easy)?, (), &mut NoEvents) {
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

struct Taker(TryArc<Took>);

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
    get_through(clock, net, talk, url, request, |_| Ok(()))
}

/// As `get_of`, with the options `set` makes.
fn get_through(
    clock: ManualClock,
    net: FakeNet,
    talk: &Conversation,
    url: &[u8],
    request: &[u8],
    set: fn(&mut Options) -> Result<(), OutOfMemory>,
) -> Result<Got, OutOfMemory> {
    let wire = Wire {
        libraries: SharedLibraries::default(),
        sent: <[u8]>::to_vec,
    };
    get_over(clock, net, talk, (url, request), set, wire)
}

/// What a GET speaks to its server with: the libraries its handle has,
/// and how what the server was sent reads as the request.
struct Wire {
    libraries: SharedLibraries,
    sent: fn(&[u8]) -> Vec<u8>,
}

/// As `get_through`, by a handle speaking as `wire` says.
fn get_over(
    clock: ManualClock,
    net: FakeNet,
    talk: &Conversation,
    (url, request): (&[u8], &[u8]),
    set: fn(&mut Options) -> Result<(), OutOfMemory>,
    wire: Wire,
) -> Result<Got, OutOfMemory> {
    let env = Env {
        clock: try_box(clock)?,
        net: try_box(net)?,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::new(env)?;
    let mut easy = Easy::new();
    easy.set_libraries(wire.libraries);
    let o = easy.options_mut();
    o.set_url(Some(url))?;
    o.http.user_agent = Some(b"curl/test".to_vec_fallible()?);
    let took = TryArc::try_new(Took::default())?;
    o.callbacks.write = Some(Handler::write(Taker(took.clone()))?);
    o.callbacks.header = Some(Handler::header(Taker(took.clone()))?);
    set(o)?;
    let id = match m.add(try_box(easy)?, (), &mut NoEvents) {
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
        track::untracked(|| assert_eq!((wire.sent)(&talk.received()), request, "the request sent"));
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

/// Takes the trace and keeps none of it.
struct Discard;

impl DebugHandler for Discard {
    fn debug(&self, _: &mut TransferCx<'_>, _: DebugKind, _: &[u8]) {}
}

/// A traced GET to a port nothing listens on: the connect is refused at
/// once, and the trace says why in the system's words (test 504). The
/// transfer fails to connect, or for memory, and nothing else.
fn refused_scenario() -> Result<Result<(), ErrorKind>, OutOfMemory> {
    let clock = track::untracked(|| ManualClock::new().expect("a clock"));
    let env = Env {
        net: try_box(fake_net(&clock))?,
        clock: try_box(clock)?,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::new(env)?;
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(URL))?;
    o.output.verbose = true;
    o.callbacks.debug = Some(Handler::debug(Discard)?);
    let id = match m.add(try_box(easy)?, (), &mut NoEvents) {
        Ok(id) => id,
        Err(AddError {
            kind: MultiErrorKind::OutOfMemory,
            ..
        }) => return Err(OutOfMemory),
        Err(e) => panic!("add refused with {:?}, not for memory", e.kind),
    };
    let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents)
        .expect("the transfer is in the multi");
    if !matches!(
        result,
        Err(ErrorKind::CouldntConnect | ErrorKind::OutOfMemory)
    ) {
        track::untracked(|| panic!("the GET ended with {result:?}"));
    }
    m.remove(id, &mut NoEvents).expect("in the multi");
    Ok(result)
}

fn a_refused_connect_survives_every_allocation_failing() {
    torture(refused_scenario, Ok(Err(ErrorKind::CouldntConnect)));
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

/// A refusal while setting up a tunnel, or reading the proxy's answer,
/// fails the transfer for memory: never as a bad answer, never unnoticed.
fn a_tunneled_get_takes_no_refusal_for_success() {
    fn scenario() -> Result<Got, OutOfMemory> {
        let (clock, net, talk) = track::untracked(|| {
            let clock = ManualClock::new().expect("a clock");
            let at = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
            let talk = Conversation::replies(&[b"HTTP/1.1 200 Fine\r\n\r\n", REPLY], false);
            let net = FakeNet::new(clock.clone())
                .with_peer(at, Peer::Accepts)
                .with_conversation(at, talk.clone());
            (clock, net, talk)
        });
        let request = b"CONNECT origin.example:80 HTTP/1.1\r\nHost: origin.example:80\r\n\
            User-Agent: curl/test\r\nProxy-Connection: Keep-Alive\r\n\r\n\
            GET /1?q HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\n\
            Accept: */*\r\n\r\n";
        get_through(
            clock,
            net,
            &talk,
            b"http://origin.example/1?q",
            request,
            |o| {
                o.proxy.make_mut()?.url = Some(b"127.0.0.1:80".to_vec_fallible()?);
                o.proxy.make_mut()?.tunnel = true;
                Ok(())
            },
        )
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

/// A refusal while reading a Digest challenge, or answering it, fails the
/// transfer for memory: never the challenge read short, its 401 taken
/// for the answer or a part of it left out of the next request.
fn a_digest_get_takes_no_refusal_for_success() {
    fn scenario() -> Result<Got, OutOfMemory> {
        let (clock, net, talk) = track::untracked(|| {
            let clock = ManualClock::new().expect("a clock");
            let at = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
            let challenge = b"HTTP/1.1 401 Who\r\n\
                WWW-Authenticate: Digest realm=\"r\", nonce=\"n\", opaque=\"o\"\r\n\
                Content-Length: 0\r\n\r\n";
            let talk = Conversation::replies(&[challenge, REPLY], false);
            let net = FakeNet::new(clock.clone())
                .with_peer(at, Peer::Accepts)
                .with_conversation(at, talk.clone());
            (clock, net, talk)
        });
        let request = b"GET /1?q HTTP/1.1\r\nHost: 127.0.0.1\r\n\
            User-Agent: curl/test\r\nAccept: */*\r\n\r\n\
            GET /1?q HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Digest username=\"u\", \
            realm=\"r\", nonce=\"n\", uri=\"/1?q\", \
            response=\"38695cf802675b1ab04d0f17de868231\", opaque=\"o\"\r\n\
            User-Agent: curl/test\r\nAccept: */*\r\n\r\n";
        get_through(clock, net, &talk, AUTHED_URL, request, |o| {
            o.http.auth = curl_core::options::HttpAuth(curl_core::options::AuthMethods::DIGEST);
            Ok(())
        })
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
/// handlers; the transfer's place in the multi and its slot, boxed so
/// the table's empty rows cost little, as C's hold pointers; then the URL as fetched
/// and its parts, the URL read back once parsed (as C reads it back), the
/// target grown by its query, the protocol's state, the peer, the
/// effective URL kept for the report, the answer for the host kept in the
/// DNS cache (its name, its addresses, the answer shared, the cache's
/// table), the list of connect attempts, the socket, the request head, the
/// receive buffer, the head parser's line, the header store and the
/// content type.
const GET_BUDGET: u64 = 46;

/// The fake TLS library and the libraries naming it, made once and
/// untracked: the test's, not the library's to account for.
fn fake_tls() -> SharedLibraries {
    static LIBRARIES: std::sync::OnceLock<SharedLibraries> = std::sync::OnceLock::new();
    LIBRARIES
        .get_or_init(|| {
            track::untracked(|| {
                let backend = Box::new(FakeTls::new().expect("memory"));
                SharedLibraries::new(Libraries {
                    tls: Some(Library::Owned(backend)),
                    ..Libraries::NONE
                })
                .expect("memory")
            })
        })
        .clone()
}

/// A server at port 443 speaking the fake TLS, answering test 1's reply
/// and saying goodbye back at once, made untracked: the connection,
/// closed as the multi goes, is shut down in the one try it gets.
fn test_1_tls_server() -> (ManualClock, FakeNet, Conversation) {
    track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 443));
        let records = fake::records(REPLY).expect("memory");
        let talk = Conversation::replies(&[fake::WELCOME, &records, fake::CLOSE], false);
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        (clock, net, talk)
    })
}

/// What the server of an HTTPS GET was sent, read as the request: the
/// handshake's lines taken off, the records read.
fn sent_over_tls(wire: &[u8]) -> Vec<u8> {
    let read = fake::read_client(wire).expect("memory");
    let lines = [fake::HELLO, fake::FINISHED].concat();
    read.strip_prefix(&lines[..]).unwrap_or(&read).to_vec()
}

/// A GET of test 1's URL over HTTPS through the fake TLS library.
fn https_get_scenario() -> Result<Got, OutOfMemory> {
    let (clock, net, talk) = test_1_tls_server();
    let wire = Wire {
        libraries: fake_tls(),
        sent: sent_over_tls,
    };
    let url = b"https://127.0.0.1/1?q";
    get_over(clock, net, &talk, (url, REQUEST), |_| Ok(()), wire)
}

fn an_https_get_survives_every_allocation_failing() {
    fake_tls();
    let full = Got {
        result: Ok(()),
        body: 6,
        headers: REPLY.len() as u64 - 6,
    };
    torture(https_get_scenario, Ok(full));
}

fn an_https_get_takes_no_refusal_for_success() {
    fake_tls();
    refused_alone(https_get_scenario, |got| {
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

/// What an HTTPS GET allocates over the fake TLS library, the core's
/// own beside the plain GET's 46: the route's TLS identity (shared with
/// the connection), the handshake under way, the library's session, its
/// layer, the stream's layer stack and its list, and the multi's
/// `TlsShared` with the fake's state boxed in it, made with the multi's
/// first session; and the key the connection's TLS sessions are kept
/// by, which the fake keeps none under. The fake's session is one box; a
/// real library's own memory is its own.
const HTTPS_FAKE_GET_BUDGET: u64 = GET_BUDGET + 9;

fn an_https_get_stays_within_its_allocation_budget() {
    fake_tls();
    let (got, n) = track::count_allocations(https_get_scenario);
    assert_eq!(got.expect("nothing refused").result, Ok(()));
    track::untracked(|| eprintln!("budget: an HTTPS GET over the fake made {n} allocations"));
    assert!(
        n <= HTTPS_FAKE_GET_BUDGET,
        "an HTTPS GET over the fake made {n} allocations, over its {HTTPS_FAKE_GET_BUDGET}"
    );
}

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

/// One fake network for a multi and the share whose connections it
/// uses, as the share closes them at its end.
struct SharedNet(TryArc<std::sync::Mutex<FakeNet>>);

impl Net for SharedNet {
    fn poll(
        &mut self,
        sockets: &mut [curl_core::conn::io::SocketPoll<'_>],
        fds: &mut [curl_core::conn::io::PollFd<'_>],
        timeout: Duration,
    ) -> std::io::Result<u32> {
        self.0.lock().unwrap().poll(sockets, fds, timeout)
    }

    fn open(
        &mut self,
        addr: &curl_core::conn::io::Remote,
    ) -> std::io::Result<Box<dyn curl_core::conn::io::Socket>> {
        self.0.lock().unwrap().open(addr)
    }

    fn close(&mut self, socket: curl_core::conn::io::Sock) {
        self.0.lock().unwrap().close(socket);
    }

    fn resolve(
        &mut self,
        name: &[u8],
        family: curl_core::conn::io::Family,
    ) -> Result<Vec<std::net::IpAddr>, curl_core::conn::io::ResolveFailure> {
        self.0.lock().unwrap().resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        None
    }

    fn interface_address(
        &mut self,
        _: &[u8],
        _: bool,
        _: curl_core::conn::io::Ipv6Scope,
        _: u32,
    ) -> curl_core::conn::io::InterfaceAddress {
        curl_core::conn::io::InterfaceAddress::NotFound
    }
}

/// Two GETs of a multi whose connections a share keeps, the second
/// reusing the first's: the search of the share's pool makes room for
/// the sockets it may close before it runs. Each GET's result.
fn shared_scenario() -> Result<[Result<(), ErrorKind>; 2], OutOfMemory> {
    let (clock, talk) = track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        (clock, Conversation::replies(&[REPLY, REPLY], false))
    });
    let net = track::untracked(|| {
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        TryArc::try_new(std::sync::Mutex::new(net)).expect("a test's network")
    });
    let share = curl_core::share::Share::with_net(try_box(SharedNet(net.clone()))?)?;
    share
        .keep(curl_core::share::Kind::Connections)
        .expect("no handle holds it yet");
    let env = Env {
        clock: try_box(clock)?,
        net: try_box(SharedNet(net))?,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::new(env)?;
    let mut results = [Ok(()), Ok(())];
    for result in &mut results {
        let mut easy = Easy::new();
        easy.set_share(Some(share.clone()));
        easy.options_mut().set_url(Some(URL))?;
        let id = match m.add(try_box(easy)?, (), &mut NoEvents) {
            Ok(id) => id,
            Err(AddError {
                kind: MultiErrorKind::OutOfMemory,
                ..
            }) => return Err(OutOfMemory),
            Err(e) => panic!("add refused with {:?}, not for memory", e.kind),
        };
        *result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents)
            .expect("the transfer is in the multi");
        if !matches!(result, Ok(()) | Err(ErrorKind::OutOfMemory)) {
            track::untracked(|| panic!("a GET ended with {result:?}"));
        }
        m.remove(id, &mut NoEvents).expect("in the multi");
    }
    Ok(results)
}

fn a_share_s_connection_survives_every_allocation_failing() {
    torture(shared_scenario, Ok([Ok(()), Ok(())]));
}

/// A count the handlers keep, `Sync` as a handler is; a lock makes no
/// allocation.
#[derive(Default)]
struct Cell<T>(std::sync::Mutex<T>);

impl<T: Copy> Cell<T> {
    fn get(&self) -> T {
        *self.0.lock().unwrap()
    }

    fn set(&self, value: T) {
        *self.0.lock().unwrap() = value;
    }
}

/// A trailer line the application's handler could not add, for want of
/// memory, fails the request, though lines after it were added.
fn a_lost_trailer_line_fails_the_request() {
    use curl_core::handler::{TrailerHandler, TrailerLines, Trailers};
    use curl_core::options::{Method, UserHeaders};
    struct LosesOne;
    impl TrailerHandler for LosesOne {
        fn trailers(&self, _: &mut TransferCx<'_>, lines: &mut TrailerLines) -> Trailers {
            let (added, refused) = track::fail_once_after(0, || lines.add(b"X-A: 1"));
            assert!(refused && added.is_err(), "the line's copy refused");
            lines.add(b"Y: 2").expect("refused once only");
            Trailers::Done
        }
    }
    let (clock, net, talk) = test_1_server();
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).expect("a multi");
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(URL)).expect("a URL");
    o.method = Method::Post;
    o.upload = UploadSource::Bytes(TryArc::try_new(b"abc".to_vec()).expect("a body"));
    o.http.headers =
        UserHeaders::new([&b"Transfer-Encoding: chunked"[..], b"Expect:"]).expect("headers");
    o.callbacks.trailer = Some(Handler::trailer(LosesOne).expect("a handler"));
    let id = m.add(Box::new(easy), (), &mut NoEvents).expect("added");
    let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents)
        .expect("the transfer is in the multi");
    assert_eq!(result, Err(ErrorKind::OutOfMemory));
    let sent = talk.received();
    assert!(!sent.ends_with(b"Y: 2\r\n\r\n"), "no trailers went");
    m.remove(id, &mut NoEvents).expect("in the multi");
}

/// A group of options few transfers set is made by the first set of one
/// of them, which is where memory can run out: refused, the options still
/// read the group's defaults, and a later set makes it. Options with no
/// such group made allocate nothing, copied or not.
fn a_cold_group_is_made_or_refused_at_its_first_set() {
    let (mut o, n) = track::count_allocations(Options::default);
    assert_eq!(n, 0, "nothing set, nothing made");
    let (set, refused) = track::fail_after(0, || o.proxy.make_mut().map(|p| p.tunnel = true));
    assert!(refused);
    assert_eq!(set, Err(OutOfMemory));
    assert!(!o.proxy.tunnel, "the defaults, still");
    let ((), n) = track::count_allocations(|| o.proxy.make_mut().expect("memory").tunnel = true);
    assert_eq!(n, 1, "the group, made");
    assert!(o.proxy.tunnel);
    let ((), n) = track::count_allocations(|| o.proxy.make_mut().expect("made").tunnel = false);
    assert_eq!(n, 0, "made once");
    let (copy, n) = track::count_allocations(|| o.try_clone().expect("memory"));
    assert_eq!(n, 1, "the copy makes the proxy group alone");
    assert!(copy.login.user.is_none() && !copy.proxy.tunnel);
}

/// A file part's status is read by its name copied to the stack, as C's
/// `stat` takes it: a name longer than std's 384-byte stack buffer would
/// otherwise be copied to the heap by an allocation that cannot fail.
fn a_file_part_s_long_name_is_read_without_a_copy() {
    let name = [b'n'; 400];
    let (made, n) = track::count_allocations(|| curl_core::mime::FileData::new(&name));
    assert_eq!(made.err(), Some(curl_core::mime::FileError::Unreadable));
    assert_eq!(n, 0, "the name's status read with nothing allocated");
}
