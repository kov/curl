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
use curl_core::components::Components;
use curl_core::conn::io::{Conversation, FakeNet, Net, Peer, Waker, Winsock};
use curl_core::easy::Easy;
use curl_core::error::{ErrorKind, MultiErrorKind};
use curl_core::handler::{
    DebugHandler, DebugKind, Handler, HeaderHandler, HeaderOrigin, ProgressHandler, ProgressNow,
    ProgressVerdict, Write, WriteHandler,
};
use curl_core::http3::fake::{FakeHttp3, Script as H3Script, Told};
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
            "a_get_with_a_tls_library_allocates_as_one_without",
            a_get_with_a_tls_library_allocates_as_one_without,
        ),
        (
            "a_share_stays_within_its_allocation_budget",
            a_share_stays_within_its_allocation_budget,
        ),
        (
            "a_wait_on_a_few_sockets_allocates_nothing",
            a_wait_on_a_few_sockets_allocates_nothing,
        ),
        (
            "a_wait_on_more_sockets_allocates_once_for_each_pass",
            a_wait_on_more_sockets_allocates_once_for_each_pass,
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
            "a_tls_identity_is_made_once_per_connection",
            a_tls_identity_is_made_once_per_connection,
        ),
        (
            "a_waiting_transfer_s_new_ip_version_takes_no_refusal_for_success",
            a_waiting_transfer_s_new_ip_version_takes_no_refusal_for_success,
        ),
        (
            "an_http_2_body_s_frames_allocate_nothing",
            an_http_2_body_s_frames_allocate_nothing,
        ),
        (
            "an_http_2_get_stays_within_its_allocation_budget",
            an_http_2_get_stays_within_its_allocation_budget,
        ),
        (
            "an_ftp_data_tunnel_s_wait_allocates_nothing_per_pass",
            an_ftp_data_tunnel_s_wait_allocates_nothing_per_pass,
        ),
        (
            "an_ftp_data_connect_s_wait_allocates_nothing_per_pass",
            an_ftp_data_connect_s_wait_allocates_nothing_per_pass,
        ),
        (
            "a_share_s_connection_survives_every_allocation_failing",
            a_share_s_connection_survives_every_allocation_failing,
        ),
        (
            "a_quit_said_is_answered_before_its_connection_closes_whatever_is_refused",
            a_quit_said_is_answered_before_its_connection_closes_whatever_is_refused,
        ),
        (
            "a_push_that_cannot_start_leaves_nothing_running",
            a_push_that_cannot_start_leaves_nothing_running,
        ),
        (
            "a_lost_trailer_line_fails_the_request",
            a_lost_trailer_line_fails_the_request,
        ),
        (
            "a_cold_group_is_made_or_refused_at_its_first_set",
            a_cold_group_is_made_or_refused_at_its_first_set,
        ),
        ("a_handler_is_one_allocation", a_handler_is_one_allocation),
        (
            "a_file_part_s_long_name_is_read_without_a_copy",
            a_file_part_s_long_name_is_read_without_a_copy,
        ),
        (
            "an_http3_get_survives_every_allocation_failing",
            an_http3_get_survives_every_allocation_failing,
        ),
        (
            "an_http3_get_takes_no_refusal_for_success",
            an_http3_get_takes_no_refusal_for_success,
        ),
        (
            "an_http3_get_stays_within_its_allocation_budget",
            an_http3_get_stays_within_its_allocation_budget,
        ),
        (
            "a_tunnel_through_an_http3_proxy_survives_every_allocation_failing",
            a_tunnel_through_an_http3_proxy_survives_every_allocation_failing,
        ),
        (
            "a_tunnel_through_an_http3_proxy_takes_no_refusal_for_success",
            a_tunnel_through_an_http3_proxy_takes_no_refusal_for_success,
        ),
        (
            "http3_through_an_http3_proxy_survives_every_allocation_failing",
            http3_through_an_http3_proxy_survives_every_allocation_failing,
        ),
        (
            "http3_through_an_http3_proxy_takes_no_refusal_for_success",
            http3_through_an_http3_proxy_takes_no_refusal_for_success,
        ),
        (
            "quic_receive_rooms_are_left_unwritten",
            quic_receive_rooms_are_left_unwritten,
        ),
        (
            "one_quic_receive_room_per_multi",
            one_quic_receive_room_per_multi,
        ),
    ] {
        // The tests whose names hold a filter given, if any is, as libtest.
        if !wanted.is_empty() && !wanted.iter().any(|w| name.contains(w.as_str())) {
            continue;
        }
        if !cfg!(target_os = "linux") && RUN_ON_LINUX_ALONE.contains(&name) {
            track::untracked(|| println!("test {name} ... ignored, a fake server's replies"));
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

/// The HTTP/3 tests, whose fake server answers each send with its next
/// reply: they run where QUIC sends a run of datagrams in one call, as on
/// Linux, as the HTTP/3 trace tests do (`proto::http::tests`). Where each
/// datagram is a send of its own the replies come a flight early.
const RUN_ON_LINUX_ALONE: &[&str] = &[
    "an_http3_get_survives_every_allocation_failing",
    "an_http3_get_takes_no_refusal_for_success",
    "an_http3_get_stays_within_its_allocation_budget",
    "a_tunnel_through_an_http3_proxy_survives_every_allocation_failing",
    "a_tunnel_through_an_http3_proxy_takes_no_refusal_for_success",
    "http3_through_an_http3_proxy_survives_every_allocation_failing",
    "http3_through_an_http3_proxy_takes_no_refusal_for_success",
    "quic_receive_rooms_are_left_unwritten",
    "one_quic_receive_room_per_multi",
];

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
    // On Windows the waker is a pair of loopback sockets, made only with
    // Winsock started, as `Multi::new` expects of whoever makes it; held
    // until the multi has gone.
    let _winsock = Winsock::start().expect("Winsock");
    let waker = TryArc::try_new(Waker::new().expect("a waker"))?;
    let env = Env {
        clock: boxed,
        net,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: Some(waker),
    };
    let mut m: Multi = Multi::with_env(env)?;
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
    let mut m: Multi = Multi::with_env(env)?;
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
        refused_as: None,
        trace_all: false,
    };
    get_over(clock, net, talk, (url, request), set, wire)
}

/// What a GET speaks to its server with: the libraries its handle has,
/// and how what the server was sent reads as the request.
struct Wire {
    libraries: SharedLibraries,
    sent: fn(&[u8]) -> Vec<u8>,
    /// What else than `OutOfMemory` a refusal may fail the transfer
    /// with, as C fails it.
    refused_as: Option<ErrorKind>,
    /// Every component's lines traced, as `--trace-config all` has them.
    trace_all: bool,
}

/// Every component traced, made once and untracked.
fn all_components() -> Components {
    static ALL: std::sync::OnceLock<Components> = std::sync::OnceLock::new();
    ALL.get_or_init(|| {
        track::untracked(|| {
            let c = Components::new().expect("memory");
            c.configure(b"all");
            c
        })
    })
    .clone()
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
    let mut m: Multi = Multi::with_env(env)?;
    let mut easy = Easy::new();
    easy.set_libraries(wire.libraries);
    if wire.trace_all {
        easy.set_components(Some(all_components()));
    }
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
    let refused = matches!(result, Err(ErrorKind::OutOfMemory)) || result.err() == wire.refused_as;
    if !(result.is_ok() || refused) {
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
    let mut m: Multi = Multi::with_env(env)?;
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(URL))?;
    o.output.verbose = true;
    o.callbacks
        .rare
        .set(|r| &mut r.debug, Some(Handler::debug(Discard)?))?;
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
/// removal (`ENGINE.md` 8.1): the multi and its clock, shared with the
/// QUIC connections it makes; the easy's URL, user agent and
/// handlers, each one block with its count; the transfer's place in the multi and its slot, boxed so
/// the table's empty rows cost little, as C's hold pointers, and its
/// place in the queue of those waiting for a connection (C's
/// `multi->pending`), whose index of rows, as the multi's other sets of
/// rows, holds its first 64 in place; then the URL as fetched
/// and its parts, the URL read back once parsed (as C reads it back), the
/// target, its path and query made at once, the protocol's state, the
/// peer, the effective URL kept for the report, the answer for the host
/// kept in the
/// DNS cache (its name, its addresses, the answer shared, the cache's
/// table), the connection, as C's `connectdata`, the list of connect
/// attempts, the socket, the request head, the
/// receive buffer, the head parser's line, the header store and the
/// content type.
const GET_BUDGET: u64 = 40;

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
        refused_as: None,
        trace_all: false,
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
/// own beside the plain GET's 43: the TLS identity the connection keeps,
/// made as it is set up, the handshake under way, the library's session, its
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

/// The TLS identity a connection keeps is made of the transfer's
/// settings as the connection is set up, and a transfer that reuses the
/// connection makes none: its settings are compared where its options
/// hold them (`Curl_ssl_filter_config_tmp_init`'s shallow copy). Counted
/// by the copies of a key password of a size nothing else allocates,
/// which only an identity copies (the fake TLS library reads none).
fn a_tls_identity_is_made_once_per_connection() {
    const PASSWORD: usize = 997;
    let libraries = fake_tls();
    let (clock, net, talk) = track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 443));
        let records = fake::records(REPLY).expect("memory");
        let talk = Conversation::replies(&[fake::WELCOME, &records, &records, fake::CLOSE], false);
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        (clock, net, talk)
    });
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::with_env(env).expect("memory");
    let mut made = Vec::new();
    for _ in 0..2 {
        let mut easy = Easy::new();
        easy.set_libraries(libraries.clone());
        let o = easy.options_mut();
        o.set_url(Some(b"https://127.0.0.1/1?q")).expect("memory");
        o.tls.options.make_mut().expect("memory").key_password = Some(vec![b'k'; PASSWORD]);
        let id = m.add(Box::new(easy), (), &mut NoEvents).expect("added");
        let (result, n) = track::count_sized(PASSWORD, || {
            curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents)
                .expect("the transfer is in the multi")
        });
        assert_eq!(result, Ok(()));
        m.remove(id, &mut NoEvents).expect("in the multi");
        made.push(n);
    }
    // The positive control: the second transfer went over the first's
    // connection, its one handshake carrying both requests.
    track::untracked(|| {
        let read = fake::read_client(&talk.received()).expect("memory");
        let count = |needle: &[u8]| read.windows(needle.len()).filter(|w| *w == needle).count();
        assert_eq!(count(fake::HELLO), 1, "one handshake");
        assert_eq!(count(b"GET /1?q HTTP/1.1"), 2, "both requests over it");
    });
    track::untracked(|| eprintln!("identities made by a new connection and a reuse: {made:?}"));
    assert_eq!(
        made,
        [1, 0],
        "identities made: a new connection's, then none"
    );
}

/// A transfer waiting for room that reads another IP version as it
/// looks again fails for memory where its route's copy is refused: it
/// never goes on with the version it had.
fn a_waiting_transfer_s_new_ip_version_takes_no_refusal_for_success() {
    fn scenario() -> Result<[Result<(), ErrorKind>; 2], OutOfMemory> {
        let (clock, net) = track::untracked(|| {
            let clock = ManualClock::new().expect("a clock");
            let at = std::net::SocketAddr::from(([127, 0, 0, 1], 4));
            let net = FakeNet::new(clock.clone()).with_peer(at, Peer::Accepts);
            (clock, net)
        });
        let env = Env {
            clock: try_box(clock)?,
            net: try_box(net)?,
            arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
            waker: None,
        };
        let mut m: Multi = Multi::with_env(env)?;
        m.conn_limits_mut().max_host = std::num::NonZeroU32::new(1);
        let mut ids = [None, None];
        for slot in &mut ids {
            let mut easy = Easy::new();
            easy.options_mut().set_url(Some(b"tcp://127.0.0.1:4/"))?;
            match m.add(try_box(easy)?, (), &mut NoEvents) {
                Ok(id) => *slot = Some(id),
                Err(AddError {
                    kind: MultiErrorKind::OutOfMemory,
                    ..
                }) => return Err(OutOfMemory),
                Err(e) => panic!("add refused with {:?}, not for memory", e.kind),
            }
        }
        // The first takes the host's one connection; the second waits.
        match m.perform(&mut NoEvents) {
            Ok(_) | Err(MultiErrorKind::OutOfMemory) => {}
            Err(e) => panic!("a pass failed with {e:?}"),
        }
        let ids = ids.map(|id| id.expect("added"));
        m.easy_mut(ids[1])
            .expect("in the multi")
            .options_mut()
            .ip_version = curl_core::options::IpVersion::V4;
        let mut done = [Ok(()), Ok(())];
        for (i, id) in ids.iter().enumerate() {
            done[i] = curl_core::multi::drive_to_completion(&mut m, *id, &mut NoEvents)
                .expect("the transfer is in the multi");
        }
        for id in ids {
            m.remove(id, &mut NoEvents).expect("in the multi");
        }
        Ok(done)
    }
    // The positive control: unrefused, both are done.
    assert_eq!(scenario(), Ok([Ok(()), Ok(())]));
    refused_alone(scenario, |done| match done {
        Err(OutOfMemory) => true,
        Ok(done) => done.contains(&Err(ErrorKind::OutOfMemory)),
    });
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

/// What a share allocates as it is made, keeping nothing yet: itself and
/// the network its idle connections close through. Whether its TLS
/// sessions are going out to the application is made by its first export,
/// as few shares have one; C's share holds that in itself
/// (`Curl_ssl_scache_is_locked_by_current_thread`).
const SHARE_BUDGET: u64 = 2;

fn a_share_stays_within_its_allocation_budget() {
    let (share, n) = track::count_allocations(curl_core::share::Share::new);
    drop(share.expect("memory"));
    track::untracked(|| eprintln!("budget: a share made {n} allocations"));
    assert!(
        n <= SHARE_BUDGET,
        "a share made {n} allocations, over its {SHARE_BUDGET}"
    );
}

/// The allocations of a wait with `sockets` connections to watch, each
/// a transfer's.
fn wait_allocations(sockets: usize) -> u64 {
    let mut m: Multi = track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
        let mut net = FakeNet::new(clock.clone()).with_peer(at, Peer::Accepts);
        for _ in 0..sockets {
            net = net.with_conversation(at, Conversation::new(b"", false));
        }
        let env = Env {
            clock: Box::new(clock),
            net: Box::new(net),
            arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
            waker: None,
        };
        let mut m = Multi::with_env(env).expect("memory");
        for _ in 0..sockets {
            let mut easy = Easy::new();
            easy.options_mut().set_url(Some(URL)).expect("memory");
            m.add(Box::new(easy), (), &mut NoEvents).expect("added");
        }
        for _ in 0..5 {
            m.perform(&mut NoEvents).expect("performed");
        }
        m
    });
    let (waited, n) =
        track::count_allocations(|| m.wait(&mut [], Duration::ZERO, WaitMode::Wait, &mut NoEvents));
    track::untracked(|| {
        assert_eq!(waited, Ok(0));
        let census = m.census();
        assert_eq!((census.working(), census.pending), (sockets as u32, 0));
        drop(m);
    });
    n
}

/// A wait on as many transfers' sockets as fit on the stack, ten, keeps
/// them all there, as C's `a_few_on_stack`: an application's loop of
/// waits allocates nothing.
fn a_wait_on_a_few_sockets_allocates_nothing() {
    let n = wait_allocations(10);
    assert_eq!(n, 0, "a wait on 10 sockets made {n} allocations");
}

/// A wait on more sockets than fit on the stack allocates once for the
/// sockets it found and once for those it polls: the first pass's room
/// is taken for twice the stack's count when the stack overflows, so
/// twenty sockets need no more.
fn a_wait_on_more_sockets_allocates_once_for_each_pass() {
    let n = wait_allocations(20);
    assert_eq!(n, 2, "a wait on 20 sockets made {n} allocations");
}

/// A plain GET from a handle with a TLS library makes the same
/// allocations as one without: no scheme of HTTP's upgrades to TLS, so
/// its route keeps no settings to upgrade with (`route_cold`).
fn a_get_with_a_tls_library_allocates_as_one_without() {
    let (clock, net, talk) = test_1_server();
    let (got, without) = track::count_allocations(|| get(clock, net, &talk));
    assert_eq!(got.expect("nothing refused").result, Ok(()));
    let libraries = fake_tls();
    let (clock, net, talk) = test_1_server();
    let (got, with) = track::count_allocations(|| {
        let wire = Wire {
            libraries,
            sent: <[u8]>::to_vec,
            refused_as: None,
            trace_all: false,
        };
        get_over(clock, net, &talk, (URL, REQUEST), |_| Ok(()), wire)
    });
    assert_eq!(got.expect("nothing refused").result, Ok(()));
    assert_eq!(with, without, "allocations with a TLS library and without");
}

/// A GET by HTTP/2's prior knowledge from a server whose response's
/// head of its status, length and `fields`, then body of `frames` DATA
/// frames of 16 KiB, then its end, comes as the fake HTTP/2 library
/// frames it.
fn h2_get_scenario(frames: usize, fields: &str) -> (Result<Got, OutOfMemory>, u64) {
    static FAKE: curl_core::http2::fake::FakeH2 = curl_core::http2::fake::FakeH2;
    let (clock, net, talk, libraries) = track::untracked(|| {
        let chunk = vec![b'x'; 16 * 1024];
        let mut reply = format!(
            "S\nH 1 0\n:status: 200\ncontent-length: {}\n{fields}\n",
            frames * chunk.len()
        )
        .into_bytes();
        for i in 0..frames {
            let end = u8::from(i + 1 == frames);
            reply.extend_from_slice(format!("D 1 {} {end}\n", chunk.len()).as_bytes());
            reply.extend_from_slice(&chunk);
        }
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
        let talk = Conversation::replies(&[&reply], false).per_send();
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        let libraries = SharedLibraries::new(Libraries {
            h2: Some(&FAKE as &dyn curl_core::http2::Http2),
            ..Libraries::NONE
        })
        .expect("memory");
        (clock, net, talk, libraries)
    });
    let wire = Wire {
        libraries,
        sent: h2_request_sent,
        refused_as: None,
        trace_all: false,
    };
    let prior = |o: &mut Options| {
        o.http.version = curl_core::options::HttpVersion::Http2Prior;
        Ok(())
    };
    track::count_allocations(|| get_over(clock, net, &talk, (URL, H2_REQUEST), prior, wire))
}

/// The settings and the request's HEADERS, as the fake HTTP/2 library
/// frames them.
const H2_REQUEST: &[u8] = b"S MCS=100;IWS=65536;EP=0;\nH 1 1\n:method: GET\n:scheme: http\n\
    :authority: 127.0.0.1\n:path: /1?q\nuser-agent: curl/test\naccept: */*\n\n";

/// What the server of an HTTP/2 GET was sent, up to the end of the
/// request's HEADERS: the window updates after depend on the reads.
fn h2_request_sent(wire: &[u8]) -> Vec<u8> {
    let end = wire
        .windows(2)
        .position(|w| w == b"\n\n")
        .map_or(wire.len(), |at| at + 2);
    wire[..end].to_vec()
}

/// The body's DATA frames, read over many reads, allocate nothing of
/// their own: a 1 MiB body in 64 frames costs what one frame does
/// (DESIGN.md, no allocation per chunk on the data path).
fn an_http_2_body_s_frames_allocate_nothing() {
    let (one, n1) = h2_get_scenario(1, "");
    let (many, n64) = h2_get_scenario(64, "");
    let (one, many) = (
        one.expect("nothing refused"),
        many.expect("nothing refused"),
    );
    assert_eq!((one.result, one.body), (Ok(()), 16 * 1024));
    assert_eq!((many.result, many.body), (Ok(()), 64 * 16 * 1024));
    track::untracked(|| {
        eprintln!("budget: an HTTP/2 GET made {n1} allocations, {n64} for 64 frames")
    });
    assert_eq!(n64, n1, "64 frames made {n64} allocations, one {n1}");
}

/// A response head's usual fields beside its status and length, as an
/// Apache server sends them for a file.
const H2_FIELDS: &str = "date: Sat, 07 Nov 2026 23:55:24 GMT\n\
    server: Apache/2.4.69 (Fedora Linux) OpenSSL/3.5.9\n\
    last-modified: Sat, 07 Nov 2026 23:36:43 GMT\n\
    etag: \"2800-65fb8338e0d2c\"\n\
    accept-ranges: bytes\n\
    content-type: application/octet-stream\n";

/// What a GET by HTTP/2's prior knowledge allocates over the fake
/// library, its response's head of eight fields of a usual length.
/// Measured, not itemised: the plain GET's own beside the session, its
/// stream and the request's fields; the head's fields made into lines,
/// read and stored grow none of their buffers.
const H2_GET_BUDGET: u64 = 54;

fn an_http_2_get_stays_within_its_allocation_budget() {
    let (got, n) = h2_get_scenario(1, H2_FIELDS);
    assert_eq!(got.expect("nothing refused").result, Ok(()));
    track::untracked(|| eprintln!("budget: an HTTP/2 GET of eight fields made {n} allocations"));
    assert!(
        n <= H2_GET_BUDGET,
        "an HTTP/2 GET of eight fields made {n} allocations, over its {H2_GET_BUDGET}"
    );
}

/// The trace's text, kept untracked: the test's, not the library's.
#[derive(Default)]
struct Traced(curl_alloc::Lock<Vec<u8>>);

struct Tracer(TryArc<Traced>);

impl DebugHandler for Tracer {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text {
            track::untracked(|| self.0.0.lock().unwrap().extend_from_slice(data));
        }
    }
}

/// An FTP download whose data connection dials an address that never
/// answers: the passes that drive its setup on allocate nothing, however
/// many there are, as C's `ftp_do_more` does not.
fn an_ftp_data_connect_s_wait_allocates_nothing_per_pass() {
    const PASSES: u64 = 20;
    let (clock, net) = track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 8021));
        let data_at = std::net::SocketAddr::from(([127, 0, 0, 1], 8022));
        let control = Conversation::replies(
            &[
                b"220 hi\r\n",
                b"331 password?\r\n",
                b"230 in\r\n",
                b"257 \"/\" is it\r\n",
                b"229 Entering Extended Passive Mode (|||8022|)\r\n",
            ],
            false,
        )
        .per_send()
        .greeting();
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_peer(data_at, Peer::Silent)
            .with_conversation(at, control);
        (clock, net)
    });
    let env = Env {
        clock: try_box(clock).expect("memory"),
        net: try_box(net).expect("memory"),
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::with_env(env).expect("memory");
    let mut easy = Easy::new();
    let traced = TryArc::try_new(Traced::default()).expect("memory");
    let o = easy.options_mut();
    o.set_url(Some(b"ftp://127.0.0.1:8021/f")).expect("memory");
    o.output.verbose = true;
    o.callbacks
        .rare
        .set(
            |r| &mut r.debug,
            Some(Handler::debug(Tracer(traced.clone())).expect("memory")),
        )
        .unwrap();
    let id = m
        .add(try_box(easy).expect("memory"), (), &mut NoEvents)
        .expect("added");
    let dialing = || {
        track::untracked(|| {
            let text = traced.0.lock().unwrap();
            let needle = b"Trying 127.0.0.1:8022...";
            text.windows(needle.len()).any(|w| w == needle)
        })
    };
    for _ in 0..100 {
        if dialing() {
            break;
        }
        m.perform(&mut NoEvents).expect("performed");
    }
    assert!(dialing(), "the data connection dials");
    let ((), n) = track::count_allocations(|| {
        for _ in 0..PASSES {
            m.perform(&mut NoEvents).expect("performed");
        }
    });
    track::untracked(|| {
        eprintln!("budget: {PASSES} passes dialing a data connection made {n} allocations")
    });
    assert_eq!(n, 0, "{PASSES} passes dialing the data connection");
    m.remove(id, &mut NoEvents).expect("in the multi");
}

/// The proxy's answer that opens a tunnel.
const TUNNELED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// An FTP download through an HTTP proxy's tunnel, whose data
/// connection's `CONNECT` the proxy answers only when let: the passes of
/// DO_MORE that wait for it allocate nothing, however many there are, as
/// C's `ftp_do_more` does not (test 1631 under load).
fn an_ftp_data_tunnel_s_wait_allocates_nothing_per_pass() {
    const PASSES: u64 = 20;
    let (clock, net, file) = track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
        let greeted = [TUNNELED, b"220 hi\r\n"].concat();
        let control = Conversation::replies(
            &[
                &greeted,
                b"331 password?\r\n",
                b"230 in\r\n",
                b"257 \"/\" is it\r\n",
                b"229 Entering Extended Passive Mode (|||8022|)\r\n",
                b"200 binary\r\n",
                b"213 5\r\n",
                b"150 here\r\n226 done\r\n",
            ],
            false,
        )
        .per_send();
        let file = Conversation::replies(&[&[TUNNELED, b"hello"].concat()], true)
            .per_send()
            .held();
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, control)
            .with_conversation(at, file.clone());
        (clock, net, file)
    });
    let env = Env {
        clock: try_box(clock).expect("memory"),
        net: try_box(net).expect("memory"),
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::with_env(env).expect("memory");
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(b"ftp://127.0.0.1:8021/f")).expect("memory");
    let proxy = o.proxy.make_mut().expect("memory");
    proxy.url = Some(b"http://127.0.0.1:8080".to_vec());
    proxy.tunnel = true;
    let took = TryArc::try_new(Took::default()).expect("memory");
    o.callbacks.write = Some(Handler::write(Taker(took.clone())).expect("memory"));
    let id = m
        .add(try_box(easy).expect("memory"), (), &mut NoEvents)
        .expect("added");
    let asked = || track::untracked(|| file.received().starts_with(b"CONNECT "));
    for _ in 0..100 {
        if asked() {
            break;
        }
        m.perform(&mut NoEvents).expect("performed");
    }
    assert!(asked(), "the data connection's CONNECT is sent");
    let ((), n) = track::count_allocations(|| {
        for _ in 0..PASSES {
            m.perform(&mut NoEvents).expect("performed");
        }
    });
    track::untracked(|| {
        eprintln!("budget: {PASSES} passes waiting on a data tunnel made {n} allocations")
    });
    assert_eq!(
        n, 0,
        "{PASSES} passes waiting on the data connection's tunnel"
    );
    file.allow(1);
    let result =
        curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents).expect("in the multi");
    assert_eq!(result, Ok(()));
    assert_eq!(took.body.get(), 5);
    m.remove(id, &mut NoEvents).expect("in the multi");
}

/// One fake network for a multi and the share whose connections it
/// uses, as the share closes them at its end.
struct SharedNet(TryArc<curl_alloc::Lock<FakeNet>>);

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
        kind: curl_core::conn::io::SocketKind,
    ) -> std::io::Result<Box<dyn curl_core::conn::io::Socket>> {
        self.0.lock().unwrap().open(addr, kind)
    }

    fn close(&mut self, socket: curl_core::conn::io::Sock) {
        self.0.lock().unwrap().close(socket);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn curl_core::conn::io::Resolver)) {
        self.0.lock().unwrap().with_resolver(f);
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
        curl_core::conn::io::InterfaceAddress::NotFound(0)
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
        TryArc::try_new(curl_alloc::Lock::new(net)).expect("a test's network")
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
    let mut m: Multi = Multi::with_env(env)?;
    let mut results = [Ok(()), Ok(())];
    for result in &mut results {
        let mut easy = Easy::new();
        easy.set_share(Some(share.clone())).unwrap();
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

/// An application taking every push a server offers, counting what the
/// multi tells it: its transfers added, the pushes it took and the ones
/// given back, and the parent's body written as one was given back.
struct Pushing {
    took: TryArc<Took>,
    added: usize,
    accepted: usize,
    unpushed: usize,
    body_at_unpushed: Option<u64>,
}

impl MultiEvents<NoHost> for Pushing {
    fn added(&mut self, _: curl_core::multi::TransferId, (): &()) {
        self.added += 1;
    }

    fn wants_push(&self) -> bool {
        true
    }

    fn push(
        &mut self,
        _: &mut EventCx<'_, NoHost>,
        _: &curl_core::multi::PushOffer<'_>,
        easy: Box<Easy>,
    ) -> curl_core::multi::Pushed<NoHost> {
        self.accepted += 1;
        curl_core::multi::Pushed::Accepted { easy, owner: () }
    }

    fn unpushed(&mut self, easy: Box<Easy>, (): ()) {
        self.unpushed += 1;
        self.body_at_unpushed = Some(self.took.body.get());
        drop(easy);
    }
}

/// What a run of `push_scenario` came to.
#[derive(Debug)]
struct PushRun {
    parent: Option<Result<(), ErrorKind>>,
    /// The pushed transfer was added to the multi.
    added: bool,
    accepted: usize,
    unpushed: usize,
    /// Messages for transfers other than the parent.
    pushed_messages: usize,
    body_at_unpushed: Option<u64>,
    /// The promised stream's cancels sent.
    cancels: usize,
    /// The transfers the last pass left running.
    running: u32,
    /// The lines C says of a push that could not be added
    /// (`Curl_multi_add_perform`) and of one whose stream could not be set
    /// up (`http2_data_setup`) were traced.
    said_unadded: bool,
    said_unset: bool,
}

/// An HTTP/2 GET whose response promises a push the application takes,
/// driven until nothing runs: the multi must count no transfer running
/// once the parent is done, whatever became of the push.
fn push_scenario() -> Result<PushRun, OutOfMemory> {
    static FAKE: curl_core::http2::fake::FakeH2 = curl_core::http2::fake::FakeH2;
    const REPLY: &[u8] = b"S\nH 1 0\n:status: 200\n\nPP 1 2\n:method: GET\n:scheme: http\n\
        :authority: 127.0.0.1\n:path: /pushed\n\nH 2 0\n:status: 200\n\n\
        D 2 3 1\nabcD 1 2 1\nok";
    let (clock, net, talk, libraries) = track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
        let talk = Conversation::replies(&[REPLY, b""], false).per_send();
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        let libraries = SharedLibraries::new(Libraries {
            h2: Some(&FAKE as &dyn curl_core::http2::Http2),
            ..Libraries::NONE
        })
        .expect("memory");
        (clock, net, talk, libraries)
    });
    let env = Env {
        clock: try_box(clock)?,
        net: try_box(net)?,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::with_env(env)?;
    let mut ev = Pushing {
        took: TryArc::try_new(Took::default())?,
        added: 0,
        accepted: 0,
        unpushed: 0,
        body_at_unpushed: None,
    };
    let mut easy = Easy::new();
    easy.set_libraries(libraries);
    let o = easy.options_mut();
    o.set_url(Some(b"http://127.0.0.1/"))?;
    o.limits.total = TimeLimit::from_millis(10_000);
    o.http.version = curl_core::options::HttpVersion::Http2Prior;
    o.callbacks.write = Some(Handler::write(Taker(ev.took.clone()))?);
    let traced = TryArc::try_new(Traced::default())?;
    o.output.verbose = true;
    o.callbacks.rare.set(
        |r| &mut r.debug,
        Some(Handler::debug(Tracer(traced.clone()))?),
    )?;
    let id = match m.add(try_box(easy)?, (), &mut ev) {
        Ok(id) => id,
        Err(AddError {
            kind: MultiErrorKind::OutOfMemory,
            ..
        }) => return Err(OutOfMemory),
        Err(e) => panic!("add refused with {:?}, not for memory", e.kind),
    };
    let mut run = PushRun {
        parent: None,
        added: false,
        accepted: 0,
        unpushed: 0,
        pushed_messages: 0,
        body_at_unpushed: None,
        cancels: 0,
        running: u32::MAX,
        said_unadded: false,
        said_unset: false,
    };
    for _ in 0..20 {
        run.running = m.perform(&mut ev).expect("a pass allocates nothing");
        while let Some(msg) = m.info_read() {
            if msg.id == id {
                run.parent = Some(msg.result);
            } else {
                run.pushed_messages += 1;
            }
        }
    }
    run.added = ev.added > 1;
    run.accepted = ev.accepted;
    run.unpushed = ev.unpushed;
    run.body_at_unpushed = ev.body_at_unpushed;
    let said = |needle: &[u8]| {
        track::untracked(|| {
            let text = traced.0.lock().unwrap();
            text.windows(needle.len()).any(|w| w == needle)
        })
    };
    run.said_unadded = said(b"failed to add handle to multi\n");
    run.said_unset = said(b"error setting up stream: 27\n");
    run.cancels = track::untracked(|| {
        String::from_utf8(talk.received())
            .expect("the fake's frames are text")
            .matches("R 2 8\n")
            .count()
    });
    let mut left = None;
    while let Some(t) = m.next_transfer(left) {
        if t == id {
            left = Some(t);
            continue;
        }
        m.remove(t, &mut ev).expect("in the multi");
    }
    m.remove(id, &mut ev).expect("in the multi");
    Ok(run)
}

/// A push the application took whose transfer cannot start, for want of
/// memory, is taken out of the multi again and its handle given back to
/// the host to close, with no message, its stream cancelled once, as C
/// closes it (`discard_newhandle`): the multi counts nothing running, and
/// the parent finishes. It goes as the parent's step ends, not inside the
/// read that offered it, so the parent's body is written by then
/// (`DIVERGENCE.md`).
fn a_push_that_cannot_start_leaves_nothing_running() {
    let mut limit = 0;
    let mut discarded = 0;
    let mut failed_by_read = 0;
    let mut unadded = 0;
    loop {
        let live = track::live_tracked();
        let (outcome, refused) = track::fail_once_after(limit, push_scenario);
        if let Ok(run) = &outcome {
            if run.running != 0 {
                track::untracked(|| panic!("refusing {limit}, transfers still run: {run:?}"));
            }
            // A refusal as a started push's own frame is read fails the
            // parent's read, and with it the session's: the push fails as
            // it next runs, not left to its timeout.
            if run.added && run.unpushed == 0 && run.parent == Some(Err(ErrorKind::RecvError)) {
                track::untracked(|| {
                    assert_eq!(run.pushed_messages, 1, "refusing {limit}: {run:?}")
                });
                failed_by_read += 1;
            }
        }
        assert_eq!(
            track::live_tracked(),
            live,
            "a run refusing allocation {limit} left blocks behind"
        );
        if !refused {
            let run = outcome.expect("nothing refused");
            assert_eq!((run.parent, run.pushed_messages), (Some(Ok(())), 1));
            assert_eq!((run.accepted, run.unpushed), (1, 0));
            assert!(!run.said_unadded && !run.said_unset, "{run:?}");
            break;
        }
        // Refused as it is added, it is given back at once and said so.
        if let Ok(run) = &outcome
            && !run.added
            && run.unpushed == 1
        {
            unadded += 1;
            track::untracked(|| {
                assert!(run.said_unadded, "refusing {limit}: {run:?}");
                assert!(!run.said_unset, "refusing {limit}: {run:?}");
            });
        }
        if let Ok(run) = &outcome
            && run.added
            && run.unpushed == 1
        {
            discarded += 1;
            track::untracked(|| {
                assert_eq!(run.parent, Some(Ok(())), "refusing {limit}: {run:?}");
                assert_eq!(run.pushed_messages, 0, "refusing {limit}: {run:?}");
                assert_eq!(run.cancels, 1, "refusing {limit}: {run:?}");
                assert_eq!(run.body_at_unpushed, Some(2), "refusing {limit}: {run:?}");
                assert!(run.said_unset, "refusing {limit}: {run:?}");
                assert!(!run.said_unadded, "refusing {limit}: {run:?}");
            });
        }
        limit += 1;
        assert!(limit < 100_000, "the scenario never ran to the end");
    }
    assert!(discarded > 0, "no refusal fell in the push's start");
    assert!(unadded > 0, "no refusal fell in the push's adding");
    assert!(
        failed_by_read > 0,
        "no refusal failed a read with the push running"
    );
    track::untracked(|| {
        eprintln!(
            "torture: {limit} allocations, {discarded} in a push's start, \
             {failed_by_read} failing a read with it running"
        );
    });
}

/// A count the handlers keep, `Sync` as a handler is; its lock is made
/// untracked, so locking it allocates nothing the library is charged for.
struct Cell<T>(curl_alloc::Lock<T>);

impl<T: Default> Default for Cell<T> {
    fn default() -> Self {
        Cell(curl_alloc::Lock::new(T::default()))
    }
}

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
    let mut m: Multi = Multi::with_env(env).expect("a multi");
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(URL)).expect("a URL");
    o.method = Method::Post;
    o.upload = UploadSource::Bytes(TryArc::try_new(b"abc".to_vec()).expect("a body"));
    o.http.headers =
        UserHeaders::new([&b"Transfer-Encoding: chunked"[..], b"Expect:"]).expect("headers");
    o.callbacks
        .rare
        .set(
            |r| &mut r.trailer,
            Some(Handler::trailer(LosesOne).expect("a handler")),
        )
        .unwrap();
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

/// A handler is one block, its count with it, and a copy shares it; a
/// refused block drops the handler it was to hold.
fn a_handler_is_one_allocation() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    struct Counted(Arc<AtomicU32>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl WriteHandler for Counted {
        fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
            Write::Accepted
        }
    }
    let drops = Arc::new(AtomicU32::new(0));
    let (h, n) = track::count_allocations(|| Handler::write(Counted(Arc::clone(&drops))));
    assert_eq!(n, 1, "the handler and its count");
    let h = h.expect("memory");
    let (copy, n) = track::count_allocations(|| h.clone());
    assert_eq!(n, 0, "shared");
    assert!(Handler::ptr_eq(&h, &copy));
    drop(h);
    drop(copy);
    assert_eq!(drops.load(Ordering::Relaxed), 1, "dropped by the last");
    let (h, refused) =
        track::fail_after(0, || Handler::write(Counted(Arc::clone(&drops))).map(drop));
    assert_eq!(
        (h, refused, drops.load(Ordering::Relaxed)),
        (Err(OutOfMemory), true, 2)
    );
}

/// A file part's status is read by its name copied to the stack, as C's
/// `stat` takes it: a name longer than std's 384-byte stack buffer would
/// otherwise be copied to the heap by an allocation that cannot fail.
#[cfg(unix)]
fn a_file_part_s_long_name_is_read_without_a_copy() {
    let name = [b'n'; 400];
    let (made, n) = track::count_allocations(|| curl_core::mime::FileData::new(&name));
    assert_eq!(made.err(), Some(curl_core::mime::FileError::Unreadable));
    assert_eq!(n, 0, "the name's status read with nothing allocated");
}

/// On Windows a file part's status is read by its name in UTF-16, made
/// absolute and marked long (`\\?\`) past `MAX_PATH`, on the heap: std's
/// `metadata` makes that copy with an allocation that cannot fail. Each
/// of ours refused in turn, the status is unread, not the process
/// aborted, and nothing is left allocated. A build whose `curl-os` has
/// its `debug-hooks` (a run that builds `curl-os`'s own tests too) keeps
/// those copies from the tracker, as C's tracker does not see C's: there
/// is then nothing to refuse.
#[cfg(windows)]
fn a_file_part_s_long_name_is_read_without_a_copy() {
    let name = [b'n'; 400];
    let unreadable = Some(curl_core::mime::FileError::Unreadable);
    let (made, n) = track::count_allocations(|| curl_core::mime::FileData::new(&name));
    assert_eq!(made.err(), unreadable);
    if n == 0 {
        track::untracked(|| print!("the name's copies not tracked, "));
        return;
    }
    for limit in 0..n {
        let live = track::live_tracked();
        let (made, refused) =
            track::fail_after(limit, || curl_core::mime::FileData::new(&name).err());
        assert!(refused, "allocation {limit} of {n} refused");
        assert_eq!(made, unreadable, "allocation {limit} refused");
        assert_eq!(track::live_tracked(), live, "allocation {limit} refused");
    }
}

/// The fake HTTP/3 library, made once and untracked; each run sets the
/// scripts its connections run (`h3_scripts`).
fn fake_h3() -> &'static FakeHttp3 {
    static FAKE: std::sync::OnceLock<FakeHttp3> = std::sync::OnceLock::new();
    FAKE.get_or_init(|| track::untracked(|| FakeHttp3::new(H3Script::new())))
}

/// The fake TLS and HTTP/3 libraries and the libraries naming them, made
/// once and untracked.
fn fake_h3_libraries() -> SharedLibraries {
    static LIBRARIES: std::sync::OnceLock<SharedLibraries> = std::sync::OnceLock::new();
    LIBRARIES
        .get_or_init(|| {
            track::untracked(|| {
                let backend = Box::new(FakeTls::new().expect("memory"));
                SharedLibraries::new(Libraries {
                    tls: Some(Library::Owned(backend)),
                    h3: Some(fake_h3()),
                    ..Libraries::NONE
                })
                .expect("memory")
            })
        })
        .clone()
}

/// A connection's script: it writes the packets of `out`, each empty one
/// ending a flight; its handshake completes as it reads the first packet
/// back, and its next reads tell `answers` in turn; its peer idles out
/// after 30 s.
fn h3_script(out: &[&[u8]], answers: Vec<Vec<Told>>) -> H3Script {
    let mut s = H3Script {
        max_payload: 1200,
        path_max_payload: 1452,
        send_quantum: 12000,
        idle: Some(Duration::from_secs(30)),
        ..H3Script::default()
    };
    s.out.extend(out.iter().map(|p| p.to_vec()));
    s.on_read
        .push_back(vec![Told::HandshakeDone, Told::MaxBidiStreams(100)]);
    s.on_read.extend(answers);
    s
}

/// A field told on stream 0.
fn h3_header(name: &[u8], value: &[u8]) -> Told {
    Told::Header {
        stream: 0,
        name: name.to_vec(),
        value: value.to_vec(),
    }
}

/// The response to an HTTP/3 GET: a header that is not UTF-8 among its
/// fields, then its body, and the stream closed.
fn h3_response() -> Vec<Told> {
    vec![
        h3_header(b":status", b"200"),
        h3_header(b"content-length", b"9"),
        h3_header(b"x-obs", b"caf\xe9"),
        Told::HeadersDone(0),
        Told::Data(0, b"123456789".to_vec()),
        Told::Closed(0, 0x100),
        Told::QuicClosed(0, 0x100),
    ]
}

/// The packets a GET's connection writes: the handshake's two, then the
/// request's.
const H3_GET_OUT: &[&[u8]] = &[&[1; 1200], &[2; 1200], &[], &[], &[3; 75], &[]];

/// The fake's first connection runs `first`'s script, the next `then`'s,
/// all made untracked: the library's, not the core's to account for.
fn h3_scripts(first: fn() -> H3Script, then: Option<fn() -> H3Script>) {
    track::untracked(|| {
        let fake = fake_h3();
        *fake.script.lock().unwrap() = first();
        fake.setups.lock().unwrap().clear();
        let mut more = fake.then.lock().unwrap();
        more.clear();
        more.extend(then.map(|s| std::sync::Arc::new(curl_alloc::Lock::new(s()))));
    })
}

/// A network with a QUIC peer at 127.0.0.1:443 answering each datagram
/// with the next of `replies`, made untracked.
fn quic_server(replies: &[&[u8]]) -> (ManualClock, FakeNet, Conversation) {
    track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 443));
        let talk = Conversation::replies(replies, false).per_send();
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        (clock, net, talk)
    })
}

/// What the first connection's library was asked to send: each request's
/// fields a line, then the request body it was handed.
fn h3_sent(_wire: &[u8]) -> Vec<u8> {
    let s = fake_h3().script.lock().unwrap();
    let mut sent = Vec::new();
    for request in &s.requests {
        for field in request {
            sent.extend_from_slice(field.as_bytes());
            sent.push(b'\n');
        }
    }
    sent.extend_from_slice(&s.body.bytes);
    sent
}

/// A refusal while the HTTP/3 library reads a packet fails the read, and
/// C then fails the transfer with `CURLE_RECV_ERROR`, whatever the
/// callback's failure was (`cf_ngtcp2_recv`).
const H3_REFUSED_AS: Option<ErrorKind> = Some(ErrorKind::RecvError);

/// The GET's fields, as `h3_sent` reads them.
const H3_REQUEST: &[u8] = b":method: GET\n:scheme: https\n:authority: 127.0.0.1\n\
    :path: /1?q\nuser-agent: curl/test\naccept: */*\n";

/// Traced to a handler that keeps nothing, so that the trace's lines
/// are made.
fn traced(o: &mut Options) -> Result<(), OutOfMemory> {
    o.output.verbose = true;
    o.callbacks
        .rare
        .set(|r| &mut r.debug, Some(Handler::debug(Discard)?))?;
    Ok(())
}

/// HTTP/3 alone, traced.
fn h3_only(o: &mut Options) -> Result<(), OutOfMemory> {
    o.http.version = curl_core::options::HttpVersion::Http3Only;
    traced(o)
}

/// A traced GET of test 1's URL over HTTPS in HTTP/3 alone, through the
/// fake TLS and HTTP/3 libraries.
fn h3_get_scenario() -> Result<Got, OutOfMemory> {
    h3_scripts(|| h3_script(H3_GET_OUT, vec![h3_response()]), None);
    let (clock, net, talk) = quic_server(&[b"server flight", b"response"]);
    let wire = Wire {
        libraries: fake_h3_libraries(),
        sent: h3_sent,
        refused_as: H3_REFUSED_AS,
        trace_all: true,
    };
    let url = b"https://127.0.0.1/1?q";
    get_over(clock, net, &talk, (url, H3_REQUEST), h3_only, wire)
}

/// What an HTTP/3 GET's handlers take: its body, and its head a line at
/// a time, `HTTP/3 200 \r\n` first.
const H3_GOT: Got = Got {
    result: Ok(()),
    body: 9,
    headers: (b"HTTP/3 200 \r\n".len()
        + b"content-length: 9\r\n".len()
        + b"x-obs: caf\xe9\r\n".len()
        + b"\r\n".len()) as u64,
};

/// A refusal is never taken for success: it fails the transfer for
/// memory, or as C fails a read whose callback failed.
fn took_no_refusal(got: &Result<Got, OutOfMemory>) -> bool {
    match got {
        Err(OutOfMemory) => true,
        Ok(got) => got.result == Err(ErrorKind::OutOfMemory) || got.result.err() == H3_REFUSED_AS,
    }
}

fn an_http3_get_survives_every_allocation_failing() {
    fake_h3_libraries();
    torture(h3_get_scenario, Ok(H3_GOT));
}

fn an_http3_get_takes_no_refusal_for_success() {
    fake_h3_libraries();
    refused_alone(h3_get_scenario, took_no_refusal);
}

/// What a GET in HTTP/3 alone allocates over the fake TLS and HTTP/3
/// libraries, every component traced; the libraries' own memory is
/// theirs. Measured, not itemised: the HTTPS GET's own beside QUIC's
/// connection, its HTTP/3 session and stream, the room datagrams are
/// read into, and the group the trace's handler is kept in, which an
/// untraced transfer does not make.
const H3_GET_BUDGET: u64 = 60;

fn an_http3_get_stays_within_its_allocation_budget() {
    fake_h3_libraries();
    let (got, n) = track::count_allocations(h3_get_scenario);
    assert_eq!(got.expect("nothing refused").result, Ok(()));
    track::untracked(|| eprintln!("budget: an HTTP/3 GET over the fakes made {n} allocations"));
    assert!(
        n <= H3_GET_BUDGET,
        "an HTTP/3 GET over the fakes made {n} allocations, over its {H3_GET_BUDGET}"
    );
}

/// The HTTP/3 proxy's answer to a `CONNECT`: its status, and a header
/// that is not UTF-8.
fn h3_connect_answer() -> Vec<Told> {
    vec![
        h3_header(b":status", b"200"),
        h3_header(b"via", b"h3\xc3proxy"),
        Told::HeadersDone(0),
    ]
}

/// Through the tunnel the HTTP/3 proxy at 127.0.0.1:443 makes, traced.
fn h3_proxy(o: &mut Options) -> Result<(), OutOfMemory> {
    let proxy = o.proxy.make_mut()?;
    proxy.url = Some(b"https://127.0.0.1:443".to_vec_fallible()?);
    proxy.kind = curl_core::options::ProxyType::Https3;
    proxy.tunnel = true;
    traced(o)
}

/// The HTTP/3 proxy's connection for a tunnel: its handshake, the
/// `CONNECT`'s answer, then test 1's reply on the tunnel's stream.
fn h3_tunnel_script() -> H3Script {
    let out: &[&[u8]] = &[
        &[1; 1200],
        &[2; 1200],
        &[],
        &[],
        &[3; 75],
        &[],
        &[4; 150],
        &[],
    ];
    let response = vec![Told::Data(0, REPLY.to_vec())];
    h3_script(out, vec![h3_connect_answer(), response])
}

/// A GET of `http://origin.example/1?q` in HTTP/1.1 through the HTTP/3
/// proxy's tunnel, a stream of the QUIC connection to it
/// (`cf-ngtcp2-proxy.c`), answered with test 1's reply.
fn h3_tunnel_scenario() -> Result<Got, OutOfMemory> {
    h3_scripts(h3_tunnel_script, None);
    let (clock, net, talk) = quic_server(&[b"server flight", b"connect answer", b"response"]);
    let wire = Wire {
        libraries: fake_h3_libraries(),
        sent: h3_sent,
        refused_as: H3_REFUSED_AS,
        trace_all: true,
    };
    let request = b":method: CONNECT\n:authority: origin.example:80\nuser-agent: curl/test\n\
        GET /1?q HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\n\
        Accept: */*\r\n\r\n";
    let url = b"http://origin.example/1?q";
    get_over(clock, net, &talk, (url, request), h3_proxy, wire)
}

fn a_tunnel_through_an_http3_proxy_survives_every_allocation_failing() {
    fake_h3_libraries();
    let full = Got {
        result: Ok(()),
        body: 6,
        headers: REPLY.len() as u64 - 6,
    };
    torture(h3_tunnel_scenario, Ok(full));
}

fn a_tunnel_through_an_http3_proxy_takes_no_refusal_for_success() {
    fake_h3_libraries();
    refused_alone(h3_tunnel_scenario, took_no_refusal);
}

/// A capsule carrying the datagram `payload`, shorter than 16 KiB:
/// DATAGRAM's type, the length with the context id, the id, 0.
fn capsule(payload: &[u8]) -> Vec<u8> {
    let length = payload.len() + 1;
    let mut c = vec![0];
    match u8::try_from(length) {
        Ok(n) if n < 0x40 => c.push(n),
        _ => c.extend_from_slice(&(0x4000 | u16::try_from(length).unwrap()).to_be_bytes()),
    }
    c.push(0);
    c.extend_from_slice(payload);
    c
}

/// The proxy's script for a CONNECT-UDP: its answer agreeing to
/// capsules, then the origin's flight and response as capsules on the
/// tunnel's stream.
fn connect_udp_script() -> H3Script {
    let mut answer = h3_connect_answer();
    answer.insert(1, h3_header(b"capsule-protocol", b"?1"));
    h3_script(
        H3_GET_OUT,
        vec![
            answer,
            vec![Told::Data(0, capsule(b"server flight"))],
            vec![],
            vec![Told::Data(0, capsule(b"response"))],
        ],
    )
}

/// HTTP/3 alone to `https://origin.example/1?q` through the HTTP/3
/// proxy, over its CONNECT-UDP: the origin's QUIC connection in capsules
/// on the tunnel's stream of the proxy's.
fn h3_over_h3_proxy_scenario() -> Result<Got, OutOfMemory> {
    h3_scripts(
        connect_udp_script,
        Some(|| h3_script(H3_GET_OUT, vec![h3_response()])),
    );
    let (clock, net, talk) = quic_server(&[
        b"server flight",
        b"connect answer",
        b"origin flight",
        b"origin response",
        b"more",
        b"more",
    ]);
    let wire = Wire {
        libraries: fake_h3_libraries(),
        sent: h3_sent,
        refused_as: H3_REFUSED_AS,
        trace_all: true,
    };
    let request = track::untracked(|| {
        let mut r = b":method: CONNECT\n:scheme: https\n:authority: 127.0.0.1:443\n\
            :path: /.well-known/masque/udp/origin.example/443/\n:protocol: connect-udp\n\
            capsule-protocol: ?1\n"
            .to_vec();
        for packet in [&[1; 1200][..], &[2; 1200], &[3; 75]] {
            r.extend(capsule(packet));
        }
        r
    });
    let url = b"https://origin.example/1?q";
    let both = |o: &mut Options| {
        o.http.version = curl_core::options::HttpVersion::Http3Only;
        h3_proxy(o)
    };
    get_over(clock, net, &talk, (url, &request), both, wire)
}

fn http3_through_an_http3_proxy_survives_every_allocation_failing() {
    fake_h3_libraries();
    torture(h3_over_h3_proxy_scenario, Ok(H3_GOT));
}

fn http3_through_an_http3_proxy_takes_no_refusal_for_success() {
    fake_h3_libraries();
    refused_alone(h3_over_h3_proxy_scenario, took_no_refusal);
}

/// The rooms QUIC connections receive in, the multi's and an HTTP/3
/// proxy connection's own, are asked of the allocator zeroed, as C's are
/// left unwritten: one filled byte by byte costs milliseconds of an
/// unoptimised build at a connection's first receive, which made the
/// origin's handshake through a CONNECT-UDP tunnel lose races C's wins.
/// Nothing else a GET allocates is as large as a room.
/// Through the tunnel the HTTP/3 proxy at 127.0.0.2:443 makes.
fn other_h3_proxy(o: &mut Options) -> Result<(), OutOfMemory> {
    h3_proxy(o)?;
    o.proxy.make_mut()?.url = Some(b"https://127.0.0.2:443".to_vec_fallible()?);
    Ok(())
}

/// GETs of `http://origin.example/1?q` and then `http://other.example/1?q`
/// in one multi, each through the tunnel of an HTTP/3 proxy of its own,
/// on a connection of its own, the first's kept in the pool as the
/// second makes its own: whether both ended well.
fn two_h3_tunnels_scenario() -> Result<bool, OutOfMemory> {
    h3_scripts(h3_tunnel_script, Some(h3_tunnel_script));
    let replies: &[&[u8]] = &[b"server flight", b"connect answer", b"response"];
    let (clock, net, _talk) = quic_server(replies);
    let net = track::untracked(|| {
        let at = std::net::SocketAddr::from(([127, 0, 0, 2], 443));
        let talk = Conversation::replies(replies, false).per_send();
        net.with_peer(at, Peer::Accepts).with_conversation(at, talk)
    });
    let env = Env {
        clock: try_box(clock)?,
        net: try_box(net)?,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::with_env(env)?;
    let mut fine = true;
    type Set = fn(&mut Options) -> Result<(), OutOfMemory>;
    let gets: [(&[u8], Set); 2] = [
        (b"http://origin.example/1?q", h3_proxy),
        (b"http://other.example/1?q", other_h3_proxy),
    ];
    for (url, proxy) in gets {
        let mut easy = Easy::new();
        easy.set_libraries(fake_h3_libraries());
        let o = easy.options_mut();
        o.set_url(Some(url))?;
        o.http.user_agent = Some(b"curl/test".to_vec_fallible()?);
        proxy(o)?;
        let id = m
            .add(try_box(easy)?, (), &mut NoEvents)
            .map_err(|_| OutOfMemory)?;
        let result = curl_core::multi::drive_to_completion(&mut m, id, &mut NoEvents)
            .expect("the transfer is in the multi");
        fine &= result.is_ok();
        m.remove(id, &mut NoEvents).expect("in the multi");
    }
    Ok(fine)
}

/// One room per multi for QUIC to receive in, as C's `xfer_sockbuf`, the
/// connections to an HTTP/3 proxy borrowing it as the origin's do: two
/// pooled connections to the proxy make one between them, and an HTTP/3
/// origin through the proxy's CONNECT-UDP tunnel receives in a room of
/// its own of C's tunnel's size (`QUIC_TUNNEL_INBUF_SIZE`), leaving the
/// multi's to the proxy's connection below it.
fn one_quic_receive_room_per_multi() {
    let room = curl_os::net::BATCH * curl_os::net::SLOT;
    fake_h3_libraries();
    let (fine, rooms) = track::count_sized(room, two_h3_tunnels_scenario);
    assert!(
        fine.expect("nothing refused"),
        "both GETs through the proxy"
    );
    assert_eq!(
        rooms, 1,
        "receive rooms made for two connections to the proxy"
    );
    let (got, rooms) = track::count_sized(room, h3_over_h3_proxy_scenario);
    assert_eq!(got.expect("nothing refused").result, Ok(()));
    assert_eq!(rooms, 1, "receive rooms made for HTTP/3 through the proxy");
    let (got, tunnel_rooms) = track::count_sized(64 * 1024, h3_over_h3_proxy_scenario);
    assert_eq!(got.expect("nothing refused").result, Ok(()));
    assert!(
        tunnel_rooms >= 1,
        "the tunnelled origin's room is C's 64 KiB, made {tunnel_rooms} times"
    );
}

/// The room a multi's QUIC connections receive in is asked of the
/// allocator as it is, unwritten, as C `malloc`s its `xfer_sockbuf`: a
/// room asked zeroed is written whole for each multi made, a megabyte
/// and a half for every transfer the tool runs on its own. It is the
/// largest block a transfer asks for.
fn quic_receive_rooms_are_left_unwritten() {
    let room = curl_os::net::BATCH * curl_os::net::SLOT;
    fake_h3_libraries();
    for (what, scenario) in [
        (
            "an HTTP/3 GET",
            h3_get_scenario as fn() -> Result<Got, OutOfMemory>,
        ),
        ("HTTP/3 through an HTTP/3 proxy", h3_over_h3_proxy_scenario),
    ] {
        let (got, largest) = track::largest_unzeroed(scenario);
        assert_eq!(got.expect("nothing refused").result, Ok(()), "{what}");
        assert_eq!(
            largest, room,
            "{what}: the largest block asked for unzeroed is the receive room"
        );
    }
}

/// The multi's internal trace, kept untracked.
struct Internal(TryArc<Traced>);

impl curl_core::handler::TextSink for Internal {
    fn write(&self, text: &[u8]) {
        track::untracked(|| self.0.0.lock().unwrap().extend_from_slice(text));
    }
}

/// What a run of `quit_scenario` came to.
#[derive(Debug)]
struct Quit {
    /// The server was sent `QUIT`.
    said: bool,
    /// Its answer was read from the socket.
    answered: bool,
    /// The set could not take the connection in for want of memory.
    not_added: bool,
}

/// The FTP server's answers to a request for a file's size alone, and to
/// the `QUIT` after it.
const QUIT_REPLIES: [&[u8]; 8] = [
    b"220 hi\r\n",
    b"331 password?\r\n",
    b"230 in\r\n",
    b"257 \"/\" is it\r\n",
    b"200 binary\r\n",
    b"213 5\r\n",
    b"350 restarting\r\n",
    b"221 bye\r\n",
];

/// An FTP request for a file's size alone over a connection closed once
/// it is done, so that it says `QUIT`, whose answer the server gives a
/// poll later; run from a new multi to its cleanup.
fn quit_scenario() -> Quit {
    let (clock, net, talk, traced, components) = track::untracked(|| {
        let clock = ManualClock::new().expect("a clock");
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 8021));
        let talk = Conversation::replies(&QUIT_REPLIES, false)
            .per_send()
            .greeting()
            .late_replies();
        let net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        let traced = TryArc::try_new(Traced::default()).expect("memory");
        let components = Components::new().expect("memory");
        components.set(
            curl_core::components::Component::Multi,
            curl_core::components::Level::Info,
        );
        (clock, net, talk, traced, components)
    });
    // A refusal anywhere may end the run early: what it said is checked.
    let _ = quit_run(clock, net, components, &traced);
    track::untracked(|| {
        let sent = talk.received();
        let text = traced.0.lock().unwrap();
        let needle = b"adding failed";
        Quit {
            said: sent.ends_with(b"QUIT\r\n"),
            answered: talk.answered() == QUIT_REPLIES.len(),
            not_added: text.windows(needle.len()).any(|w| w == needle),
        }
    })
}

/// `quit_scenario`'s run, until it is done or a refusal ends it.
fn quit_run(
    clock: ManualClock,
    net: FakeNet,
    components: Components,
    traced: &TryArc<Traced>,
) -> Result<(), ()> {
    let env = Env {
        clock: try_box(clock).map_err(|_| ())?,
        net: try_box(net).map_err(|_| ())?,
        arena: ArenaPolicy::new(16, 0).expect("a valid policy"),
        waker: None,
    };
    let mut m: Multi = Multi::with_env(env).map_err(|_| ())?;
    let sink = Handler::text(Internal(traced.clone())).map_err(|_| ())?;
    m.trace_internally_to(components, sink);
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(b"ftp://127.0.0.1:8021/f")).map_err(|_| ())?;
    o.method = curl_core::options::Method::Head;
    o.limits.reuse.forbid = true;
    let id = m
        .add(try_box(easy).map_err(|_| ())?, (), &mut NoEvents)
        .map_err(|_| ())?;
    for _ in 0..100 {
        if m.perform(&mut NoEvents).is_err() || m.info_read().is_some() {
            break;
        }
        let wait = Duration::from_millis(100);
        if m.wait(&mut [], wait, WaitMode::Wait, &mut NoEvents)
            .is_err()
        {
            break;
        }
    }
    drop(m.remove(id, &mut NoEvents));
    Ok(())
}

/// Whatever allocation is refused, and every one after it, a `QUIT` the
/// server was sent is answered before its connection closes: one the
/// multi's set could not take in for want of memory has its answer waited
/// for in place, allocating nothing, as C's disconnect blocks for it. A
/// socket closed with the answer unread or still to come is reset, which
/// on Windows loses the `QUIT` itself.
fn a_quit_said_is_answered_before_its_connection_closes_whatever_is_refused() {
    let mut limit = 0;
    let mut not_added = 0;
    loop {
        let live = track::live_tracked();
        let (outcome, refused) = track::fail_after(limit, quit_scenario);
        assert_eq!(
            track::live_tracked(),
            live,
            "a run allowed {limit} allocations left blocks behind"
        );
        if outcome.said && !outcome.answered {
            track::untracked(|| panic!("a run allowed {limit} allocations gave {outcome:?}"));
        }
        if outcome.said && outcome.not_added {
            not_added += 1;
        }
        if !refused {
            assert!(outcome.said && outcome.answered, "{outcome:?}");
            assert!(not_added > 0, "no run refused the set's room");
            track::untracked(|| {
                eprintln!("torture: {limit} allocations, {not_added} runs not added to the set")
            });
            return;
        }
        limit += 1;
        assert!(limit < 100_000, "the scenario never ran to the end");
    }
}
