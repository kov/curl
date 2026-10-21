use std::num::NonZeroU64;
use std::time::Duration;

use crate::conn::io::FakeNet;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{
    DebugHandler, DebugKind, Handler, HeaderHandler, HeaderOrigin, Write, WriteHandler,
};
use crate::id::ArenaPolicy;
use crate::multi::{
    Env, Multi, NoEvents, PauseRequest, SocketEvent, TransferCx, TransferId, drive_to_completion,
};
use crate::options::script::{Piece, Script};
use crate::report::{HeaderCursor, HeaderError, HeaderView, Origins, Request};

use super::{Pipeline, Reach};
use crate::time::ManualClock;

fn multi() -> Multi {
    let clock = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
}

fn easy(url: &str) -> Easy {
    let mut e = Easy::new();
    e.options_mut().set_url(Some(url.as_bytes())).unwrap();
    e
}

/// One call a handler of a test saw: (handler, bytes).
type Seen = (&'static str, Vec<u8>);

/// What the handlers of a test saw, in order.
type Log = std::rc::Rc<std::cell::RefCell<Vec<Seen>>>;

/// Records what it is given; answers `verdict`; installs `then` as the
/// transfer's write handler on its first call.
struct Recorder {
    name: &'static str,
    log: Log,
    verdict: Write,
    then: std::cell::RefCell<Option<Handler<dyn WriteHandler>>>,
}

impl Recorder {
    fn new(name: &'static str, log: &Log) -> Recorder {
        Recorder {
            name,
            log: log.clone(),
            verdict: Write::Accepted,
            then: std::cell::RefCell::new(None),
        }
    }
}

impl WriteHandler for Recorder {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.log.borrow_mut().push((self.name, body.to_vec()));
        if let Some(next) = self.then.borrow_mut().take() {
            let me = cx.me();
            cx.options_mut(me).unwrap().callbacks.write = Some(next);
        }
        self.verdict
    }
}

impl HeaderHandler for Recorder {
    fn header(&self, _: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        self.log.borrow_mut().push((self.name, line.to_vec()));
        self.verdict
    }
}

fn handler<T: WriteHandler + 'static>(h: T) -> Handler<dyn WriteHandler> {
    Handler::write(h).unwrap()
}

fn script(pieces: Vec<Piece>) -> Easy {
    let mut e = easy("script://a");
    e.options_mut().script = Some(Script::new(pieces).unwrap());
    e
}

fn body(b: &[u8]) -> Piece {
    Piece::Body(b.to_vec())
}

/// Run `e` alone to its end and return its result.
fn run_alone(e: Easy) -> Result<(), ErrorKind> {
    let mut m = multi();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    drive_to_completion(&mut m, id, &mut NoEvents).unwrap()
}

#[test]
fn a_script_s_pieces_reach_their_handlers_in_order() {
    let log = Log::default();
    let mut e = script(vec![
        Piece::Status(b"HTTP/1.1 200 OK\r\n".to_vec()),
        Piece::Header(b"\r\n".to_vec()),
        body(b"one"),
        body(b"two"),
    ]);
    e.options_mut().callbacks.write = Some(handler(Recorder::new("write", &log)));
    e.options_mut().callbacks.header =
        Some(Handler::header(Recorder::new("header", &log)).unwrap());
    assert_eq!(run_alone(e), Ok(()));
    assert_eq!(
        *log.borrow(),
        [
            ("header", b"HTTP/1.1 200 OK\r\n".to_vec()),
            ("header", b"\r\n".to_vec()),
            ("write", b"one".to_vec()),
            ("write", b"two".to_vec()),
        ]
    );
}

#[test]
fn without_handlers_the_output_goes_nowhere() {
    assert_eq!(run_alone(script(vec![body(b"x")])), Ok(()));
}

/// A handler installed from inside a call takes the next piece
/// (8940c1436b, #23085).
#[test]
fn a_handler_replaced_inside_its_own_call_takes_the_next_piece() {
    let log = Log::default();
    let first = Recorder::new("first", &log);
    *first.then.borrow_mut() = Some(handler(Recorder::new("second", &log)));
    let mut e = script(vec![body(b"one"), body(b"two"), body(b"three")]);
    e.options_mut().callbacks.write = Some(handler(first));
    assert_eq!(run_alone(e), Ok(()));
    assert_eq!(
        *log.borrow(),
        [
            ("first", b"one".to_vec()),
            ("second", b"two".to_vec()),
            ("second", b"three".to_vec()),
        ]
    );
}

#[test]
fn a_failed_write_fails_the_transfer() {
    let log = Log::default();
    let mut e = script(vec![body(b"one"), body(b"two")]);
    let mut h = Recorder::new("write", &log);
    h.verdict = Write::Fail;
    e.options_mut().callbacks.write = Some(handler(h));
    assert_eq!(run_alone(e), Err(ErrorKind::WriteError));
    assert_eq!(
        *log.borrow(),
        [("write", b"one".to_vec())],
        "nothing after it"
    );
}

/// Fails with a reason of its own.
struct Explains;

impl WriteHandler for Explains {
    fn write(&self, cx: &mut TransferCx<'_>, _: &[u8]) -> Write {
        cx.fail(b"mine");
        Write::Fail
    }
}

/// Keeps the trace's text lines.
#[derive(Clone, Default)]
struct Trace(std::rc::Rc<std::cell::RefCell<Vec<Vec<u8>>>>);

/// The debug build's warning, which its first transfer traces.
fn debug_build_warning(line: &[u8]) -> bool {
    line.starts_with(b"!!! WARNING") || line.starts_with(b"This is a debug build")
}

impl DebugHandler for Trace {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text && !debug_build_warning(data) {
            self.0.borrow_mut().push(data.to_vec());
        }
    }
}

impl crate::handler::TextSink for Trace {
    fn write(&self, text: &[u8]) {
        self.0.borrow_mut().push(text.to_vec());
    }
}

/// A handler that says why it fails gives the transfer's reason, and the
/// transfer adds none of its own: C's write callback adapter is the one
/// that calls `failf` for a short count. The failure sink hears it once.
#[test]
fn a_handler_s_own_reason_is_the_only_one() {
    let mut e = script(vec![body(b"one")]);
    let (trace, told) = (Trace::default(), Trace::default());
    e.options_mut().output.verbose = true;
    e.options_mut().callbacks.write = Some(handler(Explains));
    e.options_mut().callbacks.debug = Some(Handler::debug(trace.clone()).unwrap());
    e.options_mut().callbacks.failure = Some(Handler::text(told.clone()).unwrap());
    let mut m = multi();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Err(ErrorKind::WriteError));
    let e = m.remove(id, &mut NoEvents).unwrap().easy;
    assert_eq!(e.report().failure(), Some(&b"mine"[..]));
    let closed = b"closing connection #0\n".to_vec();
    assert_eq!(*trace.0.borrow(), [b"mine\n".to_vec(), closed]);
    assert_eq!(*told.0.borrow(), [b"mine".to_vec()]);
}

/// Fails with two reasons.
struct ExplainsTwice;

impl WriteHandler for ExplainsTwice {
    fn write(&self, cx: &mut TransferCx<'_>, _: &[u8]) -> Write {
        cx.fail(b"first");
        cx.fail(b"second");
        Write::Fail
    }
}

/// Of a transfer's reasons, the report keeps and the failure sink hears
/// the first alone (`failf`'s `state.errorbuf`); the trace has each.
#[test]
fn the_first_reason_is_the_one_kept() {
    let mut e = script(vec![body(b"one")]);
    let (trace, told) = (Trace::default(), Trace::default());
    e.options_mut().output.verbose = true;
    e.options_mut().callbacks.write = Some(handler(ExplainsTwice));
    e.options_mut().callbacks.debug = Some(Handler::debug(trace.clone()).unwrap());
    e.options_mut().callbacks.failure = Some(Handler::text(told.clone()).unwrap());
    let mut m = multi();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    drive_to_completion(&mut m, id, &mut NoEvents)
        .unwrap()
        .unwrap_err();
    let e = m.remove(id, &mut NoEvents).unwrap().easy;
    assert_eq!(e.report().failure(), Some(&b"first"[..]));
    assert_eq!(*told.0.borrow(), [b"first".to_vec()]);
    assert_eq!(
        *trace.0.borrow(),
        [
            b"first\n".to_vec(),
            b"second\n".to_vec(),
            b"closing connection #0\n".to_vec()
        ]
    );
}

/// Sees its own transfer and its options from inside the call.
struct Introspect(std::cell::Cell<Option<TransferId>>);

impl WriteHandler for Introspect {
    fn write(&self, cx: &mut TransferCx<'_>, _: &[u8]) -> Write {
        let me = cx.me();
        assert_eq!(cx.options(me).unwrap().url(), Some(&b"script://a"[..]));
        let copy = cx.duplicate(me).unwrap().unwrap();
        assert_eq!(copy.options().url(), Some(&b"script://a"[..]));
        self.0.set(Some(me));
        Write::Accepted
    }
}

#[test]
fn a_handler_reaches_its_own_transfer() {
    let mut m = multi();
    let seen = std::rc::Rc::new(Introspect(std::cell::Cell::new(None)));
    let mut e = script(vec![body(b"x")]);
    e.options_mut().callbacks.write = Some(Handler::write(RcWrite(seen.clone())).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    assert_eq!(seen.0.get(), Some(id));
}

struct RcWrite(std::rc::Rc<Introspect>);

impl WriteHandler for RcWrite {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.write(cx, body)
    }
}

#[test]
fn a_copy_of_the_options_shares_the_handlers() {
    let log = Log::default();
    let mut e = easy("script://a");
    e.options_mut().callbacks.write = Some(handler(Recorder::new("w", &log)));
    let copy = e.try_clone().unwrap();
    let mine = e.options().callbacks.write.as_ref().unwrap();
    assert!(Handler::ptr_eq(
        copy.options().callbacks.write.as_ref().unwrap(),
        mine
    ));
    let other = handler(Recorder::new("w", &log));
    assert!(!Handler::ptr_eq(&other, mine));
    assert_eq!(format!("{other:?}"), "Handler");
}

impl DebugHandler for Recorder {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        // Only the connection's end is traced as text.
        if kind == DebugKind::Text {
            assert!(
                data.ends_with(b"connection #0\n") || debug_build_warning(data),
                "{data:?}"
            );
            return;
        }
        assert_eq!(kind, DebugKind::DataIn);
        self.log.borrow_mut().push((self.name, data.to_vec()));
    }
}

/// A transfer playing `pieces` with recording write, header and debug
/// handlers, set up by `set`; its result and what the handlers saw.
fn played(
    pieces: Vec<Piece>,
    set: impl FnOnce(&mut crate::options::Options, &Log),
) -> (Result<(), ErrorKind>, Vec<Seen>) {
    let log = Log::default();
    let mut e = script(pieces);
    let o = e.options_mut();
    o.callbacks.write = Some(handler(Recorder::new("write", &log)));
    o.callbacks.header = Some(Handler::header(Recorder::new("header", &log)).unwrap());
    o.callbacks.debug = Some(Handler::debug(Recorder::new("debug", &log)).unwrap());
    set(o, &log);
    let result = run_alone(e);
    let seen = log.borrow().clone();
    (result, seen)
}

/// The lengths of what `name` was given.
fn lengths(seen: &[Seen], name: &str) -> Vec<usize> {
    seen.iter()
        .filter(|(n, _)| *n == name)
        .map(|(_, b)| b.len())
        .collect()
}

/// A header line `n` bytes long, its line ending included.
fn header_line(n: usize) -> Vec<u8> {
    let mut line = b"x: ".to_vec();
    line.resize(n - 2, b'y');
    line.extend_from_slice(b"\r\n");
    line
}

fn bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

#[test]
fn the_body_goes_out_in_pieces_of_at_most_16_kib() {
    let (result, seen) = played(vec![Piece::Body(bytes(40000))], |_, _| {});
    assert_eq!(result, Ok(()));
    assert_eq!(lengths(&seen, "write"), [16384, 16384, 7232]);
    let joined: Vec<u8> = seen.iter().flat_map(|(_, b)| b.clone()).collect();
    assert_eq!(joined, bytes(40000));
}

#[test]
fn a_header_line_goes_out_whole() {
    let mut line = b"x: ".to_vec();
    line.extend_from_slice(&[b'y'; 19997]);
    line.extend_from_slice(b"\r\n");
    let (result, seen) = played(vec![Piece::Header(line)], |_, _| {});
    assert_eq!(result, Ok(()));
    assert_eq!(lengths(&seen, "header"), [20002]);
    assert_eq!(lengths(&seen, "write"), [0usize; 0]);
}

/// `-i`: each line to the write handler, then to the header handler.
#[test]
fn included_header_lines_go_to_the_write_handler_first() {
    let (result, seen) = played(
        vec![
            Piece::Status(b"HTTP/1.1 200 OK\r\n".to_vec()),
            Piece::Header(b"\r\n".to_vec()),
            body(b"hi"),
        ],
        |o, _| o.output.include_header = true,
    );
    assert_eq!(result, Ok(()));
    let names: Vec<_> = seen.iter().map(|(n, b)| (*n, b.as_slice())).collect();
    assert_eq!(
        names,
        [
            ("write", &b"HTTP/1.1 200 OK\r\n"[..]),
            ("header", b"HTTP/1.1 200 OK\r\n"),
            ("write", b"\r\n"),
            ("header", b"\r\n"),
            ("write", b"hi"),
        ]
    );
}

#[test]
fn a_failed_write_ends_the_output_mid_write() {
    let (result, seen) = played(vec![Piece::Body(bytes(40000))], |o, log| {
        let mut h = Recorder::new("write", log);
        h.verdict = Write::Fail;
        o.callbacks.write = Some(handler(h));
    });
    assert_eq!(result, Err(ErrorKind::WriteError));
    assert_eq!(
        lengths(&seen, "write"),
        [16384],
        "no piece after the failed one"
    );
}

#[test]
fn a_failed_header_write_ends_the_output() {
    let (result, seen) = played(
        vec![Piece::Header(b"a: b\r\n".to_vec()), body(b"hi")],
        |o, log| {
            let mut h = Recorder::new("header", log);
            h.verdict = Write::Fail;
            o.callbacks.header = Some(Handler::header(h).unwrap());
        },
    );
    assert_eq!(result, Err(ErrorKind::WriteError));
    assert_eq!(lengths(&seen, "write"), [0usize; 0]);
}

fn limit(n: u64) -> Option<NonZeroU64> {
    NonZeroU64::new(n)
}

/// The body up to the limit is delivered, then the transfer fails
/// (`cw_download_write`).
#[test]
fn a_body_over_the_size_limit_is_cut_at_the_limit() {
    let (result, seen) = played(vec![Piece::Body(bytes(40000))], |o, _| {
        o.limits.max_filesize = limit(20000);
    });
    assert_eq!(result, Err(ErrorKind::FilesizeExceeded));
    assert_eq!(lengths(&seen, "write"), [16384, 3616]);
    let (result, seen) = played(vec![Piece::Body(bytes(20000))], |o, _| {
        o.limits.max_filesize = limit(20000);
    });
    assert_eq!(result, Ok(()), "exactly the limit");
    assert_eq!(lengths(&seen, "write"), [16384, 3616]);
    let (result, seen) = played(
        vec![Piece::Body(bytes(15000)), Piece::Body(bytes(15000))],
        |o, _| o.limits.max_filesize = limit(20000),
    );
    assert_eq!(result, Err(ErrorKind::FilesizeExceeded));
    assert_eq!(
        lengths(&seen, "write"),
        [15000, 5000],
        "the limit spans writes"
    );
}

/// Included header lines count towards what was delivered, though not
/// towards the body: the piece that would pass the limit is not written
/// (`Curl_pgrs_deliver_check`).
#[test]
fn included_headers_count_against_the_size_limit() {
    let (result, seen) = played(
        vec![Piece::Header(header_line(100)), Piece::Body(bytes(100))],
        |o, _| {
            o.output.include_header = true;
            o.limits.max_filesize = limit(150);
        },
    );
    assert_eq!(result, Err(ErrorKind::FilesizeExceeded));
    assert_eq!(lengths(&seen, "write"), [100], "the header line only");
    assert_eq!(lengths(&seen, "header"), [100]);
}

/// A verbose transfer traces each body write whole, before any piece of
/// it reaches the write handler; header lines are not traced here.
#[test]
fn a_verbose_transfer_traces_the_body_as_received() {
    let pieces = || {
        vec![
            Piece::Header(b"a: b\r\n".to_vec()),
            Piece::Body(bytes(40000)),
        ]
    };
    let (result, seen) = played(pieces(), |o, _| o.output.verbose = true);
    assert_eq!(result, Ok(()));
    let names: Vec<_> = seen.iter().map(|(n, b)| (*n, b.len())).collect();
    assert_eq!(
        names,
        [
            ("header", 6),
            ("debug", 40000),
            ("write", 16384),
            ("write", 16384),
            ("write", 7232)
        ]
    );
    let (_, seen) = played(pieces(), |_, _| {});
    assert_eq!(lengths(&seen, "debug"), [0usize; 0], "not verbose");
}

/// Once a write has failed, nothing reaches a handler again, header or
/// body, and every later write fails (#13337).
#[test]
fn failed_output_stays_failed() {
    let log = Log::default();
    let mut m = multi();
    let mut e = easy("stall://a");
    let mut h = Recorder::new("write", &log);
    h.verdict = Write::Fail;
    e.options_mut().callbacks.write = Some(handler(h));
    e.options_mut().callbacks.header =
        Some(Handler::header(Recorder::new("header", &log)).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    // Exchanging, as a protocol delivering output is.
    m.perform(&mut NoEvents).unwrap();
    m.with_step_cx(id, |cx| {
        let mut p = Pipeline::new(Reach::Network);
        assert_eq!(p.body(cx, b"one"), Err(ErrorKind::WriteError));
        assert_eq!(
            p.header(cx, b"a: b\r\n", HeaderOrigin::Header),
            Err(ErrorKind::WriteError)
        );
        assert_eq!(p.body(cx, b"two"), Err(ErrorKind::WriteError));
    });
    assert_eq!(*log.borrow(), [("write", b"one".to_vec())]);
}

/// What the write handler sees of its own report at each call:
/// (download, delivered, starttransfer).
struct SizeProbe(std::cell::RefCell<Vec<(u64, u64, Duration)>>);

impl WriteHandler for std::rc::Rc<SizeProbe> {
    fn write(&self, cx: &mut TransferCx<'_>, _: &[u8]) -> Write {
        let report = cx.info(cx.me()).unwrap();
        let sizes = report.sizes();
        self.0.borrow_mut().push((
            sizes.download(),
            sizes.delivered(),
            report.timings().starttransfer(),
        ));
        Write::Accepted
    }
}

/// Inside the write handler the download size leaves out the whole write
/// in progress, the delivered size only the piece in progress
/// (`cw_download_write`, `cw_out_ptr_flush`); the response had started.
fn probed(include_header: bool) -> (Vec<(u64, u64, Duration)>, crate::report::Sizes) {
    let probe = std::rc::Rc::new(SizeProbe(Default::default()));
    let mut m = multi();
    let mut e = script(vec![
        Piece::Header(b"a: 34567\r\n".to_vec()),
        Piece::Body(bytes(40000)),
        Piece::Body(bytes(10)),
    ]);
    e.options_mut().callbacks.write = Some(Handler::write(probe.clone()).unwrap());
    e.options_mut().output.include_header = include_header;
    let id = m.add(e, (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    let seen = probe.0.borrow().clone();
    (seen, *m.easy(id).unwrap().report().sizes())
}

#[test]
fn a_handler_reads_its_report_as_it_stands() {
    let us = Duration::from_micros(1);
    let (seen, sizes) = probed(false);
    assert_eq!(
        seen,
        [
            (0, 0, us),
            (0, 16384, us),
            (0, 32768, us),
            (40000, 40000, us)
        ]
    );
    assert_eq!((sizes.download(), sizes.delivered()), (40010, 40010));
    // An included header line is delivered, not downloaded.
    let (seen, sizes) = probed(true);
    assert_eq!(seen[..2], [(0, 0, us), (0, 10, us)]);
    assert_eq!((sizes.download(), sizes.delivered()), (40010, 40020));
}

/// A proxy's CONNECT answer is not the response starting.
#[test]
fn a_connect_answer_does_not_start_the_response() {
    let mut m = multi();
    let ids = [
        Piece::Connect(b"Via: proxy\r\n".to_vec()),
        Piece::Status(b"HTTP/1.1 200 OK\r\n".to_vec()),
    ]
    .map(|p| m.add(script(vec![p]), (), &mut NoEvents).unwrap());
    for id in ids {
        assert_eq!(
            drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
            Ok(())
        );
    }
    let start = |id| m.easy(id).unwrap().report().timings().starttransfer();
    assert_eq!(start(ids[0]), Duration::ZERO);
    assert_eq!(start(ids[1]), Duration::from_micros(1));
}

/// Reads `Content-Type` from inside its call.
struct ReadsHeader(std::cell::RefCell<Option<Vec<u8>>>);

impl WriteHandler for std::rc::Rc<ReadsHeader> {
    fn write(&self, cx: &mut TransferCx<'_>, _: &[u8]) -> Write {
        let h = cx.info(cx.me()).unwrap().headers();
        let found = h.get(b"content-type", 0, Origins::ALL, Request::Last);
        *self.0.borrow_mut() = Some(found.unwrap().value.to_vec());
        Write::Accepted
    }
}

fn headed() -> Easy {
    script(vec![
        Piece::Status(b"HTTP/1.1 200 OK\r\n".to_vec()),
        Piece::Header(b"Content-Type: text/plain\r\n".to_vec()),
        Piece::Header(b"X-Two: 2\r\n".to_vec()),
        Piece::Header(b"\r\n".to_vec()),
        body(b"hi"),
    ])
}

fn next(e: &Easy, prev: Option<HeaderCursor>) -> Option<HeaderView<'_>> {
    e.report().headers().next(Origins::ALL, Request::Last, prev)
}

/// Run `e` alone to its end and give it back.
fn rerun(m: &mut Multi, e: Easy) -> Easy {
    let id = m.add(e, (), &mut NoEvents).unwrap();
    assert_eq!(drive_to_completion(m, id, &mut NoEvents).unwrap(), Ok(()));
    m.remove(id, &mut NoEvents).unwrap().easy
}

/// Header lines are stored as they arrive, the status line and the end of
/// the head aside, readable from the handlers and after the transfer,
/// until the next one starts.
#[test]
fn a_transfer_s_headers_are_stored_for_its_handlers_and_after() {
    let probe = std::rc::Rc::new(ReadsHeader(Default::default()));
    let mut m = multi();
    let mut e = headed();
    e.options_mut().callbacks.write = Some(Handler::write(probe.clone()).unwrap());
    let e = rerun(&mut m, e);
    assert_eq!(probe.0.borrow().as_deref(), Some(&b"text/plain"[..]));
    let first = next(&e, None).unwrap();
    assert_eq!(first.name, b"Content-Type");
    let cursor = first.cursor;
    assert_eq!(next(&e, Some(cursor)).unwrap().name, b"X-Two");
    assert_eq!(next(&e, Some(next(&e, Some(cursor)).unwrap().cursor)), None);
    // The next run stores its own, and the cursor is stale.
    let mut e = rerun(&mut m, e);
    let store = e.report().headers();
    let h = store
        .get(b"Content-Type", 0, Origins::ALL, Request::Last)
        .unwrap();
    assert_eq!(h.amount, 1);
    assert_eq!(next(&e, Some(cursor)), None);
    // A reset empties the store, and no later run makes the cursor good
    // again.
    e.reset();
    assert_eq!(
        e.report()
            .headers()
            .get(b"Content-Type", 0, Origins::ALL, Request::Last),
        Err(HeaderError::NoHeaders)
    );
    let mut fresh = headed();
    std::mem::swap(fresh.options_mut(), e.options_mut());
    let e = rerun(&mut m, e);
    assert_eq!(next(&e, None).unwrap().name, b"Content-Type");
    assert_eq!(next(&e, Some(cursor)), None);
}

/// A header line the store cannot split fails the transfer before it is
/// delivered.
#[test]
fn an_invalid_header_line_fails_the_transfer() {
    let (result, seen) = played(vec![Piece::Header(b"no colon\r\n".to_vec())], |_, _| {});
    assert_eq!(result, Err(ErrorKind::BadFunctionArgument));
    assert_eq!(lengths(&seen, "header"), [0usize; 0]);
}

/// Every call the handlers of one transfer saw, in order: (handler, bytes,
/// verdict).
type Calls = std::rc::Rc<std::cell::RefCell<Vec<(&'static str, Vec<u8>, Write)>>>;

/// A write or header handler answering by `plan`, given the number of the
/// call among all its transfer's handler calls; it may pause transfers.
struct Planned<F> {
    plan: std::rc::Rc<F>,
    calls: Calls,
}

impl<F: Fn(&mut TransferCx<'_>, usize) -> Write> Planned<F> {
    fn answer(&self, name: &'static str, cx: &mut TransferCx<'_>, bytes: &[u8]) -> Write {
        let n = self.calls.borrow().len();
        let w = (self.plan)(cx, n);
        self.calls.borrow_mut().push((name, bytes.to_vec(), w));
        w
    }
}

impl<F: Fn(&mut TransferCx<'_>, usize) -> Write> WriteHandler for Planned<F> {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.answer("write", cx, body)
    }
}

impl<F: Fn(&mut TransferCx<'_>, usize) -> Write> HeaderHandler for Planned<F> {
    fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        self.answer("header", cx, line)
    }
}

/// Give `e` write and header handlers answering by `plan`.
fn planned<F>(e: &mut Easy, plan: F) -> Calls
where
    F: Fn(&mut TransferCx<'_>, usize) -> Write + 'static,
{
    let calls = Calls::default();
    let plan = std::rc::Rc::new(plan);
    let cb = &mut e.options_mut().callbacks;
    cb.write = Some(
        Handler::write(Planned {
            plan: plan.clone(),
            calls: calls.clone(),
        })
        .unwrap(),
    );
    cb.header = Some(
        Handler::header(Planned {
            plan,
            calls: calls.clone(),
        })
        .unwrap(),
    );
    calls
}

/// What the handlers took, in order: (handler, bytes) of every accepted
/// call.
fn taken(calls: &Calls) -> Vec<(&'static str, Vec<u8>)> {
    calls
        .borrow()
        .iter()
        .filter(|(_, _, w)| *w == Write::Accepted)
        .map(|(n, b, _)| (*n, b.clone()))
        .collect()
}

fn pausing_on(calls: &'static [usize]) -> impl Fn(&mut TransferCx<'_>, usize) -> Write {
    move |_, n| {
        if calls.contains(&n) {
            Write::Pause
        } else {
            Write::Accepted
        }
    }
}

/// A response with header lines and body, the body in two writes.
fn response() -> Vec<Piece> {
    vec![
        Piece::Status(b"HTTP/1.1 200 OK\r\n".to_vec()),
        Piece::Header(b"A: 1\r\n".to_vec()),
        Piece::Header(b"\r\n".to_vec()),
        Piece::Body(bytes(40000)),
        Piece::Body(bytes(10)),
        Piece::Header(b"T: trailer\r\n".to_vec()),
    ]
}

/// Run `pieces`, pausing on the calls in `pause_on` and unpausing from
/// outside after every pass; what the handlers took.
fn paused_run(include_header: bool, pause_on: &'static [usize]) -> Vec<(&'static str, Vec<u8>)> {
    let mut m = multi();
    let mut e = script(response());
    e.options_mut().output.include_header = include_header;
    let calls = planned(&mut e, pausing_on(pause_on));
    let id = m.add(e, (), &mut NoEvents).unwrap();
    for _ in 0..100 {
        m.perform(&mut NoEvents).unwrap();
        if let Some(msg) = m.info_read() {
            assert_eq!(msg.result, Ok(()));
            return taken(&calls);
        }
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    }
    panic!("never completed");
}

/// However often a handler pauses, and wherever, what the handlers take
/// once unpaused is what they would have taken unpaused: same bytes, same
/// order, with `-i` or without (`cw_out_append`, `cw_out_flush_chain`).
#[test]
fn held_output_is_replayed_in_the_order_it_came() {
    for include_header in [false, true] {
        let straight = paused_run(include_header, &[]);
        let calls_unpaused = if include_header { 12 } else { 8 };
        assert_eq!(straight.len(), calls_unpaused, "{straight:?}");
        for pause_on in [
            &[0][..],
            &[1],
            &[2],
            &[4],
            &[5],
            &[0, 1, 2],
            &[1, 3, 5, 7],
            &[3, 4, 5, 6, 7, 8],
        ] {
            assert_eq!(
                paused_run(include_header, pause_on),
                straight,
                "-i {include_header}, pausing on {pause_on:?}"
            );
        }
    }
}

/// The piece a handler paused on is given again, whole, then the rest.
#[test]
fn the_paused_piece_is_given_again_whole() {
    let mut m = multi();
    let mut e = script(vec![Piece::Body(bytes(40000))]);
    let calls = planned(&mut e, pausing_on(&[1]));
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let lens: Vec<_> = calls
        .borrow()
        .iter()
        .map(|(_, b, w)| (b.len(), *w))
        .collect();
    assert_eq!(lens, [(16384, Write::Accepted), (16384, Write::Pause)]);
    let sizes = *m.easy(id).unwrap().report().sizes();
    assert_eq!(
        (sizes.download(), sizes.delivered()),
        (40000, 16384),
        "held is downloaded, not delivered"
    );
    // The unpause replays at once, before it returns.
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    let lens: Vec<_> = calls.borrow().iter().map(|(_, b, _)| b.len()).collect();
    assert_eq!(lens, [16384, 16384, 16384, 7232]);
    assert_eq!(m.easy(id).unwrap().report().sizes().delivered(), 40000);
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.info_read().map(|msg| msg.result), Some(Ok(())));
}

/// A transfer whose output is held is not done, and a timeout ends it.
#[test]
fn held_output_keeps_the_transfer_going_until_its_time_is_up() {
    let mut m = multi();
    let clock = ManualClock::new().unwrap();
    let mut e = script(vec![body(b"one")]);
    e.options_mut().limits.total = crate::time::TimeLimit::from_millis(1000);
    planned(&mut e, pausing_on(&[0]));
    drop(clock);
    let id = m.add(e, (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents),
        Ok(Err(ErrorKind::OperationTimedout))
    );
}

/// A pipeline whose protocol cannot pause fails a pausing write
/// ("Write callback asked for PAUSE when not supported").
#[test]
fn a_pause_where_none_is_supported_fails_the_write() {
    let mut m = multi();
    let mut e = easy("stall://a");
    let calls = planned(&mut e, pausing_on(&[0]));
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.with_step_cx(id, |cx| {
        let mut p = Pipeline::new(Reach::Local);
        assert!(!p.pausable());
        assert_eq!(p.body(cx, b"x"), Err(ErrorKind::WriteError));
        assert!(!p.holds_output());
    });
    assert_eq!(calls.borrow().len(), 1);
}

/// Past 64 MiB held, the transfer fails ("pause buffer not large enough").
#[test]
fn at_most_64_mib_of_output_is_held() {
    let mut e = script(vec![Piece::Body(bytes(super::held::MAX_HELD + 1))]);
    planned(&mut e, pausing_on(&[0]));
    assert_eq!(run_alone(e), Err(ErrorKind::TooLarge));
}

/// Only a transfer with a connection can be paused.
#[test]
fn a_transfer_not_exchanging_cannot_be_paused() {
    let mut m = multi();
    let id = m.add(easy("null://a"), (), &mut NoEvents).unwrap();
    let ev = &mut NoEvents;
    assert_eq!(
        m.pause(id, PauseRequest::RECV, ev),
        Err(ErrorKind::BadFunctionArgument),
        "not started"
    );
    m.perform(ev).unwrap();
    assert_eq!(
        m.pause(id, PauseRequest::RECV, ev),
        Err(ErrorKind::BadFunctionArgument),
        "completed"
    );
    m.remove(id, ev).unwrap();
    assert_eq!(
        m.pause(id, PauseRequest::RECV, ev),
        Err(ErrorKind::BadFunctionArgument),
        "gone"
    );
}

/// A pause asked for from inside a write stops new input, not the write
/// in progress; an unpause lets the input go on.
#[test]
fn a_receive_pause_finishes_the_write_under_way() {
    let mut m = multi();
    let mut e = script(vec![Piece::Body(bytes(40000)), body(b"z")]);
    let calls = planned(&mut e, |cx, n| {
        if n == 0 {
            let me = cx.me();
            cx.pause(me, PauseRequest::RECV).unwrap();
        }
        Write::Accepted
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let lens: Vec<_> = calls.borrow().iter().map(|(_, b, _)| b.len()).collect();
    assert_eq!(
        lens,
        [16384, 16384, 7232],
        "the write went on, the next did not come"
    );
    assert_eq!(m.info_read().map(|msg| msg.id), None);
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(calls.borrow().len(), 3, "still paused");
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    // The unpause marks it to run: a pass that runs only what is due or
    // marked runs it.
    m.socket_action(SocketEvent::Timeout, &mut NoEvents)
        .unwrap();
    assert_eq!(taken(&calls).last(), Some(&("write", b"z".to_vec())));
    assert_eq!(m.info_read().map(|msg| msg.result), Some(Ok(())));
}

/// An unpause from another transfer's handler replays at once; a pause
/// during that replay holds again, and a second unpause goes on from the
/// piece it held. No byte is lost or given twice.
#[test]
fn a_sibling_s_unpause_replays_at_once() {
    let mut m = multi();
    let mut a = script(vec![Piece::Body(bytes(40000))]);
    let a_calls = planned(&mut a, pausing_on(&[0, 2]));
    let a_id = m.add(a, (), &mut NoEvents).unwrap();
    let mut b = script(vec![body(b"1"), body(b"2")]);
    let b_calls = planned(&mut b, move |cx, _| {
        cx.pause(a_id, PauseRequest::CONT).unwrap();
        Write::Accepted
    });
    m.add(b, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let a_seen: Vec<_> = a_calls
        .borrow()
        .iter()
        .map(|(_, b, w)| (b.len(), *w))
        .collect();
    use Write::{Accepted as A, Pause as P};
    assert_eq!(
        a_seen,
        [(16384, P), (16384, A), (16384, P), (16384, A), (7232, A)]
    );
    let a_bytes: Vec<u8> = taken(&a_calls).into_iter().flat_map(|(_, b)| b).collect();
    assert_eq!(a_bytes, bytes(40000));
    assert_eq!(taken(&b_calls).len(), 2);
    m.perform(&mut NoEvents).unwrap();
    let mut results: Vec<_> = std::iter::from_fn(|| m.info_read().map(|msg| msg.result)).collect();
    results.sort_by_key(|r| r.is_err());
    assert_eq!(results, [Ok(()), Ok(())]);
}

/// An unpause of the transfer being replayed, from inside the replay,
/// only changes its pause: the replay under way goes on (3235).
#[test]
fn an_unpause_inside_the_replay_lets_it_go_on() {
    let mut m = multi();
    let mut e = script(vec![Piece::Body(bytes(40000))]);
    let calls = planned(&mut e, |cx, n| match n {
        0 => Write::Pause,
        1 => {
            let me = cx.me();
            cx.pause(me, PauseRequest::RECV).unwrap();
            cx.pause(me, PauseRequest::CONT).unwrap();
            Write::Accepted
        }
        _ => Write::Accepted,
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    let lens: Vec<_> = calls.borrow().iter().map(|(_, b, _)| b.len()).collect();
    assert_eq!(
        lens,
        [16384, 16384, 16384, 7232],
        "the whole replay ran inside the unpause"
    );
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.info_read().map(|msg| msg.result), Some(Ok(())));
}

/// A replay that fails is the unpause's error; the output stays failed
/// and the transfer fails at its next step, calling no handler again.
#[test]
fn a_failed_replay_fails_the_unpause_and_then_the_transfer() {
    let mut m = multi();
    let mut e = script(vec![Piece::Body(bytes(40000))]);
    let calls = planned(&mut e, |_, n| match n {
        0 => Write::Pause,
        1 => Write::Fail,
        _ => Write::Accepted,
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        m.pause(id, PauseRequest::CONT, &mut NoEvents),
        Err(ErrorKind::WriteError)
    );
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        m.info_read().map(|msg| msg.result),
        Some(Err(ErrorKind::WriteError))
    );
    assert_eq!(calls.borrow().len(), 2);
}

/// Counts the timer calls.
#[derive(Default)]
struct Timers(u32);

impl crate::multi::MultiEvents<crate::multi::NoHost> for Timers {
    fn timer(
        &mut self,
        _: &mut crate::multi::EventCx<'_, crate::multi::NoHost>,
        _: crate::multi::TimerChange,
    ) -> Result<(), crate::multi::Abort> {
        self.0 += 1;
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }
}

/// An unpause from outside that leaves the transfer running tells the
/// timer before it returns; a pause, or no change, does not.
#[test]
fn an_unpause_tells_the_timer() {
    let mut m = multi();
    let mut e = script(vec![body(b"one")]);
    planned(&mut e, pausing_on(&[0]));
    let ev = &mut Timers::default();
    let id = m.add(e, (), ev).unwrap();
    m.perform(ev).unwrap();
    let before = ev.0;
    // A change, but still paused every way it wants.
    m.pause(id, PauseRequest::ALL, ev).unwrap();
    assert_eq!(ev.0, before, "paused: nothing to run");
    m.pause(id, PauseRequest::CONT, ev).unwrap();
    assert_eq!(ev.0, before + 1, "running again, now");
    m.pause(id, PauseRequest::CONT, ev).unwrap();
    assert_eq!(ev.0, before + 1, "no change");
}

/// A receive pause asked for inside a replay lets the replay finish, every
/// entry of it, then stops the input until it is lifted.
#[test]
fn a_receive_pause_inside_the_replay_lets_it_finish() {
    let mut m = multi();
    let status = b"HTTP/1.1 200 OK\r\n";
    let mut e = script(vec![Piece::Status(status.to_vec()), body(b"z")]);
    e.options_mut().output.include_header = true;
    // The status line's copy in the body pauses, holding it and the
    // header handler's copy: two entries.
    let calls = planned(&mut e, |cx, n| match n {
        0 => Write::Pause,
        1 => {
            let me = cx.me();
            cx.pause(me, PauseRequest::RECV).unwrap();
            Write::Accepted
        }
        _ => Write::Accepted,
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    let seen: Vec<_> = calls
        .borrow()
        .iter()
        .map(|(n, b, w)| (*n, b.clone(), *w))
        .collect();
    use Write::{Accepted as A, Pause as P};
    assert_eq!(
        seen,
        [
            ("write", status.to_vec(), P),
            ("write", status.to_vec(), A),
            ("header", status.to_vec(), A),
        ]
    );
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(calls.borrow().len(), 3, "stopped: nothing more read");
    assert_eq!(m.info_read().map(|msg| msg.id), None);
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(taken(&calls).last(), Some(&("write", b"z".to_vec())));
    assert_eq!(m.info_read().map(|msg| msg.result), Some(Ok(())));
}

/// Output written while output is held but no longer paused (an unpause
/// the step has not replayed yet) goes behind what is held, body joining
/// the body before it.
#[test]
fn output_written_while_held_goes_behind_it() {
    let mut m = multi();
    let mut e = easy("stall://a");
    let calls = planned(&mut e, pausing_on(&[0]));
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.with_step_cx(id, |cx| {
        let mut p = Pipeline::new(Reach::Network);
        p.body(cx, b"one").unwrap();
        assert!(p.holds_output());
        cx.pause_mut().recv = super::RecvPause::Running;
        p.body(cx, b"two").unwrap();
        assert!(!p.holds_output());
    });
    let seen: Vec<_> = calls
        .borrow()
        .iter()
        .map(|(_, b, w)| (b.clone(), *w))
        .collect();
    assert_eq!(
        seen,
        [
            (b"one".to_vec(), Write::Pause),
            (b"onetwo".to_vec(), Write::Accepted)
        ]
    );
}
