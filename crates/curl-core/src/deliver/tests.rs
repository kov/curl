use std::num::NonZeroU64;
use std::time::Duration;

use crate::conn::io::FakeNet;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{
    DebugHandler, DebugKind, Handler, HeaderHandler, HeaderOrigin, Write, WriteHandler,
};
use crate::id::ArenaPolicy;
use crate::multi::{Env, Multi, NoEvents, TransferCx, TransferId, drive_to_completion};
use crate::options::script::{Piece, Script};
use crate::report::{HeaderCursor, HeaderError, HeaderView, Origins, Request};

use super::Pipeline;
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
fn a_failed_or_paused_write_fails_the_transfer() {
    for verdict in [Write::Fail, Write::Pause] {
        let log = Log::default();
        let mut e = script(vec![body(b"one"), body(b"two")]);
        let mut h = Recorder::new("write", &log);
        h.verdict = verdict;
        e.options_mut().callbacks.write = Some(handler(h));
        assert_eq!(run_alone(e), Err(ErrorKind::WriteError), "{verdict:?}");
        assert_eq!(
            *log.borrow(),
            [("write", b"one".to_vec())],
            "nothing after it"
        );
    }
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
        let mut p = Pipeline::default();
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
