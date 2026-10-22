use crate::test_cell::Cell;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use curl_alloc::TryArc;

use crate::conn::io::FakeNet;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{
    DebugHandler, DebugKind, Handler, ProgressHandler, ProgressNow, ProgressVerdict, Read,
    ReadHandler, Rewind, RewindFailed, Write, WriteHandler,
};
use crate::id::ArenaPolicy;
use crate::multi::{Env, Multi, NoEvents, PauseRequest, TransferCx};
use crate::options::script::{Piece, Script};
use crate::options::{Progress, UploadSource};
use crate::time::ManualClock;

use super::{Readout, Upload};

fn multi() -> (Multi, ManualClock) {
    let clock = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock.clone())),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), clock)
}

fn script(pieces: Vec<Piece>) -> Easy {
    let mut e = Easy::new();
    e.options_mut().set_url(Some(b"script://a")).unwrap();
    e.options_mut().script = Some(Script::new(pieces).unwrap());
    e
}

fn result(m: &mut Multi) -> Option<Result<(), ErrorKind>> {
    m.info_read().map(|msg| msg.result)
}

/// What a feeder's handlers saw.
#[derive(Default)]
struct Seen {
    /// The room of each read call.
    reads: Mutex<Vec<usize>>,
    rewinds: Cell<u32>,
}

/// Gives `data`, in as much as each read has room for, then Eof; or what
/// `answer` says for the call numbered from 0. Its rewinder resets `at`.
struct Feeder {
    data: Vec<u8>,
    at: Arc<Cell<usize>>,
    seen: Arc<Seen>,
    answer: Box<dyn Fn(usize) -> Option<Read> + Send + Sync>,
}

impl ReadHandler for Feeder {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        let call = self.seen.reads.lock().unwrap().len();
        self.seen.reads.lock().unwrap().push(buf.len());
        if let Some(answer) = (self.answer)(call) {
            return answer;
        }
        let at = self.at.get();
        let n = (self.data.len() - at).min(buf.len());
        buf[..n].copy_from_slice(&self.data[at..at + n]);
        self.at.set(at + n);
        NonZeroUsize::new(n).map_or(Read::Eof, Read::Data)
    }
}

struct Rewinder {
    feeder_at: Arc<Cell<usize>>,
    seen: Arc<Seen>,
    ok: bool,
}

impl Rewind for Rewinder {
    fn rewind(&self, _: &mut TransferCx<'_>) -> Result<(), RewindFailed> {
        self.seen.rewinds.set(self.seen.rewinds.get() + 1);
        if self.ok {
            self.feeder_at.set(0);
            Ok(())
        } else {
            Err(RewindFailed)
        }
    }
}

/// `e` reads `data` through a feeder answering by `answer`, `size` known
/// or not, rewound as `rewind` says (None: no rewind handler).
fn fed(
    e: &mut Easy,
    data: &[u8],
    size: Option<u64>,
    rewind: Option<bool>,
    answer: impl Fn(usize) -> Option<Read> + Send + Sync + 'static,
) -> Arc<Seen> {
    let seen = Arc::new(Seen::default());
    let at = Arc::new(Cell::new(0));
    let feeder = Feeder {
        data: data.to_vec(),
        at: at.clone(),
        seen: seen.clone(),
        answer: Box::new(answer),
    };
    e.options_mut().upload = UploadSource::Read {
        handler: Handler::read(feeder).unwrap(),
        rewind: rewind.map(|ok| {
            Handler::rewind(Rewinder {
                feeder_at: at,
                seen: seen.clone(),
                ok,
            })
            .unwrap()
        }),
        size,
    };
    seen
}

fn plain(_: usize) -> Option<Read> {
    None
}

/// Records the bytes traced as sent.
#[derive(Clone, Default)]
struct Traced(Arc<Mutex<Vec<u8>>>);

impl DebugHandler for Traced {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::DataOut {
            self.0.lock().unwrap().extend_from_slice(data);
        }
    }
}

fn traced(e: &mut Easy) -> Traced {
    let t = Traced::default();
    e.options_mut().output.verbose = true;
    e.options_mut().callbacks.debug = Some(Handler::debug(t.clone()).unwrap());
    t
}

fn run(e: Easy) -> (Result<(), ErrorKind>, crate::report::Sizes) {
    let (mut m, _clock) = multi();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let r = result(&mut m).expect("over in one pass");
    (r, *m.easy(id).unwrap().report().sizes())
}

/// What a handler gives is sent and traced, its size announced, and a read
/// has room for no more than what is left of the size: the read that
/// completes it ends the body, without another call.
#[test]
fn a_known_size_bounds_the_reads_and_ends_the_body() {
    let mut e = script(vec![Piece::Send(20), Piece::Send(100), Piece::SendAll]);
    let seen = fed(&mut e, &[7; 30], Some(30), None, plain);
    let sent = traced(&mut e);
    let (r, sizes) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(
        *seen.reads.lock().unwrap(),
        [20, 10],
        "room for the rest, then no more"
    );
    assert_eq!(*sent.0.lock().unwrap(), [7; 30]);
    assert_eq!((sizes.upload(), sizes.upload_expected()), (30, Some(30)));
}

/// Without a size, the body ends when the handler says so.
#[test]
fn an_unknown_size_ends_at_the_handler_s_eof() {
    let mut e = script(vec![Piece::SendAll]);
    let seen = fed(&mut e, &[1; 40000], None, None, plain);
    let (r, sizes) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(*seen.reads.lock().unwrap(), [16384, 16384, 16384, 16384]);
    assert_eq!((sizes.upload(), sizes.upload_expected()), (40000, None));
}

/// An end short of the size is a read error; what came before was sent.
#[test]
fn an_end_short_of_the_size_is_a_read_error() {
    let mut e = script(vec![Piece::SendAll]);
    fed(&mut e, &[1; 10], Some(30), None, plain);
    let (r, sizes) = run(e);
    assert_eq!(r, Err(ErrorKind::ReadError));
    assert_eq!(sizes.upload(), 10);
}

/// A size of nothing is complete before any read.
#[test]
fn an_empty_size_never_calls_the_handler() {
    let mut e = script(vec![Piece::SendAll, Piece::Rewind]);
    let seen = fed(&mut e, b"", Some(0), Some(true), plain);
    let (r, sizes) = run(e);
    assert_eq!(r, Ok(()));
    assert!(seen.reads.lock().unwrap().is_empty());
    assert_eq!(seen.rewinds.get(), 0, "nothing to rewind");
    assert_eq!((sizes.upload(), sizes.upload_expected()), (0, Some(0)));
}

/// Shared bytes go out in pieces, the last one ending the body; with no
/// source the body is empty.
#[test]
fn bytes_and_no_source_send_what_they_hold() {
    let mut e = script(vec![Piece::Send(4), Piece::SendAll]);
    e.options_mut().upload = UploadSource::Bytes(TryArc::try_new(b"0123456789".to_vec()).unwrap());
    let sent = traced(&mut e);
    let (r, sizes) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(*sent.0.lock().unwrap(), b"0123456789");
    assert_eq!(sizes.upload_expected(), Some(10));
    let e = script(vec![Piece::SendAll]);
    let (r, sizes) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!((sizes.upload(), sizes.upload_expected()), (0, Some(0)));
}

/// The read that completes a known size ends the body itself.
#[test]
fn the_read_that_completes_the_size_ends_the_body() {
    let (mut m, _clock) = multi();
    let mut e = script(vec![]);
    fed(&mut e, &[1; 30], Some(30), None, plain);
    let source = e.options().upload.clone();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.with_step_cx(id, |cx| {
        let mut upload = Upload::new(&source);
        let mut buf = [0; 20];
        assert_eq!(
            upload.read(cx, &mut buf, true),
            Ok(Readout { n: 20, eos: false })
        );
        assert_eq!(
            upload.read(cx, &mut buf, true),
            Ok(Readout { n: 10, eos: true })
        );
    });
}

/// A handler that said it was done, aborted, or gave more than it had room
/// for is not called again: the same answer comes back.
#[test]
fn the_handler_s_end_and_failures_stick() {
    for (answer, want) in [
        (Read::Eof, Ok(Readout { n: 0, eos: true })),
        (Read::Abort, Err(ErrorKind::AbortedByCallback)),
        (Read::Fail, Err(ErrorKind::ReadError)),
        (
            Read::Data(NonZeroUsize::new(9).unwrap()),
            Err(ErrorKind::ReadError),
        ),
    ] {
        let (mut m, _clock) = multi();
        let mut e = script(vec![]);
        let seen = fed(&mut e, b"", None, None, move |_| Some(answer));
        let source = e.options().upload.clone();
        let id = m.add(e, (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        m.with_step_cx(id, |cx| {
            let mut upload = Upload::new(&source);
            let mut buf = [0; 8];
            assert_eq!(upload.read(cx, &mut buf, true), want, "{answer:?}");
            assert_eq!(upload.read(cx, &mut buf, true), want, "{answer:?} again");
        });
        assert_eq!(
            seen.reads.lock().unwrap().len(),
            1,
            "{answer:?}: called once"
        );
    }
}

/// An abort skips the last progress pass (`multi_done`), so the
/// transfer's total time is taken at its end alone
/// (`Curl_pgrsCompleted`): the time spent paused counts.
#[test]
fn an_aborting_read_is_timed_to_its_end() {
    let (mut m, clock) = multi();
    let mut e = script(vec![Piece::Send(5), Piece::SendAll]);
    fed(&mut e, b"hello", None, None, |n| {
        Some(if n == 0 { Read::Pause } else { Read::Abort })
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), None, "paused");
    clock.advance(Duration::from_millis(700));
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), Some(Err(ErrorKind::AbortedByCallback)));
    let total = m.easy(id).unwrap().report().timings().total();
    assert_eq!(total, Duration::from_millis(700));
}

/// A pause from the handler pauses sending: the piece waits, and plays
/// again, the same read, once unpaused. Where the protocol cannot pause,
/// it is a read error.
#[test]
fn a_pausing_handler_pauses_the_sending() {
    let (mut m, _clock) = multi();
    let mut e = script(vec![Piece::Send(5), Piece::SendAll]);
    let seen = fed(&mut e, b"hello", None, None, |n| {
        (n == 0).then_some(Read::Pause)
    });
    let sent = traced(&mut e);
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), None, "paused");
    assert_eq!(
        seen.reads.lock().unwrap().len(),
        1,
        "not asked while paused"
    );
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), Some(Ok(())));
    assert_eq!(*seen.reads.lock().unwrap(), [5, 5, 16384]);
    assert_eq!(*sent.0.lock().unwrap(), b"hello");

    let (mut m, _clock) = multi();
    let mut e = script(vec![]);
    fed(&mut e, b"", None, None, |_| Some(Read::Pause));
    let source = e.options().upload.clone();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    m.with_step_cx(id, |cx| {
        let mut upload = Upload::new(&source);
        assert_eq!(
            upload.read(cx, &mut [0; 4], false),
            Err(ErrorKind::ReadError)
        );
        assert!(!cx.pause().send_paused());
    });
}

/// A rewind starts the body over: shared bytes are given again, a handler
/// is rewound by its rewind handler, and called again after its end.
#[test]
fn a_rewind_sends_the_body_again() {
    let mut e = script(vec![Piece::SendAll, Piece::Rewind, Piece::SendAll]);
    e.options_mut().upload = UploadSource::Bytes(TryArc::try_new(b"abc".to_vec()).unwrap());
    let sent = traced(&mut e);
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(*sent.0.lock().unwrap(), b"abcabc");

    let mut e = script(vec![Piece::SendAll, Piece::Rewind, Piece::SendAll]);
    let seen = fed(&mut e, b"xyz", None, Some(true), plain);
    let sent = traced(&mut e);
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(*sent.0.lock().unwrap(), b"xyzxyz");
    assert_eq!(seen.rewinds.get(), 1);
    assert_eq!(seen.reads.lock().unwrap().len(), 4, "read to its end twice");
}

/// Fails to rewind, saying why.
struct Explains;

impl Rewind for Explains {
    fn rewind(&self, cx: &mut TransferCx<'_>) -> Result<(), RewindFailed> {
        cx.fail(b"seek callback returned error 1");
        Err(RewindFailed)
    }
}

/// Keeps the trace's text lines.
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<Vec<u8>>>>);

impl crate::handler::DebugHandler for Trace {
    fn debug(&self, _: &mut TransferCx<'_>, kind: crate::handler::DebugKind, data: &[u8]) {
        // Without the debug build's warning, which its first transfer
        // traces.
        let warning =
            data.starts_with(b"!!! WARNING") || data.starts_with(b"This is a debug build");
        if kind == crate::handler::DebugKind::Text && !warning {
            self.0.lock().unwrap().push(data.to_vec());
        }
    }
}

/// A rewind handler that says why it failed gives the transfer's reason
/// in place of the transfer's own, which is neither kept nor traced
/// (`cr_in_rewind`).
#[test]
fn a_rewind_handler_s_reason_is_the_transfer_s() {
    let reason = |explains: bool| {
        let mut e = script(vec![Piece::SendAll, Piece::Rewind]);
        fed(&mut e, b"x", None, Some(false), plain);
        let trace = Trace::default();
        e.options_mut().output.verbose = true;
        e.options_mut().callbacks.debug = Some(Handler::debug(trace.clone()).unwrap());
        if explains {
            let UploadSource::Read { rewind, .. } = &mut e.options_mut().upload else {
                unreachable!()
            };
            *rewind = Some(Handler::rewind(Explains).unwrap());
        }
        let (mut m, _clock) = multi();
        let id = m.add(e, (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(result(&mut m), Some(Err(ErrorKind::SendFailRewind)));
        let kept = m.easy(id).unwrap().report().failure().map(<[u8]>::to_vec);
        let traced = trace.0.lock().unwrap().clone();
        (kept, traced)
    };
    let mine = b"seek callback returned error 1";
    let closed = b"closing connection #0\n";
    assert_eq!(
        reason(true),
        (
            Some(mine.to_vec()),
            vec![[&mine[..], b"\n"].concat(), closed.to_vec()]
        )
    );
    let its = b"necessary data rewind was not possible";
    assert_eq!(
        reason(false),
        (
            Some(its.to_vec()),
            vec![[&its[..], b"\n"].concat(), closed.to_vec()]
        )
    );
}

/// A body not yet read needs no rewind; one read from needs a rewind
/// handler that works, even when the read only paused.
#[test]
fn a_rewind_needs_the_handler_s_rewind_once_read() {
    let mut e = script(vec![Piece::Rewind, Piece::SendAll]);
    let seen = fed(&mut e, b"x", None, Some(false), plain);
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(seen.rewinds.get(), 0, "never read: nothing to rewind");

    for rewind in [None, Some(false)] {
        let mut e = script(vec![Piece::SendAll, Piece::Rewind]);
        fed(&mut e, b"x", None, rewind, plain);
        assert_eq!(run(e).0, Err(ErrorKind::SendFailRewind), "{rewind:?}");
    }

    let (mut m, _clock) = multi();
    let mut e = script(vec![Piece::Send(1), Piece::Rewind]);
    let seen = fed(&mut e, b"x", None, Some(true), |n| {
        (n == 0).then_some(Read::Pause)
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    // Unpaused, the piece reads again and the rewind follows.
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), Some(Ok(())));
    assert_eq!(seen.rewinds.get(), 1);
}

/// A request with a body is sent once the body is: its POSTTRANSFER comes
/// then; one without, at once.
#[test]
fn a_request_with_a_body_is_sent_when_its_body_is() {
    let (mut m, clock) = multi();
    let mut e = script(vec![Piece::Send(1), Piece::Yield, Piece::SendAll]);
    fed(&mut e, b"ab", None, None, plain);
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_millis(20));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), Some(Ok(())));
    let t = *m.easy(id).unwrap().report().timings();
    assert_eq!(t.posttransfer(), Duration::from_millis(20));

    let (mut m, clock) = multi();
    let id = m
        .add(script(vec![Piece::Yield]), (), &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_millis(20));
    m.perform(&mut NoEvents).unwrap();
    let t = *m.easy(id).unwrap().report().timings();
    assert_eq!(t.posttransfer(), t.pretransfer());
}

/// Progress is told of what is sent, its size, and the upload speed.
#[test]
fn progress_counts_what_is_sent() {
    struct Last(Arc<Cell<Option<ProgressNow>>>);
    impl ProgressHandler for Last {
        fn progress(&self, _: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
            self.0.set(Some(now));
            ProgressVerdict::Continue
        }
    }
    let (mut m, clock) = multi();
    let mut e = script(vec![Piece::Send(500), Piece::Yield, Piece::Yield]);
    fed(&mut e, &[0; 800], Some(800), None, plain);
    let last = Arc::new(Cell::new(None));
    e.options_mut().progress = Progress::Handler(Handler::progress(Last(last.clone())).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_secs(1));
    m.perform(&mut NoEvents).unwrap();
    let now = last.get().unwrap();
    assert_eq!((now.uploaded, now.upload_total), (500, Some(800)));
    let report = m.easy(id).unwrap().report();
    assert_eq!(
        (report.speeds().upload(), report.speeds().download()),
        (500, 0)
    );
}

/// A pause blocks an upload only when it stops both ways the request
/// moves bytes, and receiving alone once the body is sent
/// (`Curl_xfer_is_blocked`): one that does not block runs it again.
#[test]
fn a_pause_blocks_an_upload_only_every_way_it_moves() {
    let (mut m, _clock) = multi();
    let mut e = script(vec![
        Piece::Send(4),
        Piece::Yield,
        Piece::SendAll,
        Piece::Yield,
    ]);
    fed(&mut e, &[1; 10], None, None, plain);
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let runs_again = |m: &Multi| m.timeout() == Some(Duration::ZERO);
    assert!(!runs_again(&m), "resting at the yield");
    m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
    assert!(runs_again(&m), "still sending");
    m.perform(&mut NoEvents).unwrap();
    m.pause(id, PauseRequest::ALL, &mut NoEvents).unwrap();
    assert!(!runs_again(&m), "both ways stopped");
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.easy(id).unwrap().report().sizes().upload(), 10, "sent");
    m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
    assert!(!runs_again(&m), "only receiving is left");
}

/// Pauses receiving at the first write.
struct PauseOnWrite;

impl WriteHandler for PauseOnWrite {
    fn write(&self, cx: &mut TransferCx<'_>, _: &[u8]) -> Write {
        cx.pause(cx.me(), PauseRequest::RECV).unwrap();
        Write::Accepted
    }
}

/// A pause from a handler is judged against the ways the request moves
/// bytes when it asks: a body sent earlier in the same step no longer
/// counts, so pausing receiving blocks the transfer.
#[test]
fn a_pause_in_the_step_that_sent_the_body_blocks() {
    let (mut m, _clock) = multi();
    let mut e = script(vec![
        Piece::SendAll,
        Piece::Body(b"x".to_vec()),
        Piece::Body(b"y".to_vec()),
    ]);
    e.options_mut().upload = UploadSource::Bytes(TryArc::try_new(b"ab".to_vec()).unwrap());
    e.options_mut().callbacks.write = Some(Handler::write(PauseOnWrite).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(m.easy(id).unwrap().report().sizes().upload(), 2, "sent");
    assert_ne!(
        m.timeout(),
        Some(Duration::ZERO),
        "blocked: nothing to run for"
    );
}

/// A handler pausing receiving while its request still sends does not
/// block it: the transfer runs again, though its step ended waiting.
#[test]
fn a_pause_in_a_step_still_sending_runs_it_again() {
    let (mut m, _clock) = multi();
    let mut e = script(vec![
        Piece::Body(b"x".to_vec()),
        Piece::Send(1),
        Piece::Yield,
        Piece::SendAll,
    ]);
    e.options_mut().upload = UploadSource::Bytes(TryArc::try_new(b"ab".to_vec()).unwrap());
    e.options_mut().callbacks.write = Some(Handler::write(PauseOnWrite).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(
        m.easy(id).unwrap().report().sizes().upload(),
        1,
        "at the yield"
    );
    assert_eq!(m.timeout(), Some(Duration::ZERO), "still sending");
}
