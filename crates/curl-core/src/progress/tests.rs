use std::cell::RefCell;
use std::num::{NonZeroU16, NonZeroU64};
use std::rc::Rc;
use std::time::Duration;

use crate::conn::io::FakeNet;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{
    Handler, ProgressHandler, ProgressNow, ProgressVerdict, TextSink, Write, WriteHandler,
};
use crate::id::ArenaPolicy;
use crate::multi::{Env, Multi, NoEvents, PauseRequest, TransferCx, TransferId};
use crate::options::script::{Piece, Script};
use crate::options::{LowSpeed, Progress};
use crate::report::Speeds;
use crate::time::{Instant, ManualClock};

use super::c_tests::{MAX6OUT, TIME2STR, UNIT1606};
use super::meter::{self, Dir, Reading};
use super::{SECOND_US, Speedometer};

fn render(f: impl FnOnce(&mut String) -> std::fmt::Result) -> String {
    let mut s = String::new();
    f(&mut s).unwrap();
    s
}

/// unit1606: the low-speed check, a second a step, with the speed falling
/// by `dec` each second, times out at the second it should.
#[test]
fn the_speed_check_times_out_as_unit1606_says() {
    for case in UNIT1606 {
        let low = LowSpeed {
            limit: NonZeroU64::new(case.limit).unwrap(),
            time: NonZeroU16::new(case.time).unwrap(),
        };
        let mut s = Speedometer::default();
        let mut speed = case.speed;
        let mut second = 1;
        loop {
            s.current = speed;
            let now = Instant::EPOCH.after(Duration::from_secs(second));
            if s.speed_check(low, now).is_err() {
                break;
            }
            second += 1;
            speed -= case.dec;
            if second >= 100 {
                break;
            }
        }
        assert_eq!(second - 1, case.last_second, "{}", case.comment);
    }
}

/// test1636: durations in seven columns, byte counts in six.
#[test]
fn the_meter_shows_numbers_as_test1636_says() {
    for &(secs, text) in TIME2STR {
        assert_eq!(render(|s| meter::time2str(secs, s)), text, "{secs} s");
        assert_eq!(text.len(), 7, "{secs} s");
    }
    for &(bytes, text) in MAX6OUT {
        assert_eq!(render(|s| meter::max6out(bytes, s)), text, "{bytes} bytes");
        assert_eq!(text.len(), 6, "{bytes} bytes");
    }
}

/// The first count with a unit.
#[test]
fn a_count_of_100000_has_a_unit() {
    assert_eq!(render(|s| meter::max6out(99999, s)), " 99999");
    assert_eq!(render(|s| meter::max6out(100000, s)), "97.65k");
}

/// Past what test1636 reaches: an unsigned count never runs out of units.
#[test]
fn the_largest_byte_count_fits_six_columns() {
    assert_eq!(render(|s| meter::max6out(u64::MAX, s)), "15.99E");
}

/// Stock is taken every pass; the progress is shown at the first pass,
/// then once a second.
#[test]
fn progress_is_shown_once_a_second() {
    let mut s = Speedometer::default();
    let mut speeds = Speeds::default();
    assert!(s.take_stock(1000, 100, false, &mut speeds));
    assert_eq!(speeds.download(), 100_000, "the average so far");
    assert_eq!(s.current, 100_000, "the average, to start with");
    assert!(!s.take_stock(SECOND_US / 2, 200, false, &mut speeds));
    assert_eq!(speeds.download(), 400, "averages are taken every pass");
    // A second after the first record, 1000 more bytes: one a second.
    assert!(s.take_stock(1000 + SECOND_US, 1100, false, &mut speeds));
    assert_eq!(s.current, 1000);
}

/// The current speed spans the records of the last five seconds: checked
/// second by second against every record kept in a list.
#[test]
fn the_current_speed_spans_five_seconds_of_records() {
    let mut s = Speedometer::default();
    let mut speeds = Speeds::default();
    let mut all: Vec<(u64, u64)> = Vec::new();
    for sec in 0..20u64 {
        let at = 1000 + sec * SECOND_US;
        let amount = sec * 1000 + sec * sec * 37;
        s.take_stock(at, amount, false, &mut speeds);
        all.push((amount, at));
        let latest = all[all.len() - 1];
        let oldest = all[all.len().saturating_sub(6)];
        let expected = if all.len() == 1 {
            amount * 1_000_000 / at
        } else {
            (latest.0 - oldest.0) * 1_000_000 / (latest.1 - oldest.1)
        };
        assert_eq!(s.current, expected, "second {sec}");
    }
}

/// A request that is done shows its progress at once, and the next
/// showing waits a second from then, even with a new record.
#[test]
fn a_done_request_shows_its_progress_at_once() {
    let mut s = Speedometer::default();
    let mut speeds = Speeds::default();
    s.take_stock(0, 1000, false, &mut speeds);
    assert!(s.take_stock(SECOND_US / 2, 1000, true, &mut speeds));
    assert!(!s.take_stock(SECOND_US + 1, 2000, false, &mut speeds));
    assert!(s.take_stock(SECOND_US * 2 + 1, 3000, false, &mut speeds));
}

/// A finished request without a speed takes its last record from the end;
/// one with a speed keeps it.
#[test]
fn the_end_keeps_the_speed_it_had() {
    let mut s = Speedometer::default();
    let mut speeds = Speeds::default();
    s.take_stock(0, 0, false, &mut speeds);
    s.take_stock(SECOND_US, 0, false, &mut speeds);
    assert_eq!(s.current, 0);
    s.take_stock(SECOND_US * 3 / 2, 600, true, &mut speeds);
    assert_eq!(s.current, 400, "600 bytes in a second and a half");
    s.take_stock(SECOND_US * 7 / 4, 900, true, &mut speeds);
    assert_eq!(s.current, 400, "kept");
}

/// A known size with no speed yet estimates nothing; a share of a size
/// over 10000 is counted in its hundredths, as C does.
#[test]
fn the_meter_estimates_only_with_a_speed() {
    let line = |total, cur, speed| {
        let r = Reading {
            spent_us: 0,
            download: Dir {
                total: Some(total),
                cur,
                speed,
            },
            upload: Dir {
                total: None,
                cur: 0,
                speed: 0,
            },
            current_speed: 0,
        };
        render(|s| meter::line(&r, s))
    };
    let blank = " ".repeat(7);
    assert_eq!(
        line(10050, 10049, 0),
        format!("\r100  10050   0  10049   0      0      0      0 {blank} {blank} {blank}      0")
    );
    assert_eq!(
        line(10050, 10049, 1),
        format!("\r100  10050 100  10049   0      0      1      0 2:47:30 {blank} 2:47:30      0")
    );
    assert!(line(10000, 9999, 1).starts_with("\r 99  10000  99"));
}

#[test]
fn the_meter_line_shows_both_directions_and_the_time_left() {
    let r = Reading {
        spent_us: 3 * SECOND_US + 500_000,
        download: Dir {
            total: Some(200_000),
            cur: 50_000,
            speed: 10_000,
        },
        upload: Dir {
            total: None,
            cur: 0,
            speed: 0,
        },
        current_speed: 12_345,
    };
    assert_eq!(
        render(|s| meter::line(&r, s)),
        "\r 25 195.3k  25  50000   0      0  10000      0   00:20   00:03   00:17  12345"
    );
}

// The engine's calls.

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

fn body(n: usize) -> Piece {
    Piece::Body(vec![b'x'; n])
}

/// Every call a progress handler saw: what it was told, the total time
/// and download speed its report gave then, and its answer.
type Calls = Rc<RefCell<Vec<(ProgressNow, Duration, u64)>>>;

struct Recorder<F> {
    calls: Calls,
    answer: F,
}

impl<F: Fn(&mut TransferCx<'_>, usize) -> ProgressVerdict> ProgressHandler for Recorder<F> {
    fn progress(&self, cx: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
        let me = cx.me();
        let report = cx.info(me).unwrap();
        let seen = (now, report.timings().total(), report.speeds().download());
        let n = self.calls.borrow().len();
        self.calls.borrow_mut().push(seen);
        (self.answer)(cx, n)
    }
}

fn recorded<F>(e: &mut Easy, answer: F) -> Calls
where
    F: Fn(&mut TransferCx<'_>, usize) -> ProgressVerdict + 'static,
{
    let calls = Calls::default();
    let h = Recorder {
        calls: calls.clone(),
        answer,
    };
    e.options_mut().progress = Progress::Handler(Handler::progress(h).unwrap());
    calls
}

fn go(_: &mut TransferCx<'_>, _: usize) -> ProgressVerdict {
    ProgressVerdict::Continue
}

fn result(m: &mut Multi) -> Option<Result<(), ErrorKind>> {
    m.info_read().map(|msg| msg.result)
}

/// The handler is called after every step that holds a connection, after
/// every receive pass, and once more at the end; it sees the sizes as they
/// stand, the time so far and the average speed.
#[test]
fn the_handler_is_called_at_each_pass_and_at_the_end() {
    let (mut m, clock) = multi();
    let mut e = script(vec![Piece::Size(1000), body(400), Piece::Yield, body(600)]);
    let calls = recorded(&mut e, go);
    m.add(e, (), &mut NoEvents).unwrap();
    clock.advance(Duration::from_millis(1));
    m.perform(&mut NoEvents).unwrap();
    let known = |n| ProgressNow {
        download_total: Some(1000),
        downloaded: n,
        upload_total: None,
        uploaded: 0,
    };
    let unknown = ProgressNow {
        download_total: None,
        ..known(0)
    };
    let seen: Vec<_> = calls.borrow().iter().map(|c| c.0).collect();
    // After the setup step; after the receive pass, and after its step.
    assert_eq!(seen, [unknown, known(400), known(400)]);
    clock.advance(Duration::from_millis(500));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), Some(Ok(())));
    let seen: Vec<_> = calls.borrow().iter().skip(3).map(|c| c.0).collect();
    // The receive pass that ended the request, its step, and the end.
    assert_eq!(seen, [known(1000); 3]);
    let last = calls.borrow()[5];
    // It started at the first perform.
    assert_eq!(last.1, Duration::from_millis(500), "the total so far");
    assert_eq!(last.2, 2000);
}

/// Without progress, no handler is called, but the report still has the
/// total and the speeds.
#[test]
fn progress_off_calls_nothing_but_takes_stock() {
    let (mut m, clock) = multi();
    let mut e = script(vec![body(100), Piece::Yield, Piece::Yield]);
    let calls = recorded(&mut e, go);
    let sink = metered(&mut e);
    e.options_mut().progress = Progress::Off;
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_millis(10));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), None, "still going");
    assert!(calls.borrow().is_empty());
    assert_eq!(text(&sink), "", "no meter either");
    let report = m.easy(id).unwrap().report();
    assert_eq!(report.timings().total(), Duration::from_millis(10));
    assert_eq!(report.speeds().download(), 10_000);
}

/// An abort from the handler fails the transfer, and no last call follows.
#[test]
fn an_abort_fails_the_transfer_with_no_last_call() {
    for abort_at in 0..3 {
        let (mut m, _clock) = multi();
        let mut e = script(vec![body(100), Piece::Yield, body(100)]);
        let calls = recorded(&mut e, move |_, n| {
            if n == abort_at {
                ProgressVerdict::Abort
            } else {
                ProgressVerdict::Continue
            }
        });
        m.add(e, (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(
            result(&mut m),
            Some(Err(ErrorKind::AbortedByCallback)),
            "abort at {abort_at}"
        );
        assert_eq!(calls.borrow().len(), abort_at + 1, "abort at {abort_at}");
    }
}

/// A request that ended well fails with an abort after it: from its
/// step's pass (with no last call) or from the last call.
#[test]
fn an_abort_after_the_request_fails_the_transfer() {
    for (abort_at, calls_made) in [(2, 3), (3, 4)] {
        let (mut m, _clock) = multi();
        let mut e = script(vec![body(100)]);
        let calls = recorded(&mut e, move |_, n| {
            if n == abort_at {
                ProgressVerdict::Abort
            } else {
                ProgressVerdict::Continue
            }
        });
        m.add(e, (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(
            result(&mut m),
            Some(Err(ErrorKind::AbortedByCallback)),
            "abort at {abort_at}"
        );
        assert_eq!(calls.borrow().len(), calls_made, "abort at {abort_at}");
    }
}

/// What the meter wrote.
#[derive(Clone, Default)]
struct Sink(Rc<RefCell<Vec<u8>>>);

impl TextSink for Sink {
    fn write(&self, text: &[u8]) {
        self.0.borrow_mut().extend_from_slice(text);
    }
}

fn metered(e: &mut Easy) -> Sink {
    let sink = Sink::default();
    e.options_mut().progress = Progress::Meter;
    e.options_mut().callbacks.stderr = Some(Handler::text(sink.clone()).unwrap());
    sink
}

fn text(sink: &Sink) -> String {
    String::from_utf8(sink.0.borrow().clone()).unwrap()
}

/// The meter: titles once per handle, a line at the first pass and once a
/// second, and at the end, which ends the line.
#[test]
fn the_meter_draws_once_a_second_and_ends_its_line() {
    let (mut m, clock) = multi();
    let mut e = script(vec![
        Piece::Size(3000),
        body(1000),
        Piece::Yield,
        body(1000),
        Piece::Yield,
        body(1000),
    ]);
    let sink = metered(&mut e);
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let first = text(&sink);
    assert_eq!(first.matches('\r').count(), 1, "{first:?}");
    assert!(first.starts_with(meter::HEADER), "{first:?}");
    clock.advance(Duration::from_millis(500));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(text(&sink), first, "not a second yet");
    clock.advance(Duration::from_millis(500));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), Some(Ok(())));
    let all = text(&sink);
    let lines: Vec<_> = all[meter::HEADER.len()..].split('\r').skip(1).collect();
    let start = format!(
        "  0      0   0      0   0      0      0      0 {0} {0} {0}      0",
        " ".repeat(7)
    );
    let end = "100   3000 100   3000   0      0   3000      0   00:01   00:01           3000";
    // At the end: the receive pass, its step, and the last call, which
    // ends the line.
    assert_eq!(lines, [start, end.into(), end.into(), format!("{end}\n")]);
    // The same handle, run again: no titles.
    let mut e = m.remove(id, &mut NoEvents).unwrap().easy;
    e.options_mut().script = Some(Script::new(vec![body(1)]).unwrap());
    m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(text(&sink).matches(meter::HEADER).count(), 1);
}

/// A handler asking for the meter gets it, but the line is not ended: the
/// application owns the output.
#[test]
fn a_handler_may_ask_for_the_meter() {
    let (mut m, _clock) = multi();
    let mut e = script(vec![body(10)]);
    let sink = metered(&mut e);
    recorded(&mut e, |_, _| ProgressVerdict::ContinueWithMeter);
    m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let all = text(&sink);
    assert!(all.starts_with(meter::HEADER), "{all:?}");
    assert!(!all.ends_with('\n'), "{all:?}");
}

fn slow(limit: u64, secs: u16) -> Option<LowSpeed> {
    Some(LowSpeed {
        limit: NonZeroU64::new(limit).unwrap(),
        time: NonZeroU16::new(secs).unwrap(),
    })
}

/// A transfer slower than the limit for its whole time fails; the check
/// wakes it every second to look.
#[test]
fn a_transfer_too_slow_for_too_long_times_out() {
    let (mut m, clock) = multi();
    let mut e = script(vec![
        body(10),
        Piece::Yield,
        Piece::Yield,
        Piece::Yield,
        Piece::Yield,
    ]);
    e.options_mut().limits.low_speed = slow(1000, 2);
    m.add(e, (), &mut NoEvents).unwrap();
    let mut ended = None;
    for second in 0..10 {
        m.perform(&mut NoEvents).unwrap();
        if let Some(r) = result(&mut m) {
            ended = Some((second, r));
            break;
        }
        assert_eq!(m.timeout(), Some(Duration::from_secs(1)), "second {second}");
        clock.advance(Duration::from_secs(1));
    }
    assert_eq!(ended, Some((2, Err(ErrorKind::OperationTimedout))));
}

/// Fast enough, no matter how long: the check passes.
#[test]
fn a_transfer_fast_enough_is_not_stopped() {
    let (mut m, clock) = multi();
    let mut pieces = vec![];
    for _ in 0..5 {
        pieces.push(body(2000));
        pieces.push(Piece::Yield);
    }
    let mut e = script(pieces);
    e.options_mut().limits.low_speed = slow(1000, 2);
    m.add(e, (), &mut NoEvents).unwrap();
    for _ in 0..6 {
        m.perform(&mut NoEvents).unwrap();
        clock.advance(Duration::from_secs(1));
    }
    assert_eq!(result(&mut m), Some(Ok(())));
}

struct Pausing;

impl WriteHandler for Pausing {
    fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
        Write::Pause
    }
}

/// A paused transfer is not judged on its speed, and an unpause starts the
/// measure over.
#[test]
fn a_paused_transfer_is_not_too_slow() {
    let (mut m, clock) = multi();
    let mut e = script(vec![
        body(10),
        Piece::Yield,
        Piece::Yield,
        Piece::Yield,
        Piece::Yield,
    ]);
    e.options_mut().limits.low_speed = slow(1000, 2);
    e.options_mut().callbacks.write = Some(Handler::write(Pausing).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    for _ in 0..5 {
        m.perform(&mut NoEvents).unwrap();
        clock.advance(Duration::from_secs(1));
    }
    assert_eq!(result(&mut m), None, "held, never slow");
    m.easy_mut(id).unwrap().options_mut().callbacks.write = None;
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), None, "measured from the unpause");
    clock.advance(Duration::from_secs(1));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), None);
    clock.advance(Duration::from_secs(1));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), Some(Err(ErrorKind::OperationTimedout)));
}

/// Held output a progress handler unpauses is replayed when it returns,
/// in the same step.
#[test]
fn an_unpause_from_the_progress_handler_replays_at_once() {
    let (mut m, _clock) = multi();
    let mut e = script(vec![body(10), Piece::Yield]);
    let written = Rc::new(RefCell::new(Vec::new()));
    struct Once(Rc<RefCell<Vec<usize>>>);
    impl WriteHandler for Once {
        fn write(&self, _: &mut TransferCx<'_>, b: &[u8]) -> Write {
            let first = self.0.borrow().is_empty();
            self.0.borrow_mut().push(b.len());
            if first { Write::Pause } else { Write::Accepted }
        }
    }
    e.options_mut().callbacks.write = Some(Handler::write(Once(written.clone())).unwrap());
    let calls = recorded(&mut e, |cx, _| {
        let me: TransferId = cx.me();
        cx.pause(me, PauseRequest::CONT).unwrap();
        ProgressVerdict::Continue
    });
    m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(*written.borrow(), [10, 10], "paused, then replayed");
    assert_eq!(calls.borrow().len(), 3);
}

/// A speed back over the limit starts the low-speed time over.
#[test]
fn a_speed_back_over_the_limit_starts_the_time_over() {
    let low = slow(1000, 2).unwrap();
    let mut s = Speedometer::default();
    let at = |sec| Instant::EPOCH.after(Duration::from_secs(sec));
    for (sec, speed) in [(1, 10), (2, 10), (3, 5000), (4, 10), (5, 10)] {
        s.current = speed;
        assert_eq!(s.speed_check(low, at(sec)), Ok(()), "second {sec}");
    }
    s.current = 10;
    assert_eq!(s.speed_check(low, at(6)), Err(ErrorKind::OperationTimedout));
}

/// An unpause, even of a transfer not paused, forgets how long it has
/// been slow (`curl_easy_pause` resets `keeps_speed`).
#[test]
fn an_unpause_forgets_the_slow_time() {
    let (mut m, clock) = multi();
    let mut pieces = vec![body(10)];
    pieces.extend((0..8).map(|_| Piece::Yield));
    let mut e = script(pieces);
    e.options_mut().limits.low_speed = slow(1000, 2);
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_secs(1));
    m.perform(&mut NoEvents).unwrap();
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    clock.advance(Duration::from_secs(1));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), None, "slow since the unpause only");
    clock.advance(Duration::from_secs(1));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), None);
    clock.advance(Duration::from_secs(1));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), Some(Err(ErrorKind::OperationTimedout)));
}

/// A transfer cut short gets its last call, but the meter is drawn only if
/// a second has passed: the request is not done.
#[test]
fn a_transfer_cut_short_ends_the_meter_without_drawing_it() {
    let (mut m, clock) = multi();
    let mut e = script(vec![body(10), Piece::Yield, Piece::Yield]);
    e.options_mut().limits.total = crate::time::TimeLimit::from_millis(500);
    let sink = metered(&mut e);
    m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let first = text(&sink);
    clock.advance(Duration::from_millis(600));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(result(&mut m), Some(Err(ErrorKind::OperationTimedout)));
    assert_eq!(text(&sink), format!("{first}\n"));
}

/// The second a transfer slow from its second second times out, with
/// `act` done to it two and a half seconds in: 10000 bytes at once, then
/// nothing, against a limit of 1000 a second for 3 seconds.
fn slow_until(act: impl FnOnce(&mut Multi, TransferId)) -> Option<u64> {
    let (mut m, clock) = multi();
    let mut pieces = vec![body(10000)];
    pieces.extend((0..20).map(|_| Piece::Yield));
    let mut e = script(pieces);
    e.options_mut().limits.low_speed = slow(1000, 3);
    let id = m.add(e, (), &mut NoEvents).unwrap();
    let mut act = Some(act);
    for second in 0..15 {
        m.perform(&mut NoEvents).unwrap();
        if let Some(r) = result(&mut m) {
            assert_eq!(r, Err(ErrorKind::OperationTimedout));
            return Some(second);
        }
        if second == 2 {
            clock.advance(Duration::from_millis(500));
            (act.take().unwrap())(&mut m, id);
            clock.advance(Duration::from_millis(500));
        } else {
            clock.advance(Duration::from_secs(1));
        }
    }
    None
}

/// The first second's 10000 bytes keep the five-second window fast until
/// it slides past them, at six seconds: three more and it times out. An
/// unpause of a paused direction starts the records over at two and a
/// half, so the window slides past them at four. An unpause of a transfer
/// not paused leaves the records as they are.
#[test]
fn an_unpause_measures_the_speed_afresh() {
    assert_eq!(slow_until(|_, _| {}), Some(9));
    let unpause = |req| {
        move |m: &mut Multi, id| {
            m.pause(id, req, &mut NoEvents).unwrap();
            m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
        }
    };
    assert_eq!(
        slow_until(unpause(PauseRequest::RECV)),
        Some(7),
        "receiving"
    );
    assert_eq!(slow_until(unpause(PauseRequest::SEND)), Some(7), "sending");
    assert_eq!(
        slow_until(unpause(PauseRequest::CONT)),
        Some(9),
        "not paused"
    );
}

/// A transfer paused for sending is not judged on its speed either.
#[test]
fn a_send_paused_transfer_is_not_too_slow() {
    let paused = slow_until(|m, id| m.pause(id, PauseRequest::SEND, &mut NoEvents).unwrap());
    assert_eq!(paused, None);
}
