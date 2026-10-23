use std::num::NonZeroU64;
use std::time::Duration;

use super::*;
use crate::deliver::RecvPause;
use crate::options::ColdGroup as _;

fn at(us: u64) -> Instant {
    Instant::EPOCH.after(Duration::from_micros(us))
}

/// A bucket of `rate` a second, at most `burst` held, started at `now`
/// (`Curl_rlimit_init`).
fn bucket(rate: i64, burst: i64, now: Instant) -> Bucket {
    let mut b = Bucket::default();
    b.change(rate, burst);
    b.start(now, None);
    b
}

const START: u64 = 5_000_000;

/// C's unit test 3216, line for line. Blocking is a pause, which stops
/// the bucket from outside it; unblocking starts it over.
#[test]
fn unit3216() {
    // A limit that is no limit.
    let mut ts = at(START);
    let mut r = bucket(0, 0, ts);
    assert_eq!(r.avail(ts), i64::MAX, "inf");
    r.drain(1_000_000, ts);
    assert_eq!(r.avail(ts), i64::MAX, "drain keep inf");
    assert_eq!(r.wait_ms(ts), 0, "inf never waits");

    // 10 tokens a second.
    r = bucket(10, 0, ts);
    assert_eq!(r.avail(ts), 10, "initial 10");
    r.drain(5, ts);
    assert_eq!(r.avail(ts), 5, "drain to 5");
    r.drain(3, ts);
    assert_eq!(r.avail(ts), 2, "drain to 2");
    ts = ts.after(Duration::from_millis(1));
    r.drain(3, ts);
    assert_eq!(r.avail(ts), -1, "drain to -1");
    assert_eq!(r.wait_ms(ts), 1099, "wait 1099ms");
    ts = ts.after(Duration::from_millis(1));
    assert_eq!(r.wait_ms(ts), 1098, "wait 1098ms");
    ts = ts.after(Duration::from_secs(1));
    assert_eq!(r.avail(ts), 9, "10 inc per sec");
    ts = ts.after(Duration::from_secs(1));
    assert_eq!(r.avail(ts), 19, "10 inc per sec(2)");
    r.start(ts, None);
    assert_eq!(r.avail(ts), 10, "unblocked 10");

    // 10 tokens a second, at most 15 held.
    ts = at(START);
    r = bucket(10, 15, ts);
    assert_eq!(r.avail(ts), 10, "initial 10");
    r.drain(5, ts);
    assert_eq!(r.avail(ts), 5, "drain to 5");
    r.drain(3, ts);
    assert_eq!(r.avail(ts), 2, "drain to 2");
    r.drain(3, ts);
    assert_eq!(r.avail(ts), -1, "drain to -1");
    ts = ts.after(Duration::from_secs(1));
    assert_eq!(r.avail(ts), 9, "10 inc per sec");
    ts = ts.after(Duration::from_secs(1));
    assert_eq!(r.avail(ts), 15, "10/15 burst limit");
    ts = ts.after(Duration::from_secs(1));
    assert_eq!(r.avail(ts), 15, "10/15 burst limit(2)");
    r.drain(15, ts);
    assert_eq!(r.avail(ts), 0, "drain to 0");
    assert_eq!(r.wait_ms(ts), 1000, "wait 1 sec");
    ts = ts.after(Duration::from_millis(500));
    assert_eq!(r.avail(ts), 0, "0 after 0.5 sec");
    assert_eq!(r.wait_ms(ts), 500, "wait 0.5 sec");
    ts = ts.after(Duration::from_secs(1));
    assert_eq!(r.avail(ts), 10, "10 after 1.5 sec");
    assert_eq!(r.wait_ms(ts), 0, "wait 0");
    ts = ts.after(Duration::from_millis(500));
    assert_eq!(r.avail(ts), 15, "10 after 2 sec");
}

/// A known total makes the last step small: 1500 bytes at 1000 a
/// second go as 1485 in a step of 1485 ms, then the last 15 (values
/// from `rlimit_tune_steps`' arithmetic).
#[test]
fn a_known_total_spreads_over_longer_steps() {
    let ts = at(START);
    let mut r = bucket(1000, 32 * 1024, ts);
    r.start(ts, Some(1500));
    assert_eq!(r.step_us(), 1_485_000);
    assert_eq!(r.rate_per_step, 1485);
    assert_eq!(r.burst_per_step(), 32 * 1024 + 32 * 1024 * 485 / 1000);
    assert_eq!(r.avail(ts), 1485);
    r.drain(1485, ts);
    assert_eq!(r.wait_ms(ts), 1485);
    let later = ts.after(Duration::from_millis(1485));
    assert_eq!(r.avail(later), 1485);
}

/// Less than a step's worth: one step exactly as long as the bytes take.
#[test]
fn a_total_under_a_second_is_one_step() {
    let ts = at(START);
    let mut r = bucket(1000, 0, ts);
    // 500 bytes: 5 for the last step, 495 in 495 ms.
    r.start(ts, Some(500));
    assert_eq!(
        (r.step_us(), r.rate_per_step, r.tokens),
        (495_000, 495, 495)
    );
    // Too few to tune: 1 byte, or a step under 2 ms.
    r.start(ts, Some(1));
    assert_eq!((r.step_us(), r.rate_per_step), (1_000_000, 1000));
    r.start(ts, Some(2));
    assert_eq!((r.step_us(), r.rate_per_step), (1_000_000, 1000));
    // A big total keeps at most MIN_RATE for the last step.
    r.start(ts, Some(10_000_000));
    let main = 10_000_000 - MIN_RATE;
    let msteps = main * 1000 / 1000;
    let inc = (msteps % 1000) / (msteps / 1000);
    assert_eq!(r.step_us(), 1_000_000 + inc * 1000);
}

/// A rate set while the bucket is in use keeps its time and cuts its
/// tokens to the new rate (`Curl_rlimit_change`).
#[test]
fn a_new_rate_cuts_the_tokens() {
    let ts = at(START);
    let mut r = bucket(1000, 32 * 1024, ts);
    r.sync(NonZeroU64::new(100));
    assert_eq!((r.tokens, r.burst_per_step(), r.ts), (100, 32 * 1024, ts));
    r.sync(NonZeroU64::new(100_000));
    assert_eq!((r.tokens, r.burst_per_step()), (100, 100_000));
    r.sync(None);
    assert!(!r.active());
}

/// A bucket never started fills to its burst at its first use, as C's
/// zeroed one, dated to the clock's origin, does.
#[test]
fn a_bucket_never_started_has_its_burst() {
    let mut r = Bucket::default();
    r.sync(NonZeroU64::new(10));
    assert_eq!(r.avail(at(START)), 32 * 1024);
    assert_eq!(r.next_step_ms(at(START)), 1000);
    let mut never = Bucket::default();
    never.sync(NonZeroU64::new(10));
    assert_eq!(never.next_step_ms(at(START)), 0);
}

fn limits(recv: u64, send: u64) -> Flow {
    Flow {
        max_recv_speed: NonZeroU64::new(recv),
        max_send_speed: NonZeroU64::new(send),
        ..Flow::NONE
    }
}

/// The longer wait of the two directions, or the sooner next step.
#[test]
fn the_verdict_weighs_both_directions() {
    let l = limits(1000, 2000);
    let ts = at(START);
    let mut r = RateLimits::default();
    let run = Pause::default();
    r.start(Way::Recv, &l, ts, None);
    r.start(Way::Send, &l, ts.after(Duration::from_millis(300)), None);
    let now = ts.after(Duration::from_millis(400));
    assert_eq!(
        r.verdict(&l, run, now),
        Verdict::Go(Some(Duration::from_millis(600)))
    );
    r.drain(Way::Recv, &l, run, 1000, now);
    assert_eq!(
        r.verdict(&l, run, now),
        Verdict::Wait(Duration::from_millis(600))
    );
    r.drain(Way::Send, &l, run, 4000, now);
    // A debt of a whole rate waits a step more: 900 + 1000 ms.
    assert_eq!(
        r.verdict(&l, run, now),
        Verdict::Wait(Duration::from_millis(1900))
    );
}

/// A paused direction has nothing to spend, spends nothing and waits
/// for nothing; going on, it starts over.
#[test]
fn a_pause_stops_the_bucket() {
    let l = limits(1000, 0);
    let ts = at(START);
    let mut r = RateLimits::default();
    r.start(Way::Recv, &l, ts, None);
    let mut paused = Pause::default();
    paused.recv = RecvPause::Stopped;
    assert_eq!(r.allowance(Way::Recv, &l, paused, ts), Some(0));
    assert_eq!(r.allowance(Way::Send, &l, paused, ts), None);
    r.drain(Way::Recv, &l, paused, 5000, ts);
    assert_eq!(r.verdict(&l, paused, ts), Verdict::Go(None));
    let run = Pause::default();
    assert_eq!(r.allowance(Way::Recv, &l, run, ts), Some(1000));
    // Time paused earns nothing.
    let later = ts.after(Duration::from_secs(5));
    r.drain(Way::Recv, &l, run, 1000, ts);
    r.start(Way::Recv, &l, later, None);
    assert_eq!(r.allowance(Way::Recv, &l, run, later), Some(1000));
}

/// Every whole step since the last update earns its tokens at once,
/// with no burst to cap them; the rest of a step is kept, and the wait
/// for the next tokens is what is left of it.
#[test]
fn whole_steps_earn_their_tokens() {
    let mut ts = at(START);
    let mut r = bucket(10, 0, ts);
    r.drain(10, ts);
    ts = ts.after(Duration::from_millis(3500));
    assert_eq!(r.avail(ts), 30);
    r.drain(30, ts);
    assert_eq!(r.wait_ms(ts), 500, "the half step left");
    ts = ts.after(Duration::from_millis(500));
    assert_eq!(r.avail(ts), 10);
}

/// Tokens earned saturate at `i64::MAX`, the gain and the sum each, as
/// C guards them (`rlimit_update`): only a gain past it is cut.
#[test]
fn earned_tokens_saturate() {
    let mut ts = at(START);
    // Two steps of half the most: one short of it, added to a debt.
    let half = i64::MAX / 2;
    let mut r = bucket(half, 0, ts);
    r.drain(usize::MAX, ts);
    assert_eq!(r.avail(ts), half - i64::MAX);
    ts = ts.after(Duration::from_secs(2));
    assert_eq!(r.avail(ts), half - i64::MAX + 2 * half);
    // Never updated, a bucket is filled to the most; then it earns
    // again what it spends.
    let mut r = Bucket::default();
    r.change(2, 0);
    assert_eq!(r.avail(ts), i64::MAX);
    r.drain(10, ts);
    ts = ts.after(Duration::from_secs(1));
    assert_eq!(r.avail(ts), i64::MAX - 8);
}

/// The tuning of the steps for a known total (`rlimit_tune_steps`): a
/// rest that takes 2 ms is one short step; one that takes a second
/// exactly is left as it is; one that takes 1.5 s is one step 1.5 s long
/// with half as many tokens again; a total past what C can multiply is
/// not tuned.
#[test]
fn steps_are_tuned_for_a_known_total() {
    let ts = at(START);
    let tuned = |rate: i64, total: u64| {
        let mut r = Bucket::default();
        r.change(rate, 0);
        r.start(ts, Some(total));
        (r.next_step_ms(ts), r.avail(ts))
    };
    // 2 tokens for the rest at 1000 a second, 1 for the last.
    assert_eq!(tuned(1000, 3), (2, 2));
    // 100051 for the rest at 100000 a second, 1010 for the last.
    assert_eq!(tuned(100_000, 101_061), (1000, 100_000));
    let most = (i64::MAX / 1000) as u64;
    assert_eq!(
        tuned(6_148_914_691_233_786, most),
        (1500, 6_148_914_691_233_786 + 3_074_457_345_616_893)
    );
    assert_eq!(tuned(1000, most + 1), (1000, 1000));
    assert_eq!(tuned(1000, i64::MAX as u64), (1000, 1000));
}
