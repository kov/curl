//! The speed limits on a transfer's receiving and sending
//! (`CURLOPT_MAX_RECV_SPEED_LARGE`, `CURLOPT_MAX_SEND_SPEED_LARGE`): a
//! token bucket for each direction (`lib/ratelimit.c`).
//!
//! A bucket gives its rate's worth of tokens each step, a second unless
//! tuned, and a byte moved takes one. It holds no more than its burst,
//! so a transfer idle for a while does not rush. A pause is C's
//! `blocked`: it is the transfer's `Pause`, read here, and not kept a
//! second time in the bucket.

use std::num::NonZeroU64;
use std::time::Duration;

use crate::deliver::Pause;
use crate::options::Flow;
use crate::time::Instant;

const US_PER_SEC: i64 = 1_000_000;
/// The most tokens a tuned bucket keeps for its last step
/// (`CURL_RLIMIT_MIN_RATE`).
const MIN_RATE: i64 = 4 * 1024;
/// A tuned step is no shorter (`CURL_RLIMIT_STEP_MIN_MS`).
const STEP_MIN_MS: i64 = 2;
/// The least burst a limit has, as some protocols read and write in
/// batches (setopt.c).
const MIN_BURST: u64 = 32 * 1024;

/// One direction's bucket (`struct Curl_rlimit`, but for `blocked`).
/// Every transfer carries two, so it is kept small: the step's burst is
/// worked out from the second's and the step's length, as C's tuning
/// makes it, and the time of no update yet is a sentinel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bucket {
    /// Tokens a second; 0 for no limit.
    rate_per_sec: i64,
    /// The most tokens held, a second's worth; 0 for no cap.
    burst_per_sec: i64,
    rate_per_step: i64,
    /// Tokens left, negative when more was taken than there was.
    tokens: i64,
    /// The last update; `never()` before the first. C's bucket starts
    /// zeroed, its time at the monotonic clock's origin, long enough ago
    /// that the first update fills it to its burst. Its first step then
    /// ends at the clock's next whole second; here it is a whole step
    /// (DIVERGENCE.md).
    ts: Instant,
    /// A step's length: a second, or as tuned, under 2 s.
    step_us: u32,
    /// Time since the last update that earned no token yet, under a step.
    spare_us: u32,
}

/// The time of a bucket never updated.
fn never() -> Instant {
    Instant::EPOCH.after(Duration::MAX)
}

impl Default for Bucket {
    fn default() -> Bucket {
        Bucket {
            rate_per_sec: 0,
            burst_per_sec: 0,
            rate_per_step: 0,
            tokens: 0,
            ts: never(),
            step_us: US_PER_SEC as u32,
            spare_us: 0,
        }
    }
}

/// Microseconds from `earlier` to `now`, saturating.
fn micros_since(now: Instant, earlier: Instant) -> i64 {
    i64::try_from(now.since(earlier).as_micros()).unwrap_or(i64::MAX)
}

impl Bucket {
    fn step_us(&self) -> i64 {
        i64::from(self.step_us)
    }

    fn spare_us(&self) -> i64 {
        i64::from(self.spare_us)
    }

    /// The most tokens held in a step: the second's, grown with a step
    /// tuned longer by as many thousandths (`rlimit_tune_steps`).
    fn burst_per_step(&self) -> i64 {
        let longer_ms = (self.step_us() - US_PER_SEC).max(0) / 1000;
        self.burst_per_sec + self.burst_per_sec * longer_ms / 1000
    }

    /// Earn the tokens of the whole steps since the last update
    /// (`rlimit_update`).
    fn update(&mut self, now: Instant) {
        debug_assert!(self.rate_per_step != 0, "only a limit is updated");
        let elapsed_steps = if self.ts == never() {
            self.spare_us = 0;
            i64::MAX
        } else if self.ts == now {
            return;
        } else {
            let elapsed_us = micros_since(now, self.ts).saturating_add(self.spare_us());
            if elapsed_us < self.step_us() {
                return;
            }
            self.spare_us = u32::try_from(elapsed_us % self.step_us()).expect("under a step");
            elapsed_us / self.step_us()
        };
        self.ts = now;
        let gain = if self.rate_per_step > i64::MAX / elapsed_steps {
            i64::MAX
        } else {
            self.rate_per_step * elapsed_steps
        };
        self.tokens = if i64::MAX - gain > self.tokens {
            self.tokens + gain
        } else {
            i64::MAX
        };
        let burst = self.burst_per_step();
        if burst != 0 && self.tokens > burst {
            self.tokens = burst;
        }
    }

    /// Make the last step small when the total to move is known: a
    /// hundredth of it, at least one token and at most `MIN_RATE`, with
    /// the steps before it lengthened to give the rest at the rate
    /// (`rlimit_tune_steps`). Untuned, the last step's tokens would all
    /// go at its start, and a short transfer end too soon.
    fn tune_steps(&mut self, total: i64) {
        if self.rate_per_step == 0 || total <= 1 || total > i64::MAX / 1000 {
            return;
        }
        let last = (total / 100).clamp(1, MIN_RATE);
        let main = total - last;
        debug_assert_eq!(self.step_us(), US_PER_SEC);
        // How many milliseconds the rest takes at the rate.
        let msteps = main * 1000 / self.rate_per_step;
        if msteps < STEP_MIN_MS {
            // Steps this short do not work.
        } else if msteps < 1000 {
            // Less than a step: one step exactly that long, with exactly
            // those tokens.
            self.step_us = u32::try_from(msteps * 1000).expect("under a second");
            self.rate_per_step = main;
            self.tokens = self.rate_per_step;
        } else {
            // Spread the milliseconds past whole steps, and the tokens they
            // need, over the steps, as far as integers can.
            let unaccounted = msteps % 1000;
            let inc = unaccounted / (msteps / 1000);
            if inc != 0 {
                let rate_inc = self.rate_per_step * inc / 1000;
                // The burst grows with the step (`burst_per_step`).
                if rate_inc != 0 {
                    self.step_us = u32::try_from(US_PER_SEC + inc * 1000).expect("under 2 s");
                    self.rate_per_step += rate_inc;
                    self.tokens = self.rate_per_step;
                }
            }
        }
    }

    /// Take a new rate and burst, the bucket perhaps in use: the time
    /// already counted stays, the tokens are cut to the new rate
    /// (`Curl_rlimit_change`).
    fn change(&mut self, rate: i64, burst: i64) {
        self.rate_per_sec = rate;
        self.rate_per_step = rate;
        self.burst_per_sec = burst;
        self.step_us = US_PER_SEC as u32;
        self.spare_us = 0;
        self.tokens = self.tokens.min(self.rate_per_step);
    }

    /// Start afresh at `now`, a step's tokens in hand, tuned for `total`
    /// tokens if that is known (`Curl_rlimit_start`).
    fn start(&mut self, now: Instant, total: Option<u64>) {
        self.rate_per_step = self.rate_per_sec;
        self.step_us = US_PER_SEC as u32;
        self.spare_us = 0;
        self.tokens = self.rate_per_step;
        self.ts = now;
        if let Some(total) = total {
            self.tune_steps(i64::try_from(total).unwrap_or(i64::MAX));
        }
    }

    /// Whether there is a limit (`Curl_rlimit_active`, unpaused).
    fn active(&self) -> bool {
        self.rate_per_step > 0
    }

    /// Tokens to spend now, perhaps negative; `i64::MAX` without a limit
    /// (`Curl_rlimit_avail`, unpaused).
    fn avail(&mut self, now: Instant) -> i64 {
        if self.rate_per_step == 0 {
            return i64::MAX;
        }
        self.update(now);
        self.tokens
    }

    /// Spend `n` tokens (`Curl_rlimit_drain`, unpaused).
    fn drain(&mut self, n: usize, now: Instant) {
        if self.rate_per_step == 0 {
            return;
        }
        self.update(now);
        let n = i64::try_from(n).unwrap_or(i64::MAX);
        self.tokens = self.tokens.saturating_sub(n);
    }

    /// How long, in whole milliseconds rounded up, until there are tokens
    /// again: a debt waits a step for every rate's worth of it, in whole
    /// hundredths (`Curl_rlimit_wait_ms`, unpaused).
    fn wait_ms(&mut self, now: Instant) -> u64 {
        if self.rate_per_step == 0 {
            return 0;
        }
        self.update(now);
        if self.tokens > 0 {
            return 0;
        }
        let mut wait_us = self.step_us() - self.spare_us();
        if self.tokens < 0 {
            let debt_pct = self.tokens.saturating_neg().saturating_mul(100) / self.rate_per_step;
            if debt_pct != 0 {
                wait_us = wait_us.saturating_add(self.step_us().saturating_mul(debt_pct) / 100);
            }
        }
        let elapsed_us = micros_since(now, self.ts);
        if elapsed_us >= wait_us {
            return 0;
        }
        u64::try_from((wait_us - elapsed_us + 999) / 1000).expect("a positive wait")
    }

    /// How long, in whole milliseconds rounded up, until the next step's
    /// tokens; 0 if they are due (`Curl_rlimit_next_step_ms`, unpaused).
    fn next_step_ms(&self, now: Instant) -> u64 {
        if self.rate_per_step == 0 {
            return 0;
        }
        if self.ts == never() {
            return 0;
        }
        let elapsed_us = micros_since(now, self.ts).saturating_add(self.spare_us());
        if self.step_us() > elapsed_us {
            u64::try_from((self.step_us() - elapsed_us + 999) / 1000).expect("a positive wait")
        } else {
            0
        }
    }

    /// Take the option's rate if it is not the bucket's. C changes the
    /// bucket as the option is set; the rate is the option's alone here,
    /// so the bucket takes it at its next use. Only a rate set and set
    /// back between two uses tells them apart: C cuts the tokens to it.
    fn sync(&mut self, rate: Option<NonZeroU64>) {
        let rate = rate.map_or(0, |r| i64::try_from(r.get()).unwrap_or(i64::MAX));
        if rate != self.rate_per_sec {
            let burst = if rate == 0 {
                0
            } else {
                rate.max(MIN_BURST as i64)
            };
            self.change(rate, burst);
        }
    }
}

/// Which way bytes move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Way {
    Recv,
    Send,
}

/// What the limits ask of a transfer before and after it moves bytes
/// (`mspeed_check`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Move nothing for this long (`MSTATE_RATELIMITING`).
    Wait(Duration),
    /// Go on, and look again when the next tokens are due, if a limit
    /// earns any.
    Go(Option<Duration>),
}

/// A transfer's two buckets (`progress.dl.rlimit`, `progress.ul.rlimit`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RateLimits {
    recv: Bucket,
    send: Bucket,
}

impl RateLimits {
    /// The bucket for `way`, on the options' rate.
    fn bucket(&mut self, way: Way, flow: &Flow) -> &mut Bucket {
        let (bucket, rate) = match way {
            Way::Recv => (&mut self.recv, flow.max_recv_speed),
            Way::Send => (&mut self.send, flow.max_send_speed),
        };
        bucket.sync(rate);
        bucket
    }

    /// Start `way` afresh at `now`, tuned for `total` bytes if known:
    /// the body's first bytes for receiving, the first read of the
    /// upload for sending, and either way an unpause.
    pub(crate) fn start(&mut self, way: Way, flow: &Flow, now: Instant, total: Option<u64>) {
        self.bucket(way, flow).start(now, total);
    }

    /// How many bytes `way` may move now, if it is limited: none while
    /// it is paused (`Curl_rlimit_active` and `Curl_rlimit_avail`).
    pub(crate) fn allowance(
        &mut self,
        way: Way,
        flow: &Flow,
        pause: Pause,
        now: Instant,
    ) -> Option<i64> {
        if paused(way, pause) {
            return Some(0);
        }
        let bucket = self.bucket(way, flow);
        bucket.active().then(|| bucket.avail(now))
    }

    /// `n` bytes moved `way` (`Curl_rlimit_drain`).
    pub(crate) fn drain(&mut self, way: Way, flow: &Flow, pause: Pause, n: usize, now: Instant) {
        if !paused(way, pause) {
            self.bucket(way, flow).drain(n, now);
        }
    }

    /// Whether the transfer waits for tokens, and if not, when the next
    /// come (`mspeed_check`): the longer wait of the two directions, or
    /// the sooner of their next steps.
    pub(crate) fn verdict(&mut self, flow: &Flow, pause: Pause, now: Instant) -> Verdict {
        let mut wait = [0; 2];
        let mut next = [0; 2];
        for (i, way) in [Way::Send, Way::Recv].into_iter().enumerate() {
            if paused(way, pause) {
                continue;
            }
            let bucket = self.bucket(way, flow);
            wait[i] = bucket.wait_ms(now);
            next[i] = bucket.next_step_ms(now);
        }
        let ms = |n: u64| Duration::from_millis(n);
        if wait[0] != 0 || wait[1] != 0 {
            return Verdict::Wait(ms(wait[0].max(wait[1])));
        }
        Verdict::Go(match (next[0], next[1]) {
            (0, 0) => None,
            (0, n) | (n, 0) => Some(ms(n)),
            (a, b) => Some(ms(a.min(b))),
        })
    }
}

fn paused(way: Way, pause: Pause) -> bool {
    match way {
        Way::Recv => pause.recv_paused(),
        Way::Send => pause.send_paused(),
    }
}

#[cfg(test)]
mod tests;
