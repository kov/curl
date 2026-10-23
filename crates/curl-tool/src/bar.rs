//! `--progress-bar`: a line of `#` that grows as the transfer does, or a
//! bouncing ball while its size is unknown (`tool_cb_prg.c`). It is drawn
//! on standard error by the tool's own progress handler.

use std::io::Write as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use curl_alloc::{OutOfMemory, TryArc};
use curl_core::handler::{Handler, ProgressHandler, ProgressNow, ProgressVerdict};
use curl_core::multi::TransferCx;

use crate::msgs;

const MAX_WIDTH: usize = 400;
const MIN_WIDTH: usize = 20;

/// Redrawn at most this often, but for the last draw at 100%.
const REDRAW: Duration = Duration::from_millis(100);

/// `sin(i / 200 * 2 * pi) * 500000 + 500000` for i in 1..=200, with pi
/// as 3.1415: where the ball's trail is drawn.
const SINUS: [i32; 200] = [
    515704, 531394, 547052, 562664, 578214, 593687, 609068, 624341, 639491, 654504, 669364, 684057,
    698568, 712883, 726989, 740870, 754513, 767906, 781034, 793885, 806445, 818704, 830647, 842265,
    853545, 864476, 875047, 885248, 895069, 904500, 913532, 922156, 930363, 938145, 945495, 952406,
    958870, 964881, 970434, 975522, 980141, 984286, 987954, 991139, 993840, 996054, 997778, 999011,
    999752, 999999, 999754, 999014, 997783, 996060, 993848, 991148, 987964, 984298, 980154, 975536,
    970449, 964898, 958888, 952426, 945516, 938168, 930386, 922180, 913558, 904527, 895097, 885277,
    875077, 864507, 853577, 842299, 830682, 818739, 806482, 793922, 781072, 767945, 754553, 740910,
    727030, 712925, 698610, 684100, 669407, 654548, 639536, 624386, 609113, 593733, 578260, 562710,
    547098, 531440, 515751, 500046, 484341, 468651, 452993, 437381, 421830, 406357, 390976, 375703,
    360552, 345539, 330679, 315985, 301474, 287158, 273052, 259170, 245525, 232132, 219003, 206152,
    193590, 181331, 169386, 157768, 146487, 135555, 124983, 114781, 104959, 95526, 86493, 77868,
    69660, 61876, 54525, 47613, 41147, 35135, 29581, 24491, 19871, 15724, 12056, 8868, 6166, 3951,
    2225, 990, 248, 0, 244, 982, 2212, 3933, 6144, 8842, 12025, 15690, 19832, 24448, 29534, 35084,
    41092, 47554, 54462, 61809, 69589, 77794, 86415, 95445, 104873, 114692, 124891, 135460, 146389,
    157667, 169282, 181224, 193480, 206039, 218888, 232015, 245406, 259048, 272928, 287032, 301346,
    315856, 330548, 345407, 360419, 375568, 390841, 406221, 421693, 437243, 452854, 468513, 484202,
    499907,
];

/// One transfer's bar, shared by its progress handler and the tool, which
/// ends the line once the transfer is over.
#[derive(Clone)]
pub(crate) struct Bar(TryArc<Mutex<State>>);

/// C's `struct ProgressData`.
struct State {
    /// Where the transfer starts in the whole: a resumed transfer's bar
    /// shows the whole. `None` when the peer will say (an upload resumed
    /// at the end of what it holds).
    start: Option<u64>,
    /// Times drawn or looked at; the line is ended only if not 0.
    calls: u64,
    /// The bytes last shown, and when.
    prev: u64,
    prev_time: Option<Instant>,
    width: usize,
    /// The ball's phase in `SINUS`, its place and its direction.
    tick: usize,
    ball: usize,
    rightwards: bool,
}

impl Bar {
    pub(crate) fn new(start: Option<u64>) -> Result<Bar, OutOfMemory> {
        Ok(Bar(TryArc::try_new(Mutex::new(State::new(start)))?))
    }

    pub(crate) fn handler(&self) -> Result<Handler<dyn ProgressHandler>, OutOfMemory> {
        Handler::progress(self.clone())
    }

    /// The bar was drawn: the line it is on wants ending.
    pub(crate) fn shown(&self) -> bool {
        self.0.lock().expect("no panic holds it").calls > 0
    }
}

impl Bar {
    /// Draw the transfer at `now` (`tool_progress_cb`); false if it was
    /// drawn too recently to be again, as C's returns early.
    pub(crate) fn update(&self, now: ProgressNow) -> bool {
        let mut out = std::io::stderr().lock();
        let mut state = self.0.lock().expect("no panic holds it");
        let drawn = state.draw(now, Instant::now(), width());
        // A failed write has nowhere to be reported, as in C.
        let _ = out.write_all(drawn.bytes()).and_then(|()| out.flush());
        drawn.whole
    }
}

impl ProgressHandler for Bar {
    fn progress(&self, _: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
        self.update(now);
        ProgressVerdict::Continue
    }
}

/// The bar's width: the terminal's, within limits (`update_width`).
fn width() -> usize {
    msgs::terminal_columns().clamp(MIN_WIDTH, MAX_WIDTH)
}

/// What one call draws: a carriage return and a line at most as wide as
/// the widest bar, with the ball's line one more for its own return.
struct Drawn {
    buf: [u8; 2 * (MAX_WIDTH + 1)],
    len: usize,
    /// The call was not cut short for coming too soon after the last.
    whole: bool,
}

impl Drawn {
    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn push(&mut self, bytes: &[u8]) {
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }
}

impl State {
    /// `progressbarinit`.
    fn new(start: Option<u64>) -> State {
        State {
            start,
            calls: 0,
            prev: 0,
            prev_time: None,
            width: MIN_WIDTH,
            tick: 150,
            ball: 0,
            rightwards: true,
        }
    }

    /// `tool_progress_cb` at `at`, the terminal `width` wide.
    fn draw(&mut self, now: ProgressNow, at: Instant, width: usize) -> Drawn {
        let mut drawn = Drawn {
            buf: [0; 2 * (MAX_WIDTH + 1)],
            len: 0,
            whole: false,
        };
        let known = now.download_total.is_some() || now.upload_total.is_some();
        let total_all = now
            .download_total
            .unwrap_or(0)
            .saturating_add(now.upload_total.unwrap_or(0));
        let now_all = now.downloaded.saturating_add(now.uploaded);
        let (mut total, point) = match self.start {
            None if known => (total_all, now_all),
            None => (u64::MAX, u64::MAX),
            Some(start) => (
                total_all.saturating_add(start),
                now_all.saturating_add(start),
            ),
        };
        let since = self
            .prev_time
            .map(|prev| at.saturating_duration_since(prev));
        if self.calls > 0 {
            let recent = since.is_some_and(|d| d < REDRAW);
            if total > 0 {
                if self.prev == point || (recent && point < total) {
                    return drawn;
                }
            } else {
                if recent {
                    return drawn;
                }
                self.width = width;
                self.fly(point != self.prev, &mut drawn);
            }
        }
        self.calls += 1;
        self.width = width;
        if total > 0 && point != self.prev {
            total = total.max(point);
            let frac = point as f64 / total as f64;
            let bar_width = self.width - 7;
            let hashes = ((bar_width as f64 * frac) as usize).min(MAX_WIDTH);
            drawn.push(b"\r");
            for i in 0..bar_width.max(hashes) {
                drawn.push(if i < hashes { b"#" } else { b" " });
            }
            let mut percent = [0u8; 16];
            let mut cursor = std::io::Cursor::new(&mut percent[..]);
            write!(cursor, " {:5.1}%", frac * 100.0).expect("a percentage fits");
            let n = cursor.position() as usize;
            drawn.push(&percent[..n]);
        }
        self.prev = point;
        self.prev_time = Some(at);
        drawn.whole = true;
        drawn
    }

    /// The ball and its trail, moved along if the transfer `moved`.
    fn fly(&mut self, moved: bool, drawn: &mut Drawn) {
        let width = self.width;
        let start = drawn.len;
        drawn.push(b"\r");
        for _ in 0..width {
            drawn.push(b" ");
        }
        let line = &mut drawn.buf[start + 1..start + 1 + width];
        // A terminal narrowed since cuts the ball at the line's end, where
        // C's string ends; the ball is back on the line after.
        if let Some(room) = width.checked_sub(self.ball) {
            let ball = &b"-=O=-"[..room.min(5)];
            line[self.ball..self.ball + ball.len()].copy_from_slice(ball);
        }
        let step = 1_000_000 / (width as i32 - 2);
        for lag in [0, 5, 10, 15] {
            let at = (SINUS[(self.tick + lag) % 200] / step) as usize;
            line[at] = b'#';
        }
        self.tick = (self.tick + 2) % 200;
        if moved {
            if self.rightwards {
                self.ball += 1;
            } else if self.ball == 0 {
                self.rightwards = true;
            } else {
                self.ball -= 1;
            }
        }
        if self.ball >= width - 6 {
            self.rightwards = false;
            self.ball = width - 6;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now(downloaded: u64, total: Option<u64>) -> ProgressNow {
        ProgressNow {
            download_total: total,
            downloaded,
            upload_total: None,
            uploaded: 0,
        }
    }

    /// A known size draws `#` for what came, the percentage beside it;
    /// redraws wait 100 ms, but for the last.
    #[test]
    fn draws_the_share_done() {
        let mut s = State::new(Some(0));
        let t0 = Instant::now();
        let first = s.draw(now(0, Some(100)), t0, 79);
        assert_eq!(first.bytes(), b"", "nothing yet");
        assert!(first.whole, "looked at");
        let soon = s.draw(now(50, Some(100)), t0, 79);
        assert_eq!(soon.bytes(), b"", "too soon");
        // Cut short, as C's returns before it lets a `-T .` upload go on.
        assert!(!soon.whole);
        let t1 = t0 + REDRAW;
        let half = s.draw(now(50, Some(100)), t1, 79);
        assert!(half.whole);
        let mut want = b"\r".to_vec();
        want.extend_from_slice(&[b'#'; 36]);
        want.extend_from_slice(&[b' '; 36]);
        want.extend_from_slice(b"  50.0%");
        assert_eq!(half.bytes(), want);
        assert_eq!(s.draw(now(60, Some(100)), t1, 79).bytes(), b"", "too soon");
        let all = s.draw(now(100, Some(100)), t1, 79);
        let mut want = b"\r".to_vec();
        want.extend_from_slice(&[b'#'; 72]);
        want.extend_from_slice(b" 100.0%");
        assert_eq!(all.bytes(), want);
        assert!(s.calls > 0);
    }

    /// A resumed transfer's bar shows the whole, what was there counted.
    #[test]
    fn counts_what_a_resumed_transfer_had() {
        let mut s = State::new(Some(100));
        let drawn = s.draw(now(0, Some(100)), Instant::now(), 27);
        let mut want = b"\r".to_vec();
        want.extend_from_slice(&[b'#'; 10]);
        want.extend_from_slice(&[b' '; 10]);
        want.extend_from_slice(b"  50.0%");
        assert_eq!(drawn.bytes(), want);
    }

    /// An unknown size bounces a ball, from the first call after the
    /// first.
    #[test]
    fn bounces_a_ball_while_the_size_is_unknown() {
        let mut s = State::new(Some(0));
        let t0 = Instant::now();
        assert_eq!(s.draw(now(5, None), t0, 20).bytes(), b"");
        let t1 = t0 + REDRAW;
        let drawn = s.draw(now(10, None), t1, 20);
        let line = &drawn.bytes()[1..];
        assert_eq!(drawn.bytes()[0], b'\r');
        // The trail starts at the left, over the ball's tail: C's
        // arithmetic puts it at 0, 0, 0 and 1.
        let mut want = b"##O=-".to_vec();
        want.extend_from_slice(&[b' '; 15]);
        assert_eq!(line, want);
        assert_eq!(s.ball, 1, "it moved");
        assert_eq!(s.draw(now(15, None), t1, 20).bytes(), b"", "too soon");
    }

    /// C's `fly`, as its arithmetic has it: the line it draws `width`
    /// wide, then where the ball goes.
    struct Fly {
        tick: usize,
        ball: i64,
        step: i64,
    }

    impl Fly {
        fn frame(&mut self, width: usize, moved: bool) -> Vec<u8> {
            let mut buf = vec![b' '; width + 1];
            buf[0] = b'\r';
            // Copied past the string's end, the ball is not shown there.
            for (i, &b) in b"-=O=-".iter().enumerate() {
                let at = self.ball as usize + 1 + i;
                if at <= width {
                    buf[at] = b;
                }
            }
            let check = width as i32 - 2;
            for lag in [0, 5, 10, 15] {
                buf[(SINUS[(self.tick + lag) % 200] / (1_000_000 / check) + 1) as usize] = b'#';
            }
            self.tick += 2;
            if self.tick >= 200 {
                self.tick -= 200;
            }
            if moved {
                self.ball += self.step;
            }
            let last = width as i64 - 6;
            if self.ball >= last {
                self.step = -1;
                self.ball = last;
            } else if self.ball < 0 {
                self.step = 1;
                self.ball = 0;
            }
            buf
        }
    }

    /// The ball runs to the right end and back, still while nothing comes,
    /// its trail on C's sine; a narrowed terminal cuts it at the line's
    /// end, then has it back on the line.
    #[test]
    fn bounces_the_ball_as_c_does() {
        let mut s = State::new(Some(0));
        let mut c = Fly {
            tick: 150,
            ball: 0,
            step: 1,
        };
        let mut t = Instant::now();
        assert_eq!(s.draw(now(0, None), t, 20).bytes(), b"");
        let mut got = 0;
        let mut frame = |width: usize, moved: bool| {
            t += REDRAW;
            got += u64::from(moved);
            let drawn = s.draw(now(got, None), t, width).bytes().to_vec();
            assert_eq!(
                String::from_utf8(drawn).unwrap(),
                String::from_utf8(c.frame(width, moved)).unwrap(),
                "at {got}, {width} wide"
            );
        };
        // Past the tick's wrap, to the right end, back and right again.
        for _ in 0..34 {
            frame(20, true);
        }
        frame(20, false);
        frame(20, false);
        for _ in 0..30 {
            frame(40, true);
        }
        // The ball at 30 of 40, then 20 wide: hidden, then back on.
        frame(20, true);
        frame(20, true);
        frame(23, true);
        frame(20, false);
        // Back to 17 of 40, then 20 wide: the ball's head only.
        for _ in 0..29 {
            frame(40, true);
        }
        frame(20, true);
        frame(20, true);
    }

    /// Without a start, a size the peer gives is the whole; with none
    /// known, the bar is full from the first.
    #[test]
    fn takes_the_size_the_peer_gives() {
        let mut s = State::new(None);
        let drawn = s.draw(now(50, Some(100)), Instant::now(), 27);
        let mut want = b"\r".to_vec();
        want.extend_from_slice(&[b'#'; 10]);
        want.extend_from_slice(&[b' '; 10]);
        want.extend_from_slice(b"  50.0%");
        assert_eq!(drawn.bytes(), want);
        let mut s = State::new(None);
        let up = ProgressNow {
            upload_total: Some(100),
            uploaded: 25,
            ..now(0, None)
        };
        let drawn = s.draw(up, Instant::now(), 27);
        assert_eq!(&drawn.bytes()[..7], b"\r##### ");
        assert!(drawn.bytes().ends_with(b"  25.0%"));
        let mut s = State::new(None);
        let drawn = s.draw(now(50, None), Instant::now(), 27);
        let mut want = b"\r".to_vec();
        want.extend_from_slice(&[b'#'; 20]);
        want.extend_from_slice(b" 100.0%");
        assert_eq!(drawn.bytes(), want);
    }
}
