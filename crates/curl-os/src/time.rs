//! The system's monotonic clock (`clock_gettime`; on Windows the
//! performance counter, as C's `curlx_now`), the local time of day, as
//! the time zone of the process says (`localtime_r`, `localtime_s`), and a
//! time in UTC formatted by the C library (`strftime`).

#![allow(unsafe_code)]

use core::ffi::CStr;
use core::time::Duration;

/// The time on the system's monotonic clock, since a start of its own
/// that every reading in the system shares (`CLOCK_MONOTONIC`, as C's
/// `Curl_now`): two readings anywhere compare.
#[cfg(unix)]
pub fn monotonic() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid `timespec` the call writes, alive through it.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    assert_eq!(rc, 0, "the monotonic clock is always there");
    let secs = u64::try_from(ts.tv_sec).expect("the monotonic clock starts at 0");
    let nanos = u32::try_from(ts.tv_nsec).expect("under a second");
    Duration::new(secs, nanos)
}

/// The time on the system's performance counter (`QueryPerformanceCounter`,
/// as C's `curlx_pnow` reads it on Windows), since the system started:
/// two readings anywhere compare. Its frequency is fixed at boot, so it is
/// read each time rather than kept.
#[cfg(windows)]
pub fn monotonic() -> Duration {
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };
    let (mut count, mut freq) = (0i64, 0i64);
    // SAFETY: each writes the `i64` it is given, alive through the call.
    let ok = unsafe { QueryPerformanceCounter(&raw mut count) } != 0
        // SAFETY: as above.
        && unsafe { QueryPerformanceFrequency(&raw mut freq) } != 0;
    assert!(ok, "the performance counter is always there");
    let count = u64::try_from(count).expect("the counter starts at 0");
    let freq = u64::try_from(freq).expect("a frequency is positive");
    let nanos = u128::from(count % freq) * 1_000_000_000 / u128::from(freq);
    Duration::new(count / freq, u32::try_from(nanos).expect("under a second"))
}

/// The latest time the C library breaks down (`_MAX__TIME64_T`, the end
/// of the year 3000 in UTC). Past it, or before the epoch, `localtime_s`
/// and `gmtime_s` may call the C library's invalid-parameter handler,
/// which ends the process: such a time is refused here first.
#[cfg(windows)]
const LAST_TIME: i64 = 32_535_215_999;

#[cfg(windows)]
unsafe extern "C" {
    #[link_name = "_localtime64_s"]
    fn localtime_s(tm: *mut libc::tm, t: *const i64) -> i32;
    #[link_name = "_gmtime64_s"]
    fn gmtime_s(tm: *mut libc::tm, t: *const i64) -> i32;
    fn strftime(
        out: *mut core::ffi::c_char,
        max: usize,
        format: *const core::ffi::c_char,
        tm: *const libc::tm,
    ) -> usize;
}

/// The broken-down time `t` seconds after the epoch, local or in UTC;
/// `None` out of the C library's range.
#[cfg(windows)]
fn broken_down(t: i64, local: bool) -> Option<libc::tm> {
    if !(0..=LAST_TIME).contains(&t) {
        return None;
    }
    // SAFETY: `tm` is plain data; any bit pattern, zeros among them, is
    // one.
    let mut tm: libc::tm = unsafe { core::mem::zeroed() };
    let rc = if local {
        // SAFETY: both pointers point to live values of their types for
        // the call, which writes only to `tm`; `t` is in its range.
        unsafe { localtime_s(&raw mut tm, &raw const t) }
    } else {
        // SAFETY: as above.
        unsafe { gmtime_s(&raw mut tm, &raw const t) }
    };
    (rc == 0).then_some(tm)
}

/// Whether `format` asks `strftime` only for what the C library on
/// Windows knows: any other conversion calls its invalid-parameter
/// handler, which ends the process. C hands the tool's `%time{}` to it
/// as it is; here such a format makes nothing.
#[cfg(windows)]
fn known_conversions(format: &CStr) -> bool {
    let mut bytes = format.to_bytes().iter();
    while let Some(&b) = bytes.next() {
        if b != b'%' {
            continue;
        }
        let mut c = bytes.next();
        if c == Some(&b'#') {
            c = bytes.next();
        }
        match c {
            Some(c) if b"aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%".contains(c) => {}
            _ => return false,
        }
    }
    true
}

/// A time of day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeOfDay {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// The local time of day `t` seconds after the epoch; `None` where the
/// system cannot say, for a time out of its range.
#[cfg(windows)]
pub fn local_time_of_day(t: i64) -> Option<TimeOfDay> {
    let tm = broken_down(t, true)?;
    Some(TimeOfDay {
        hour: u8::try_from(tm.tm_hour).ok()?,
        minute: u8::try_from(tm.tm_min).ok()?,
        second: u8::try_from(tm.tm_sec).ok()?,
    })
}

/// `format`, as `strftime` makes it of the time `t` seconds after the
/// epoch in UTC, written to `out` with a zero byte after it; how many
/// bytes it made. None where the time cannot be broken down, the format
/// asks for a conversion the C library does not know, or what it makes is
/// empty or does not fit.
#[cfg(windows)]
pub fn format_utc(format: &CStr, t: i64, out: &mut [u8]) -> Option<usize> {
    let tm = broken_down(t, false)?;
    if !known_conversions(format) || out.is_empty() {
        return None;
    }
    // SAFETY: `out` is writable for its length, which is what `strftime`
    // is told; `format` is a C string of conversions it knows and `tm` a
    // broken-down time, both live for the call.
    let n = unsafe {
        strftime(
            out.as_mut_ptr().cast(),
            out.len(),
            format.as_ptr(),
            &raw const tm,
        )
    };
    (n > 0).then_some(n)
}

/// The local time of day `t` seconds after the epoch; `None` where the
/// system cannot say, for a time out of its range.
#[cfg(unix)]
pub fn local_time_of_day(t: i64) -> Option<TimeOfDay> {
    let t = libc::time_t::try_from(t).ok()?;
    // SAFETY: `tm` is plain data; any bit pattern, zeros among them, is
    // one.
    let mut tm: libc::tm = unsafe { core::mem::zeroed() };
    // SAFETY: both pointers point to live values of their types for the
    // call; `localtime_r` writes only to `tm`.
    let filled = unsafe { libc::localtime_r(&raw const t, &raw mut tm) };
    if filled.is_null() {
        return None;
    }
    Some(TimeOfDay {
        hour: u8::try_from(tm.tm_hour).ok()?,
        minute: u8::try_from(tm.tm_min).ok()?,
        second: u8::try_from(tm.tm_sec).ok()?,
    })
}

/// `format`, as `strftime` makes it of the time `t` seconds after the
/// epoch in UTC, written to `out` with a zero byte after it; how many
/// bytes it made. None where the time cannot be broken down, or what it
/// makes is empty or does not fit.
#[cfg(unix)]
pub fn format_utc(format: &CStr, t: i64, out: &mut [u8]) -> Option<usize> {
    let t = libc::time_t::try_from(t).ok()?;
    // SAFETY: `tm` is plain data; any bit pattern, zeros among them, is
    // one.
    let mut tm: libc::tm = unsafe { core::mem::zeroed() };
    // SAFETY: both pointers point to live values of their types for the
    // call; `gmtime_r` writes only to `tm`.
    let filled = unsafe { libc::gmtime_r(&raw const t, &raw mut tm) };
    if filled.is_null() {
        return None;
    }
    // SAFETY: `out` is writable for its length, which is what `strftime`
    // is told; `format` is a C string and `tm` a broken-down time, both
    // live for the call.
    let n = unsafe {
        libc::strftime(
            out.as_mut_ptr().cast(),
            out.len(),
            format.as_ptr(),
            &raw const tm,
        )
    };
    (n > 0).then_some(n)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use super::*;

    /// The clock does not go back.
    #[test]
    fn the_monotonic_clock_moves_on() {
        let a = monotonic();
        let b = monotonic();
        assert!(a <= b && a > Duration::ZERO);
    }

    /// A time in UTC is formatted as `strftime` formats it, in the C
    /// locale; nothing for an empty result, one that does not fit with
    /// its zero byte, or a time that cannot be broken down.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not run gmtime_r or strftime")]
    fn formats_a_time_in_utc() {
        let mut out = [0u8; 64];
        let n = format_utc(c"%d/%b/%Y %H:%M:%S %a %j", 1_754_037_103, &mut out).unwrap();
        assert_eq!(&out[..n], b"01/Aug/2025 08:31:43 Fri 213");
        assert_eq!(out[n], 0);
        assert_eq!(format_utc(c"", 0, &mut out), None);
        assert_eq!(format_utc(c"%Y", 0, &mut out[..4]), None);
        assert_eq!(format_utc(c"%Y", 0, &mut out[..5]), Some(4));
        assert_eq!(format_utc(c"%Y", i64::MAX, &mut out), None);
    }

    /// What would end the process in the C library is refused first: a
    /// time out of its range, and a conversion it does not know.
    #[test]
    #[cfg(windows)]
    fn refuses_what_the_c_library_cannot_take() {
        let mut out = [0u8; 64];
        assert_eq!(format_utc(c"%Y", -1, &mut out), None);
        assert_eq!(format_utc(c"%Y", LAST_TIME + 1, &mut out), None);
        assert_eq!(format_utc(c"%Y", LAST_TIME, &mut out), Some(4));
        assert_eq!(&out[..4], b"3000");
        assert_eq!(format_utc(c"%Q", 0, &mut out), None);
        assert_eq!(format_utc(c"%", 0, &mut out), None);
        assert_eq!(format_utc(c"%Ey", 0, &mut out), None);
        assert_eq!(format_utc(c"%#d%%", 0, &mut out), Some(2));
        assert_eq!(&out[..2], b"1%");
        assert_eq!(local_time_of_day(-1), None);
        assert_eq!(local_time_of_day(i64::MIN), None);
    }

    /// A zone three hours behind UTC, as the C library reads `TZ`: the
    /// Windows one takes a name of three letters.
    #[cfg(unix)]
    const ZONE_THREE_HOURS_WEST: &str = "WEST+3";
    #[cfg(windows)]
    const ZONE_THREE_HOURS_WEST: &str = "WST+3";

    /// Set in the child process `follows_the_time_zone` runs.
    const CHILD: &str = "CURL_OS_TIME_ZONE_CHILD";

    /// Time zones are whole minutes off UTC: the seconds are the epoch's.
    #[test]
    fn tells_the_time_of_day() {
        for t in [0, 59, 86_399, 1_700_000_000] {
            let now = local_time_of_day(t).unwrap();
            assert_eq!(i64::from(now.second), t % 60);
            assert!(now.hour < 24 && now.minute < 60);
        }
        // Miri's `localtime_r` panics past its range rather than fail.
        #[cfg(not(miri))]
        assert_eq!(local_time_of_day(i64::MAX), None);
    }

    /// The time is the zone's, not UTC: the test binary runs this module's
    /// `in_a_zone_three_hours_west` again with `TZ` set.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not run processes")]
    fn follows_the_time_zone() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "time::tests::in_a_zone_three_hours_west"])
            .env("TZ", ZONE_THREE_HOURS_WEST)
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "{out:?}"
        );
    }

    #[test]
    fn in_a_zone_three_hours_west() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let midnight = local_time_of_day(0).unwrap();
        assert_eq!(
            midnight,
            TimeOfDay {
                hour: 21,
                minute: 0,
                second: 0
            }
        );
    }
}
