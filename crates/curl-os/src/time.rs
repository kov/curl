//! The local time of day, as the time zone of the process says
//! (`localtime_r`), and a time in UTC formatted by the C library
//! (`strftime`).

#![allow(unsafe_code)]

use core::ffi::CStr;

/// A time of day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeOfDay {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// The local time of day `t` seconds after the epoch; `None` where the
/// system cannot say, for a time out of its range.
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
            .env("TZ", "WEST+3")
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
