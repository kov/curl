//! The local time of day, as the time zone of the process says
//! (`localtime_r`).

#![allow(unsafe_code)]

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

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use super::*;

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
