//! The progress meter's text (`progress_meter`, `time2str`, `max6out`).

use std::fmt;

/// One direction, as the meter shows it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Dir {
    pub(crate) total: Option<u64>,
    pub(crate) cur: u64,
    /// The average speed, bytes a second.
    pub(crate) speed: u64,
}

/// What a line of the meter shows.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reading {
    /// Microseconds since the transfer started.
    pub(crate) spent_us: u64,
    pub(crate) download: Dir,
    pub(crate) upload: Dir,
    /// The speed of the last five seconds.
    pub(crate) current_speed: u64,
}

/// The meter's column titles, written once per handle.
pub(crate) const HEADER: &str = "  % Total    % Received % Xferd  Average Speed  \
     Time    Time    Time   Current\n                                 Dload  Upload  \
     Total   Spent   Left   Speed\n";

/// One line of the meter, starting with a carriage return.
pub(crate) fn line(r: &Reading, out: &mut impl fmt::Write) -> fmt::Result {
    let cur_secs = to_i64(r.spent_us / 1_000_000);
    let (ul_secs, ul_percent) = estimate(&r.upload);
    let (dl_secs, dl_percent) = estimate(&r.download);
    // Both directions move at once: the longer is the total. Without one,
    // what is left is negative, and blank as nothing is.
    let total_secs = ul_secs.max(dl_secs);
    let left = total_secs - cur_secs;
    let expected = r
        .upload
        .total
        .unwrap_or(r.upload.cur)
        .saturating_add(r.download.total.unwrap_or(r.download.cur));
    let cur = r.download.cur.saturating_add(r.upload.cur);
    write!(out, "\r{:3} ", percent(expected, cur))?;
    max6out(expected, out)?;
    write!(out, " {dl_percent:3} ")?;
    max6out(r.download.cur, out)?;
    write!(out, " {ul_percent:3} ")?;
    max6out(r.upload.cur, out)?;
    out.write_char(' ')?;
    max6out(r.download.speed, out)?;
    out.write_char(' ')?;
    max6out(r.upload.speed, out)?;
    out.write_char(' ')?;
    time2str(total_secs, out)?;
    out.write_char(' ')?;
    time2str(cur_secs, out)?;
    out.write_char(' ')?;
    time2str(left, out)?;
    out.write_char(' ')?;
    max6out(r.current_speed, out)
}

/// Seconds to the end and the share done, where the size and a speed are
/// known (`pgrs_estimates`).
fn estimate(d: &Dir) -> (i64, u64) {
    match d.total {
        Some(total) if d.speed > 0 => (to_i64(total / d.speed), percent(total, d.cur)),
        _ => (0, 0),
    }
}

/// `cur` as a percentage of `total` (`pgrs_est_percent`).
fn percent(total: u64, cur: u64) -> u64 {
    if total > 10000 {
        cur / (total / 100)
    } else {
        cur.saturating_mul(100).checked_div(total).unwrap_or(0)
    }
}

fn to_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// A duration in seven columns: blank for none, then minutes and seconds,
/// hours, days, months and years as it grows (`time2str`).
pub(crate) fn time2str(seconds: i64, out: &mut impl fmt::Write) -> fmt::Result {
    if seconds <= 0 {
        return out.write_str("       ");
    }
    let h = seconds / 3600;
    if h <= 99 {
        let m = (seconds - h * 3600) / 60;
        if h <= 9 {
            let s = seconds - h * 3600 - m * 60;
            if h > 0 {
                write!(out, "{h}:{m:02}:{s:02}")
            } else {
                write!(out, "  {m:02}:{s:02}")
            }
        } else {
            write!(out, "{h}h {m:02}m")
        }
    } else {
        let d = seconds / 86400;
        let h = (seconds - d * 86400) / 3600;
        if d <= 99 {
            write!(out, "{d:2}d {h:02}h")
        } else if d <= 999 {
            write!(out, "{d:6}d")
        } else if d / 30 <= 999 {
            write!(out, "{:6}m", d / 30)
        } else if d / 365 <= 99999 {
            write!(out, "{:6}y", d / 365)
        } else {
            out.write_str(">99999y")
        }
    }
}

/// A byte count in six columns, with a unit past 99999 (`max6out`).
pub(crate) fn max6out(bytes: u64, out: &mut impl fmt::Write) -> fmt::Result {
    if bytes < 100000 {
        return write!(out, "{bytes:6}");
    }
    const UNITS: [char; 6] = ['k', 'M', 'G', 'T', 'P', 'E'];
    let mut bytes = bytes;
    let mut k = 0;
    let mut n = bytes / 1024;
    // The largest count, 2^64 - 1, is 16 in the last unit, so the units
    // never run out.
    while n >= 1000 {
        bytes = n;
        k += 1;
        n = bytes / 1024;
    }
    let rest = bytes % 1024;
    if n <= 99 {
        write!(out, "{n:2}.{:02}{}", rest * 100 / 1024, UNITS[k])
    } else {
        write!(out, "{n:3}.{}{}", rest * 10 / 1024, UNITS[k])
    }
}
