//! Dates as servers and files write them (`lib/parsedate.c`): RFC 1123,
//! RFC 850, asctime and the many variations on them C accepts.
//!
//! The parser takes up to six parts, each a name (a weekday, a month or a
//! time zone), a time of day or a number, separated by anything that is
//! neither a letter nor a digit; a part it cannot place fails the date.

#[cfg(test)]
mod c_tests;

use std::fmt;

/// A date that could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadDate;

/// The seconds since 1970-01-01 00:00:00 UTC that `date` names
/// (`Curl_getdate_capped`), negative before then. Reading stops at a zero
/// byte, as C reads a string. A date without a time zone is in UTC.
pub fn parse(date: &[u8]) -> Result<i64, BadDate> {
    let date = date.split(|&b| b == 0).next().unwrap_or_default();
    let mut w = When::default();
    let mut at = 0;
    for _ in 0..MAX_PARTS {
        at += date[at..]
            .iter()
            .take_while(|b| !b.is_ascii_alphanumeric())
            .count();
        let Some(&first) = date.get(at) else {
            break;
        };
        at = if first.is_ascii_alphabetic() {
            name(date, at, &mut w)?
        } else {
            number(date, at, &mut w)?
        };
    }
    let (Some(mon), Some(mday), Some(year)) = (w.mon, w.mday, w.year) else {
        return Err(BadDate);
    };
    // The Gregorian calendar was introduced in 1582.
    if year < 1583 || mday > 31 {
        return Err(BadDate);
    }
    let seconds = to_epoch(year, mon, mday, w.dsecs.unwrap_or(0));
    // A zone ahead of UTC is subtracted. A time past the latest is the
    // latest, as C caps it, though no year of eight digits comes near.
    let zone = i64::from(w.zone.unwrap_or(0));
    Ok(seconds.saturating_add(zone))
}

/// The most parts a date is read in.
const MAX_PARTS: usize = 6;

/// "Wednesday" is the longest name read: a run of this many letters is no
/// name.
const NAME_LEN: usize = 10;

/// What the parts read so far said, each unknown until one says it.
#[derive(Debug, Default)]
struct When {
    /// The day of the week, 0 for Monday; read and otherwise ignored.
    wday: Option<u8>,
    /// The month, 0 for January.
    mon: Option<u8>,
    /// The day of the month, 0 to 99 from a compact date.
    mday: Option<u32>,
    /// Seconds into the day.
    dsecs: Option<u32>,
    year: Option<u32>,
    /// Seconds to add to the local time for UTC.
    zone: Option<i32>,
}

/// Read the name at `at`: the first of a weekday, a month and a time zone
/// not yet known that it is (`datestring`). Where it ends.
fn name(date: &[u8], at: usize, w: &mut When) -> Result<usize, BadDate> {
    let len = date[at..]
        .iter()
        .take(NAME_LEN)
        .take_while(|b| b.is_ascii_alphabetic())
        .count();
    if len == NAME_LEN {
        return Err(BadDate);
    }
    let word = &date[at..at + len];
    let end = Ok(at + len);
    if w.wday.is_none() {
        w.wday = weekday(word);
        if w.wday.is_some() {
            return end;
        }
    }
    if w.mon.is_none() {
        w.mon = month(word);
        if w.mon.is_some() {
            return end;
        }
    }
    if w.zone.is_none() {
        w.zone = zone(word);
        if w.zone.is_some() {
            return end;
        }
    }
    Err(BadDate)
}

/// Read the digits at `at`: a time of day if none is known yet, else a
/// zone offset after a sign, a compact `YYYYMMDD`, a day of the month or
/// a year, the first that applies and is not known yet (`datenum`). Where
/// it ends.
fn number(date: &[u8], at: usize, w: &mut When) -> Result<usize, BadDate> {
    if w.dsecs.is_none()
        && let Some((dsecs, end)) = time_of_day(date, at)
    {
        w.dsecs = Some(dsecs);
        return Ok(at + end);
    }
    let digits = date[at..].iter().take_while(|b| b.is_ascii_digit()).count();
    // As `curlx_str_number` reads it: leading zeros are allowed, and a
    // value over the limit fails.
    let mut val: u32 = 0;
    for &d in &date[at..at + digits] {
        val = val * 10 + u32::from(d - b'0');
        if val > 99_999_999 {
            return Err(BadDate);
        }
    }
    let end = Ok(at + digits);
    let sign = at.checked_sub(1).map(|i| date[i]);
    if w.zone.is_none() && digits == 4 && val <= 1400 && matches!(sign, Some(b'+' | b'-')) {
        // An offset: hours and minutes ahead of UTC (`+`), or behind.
        let offset = i32::try_from((val / 100 * 60 + val % 100) * 60).expect("at most 14:99");
        w.zone = Some(if sign == Some(b'+') { -offset } else { offset });
        return end;
    }
    if digits == 8 && w.year.is_none() && w.mon.is_none() && w.mday.is_none() {
        // YYYYMMDD. A month of 00 leaves the month unknown, as C's -1
        // does: a later name may still give it.
        let mon = (val % 10_000) / 100;
        if mon > 12 {
            return Err(BadDate);
        }
        w.year = Some(val / 10_000);
        w.mon = mon
            .checked_sub(1)
            .map(|m| u8::try_from(m).expect("below 12"));
        w.mday = Some(val % 100);
        return end;
    }
    if w.mday.is_none() && (1..32).contains(&val) {
        w.mday = Some(val);
        return end;
    }
    if w.year.is_none() {
        w.year = Some(match val {
            71..100 => val + 1900,
            0..=70 => val + 2000,
            _ => val,
        });
        return end;
    }
    Err(BadDate)
}

/// `HH:MM:SS` or `HH:MM` at `at`, each of one or two digits, and the
/// length read (`match_time`). A leap second is allowed.
fn time_of_day(date: &[u8], at: usize) -> Option<(u32, usize)> {
    let s = &date[at..];
    let (hh, mut p) = one_or_two_digits(s)?;
    if hh >= 24 || s.get(p) != Some(&b':') {
        return None;
    }
    let (mm, n) = one_or_two_digits(&s[p + 1..])?;
    p += 1 + n;
    if mm >= 60 {
        return None;
    }
    let mut ss = 0;
    if s.get(p) == Some(&b':')
        && let Some((secs, n)) = one_or_two_digits(&s[p + 1..])
    {
        if secs > 60 {
            return None;
        }
        ss = secs;
        p += 1 + n;
    }
    Some((hh * 3600 + mm * 60 + ss, p))
}

/// A number of one or two digits at the start of `s`, and its length.
fn one_or_two_digits(s: &[u8]) -> Option<(u32, usize)> {
    let digit = |i: usize| {
        s.get(i)
            .filter(|b| b.is_ascii_digit())
            .map(|b| u32::from(b - b'0'))
    };
    let first = digit(0)?;
    Some(match digit(1) {
        Some(second) => (first * 10 + second, 2),
        None => (first, 1),
    })
}

/// The day of the week `word` names, three letters or whole, in any case;
/// 0 for Monday (`checkday`).
fn weekday(word: &[u8]) -> Option<u8> {
    const DAYS: [&[u8]; 7] = [
        b"monday",
        b"tuesday",
        b"wednesday",
        b"thursday",
        b"friday",
        b"saturday",
        b"sunday",
    ];
    if word.len() < 3 {
        return None;
    }
    let day = DAYS
        .iter()
        .position(|d| d[..3].eq_ignore_ascii_case(&word[..3]))?;
    (word.len() == 3 || word.eq_ignore_ascii_case(DAYS[day])).then_some(day as u8)
}

/// The month `word` names in three letters, in any case; 0 for January
/// (`checkmonth`).
fn month(word: &[u8]) -> Option<u8> {
    const MONTHS: [&[u8]; 12] = [
        b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov",
        b"dec",
    ];
    MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(word))
        .map(|m| m as u8)
}

/// The seconds to add to a local time in the zone `word` names, in
/// capitals, for UTC (`checktz`).
fn zone(word: &[u8]) -> Option<i32> {
    // Minutes behind UTC. Daylight time is an hour less.
    const DST: i32 = -60;
    // Military zones: A to Z, J not one.
    const LETTERS: [Option<i32>; 26] = [
        Some(-60),
        Some(-2 * 60),
        Some(-3 * 60),
        Some(-4 * 60),
        Some(-5 * 60),
        Some(-6 * 60),
        Some(-7 * 60),
        Some(-8 * 60),
        Some(-9 * 60),
        None,
        Some(-10 * 60),
        Some(-11 * 60),
        Some(-12 * 60),
        Some(60),
        Some(2 * 60),
        Some(3 * 60),
        Some(4 * 60),
        Some(5 * 60),
        Some(6 * 60),
        Some(7 * 60),
        Some(8 * 60),
        Some(9 * 60),
        Some(10 * 60),
        Some(11 * 60),
        Some(12 * 60),
        Some(0),
    ];
    const NAMES: [(&[u8], i32); 44] = [
        (b"NT", 11 * 60),
        (b"UT", 0),
        (b"ADT", 240 + DST),
        (b"AST", 240),
        (b"BST", DST),
        (b"CAT", 600),
        (b"CCT", -480),
        (b"CDT", 360 + DST),
        (b"CET", -60),
        (b"CST", 360),
        (b"EDT", 300 + DST),
        (b"EET", -120),
        (b"EST", 300),
        (b"FST", -60 + DST),
        (b"FWT", -60),
        (b"GMT", 0),
        (b"GST", -600),
        (b"HDT", 600 + DST),
        (b"HST", 600),
        (b"JST", -540),
        (b"MDT", 420 + DST),
        (b"MET", -60),
        (b"MST", 420),
        (b"NZT", -720),
        (b"PDT", 480 + DST),
        (b"PST", 480),
        (b"UTC", 0),
        (b"WAT", 60),
        (b"WET", 0),
        (b"YDT", 540 + DST),
        (b"YST", 540),
        (b"AHST", 600),
        (b"CEST", -60 + DST),
        (b"EADT", -600 + DST),
        (b"EAST", -600),
        (b"IDLE", -720),
        (b"IDLW", 720),
        (b"MEST", -60 + DST),
        (b"MESZ", -60 + DST),
        (b"MEWT", -60),
        (b"NZDT", -720 + DST),
        (b"NZST", -720),
        (b"WADT", -420 + DST),
        (b"WAST", -420),
    ];
    let minutes = match word {
        &[letter] => letter
            .is_ascii_uppercase()
            .then(|| LETTERS[usize::from(letter - b'A')])
            .flatten(),
        _ => NAMES
            .iter()
            .find(|(name, _)| *name == word)
            .map(|&(_, m)| m),
    };
    minutes.map(|m| m * 60)
}

/// The seconds from 1970 to the start of `mday` of `mon` in `year`, plus
/// `dsecs` (`time2epoch`). Days past the month's end run into the next.
fn to_epoch(year: u32, mon: u8, mday: u32, dsecs: u32) -> i64 {
    const CUMULATIVE_DAYS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    // Leap days are counted to the year before when the date is before
    // March.
    let y = i64::from(year) - i64::from(mon <= 1);
    let leap_days = y / 4 - y / 100 + y / 400 - (1969 / 4 - 1969 / 100 + 1969 / 400);
    let days = (i64::from(year) - 1970) * 365
        + leap_days
        + CUMULATIVE_DAYS[usize::from(mon)]
        + i64::from(mday)
        - 1;
    days * 86_400 + i64::from(dsecs)
}

/// A moment as HTTP writes it, in UTC: `Tue, 15 Nov 1994 12:45:26 GMT`
/// (C's `Curl_wkday` and `Curl_month` over `curlx_gmtime`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpDate {
    /// From Sunday.
    weekday: u8,
    day: u8,
    /// From January.
    month: u8,
    year: i64,
    secs: u32,
}

/// A moment C's `struct tm` cannot hold: `gmtime_r` fails on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutOfRange;

impl HttpDate {
    /// The moment `t` seconds after 1970-01-01 00:00:00 UTC.
    pub(crate) fn of(t: i64) -> Result<HttpDate, OutOfRange> {
        let days = t.div_euclid(86400);
        // 1970-01-01 was a Thursday.
        let weekday = (days + 4).rem_euclid(7);
        let (year, month, day) = civil(days);
        if i32::try_from(year - 1900).is_err() {
            return Err(OutOfRange);
        }
        Ok(HttpDate {
            weekday: weekday as u8,
            day: day as u8,
            month: (month - 1) as u8,
            year,
            secs: t.rem_euclid(86400) as u32,
        })
    }
}

impl HttpDate {
    /// The moment as `%Y%m%dT%H%M%SZ` writes it: `19700101T000000Z`.
    pub(crate) fn write_compact(&self, out: &mut impl fmt::Write) -> fmt::Result {
        let s = self.secs;
        write!(
            out,
            "{}{:02}{:02}T{:02}{:02}{:02}Z",
            self.year,
            self.month + 1,
            self.day,
            s / 3600,
            s / 60 % 60,
            s % 60
        )
    }
}

impl fmt::Display for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let s = self.secs;
        write!(
            f,
            "{}, {:02} {} {:4} {:02}:{:02}:{:02} GMT",
            WEEKDAYS[usize::from(self.weekday)],
            self.day,
            MONTHS[usize::from(self.month)],
            self.year,
            s / 3600,
            s / 60 % 60,
            s % 60
        )
    }
}

/// The proleptic Gregorian year, month and day of `days` after
/// 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// lib517: `curl_getdate`, which is this parse with -1 given for a
    /// date it cannot read and 0 for one second before 1970.
    #[test]
    fn lib517_dates() {
        for &(input, want) in c_tests::LIB517 {
            let got = match parse(input.as_bytes()) {
                Ok(-1) => 0,
                Ok(t) => t,
                Err(BadDate) => -1,
            };
            assert_eq!(got, want, "{input}");
        }
    }

    /// unit4781: the names of days, months and zones.
    #[test]
    fn unit4781_names() {
        let index = |n: Option<u8>| n.map_or(-1, i32::from);
        for &(name, want) in c_tests::UNIT4781_DAYS {
            assert_eq!(index(weekday(name.as_bytes())), want, "{name}");
        }
        for &(name, want) in c_tests::UNIT4781_MONTHS {
            assert_eq!(index(month(name.as_bytes())), want, "{name}");
        }
        for &(name, want) in c_tests::UNIT4781_ZONES {
            assert_eq!(zone(name.as_bytes()).unwrap_or(-1), want, "{name}");
        }
    }

    #[test]
    fn a_zero_byte_ends_the_date() {
        assert_eq!(parse(b"06 Nov 1994\0 08:49:37"), Ok(784_080_000));
        assert_eq!(parse(b"\x0006 Nov 1994"), Err(BadDate));
    }

    #[test]
    fn a_compact_date_with_month_00_takes_a_later_month() {
        // C's month of -1 is "unknown": a month name after it gives it.
        assert_eq!(parse(b"19940006 Nov"), parse(b"06 Nov 1994"));
    }

    #[test]
    fn a_compact_date_s_month_is_at_most_12() {
        assert_eq!(parse(b"19941206"), Ok(786_672_000));
        assert_eq!(parse(b"19941306"), Err(BadDate));
    }

    #[test]
    fn six_parts_are_read_and_the_rest_ignored() {
        assert_eq!(parse(b"Sun 06 Nov 1994 08:49:37 GMT junk"), Ok(784_111_777));
        assert_eq!(parse(b"Sun 06 Nov 1994 08:49:37 junk"), Err(BadDate));
    }

    #[test]
    fn the_latest_year_has_eight_digits() {
        // In a zone behind UTC, and still far from the latest time.
        assert_eq!(
            parse(b"31 Dec 99999999 23:59:59 -1400"),
            Ok(3_155_633_032_831_199)
        );
        assert_eq!(parse(b"1 Jan 999999999"), Err(BadDate));
    }

    const WORDS: &[&[u8]] = &[
        b"Tue",
        b"Tuesday",
        b"Nov",
        b"November",
        b"GMT",
        b"UTC",
        b"PST",
        b"MEZ",
        b"Z",
        b"+0100",
        b"-1200",
        b"+99999",
        b"09",
        b"9",
        b"2010",
        b"1969",
        b"99999999999999",
        b"14:49:00",
        b"14:49",
        b"25:61:61",
        b"1:2:3",
        b",",
        b" ",
        b"-",
        b"+",
        b"/",
        b".",
        b"\0",
    ];
    const DATES: &[&[u8]] = &[
        b"Tue, 09 Nov 2010 14:49:00 GMT",
        b"Sunday, 06-Nov-94 08:49:37 GMT",
        b"Sun Nov  6 08:49:37 1994",
        b"20040912 15:05:58 -0700",
        b"Thu, 01-Jan-1970 00:00:00 GMT",
    ];

    proptest::proptest! {
        #![proptest_config(crate::untrusted::config(512))]

        /// Any text is a date or not, without a panic; one that is can
        /// be written as an HTTP date or is out of its range.
        #[test]
        fn any_text_is_a_date_or_not(date in crate::untrusted::input(WORDS, DATES, 12)) {
            if let Ok(t) = parse(&date)
                && let Ok(http) = HttpDate::of(t)
            {
                http.to_string();
            }
        }
    }
}
