//! Numeric option arguments, read as `src/tool_paramhlp.c` reads them.

use super::ParamError;

/// C's `LONG_MAX` on the platforms in scope.
const LONG_MAX: u64 = i64::MAX.unsigned_abs();

/// The leading decimal number of `s`, and what follows it, as
/// `curlx_str_number` reads it: at least one digit, no sign, no space, and
/// `None` above `max`.
pub(crate) fn leading_number(s: &[u8], max: u64) -> Option<(u64, &[u8])> {
    let (n, digits) = digits_up_to(s, 10, max).ok()?;
    (digits > 0).then(|| (n, &s[digits..]))
}

/// The value of the leading digits of `s` in `base` (8, 10 or 16), and
/// how many there are, in one pass as `curlx_str_number` and its
/// siblings read them; `Err` once the value would pass `max`, before any
/// digit after.
fn digits_up_to(s: &[u8], base: u8, max: u64) -> Result<(u64, usize), ()> {
    let mut n: u64 = 0;
    for (i, &b) in s.iter().enumerate() {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0xff,
        };
        if d >= base {
            return Ok((n, i));
        }
        let d = u64::from(d);
        // As C checks it: what the next digit adds must still fit.
        if max < d || n > (max - d) / u64::from(base) {
            return Err(());
        }
        n = n * u64::from(base) + d;
    }
    Ok((n, s.len()))
}

/// A whole-number argument that must not be negative, as `str2unum`
/// reads it: an optional `-`, then only digits, at most `LONG_MAX`.
pub(crate) fn unsigned(s: &[u8]) -> Result<u64, ParamError> {
    let (negative, digits) = match s.strip_prefix(b"-") {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    match leading_number(digits, LONG_MAX) {
        Some((n, b"")) if negative && n > 0 => Err(ParamError::NegativeNumeric),
        Some((n, b"")) => Ok(n),
        _ => Err(ParamError::BadNumeric),
    }
}

/// A whole number, as `str2num` reads it: an optional `-`, then only
/// digits, at most `LONG_MAX`.
pub(crate) fn signed(s: &[u8]) -> Result<i64, ParamError> {
    let (negative, digits) = match s.strip_prefix(b"-") {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    match leading_number(digits, LONG_MAX) {
        Some((n, b"")) => {
            let n = i64::try_from(n).expect("at most LONG_MAX");
            Ok(if negative { -n } else { n })
        }
        _ => Err(ParamError::BadNumeric),
    }
}

/// A byte offset, as `str2offset` reads it: only digits, at most
/// `CURL_OFF_T_MAX`.
pub(crate) fn offset(s: &[u8]) -> Result<u64, ParamError> {
    match leading_number(s, LONG_MAX) {
        Some((n, b"")) => Ok(n),
        _ => Err(ParamError::BadNumeric),
    }
}

/// An octal number at most `max`, as `oct2nummax` reads it: only octal
/// digits, at least one.
pub(crate) fn octal(s: &[u8], max: u64) -> Result<u64, ParamError> {
    // Too large is found before anything after the digits.
    let (n, digits) = digits_up_to(s, 8, max).map_err(|()| ParamError::NumberTooLarge)?;
    if digits == 0 || digits != s.len() {
        return Err(ParamError::BadNumeric);
    }
    Ok(n)
}

/// The shortest time between transfer starts `--rate` asks for, in
/// milliseconds, as `set_rate` reads it: transfers per hour, or per `N`
/// seconds, minutes, hours or days after a `/`, `N` 1 if not given. What
/// follows the number, or the unit, is ignored. `bad` is told the error
/// C reports about the unit.
pub(crate) fn rate(s: &[u8], bad: &mut dyn FnMut(&[u8])) -> Result<u64, ParamError> {
    const MAX: u64 = i64::MAX.unsigned_abs();
    let (per, rest) = leading_number(s, MAX).ok_or(ParamError::BadNumeric)?;
    if per < 1 {
        return Err(ParamError::BadUse);
    }
    let mut err = None;
    // Per hour unless said otherwise.
    let mut span: u64 = 60 * 60 * 1000;
    if let Some(rest) = rest.strip_prefix(b"/") {
        let (units, rest) = leading_number(rest, MAX).unwrap_or((1, rest));
        match rest.first() {
            Some(b's') => span = 1000,
            Some(b'm') => span = 60 * 1000,
            Some(b'h') => {}
            Some(b'd') => span = 24 * 60 * 60 * 1000,
            _ => {
                bad(b"unsupported --rate unit");
                err = Some(ParamError::BadUse);
            }
        }
        // The check is made after an unknown unit too, as in C.
        if MAX / span < units {
            bad(b"too large --rate unit");
            err = Some(ParamError::NumberTooLarge);
        } else {
            span *= units;
        }
    }
    match err {
        Some(e) => Err(e),
        None if per > span => Err(ParamError::NumberTooLarge),
        None => Ok(span / per),
    }
}

/// A number of seconds with an optional fraction, in milliseconds, as
/// `secs2ms` reads it. Anything after the number is ignored, as in C.
pub(crate) fn seconds_as_millis(s: &[u8]) -> Result<u64, ParamError> {
    const DIGITS: [u64; 9] = [
        1,
        10,
        100,
        1000,
        10000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
    ];
    let (secs, rest) = leading_number(s, LONG_MAX / 1000 - 1).ok_or(ParamError::BadNumeric)?;
    let mut millis = 0;
    if let Some(fraction) = rest.strip_prefix(b".") {
        let (mut fracs, after) =
            leading_number(fraction, LONG_MAX).ok_or(ParamError::NumberTooLarge)?;
        let mut len = fraction.len() - after.len();
        while len > DIGITS.len() || fracs > LONG_MAX / 100 {
            fracs /= 10;
            len -= 1;
        }
        millis = fracs * 100 / DIGITS[len - 1];
    }
    Ok(secs * 1000 + millis)
}

/// A size in bytes with an optional fraction and unit, `k` to `p` (or
/// `b`), as `GetSizeParameter` reads it for `--max-filesize`.
pub(crate) fn size(s: &[u8]) -> Result<u64, ParamError> {
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return Err(ParamError::BadNumeric);
    }
    let value = leading_number(s, LONG_MAX)
        .ok_or(ParamError::NumberTooLarge)?
        .0;
    let mut unit = &s[digits..];
    let (mut prec, mut plen) = (0, 0);
    if let Some(fraction) = unit.strip_prefix(b".") {
        let (p, after) = leading_number(fraction, LONG_MAX).ok_or(ParamError::BadNumeric)?;
        plen = fraction.len() - after.len();
        prec = p;
        unit = after;
    }
    if unit.len() > 1 {
        return Err(ParamError::BadUse);
    }
    let (mul, add) = match unit.first().map(|&u| u | 0x20) {
        None | Some(b'b') if plen > 0 => return Err(ParamError::BadUse),
        None | Some(b'b') => (1, 0),
        Some(u) => {
            let (mul, mlen): (u64, usize) = match u {
                b'p' => (1 << 50, 16),
                b't' => (1 << 40, 13),
                b'g' => (1 << 30, 10),
                b'm' => (1 << 20, 7),
                b'k' => (1 << 10, 4),
                _ => return Err(ParamError::BadUse),
            };
            let mut add = 0;
            if prec != 0 {
                // Digits past what the unit can tell apart are dropped.
                while mlen <= plen {
                    prec /= 10;
                    plen -= 1;
                }
                let frac = 10u64.pow(u32::try_from(plen).expect("fewer digits than the unit's"));
                add = if LONG_MAX / mul > prec {
                    mul * prec / frac
                } else {
                    (mul / frac) * prec
                };
            }
            (mul, add)
        }
    };
    if value > (LONG_MAX - add) / mul {
        return Err(ParamError::NumberTooLarge);
    }
    Ok(value * mul + add)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `str2num`: a whole number, negative or not, and nothing after it.
    #[test]
    fn signed_like_c() {
        assert_eq!(signed(b"12"), Ok(12));
        assert_eq!(signed(b"-12"), Ok(-12));
        assert_eq!(signed(b"0"), Ok(0));
        for bad in [&b""[..], b"-", b"12x", b" 1", b"+1"] {
            assert_eq!(signed(bad), Err(ParamError::BadNumeric), "{bad:?}");
        }
    }

    /// Unit test 1623's cases, read from its source.
    #[test]
    fn size_like_c() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/tunit/tool1623.c"
        ))
        .unwrap();
        let mut checked = 0;
        for line in source.lines().map(str::trim) {
            let Some(case) = line
                .strip_prefix("{ \"")
                .and_then(|l| l.strip_suffix(" },"))
            else {
                continue;
            };
            let (input, rest) = case.split_once("\", ").unwrap();
            let (amount, err) = rest.split_once(", ").unwrap();
            let want = match err {
                "PARAM_OK" => Ok(amount.parse().unwrap()),
                "PARAM_BAD_USE" => Err(ParamError::BadUse),
                "PARAM_BAD_NUMERIC" => Err(ParamError::BadNumeric),
                "PARAM_NUMBER_TOO_LARGE" => Err(ParamError::NumberTooLarge),
                other => panic!("{other}"),
            };
            assert_eq!(size(input.as_bytes()), want, "{input}");
            checked += 1;
        }
        assert!(checked > 50, "the cases were read");
        // A fraction as long as the unit's digits is cut by one: the C
        // tool takes `1.1234k` as 1149 bytes, as `1.123k`.
        assert_eq!(size(b"1.1234k"), Ok(1149));
        // At `LONG_MAX / mul == prec` C takes the second form, which rounds
        // the unit down first.
        assert_eq!(size(b"0.8191p"), Ok(922_224_613_692_644));
        // The fraction counts against the limit.
        assert_eq!(size(b"9007199254740991.5k"), Ok(9_223_372_036_854_775_296));
        assert_eq!(
            size(b"9007199254740992.5k"),
            Err(ParamError::NumberTooLarge)
        );
    }

    /// The C tool's answers, from `build/c/src/curl --retry` and friends.
    #[test]
    fn offset_like_c() {
        assert_eq!(offset(b"0"), Ok(0));
        assert_eq!(offset(b"9223372036854775807"), Ok(LONG_MAX));
        assert_eq!(offset(b"9223372036854775808"), Err(ParamError::BadNumeric));
        assert_eq!(offset(b"-1"), Err(ParamError::BadNumeric));
        assert_eq!(offset(b"1k"), Err(ParamError::BadNumeric));
        assert_eq!(offset(b""), Err(ParamError::BadNumeric));
    }

    /// `set_rate`, as the C tool reads `--rate`.
    #[test]
    fn rate_like_c() {
        use ParamError::*;
        let read = |s: &str| {
            let mut said = Vec::new();
            let got = rate(s.as_bytes(), &mut |m| {
                said.push(String::from_utf8(m.to_vec()).unwrap())
            });
            (got, said)
        };
        for (given, ms) in [
            ("1/s", 1000),
            ("2/s", 500),
            ("3/s", 333),
            ("1/3s", 3000),
            ("10/m", 6000),
            ("1/h", 3_600_000),
            ("2", 1_800_000),
            ("2x", 1_800_000),
            ("1/d", 86_400_000),
            ("1/2days", 172_800_000),
            ("1000/s", 1),
        ] {
            assert_eq!(read(given), (Ok(ms), vec![]), "{given}");
        }
        assert_eq!(read("1001/s").0, Err(NumberTooLarge));
        // As many units as fit in milliseconds, and one more.
        assert_eq!(read("1/9223372036854775s").0, Ok(9_223_372_036_854_775_000));
        assert_eq!(read("1/9223372036854776s").0, Err(NumberTooLarge));
        assert_eq!(read("0/s").0, Err(BadUse));
        assert_eq!(read("x").0, Err(BadNumeric));
        assert_eq!(read("-1").0, Err(BadNumeric));
        assert_eq!(read("99999999999999999999").0, Err(BadNumeric));
        let unknown = vec!["unsupported --rate unit".to_string()];
        assert_eq!(read("1/w"), (Err(BadUse), unknown.clone()));
        assert_eq!(read("1/"), (Err(BadUse), unknown.clone()));
        assert_eq!(read("1/xs"), (Err(BadUse), unknown));
        assert_eq!(
            read("1/9999999999999999s"),
            (
                Err(NumberTooLarge),
                vec!["too large --rate unit".to_string()]
            )
        );
        assert_eq!(
            read("1/9999999999999999w"),
            (
                Err(NumberTooLarge),
                vec![
                    "unsupported --rate unit".to_string(),
                    "too large --rate unit".to_string()
                ]
            )
        );
    }

    /// `oct2nummax`, as the C tool reads `--create-file-mode`.
    #[test]
    fn octal_like_c() {
        use ParamError::*;
        for (given, read) in [
            ("0777", Ok(0o777)),
            ("644", Ok(0o644)),
            ("0", Ok(0)),
            ("0000000000000000000000000000007", Ok(7)),
            ("1000", Err(NumberTooLarge)),
            ("10000x", Err(NumberTooLarge)),
            ("0778", Err(BadNumeric)),
            ("7a", Err(BadNumeric)),
            ("8", Err(BadNumeric)),
            ("-1", Err(BadNumeric)),
            (" 7", Err(BadNumeric)),
            ("", Err(BadNumeric)),
        ] {
            assert_eq!(octal(given.as_bytes(), 0o777), read, "{given}");
        }
    }

    /// The one-pass reader takes the digits a base allows and refuses a
    /// value past `max` as `str_num_base` does: each digit checked before
    /// it is added, a `max` below the base included. Checked against the
    /// value read whole, for every string of up to four bytes from an
    /// alphabet of each base's edge digits and a non-digit, under maxima
    /// at and around the base and at the top of the range.
    #[test]
    fn reads_digits_as_c_against_every_max() {
        fn whole(s: &[u8], base: u8, max: u64) -> Result<(u64, usize), ()> {
            let digits = s
                .iter()
                .take_while(|&&b| char::from(b).is_digit(u32::from(base)))
                .count();
            let mut n: u128 = 0;
            for &b in &s[..digits] {
                n = n * u128::from(base) + u128::from(char::from(b).to_digit(16).unwrap());
                if n > u128::from(max) {
                    return Err(());
                }
            }
            Ok((u64::try_from(n).unwrap(), digits))
        }
        const ALPHABET: &[u8] = b"0179aFg";
        let mut strings: Vec<Vec<u8>> = vec![Vec::new()];
        let mut last = strings.clone();
        for _ in 0..4 {
            let next: Vec<Vec<u8>> = last
                .iter()
                .flat_map(|s| {
                    ALPHABET.iter().map(move |&b| {
                        let mut t = s.clone();
                        t.push(b);
                        t
                    })
                })
                .collect();
            strings.extend(next.iter().cloned());
            last = next;
        }
        strings.push(b"18446744073709551615".to_vec());
        strings.push(b"18446744073709551616".to_vec());
        strings.push(b"FFFFFFFFFFFFFFFF".to_vec());
        strings.push(b"1777777777777777777777".to_vec());
        for base in [8, 10, 16] {
            for max in [
                0,
                1,
                6,
                7,
                8,
                9,
                10,
                15,
                16,
                17,
                100,
                0o777,
                LONG_MAX,
                u64::MAX,
            ] {
                for s in &strings {
                    assert_eq!(
                        digits_up_to(s, base, max),
                        whole(s, base, max),
                        "{s:?} base {base} max {max}"
                    );
                }
            }
        }
    }

    #[test]
    fn unsigned_like_c() {
        assert_eq!(unsigned(b"0"), Ok(0));
        assert_eq!(unsigned(b"-0"), Ok(0));
        assert_eq!(unsigned(b"42"), Ok(42));
        assert_eq!(unsigned(b"9223372036854775807"), Ok(LONG_MAX));
        assert_eq!(
            unsigned(b"9223372036854775808"),
            Err(ParamError::BadNumeric)
        );
        assert_eq!(unsigned(b"-3"), Err(ParamError::NegativeNumeric));
        assert_eq!(unsigned(b"3x"), Err(ParamError::BadNumeric));
        assert_eq!(unsigned(b""), Err(ParamError::BadNumeric));
        assert_eq!(unsigned(b"+3"), Err(ParamError::BadNumeric));
        assert_eq!(unsigned(b" 3"), Err(ParamError::BadNumeric));
    }

    #[test]
    fn seconds_like_c() {
        assert_eq!(seconds_as_millis(b"2"), Ok(2000));
        assert_eq!(seconds_as_millis(b"2.5"), Ok(2500));
        assert_eq!(seconds_as_millis(b"0.05"), Ok(50));
        assert_eq!(seconds_as_millis(b"1.123456789123"), Ok(1123));
        assert_eq!(seconds_as_millis(b"2abc"), Ok(2000));
        assert_eq!(seconds_as_millis(b"abc"), Err(ParamError::BadNumeric));
        assert_eq!(seconds_as_millis(b"-1"), Err(ParamError::BadNumeric));
        assert_eq!(seconds_as_millis(b"1."), Err(ParamError::NumberTooLarge));
        // Test 746: 22222242222222222 seconds is more than C allows.
        assert_eq!(
            seconds_as_millis(b"22222242222222222"),
            Err(ParamError::BadNumeric)
        );
        assert_eq!(
            seconds_as_millis(b"9223372036854774"),
            Ok(9_223_372_036_854_774_000)
        );
        assert_eq!(
            seconds_as_millis(b"9223372036854775"),
            Err(ParamError::BadNumeric)
        );
    }

    const WORDS: &[&[u8]] = &[
        b"0",
        b"1",
        b"9",
        b"10",
        b"9223372036854775807",
        b"9223372036854775808",
        b"99999999999999999999",
        b"-",
        b"+",
        b".",
        b"5",
        b"000000000000000000001",
        b"k",
        b"M",
        b"g",
        b"T",
        b"p",
        b"b",
        b"x",
        b" ",
        b"\0",
    ];
    const NUMBERS: &[&[u8]] = &[b"12", b"-3", b"1.5", b"2.25G", b"0.0000000001", b"7k"];

    proptest::proptest! {
        #![proptest_config(crate::untrusted::config(512))]

        /// Any argument is a number in range or is refused, by each way
        /// of reading one.
        #[test]
        fn any_argument_is_a_number_or_refused(
            s in crate::untrusted::input(WORDS, NUMBERS, 8),
        ) {
            const MAX: u64 = i64::MAX as u64;
            if let Ok(n) = unsigned(&s) {
                proptest::prop_assert!(n <= MAX);
            }
            signed(&s).ok();
            if let Ok(n) = offset(&s) {
                proptest::prop_assert!(n <= MAX);
            }
            if let Ok(n) = seconds_as_millis(&s) {
                proptest::prop_assert!(n <= MAX);
            }
            if let Ok(n) = size(&s) {
                proptest::prop_assert!(n <= MAX);
            }
        }
    }
}

/// The counterpart of `tests/perf/numparser.c`: its numbers, caps, loop
/// count and output lines, timing the rewrite's parsers. Decimal is
/// `leading_number` (`curlx_str_number`) and octal is `octal`
/// (`oct2nummax`, which also refuses what follows the digits). The
/// rewrite has no capped hexadecimal reader: as the chunked decoder
/// reads a chunk size, the hex digits are taken, then parsed with
/// `from_str_radix` and the cap applied. Run by
/// `inventory/measure/perf.py` from a release build of the tool's tests
/// (`--ignored --exact options::number::perf::numparser --nocapture`).
#[cfg(test)]
mod perf {
    use std::hint::black_box;
    use std::time::Instant;

    /// `tests/perf/numparser.c`'s default loop count.
    const LOOPS: u64 = 500_000;

    /// `nums[]`: the text, its base and the largest value taken.
    const NUMS: &[(&[u8], u32, i64)] = &[
        (b"9223372036854775807", 10, 9223372036854775807),
        (b"123456789123456123A", 10, 9223372036854775807),
        (b"123456789123456123B", 10, 9223372036854775807),
        (b"123456789123456123C", 10, 9223372036854775807),
        (b"123456789123456123D", 10, 9223372036854775807),
        (b"1234567891234561234", 10, 9223372036854775807),
        (b"123456789123456123", 10, 9223372036854775807),
        (b"12345678912345612", 10, 9223372036854775807),
        (b"1234567891234561", 10, 9223372036854775807),
        (b"123456789123456", 10, 9223372036854775807),
        (b"12345678912345", 10, 9223372036854775807),
        (b"1234567891234", 10, 9223372036854775807),
        (b"123456789123", 10, 9223372036854775807),
        (b"12345678912", 10, 9223372036854775807),
        (b"1234567891", 10, 9223372036854775807),
        (b"123456789", 10, 9223372036854775807),
        (b"12345678", 10, 9223372036854775807),
        (b"1234567", 10, 9223372036854775807),
        (b"123456", 10, 9223372036854775807),
        (b"12345", 10, 9223372036854775807),
        (b"1234", 10, 9223372036854775807),
        (b"123", 10, 9223372036854775807),
        (b"12", 10, 9223372036854775807),
        (b"1", 10, 9223372036854775807),
        (b"9223372036854775807", 10, 9223372036854775806),
        (b"1234567891234561234", 10, 1234567891234561233),
        (b"234567891234561234", 10, 234567891234561233),
        (b"34567891234561234", 10, 34567891234561233),
        (b"4567891234561234", 10, 4567891234561233),
        (b"567891234561234", 10, 567891234561233),
        (b"67891234561234", 10, 67891234561233),
        (b"7891234561234", 10, 7891234561233),
        (b"891234561234", 10, 891234561233),
        (b"91234561234", 10, 91234561233),
        (b"1234561234", 10, 1234561233),
        (b"234561234", 10, 234561233),
        (b"34561234", 10, 34561233),
        (b"4561234", 10, 4561233),
        (b"7FFFFFFFFFFFFFFF", 16, 9223372036854775807),
        (b"7FFFFFFFFFFFFFFF", 16, 9223372036854775806),
        (b"7FFFFFFFFFFFFFFF", 16, 9223372036854775805),
        (b"7FFFFFFFFFFFFFFF", 16, 9223372036854775804),
        (b"7FFFFFFFFFFFFFFF", 16, 9223372036854775803),
        (b"7FFFFFFFFFFFFFFE", 16, 9223372036854775807),
        (b"7FFFFFFFFFFFFFFD", 16, 9223372036854775807),
        (b"7FFFFFFFFFFFFFFC", 16, 9223372036854775807),
        (b"7FFFFFFFFFFFFFFB", 16, 9223372036854775807),
        (b"7FFFFFFFFFFFFFFA", 16, 9223372036854775807),
        (b"7FFFFFFFFFFFFFF9", 16, 9223372036854775807),
        (b"7FFFFFFFFFFFFFFG", 16, 9223372036854775807),
        (b"GFFFFFFFFFFFFFF9", 16, 9223372036854775807),
        (b"HFFFFFFFFFFFFFF9", 16, 9223372036854775807),
        (b"IFFFFFFFFFFFFFF9", 16, 9223372036854775807),
        (b"KFFFFFFFFFFFFFF9", 16, 9223372036854775807),
        (b"1234567890123456", 16, 1311768467284833366),
        (b"123456789012345G", 16, 1311768467284833366),
        (b"123456789012345H", 16, 1311768467284833366),
        (b"123456789012345I", 16, 1311768467284833366),
        (b"123456789012345J", 16, 1311768467284833366),
        (b"123456789012345K", 16, 1311768467284833366),
        (b"234567890123456", 16, 1311768467284833366),
        (b"34567890123456", 16, 1311768467284833366),
        (b"4567890123456", 16, 1311768467284833366),
        (b"567890123456", 16, 1311768467284833366),
        (b"567890123456", 16, 1311768467284833366),
        (b"67890123456", 16, 1311768467284833366),
        (b"7890123456", 16, 1311768467284833366),
        (b"890123456", 16, 1311768467284833366),
        (b"90123456", 16, 1311768467284833366),
        (b"0123456", 16, 1311768467284833366),
        (b"123456", 16, 1311768467284833366),
        (b"23456", 16, 1311768467284833366),
        (b"3456", 16, 1311768467284833366),
        (b"456", 16, 1311768467284833366),
        (b"56", 16, 1311768467284833366),
        (b"6", 16, 1311768467284833366),
        (b"1234567890123456", 16, 1311768467284833365),
        (b"234567890123456", 16, 158846962677986389),
        (b"34567890123456", 16, 14731774602130517),
        (b"4567890123456", 16, 1220975720019029),
        (b"67890123456", 16, 7114882954325),
        (b"7890123456", 16, 517813187669),
        (b"890123456", 16, 36776850517),
        (b"90123456", 16, 2417112149),
        (b"0123456", 16, 1193045),
        (b"123456", 16, 1193045),
        (b"23456", 16, 144469),
        (b"10", 10, 5),
        (b"9", 10, 5),
        (b"8", 10, 5),
        (b"7", 10, 5),
        (b"3", 10, 5),
        (b"2", 10, 5),
        (b"1", 10, 5),
        (b"10", 16, 8),
        (b"9", 16, 8),
        (b"8", 16, 8),
        (b"7", 16, 6),
        (b"3", 16, 7),
        (b"2", 16, 5),
        (b"1", 16, 5),
        (b"777777777777777777777", 8, 9223372036854775807),
        (b"777777777777777777776", 8, 9223372036854775807),
        (b"777777777777777777775", 8, 9223372036854775807),
        (b"777777777777777777774", 8, 9223372036854775807),
        (b"777777777777777777773", 8, 9223372036854775807),
        (b"777777777777777777772", 8, 9223372036854775807),
        (b"777777777777777777779", 8, 9223372036854775807),
        (b"123456701234567012345", 8, 1505851632739161317),
        (b"12345670123456701234", 8, 1505851632739161317),
        (b"1234567012345670123", 8, 1505851632739161317),
        (b"123456701234567012", 8, 1505851632739161317),
        (b"12345670123456701", 8, 1505851632739161317),
        (b"1234567012345670", 8, 1505851632739161317),
        (b"123456701234567", 8, 1505851632739161317),
        (b"12345670123456", 8, 1505851632739161317),
        (b"1234567012345", 8, 1505851632739161317),
        (b"123456701234", 8, 1505851632739161317),
        (b"12345670123", 8, 1505851632739161317),
        (b"1234567012", 8, 1505851632739161317),
        (b"123456701", 8, 1505851632739161317),
        (b"123456701234567012345", 8, 1505851632739161316),
        (b"23456701234567012345", 8, 352930128132314340),
        (b"3456701234567012345", 8, 64699751980602596),
        (b"456701234567012345", 8, 10656556452156644),
        (b"56701234567012345", 8, 1649357197415652),
        (b"6701234567012345", 8, 241982313862372),
        (b"701234567012345", 8, 30876081329380),
        (b"01234567012345", 8, 89755751652),
        (b"1234567012345", 8, 89755751652),
        (b"234567012345", 8, 21036274916),
        (b"34567012345", 8, 3856405732),
        (b"4567012345", 8, 635180260),
        (b"567012345", 8, 98309348),
        (b"67012345", 8, 14423268),
        (b"123456701234567012348", 8, 1505851632739161316),
        (b"123456701234567012349", 8, 1505851632739161316),
        (b"12345670123456701234A", 8, 1505851632739161316),
        (b"12345670123456701234C", 8, 1505851632739161316),
        (b"12345670123456701234B", 8, 1505851632739161316),
    ];

    /// `curlx_str_hex`: the tool reads no hex argument of its own, so the
    /// benchmark reads it with the same one-pass reader.
    fn hex(s: &[u8], max: u64) -> Option<u64> {
        let (n, digits) = super::digits_up_to(s, 16, max).ok()?;
        (digits > 0).then_some(n)
    }

    #[test]
    #[ignore = "a benchmark, run by inventory/measure/perf.py"]
    fn numparser() {
        println!("Found {} numbers to parse", NUMS.len());
        let mut count: u64 = 0;
        let mut errors: u64 = 0;
        let start = Instant::now();
        for _ in 0..LOOPS {
            for &(s, base, max) in black_box(NUMS) {
                let max = max.unsigned_abs();
                let ok = match base {
                    10 => super::leading_number(s, max).is_some(),
                    16 => hex(s, max).is_some(),
                    _ => super::octal(s, max).is_ok(),
                };
                if !black_box(ok) {
                    errors += 1;
                }
                count += 1;
            }
        }
        let us = u64::try_from(start.elapsed().as_micros()).unwrap();
        let hn = us * 1_000_000 / count;
        println!("Numbers:   {count}");
        println!("Time:      {us} usecs");
        println!("Time/num:  {}.{:03} ns", hn / 1000, hn % 1000);
        let per_sec = (count * 1_000_000).checked_div(us).unwrap_or(0);
        println!("Nums/sec:  {per_sec}");
        println!("Errors:    {errors}");
    }
}
