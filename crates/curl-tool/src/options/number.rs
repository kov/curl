//! Numeric option arguments, read as `src/tool_paramhlp.c` reads them.

use super::ParamError;

/// C's `LONG_MAX` on the platforms in scope.
const LONG_MAX: u64 = i64::MAX.unsigned_abs();

/// The leading decimal number of `s`, and what follows it, as
/// `curlx_str_number` reads it: at least one digit, no sign, no space, and
/// `None` above `max`.
pub(crate) fn leading_number(s: &[u8], max: u64) -> Option<(u64, &[u8])> {
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: u64 = 0;
    for &d in &s[..digits] {
        n = n.checked_mul(10)?.checked_add(u64::from(d - b'0'))?;
        if n > max {
            return None;
        }
    }
    Some((n, &s[digits..]))
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
    let digits = s.iter().take_while(|b| (b'0'..=b'7').contains(b)).count();
    if digits == 0 {
        return Err(ParamError::BadNumeric);
    }
    // Too large is found before anything after the digits.
    let mut n: u64 = 0;
    for &d in &s[..digits] {
        n = n * 8 + u64::from(d - b'0');
        if n > max {
            return Err(ParamError::NumberTooLarge);
        }
    }
    if digits != s.len() {
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
