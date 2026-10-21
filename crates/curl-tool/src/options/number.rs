//! Numeric option arguments, read as `src/tool_paramhlp.c` reads them.

use super::ParamError;

/// C's `LONG_MAX` on the platforms in scope.
const LONG_MAX: u64 = i64::MAX.unsigned_abs();

/// The leading decimal number of `s`, and what follows it, as
/// `curlx_str_number` reads it: at least one digit, no sign, no space, and
/// `None` above `max`.
fn leading_number(s: &[u8], max: u64) -> Option<(u64, &[u8])> {
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

/// A byte offset, as `str2offset` reads it: only digits, at most
/// `CURL_OFF_T_MAX`.
pub(crate) fn offset(s: &[u8]) -> Result<u64, ParamError> {
    match leading_number(s, LONG_MAX) {
        Some((n, b"")) => Ok(n),
        _ => Err(ParamError::BadNumeric),
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
            if prec > 0 {
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
}
