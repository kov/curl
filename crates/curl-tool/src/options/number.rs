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

#[cfg(test)]
mod tests {
    use super::*;

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
