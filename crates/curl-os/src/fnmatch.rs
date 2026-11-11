//! Matching a name against a shell pattern: the system's `fnmatch(3)`,
//! which C's build uses where it has one (`Curl_fnmatch` with
//! `HAVE_FNMATCH`), for FTP's wildcard downloads; on Windows, which has
//! none, C's own matcher, in safe code.

#![allow(unsafe_code)]

#[cfg(unix)]
use core::ffi::CStr;

use curl_alloc::OutOfMemory;
#[cfg(unix)]
use curl_alloc::TryVec as _;

/// How a name compares with a pattern (`CURL_FNMATCH_MATCH`,
/// `CURL_FNMATCH_NOMATCH`, `CURL_FNMATCH_FAIL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Matched {
    Match,
    NoMatch,
    /// The system could not tell: the pattern is too much for it.
    Fail,
}

/// Whether `name` matches `pattern`, as `fnmatch(pattern, name, 0)` says.
/// Each is taken up to a zero byte in it, as C's strings end there.
#[cfg(unix)]
pub fn fnmatch(pattern: &[u8], name: &[u8]) -> Result<Matched, OutOfMemory> {
    let rc = with_c_string(pattern, |pattern| {
        with_c_string(name, |name| {
            // SAFETY: both are C strings, zero-terminated by their type,
            // and live for the call, which only reads them.
            unsafe { libc::fnmatch(pattern.as_ptr(), name.as_ptr(), 0) }
        })
    })??;
    Ok(match rc {
        0 => Matched::Match,
        libc::FNM_NOMATCH => Matched::NoMatch,
        _ => Matched::Fail,
    })
}

/// The longest string copied on the stack, its zero byte not counted: a
/// listing's names and the patterns asked of them are mostly shorter,
/// and each is matched once per name.
#[cfg_attr(windows, allow(dead_code))]
const ON_STACK: usize = 255;

/// `f` given `bytes` up to its first zero byte as a C string: copied on
/// the stack if short enough, else to memory of its own.
#[cfg(unix)]
fn with_c_string<R>(bytes: &[u8], f: impl FnOnce(&CStr) -> R) -> Result<R, OutOfMemory> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    fn c(held: &[u8]) -> &CStr {
        CStr::from_bytes_with_nul(held).expect("one zero byte, at the end")
    }
    if end <= ON_STACK {
        let mut buf = [0u8; ON_STACK + 1];
        buf[..end].copy_from_slice(&bytes[..end]);
        return Ok(f(c(&buf[..=end])));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(end + 1)?;
    out.try_extend_from_slice(&bytes[..end])?;
    out.try_extend_from_slice(&[0])?;
    Ok(f(c(&out)))
}

/// Whether `name` matches `pattern`, as C's own matcher says where the
/// system has no `fnmatch` (`Curl_fnmatch` without `HAVE_FNMATCH`, as on
/// Windows). Each is taken up to a zero byte in it, as C's strings end
/// there. Nothing is allocated.
#[cfg(windows)]
pub fn fnmatch(pattern: &[u8], name: &[u8]) -> Result<Matched, OutOfMemory> {
    Ok(own::matches(pattern, name))
}

/// C's own matcher (`lib/curl_fnmatch.c`), over the bytes of C strings:
/// a byte past the end reads as the zero that would end it. Built on every
/// platform, so its table is checked on each.
#[cfg_attr(not(windows), allow(dead_code))]
mod own;

#[cfg(test)]
mod tests {
    use super::*;

    /// A string the stack cannot hold is matched as one it can: each
    /// side of the bound, a zero byte cutting it short.
    #[test]
    #[allow(clippy::disallowed_methods, clippy::disallowed_macros)]
    fn long_strings_match_as_short_ones() {
        for len in [ON_STACK - 1, ON_STACK, ON_STACK + 1, 4 * ON_STACK] {
            let mut name = vec![b'a'; len];
            name.push(b'z');
            assert_eq!(fnmatch(b"a*z", &name), Ok(Matched::Match), "{len}");
            let mut pattern = vec![b'a'; len];
            pattern.push(b'*');
            assert_eq!(fnmatch(&pattern, &name), Ok(Matched::Match), "{len}");
            pattern.extend_from_slice(b"\0y");
            name.extend_from_slice(b"\0y");
            assert_eq!(fnmatch(&pattern, &name), Ok(Matched::Match), "{len}");
            assert_eq!(fnmatch(b"*y", &name), Ok(Matched::NoMatch), "{len}");
        }
    }

    /// A row of unit1307's: the pattern, the name, the result of C's own
    /// matcher, and the systems' results where they differ.
    type Row1307 = (Vec<u8>, Vec<u8>, Matched, Vec<String>);

    /// unit1307's table, read from its source: each row's pattern, name
    /// and the result C expects of its own matcher, and of Linux's and
    /// macOS's `fnmatch` where they differ (`LINUX_MATCH`, `MAC_FAIL`).
    #[allow(clippy::disallowed_methods)]
    fn unit1307_rows() -> Vec<Row1307> {
        let rows = crate::c_source::table("tests/unit/unit1307.c", "tests[] =", |c| panic!("{c}"));
        rows.iter()
            .map(|row| {
                let [pattern, name, result] = row.group() else {
                    panic!("{row:?}")
                };
                let mut words = result.word().split('|').map(|w| w.trim().to_owned());
                let own = match words.next().as_deref() {
                    Some("MATCH") => Matched::Match,
                    Some("NOMATCH") => Matched::NoMatch,
                    other => panic!("{other:?}"),
                };
                (
                    pattern.str().to_vec(),
                    name.str().to_vec(),
                    own,
                    words.collect(),
                )
            })
            .collect()
    }

    /// unit1307's table, with the results C expects of Linux's `fnmatch`,
    /// in the C locale the tests run in: there a byte past ASCII is a
    /// character like any other, so a row C expects to fail in a UTF-8
    /// locale (`LINUX_FAIL`) gives its portable result. macOS's `fnmatch`
    /// fails the rows `MACOS_FAILS` names, as measured on macOS 27 (C runs
    /// no test of it: 1307 is in `DISABLED`, the systems differing).
    #[test]
    #[cfg(unix)]
    fn unit1307_system_matcher() {
        /// The rows macOS's `fnmatch` fails: a bracket left open, a class
        /// it does not know, and a pattern ending in a backslash.
        const MACOS_FAILS: [usize; 6] = [0, 2, 3, 100, 101, 131];
        let rows = unit1307_rows();
        assert_eq!(rows.len(), 163);
        for (i, (pattern, name, own, differ)) in rows.iter().enumerate() {
            let mut want = *own;
            for d in differ {
                match d.as_str() {
                    "LINUX_MATCH" => want = Matched::Match,
                    "LINUX_NOMATCH" => want = Matched::NoMatch,
                    "LINUX_FAIL" | "MAC_FAIL" | "MAC_MATCH" => {}
                    other => panic!("{other}"),
                }
            }
            if cfg!(target_vendor = "apple") && MACOS_FAILS.contains(&i) {
                want = Matched::Fail;
            }
            assert_eq!(fnmatch(pattern, name).unwrap(), want, "row {i}");
        }
    }

    /// unit1307's table, with the results C expects of its own matcher:
    /// the one Windows uses, checked here on each platform.
    #[test]
    fn unit1307_own_matcher() {
        let rows = unit1307_rows();
        assert_eq!(rows.len(), 163);
        for (i, (pattern, name, want, _)) in rows.iter().enumerate() {
            assert_eq!(own::matches(pattern, name), *want, "row {i}");
        }
    }

    /// A zero byte ends either, and at most two stars are gone back to.
    #[test]
    fn the_own_matcher_stops_at_a_zero_byte_and_two_stars() {
        assert_eq!(own::matches(b"a*\0b", b"abc"), Matched::Match);
        assert_eq!(own::matches(b"abc", b"ab\0c"), Matched::NoMatch);
        assert_eq!(own::matches(b"*a*b", b"xaxb"), Matched::Match);
        assert_eq!(own::matches(b"*a*b*c", b"xaxbxc"), Matched::NoMatch);
    }

    /// A zero byte ends either, as it ends C's string.
    #[test]
    fn a_zero_byte_ends_the_pattern_and_the_name() {
        assert_eq!(fnmatch(b"a*\0b", b"abc").unwrap(), Matched::Match);
        assert_eq!(fnmatch(b"abc", b"abc\0d").unwrap(), Matched::Match);
        assert_eq!(fnmatch(b"abc", b"ab\0c").unwrap(), Matched::NoMatch);
    }
}
