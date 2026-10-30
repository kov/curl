//! Matching a name against a shell pattern: the system's `fnmatch(3)`,
//! which C's build uses where it has one (`Curl_fnmatch` with
//! `HAVE_FNMATCH`), for FTP's wildcard downloads.

#![allow(unsafe_code)]

use core::ffi::c_char;

use curl_alloc::{OutOfMemory, TryVec as _};

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
pub fn fnmatch(pattern: &[u8], name: &[u8]) -> Result<Matched, OutOfMemory> {
    let pattern = c_string(pattern)?;
    let name = c_string(name)?;
    // SAFETY: both are zero-terminated and live for the call, which
    // only reads them.
    let rc = unsafe {
        libc::fnmatch(
            pattern.as_ptr().cast::<c_char>(),
            name.as_ptr().cast::<c_char>(),
            0,
        )
    };
    Ok(match rc {
        0 => Matched::Match,
        libc::FNM_NOMATCH => Matched::NoMatch,
        _ => Matched::Fail,
    })
}

/// `bytes` up to its first zero byte, with one after.
fn c_string(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let mut out = Vec::new();
    out.try_reserve_exact(end + 1)?;
    out.try_extend_from_slice(&bytes[..end])?;
    out.try_extend_from_slice(&[0])?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C's unit test 1307's table, with the results it expects of Linux's
    /// `fnmatch`, in the C locale the tests run in: there a byte past
    /// ASCII is a character like any other, and the rows that fail in a
    /// UTF-8 locale give the table's portable result.
    #[test]
    fn patterns_match_as_c_s_unit_test_expects_of_linux() {
        let rows: &[(&[u8], &[u8], Matched)] = &[
        (b"*[*[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\x01\x7f[[[[[[[[[[[[[[[[[[[[[", b"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[", Matched::NoMatch),
        (b"\\[", b"[", Matched::Match),
        (b"[", b"[", Matched::Match),
        (b"[]", b"[]", Matched::Match),
        (b"[][]", b"[", Matched::Match),
        (b"[][]", b"]", Matched::Match),
        (b"[[]", b"[", Matched::Match),
        (b"[[[]", b"[", Matched::Match),
        (b"[[[[]", b"[", Matched::Match),
        (b"[[[[]", b"[", Matched::Match),
        (b"[][[]", b"]", Matched::Match),
        (b"[][[[]", b"[", Matched::Match),
        (b"[[]", b"]", Matched::NoMatch),
        (b"[a@]", b"a", Matched::Match),
        (b"[a-z]", b"a", Matched::Match),
        (b"[a-z]", b"A", Matched::NoMatch),
        (b"?[a-z]", b"?Z", Matched::NoMatch),
        (b"[A-Z]", b"C", Matched::Match),
        (b"[A-Z]", b"c", Matched::NoMatch),
        (b"[0-9]", b"7", Matched::Match),
        (b"[7-8]", b"7", Matched::Match),
        (b"[7-]", b"7", Matched::Match),
        (b"[7-]", b"-", Matched::Match),
        (b"[7-]", b"[", Matched::NoMatch),
        (b"[a-bA-F]", b"F", Matched::Match),
        (b"[a-bA-B9]", b"9", Matched::Match),
        (b"[a-bA-B98]", b"8", Matched::Match),
        (b"[a-bA-B98]", b"C", Matched::NoMatch),
        (b"[a-bA-Z9]", b"F", Matched::Match),
        (b"[a-bA-Z9]ero*", b"Zero chance.", Matched::Match),
        (b"S[a-][x]opho*", b"Saxophone", Matched::Match),
        (b"S[a-][x]opho*", b"SaXophone", Matched::NoMatch),
        (b"S[a-][x]*.txt", b"S-x.txt", Matched::Match),
        (b"[\\a-\\b]", b"a", Matched::Match),
        (b"[\\a-\\b]", b"b", Matched::Match),
        (b"[?*[][?*[][?*[]", b"?*[", Matched::Match),
        (b"[][?*-]", b"]", Matched::Match),
        (b"[][?*-]", b"[", Matched::Match),
        (b"[][?*-]", b"?", Matched::Match),
        (b"[][?*-]", b"*", Matched::Match),
        (b"[][?*-]", b"-", Matched::Match),
        (b"[]?*-]", b"-", Matched::Match),
        (b"[\xff]", b"\xff", Matched::Match),
        (b"?/b/c", b"a/b/c", Matched::Match),
        (b"^_{}~", b"^_{}~", Matched::Match),
        (b"!#%+,-./01234567889", b"!#%+,-./01234567889", Matched::Match),
        (b"PQRSTUVWXYZ]abcdefg", b"PQRSTUVWXYZ]abcdefg", Matched::Match),
        (b":;=@ABCDEFGHIJKLMNO", b":;=@ABCDEFGHIJKLMNO", Matched::Match),
        (b"[!a]", b"b", Matched::Match),
        (b"[!a]", b"a", Matched::NoMatch),
        (b"[^a]", b"b", Matched::Match),
        (b"[^a]", b"a", Matched::NoMatch),
        (b"[^a-z0-9A-Z]", b"a", Matched::NoMatch),
        (b"[^a-z0-9A-Z]", b"-", Matched::Match),
        (b"curl[!a-z]lib", b"curl lib", Matched::Match),
        (b"curl[! ]lib", b"curl lib", Matched::NoMatch),
        (b"[! ][ ]", b"  ", Matched::NoMatch),
        (b"[! ][ ]", b"a ", Matched::Match),
        (b"*[^a].t?t", b"a.txt", Matched::NoMatch),
        (b"*[^a].t?t", b"ca.txt", Matched::NoMatch),
        (b"*[^a].t?t", b"ac.txt", Matched::Match),
        (b"*[^a]", b"", Matched::NoMatch),
        (b"[!\xff]", b"", Matched::NoMatch),
        (b"[!\xff]", b"\xff", Matched::NoMatch),
        (b"[!\xff]", b"a", Matched::Match),
        (b"[!?*[]", b"?", Matched::NoMatch),
        (b"[!!]", b"!", Matched::NoMatch),
        (b"[!!]", b"x", Matched::Match),
        (b"[[:alpha:]]", b"a", Matched::Match),
        (b"[[:alpha:]]", b"9", Matched::NoMatch),
        (b"[[:alnum:]]", b"a", Matched::Match),
        (b"[[:alnum:]]", b"[", Matched::NoMatch),
        (b"[[:alnum:]]", b"]", Matched::NoMatch),
        (b"[[:alnum:]]", b"9", Matched::Match),
        (b"[[:digit:]]", b"9", Matched::Match),
        (b"[[:xdigit:]]", b"9", Matched::Match),
        (b"[[:xdigit:]]", b"F", Matched::Match),
        (b"[[:xdigit:]]", b"G", Matched::NoMatch),
        (b"[[:upper:]]", b"U", Matched::Match),
        (b"[[:upper:]]", b"u", Matched::NoMatch),
        (b"[[:lower:]]", b"l", Matched::Match),
        (b"[[:lower:]]", b"L", Matched::NoMatch),
        (b"[[:print:]]", b"L", Matched::Match),
        (b"[[:print:]]", b"\x08", Matched::NoMatch),
        (b"[[:print:]]", b"\x08", Matched::NoMatch),
        (b"[[:print:]]", b"\x09", Matched::NoMatch),
        (b"[[:print:]]", b"\x0a", Matched::NoMatch),
        (b"[[:print:]]", b"\x0d", Matched::NoMatch),
        (b"[[:space:]]", b" ", Matched::Match),
        (b"[[:space:]]", b"x", Matched::NoMatch),
        (b"[[:graph:]]", b" ", Matched::NoMatch),
        (b"[[:graph:]]", b"x", Matched::Match),
        (b"[[:graph:]]", b"\x09", Matched::NoMatch),
        (b"[[:graph:]]", b"\x0d", Matched::NoMatch),
        (b"[[:blank:]]", b"\x09", Matched::Match),
        (b"[[:blank:]]", b" ", Matched::Match),
        (b"[[:blank:]]", b"\x0d", Matched::NoMatch),
        (b"[^[:blank:]]", b"\x09", Matched::NoMatch),
        (b"[^[:print:]]", b"\x08", Matched::Match),
        (b"[[:lower:]][[:lower:]]", b"ll", Matched::Match),
        (b"[[:foo:]]", b"bar", Matched::NoMatch),
        (b"[[:foo:]]", b"f]", Matched::NoMatch),
        (b"curl[[:blank:]];-)", b"curl ;-)", Matched::Match),
        (b"*[[:blank:]]*", b" ", Matched::Match),
        (b"*[[:blank:]]*", b"", Matched::NoMatch),
        (b"*[[:blank:]]*", b"hi, im_Pavel", Matched::Match),
        (b"Filename.dat", b"Filename.dat", Matched::Match),
        (b"*curl*", b"lets use curl!!", Matched::Match),
        (b"filename.txt", b"filename.dat", Matched::NoMatch),
        (b"*.txt", b"text.txt", Matched::Match),
        (b"*.txt", b"a.txt", Matched::Match),
        (b"*.txt", b".txt", Matched::Match),
        (b"*.txt", b"txt", Matched::NoMatch),
        (b"??.txt", b"99.txt", Matched::Match),
        (b"??.txt", b"a99.txt", Matched::NoMatch),
        (b"?.???", b"a.txt", Matched::Match),
        (b"*.???", b"somefile.dat", Matched::Match),
        (b"*.???", b"photo.jpeg", Matched::NoMatch),
        (b".*", b".htaccess", Matched::Match),
        (b".*", b".", Matched::Match),
        (b".*", b"..", Matched::Match),
        (b"**.txt", b"text.txt", Matched::Match),
        (b"***.txt", b"t.txt", Matched::Match),
        (b"****.txt", b".txt", Matched::Match),
        (b"*a*b*c", b"abc", Matched::Match),
        (b"", b"", Matched::Match),
        (b"", b"hello", Matched::NoMatch),
        (b"file", b"", Matched::NoMatch),
        (b"?", b"", Matched::NoMatch),
        (b"*", b"", Matched::Match),
        (b"x", b"", Matched::NoMatch),
        (b"\\", b"\\", Matched::NoMatch),
        (b"\\\\", b"\\", Matched::Match),
        (b"\\\\", b"\\\\", Matched::NoMatch),
        (b"\\?", b"?", Matched::Match),
        (b"\\*", b"*", Matched::Match),
        (b"?.txt", b"?.txt", Matched::Match),
        (b"*.txt", b"*.txt", Matched::Match),
        (b"\\?.txt", b"?.txt", Matched::Match),
        (b"\\*.txt", b"*.txt", Matched::Match),
        (b"\\?.txt", b"x.txt", Matched::NoMatch),
        (b"\\*.txt", b"x.txt", Matched::NoMatch),
        (b"\\*\\\\.txt", b"*\\.txt", Matched::Match),
        (b"*\\**\\?*\\\\*", b"cc*cc?cccc", Matched::NoMatch),
        (b"*\\?*\\**", b"cc?cc", Matched::NoMatch),
        (b"\\\"\\$\\&\\'\\(\\)", b"\"$&'()", Matched::Match),
        (b"\\*\\?\\[\\\\\\`\\|", b"*?[\\`|", Matched::Match),
        (b"[\\a\\b]c", b"ac", Matched::Match),
        (b"[\\a\\b]c", b"bc", Matched::Match),
        (b"[\\a\\b]d", b"bc", Matched::NoMatch),
        (b"[a-bA-B\\?]", b"?", Matched::Match),
        (b"cu[a-ab-b\\r]l", b"curl", Matched::Match),
        (b"[\\a-z]", b"c", Matched::Match),
        (b"?*?*?.*?*", b"abc.c", Matched::Match),
        (b"?*?*?.*?*", b"abcc", Matched::NoMatch),
        (b"?*?*?.*?*", b"abc.", Matched::NoMatch),
        (b"?*?*?.*?*", b"abc.c++", Matched::Match),
        (b"?*?*?.*?*", b"abcdef.c++", Matched::Match),
        (b"?*?*?.?", b"abcdef.c", Matched::Match),
        (b"?*?*?.?", b"abcdef.cd", Matched::NoMatch),
        (b"Lindm\xc3\xa4tarv", b"Lindm\xc3\xa4tarv", Matched::Match),
        (b"", b"", Matched::Match),
        (b"**]*[*[\x13]**[*\x13)]*]*[**[*\x13~r-]*]**[.*]*[\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3*[\x13]**[*\x13)]*]*[*[\x13]*[~r]*]*\xba\x13\xa6~b-]*", b"a", Matched::NoMatch),
        ];
        for (i, &(pattern, name, want)) in rows.iter().enumerate() {
            assert_eq!(fnmatch(pattern, name).unwrap(), want, "row {i}");
        }
    }

    /// A zero byte ends either, as it ends C's string.
    #[test]
    fn a_zero_byte_ends_the_pattern_and_the_name() {
        assert_eq!(fnmatch(b"a*\0b", b"abc").unwrap(), Matched::Match);
        assert_eq!(fnmatch(b"abc", b"abc\0d").unwrap(), Matched::Match);
        assert_eq!(fnmatch(b"abc", b"ab\0c").unwrap(), Matched::NoMatch);
    }
}
