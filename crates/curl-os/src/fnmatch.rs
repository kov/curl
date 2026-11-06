//! Matching a name against a shell pattern: the system's `fnmatch(3)`,
//! which C's build uses where it has one (`Curl_fnmatch` with
//! `HAVE_FNMATCH`), for FTP's wildcard downloads; on Windows, which has
//! none, C's own matcher, in safe code.

#![allow(unsafe_code)]

#[cfg(unix)]
use core::ffi::c_char;

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
            // SAFETY: both are zero-terminated and live for the call,
            // which only reads them.
            unsafe {
                libc::fnmatch(
                    pattern.as_ptr().cast::<c_char>(),
                    name.as_ptr().cast::<c_char>(),
                    0,
                )
            }
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

/// `f` given `bytes` up to its first zero byte, with one after: copied on
/// the stack if short enough, else to memory of its own.
#[cfg(unix)]
fn with_c_string<R>(bytes: &[u8], f: impl FnOnce(&[u8]) -> R) -> Result<R, OutOfMemory> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end <= ON_STACK {
        let mut buf = [0u8; ON_STACK + 1];
        buf[..end].copy_from_slice(&bytes[..end]);
        return Ok(f(&buf[..=end]));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(end + 1)?;
    out.try_extend_from_slice(&bytes[..end])?;
    out.try_extend_from_slice(&[0])?;
    Ok(f(&out))
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
mod own {
    use super::Matched;

    /// The bytes, then a flag for each of these after them.
    const NEGATE: usize = 256;
    const ALNUM: usize = 257;
    const DIGIT: usize = 258;
    const XDIGIT: usize = 259;
    const ALPHA: usize = 260;
    const PRINT: usize = 261;
    const BLANK: usize = 262;
    const LOWER: usize = 263;
    const GRAPH: usize = 264;
    const SPACE: usize = 265;
    const UPPER: usize = 266;

    /// A bracket expression's bytes and classes (`charset`).
    type Set = [bool; 256 + 15];

    /// Byte `i` of the C string `s`: zero at and past its end.
    fn at(s: &[u8], i: usize) -> u8 {
        s.get(i).copied().unwrap_or(0)
    }

    /// C's ASCII classes (`curl_ctype.h`), whatever the locale.
    fn is_print(c: u8) -> bool {
        (0x20..=0x7e).contains(&c)
    }

    fn is_graph(c: u8) -> bool {
        (0x21..=0x7e).contains(&c)
    }

    fn is_blank(c: u8) -> bool {
        c == b' ' || c == b'\t'
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Class {
        Other,
        Digit,
        Upper,
        Lower,
    }

    fn class(c: u8) -> Class {
        if c.is_ascii_uppercase() {
            Class::Upper
        } else if c.is_ascii_lowercase() {
            Class::Lower
        } else if c.is_ascii_digit() {
            Class::Digit
        } else {
            Class::Other
        }
    }

    /// The class named at `*i`, after `[:`, up to `:]` (`parsekeyword`):
    /// set in `set` and `*i` moved past it, or false if it names none.
    fn keyword(p: &[u8], i: &mut usize, set: &mut Set) -> bool {
        let mut word = [0u8; 10];
        let mut q = *i;
        let mut after_colon = false;
        let mut n = 0;
        loop {
            let c = at(p, q);
            q += 1;
            if n >= word.len() {
                return false;
            }
            if after_colon {
                if c != b']' {
                    return false;
                }
                break;
            }
            if c.is_ascii_lowercase() {
                word[n] = c;
            } else if c == b':' {
                after_colon = true;
            } else {
                return false;
            }
            n += 1;
        }
        let end = word.iter().position(|&b| b == 0).unwrap_or(word.len());
        let flag = match &word[..end] {
            b"digit" => DIGIT,
            b"alnum" => ALNUM,
            b"alpha" => ALPHA,
            b"xdigit" => XDIGIT,
            b"print" => PRINT,
            b"graph" => GRAPH,
            b"space" => SPACE,
            b"blank" => BLANK,
            b"upper" => UPPER,
            b"lower" => LOWER,
            _ => return false,
        };
        *i = q;
        set[flag] = true;
        true
    }

    /// The byte at `*i` into `set`, and a range from it if one follows
    /// within its class (`setcharorrange`).
    fn byte_or_range(p: &[u8], i: &mut usize, set: &mut Set) {
        let mut q = *i;
        *i += 1;
        let c = at(p, q);
        q += 1;
        set[usize::from(c)] = true;
        if !c.is_ascii_alphanumeric() || at(p, q) != b'-' {
            return;
        }
        q += 1;
        let cc = class(c);
        let mut end = at(p, q);
        q += 1;
        if end == b'\\' {
            end = at(p, q);
            q += 1;
        }
        if end >= c && class(end) == cc {
            let mut b = c;
            while b != end {
                b += 1;
                // A class's bytes need not run together.
                if class(b) == cc {
                    set[usize::from(b)] = true;
                }
            }
            *i = q;
        }
    }

    /// The bracket expression at `*i`, after its `[`, into `set`, `*i`
    /// left at its `]` (`setcharset`); false if it is not one.
    fn bracket(p: &[u8], i: &mut usize, set: &mut Set) -> bool {
        #[derive(PartialEq, Eq)]
        enum State {
            Default,
            RightBracket,
            RightThenLeft,
        }
        let mut state = State::Default;
        let mut something = false;
        *set = [false; 256 + 15];
        loop {
            let c = at(p, *i);
            if c == 0 {
                return false;
            }
            match state {
                State::Default => {
                    if c == b']' {
                        if something {
                            return true;
                        }
                        something = true;
                        state = State::RightBracket;
                        set[usize::from(c)] = true;
                        *i += 1;
                    } else if c == b'[' {
                        let mut q = *i + 1;
                        let named = at(p, q) == b':' && {
                            q += 1;
                            keyword(p, &mut q, set)
                        };
                        if named {
                            *i = q;
                        } else {
                            set[usize::from(c)] = true;
                            *i += 1;
                        }
                        something = true;
                    } else if c == b'^' || c == b'!' {
                        if something {
                            set[usize::from(c)] = true;
                        } else if set[NEGATE] {
                            set[usize::from(c)] = true;
                            something = true;
                        } else {
                            set[NEGATE] = true;
                        }
                        *i += 1;
                    } else if c == b'\\' {
                        *i += 1;
                        if at(p, *i) == 0 {
                            set[usize::from(b'\\')] = true;
                        } else {
                            byte_or_range(p, i, set);
                        }
                        something = true;
                    } else {
                        byte_or_range(p, i, set);
                        something = true;
                    }
                }
                State::RightBracket => {
                    if c == b'[' {
                        state = State::RightThenLeft;
                        set[usize::from(c)] = true;
                        *i += 1;
                    } else if c == b']' {
                        return true;
                    } else if is_print(c) {
                        set[usize::from(c)] = true;
                        *i += 1;
                        state = State::Default;
                    } else {
                        return false;
                    }
                }
                State::RightThenLeft => {
                    if c == b']' {
                        return true;
                    }
                    state = State::Default;
                    set[usize::from(c)] = true;
                    *i += 1;
                }
            }
        }
    }

    /// What one token of the pattern at `*pi` makes of the byte at `*si`
    /// (`matchtoken`): `Some(true)` and both moved past if it matches,
    /// `Some(false)` if not, `None` for a bracket expression that is none.
    fn token(p: &[u8], pi: &mut usize, s: &[u8], si: &mut usize) -> Option<bool> {
        let mut q = *pi;
        let b = at(s, *si);
        match at(p, q) {
            b'?' => {}
            b'\\' => {
                if at(p, q + 1) != 0 {
                    q += 1;
                }
                if b != at(p, q) {
                    return Some(false);
                }
            }
            b'[' => {
                let mut set: Set = [false; 256 + 15];
                let mut end = q + 1;
                if !bracket(p, &mut end, &mut set) {
                    return None;
                }
                // Only the first class asked for counts, as C tests them.
                let mut found = set[usize::from(b)]
                    || [
                        (ALNUM, b.is_ascii_alphanumeric()),
                        (ALPHA, b.is_ascii_alphabetic()),
                        (DIGIT, b.is_ascii_digit()),
                        (XDIGIT, b.is_ascii_hexdigit()),
                        (PRINT, is_print(b)),
                        // C's `[:space:]` is its blanks.
                        (SPACE, is_blank(b)),
                        (UPPER, b.is_ascii_uppercase()),
                        (LOWER, b.is_ascii_lowercase()),
                        (BLANK, is_blank(b)),
                        (GRAPH, is_graph(b)),
                    ]
                    .into_iter()
                    .find(|&(flag, _)| set[flag])
                    .is_some_and(|(_, is)| is);
                if set[NEGATE] {
                    found = !found;
                }
                if !found {
                    return Some(false);
                }
                *pi = end + 1;
                *si += 1;
                return Some(true);
            }
            c => {
                if c != b {
                    return Some(false);
                }
            }
        }
        *pi = q + 1;
        *si += 1;
        Some(true)
    }

    /// Whether `name` matches `pattern`, each up to a zero byte in it: a
    /// greedy match that goes back to the last `*`, at most two of them
    /// (`loop`).
    pub(super) fn matches(pattern: &[u8], name: &[u8]) -> Matched {
        let p = pattern.split(|&b| b == 0).next().unwrap_or_default();
        let s = name.split(|&b| b == 0).next().unwrap_or_default();
        let (mut pi, mut si) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        let mut stars_left = 2;
        while at(s, si) != 0 {
            if at(p, pi) == b'*' {
                if stars_left == 0 {
                    return Matched::NoMatch;
                }
                stars_left -= 1;
                loop {
                    pi += 1;
                    match at(p, pi) {
                        0 => return Matched::Match,
                        b'?' => {
                            if at(s, si) == 0 {
                                return Matched::NoMatch;
                            }
                            si += 1;
                        }
                        b'*' => {}
                        _ => break,
                    }
                }
                star = Some((pi, si));
            } else if at(p, pi) != 0 {
                let (mut np, mut ns) = (pi, si);
                match token(p, &mut np, s, &mut ns) {
                    None => return Matched::NoMatch,
                    Some(true) => {
                        (pi, si) = (np, ns);
                        continue;
                    }
                    Some(false) => {}
                }
                let Some((sp, ss)) = star else {
                    return Matched::NoMatch;
                };
                star = Some((sp, ss + 1));
                (pi, si) = (sp, ss + 1);
            } else if let Some((sp, ss)) = star {
                star = Some((sp, ss + 1));
                (pi, si) = (sp, ss + 1);
            } else {
                return Matched::NoMatch;
            }
        }
        while at(p, pi) == b'*' {
            if stars_left == 0 {
                return Matched::NoMatch;
            }
            stars_left -= 1;
            loop {
                pi += 1;
                match at(p, pi) {
                    b'?' => return Matched::NoMatch,
                    b'*' => {}
                    _ => break,
                }
            }
        }
        if at(p, pi) == 0 {
            Matched::Match
        } else {
            Matched::NoMatch
        }
    }
}

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

    /// C's unit test 1307's table, with the results it expects of Linux's
    /// `fnmatch`, in the C locale the tests run in: there a byte past
    /// ASCII is a character like any other, and the rows that fail in a
    /// UTF-8 locale give the table's portable result. macOS's `fnmatch`
    /// fails the rows `MACOS_FAILS` names, as measured on macOS 27 (C runs
    /// no test of it: 1307 is in `DISABLED`, the systems differing).
    #[test]
    #[cfg(unix)]
    fn unit1307_system_matcher() {
        /// The rows macOS's `fnmatch` fails: a bracket left open, a class
        /// it does not know, and a pattern ending in a backslash.
        const MACOS_FAILS: [usize; 6] = [0, 2, 3, 100, 101, 131];
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
            let want = if cfg!(target_vendor = "apple") && MACOS_FAILS.contains(&i) {
                Matched::Fail
            } else {
                want
            };
            assert_eq!(fnmatch(pattern, name).unwrap(), want, "row {i}");
        }
    }

    /// C's unit test 1307's table, with the results it expects of C's own
    /// matcher: the one Windows uses, checked here on each platform.
    #[test]
    fn unit1307_own_matcher() {
        let rows: &[(&[u8], &[u8], Matched)] = &[
            (b"*[*[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\x01\x7f[[[[[[[[[[[[[[[[[[[[[", b"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[", Matched::NoMatch),
            (b"\\[", b"[", Matched::Match),
            (b"[", b"[", Matched::NoMatch),
            (b"[]", b"[]", Matched::NoMatch),
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
            (b"[[:foo:]]", b"f]", Matched::Match),
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
            (b"*a*b*c", b"abc", Matched::NoMatch),
            (b"", b"", Matched::Match),
            (b"", b"hello", Matched::NoMatch),
            (b"file", b"", Matched::NoMatch),
            (b"?", b"", Matched::NoMatch),
            (b"*", b"", Matched::Match),
            (b"x", b"", Matched::NoMatch),
            (b"\\", b"\\", Matched::Match),
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
            assert_eq!(own::matches(pattern, name), want, "row {i}");
        }
        assert_eq!(own::matches(b"a*\0b", b"abc"), Matched::Match);
        assert_eq!(own::matches(b"abc", b"ab\0c"), Matched::NoMatch);
        // At most two stars are gone back to.
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
