//! C's own matcher (`lib/curl_fnmatch.c`), over the bytes of C strings:
//! a byte past the end reads as the zero that would end it. Built on every
//! platform, so its table is checked on each.
//!
//! Safe code alone, by construction: the module forbids `unsafe`.

#![forbid(unsafe_code)]

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
