//! Removing dot segments from a URL path (RFC 3986 section 5.2.4), as
//! `dedotdotify` in `lib/urlapi.c` does: `%2e` counts as a dot.

use super::Bytes;
use super::encode::push;
use crate::error::UrlErrorKind;

/// If `s` starts with a dot, plain or `%2e`, what follows it.
fn after_dot(s: &[u8]) -> Option<&[u8]> {
    match s {
        [b'.', rest @ ..] => Some(rest),
        [b'%', b'2', e, rest @ ..] if e | 0x20 == b'e' => Some(rest),
        _ => None,
    }
}

fn is_slash_or_end(s: &[u8]) -> bool {
    s.first().is_none_or(|&b| b == b'/')
}

/// Whether `p` has a `.` or `..` segment to remove (`needs_dedotdot`).
fn needs_work(mut p: &[u8]) -> bool {
    if p.len() < 2 || !p.iter().any(|&b| b == b'.' || b == b'%') {
        return false;
    }
    while !p.is_empty() {
        match after_dot(p) {
            Some(rest) if is_slash_or_end(rest) => return true,
            Some(rest) => match after_dot(rest) {
                Some(rest2) if is_slash_or_end(rest2) => return true,
                Some(rest2) => p = rest2,
                None => p = rest,
            },
            None => p = &p[1..],
        }
    }
    false
}

/// `path` with its dot segments removed, or `None` if it has none.
pub(super) fn remove_dot_segments(path: &[u8]) -> Result<Option<Bytes>, UrlErrorKind> {
    if !needs_work(path) {
        return Ok(None);
    }
    let mut out = Bytes::new();
    let mut input = path;
    // A leading "./" or "../" goes; a path of only ".." is empty.
    if let Some(rest) = after_dot(input) {
        if rest.first() == Some(&b'/') {
            input = &rest[1..];
        } else if let Some(rest2) = after_dot(rest) {
            if rest2.is_empty() {
                return Ok(Some(out));
            }
            if rest2[0] == b'/' {
                input = &rest2[1..];
            }
        }
    }
    while let Some(&b) = input.first() {
        if b == b'/'
            && let Some(p) = after_dot(&input[1..])
        {
            if p.is_empty() {
                // "/." at the end.
                push(&mut out, b"/")?;
                break;
            }
            if p[0] == b'/' {
                // "/./"
                input = p;
                continue;
            }
            if let Some(p2) = after_dot(p).filter(|p2| is_slash_or_end(p2)) {
                // "/../" or "/.." at the end: drop the last segment.
                if let Some(last) = out.iter().rposition(|&c| c == b'/') {
                    out.truncate(last);
                }
                if !p2.is_empty() {
                    input = p2;
                    continue;
                }
                push(&mut out, b"/")?;
                break;
            }
        }
        push(&mut out, &[b])?;
        input = &input[1..];
    }
    Ok(Some(out))
}
