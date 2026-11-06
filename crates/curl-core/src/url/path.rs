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
    if p.len() < 2 {
        return false;
    }
    // Byte by byte, as C's loop goes, but straight to the next byte that
    // can start a dot: the bytes before it each only move it on.
    while let Some(at) = super::find_any(p, *b".%") {
        p = &p[at..];
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
    // Room for all of it: removing dot segments never lengthens a path.
    let mut out = Bytes::new();
    out.try_reserve_exact(path.len())
        .map_err(|_| UrlErrorKind::OutOfMemory)?;
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
        // The byte and the rest of its segment, up to the next `/`: only a
        // `/` starts a dot segment, so the bytes before one are kept.
        let end = 1 + super::find_byte(&input[1..], b'/').unwrap_or(input.len() - 1);
        push(&mut out, &input[..end])?;
        input = &input[end..];
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `needs_dedotdot` as C walks it, a byte at a time.
    fn needs_work_bytewise(mut p: &[u8]) -> bool {
        if p.len() < 2 || !p.iter().any(|b| matches!(b, b'.' | b'%')) {
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

    /// Removing dot segments a byte at a time, as C's `dedotdotify` does.
    fn remove_bytewise(path: &[u8]) -> Option<Vec<u8>> {
        if !needs_work_bytewise(path) {
            return None;
        }
        let mut out = Vec::new();
        let mut input = path;
        if let Some(rest) = after_dot(input) {
            if rest.first() == Some(&b'/') {
                input = &rest[1..];
            } else if let Some(rest2) = after_dot(rest) {
                if rest2.is_empty() {
                    return Some(out);
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
                    out.extend_from_slice(b"/");
                    break;
                }
                if p[0] == b'/' {
                    input = p;
                    continue;
                }
                if let Some(p2) = after_dot(p).filter(|p2| is_slash_or_end(p2)) {
                    if let Some(last) = out.iter().rposition(|&c| c == b'/') {
                        out.truncate(last);
                    }
                    if !p2.is_empty() {
                        input = p2;
                        continue;
                    }
                    out.extend_from_slice(b"/");
                    break;
                }
            }
            out.extend_from_slice(&[b]);
            input = &input[1..];
        }
        Some(out)
    }

    /// Every path of up to six bytes from those that make dot segments
    /// and the bytes around them, and longer ones built of their pieces:
    /// whether work is needed and what is left, segment at a time, as a
    /// byte at a time.
    #[test]
    fn removes_dot_segments_as_byte_by_byte() {
        let alphabet = b"./%2eEa";
        let mut paths: Vec<Vec<u8>> = vec![Vec::new()];
        for _ in 0..6 {
            let longer: Vec<Vec<u8>> = paths
                .iter()
                .filter(|p| p.len() == paths.last().unwrap().len())
                .flat_map(|p| {
                    alphabet.iter().map(move |&b| {
                        let mut q = p.clone();
                        q.push(b);
                        q
                    })
                })
                .collect();
            paths.extend(longer);
        }
        for pieces in [
            &[&b"/first"[..], b"/../", b"home"][..],
            &[b"/a/b/c", b"/./", b"%2E%2e", b"/", b"..", b"/x.html"],
            &[
                b"/very-long-segment-name",
                b"/.",
                b"%2e/",
                b"tail.",
                b"/..%2e/z",
            ],
        ] {
            paths.push(pieces.concat());
        }
        for path in &paths {
            assert_eq!(needs_work(path), needs_work_bytewise(path), "{path:?}");
            assert_eq!(
                remove_dot_segments(path).unwrap(),
                remove_bytewise(path),
                "{path:?}"
            );
        }
    }
}
