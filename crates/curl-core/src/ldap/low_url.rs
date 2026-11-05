//! C's own LDAP URL parser (`lib/ldap.c`'s `ldap_url_parse_low`), for a
//! library that has none of its own, as WinLDAP has not: the search read
//! from the URL's path and query as the transfer has them, rather than
//! from the URL's text.

use curl_alloc::{OutOfMemory, TryVec as _};

use super::{Scope, Search};
use crate::error::UrlErrorKind;
use crate::url::{decode_but_control, decode_but_zero};

/// What is wrong with a URL, as C's parser says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LowUrlError {
    /// The URL is no search (`LDAP_INVALID_SYNTAX`): its path does not
    /// start with a slash, its scope is none C knows, or it ends in an
    /// empty extension.
    InvalidSyntax,
    /// A part did not decode, a zero byte in a name or a control byte in
    /// a filter among the reasons, was not UTF-8 where it must be, or
    /// memory ran out: C says all of them as it says the last
    /// (`LDAP_NO_MEMORY`).
    NoMemory,
}

impl From<OutOfMemory> for LowUrlError {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        LowUrlError::NoMemory
    }
}

/// The longest attribute C reads; one longer ends the list there
/// (`curlx_str_until`'s `max`).
const MAX_ATTRIBUTE: usize = 1024;

/// The search the URL with `path`, as it is encoded, and `query`, empty
/// where the URL ends in `?`, names (`ldap_url_parse2_low`):
/// `/<dn>?<attributes>?<scope>?<filter>?<extensions>`, every part
/// optional. The base is the path past its slash, decoded; the attributes
/// a comma-separated list, each decoded, the list ending at the first
/// empty or overlong one; the scope a word C knows, `base` if none; the
/// filter decoded; any extensions ignored, but an empty last part is an
/// error. With `utf8`, each part decoded must be UTF-8, as C's Unicode
/// build converts it to UTF-16 as it is read (`curlx_convert_UTF8_to_tchar`).
pub fn parse_url_low(path: &[u8], query: Option<&[u8]>, utf8: bool) -> Result<Search, LowUrlError> {
    let Some(dn) = path.strip_prefix(b"/") else {
        return Err(LowUrlError::InvalidSyntax);
    };
    let mut search = Search::default();
    if !dn.is_empty() {
        search.dn = Some(decoded(decode_but_zero(dn), utf8)?);
    }
    let Some(query) = query else {
        return Ok(search);
    };
    // Each part ends at the next `?`; `rest` is none past the last one.
    let mut rest = Some(query);
    let mut next = || {
        let part = rest?;
        Some(match part.iter().position(|&b| b == b'?') {
            Some(at) => {
                rest = Some(&part[at + 1..]);
                &part[..at]
            }
            None => {
                rest = None;
                part
            }
        })
    };
    let Some(attrs) = next() else {
        return Ok(search);
    };
    if !attrs.is_empty() {
        search.attrs = Some(attributes(attrs, utf8)?);
    }
    let Some(scope) = next() else {
        return Ok(search);
    };
    if !scope.is_empty() {
        search.scope = scope_of(scope).ok_or(LowUrlError::InvalidSyntax)?;
    }
    let Some(filter) = next() else {
        return Ok(search);
    };
    if !filter.is_empty() {
        search.filter = Some(decoded(decode_but_control(filter), utf8)?);
    }
    match next() {
        Some([]) => Err(LowUrlError::InvalidSyntax),
        _ => Ok(search),
    }
}

/// The attributes of the list `list`, each decoded, up to the first that
/// is empty or longer than C reads, and not past one not followed by a
/// comma.
fn attributes(list: &[u8], utf8: bool) -> Result<Vec<Vec<u8>>, LowUrlError> {
    let mut attrs = Vec::new();
    let mut at = list;
    loop {
        let len = at.iter().position(|&b| b == b',').unwrap_or(at.len());
        if len == 0 || len > MAX_ATTRIBUTE {
            break;
        }
        attrs.try_push(decoded(decode_but_zero(&at[..len]), utf8)?)?;
        match at.get(len) {
            Some(b',') => at = &at[len + 1..],
            _ => break,
        }
    }
    Ok(attrs)
}

/// A part as `Curl_urldecode` decoded it, and with `utf8` as it converts
/// to UTF-16: any failure, a byte refused or text that is not UTF-8
/// among them, is said as running out of memory.
fn decoded(
    part: Result<Option<Vec<u8>>, UrlErrorKind>,
    utf8: bool,
) -> Result<Vec<u8>, LowUrlError> {
    let part = part.ok().flatten().ok_or(LowUrlError::NoMemory)?;
    if utf8 && core::str::from_utf8(&part).is_err() {
        return Err(LowUrlError::NoMemory);
    }
    Ok(part)
}

/// The scope a word names, case aside (`str2scope`).
fn scope_of(word: &[u8]) -> Option<Scope> {
    let is = |w: &[u8]| word.eq_ignore_ascii_case(w);
    if is(b"one") || is(b"onetree") {
        Some(Scope::OneLevel)
    } else if is(b"base") {
        Some(Scope::Base)
    } else if is(b"sub") || is(b"subtree") {
        Some(Scope::Subtree)
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
