//! Where a response's `Location:` leads (`lib/http.c`'s
//! `Curl_http_follow` and its helpers).

use crate::error::{ErrorKind, UrlErrorKind};
use crate::multi::state::url_error;
use crate::url::{GetOptions, ParseOptions, Part, SetOptions, Url};

/// Where `location` leads from `base`, the request's URL, for a response
/// not followed (`follow_parse_url` and `follow_fake`, `FOLLOW_FAKE`):
/// resolved against it, any scheme allowed, and read back without
/// credentials; or as the server gave it, if it does not resolve. Paths
/// keep their dot segments if `path_as_is`.
pub(crate) fn would_redirect(
    mut base: Url,
    location: &[u8],
    path_as_is: bool,
) -> Result<Vec<u8>, ErrorKind> {
    let any_scheme = ParseOptions {
        non_support_scheme: true,
        ..ParseOptions::NONE
    };
    let fake = SetOptions {
        parse: any_scheme,
        ..SetOptions::NONE
    };
    match base.set(Part::Url, Some(location), fake) {
        Ok(()) => {}
        Err(UrlErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(_) => return copied(location),
    }
    let url = base.get(Part::Url, GetOptions::NONE).map_err(url_error)?;
    // Without credentials if it reads back without them; as it is if not.
    let mut bare = Url::default();
    let reparse = SetOptions {
        parse: ParseOptions {
            path_as_is,
            ..any_scheme
        },
        ..SetOptions::NONE
    };
    let get_empty = GetOptions {
        get_empty: true,
        ..GetOptions::NONE
    };
    let stripped = bare
        .set(Part::Url, Some(&url), reparse)
        .and_then(|()| bare.set(Part::User, None, SetOptions::NONE))
        .and_then(|()| bare.set(Part::Password, None, SetOptions::NONE))
        .and_then(|()| bare.get(Part::Url, get_empty));
    Ok(stripped.unwrap_or(url))
}

fn copied(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut copy = Vec::new();
    curl_alloc::TryVec::try_extend_from_slice(&mut copy, bytes)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(copy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from(base: &str, location: &[u8]) -> String {
        let base = Url::parse(base.as_bytes(), ParseOptions::NONE).unwrap();
        String::from_utf8(would_redirect(base, location, false).unwrap()).unwrap()
    }

    #[test]
    fn resolves_against_the_request_without_credentials() {
        assert_eq!(
            from(
                "http://u:p@h/we/want/1029",
                b"data/10290002.txt?coolsite=yes"
            ),
            "http://h/we/want/data/10290002.txt?coolsite=yes"
        );
        // Any scheme, as C's FOLLOW_FAKE allows.
        assert_eq!(
            from("http://h/a", b"ldaps://other/x#frag"),
            "ldaps://other/x#frag"
        );
        // Read back as C reads it: an empty query left out.
        assert_eq!(from("http://h/a", b"/b/../c?"), "http://h/c");
        // One that does not resolve is kept as the server gave it.
        assert_eq!(from("http://h/a", b"http://a b/"), "http://a b/");
        // Spaces are encoded, as a relative URL's are.
        assert_eq!(from("http://h/a/b", b"c d"), "http://h/a/c%20d");
    }
}
