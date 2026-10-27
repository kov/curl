//! Where a response's `Location:` leads (`lib/http.c`'s
//! `Curl_http_follow` and its helpers).

use crate::error::{ErrorKind, UrlErrorKind, url_error};
use crate::options::{Method, PostRedir};
use crate::url::{GetOptions, ParseOptions, Part, SetOptions, Url};

/// What an HTTP request takes from the requests of its transfer before
/// it, beyond the method and the first origin, which any protocol's
/// does. The engine keeps it for HTTP between the requests and never
/// reads it.
#[derive(Debug)]
pub(crate) struct Inherited {
    /// The application's custom method is no longer sent
    /// (`state.http_ignorecustom`).
    pub(in crate::proto) ignore_custom: bool,
    /// A response said HTTP/1.0: so do the requests after it
    /// (`state.http_neg.rcvd_min`).
    pub(in crate::proto) http10: bool,
    /// A 417 refused `Expect: 100-continue`: the library adds it no more
    /// (`state.disableexpect`).
    pub(in crate::proto) no_expect: bool,
    /// The versions the requests may speak, as the last left them
    /// (`state.http_neg`).
    pub(in crate::proto) neg: crate::proto::http::Negotiation,
}

impl Inherited {
    /// What a transfer asking for `version` starts with.
    pub(crate) fn new(version: crate::options::HttpVersion) -> Inherited {
        Inherited {
            ignore_custom: false,
            http10: false,
            no_expect: false,
            neg: crate::proto::http::Negotiation::new(version),
        }
    }
}

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

/// `location` resolved against `base`, the request's URL, for a redirect
/// followed (`follow_parse_url`, `FOLLOW_REDIR`): what needs it encoded,
/// spaces allowed, and only a scheme this build knows.
pub(crate) fn resolve(
    mut base: Url,
    location: &[u8],
    path_as_is: bool,
) -> Result<Url, UrlErrorKind> {
    let follow = SetOptions {
        parse: ParseOptions {
            url_encode: true,
            allow_space: true,
            path_as_is,
            ..ParseOptions::NONE
        },
        ..SetOptions::NONE
    };
    base.set(Part::Url, Some(location), follow)?;
    Ok(base)
}

/// Whether a redirect with `code` turns a request with `method` into a
/// GET (`follow_switch_get`): a POST on a 301 or 302 unless `keep` says
/// otherwise, and anything on a 303 but a POST `keep` keeps.
pub(crate) fn switches_to_get(code: u16, method: Method, keep: PostRedir) -> bool {
    let post = method == Method::Post;
    match code {
        301 => post && !keep.post301,
        302 => post && !keep.post302,
        303 => !post || !keep.post303,
        _ => false,
    }
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
        // A scheme this build does not know still resolves, and loses
        // its credentials (the C build gives the same).
        assert_eq!(from("http://h/x", b"foo://u:p@h/a/../b"), "foo://h/b");
    }

    fn followed(location: &[u8], path_as_is: bool) -> String {
        let base = Url::parse(b"http://h/x", ParseOptions::NONE).unwrap();
        let url = resolve(base, location, path_as_is).unwrap();
        String::from_utf8(url.get(Part::Url, GetOptions::NONE).unwrap()).unwrap()
    }

    /// A redirect followed has spaces allowed and what needs it encoded,
    /// and keeps its dot segments if `path_as_is`; the C build requests
    /// the same paths.
    #[test]
    fn a_followed_location_is_encoded_as_c_encodes_it() {
        assert_eq!(followed(b"/a b/../c?x y", false), "http://h/c?x+y");
        assert_eq!(
            followed("/d/café/./e".as_bytes(), false),
            "http://h/d/caf%C3%A9/e"
        );
        assert_eq!(followed(b"http://h/a b?x y", false), "http://h/a%20b?x+y");
        assert_eq!(followed(b"http://h/a/../b", false), "http://h/b");
        assert_eq!(followed(b"http://h/a/../b", true), "http://h/a/../b");
    }
}
