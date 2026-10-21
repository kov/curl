//! URLs, parsed and put back together as libcurl's URL API does
//! (`lib/urlapi.c`), so that the C ABI's `curl_url_*` and every transfer
//! read a URL the same way C does.
//!
//! Implemented: parsing a whole URL, resolving a relative one against it,
//! setting, clearing and appending to single parts, with every flag
//! `curl_url_set` takes, and getting any part back with every flag of
//! `curl_url_get`. The IDN conversions (`CURLU_PUNYCODE`,
//! `CURLU_PUNY2IDN`) need an IDN library, and fail with LacksIdn where
//! they would convert, as in C's build without one.

mod encode;

pub(crate) use encode::decode_but_zero;
mod host;
mod path;
#[rustfmt::skip]
mod schemes;
#[cfg(test)]
#[rustfmt::skip]
mod c_tests;


use crate::error::UrlErrorKind;
use encode::{Query, bad_octets, copy, push};

/// URL text: bytes, valid UTF-8 or not, without a terminating zero.
type Bytes = Vec<u8>;

/// `bytes` with every byte but letters, digits and `-._~` escaped as
/// `%XX` (`curl_easy_escape`).
pub fn escape(bytes: &[u8]) -> Result<Vec<u8>, curl_alloc::OutOfMemory> {
    encode::escape(bytes).map_err(|_| curl_alloc::OutOfMemory)
}

/// The longest URL C accepts (`CURL_MAX_INPUT_LENGTH`); its buffers also
/// stop just short of it.
pub const MAX_INPUT: usize = 8_000_000;

/// The scheme used when a URL has none and `default_scheme` is set.
const DEFAULT_SCHEME: &[u8] = b"https";

/// The longest scheme name looked for (`MAX_SCHEME_LEN`).
const MAX_SCHEME: usize = 40;

/// How a URL is parsed: the `CURLU_*` flags of `curl_url_set` that apply
/// to a whole URL.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParseOptions {
    /// `CURLU_DEFAULT_SCHEME`: a URL without a scheme is `https`.
    pub default_scheme: bool,
    /// `CURLU_GUESS_SCHEME`: a URL without a scheme gets one from its host
    /// name, `http` unless it starts with `ftp.`, `dict.` and the like.
    pub guess_scheme: bool,
    /// `CURLU_NON_SUPPORT_SCHEME`: accept schemes libcurl does not know.
    pub non_support_scheme: bool,
    /// `CURLU_NO_AUTHORITY`: the host may be empty.
    pub no_authority: bool,
    /// `CURLU_PATH_AS_IS`: keep `.` and `..` segments.
    pub path_as_is: bool,
    /// `CURLU_DISALLOW_USER`: reject a URL with credentials.
    pub disallow_user: bool,
    /// `CURLU_ALLOW_SPACE`: spaces are allowed, and encoded as needed.
    pub allow_space: bool,
    /// `CURLU_URLENCODE`: percent-encode the path, query and fragment.
    pub url_encode: bool,
}

impl ParseOptions {
    pub const NONE: ParseOptions = ParseOptions {
        default_scheme: false,
        guess_scheme: false,
        non_support_scheme: false,
        no_authority: false,
        path_as_is: false,
        disallow_user: false,
        allow_space: false,
        url_encode: false,
    };
}

/// How `Url::set` takes a part: the `CURLU_*` flags of `curl_url_set`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetOptions {
    /// How a whole URL is parsed; `url_encode` also encodes a part set
    /// alone.
    pub parse: ParseOptions,
    /// `CURLU_APPENDQUERY`: a query is added to the one there, after a `&`.
    pub append_query: bool,
    /// How the URL a relative one is resolved against is read back: C
    /// reads it with the flags it was given to set with.
    pub get: GetOptions,
}

impl SetOptions {
    pub const NONE: SetOptions = SetOptions {
        parse: ParseOptions::NONE,
        append_query: false,
        get: GetOptions::NONE,
    };
}

/// How a part is returned: the `CURLU_*` flags of `curl_url_get`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetOptions {
    /// `CURLU_DEFAULT_PORT`: the scheme's port when the URL has none.
    pub default_port: bool,
    /// `CURLU_NO_DEFAULT_PORT`: no port when it is the scheme's.
    pub no_default_port: bool,
    /// `CURLU_DEFAULT_SCHEME`: `https` when the URL has no scheme.
    pub default_scheme: bool,
    /// `CURLU_URLDECODE`: decode `%xx`, and `+` in the query.
    pub url_decode: bool,
    /// `CURLU_URLENCODE`: encode what needs it.
    pub url_encode: bool,
    /// `CURLU_GET_EMPTY`: an empty query or fragment is returned, and kept
    /// in the URL with its separator.
    pub get_empty: bool,
    /// `CURLU_NO_GUESS_SCHEME`: a guessed scheme counts as missing.
    pub no_guess_scheme: bool,
    /// `CURLU_PUNYCODE`: a host not in ASCII in its punycode form.
    pub punycode: bool,
    /// `CURLU_PUNY2IDN`: a host in ASCII with its punycode decoded.
    pub puny2idn: bool,
}

impl GetOptions {
    pub const NONE: GetOptions = GetOptions {
        default_port: false,
        no_default_port: false,
        default_scheme: false,
        url_decode: false,
        url_encode: false,
        get_empty: false,
        no_guess_scheme: false,
        punycode: false,
        puny2idn: false,
    };

    /// Whether the IDN conversions asked for would convert `host`: with
    /// no IDN library, an error (`host_decode`, `host_encode`).
    fn idn(&self, host: &[u8]) -> Result<(), UrlErrorKind> {
        let ascii = host.is_ascii();
        if (self.punycode && !ascii) || (self.puny2idn && ascii) {
            return Err(UrlErrorKind::LacksIdn);
        }
        Ok(())
    }
}

/// A part of a URL, as `CURLUPART_*` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Url,
    Scheme,
    User,
    Password,
    Options,
    Host,
    ZoneId,
    Port,
    Path,
    Query,
    Fragment,
}

#[derive(Debug, PartialEq, Eq)]
struct Scheme {
    /// Lowercase.
    name: Bytes,
    /// Guessed from the host name rather than given.
    guessed: bool,
}

/// A query or a fragment that is there: its separator alone, or text
/// (C's `query_present` or `fragment_present`, and the text or NULL).
#[derive(Debug, PartialEq, Eq)]
enum Tail {
    /// The separator with nothing after it: a fragment parsed from a bare
    /// `#`, or a part set empty with `url_encode`.
    Bare,
    /// What follows the separator; empty for a query parsed from a bare
    /// `?`, or a part set empty.
    Text(Bytes),
}

/// A parsed URL: each part as `struct Curl_URL` holds it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Url {
    scheme: Option<Scheme>,
    user: Option<Bytes>,
    password: Option<Bytes>,
    options: Option<Bytes>,
    host: Option<Bytes>,
    zone_id: Option<Bytes>,
    port: Option<u16>,
    path: Option<Bytes>,
    query: Option<Tail>,
    fragment: Option<Tail>,
}

impl Drop for Url {
    fn drop(&mut self) {
        // As C clears a password before freeing it.
        self.forget_credentials();
    }
}

/// The scheme of `url`, lowercase, if it starts with one: a letter, up to
/// 39 more letters, digits, `+`, `-` or `.`, then `:`. When guessing, `:`
/// must also be followed by `/`, since `host:80` has no scheme
/// (`Curl_is_absolute_url`).
fn scheme_of(url: &[u8], guessing: bool) -> Option<&[u8]> {
    if !url.first()?.is_ascii_alphabetic() {
        return None;
    }
    let len = 1 + url[1..]
        .iter()
        .take(MAX_SCHEME - 1)
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        .count();
    match url.get(len..) {
        Some([b':', b'/', ..]) => Some(&url[..len]),
        Some([b':', ..]) if !guessing => Some(&url[..len]),
        _ => None,
    }
}

/// Whether libcurl knows `scheme`, lowercase, built in or not
/// (`Curl_get_scheme`).
pub(crate) fn is_known_scheme(scheme: &[u8]) -> bool {
    schemes::KNOWN
        .binary_search_by(|k| k.name.as_bytes().cmp(scheme))
        .is_ok()
}

/// Whether `url` starts with a scheme, `:` and `/` (`Curl_is_absolute_url`
/// guessing).
pub(crate) fn has_scheme(url: &[u8]) -> bool {
    scheme_of(url, true).is_some()
}

/// The scheme `name` if libcurl knows it, built in or not.
fn known(name: &[u8]) -> Option<&'static schemes::Known> {
    schemes::KNOWN
        .iter()
        .find(|k| k.name.as_bytes().eq_ignore_ascii_case(name))
}

/// `s` starts with `prefix`, in any case (`checkprefix`).
fn starts_with_nocase(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// A Windows drive at the start of a `file:` path: a letter, `:` or `|`,
/// then a slash, a backslash or the end (`STARTS_WITH_URL_DRIVE_PREFIX`).
fn drive_prefix(s: &[u8]) -> bool {
    matches!(s, [l, b':' | b'|', rest @ ..]
        if l.is_ascii_alphabetic() && matches!(rest.first(), None | Some(b'/' | b'\\')))
}

impl Url {
    /// Parse `url` as `curl_url_set(CURLUPART_URL)` does.
    pub fn parse(url: &[u8], opts: ParseOptions) -> Result<Url, UrlErrorKind> {
        // C sees a NUL-terminated string: anything past a zero byte is not
        // part of the URL it was given.
        // An empty URL is valid only relative to one already set, which
        // `curl_url_set` resolves and parsing a fresh URL never sees.
        if url.is_empty() || url.len() > MAX_INPUT || url.contains(&0) {
            return Err(UrlErrorKind::MalformedInput);
        }
        let mut u = Url::default();
        let scheme = scheme_of(url, opts.guess_scheme || opts.default_scheme);
        let (path, is_file) = if scheme.is_some_and(|s| s.eq_ignore_ascii_case(b"file")) {
            (u.parse_file(url)?, true)
        } else {
            (u.parse_authority_part(url, scheme, opts)?, false)
        };
        // The path still holds the query and the fragment.
        let mut path = path;
        if let Some(at) = path.iter().position(|&b| b == b'#') {
            u.fragment = Some(if path.len() - at <= 1 {
                Tail::Bare
            } else {
                Tail::Text(part_after(
                    &path[at..],
                    opts,
                    Query::No,
                    UrlErrorKind::BadFragment,
                )?)
            });
            path = &path[..at];
        }
        if let Some(at) = path.iter().position(|&b| b == b'?') {
            u.query = Some(Tail::Text(part_after(
                &path[at..],
                opts,
                Query::Yes,
                UrlErrorKind::BadQuery,
            )?));
            path = &path[..at];
        }
        u.path = path_part(path, opts, is_file)?;
        Ok(u)
    }

    /// `parse_file`: a `file:` URL, the path it leaves.
    fn parse_file<'a>(&mut self, url: &'a [u8]) -> Result<&'a [u8], UrlErrorKind> {
        if url.len() <= 6 {
            return Err(UrlErrorKind::BadFileUrl);
        }
        let mut path = &url[5..];
        if path[0] != b'/' {
            return Err(UrlErrorKind::BadFileUrl);
        }
        if let Some(rest) = path.strip_prefix(b"//") {
            // An authority: empty, or localhost, or 127.0.0.1.
            path = if rest.first() == Some(&b'/') || drive_prefix(rest) {
                rest
            } else if starts_with_nocase(rest, b"localhost/")
                || starts_with_nocase(rest, b"127.0.0.1/")
            {
                &rest[9..]
            } else {
                return Err(UrlErrorKind::BadFileUrl);
            };
        }
        // Drive letters only mean something on Windows.
        if drive_prefix(path) || (path.first() == Some(&b'/') && drive_prefix(&path[1..])) {
            return Err(UrlErrorKind::BadFileUrl);
        }
        self.scheme = Some(Scheme {
            name: copy(b"file")?,
            guessed: false,
        });
        Ok(path)
    }

    /// `parse_scheme` and the authority: what follows the scheme up to the
    /// path, which is returned.
    fn parse_authority_part<'a>(
        &mut self,
        url: &'a [u8],
        scheme: Option<&[u8]>,
        opts: ParseOptions,
    ) -> Result<&'a [u8], UrlErrorKind> {
        let host_start = match scheme {
            Some(name) => {
                if known(name).is_none() && !opts.non_support_scheme {
                    return Err(UrlErrorKind::UnsupportedScheme);
                }
                let after = &url[name.len() + 1..];
                if after.first() != Some(&b'/') {
                    return Err(UrlErrorKind::BadSlashes);
                }
                let most = if opts.no_authority { 2 } else { 4 };
                let slashes = after.iter().take(most).take_while(|&&b| b == b'/').count();
                if !opts.no_authority && slashes > 3 {
                    return Err(UrlErrorKind::BadSlashes);
                }
                let mut lower = copy(name)?;
                lower.make_ascii_lowercase();
                self.scheme = Some(Scheme {
                    name: lower,
                    guessed: false,
                });
                name.len() + 1 + slashes
            }
            None => {
                if !(opts.default_scheme || opts.guess_scheme) {
                    return Err(UrlErrorKind::BadScheme);
                }
                if opts.default_scheme {
                    self.scheme = Some(Scheme {
                        name: copy(DEFAULT_SCHEME)?,
                        guessed: false,
                    });
                }
                0
            }
        };
        let rest = &url[host_start..];
        let host_len = rest
            .iter()
            .position(|&b| matches!(b, b'/' | b'?' | b'#'))
            .unwrap_or(rest.len());
        let (authority, path) = rest.split_at(host_len);
        if !authority.is_empty() {
            let host = self.parse_authority(authority, opts)?;
            if opts.guess_scheme && self.scheme.is_none() {
                let name: &[u8] = [
                    (&b"ftp."[..], &b"ftp"[..]),
                    (b"dict.", b"dict"),
                    (b"ldap.", b"ldap"),
                    (b"imap.", b"imap"),
                    (b"smtp.", b"smtp"),
                    (b"pop3.", b"pop3"),
                ]
                .into_iter()
                .find(|(prefix, _)| starts_with_nocase(&host, prefix))
                .map_or(b"http", |(_, name)| name);
                self.scheme = Some(Scheme {
                    name: copy(name)?,
                    guessed: true,
                });
            }
            self.host = Some(host);
        } else if opts.no_authority {
            self.host = Some(Bytes::new());
        } else {
            return Err(UrlErrorKind::NoHost);
        }
        Ok(path)
    }

    /// `parse_authority`: the credentials, host and port; returns the host.
    fn parse_authority(&mut self, auth: &[u8], opts: ParseOptions) -> Result<Bytes, UrlErrorKind> {
        let host_at = self.parse_login(auth, opts)?;
        let mut host = copy(&auth[host_at..])?;
        let port = parse_port(&mut host, self.scheme.is_some());
        if host.is_empty() {
            // A missing host outranks a bad port.
            return Err(UrlErrorKind::NoHost);
        }
        self.port = port?;
        if host.contains(&b'%') {
            host = encode::decode(&host)?.ok_or(UrlErrorKind::BadHostname)?;
        }
        if auth[host_at] == b'[' {
            self.zone_id = host::ipv6(&mut host)?;
        } else if let Some(a) = host::ipv4(&host) {
            host.clear();
            host::ipv4_text(&mut host, a)?;
        } else {
            host::check_name(&host)?;
        }
        Ok(host)
    }

    /// `parse_hostname_login`: `[user[:password][;options]]@` at the start
    /// of the authority; returns where the host starts.
    fn parse_login(&mut self, auth: &[u8], opts: ParseOptions) -> Result<usize, UrlErrorKind> {
        let Some(at) = auth.iter().position(|&b| b == b'@') else {
            return Ok(0);
        };
        let login = &auth[..at];
        let with_options = self
            .scheme
            .as_ref()
            .and_then(|s| known(&s.name))
            .is_some_and(|k| k.url_options);
        // `Curl_parse_login_details`: the password runs from the first `:`,
        // the options from the first `;`, each to the other or the end.
        let colon = login.iter().position(|&b| b == b':');
        let semi = with_options
            .then(|| login.iter().position(|&b| b == b';'))
            .flatten();
        let user_end = match (colon, semi) {
            (Some(c), Some(s)) => c.min(s),
            (Some(c), None) => c,
            (None, Some(s)) => s,
            (None, None) => login.len(),
        };
        let end_after = |from: usize, other: Option<usize>| match other {
            Some(o) if o > from => o,
            _ => login.len(),
        };
        if opts.disallow_user {
            return Err(UrlErrorKind::UserNotAllowed);
        }
        let user = copy(&login[..user_end])?;
        let password = colon
            .map(|c| copy(&login[c + 1..end_after(c, semi)]))
            .transpose()?;
        let options = semi
            .map(|s| &login[s + 1..end_after(s, colon)])
            .filter(|o| !o.is_empty())
            .map(copy)
            .transpose()?;
        if bad_octets(&user, opts.allow_space) {
            return Err(UrlErrorKind::BadUser);
        }
        if password
            .as_ref()
            .is_some_and(|p| bad_octets(p, opts.allow_space))
        {
            return Err(UrlErrorKind::BadPassword);
        }
        if options
            .as_ref()
            .is_some_and(|o| bad_octets(o, opts.allow_space))
        {
            return Err(UrlErrorKind::MalformedInput);
        }
        self.user = Some(user);
        self.password = password;
        self.options = options;
        Ok(at + 1)
    }

    /// A copy (`curl_url_dup`).
    pub fn try_clone(&self) -> Result<Url, UrlErrorKind> {
        let dup = |b: &Option<Bytes>| b.as_deref().map(copy).transpose();
        let tail = |t: &Option<Tail>| match t {
            None => Ok(None),
            Some(Tail::Bare) => Ok(Some(Tail::Bare)),
            Some(Tail::Text(t)) => Ok(Some(Tail::Text(copy(t)?))),
        };
        let scheme = match &self.scheme {
            Some(s) => Some(Scheme {
                name: copy(&s.name)?,
                guessed: s.guessed,
            }),
            None => None,
        };
        Ok(Url {
            scheme,
            user: dup(&self.user)?,
            password: dup(&self.password)?,
            options: dup(&self.options)?,
            host: dup(&self.host)?,
            zone_id: dup(&self.zone_id)?,
            port: self.port,
            path: dup(&self.path)?,
            query: tail(&self.query)?,
            fragment: tail(&self.fragment)?,
        })
    }

    /// Set part `what` to `value`, or clear it if `None`, as `curl_url_set`
    /// does. A whole URL replaces this one, or, if relative, is resolved
    /// against it. A part set alone is encoded or not, but not checked,
    /// but for the scheme, the port and the host.
    pub fn set(
        &mut self,
        what: Part,
        value: Option<&[u8]>,
        opts: SetOptions,
    ) -> Result<(), UrlErrorKind> {
        let Some(value) = value else {
            self.clear(what);
            return Ok(());
        };
        // C sees a NUL-terminated string.
        if value.len() > MAX_INPUT || value.contains(&0) {
            return Err(UrlErrorKind::MalformedInput);
        }
        match what {
            Part::Url => return self.set_url(value, opts),
            Part::Port => {
                self.port = Some(port_number(value)?);
                return Ok(());
            }
            Part::Scheme => {
                check_scheme(value, opts.parse.non_support_scheme)?;
                self.scheme = Some(Scheme {
                    name: copy(value)?,
                    guessed: false,
                });
                return Ok(());
            }
            // Gone whether or not the host is taken.
            Part::Host => self.zone_id = None,
            _ => {}
        }
        let url_encode = opts.parse.url_encode;
        let mut enc = Bytes::new();
        if what == Part::Path && value.first() != Some(&b'/') {
            push(&mut enc, b"/")?;
        }
        if url_encode {
            let query = what == Part::Query;
            let path = what == Part::Path;
            encode::encode_part(&mut enc, value, query, path, query && opts.append_query)?;
        } else {
            encode::uppercase_hex(&mut enc, value)?;
        }
        // C's buffer is no string until something is written to it: an
        // empty part encoded is set as missing.
        let text = if url_encode && enc.is_empty() {
            None
        } else {
            Some(enc)
        };
        match what {
            Part::Query => match text {
                Some(q) if opts.append_query => self.append_query(&q)?,
                Some(q) => self.query = Some(Tail::Text(q)),
                None => self.query = Some(Tail::Bare),
            },
            Part::Fragment => self.fragment = Some(text.map_or(Tail::Bare, Tail::Text)),
            Part::Host => {
                let host = match text {
                    Some(h) if !h.is_empty() => Some(self.checked_host(h, url_encode)?),
                    _ if !opts.parse.no_authority => return Err(UrlErrorKind::BadHostname),
                    empty => empty,
                };
                self.host = host;
            }
            Part::Password => {
                self.forget_password();
                self.password = text;
            }
            Part::User => self.user = text,
            Part::Options => self.options = text,
            Part::ZoneId => self.zone_id = text,
            Part::Path => self.path = text,
            Part::Url | Part::Port | Part::Scheme => unreachable!("set above"),
        }
        Ok(())
    }

    /// `urlset_clear`.
    fn clear(&mut self, what: Part) {
        match what {
            Part::Url => *self = Url::default(),
            Part::Scheme => self.scheme = None,
            Part::User => self.user = None,
            Part::Password => {
                self.forget_password();
                self.password = None;
            }
            Part::Options => self.options = None,
            Part::Host => self.host = None,
            Part::ZoneId => self.zone_id = None,
            Part::Port => self.port = None,
            Part::Path => self.path = None,
            Part::Query => self.query = None,
            Part::Fragment => self.fragment = None,
        }
    }

    /// `set_url`: a URL replaces this one, or a relative one is resolved
    /// against it.
    fn set_url(&mut self, url: &[u8], opts: SetOptions) -> Result<(), UrlErrorKind> {
        if url.is_empty() {
            // The same URL without its fragment (RFC 3986 section
            // 5.2.2), if this one is whole.
            return match self.get(Part::Url, opts.get) {
                Ok(_) => {
                    self.fragment = None;
                    Ok(())
                }
                Err(UrlErrorKind::OutOfMemory) => Err(UrlErrorKind::OutOfMemory),
                Err(_) => Err(UrlErrorKind::MalformedInput),
            };
        }
        let guessing = opts.parse.guess_scheme || opts.parse.default_scheme;
        if scheme_of(url, guessing).is_some() {
            *self = Url::parse(url, opts.parse)?;
            return Ok(());
        }
        // Empty separators are kept: they change where the relative URL
        // goes.
        let base_opts = GetOptions {
            get_empty: true,
            no_guess_scheme: false,
            ..opts.get
        };
        match self.get(Part::Url, base_opts) {
            Ok(base) => self.resolve(&base, url, opts.parse),
            Err(UrlErrorKind::OutOfMemory) => Err(UrlErrorKind::OutOfMemory),
            // Not whole: nothing to be relative to.
            Err(_) => {
                *self = Url::parse(url, opts.parse)?;
                Ok(())
            }
        }
    }

    /// `redirect_url`: `rel` resolved against `base`, this URL as text,
    /// replaces this one.
    fn resolve(&mut self, base: &[u8], rel: &[u8], opts: ParseOptions) -> Result<(), UrlErrorKind> {
        let scheme = self.scheme.as_ref().map_or(DEFAULT_SCHEME, |s| &s.name[..]);
        // Where the authority starts, after `scheme://`, which the base
        // was read back with.
        let host_at = scheme.len() + 3;
        assert!(base.len() >= host_at, "a whole URL starts with its scheme");
        let find = |b: u8| {
            base[host_at..]
                .iter()
                .position(|&c| c == b)
                .map(|i| host_at + i)
        };
        let (cutoff, rel, new_host) = match rel {
            [b'/', b'/', rest @ ..] => (Some(host_at), rest, true),
            [b'/', ..] => (find(b'/'), rel, false),
            [b'#', ..] => (self.fragment.as_ref().and_then(|_| find(b'#')), rel, false),
            _ => {
                let mut cutoff = if self.query.is_some() {
                    find(b'?')
                } else if self.fragment.is_some() {
                    find(b'#')
                } else {
                    None
                };
                if rel[0] != b'?' {
                    // After the last slash of the path.
                    let end = cutoff.unwrap_or(base.len());
                    cutoff = base[host_at..end]
                        .iter()
                        .rposition(|&c| c == b'/')
                        .map(|i| host_at + i + 1);
                }
                (cutoff, rel, false)
            }
        };
        let keep = cutoff.unwrap_or(base.len());
        let mut url = Bytes::new();
        let built = (|| {
            push(&mut url, &base[..keep])?;
            let mut rest = rel;
            if new_host {
                let host_end = host_sep(rel);
                push(&mut url, &rel[..host_end])?;
                rest = &rel[host_end..];
            }
            encode::reencode(&mut url, rest, Query::NotYet)
        })();
        // C reports any failure to build it as out of memory.
        built.map_err(|_| UrlErrorKind::OutOfMemory)?;
        let opts = ParseOptions {
            path_as_is: false,
            ..opts
        };
        *self = Url::parse(&url, opts)?;
        Ok(())
    }

    /// `url_append_query`: `q` after the query there and a `&`, unless it
    /// ends with one.
    fn append_query(&mut self, q: &[u8]) -> Result<(), UrlErrorKind> {
        let old = match &self.query {
            Some(Tail::Text(old)) if !old.is_empty() => old,
            _ => {
                self.query = Some(Tail::Text(copy(q)?));
                return Ok(());
            }
        };
        let mut joined = Bytes::new();
        push(&mut joined, old)?;
        if old.last() != Some(&b'&') {
            push(&mut joined, b"&")?;
        }
        push(&mut joined, q)?;
        self.query = Some(Tail::Text(joined));
        Ok(())
    }

    /// `url_sethost`: `host` checked, as given or decoded, and an IPv4
    /// address in any form C reads written as four decimals. A bracketed
    /// address's zone id is taken; the host keeps its own text.
    fn checked_host(&mut self, host: Bytes, encoded: bool) -> Result<Bytes, UrlErrorKind> {
        let bad = |_| UrlErrorKind::BadHostname;
        let plain = if encoded {
            copy(&host)?
        } else {
            encode::decode(&host)?.ok_or(UrlErrorKind::BadHostname)?
        };
        if plain.first() == Some(&b'[') {
            let mut addr = plain;
            self.zone_id = host::ipv6(&mut addr).map_err(bad)?;
            return Ok(host);
        }
        host::check_name(&plain).map_err(bad)?;
        match host::ipv4(&plain) {
            Some(a) => {
                let mut dotted = Bytes::new();
                host::ipv4_text(&mut dotted, a)?;
                Ok(dotted)
            }
            None => Ok(host),
        }
    }

    /// Zero the password before it goes, as C does.
    fn forget_password(&mut self) {
        if let Some(p) = &mut self.password {
            p.fill(0);
            std::hint::black_box(p);
        }
    }

    /// Take out the user and the password, the password cleared first.
    pub(crate) fn forget_credentials(&mut self) {
        self.forget_password();
        self.user = None;
        self.password = None;
    }

    /// Part `what`, as `curl_url_get` returns it.
    pub fn get(&self, what: Part, opts: GetOptions) -> Result<Bytes, UrlErrorKind> {
        let mut opts = opts;
        let mut port_text = [0u8; 5];
        let (part, missing): (Option<&[u8]>, UrlErrorKind) = match what {
            Part::Url => return self.whole(opts),
            Part::Scheme => {
                opts.url_decode = false;
                if opts.no_guess_scheme && self.scheme.as_ref().is_some_and(|s| s.guessed) {
                    return Err(UrlErrorKind::NoScheme);
                }
                (
                    self.scheme.as_ref().map(|s| &s.name[..]),
                    UrlErrorKind::NoScheme,
                )
            }
            Part::User => (self.user.as_deref(), UrlErrorKind::NoUser),
            Part::Password => (self.password.as_deref(), UrlErrorKind::NoPassword),
            Part::Options => (self.options.as_deref(), UrlErrorKind::NoOptions),
            Part::Host => (self.host.as_deref(), UrlErrorKind::NoHost),
            Part::ZoneId => (self.zone_id.as_deref(), UrlErrorKind::NoZoneid),
            Part::Port => {
                opts.url_decode = false;
                (
                    self.port_for(opts).map(|p| decimal(&mut port_text, p)),
                    UrlErrorKind::NoPort,
                )
            }
            Part::Path => (
                Some(self.path.as_deref().unwrap_or(b"/")),
                UrlErrorKind::UnknownPart,
            ),
            Part::Query => (
                match &self.query {
                    Some(Tail::Text(q)) if !q.is_empty() || opts.get_empty => Some(&q[..]),
                    _ => None,
                },
                UrlErrorKind::NoQuery,
            ),
            Part::Fragment => (
                match &self.fragment {
                    Some(Tail::Text(f)) => Some(&f[..]),
                    Some(Tail::Bare) if opts.get_empty => Some(&b""[..]),
                    _ => None,
                },
                UrlErrorKind::NoFragment,
            ),
        };
        let part = part.ok_or(missing)?;
        // `urlget_format`
        let mut out = copy(part)?;
        if opts.url_decode {
            if what == Part::Query {
                for b in out.iter_mut().filter(|b| **b == b'+') {
                    *b = b' ';
                }
            }
            out = encode::decode(&out)?.ok_or(UrlErrorKind::Urldecode)?;
        }
        if opts.url_encode {
            let mut enc = Bytes::new();
            let query = if what == Part::Query {
                Query::Yes
            } else {
                Query::No
            };
            encode::reencode(&mut enc, &out, query)?;
            out = enc;
        } else if what == Part::Host {
            opts.idn(part)?;
        }
        Ok(out)
    }

    /// The port to show: the URL's, unless it is the scheme's and
    /// `no_default_port` asks to leave it out, or the scheme's if the URL
    /// has none and `default_port` asks for it.
    fn port_for(&self, opts: GetOptions) -> Option<u16> {
        let scheme = self.scheme.as_ref().and_then(|s| known(&s.name));
        match self.port {
            Some(p) if opts.no_default_port && scheme.is_some_and(|k| k.default_port == p) => None,
            Some(p) => Some(p),
            None if opts.default_port => scheme.map(|k| k.default_port),
            None => None,
        }
    }

    /// The whole URL (`urlget_url`).
    fn whole(&self, opts: GetOptions) -> Result<Bytes, UrlErrorKind> {
        // Each shown with its separator, or not at all.
        let fragment = match &self.fragment {
            Some(Tail::Text(f)) => Some(&f[..]),
            Some(Tail::Bare) if opts.get_empty => Some(&b""[..]),
            _ => None,
        };
        let query = match &self.query {
            Some(Tail::Text(q)) if !q.is_empty() || opts.get_empty => Some(&q[..]),
            Some(Tail::Bare) if opts.get_empty => Some(&b""[..]),
            _ => None,
        };
        // Room for the parts as they are and their separators, so a URL
        // that needs no encoding is read back in one allocation.
        let parts = [
            self.scheme.as_ref().map(|s| &s.name[..]),
            self.user.as_deref(),
            self.password.as_deref(),
            self.options.as_deref(),
            self.host.as_deref(),
            self.zone_id.as_deref(),
            self.path.as_deref(),
            query,
            fragment,
        ];
        let room = parts.iter().flatten().map(|p| p.len()).sum::<usize>() + 32;
        let mut out = Bytes::new();
        out.try_reserve_exact(room.min(MAX_INPUT))
            .map_err(|_| UrlErrorKind::OutOfMemory)?;
        let tail = |out: &mut Bytes| -> Result<(), UrlErrorKind> {
            if let Some(q) = query {
                push(out, b"?")?;
                push(out, q)?;
            }
            if let Some(f) = fragment {
                push(out, b"#")?;
                push(out, f)?;
            }
            Ok(())
        };
        if self
            .scheme
            .as_ref()
            .is_some_and(|s| s.name.eq_ignore_ascii_case(b"file"))
        {
            push(&mut out, b"file://")?;
            // A path cleared or never set prints as C prints a NULL.
            push(&mut out, self.path.as_deref().unwrap_or(b"(nil)"))?;
            tail(&mut out)?;
            return Ok(out);
        }
        let host = self.host.as_deref().ok_or(UrlErrorKind::NoHost)?;
        let scheme = match &self.scheme {
            Some(s) => &s.name[..],
            None if opts.default_scheme => DEFAULT_SCHEME,
            None => return Err(UrlErrorKind::NoScheme),
        };
        let known = known(scheme);
        // With the scheme's default port asked for, the scheme must be
        // known to have one; `port_for` only knows the URL's own scheme.
        let port = match self.port {
            Some(p) if opts.no_default_port && known.is_some_and(|k| k.default_port == p) => None,
            Some(p) => Some(p),
            None if opts.default_port => known.map(|k| k.default_port),
            None => None,
        };
        let options = self
            .options
            .as_deref()
            .filter(|_| known.is_none_or(|k| k.url_options));
        let shown_host = if host.first() == Some(&b'[') {
            match &self.zone_id {
                Some(zone) => {
                    let mut h = copy(&host[..host.len() - 1])?;
                    push(&mut h, b"%25")?;
                    push(&mut h, zone)?;
                    push(&mut h, b"]")?;
                    Some(h)
                }
                None => None,
            }
        } else if opts.url_encode {
            Some(encode::escape(host)?)
        } else {
            opts.idn(host)?;
            None
        };
        if !opts.no_guess_scheme || !self.scheme.as_ref().is_some_and(|s| s.guessed) {
            push(&mut out, scheme)?;
            push(&mut out, b"://")?;
        }
        if let Some(user) = &self.user {
            push(&mut out, user)?;
        }
        if let Some(password) = &self.password {
            push(&mut out, b":")?;
            push(&mut out, password)?;
        }
        if let Some(options) = options {
            push(&mut out, b";")?;
            push(&mut out, options)?;
        }
        if self.user.is_some() || self.password.is_some() || options.is_some() {
            push(&mut out, b"@")?;
        }
        push(&mut out, shown_host.as_deref().unwrap_or(host))?;
        if let Some(p) = port {
            let mut text = [0u8; 5];
            push(&mut out, b":")?;
            push(&mut out, decimal(&mut text, p))?;
        }
        push(&mut out, self.path.as_deref().unwrap_or(b"/"))?;
        tail(&mut out)?;
        Ok(out)
    }
}

/// Where the host of `url` ends, after any `//`: at its first `/` or `?`
/// (`find_host_sep`).
fn host_sep(url: &[u8]) -> usize {
    let start = url
        .windows(2)
        .position(|w| w == b"//")
        .map_or(0, |at| at + 2);
    start
        + url[start..]
            .iter()
            .position(|&b| matches!(b, b'/' | b'?'))
            .unwrap_or(url.len() - start)
}

/// A port set alone: decimal digits, at most 65535 (`set_url_port`).
fn port_number(s: &[u8]) -> Result<u16, UrlErrorKind> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return Err(UrlErrorKind::BadPortNumber);
    }
    let mut port: u32 = 0;
    for &d in s {
        port = port * 10 + u32::from(d - b'0');
        if port > 0xffff {
            return Err(UrlErrorKind::BadPortNumber);
        }
    }
    Ok(u16::try_from(port).expect("checked above"))
}

/// A scheme set alone (`set_url_scheme`): one this build implements, or
/// with `any` one well formed, `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn check_scheme(s: &[u8], any: bool) -> Result<(), UrlErrorKind> {
    if s.is_empty() || s.len() > MAX_SCHEME {
        return Err(UrlErrorKind::BadScheme);
    }
    let found = known(s);
    if !any && !found.is_some_and(|k| k.built) {
        return Err(UrlErrorKind::UnsupportedScheme);
    }
    let well_formed = s[0].is_ascii_alphabetic()
        && s[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    if found.is_none() && !well_formed {
        return Err(UrlErrorKind::BadScheme);
    }
    Ok(())
}

/// `p` in decimal, in `buf`.
fn decimal(buf: &mut [u8; 5], mut p: u16) -> &[u8] {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (p % 10) as u8;
        p /= 10;
        if p == 0 {
            return &buf[at..];
        }
    }
}

/// `parse_port`: take the port off the end of `host`. `Ok(None)` when
/// there is none, or only a `:` and the URL has a scheme.
fn parse_port(host: &mut Bytes, has_scheme: bool) -> Result<Option<u16>, UrlErrorKind> {
    let colon = if host.first() == Some(&b'[') {
        let close = host[1..]
            .iter()
            .position(|&b| b == b']')
            .ok_or(UrlErrorKind::BadIpv6)?
            + 2;
        match host.get(close) {
            None => None,
            Some(b':') => Some(close),
            Some(_) => return Err(UrlErrorKind::BadPortNumber),
        }
    } else {
        host.iter().position(|&b| b == b':')
    };
    let Some(colon) = colon else {
        return Ok(None);
    };
    let digits = copy(&host[colon + 1..])?;
    host.truncate(colon);
    if digits.is_empty() {
        return if has_scheme {
            Ok(None)
        } else {
            Err(UrlErrorKind::BadPortNumber)
        };
    }
    let n = digits.iter().take_while(|b| b.is_ascii_digit()).count();
    match digits.get(n) {
        // A backslash ends the digits, first or not.
        Some(b'\\') => return Err(UrlErrorKind::Backslash),
        Some(_) => return Err(UrlErrorKind::BadPortNumber),
        None => {}
    }
    let mut port: u32 = 0;
    for &d in &digits {
        port = port * 10 + u32::from(d - b'0');
        if port > 0xffff {
            return Err(UrlErrorKind::BadPortNumber);
        }
    }
    Ok(Some(u16::try_from(port).expect("checked above")))
}

/// The query or fragment after its `?` or `#` (`handle_query`,
/// `handle_fragment`). Empty when there is nothing after it.
fn part_after(
    s: &[u8],
    opts: ParseOptions,
    query: Query,
    bad: UrlErrorKind,
) -> Result<Bytes, UrlErrorKind> {
    if s.len() <= 1 {
        return Ok(Bytes::new());
    }
    if opts.url_encode {
        let mut enc = Bytes::new();
        encode::reencode(&mut enc, &s[1..], query)?;
        return Ok(enc);
    }
    // C checks the separator too, which is never a bad byte.
    if bad_octets(s, opts.allow_space) {
        return Err(bad);
    }
    copy(&s[1..])
}

/// The path (`handle_path`): kept only if it is more than `/` (or, for
/// `file:`, more than nothing), checked, and with dot segments removed
/// unless `path_as_is`.
fn path_part(
    path: &[u8],
    opts: ParseOptions,
    is_file: bool,
) -> Result<Option<Bytes>, UrlErrorKind> {
    let mut encoded = None;
    if !path.is_empty() && opts.url_encode {
        let mut enc = Bytes::new();
        encode::reencode(&mut enc, path, Query::No)?;
        encoded = Some(enc);
    }
    let text = encoded.as_deref().unwrap_or(path);
    if text.len() < 1 + usize::from(!is_file) {
        return Ok(encoded);
    }
    if bad_octets(text, opts.allow_space) {
        return Err(UrlErrorKind::BadPath);
    }
    let kept = match encoded {
        Some(e) => e,
        None => copy(path)?,
    };
    if opts.path_as_is {
        return Ok(Some(kept));
    }
    Ok(Some(path::remove_dot_segments(&kept)?.unwrap_or(kept)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The C code of `kind`.
    fn code(kind: UrlErrorKind) -> usize {
        1 + UrlErrorKind::ALL
            .iter()
            .position(|&k| k == kind)
            .expect("every kind is listed")
    }

    /// The parts of `u` as lib1560's `checkparts` prints them. C prints
    /// into 256 bytes; no row is that long, and one that were would fail
    /// here rather than compare truncated.
    fn checkparts(u: &Url, opts: GetOptions) -> Vec<u8> {
        let parts = [
            Part::Scheme,
            Part::User,
            Part::Password,
            Part::Options,
            Part::Host,
            Part::Port,
            Part::Path,
            Part::Query,
            Part::Fragment,
        ];
        let mut out = Vec::new();
        for (i, part) in parts.into_iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b" | ");
            }
            match u.get(part, opts) {
                Ok(p) => {
                    out.extend_from_slice(&p);
                    if part == Part::Host
                        && p.first() == Some(&b'[')
                        && let Ok(z) = u.get(Part::ZoneId, opts)
                    {
                        out.push(b' ');
                        out.extend_from_slice(&z);
                    }
                }
                Err(e) => out.extend_from_slice(format!("[{}]", code(e)).as_bytes()),
            }
        }
        out
    }

    fn show(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    /// lib1560's `get_parts`: every row's parts, or its error.
    #[test]
    fn lib1560_get_parts() {
        let mut failed = Vec::new();
        for case in c_tests::PARTS {
            let got = Url::parse(case.url, case.parse).map(|u| checkparts(&u, case.get));
            let ok = match (&got, case.code) {
                (Ok(parts), None) => parts == case.expect,
                (Err(e), Some(c)) => *e == c,
                _ => false,
            };
            if !ok {
                failed.push(format!(
                    "{:?}: got {:?}, C {:?}",
                    show(case.url),
                    got.map(|p| show(&p)),
                    case.code.ok_or_else(|| show(case.expect))
                ));
            }
        }
        assert!(
            failed.is_empty(),
            "{} of {} rows differ:\n{}",
            failed.len(),
            c_tests::PARTS.len(),
            failed.join("\n")
        );
    }

    /// lib1560's `get_url`: every row's URL, or its error.
    #[test]
    fn lib1560_get_url() {
        let mut failed = Vec::new();
        for case in c_tests::URLS {
            let got = Url::parse(case.url, case.parse).and_then(|u| u.get(Part::Url, case.get));
            let ok = match (&got, case.code) {
                (Ok(url), None) => url == case.expect,
                (Err(e), Some(c)) => *e == c,
                _ => false,
            };
            if !ok {
                failed.push(format!(
                    "{:?}: got {:?}, C {:?}",
                    show(case.url),
                    got.map(|p| show(&p)),
                    case.code.ok_or_else(|| show(case.expect))
                ));
            }
        }
        assert!(
            failed.is_empty(),
            "{} of {} rows differ:\n{}",
            failed.len(),
            c_tests::URLS.len(),
            failed.join("\n")
        );
    }

    /// lib1560's `updateurl`: each `part=value,` of `cmds` set in turn,
    /// `NULL` clearing the part and `""` setting it empty; the first error.
    fn updateurl(u: &mut Url, cmds: &[u8], opts: SetOptions) -> Result<(), UrlErrorKind> {
        let mut rest = cmds;
        // A command counts only with its comma, as C reads them.
        while let Some(comma) = rest.iter().position(|&b| b == b',') {
            let cmd = &rest[..comma];
            rest = &rest[comma + 1..];
            // `sscanf("%79[^=]=%79[^,]")`: both sides not empty.
            let Some(eq) = cmd.iter().position(|&b| b == b'=') else {
                continue;
            };
            let (name, value) = (&cmd[..eq], &cmd[eq + 1..]);
            if name.is_empty() || value.is_empty() {
                continue;
            }
            assert!(name.len() < 80 && value.len() < 80, "C reads at most 79");
            let part = match name {
                b"url" => Part::Url,
                b"scheme" => Part::Scheme,
                b"user" => Part::User,
                b"password" => Part::Password,
                b"options" => Part::Options,
                b"host" => Part::Host,
                b"port" => Part::Port,
                b"path" => Part::Path,
                b"query" => Part::Query,
                b"fragment" => Part::Fragment,
                b"zoneid" => Part::ZoneId,
                other => panic!("unknown part {}", show(other)),
            };
            let value = match value {
                b"NULL" => None,
                b"\"\"" => Some(&b""[..]),
                v => Some(v),
            };
            u.set(part, value, opts)?;
        }
        Ok(())
    }

    /// lib1560's `set_url`: a URL, relative or not, set on one.
    #[test]
    fn lib1560_set_url() {
        let mut failed = Vec::new();
        for case in c_tests::REDIRECTS {
            let mut u = Url::default();
            let got = match u.set(Part::Url, Some(case.url), case.url_flags) {
                Ok(()) => u
                    .set(Part::Url, Some(case.rel), case.set_flags)
                    .and_then(|()| {
                        let get_empty = GetOptions {
                            get_empty: true,
                            ..GetOptions::NONE
                        };
                        u.get(Part::Url, get_empty)
                    }),
                Err(e) if Some(e) == case.code => continue,
                Err(e) => Err(e),
            };
            if got.as_deref() != Ok(case.expect) {
                failed.push(format!(
                    "{:?} + {:?}: got {:?}, C {:?}",
                    show(case.url),
                    show(case.rel),
                    got.map(|p| show(&p)),
                    show(case.expect)
                ));
            }
        }
        assert!(
            failed.is_empty(),
            "{} rows differ:\n{}",
            failed.len(),
            failed.join("\n")
        );
    }

    /// lib1560's `set_parts` and `setget_parts`: parts set on a URL, and
    /// the URL or the parts got back.
    #[test]
    fn lib1560_set_parts() {
        let mut failed = Vec::new();
        let tables = [(c_tests::SET_PARTS, false), (c_tests::SETGET_PARTS, true)];
        for (case, parts) in tables
            .iter()
            .flat_map(|(t, p)| t.iter().map(move |c| (c, *p)))
        {
            let mut u = Url::default();
            let set = match case.url {
                Some(url) => u.set(Part::Url, Some(url), case.url_flags),
                None => Ok(()),
            };
            let got = match set {
                Err(e) if Some(e) == case.url_code => continue,
                Err(e) => Err(e),
                Ok(()) => match updateurl(&mut u, case.cmds, case.set_flags) {
                    Err(e) if Some(e) == case.code => continue,
                    Err(e) => Err(e),
                    Ok(()) if parts => Ok(checkparts(&u, case.get)),
                    Ok(()) => u.get(Part::Url, GetOptions::NONE),
                },
            };
            let ok = case.code.is_none() && got.as_deref() == Ok(case.expect);
            if !ok {
                failed.push(format!(
                    "{:?} with {:?}: got {:?}, C {:?}",
                    case.url.map(show),
                    show(case.cmds),
                    got.map(|p| show(&p)),
                    case.code.ok_or_else(|| show(case.expect))
                ));
            }
        }
        assert!(
            failed.is_empty(),
            "{} rows differ:\n{}",
            failed.len(),
            failed.join("\n")
        );
    }

    /// lib1560's `append`: a query appended to a URL's.
    #[test]
    fn lib1560_append() {
        for case in c_tests::APPENDS {
            let mut u = Url::default();
            u.set(Part::Url, Some(case.url), case.url_flags).unwrap();
            let set = u.set(Part::Query, Some(case.query), case.set_flags);
            assert_eq!(set.err(), case.code, "{}", show(case.url));
            if case.code.is_none() {
                let got = u.get(Part::Url, GetOptions::NONE).unwrap();
                assert_eq!(show(&got), show(case.expect), "{}", show(case.url));
            }
        }
    }

    /// lib1560's `clear_url`: every part gone with the URL cleared.
    #[test]
    fn lib1560_clear_url() {
        let mut u = Url::default();
        for c in c_tests::CLEARS {
            u.set(c.part, Some(c.value), SetOptions::NONE).unwrap();
            u.set(Part::Url, None, SetOptions::NONE).unwrap();
            let got = u.get(c.part, GetOptions::NONE);
            assert_eq!(got.as_ref().err().copied(), c.code, "{:?}", c.part);
            if let (Ok(got), Some(expect)) = (got, c.expect) {
                assert_eq!(got, expect, "{:?}", c.part);
            }
        }
    }

    /// lib1560's `get_nothing` and `scopeid`, and what C gives where its
    /// tables do not look.
    #[test]
    fn sets_parts_as_c_does() {
        let none = SetOptions::NONE;
        let g = GetOptions::NONE;
        let u = Url::default();
        for (part, missing) in [
            (Part::Scheme, UrlErrorKind::NoScheme),
            (Part::Host, UrlErrorKind::NoHost),
            (Part::User, UrlErrorKind::NoUser),
            (Part::Password, UrlErrorKind::NoPassword),
            (Part::Options, UrlErrorKind::NoOptions),
            (Part::Query, UrlErrorKind::NoQuery),
            (Part::Fragment, UrlErrorKind::NoFragment),
            (Part::ZoneId, UrlErrorKind::NoZoneid),
        ] {
            assert_eq!(u.get(part, g), Err(missing), "{part:?}");
        }
        assert_eq!(u.get(Part::Path, g).unwrap(), b"/");

        let mut u = Url::default();
        let zoned = b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello.html";
        u.set(Part::Url, Some(zoned), none).unwrap();
        u.set(Part::Host, Some(b"[::1]"), none).unwrap();
        assert_eq!(u.get(Part::ZoneId, g), Err(UrlErrorKind::NoZoneid));
        assert_eq!(
            show(&u.get(Part::Url, g).unwrap()),
            "https://[::1]/hello.html"
        );
        u.set(Part::ZoneId, Some(b"eth1"), none).unwrap();
        u.set(Part::Host, Some(b"example.com"), none).unwrap();
        assert_eq!(u.get(Part::ZoneId, g), Err(UrlErrorKind::NoZoneid));
        u.set(Part::Host, Some(b"[fe80::20c:29ff:fe9c:409b%25eth0]"), none)
            .unwrap();
        assert_eq!(u.get(Part::ZoneId, g).unwrap(), b"eth0");
        // The host keeps its text, zone and all, as C's does.
        assert_eq!(
            show(&u.get(Part::Url, g).unwrap()),
            "https://[fe80::20c:29ff:fe9c:409b%25eth0%25eth0]/hello.html"
        );
        u.set(Part::ZoneId, Some(b"clown"), none).unwrap();
        assert_eq!(u.get(Part::ZoneId, g).unwrap(), b"clown");

        // An IPv4 address in any form is written in decimal.
        u.set(Part::Host, Some(b"0x7f.1"), none).unwrap();
        assert_eq!(u.get(Part::Host, g).unwrap(), b"127.0.0.1");
        // A port set alone: digits only, at most 65535.
        assert_eq!(u.set(Part::Port, Some(b"00080"), none), Ok(()));
        assert_eq!(u.get(Part::Port, g).unwrap(), b"80");
        for bad in [&b""[..], b"65536", b"8o", b" 80", b"+80"] {
            assert_eq!(
                u.set(Part::Port, Some(bad), none),
                Err(UrlErrorKind::BadPortNumber),
                "{}",
                show(bad)
            );
        }
        // A scheme set alone must be built, unless any is allowed.
        let any = SetOptions {
            parse: ParseOptions {
                non_support_scheme: true,
                ..ParseOptions::NONE
            },
            ..none
        };
        assert_eq!(
            u.set(Part::Scheme, Some(b"socks5"), none),
            Err(UrlErrorKind::UnsupportedScheme)
        );
        assert_eq!(u.set(Part::Scheme, Some(b"socks5"), any), Ok(()));
        assert_eq!(u.set(Part::Scheme, Some(b"x-y.z+1"), any), Ok(()));
        for bad in [&b"1x"[..], b"x_y", b"", &[b'a'; 41][..]] {
            assert_eq!(
                u.set(Part::Scheme, Some(bad), any),
                Err(UrlErrorKind::BadScheme),
                "{}",
                show(bad)
            );
        }
        assert_eq!(u.set(Part::Scheme, Some(b"HTTP"), none), Ok(()));
        assert_eq!(u.get(Part::Scheme, g).unwrap(), b"HTTP", "as given");

        // A part set empty with encoding is missing, its separator kept.
        let encode = SetOptions {
            parse: ParseOptions {
                url_encode: true,
                ..ParseOptions::NONE
            },
            ..none
        };
        let get_empty = GetOptions {
            get_empty: true,
            ..g
        };
        let mut u = Url::parse(b"http://h/p?q#f", ParseOptions::NONE).unwrap();
        u.set(Part::Query, Some(b""), encode).unwrap();
        u.set(Part::Fragment, Some(b""), encode).unwrap();
        u.set(Part::User, Some(b""), encode).unwrap();
        assert_eq!(u.get(Part::Query, get_empty), Err(UrlErrorKind::NoQuery));
        assert_eq!(u.get(Part::Fragment, get_empty).unwrap(), b"");
        assert_eq!(u.get(Part::User, g), Err(UrlErrorKind::NoUser));
        assert_eq!(show(&u.get(Part::Url, get_empty).unwrap()), "http://h/p?#");
        assert_eq!(show(&u.get(Part::Url, g).unwrap()), "http://h/p");
        // Without, it is there and empty: a fragment shows its `#`.
        u.set(Part::Fragment, Some(b""), none).unwrap();
        assert_eq!(u.get(Part::Fragment, g).unwrap(), b"");
        assert_eq!(show(&u.get(Part::Url, g).unwrap()), "http://h/p#");

        // A file: URL without a path prints C's NULL.
        let mut u = Url::parse(b"http://h", ParseOptions::NONE).unwrap();
        u.set(Part::Scheme, Some(b"FILE"), none).unwrap();
        assert_eq!(show(&u.get(Part::Url, g).unwrap()), "file://(nil)");

        // No IDN library: a conversion that would happen fails.
        let puny = GetOptions {
            punycode: true,
            ..g
        };
        let idn = GetOptions {
            puny2idn: true,
            ..g
        };
        let u = Url::parse("http://räksmörgås.se/".as_bytes(), ParseOptions::NONE).unwrap();
        assert_eq!(u.get(Part::Host, puny), Err(UrlErrorKind::LacksIdn));
        assert_eq!(u.get(Part::Url, puny), Err(UrlErrorKind::LacksIdn));
        assert!(u.get(Part::Host, idn).is_ok(), "nothing to decode");
        let u = Url::parse(b"http://xn--rksmrgs-5wao1o.se/", ParseOptions::NONE).unwrap();
        assert!(u.get(Part::Url, puny).is_ok(), "already ASCII");
        assert_eq!(u.get(Part::Host, idn), Err(UrlErrorKind::LacksIdn));
        let copy = u.try_clone().unwrap();
        assert_eq!(copy, u);

        // A relative URL resolved against a base read with the flags
        // given: the default port is written into the result.
        let default_port = SetOptions {
            get: GetOptions {
                default_port: true,
                ..g
            },
            ..none
        };
        let mut u = Url::parse(b"http://h/a/b", ParseOptions::NONE).unwrap();
        u.set(Part::Url, Some(b"c d?e f"), default_port).unwrap();
        assert_eq!(
            show(&u.get(Part::Url, g).unwrap()),
            "http://h:80/a/c%20d?e+f"
        );
        // A new host is taken as it is, the rest encoded.
        u.set(Part::Url, Some(b"//other/x y"), none).unwrap();
        assert_eq!(show(&u.get(Part::Url, g).unwrap()), "http://other/x%20y");
        assert_eq!(
            u.set(Part::Url, Some(b"//bad host/x y"), none),
            Err(UrlErrorKind::BadHostname)
        );
    }

    /// unit1395: dot segments removed as `dedotdotify` removes them.
    #[test]
    fn unit1395_dot_segments() {
        for &(input, expect) in c_tests::DOT_SEGMENTS {
            let got = path::remove_dot_segments(input).unwrap();
            assert_eq!(got.as_deref(), expect, "{:?}", show(input));
        }
    }

    /// Branches lib1560 does not reach, with what C's `curl_url_get` gives.
    #[test]
    fn branches_as_c_takes_them() {
        let get = |url: &str, part, parse, get| {
            Url::parse(url.as_bytes(), parse)
                .and_then(|u| u.get(part, get))
                .map(|b| show(&b))
        };
        let none = (ParseOptions::NONE, GetOptions::NONE);
        let (p, g) = none;
        assert_eq!(
            get("imap://user;@host/", Part::Options, p, g),
            Err(UrlErrorKind::NoOptions)
        );
        assert_eq!(
            get("imap://user;@host/", Part::Url, p, g).as_deref(),
            Ok("imap://user@host/")
        );
        assert_eq!(
            get("imap://user;x@host/", Part::Options, p, g).as_deref(),
            Ok("x")
        );
        let zone = format!("http://[fe80::1%25{}]/", "a".repeat(15));
        assert_eq!(
            get(&zone, Part::ZoneId, p, g).as_deref(),
            Ok(&"a".repeat(15)[..])
        );
        let zone = format!("http://[fe80::1%25{}]/", "a".repeat(16));
        assert_eq!(get(&zone, Part::ZoneId, p, g), Err(UrlErrorKind::BadIpv6));
        for drive in [
            "file:///c:/foo",
            "file://c:/foo",
            "file:/c:/foo",
            "file:c:/foo",
            "file:///c|/foo",
        ] {
            assert_eq!(
                get(drive, Part::Url, p, g),
                Err(UrlErrorKind::BadFileUrl),
                "{drive}"
            );
        }
        assert_eq!(
            get("file:///cc:/foo", Part::Path, p, g).as_deref(),
            Ok("/cc:/foo")
        );
        for local in ["file://localhost/a", "file://LocalHost/a"] {
            assert_eq!(get(local, Part::Url, p, g).as_deref(), Ok("file:///a"));
        }
        assert_eq!(
            get("file://localhostx/a", Part::Url, p, g),
            Err(UrlErrorKind::BadFileUrl)
        );
        // Parts C lets an application set one at a time.
        let mut u = Url::parse(b"http://h/", p).unwrap();
        u.password = Some(copy(b"pw").unwrap());
        assert_eq!(show(&u.get(Part::Url, g).unwrap()), "http://:pw@h/");
        let mut u = Url::parse(b"imap://h/", p).unwrap();
        u.options = Some(copy(b"opt").unwrap());
        assert_eq!(show(&u.get(Part::Url, g).unwrap()), "imap://;opt@h/");
        let mut u = Url::parse(b"http://h/", p).unwrap();
        u.scheme = None;
        assert_eq!(u.get(Part::Url, g), Err(UrlErrorKind::NoScheme));
        let default_scheme = GetOptions {
            default_scheme: true,
            ..GetOptions::NONE
        };
        assert_eq!(
            show(&u.get(Part::Url, default_scheme).unwrap()),
            "https://h/"
        );
        // The input limit, inclusive.
        let long = |n: usize| format!("http://h/{}", "a".repeat(n - 9));
        assert!(get(&long(MAX_INPUT), Part::Path, p, g).is_ok());
        assert_eq!(
            get(&long(MAX_INPUT + 1), Part::Path, p, g),
            Err(UrlErrorKind::MalformedInput)
        );
        assert_eq!(
            get("http://h/\0", Part::Path, p, g),
            Err(UrlErrorKind::MalformedInput)
        );
        let default_port = GetOptions {
            default_port: true,
            ..GetOptions::NONE
        };
        let no_default_port = GetOptions {
            no_default_port: true,
            ..GetOptions::NONE
        };
        let any_scheme = ParseOptions {
            non_support_scheme: true,
            ..ParseOptions::NONE
        };
        assert_eq!(
            get("http://h/", Part::Url, p, default_port).as_deref(),
            Ok("http://h:80/")
        );
        assert_eq!(
            get("foo://h/", Part::Url, any_scheme, default_port).as_deref(),
            Ok("foo://h/")
        );
        assert_eq!(
            get("http://h:80/", Part::Url, p, no_default_port).as_deref(),
            Ok("http://h/")
        );
    }

    #[test]
    fn parses_the_milestone_urls() {
        let guess = ParseOptions {
            guess_scheme: true,
            non_support_scheme: true,
            ..ParseOptions::NONE
        };
        let url = |s: &str| {
            let u = Url::parse(s.as_bytes(), guess).unwrap();
            String::from_utf8(u.get(Part::Url, GetOptions::NONE).unwrap()).unwrap()
        };
        assert_eq!(url("127.0.0.1:8990/22"), "http://127.0.0.1:8990/22");
        assert_eq!(
            url("http://127.0.0.1:8990?mooo/59"),
            "http://127.0.0.1:8990/?mooo/59"
        );
        assert_eq!(url("http://h/1109#test"), "http://h/1109#test");
        let u = Url::parse(b"http://:example@h/367", guess).unwrap();
        assert_eq!(u.get(Part::User, GetOptions::NONE).unwrap(), b"");
        assert_eq!(u.get(Part::Password, GetOptions::NONE).unwrap(), b"example");
        assert_eq!(
            Url::parse(b"htfp://h/none.htfml", ParseOptions::NONE).unwrap_err(),
            UrlErrorKind::UnsupportedScheme
        );
    }
}
