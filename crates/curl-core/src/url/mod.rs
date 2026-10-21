//! URLs, parsed and put back together as libcurl's URL API does
//! (`lib/urlapi.c`), so that the C ABI's `curl_url_*` and every transfer
//! read a URL the same way C does.
//!
//! Implemented: parsing a whole URL with every flag `curl_url_set` takes
//! for it, and getting any part back with every flag of `curl_url_get`
//! except the IDN conversions (`CURLU_PUNYCODE`, `CURLU_PUNY2IDN`), which
//! need an IDN library. Not yet: setting single parts, resolving a
//! relative URL against a base, and appending to the query.

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

/// The longest URL C accepts (`CURL_MAX_INPUT_LENGTH`); its buffers also
/// stop just short of it.
const MAX_INPUT: usize = 8_000_000;

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
    };
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
    /// Empty when the URL had a `?` and nothing after it.
    query: Option<Bytes>,
    /// Empty when the URL had a `#` and nothing after it.
    fragment: Option<Bytes>,
}

impl Drop for Url {
    fn drop(&mut self) {
        // As C clears a password before freeing it.
        if let Some(p) = &mut self.password {
            p.fill(0);
            std::hint::black_box(p);
        }
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
            u.fragment = Some(part_after(
                &path[at..],
                opts,
                Query::No,
                UrlErrorKind::BadFragment,
            )?);
            path = &path[..at];
        }
        if let Some(at) = path.iter().position(|&b| b == b'?') {
            u.query = Some(part_after(
                &path[at..],
                opts,
                Query::Yes,
                UrlErrorKind::BadQuery,
            )?);
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
                self.query
                    .as_deref()
                    .filter(|q| !q.is_empty() || opts.get_empty),
                UrlErrorKind::NoQuery,
            ),
            Part::Fragment => (
                self.fragment
                    .as_deref()
                    .filter(|f| !f.is_empty() || opts.get_empty),
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
        let fragment = self
            .fragment
            .as_deref()
            .filter(|f| !f.is_empty() || opts.get_empty);
        let query = self
            .query
            .as_deref()
            .filter(|q| !q.is_empty() || opts.get_empty);
        let mut out = Bytes::new();
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
        if self.scheme.as_ref().is_some_and(|s| s.name == b"file") {
            push(&mut out, b"file://")?;
            push(
                &mut out,
                self.path.as_deref().expect("a file: URL has a path"),
            )?;
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
