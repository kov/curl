//! The request head of HTTP/1 (`lib/http.c`'s `Curl_http`): what is sent,
//! in which order, and which of the application's headers go with it.

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::coding::{Coding, Decoders};
use crate::conn::Peer;
use crate::date::HttpDate;
use crate::error::ErrorKind;
use crate::handler::{Handler, LineSource};
use crate::options::{Listed, Ranged, Resume};
use crate::text::Text;
use std::fmt::Write as _;

use super::fields;

/// The most a request head may be, the terminating byte C's buffer keeps
/// for itself taken off (`DYN_HTTP_REQUEST`).
const MAX_HEAD: usize = 1024 * 1024 - 1;

/// The application's header line `line`, copied and classified.
fn header(line: &[u8]) -> Result<UserHeader, OutOfMemory> {
    let mut copy = Vec::new();
    copy.try_extend_from_slice(line)?;
    Ok(classify(copy))
}

/// The version an HTTP request is made in (`CURLOPT_HTTP_VERSION`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Version {
    Http10,
    #[default]
    Http11,
}

/// Whether what the application said for the first origin may go to the
/// one the request is for: the only way to the tokens that let a custom
/// Host, an Authorization or a Cookie into a request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CredentialGate {
    same: bool,
    trusted: bool,
}

/// The request is for the origin the transfer started with.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SameOrigin(());

/// Credentials may go to the request's origin (`Curl_auth_allowed_to_host`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Trusted(());

impl Trusted {
    /// Credentials the request's own URL carries go to its origin, which
    /// they were given for, wherever the transfer started
    /// (`url_set_data_creds`); so do those a `.netrc` entry gives for
    /// its host.
    pub(crate) fn own_url() -> Trusted {
        Trusted(())
    }
}

impl CredentialGate {
    /// The gate for the transfer's first request.
    pub(crate) const FIRST: CredentialGate = CredentialGate {
        same: true,
        trusted: true,
    };

    /// The gate for a request to `now` in a transfer that started at
    /// `initial`; `other_hosts` lets credentials follow it anywhere
    /// (`CURLOPT_UNRESTRICTED_AUTH`).
    pub(crate) fn new(initial: &Peer, now: &Peer, other_hosts: bool) -> CredentialGate {
        let same = initial == now;
        CredentialGate {
            same,
            trusted: same || other_hosts,
        }
    }

    pub(crate) fn same_origin(&self) -> Option<SameOrigin> {
        self.same.then_some(SameOrigin(()))
    }

    pub(crate) fn trusted(&self) -> Option<Trusted> {
        self.trusted.then_some(Trusted(()))
    }
}

/// The `Authorization` line a method sends: its name, and what follows
/// it. Only the gate's leave makes one, and only where the application
/// sends no Authorization of its own (`output_auth_headers`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Authorization<'a> {
    method: &'static str,
    value: &'a [u8],
}

impl<'a> Authorization<'a> {
    pub(crate) fn new(
        method: &'static str,
        value: &'a [u8],
        _: Trusted,
        headers: &UserHeaders,
    ) -> Option<Authorization<'a>> {
        (!headers.replaces(b"Authorization")).then_some(Authorization { method, value })
    }

    /// A `Proxy-Authorization` line, for a proxy, which the gate does not
    /// hold back.
    pub(crate) fn to_proxy(method: &'static str, value: &'a [u8]) -> Authorization<'a> {
        Authorization { method, value }
    }

    /// A line that goes even beside the application's own Authorization.
    pub(crate) fn alongside(
        method: &'static str,
        value: &'a [u8],
        _: Trusted,
    ) -> Authorization<'a> {
        Authorization { method, value }
    }
}

/// What one of the application's header lines asks for, decided once when
/// it is given (`Curl_add_custom_headers`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asks {
    /// `Name: value`: the line goes as it is.
    Value,
    /// `Name;`: the name goes with nothing after it.
    Blank,
    /// No colon, or nothing after it: the line itself goes nowhere, though
    /// its name still replaces a header of the library's.
    Nothing,
}

#[derive(Debug)]
struct UserHeader {
    line: Vec<u8>,
    /// Where the name is in `line`, its blanks trimmed.
    name: (usize, usize),
    asks: Asks,
}

impl UserHeader {
    fn name(&self) -> &[u8] {
        &self.line[self.name.0..self.name.1]
    }

    fn is(&self, name: &[u8]) -> bool {
        self.name().eq_ignore_ascii_case(name)
    }

    /// Whether the line replaces the library's header `name` (C's
    /// `Curl_checkheaders`): it starts with the name, untrimmed, then a
    /// colon or a semicolon.
    fn replaces(&self, name: &[u8]) -> bool {
        self.line.len() > name.len()
            && self.line[..name.len()].eq_ignore_ascii_case(name)
            && matches!(self.line[name.len()], b':' | b';')
    }

    /// The value after the name's colon or semicolon, its blanks trimmed,
    /// if there is one (C's `header_has_value`).
    fn value(&self) -> Option<&[u8]> {
        let at = self.line.iter().position(|&b| b == b':' || b == b';')?;
        let rest = &self.line[at + 1..];
        let end = rest
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .unwrap_or(rest.len());
        Some(trim(&rest[..end]))
    }
}

/// The headers the application adds (`CURLOPT_HTTPHEADER`), in the order
/// given: fixed, or read from a source again as each request starts.
#[derive(Debug, Default)]
pub struct UserHeaders {
    lines: Listed<UserHeader>,
}

impl UserHeaders {
    /// None at all.
    pub const NONE: UserHeaders = UserHeaders {
        lines: Listed::NONE,
    };

    /// The headers of `lines`, each as the application gave it.
    pub fn new<'a>(lines: impl IntoIterator<Item = &'a [u8]>) -> Result<UserHeaders, OutOfMemory> {
        let mut headers = Vec::new();
        for line in lines {
            headers.try_push(header(line)?)?;
        }
        Ok(UserHeaders {
            lines: Listed::Given(headers),
        })
    }

    /// The headers `source` gives, read now and as each request starts.
    pub fn from_source(source: Handler<dyn LineSource>) -> Result<UserHeaders, OutOfMemory> {
        Ok(UserHeaders {
            lines: Listed::from_source(source, header)?,
        })
    }

    /// The source's lines read again, in place of those read before.
    pub(crate) fn refill(&mut self) -> Result<(), OutOfMemory> {
        self.lines.refill(header)
    }

    /// The lines, as the application gave them.
    pub fn lines(&self) -> impl Iterator<Item = &[u8]> {
        self.lines.items().iter().map(|h| &h.line[..])
    }

    /// A copy (`curl_easy_duphandle`), reading the same source.
    pub fn try_clone(&self) -> Result<UserHeaders, OutOfMemory> {
        Ok(UserHeaders {
            lines: self.lines.try_clone(|h| header(&h.line))?,
        })
    }

    /// Whether a line replaces the library's header `name`
    /// (`Curl_checkheaders`).
    pub(crate) fn replaces(&self, name: &[u8]) -> bool {
        self.replacing(name).is_some()
    }

    /// The first line that replaces the library's header `name`.
    fn replacing(&self, name: &[u8]) -> Option<&UserHeader> {
        self.lines.items().iter().find(|h| h.replaces(name))
    }

    /// The first line that replaces the library's header `name`, as the
    /// application gave it (`Curl_checkheaders`).
    pub(crate) fn line_replacing(&self, name: &[u8]) -> Option<&[u8]> {
        self.replacing(name).map(|h| &h.line[..])
    }

    /// Whether the application's `Expect` asks for `100-continue`; none
    /// if it gives no `Expect`.
    pub(crate) fn expects_continue(&self) -> Option<bool> {
        let expect = self.replacing(b"Expect")?;
        Some(fields::header_says(
            &expect.line,
            b"Expect:",
            b"100-continue",
        ))
    }

    /// Whether the application's `Transfer-Encoding` asks for the body
    /// chunked; none if it gives no `Transfer-Encoding`
    /// (`http_req_set_TE`).
    pub fn asks_chunked(&self) -> Option<bool> {
        let te = self.replacing(b"Transfer-Encoding")?;
        Some(fields::header_says(
            &te.line,
            b"Transfer-Encoding:",
            b"chunked",
        ))
    }

    /// The Host the application gave, which goes only to the first origin.
    fn host(&self, _: SameOrigin) -> Option<&UserHeader> {
        self.replacing(b"Host")
    }

    /// What the application's Host says, its blanks trimmed.
    pub(crate) fn host_value(&self, same: SameOrigin) -> Option<&[u8]> {
        self.host(same)?.value()
    }

    /// The lines that may go as the application gave them: its credentials
    /// among them only with the gate's leave.
    /// The lines as a `CONNECT` sends them (`dynhds_add_custom`): each
    /// name trimmed, with what follows its colon and blanks, to the end;
    /// `Name;` alone with an empty value. A line with nothing after its
    /// colon, or anything after its semicolon, or no name, is left out,
    /// and so are an Authorization and a Cookie unless `trusted`.
    pub(crate) fn for_connect(
        &self,
        trusted: Option<Trusted>,
    ) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.lines.items().iter().filter_map(move |h| {
            let line = &h.line[..];
            let at = line.iter().position(|&b| b == b':' || b == b';')?;
            let rest = &line[at + 1..];
            let rest = &rest[rest
                .iter()
                .position(|&b| !is_blank(b))
                .unwrap_or(rest.len())..];
            let value = match line[at] {
                b':' if !rest.is_empty() => rest,
                b';' if rest.is_empty() => rest,
                _ => return None,
            };
            let name = trim(&line[..at]);
            let secret =
                name.eq_ignore_ascii_case(b"Authorization") || name.eq_ignore_ascii_case(b"Cookie");
            (!name.is_empty() && (trusted.is_some() || !secret)).then_some((name, value))
        })
    }

    fn sendable(&self, trusted: Option<Trusted>) -> impl Iterator<Item = &UserHeader> {
        self.lines
            .items()
            .iter()
            .filter(move |h| trusted.is_some() || !(h.is(b"Authorization") || h.is(b"Cookie")))
    }
}

fn classify(line: Vec<u8>) -> UserHeader {
    // `Name;` alone, with no colon in the name, asks for a blank header.
    let blank = line
        .iter()
        .position(|&b| b == b';')
        .filter(|&at| at + 1 == line.len() && !line[..at].contains(&b':'));
    let (end, asks) = match blank {
        Some(at) => (at, Asks::Blank),
        None => match line.iter().position(|&b| b == b':') {
            Some(at) => {
                let rest = &line[at + 1..];
                let to_nl = rest
                    .iter()
                    .position(|&b| b == b'\r' || b == b'\n')
                    .unwrap_or(rest.len());
                let asks = if trim(&rest[..to_nl]).is_empty() {
                    Asks::Nothing
                } else {
                    Asks::Value
                };
                (at, asks)
            }
            None => (line.len(), Asks::Nothing),
        },
    };
    // The name is trimmed, so `Authorization :` is still an Authorization.
    let start = line[..end]
        .iter()
        .position(|&b| !is_blank(b))
        .unwrap_or(end);
    let stop = line[..end]
        .iter()
        .rposition(|&b| !is_blank(b))
        .map_or(start, |p| p + 1);
    UserHeader {
        line,
        name: (start, stop),
        asks,
    }
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !is_blank(b))
        .unwrap_or(bytes.len());
    let stop = bytes
        .iter()
        .rposition(|&b| !is_blank(b))
        .map_or(start, |p| p + 1);
    &bytes[start..stop]
}

/// The parts of a request head, in the order they are sent (`http_hd_t`).
/// Rendering walks this list, so the order is the type's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Request,
    Host,
    ProxyAuthorization,
    Authorization,
    Range,
    UserAgent,
    Accept,
    Te,
    AcceptEncoding,
    Referer,
    ProxyConnection,
    TransferEncoding,
    AltUsed,
    Upgrade,
    Cookie,
    Conditionals,
    Custom,
    Content,
    Connection,
    End,
}

impl Part {
    const ALL: [Part; 20] = [
        Part::Request,
        Part::Host,
        Part::ProxyAuthorization,
        Part::Authorization,
        Part::Range,
        Part::UserAgent,
        Part::Accept,
        Part::Te,
        Part::AcceptEncoding,
        Part::Referer,
        Part::ProxyConnection,
        Part::TransferEncoding,
        Part::AltUsed,
        Part::Upgrade,
        Part::Cookie,
        Part::Conditionals,
        Part::Custom,
        Part::Content,
        Part::Connection,
        Part::End,
    ];
}

/// A request going to a proxy that sends it on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Forwarding<'o> {
    /// The proxy's own lines, sent after the application's for the
    /// origin, where the two are kept apart.
    pub(crate) own_headers: Option<&'o UserHeaders>,
}

/// What a request says, for one origin.
#[derive(Debug)]
pub(crate) struct RequestHead<'o> {
    pub(crate) method: &'o [u8],
    /// The path and query, as the URL holds them.
    pub(crate) target: &'o [u8],
    pub(crate) version: Version,
    /// The origin's host as the URL names it, an IPv6 address in
    /// brackets, and its port unless it is the scheme's.
    pub(crate) host: &'o [u8],
    pub(crate) port: Option<u16>,
    pub(crate) user_agent: Option<&'o [u8]>,
    pub(crate) referer: Option<&'o [u8]>,
    pub(crate) proxy_authorization: Option<Authorization<'o>>,
    pub(crate) authorization: Option<Authorization<'o>>,
    /// The lines a signature sends in Authorization's place, each ended
    /// by CRLF: AWS SigV4's `Authorization` and the headers it adds.
    pub(crate) signed: Option<&'o [u8]>,
    /// The range the request asks for, or for an upload sends.
    pub(crate) range: Option<RangeLine<'o>>,
    /// The body the request sends, if it has one.
    pub(crate) content: Option<Content<'o>>,
    /// The library says the body is chunked (`http_req_set_TE`); one the
    /// application asks chunked, its own header says.
    pub(crate) chunked: bool,
    /// The body is left out to probe for authentication (`authneg`): the
    /// library's `Content-Length: 0` goes in place of the application's.
    pub(crate) probe: bool,
    /// The codings `Accept-Encoding` asks for, if any.
    pub(crate) accept_encoding: Option<Accepted<'o>>,
    /// `TE: gzip` asks for gzip as a transfer coding, and `Connection`
    /// names it (`http_hd_te`).
    pub(crate) te: bool,
    /// The time condition's header, unless the application sends its own.
    pub(crate) conditional: Option<Conditional>,
    /// What the `Cookie:` line says, if the request has one.
    pub(crate) cookie: Option<&'o [u8]>,
    /// The request goes to a proxy that sends it on: it asks to keep the
    /// connection to the proxy (`origin_is_proxy`).
    pub(crate) forwarded: Option<Forwarding<'o>>,
    pub(crate) headers: &'o UserHeaders,
}

/// The range a request names (`http_range`).
#[derive(Clone, Copy, Debug)]
pub(crate) enum RangeLine<'o> {
    /// A GET or HEAD asks for it: `Range:`.
    Get(Ranged<'o>),
    /// A POST or PUT sends its body as this range of a resource whose
    /// size is the body's, C's -1 if not known: `Content-Range:`.
    Upload { range: &'o [u8], total: Option<u64> },
}

/// A time condition as a request header (`Curl_add_timecondition`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Conditional {
    pub(crate) name: &'static [u8],
    pub(crate) date: HttpDate,
}

/// What an `Accept-Encoding` says.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Accepted<'o> {
    /// The application's words.
    Given(&'o [u8]),
    /// Every coding these undo; `identity` if none.
    All(Decoders),
}

/// What the head says of a body (`http_add_content_hds`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Content<'o> {
    /// Its size, unless it goes chunked or its end is the connection's.
    pub(crate) length: Option<u64>,
    /// The library asks for a 100 before it (`addexpect`); one the
    /// application asks for, its own header says.
    pub(crate) expect: bool,
    pub(crate) typed: Typed<'o>,
}

/// How the head types a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Typed<'o> {
    /// Not at all: a PUT's.
    No,
    /// A POST's, as a form unless the application types it.
    Form,
    /// A multipart body's, by its top part's header lines: they take the
    /// application's `Content-Type` in, which its headers then leave out
    /// (`Curl_add_custom_headers`).
    Mime(&'o [Vec<u8>]),
}

/// The request head as it goes on the wire, or only its length.
struct Out<'b> {
    buf: Option<&'b mut Vec<u8>>,
    len: usize,
}

impl Out<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        if self.len + bytes.len() > MAX_HEAD {
            return Err(ErrorKind::TooLarge);
        }
        if let Some(buf) = &mut self.buf {
            buf.try_extend_from_slice(bytes)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        }
        self.len += bytes.len();
        Ok(())
    }

    fn line(&mut self, parts: &[&[u8]]) -> Result<(), ErrorKind> {
        for part in parts {
            self.put(part)?;
        }
        self.put(b"\r\n")
    }
}

/// Write `head` to `out` as HTTP/1 sends it; `TooLarge` past 1 MiB.
pub(crate) fn render_h1(
    head: &RequestHead<'_>,
    gate: &CredentialGate,
    out: &mut Vec<u8>,
) -> Result<(), ErrorKind> {
    // Measured first, so that the head takes one allocation.
    let mut measure = Out {
        buf: None,
        len: out.len(),
    };
    write_h1(head, gate, &mut measure)?;
    out.try_reserve_exact(measure.len - out.len())
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let len = out.len();
    write_h1(
        head,
        gate,
        &mut Out {
            buf: Some(out),
            len,
        },
    )
}

fn write_h1(
    head: &RequestHead<'_>,
    gate: &CredentialGate,
    out: &mut Out<'_>,
) -> Result<(), ErrorKind> {
    // A custom Host replaces the library's only for the first origin
    // (`http_set_aptr_host`); `Host:` with nothing after it drops it.
    let custom_host = gate.same_origin().and_then(|o| head.headers.host(o));
    for part in Part::ALL {
        match part {
            Part::Request => {
                let version: &[u8] = match head.version {
                    Version::Http10 => b"1.0",
                    Version::Http11 => b"1.1",
                };
                out.line(&[head.method, b" ", head.target, b" HTTP/", version])?;
            }
            Part::Host => match custom_host {
                Some(h) if h.line.eq_ignore_ascii_case(b"Host:") => {}
                Some(h) => out.line(&[b"Host:", &h.line[5..]])?,
                None => {
                    out.put(b"Host: ")?;
                    out.put(head.host)?;
                    if let Some(port) = head.port {
                        let mut digits = [0u8; 6];
                        out.put(port_text(port, &mut digits))?;
                    }
                    out.put(b"\r\n")?;
                }
            },
            Part::ProxyAuthorization => {
                if let Some(Authorization { method, value }) = head.proxy_authorization {
                    out.line(&[b"Proxy-Authorization: ", method.as_bytes(), b" ", value])?;
                }
            }
            Part::Authorization => {
                if let Some(Authorization { method, value }) = head.authorization {
                    out.line(&[b"Authorization: ", method.as_bytes(), b" ", value])?;
                }
                if let Some(lines) = head.signed {
                    out.put(lines)?;
                }
            }
            Part::Range => match head.range {
                Some(RangeLine::Get(ranged)) if head.headers.replacing(b"Range").is_none() => {
                    let mut digits = [0u8; 20];
                    let range: [&[u8]; 2] = match ranged {
                        Ranged::Resume(Resume::At(from)) => {
                            [decimal(from.get(), &mut digits), b"-"]
                        }
                        // C prints its -1 as the offset: `-1-`.
                        Ranged::Resume(Resume::AtEnd) => [b"-1-", b""],
                        Ranged::Given(given) => [given, b""],
                    };
                    out.line(&[b"Range: bytes=", range[0], range[1]])?;
                }
                Some(RangeLine::Upload { range, total })
                    if head.headers.replacing(b"Content-Range").is_none() =>
                {
                    let mut digits = [0u8; 20];
                    let total = match total {
                        Some(n) => decimal(n, &mut digits),
                        None => b"-1",
                    };
                    out.line(&[b"Content-Range: bytes ", range, b"/", total])?;
                }
                _ => {}
            },
            Part::UserAgent => {
                if let Some(ua) = head.user_agent.filter(|ua| !ua.is_empty())
                    && head.headers.replacing(b"User-Agent").is_none()
                {
                    out.line(&[b"User-Agent: ", ua])?;
                }
            }
            Part::Accept => {
                if head.headers.replacing(b"Accept").is_none() {
                    out.line(&[b"Accept: */*"])?;
                }
            }
            Part::Referer => {
                if let Some(referer) = head.referer
                    && head.headers.replacing(b"Referer").is_none()
                {
                    out.line(&[b"Referer: ", referer])?;
                }
            }
            Part::Content => {
                if let Some(content) = head.content {
                    if let Some(length) = content.length
                        && (head.probe || head.headers.replacing(b"Content-Length").is_none())
                    {
                        let mut digits = [0u8; 20];
                        out.line(&[b"Content-Length: ", decimal(length, &mut digits)])?;
                    }
                    match content.typed {
                        Typed::No => {}
                        Typed::Form => {
                            if head.headers.replacing(b"Content-Type").is_none() {
                                out.line(&[b"Content-Type: application/x-www-form-urlencoded"])?;
                            }
                        }
                        Typed::Mime(lines) => {
                            for l in lines {
                                out.line(&[l])?;
                            }
                        }
                    }
                    if content.expect {
                        out.line(&[b"Expect: 100-continue"])?;
                    }
                }
            }
            Part::TransferEncoding => {
                if head.chunked {
                    out.line(&[b"Transfer-Encoding: chunked"])?;
                }
            }
            Part::Cookie => {
                if let Some(cookie) = head.cookie {
                    out.line(&[b"Cookie: ", cookie])?;
                }
            }
            Part::Custom => custom(head, gate, out)?,
            Part::Connection => connection(head.headers, head.te, out)?,
            Part::End => out.put(b"\r\n")?,
            // What no option asks for yet.
            Part::ProxyConnection => {
                if let Some(f) = head.forwarded
                    && !head.headers.replaces(b"Proxy-Connection")
                    && !f
                        .own_headers
                        .is_some_and(|h| h.replaces(b"Proxy-Connection"))
                {
                    out.line(&[b"Proxy-Connection: Keep-Alive"])?;
                }
            }
            Part::AcceptEncoding => {
                if let Some(accepted) = head.accept_encoding
                    && head.headers.replacing(b"Accept-Encoding").is_none()
                {
                    match accepted {
                        Accepted::Given(value) => out.line(&[b"Accept-Encoding: ", value])?,
                        Accepted::All(decoders) => {
                            let mut parts: [&[u8]; 1 + 2 * Coding::ALL.len()] =
                                [b""; 1 + 2 * Coding::ALL.len()];
                            parts[0] = b"Accept-Encoding: ";
                            let mut n = 1;
                            for coding in decoders.codings() {
                                if n > 1 {
                                    parts[n] = b", ";
                                    n += 1;
                                }
                                parts[n] = coding.name().as_bytes();
                                n += 1;
                            }
                            if n == 1 {
                                parts[1] = b"identity";
                                n = 2;
                            }
                            out.line(&parts[..n])?;
                        }
                    }
                }
            }
            Part::Te => {
                if head.te {
                    out.line(&[b"TE: gzip"])?;
                }
            }
            Part::Conditionals => {
                if let Some(c) = head.conditional {
                    let mut date = Text::<40>::new();
                    write!(date, "{}", c.date).expect("a date fits");
                    out.line(&[c.name, b": ", date.bytes()])?;
                }
            }
            Part::AltUsed | Part::Upgrade => {}
        }
    }
    Ok(())
}

/// `n` in decimal, in `buf`.
pub(crate) fn decimal(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &buf[at..];
        }
    }
}

/// `:port` in `buf`.
fn port_text(port: u16, buf: &mut [u8; 6]) -> &[u8] {
    buf[0] = b':';
    let mut n = port;
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    buf.copy_within(at.., 1);
    &buf[..1 + (buf.len() - at)]
}

/// The application's headers, but those the library sends itself or the
/// gate holds back (`Curl_add_custom_headers`).
fn custom(
    head: &RequestHead<'_>,
    gate: &CredentialGate,
    out: &mut Out<'_>,
) -> Result<(), ErrorKind> {
    let proxy = head
        .forwarded
        .and_then(|f| f.own_headers)
        .into_iter()
        .flat_map(|h| h.sendable(gate.trusted()));
    for h in head.headers.sendable(gate.trusted()).chain(proxy) {
        // Host goes as its own part or not at all, Connection with the
        // library's.
        if h.asks == Asks::Nothing || h.is(b"Host") || h.is(b"Connection") {
            continue;
        }
        if head.probe && h.is(b"Content-Length") {
            continue;
        }
        if h.is(b"Content-Type")
            && head
                .content
                .is_some_and(|c| matches!(c.typed, Typed::Mime(_)))
        {
            continue;
        }
        match h.asks {
            Asks::Blank => out.line(&[h.name(), b":"])?,
            Asks::Value => out.line(&[&h.line])?,
            Asks::Nothing => unreachable!("skipped above"),
        }
    }
    Ok(())
}

/// The application's Connection headers (`http_add_connection_hd`): the
/// first with a value as the library's, its value trimmed, then the rest as
/// given.
fn connection(headers: &UserHeaders, te: bool, out: &mut Out<'_>) -> Result<(), ErrorKind> {
    let mut given = headers
        .lines
        .items()
        .iter()
        .filter(|h| h.replaces(b"Connection") && h.value().is_some_and(|v| !v.is_empty()));
    // The application's first, then the library's tokens after it
    // (`http_add_connection_hd`).
    match (given.next(), te) {
        (Some(first), true) => {
            out.line(&[
                b"Connection: ",
                first.value().expect("filtered on it"),
                b", TE",
            ])?;
        }
        (Some(first), false) => {
            out.line(&[b"Connection: ", first.value().expect("filtered on it")])?;
        }
        (None, true) => out.line(&[b"Connection: TE"])?,
        (None, false) => {}
    }
    for h in given {
        out.line(&[&h.line])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Scheme;

    const PORT: u16 = 8990;
    const UA: &[u8] = b"curl/8.99.0-test";

    /// The request a test of `tests/data` expects, with its variables and
    /// line endings as `runtests.pl` gives them.
    fn expected(test: u32) -> Vec<u8> {
        let path = format!("{}/../../tests/data/test{test}", env!("CARGO_MANIFEST_DIR"));
        let file = std::fs::read(path).unwrap();
        let open = find(&file, b"<protocol").expect("a protocol section");
        let body_at = open + find(&file[open..], b">\n").unwrap() + 2;
        let attrs = &file[open..body_at];
        let close = body_at + find(&file[body_at..], b"</protocol>").unwrap();
        let mut text = file[body_at..close].to_vec();
        for (var, value) in [
            (&b"%HOSTIP"[..], &b"127.0.0.1"[..]),
            (b"%HTTPPORT", PORT.to_string().as_bytes()),
            (b"%TESTNUMBER", test.to_string().as_bytes()),
            (b"%VERSION", &UA[5..]),
        ] {
            text = replace(&text, var, value);
        }
        // `crlf="headers"` and `crlf="yes"` alike end every line of a
        // request head with CRLF.
        assert!(find(attrs, b"crlf=").is_some(), "{test}: CRLF lines");
        replace(&text, b"\n", b"\r\n")
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    fn replace(text: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0;
        while let Some(i) = find(&text[at..], from) {
            out.extend_from_slice(&text[at..at + i]);
            out.extend_from_slice(to);
            at += i + from.len();
        }
        out.extend_from_slice(&text[at..]);
        out
    }

    const HTTP: Scheme = Scheme {
        name: "http",
        reuse: true,
    };

    fn peer(host: &[u8]) -> Peer {
        Peer::new(HTTP, host.to_vec(), PORT, None)
    }

    /// What `curl` sends for a GET of `target` with `headers`.
    fn render(method: &[u8], target: &[u8], version: Version, headers: &[&[u8]]) -> Vec<u8> {
        let headers = UserHeaders::new(headers.iter().copied()).unwrap();
        let head = RequestHead {
            method,
            target,
            version,
            host: b"127.0.0.1",
            port: Some(PORT),
            user_agent: Some(UA),
            referer: None,
            proxy_authorization: None,
            authorization: None,
            signed: None,
            range: None,
            content: None,
            chunked: false,
            probe: false,
            accept_encoding: None,
            te: false,
            conditional: None,
            cookie: None,
            forwarded: None,
            headers: &headers,
        };
        let here = peer(b"127.0.0.1");
        let mut out = Vec::new();
        render_h1(&head, &CredentialGate::new(&here, &here, false), &mut out).unwrap();
        out
    }

    /// A test's number, method, target, version and `-H` lines.
    type Case = (
        u32,
        &'static [u8],
        &'static [u8],
        Version,
        &'static [&'static [u8]],
    );

    /// Byte for byte what the C tool sends in the tests that pin the
    /// request head of a plain transfer.
    #[test]
    fn requests_are_what_the_tests_expect() {
        use Version::{Http10, Http11};
        let cases: [Case; 6] = [
            (1, b"GET", b"/1", Http11, &[]),
            (14, b"HEAD", b"/want/14", Http11, &[]),
            (47, b"GET", b"/47", Http10, &[]),
            (461, b"GET", b"/461", Http11, &[b"host:"]),
            (
                1121,
                b"GET",
                b"/1121",
                Http11,
                &[b"Host: host1", b"Host: host2", b"Host: host3"],
            ),
            (1292, b"GET", b"/1292", Http11, &[b"Host;", b"Accept;"]),
        ];
        for (test, method, target, version, headers) in cases {
            let got = render(method, target, version, headers);
            assert_eq!(
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&expected(test)),
                "test {test}"
            );
        }
    }

    /// The referer goes after `Accept`, unless the application sends its
    /// own; the C tool's request with `-e` (with `;auto` cut by the tool).
    #[test]
    fn the_referer_follows_accept() {
        let send = |headers: &[&[u8]]| {
            let headers = UserHeaders::new(headers.iter().copied()).unwrap();
            let head = RequestHead {
                method: b"GET",
                target: b"/",
                version: Version::Http11,
                host: b"127.0.0.1",
                port: Some(PORT),
                user_agent: Some(b"ua/1"),
                referer: Some(b"http://ref.example/x"),
                proxy_authorization: None,
                authorization: None,
                signed: None,
                range: None,
                content: None,
                chunked: false,
                probe: false,
                accept_encoding: None,
                te: false,
                conditional: None,
                cookie: None,
                forwarded: None,

                headers: &headers,
            };
            let here = peer(b"127.0.0.1");
            let mut out = Vec::new();
            render_h1(&head, &CredentialGate::new(&here, &here, false), &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        assert_eq!(
            send(&[b"X-A: 1", b"Accept-Encoding: q"]),
            format!(
                "GET / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: ua/1\r\nAccept: */*\r\n\
                 Referer: http://ref.example/x\r\nX-A: 1\r\nAccept-Encoding: q\r\n\r\n"
            )
        );
        assert_eq!(
            send(&[b"Referer: mine"]),
            format!(
                "GET / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: ua/1\r\nAccept: */*\r\n\
                 Referer: mine\r\n\r\n"
            )
        );
    }

    /// Basic credentials go after Host, as test 367 sends them, unless
    /// the application sends an Authorization of its own.
    #[test]
    fn basic_credentials_follow_host() {
        let here = peer(b"h");
        let gate = CredentialGate::new(&here, &here, false);
        let send = |headers: &[&[u8]]| {
            let headers = UserHeaders::new(headers.iter().copied()).unwrap();
            let trusted = gate.trusted().unwrap();
            let head = RequestHead {
                method: b"GET",
                target: b"/",
                version: Version::Http11,
                host: b"h",
                port: None,
                user_agent: Some(b"ua/1"),
                referer: None,
                proxy_authorization: None,
                authorization: Authorization::new("Basic", b"OmV4YW1wbGU=", trusted, &headers),
                signed: None,
                range: None,
                content: None,
                chunked: false,
                probe: false,
                accept_encoding: None,
                te: false,
                conditional: None,
                cookie: None,
                forwarded: None,

                headers: &headers,
            };
            let mut out = Vec::new();
            render_h1(&head, &gate, &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        assert_eq!(
            send(&[]),
            "GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Basic OmV4YW1wbGU=\r\n\
             User-Agent: ua/1\r\nAccept: */*\r\n\r\n"
        );
        assert_eq!(
            send(&[b"authorization: mine"]),
            "GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: ua/1\r\nAccept: */*\r\n\
             authorization: mine\r\n\r\n"
        );
    }

    /// A header the library sends is replaced by one of the application's
    /// whose line starts with its name and a separator, untrimmed; a
    /// trimmed name only decides what the gate holds back.
    #[test]
    fn the_application_s_headers_replace_and_add() {
        let got = render(
            b"GET",
            b"/",
            Version::Http11,
            &[
                b"Accept:",
                b"User-Agent: me",
                b"X-Empty;",
                b"X-Twice: 1",
                b"X-Twice: 2",
                b"No colon",
                b"X-Blank:   ",
                b"Accept-Language :fr",
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&got),
            "GET / HTTP/1.1\r\n\
             Host: 127.0.0.1:8990\r\n\
             User-Agent: me\r\n\
             X-Empty:\r\n\
             X-Twice: 1\r\n\
             X-Twice: 2\r\n\
             Accept-Language :fr\r\n\
             \r\n"
        );
        let spaced = render(b"GET", b"/", Version::Http11, &[b"Accept :x"]);
        assert!(
            find(&spaced, b"Accept: */*\r\n").is_some(),
            "a name and a blank do not replace the library's"
        );
    }

    /// Lines the C tool sends, or not, as `-H` gives them: a value ends at
    /// a CR, a header named as the library's but with no colon replaces
    /// nothing, and a semicolon asks for a blank header only at the end
    /// of a name with no colon.
    #[test]
    fn the_application_s_odd_headers_go_as_in_c() {
        let got = render(
            b"GET",
            b"/",
            Version::Http11,
            &[
                b"Connection: close\r",
                b"Accept",
                b"X-A: b\r",
                b"X-B: \r",
                b"X-C: a;",
                b"X;y",
                b"X-D;",
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&got),
            "GET / HTTP/1.1\r\n\
             Host: 127.0.0.1:8990\r\n\
             User-Agent: curl/8.99.0-test\r\n\
             Accept: */*\r\n\
             X-A: b\r\r\n\
             X-C: a;\r\n\
             X-D:\r\n\
             Connection: close\r\n\
             \r\n"
        );
    }

    /// The lines come back as given, and a copy has them all.
    #[test]
    fn the_application_s_headers_are_kept_as_given() {
        let lines: [&[u8]; 3] = [b"X-A: 1", b"Accept;", b"No colon"];
        let headers = UserHeaders::new(lines).unwrap();
        assert!(headers.lines().eq(lines));
        assert!(headers.try_clone().unwrap().lines().eq(lines));
    }

    /// Origins are the same only with scheme, host and port alike, the
    /// host in any case.
    #[test]
    fn the_same_origin_is_the_same_wholly() {
        let at = |scheme, host: &[u8], port| Peer::new(scheme, host.to_vec(), port, None);
        let other = Scheme {
            name: "https",
            reuse: true,
        };
        let here = at(HTTP, b"Example.COM", 80);
        let same = |p: &Peer| CredentialGate::new(&here, p, false).same_origin().is_some();
        assert!(same(&at(HTTP, b"example.com", 80)));
        assert!(!same(&at(HTTP, b"example.com", 81)));
        assert!(!same(&at(HTTP, b"example.org", 80)));
        assert!(!same(&at(other, b"example.com", 80)));
    }

    /// The application's Connection headers: the first with a value as
    /// the library's, trimmed, then the others as given, after the rest.
    #[test]
    fn connection_headers_come_last() {
        let got = render(
            b"GET",
            b"/",
            Version::Http11,
            &[
                b"Connection;",
                b"Connection:  close  ",
                b"X-A: 1",
                b"Connection: x",
            ],
        );
        assert!(
            got.ends_with(b"X-A: 1\r\nConnection: close\r\nConnection: x\r\n\r\n"),
            "{}",
            String::from_utf8_lossy(&got)
        );
    }

    /// A request a proxy forwards sends the proxy's own lines after the
    /// application's for the origin (test 1528); a Proxy-Connection in
    /// either replaces the library's.
    #[test]
    fn a_forwarded_request_sends_the_proxy_s_lines_after() {
        let headers = UserHeaders::new([&b"X-A: 1"[..]]).unwrap();
        let own = UserHeaders::new([&b"X-B: 2"[..], b"Proxy-Connection: close"]).unwrap();
        let head = |forwarded| RequestHead {
            method: b"GET",
            target: b"http://origin/",
            version: Version::Http11,
            host: b"origin",
            port: None,
            user_agent: None,
            referer: None,
            proxy_authorization: None,
            authorization: None,
            signed: None,
            range: None,
            content: None,
            chunked: false,
            probe: false,
            accept_encoding: None,
            te: false,
            conditional: None,
            cookie: None,
            forwarded,
            headers: &headers,
        };
        let here = peer(b"origin");
        let gate = CredentialGate::new(&here, &here, false);
        let mut out = Vec::new();
        let apart = Forwarding {
            own_headers: Some(&own),
        };
        render_h1(&head(Some(apart)), &gate, &mut out).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out),
            "GET http://origin/ HTTP/1.1\r\nHost: origin\r\nAccept: */*\r\n\
             X-A: 1\r\nX-B: 2\r\nProxy-Connection: close\r\n\r\n"
        );
        out.clear();
        let unified = Forwarding { own_headers: None };
        render_h1(&head(Some(unified)), &gate, &mut out).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out),
            "GET http://origin/ HTTP/1.1\r\nHost: origin\r\nAccept: */*\r\n\
             Proxy-Connection: Keep-Alive\r\nX-A: 1\r\n\r\n"
        );
    }

    /// Another origin gets the library's Host, and Authorization and
    /// Cookie only when credentials may follow the transfer anywhere.
    #[test]
    fn the_gate_holds_back_what_was_said_for_the_first_origin() {
        let headers = UserHeaders::new([
            &b"Host: elsewhere"[..],
            b"Authorization : Basic eA==",
            b"Cookie: a=b",
            b"X-Other: 1",
        ])
        .unwrap();
        let head = RequestHead {
            method: b"GET",
            target: b"/",
            version: Version::Http11,
            host: b"[::1]",
            port: None,
            user_agent: None,
            referer: None,
            proxy_authorization: None,
            authorization: None,
            signed: None,
            range: None,
            content: None,
            chunked: false,
            probe: false,
            accept_encoding: None,
            te: false,
            conditional: None,
            cookie: None,
            forwarded: None,
            headers: &headers,
        };
        let first = peer(b"127.0.0.1");
        let now = Peer::new(HTTP, b"[::1]".to_vec(), 80, None);
        let mut out = Vec::new();
        render_h1(&head, &CredentialGate::new(&first, &now, false), &mut out).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out),
            "GET / HTTP/1.1\r\nHost: [::1]\r\nAccept: */*\r\nX-Other: 1\r\n\r\n"
        );
        out.clear();
        render_h1(&head, &CredentialGate::new(&first, &now, true), &mut out).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out),
            "GET / HTTP/1.1\r\nHost: [::1]\r\nAccept: */*\r\n\
             Authorization : Basic eA==\r\nCookie: a=b\r\nX-Other: 1\r\n\r\n"
        );
        let same = CredentialGate::new(&first, &peer(b"127.0.0.1"), false);
        out.clear();
        render_h1(&head, &same, &mut out).unwrap();
        assert!(out.starts_with(b"GET / HTTP/1.1\r\nHost: elsewhere\r\n"));
    }

    /// A head fills C's request buffer but for the byte it keeps for
    /// itself; one byte more is too large.
    #[test]
    fn a_head_is_at_most_a_mebibyte_less_a_byte() {
        let sized = |value: usize| {
            let mut line = b"X-Long: ".to_vec();
            line.resize(line.len() + value, b'a');
            let headers = UserHeaders::new([&line[..]]).unwrap();
            let head = RequestHead {
                method: b"GET",
                target: b"/",
                version: Version::Http11,
                host: b"h",
                port: None,
                user_agent: None,
                referer: None,
                proxy_authorization: None,
                authorization: None,
                signed: None,
                range: None,
                content: None,
                chunked: false,
                probe: false,
                accept_encoding: None,
                te: false,
                conditional: None,
                cookie: None,
                forwarded: None,

                headers: &headers,
            };
            let here = peer(b"h");
            let mut out = Vec::new();
            render_h1(&head, &CredentialGate::new(&here, &here, false), &mut out)
                .map(|()| out.len())
        };
        // The request line, Host, Accept, the header's name and both its
        // and the head's line ends: 50 bytes.
        let fits = 1024 * 1024 - 1 - 50;
        assert_eq!(sized(fits), Ok(1024 * 1024 - 1));
        assert_eq!(sized(fits + 1), Err(ErrorKind::TooLarge));
    }
}
