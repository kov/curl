//! The request head of HTTP/1 (`lib/http.c`'s `Curl_http`): what is sent,
//! in which order, and which of the application's headers go with it.

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::error::ErrorKind;

/// The most a request head may be, the terminating byte C's buffer keeps
/// for itself taken off (`DYN_HTTP_REQUEST`).
const MAX_HEAD: usize = 1024 * 1024 - 1;

/// The version an HTTP request is made in (`CURLOPT_HTTP_VERSION`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Version {
    Http10,
    #[default]
    Http11,
}

/// One endpoint as the credential gate compares them (`Curl_peer_equal`):
/// the scheme, the host as the URL names it, and the port.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Peer<'a> {
    pub(crate) scheme: &'a [u8],
    pub(crate) host: &'a [u8],
    pub(crate) port: u16,
}

impl Peer<'_> {
    fn same(&self, other: &Peer<'_>) -> bool {
        self.scheme.eq_ignore_ascii_case(other.scheme)
            && self.host.eq_ignore_ascii_case(other.host)
            && self.port == other.port
    }
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

impl CredentialGate {
    /// The gate for a request to `now` in a transfer that started at
    /// `initial`; `other_hosts` lets credentials follow it anywhere
    /// (`CURLOPT_UNRESTRICTED_AUTH`).
    pub(crate) fn new(initial: &Peer<'_>, now: &Peer<'_>, other_hosts: bool) -> CredentialGate {
        let same = initial.same(now);
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
/// given.
#[derive(Debug, Default)]
pub struct UserHeaders {
    lines: Vec<UserHeader>,
}

impl UserHeaders {
    /// The headers of `lines`, each as the application gave it.
    pub fn new<'a>(lines: impl IntoIterator<Item = &'a [u8]>) -> Result<UserHeaders, OutOfMemory> {
        let mut headers = UserHeaders::default();
        for line in lines {
            let mut copy = Vec::new();
            copy.try_extend_from_slice(line)?;
            headers.lines.try_push(classify(copy))?;
        }
        Ok(headers)
    }

    /// A copy (`curl_easy_duphandle`).
    pub fn try_clone(&self) -> Result<UserHeaders, OutOfMemory> {
        UserHeaders::new(self.lines.iter().map(|h| &h.line[..]))
    }

    /// The first line that replaces the library's header `name`.
    fn replacing(&self, name: &[u8]) -> Option<&UserHeader> {
        self.lines.iter().find(|h| h.replaces(name))
    }

    /// The Host the application gave, which goes only to the first origin.
    fn host(&self, _: SameOrigin) -> Option<&UserHeader> {
        self.replacing(b"Host")
    }

    /// The lines that may go as the application gave them: its credentials
    /// among them only with the gate's leave.
    fn sendable(&self, trusted: Option<Trusted>) -> impl Iterator<Item = &UserHeader> {
        self.lines
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
    pub(crate) headers: &'o UserHeaders,
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
            Part::Custom => custom(head, gate, out)?,
            Part::Connection => connection(head.headers, out)?,
            Part::End => out.put(b"\r\n")?,
            // What no option asks for yet.
            Part::ProxyAuthorization
            | Part::Authorization
            | Part::Range
            | Part::Te
            | Part::AcceptEncoding
            | Part::Referer
            | Part::ProxyConnection
            | Part::TransferEncoding
            | Part::AltUsed
            | Part::Upgrade
            | Part::Cookie
            | Part::Conditionals
            | Part::Content => {}
        }
    }
    Ok(())
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
    for h in head.headers.sendable(gate.trusted()) {
        // Host goes as its own part or not at all, Connection with the
        // library's.
        if h.asks == Asks::Nothing || h.is(b"Host") || h.is(b"Connection") {
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
fn connection(headers: &UserHeaders, out: &mut Out<'_>) -> Result<(), ErrorKind> {
    let mut given = headers
        .lines
        .iter()
        .filter(|h| h.replaces(b"Connection") && h.value().is_some_and(|v| !v.is_empty()));
    if let Some(first) = given.next() {
        out.line(&[b"Connection: ", first.value().expect("filtered on it")])?;
    }
    for h in given {
        out.line(&[&h.line])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn peer(host: &[u8]) -> Peer<'_> {
        Peer {
            scheme: b"http",
            host,
            port: PORT,
        }
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
            headers: &headers,
        };
        let first = peer(b"127.0.0.1");
        let now = Peer {
            scheme: b"http",
            host: b"[::1]",
            port: 80,
        };
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
