//! HTTP/2 on a connection (`lib/http2.c`): the session a library keeps
//! for it, beside its layers, the bytes it wants sent waiting for the
//! connection to take them, and the request's head turned into fields
//! (`Curl_h1_req_parse_read`, `Curl_http_req_to_h2`).
//!
//! A request's stream lives with the request (`proto::http`), the session
//! with the connection, which knows each open stream's transfer: what it
//! reads for another transfer's stream is delivered to that one.

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::conn::io::{Recv, Sent};
use crate::conn::layer::{Alive, Handshake, LayerCx, Lower as _, Part as ConnPart};
use crate::conn::mux::{Carrier, Routes};
use crate::error::ErrorKind;
use crate::error::UrlErrorKind;
use crate::http2::{
    BodyRead, Event, FrameError, H2Error, Heard, Http2, Session, Setting, StreamId,
};
use crate::multi::TransferId;
use crate::url::{GetOptions, ParseOptions, Part, Url};

/// A stream's receive window, as the client opens it
/// (`H2_STREAM_WINDOW_SIZE_INITIAL`).
pub(crate) const STREAM_WINDOW: u32 = 64 * 1024;

/// A stream's receive window once its transfer takes what it is sent,
/// and no rate limit holds it (`H2_STREAM_WINDOW_SIZE_MAX`).
pub(crate) const STREAM_WINDOW_MAX: i32 = 10 * 1024 * 1024;

/// The connection's receive window: as large as it goes, the streams'
/// own windows doing the flow control (`HTTP2_HUGE_WINDOW_SIZE`).
const CONNECTION_WINDOW: i32 = 100 * STREAM_WINDOW_MAX;

/// The most the session's output may hold before it is sent on
/// (`H2_NW_SEND_CHUNKS` of `H2_CHUNK_SIZE`).
const OUT_MAX: usize = 16 * 1024;

/// The most of a request's body held for the session to frame
/// (`H2_STREAM_SEND_CHUNKS` of `H2_CHUNK_SIZE`).
pub(crate) const SEND_MAX: usize = 64 * 1024;

/// What a connection that speaks HTTP/2 keeps (`cf_h2_ctx`).
pub(crate) struct H2Conn {
    session: Box<dyn Session>,
    /// What the session gave to send and the connection has not taken
    /// yet (`outbufq`): `out[sent..]`.
    out: Vec<u8>,
    sent: usize,
    /// The peer said GOAWAY: streams past `last` are not served.
    goaway: Option<GoAway>,
    /// The peer closed the connection.
    closed: bool,
    /// The client said GOAWAY, as the connection shuts down.
    sent_goaway: bool,
    /// Each open stream's transfer, with the receive window last asked
    /// for it (`local_window_size`).
    routes: Routes<StreamId, i32>,
}

/// Which call setting a stream's window failed, and how.
#[derive(Clone, Copy, Debug)]
pub(crate) enum WindowFailed {
    /// Setting its size, growing it or not.
    Set { grows: bool, e: FrameError },
    /// Telling the peer it grew.
    Update(FrameError),
}

impl std::fmt::Debug for H2Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Conn")
            .field("pending", &(self.out.len() - self.sent))
            .field("goaway", &self.goaway)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

/// What a GOAWAY said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GoAway {
    pub(crate) last: StreamId,
    pub(crate) error: H2Error,
}

/// The session could not be set up (`cf_h2_ctx_open`'s failures).
fn failed(_: FrameError) -> ErrorKind {
    ErrorKind::Http2
}

/// What sending on the session needs of its caller: the connection's
/// context to send in, each stream's body as the session frames it, and
/// what the session tells of streams as it sends (`h2_progress_egress`).
pub(crate) trait Egress {
    fn layer_cx(&mut self) -> &mut dyn LayerCx;
    /// Read `stream`'s body into `room`; `to` is the transfer the
    /// stream is routed to, if any.
    fn body(&mut self, stream: StreamId, to: Option<TransferId>, room: &mut [u8]) -> BodyRead;
    fn event(&mut self, event: Event<'_>) -> Heard;
}

/// Sending with no body to frame and nothing to hear, as a goodbye.
struct Bare<'a>(&'a mut dyn LayerCx);

impl Egress for Bare<'_> {
    fn layer_cx(&mut self) -> &mut dyn LayerCx {
        self.0
    }

    fn body(&mut self, _: StreamId, _: Option<TransferId>, _: &mut [u8]) -> BodyRead {
        BodyRead::Failed
    }

    fn event(&mut self, _: Event<'_>) -> Heard {
        Heard::Fine
    }
}

/// Why sending failed.
#[derive(Debug)]
pub(crate) enum EgressFailed {
    /// The session failed (`nghttp2_session_send`).
    Session(FrameError),
    /// The connection did, and said why.
    Send,
    OutOfMemory,
}

impl H2Conn {
    /// A session over a connection: its SETTINGS queued, and its receive
    /// window opened (`cf_h2_ctx_open`); nothing sent yet. With
    /// `upgrade`, the connection was upgraded from HTTP/1.1, the request
    /// having sent these settings, which the session takes as sent.
    pub(crate) fn open(
        library: &dyn Http2,
        settings: &[Setting],
        upgrade: Option<(&[u8], bool)>,
    ) -> Result<(H2Conn, Option<StreamId>), ErrorKind> {
        let mut session = library
            .client()
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        let stream = match upgrade {
            Some((payload, head)) => Some(session.upgrade(payload, head).map_err(failed)?),
            None => {
                session.submit_settings(settings).map_err(failed)?;
                None
            }
        };
        session
            .set_local_window(CONNECTION_WINDOW)
            .map_err(failed)?;
        Ok((
            H2Conn {
                session,
                out: Vec::new(),
                sent: 0,
                goaway: None,
                closed: false,
                sent_goaway: false,
                routes: Routes::new(),
            },
            stream,
        ))
    }

    pub(crate) fn session(&mut self) -> &mut dyn Session {
        &mut *self.session
    }

    /// How many transfers it takes at once, with `attached` on it
    /// (`cf_h2_query`'s `CF_QUERY_MAX_CONCURRENT`): the peer's limit, or,
    /// once it may make no more requests, its peer gone or going away,
    /// those on it.
    pub(crate) fn max_concurrent(&self, attached: u32) -> u32 {
        if self.closed() || self.goaway.is_some() {
            return attached;
        }
        self.session.max_concurrent()
    }

    pub(crate) fn version(&self) -> crate::report::ResponseVersion {
        crate::report::ResponseVersion::Http2
    }

    /// Stream `stream` is transfer `to`'s, from its opening on.
    pub(crate) fn route(&mut self, stream: StreamId, to: TransferId) -> Result<(), OutOfMemory> {
        self.routes.route(stream, to, STREAM_WINDOW as i32)
    }

    /// Stream `stream` is no transfer's any more: its request is over.
    pub(crate) fn unroute(&mut self, stream: StreamId) {
        self.routes.unroute(stream);
    }

    /// The transfer stream `stream` is for, while its request runs.
    pub(crate) fn route_of(&self, stream: StreamId) -> Option<TransferId> {
        self.routes.route_of(stream)
    }

    /// The transfers of the streams open, but `but`'s.
    pub(crate) fn others(&self, but: TransferId) -> impl Iterator<Item = TransferId> + '_ {
        self.routes.others(but)
    }

    /// Feed the session what the connection read, `events` hearing
    /// each event with the transfer its stream is routed to, if any.
    pub(crate) fn recv(
        &mut self,
        bytes: &[u8],
        events: &mut dyn FnMut(Event<'_>, Option<TransferId>) -> Heard,
    ) -> Result<usize, FrameError> {
        let H2Conn {
            session, routes, ..
        } = self;
        session.recv(bytes, &mut |event| {
            let to = event.stream().and_then(|s| routes.route_of(s));
            events(event, to)
        })
    }

    /// Ask for `stream`'s receive window to be `wanted`, as its transfer
    /// can take: none while its output is paused, so that the server
    /// holds back what it would only buffer (`cf_h2_update_local_win`).
    /// Growing it, the peer is told by how much, as C tells it.
    pub(crate) fn window_to(&mut self, stream: StreamId, wanted: i32) -> Result<(), WindowFailed> {
        let Some(window) = self.routes.kept_mut(stream) else {
            return Ok(());
        };
        if *window == wanted {
            return Ok(());
        }
        let now = self.session.stream_window(stream);
        let grows = wanted > now;
        self.session
            .set_stream_window(stream, wanted)
            .map_err(|e| WindowFailed::Set { grows, e })?;
        if grows {
            self.session
                .submit_window_update(stream, wanted - now)
                .map_err(WindowFailed::Update)?;
        }
        *window = wanted;
        Ok(())
    }

    pub(crate) fn goaway(&self) -> Option<GoAway> {
        self.goaway
    }

    pub(crate) fn set_goaway(&mut self, goaway: GoAway) {
        self.goaway = Some(goaway);
    }

    /// The peer closed the connection.
    pub(crate) fn closed(&self) -> bool {
        self.closed
    }

    pub(crate) fn set_closed(&mut self) {
        self.closed = true;
    }

    /// Ask the session for what it wants sent, reading bodies and telling
    /// what it says of streams through `with`, and send what the
    /// connection takes (`h2_progress_egress`): whether all of it went.
    pub(crate) fn egress(
        &mut self,
        with: &mut dyn Egress,
        io: &mut Carrier<'_>,
    ) -> Result<bool, EgressFailed> {
        loop {
            if !self.flush(with.layer_cx(), io)? {
                return Ok(false);
            }
            let H2Conn {
                session,
                out,
                routes,
                ..
            } = self;
            let mut oom = false;
            let with = std::cell::RefCell::new(&mut *with);
            session
                .send(
                    &mut |bytes| {
                        if out.try_extend_from_slice(bytes).is_err() {
                            oom = true;
                            return false;
                        }
                        out.len() < OUT_MAX
                    },
                    &mut |stream, room| {
                        with.borrow_mut()
                            .body(stream, routes.route_of(stream), room)
                    },
                    &mut |event| with.borrow_mut().event(event),
                )
                .map_err(EgressFailed::Session)?;
            if oom {
                return Err(EgressFailed::OutOfMemory);
            }
            if self.out.is_empty() {
                return Ok(true);
            }
        }
    }

    /// Send what the session's output holds, as far as the connection
    /// takes it: whether all of it went.
    fn flush(&mut self, cx: &mut dyn LayerCx, io: &mut Carrier<'_>) -> Result<bool, EgressFailed> {
        while self.sent < self.out.len() {
            match io.send(cx, &self.out[self.sent..]) {
                Ok(Sent::Bytes(n)) => self.sent += n.get(),
                Ok(_) => return Ok(false),
                Err(_) => return Err(EgressFailed::Send),
            }
        }
        self.out.clear();
        self.sent = 0;
        Ok(true)
    }
}

impl<'a> ConnPart<Carrier<'a>> for H2Conn {
    /// What an idle connection has to read, read by the session, which a
    /// frame for no stream leaves alive: whether it still is, its session
    /// neither failed, told to go away nor done (`http2_connisalive`,
    /// `should_close_session`).
    fn is_alive(&mut self, cx: &mut dyn LayerCx, mut below: Carrier<'a>) -> Alive {
        use crate::http2::{Event, Heard};
        let below_alive = below.reborrow().alive(cx);
        if below_alive
            != (Alive::Alive {
                input_pending: true,
            })
        {
            return below_alive;
        }
        let alive = match below.recv(cx, 16 * 1024) {
            Ok(Recv::WouldBlock) => true,
            Ok(Recv::Eof) | Err(_) => false,
            Ok(Recv::Data(_)) => {
                let mut rx = std::mem::take(below.rx_mut());
                let mut goaway = false;
                let read = self.session.recv(rx.filled(), &mut |event| {
                    goaway |= matches!(event, Event::GoAway { .. });
                    Heard::Fine
                });
                let all = rx.filled().len();
                rx.consume(all);
                *below.rx_mut() = rx;
                let wants = self.session.wants();
                read.is_ok() && !goaway && (wants.read || wants.write)
            }
        };
        if alive {
            Alive::Alive {
                input_pending: false,
            }
        } else {
            Alive::Dead
        }
    }

    /// Say goodbye as the connection shuts down, once, and send what the
    /// connection takes of it now (`cf_h2_shutdown`): a peer that closed
    /// hears nothing. What does not go now goes with the connection.
    fn shutdown(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Carrier<'a>,
    ) -> Result<Handshake, ErrorKind> {
        if self.closed || self.sent_goaway {
            return Ok(Handshake::Done);
        }
        self.sent_goaway = true;
        if self
            .session
            .goaway(H2Error::NO_ERROR, b"shutdown\0")
            .is_ok()
        {
            let sent = self.egress(&mut Bare(cx), &mut below);
            drop(sent);
        }
        Ok(Handshake::Done)
    }
}

/// The settings a client sends (`populate_settings`), letting the server
/// open `max_streams` at once, and push responses if the application
/// takes them.
pub(crate) fn settings(max_streams: u32, push: bool) -> [Setting; 3] {
    [
        Setting::MaxConcurrentStreams(max_streams),
        Setting::InitialWindowSize(STREAM_WINDOW),
        Setting::EnablePush(push),
    ]
}

/// A field: its name and its value.
pub(crate) type Field<'a> = (&'a [u8], &'a [u8]);

/// A request's fields, made of its HTTP/1 head: its bytes, and each
/// field as ranges of them, the pseudo-headers first.
#[derive(Debug, Default)]
pub(crate) struct Fields {
    bytes: Vec<u8>,
    ranges: Vec<(std::ops::Range<usize>, std::ops::Range<usize>)>,
}

impl Fields {
    /// Each field, as the session takes them.
    pub(crate) fn pairs(&self) -> Result<Vec<Field<'_>>, OutOfMemory> {
        let mut pairs = Vec::new();
        pairs.try_reserve_exact(self.ranges.len())?;
        for (n, v) in &self.ranges {
            pairs.try_push((&self.bytes[n.clone()], &self.bytes[v.clone()]))?;
        }
        Ok(pairs)
    }

    fn add(&mut self, name: &[u8], value: &[u8], lowercase: bool) -> Result<(), OutOfMemory> {
        let start = self.bytes.len();
        self.bytes.try_extend_from_slice(name)?;
        if lowercase {
            self.bytes[start..].make_ascii_lowercase();
        }
        let mid = self.bytes.len();
        self.bytes.try_extend_from_slice(value)?;
        let end = self.bytes.len();
        self.ranges.try_push((start..mid, mid..end))?;
        Ok(())
    }
}

/// The fields that do not go in HTTP/2 (`H2_NON_FIELD`).
const NOT_FIELDS: &[&[u8]] = &[
    b"Host",
    b"Upgrade",
    b"Connection",
    b"Keep-Alive",
    b"Proxy-Connection",
    b"Transfer-Encoding",
];

/// The fields of the request whose HTTP/1 head is `head`, its method the
/// application's `custom` if the request line starts with it, its scheme
/// `scheme` (`Curl_h1_req_parse_read`, `Curl_http_req_to_h2`): `:method`,
/// `:scheme`, `:authority` from `Host:`, and `:path`, then each header
/// but those HTTP/2 has no use for, its name in lowercase, `TE` only as
/// `trailers`. A head C's parser refuses is a malformed URL's.
pub(crate) fn fields_of(
    head: &[u8],
    custom: Option<&[u8]>,
    scheme: &[u8],
) -> Result<Fields, ErrorKind> {
    let oom = |OutOfMemory| ErrorKind::OutOfMemory;
    let mut lines = head.split_inclusive(|&b| b == b'\n').map(trim_line);
    let request = lines.next().ok_or(ErrorKind::UrlMalformat)?;
    // "METHOD TARGET VERSION", the method the application's if it starts
    // the line, the target running to the last space.
    let method_len = match custom.filter(|m| !m.is_empty() && request.starts_with(m)) {
        Some(m) => m.len(),
        None => match request.iter().position(|&b| b == b' ') {
            Some(0) | None => return Err(ErrorKind::UrlMalformat),
            Some(n) => n,
        },
    };
    let method = &request[..method_len];
    let last_space = request
        .iter()
        .rposition(|&b| b == b' ')
        .filter(|&i| i > method_len)
        .ok_or(ErrorKind::UrlMalformat)?;
    let target = request
        .get(method_len + 1..last_space)
        .filter(|t| !t.is_empty())
        .ok_or(ErrorKind::UrlMalformat)?;
    let mut headers: Vec<(&[u8], &[u8])> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let colon = match line.iter().position(|&b| b == b':') {
            Some(0) | None => return Err(ErrorKind::BadFunctionArgument),
            Some(c) => c,
        };
        let value = &line[colon + 1..];
        let blanks = value
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        headers
            .try_push((&line[..colon], &value[blanks..]))
            .map_err(oom)?;
    }
    let mut fields = Fields::default();
    fields.add(b":method", method, false).map_err(oom)?;
    let connect = method == b"CONNECT";
    // The target in absolute form, as a request to a proxy sends it,
    // gives the scheme, authority and path (`start_req`).
    let url: Option<TargetUrl> = match target {
        b"*" => None,
        _ if connect || target[0] == b'/' => None,
        _ if target.len() >= MOST_TARGET => return Err(ErrorKind::UrlMalformat),
        _ if !crate::url::is_absolute(target) => None,
        _ => Some(TargetUrl::of(target)?),
    };
    if !connect {
        let scheme = url
            .as_ref()
            .and_then(|u| u.scheme.as_deref())
            .unwrap_or(scheme);
        fields.add(b":scheme", scheme, false).map_err(oom)?;
    }
    let host = || {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(b"Host"))
            .map(|(_, v)| *v)
    };
    let authority = match &url {
        _ if connect => Some(target),
        Some(TargetUrl {
            authority: Some(a), ..
        }) => Some(&a[..]),
        _ => host(),
    };
    if let Some(authority) = authority {
        fields.add(b":authority", authority, false).map_err(oom)?;
    }
    if !connect {
        let path = url.as_ref().map_or(target, |u| &u.path[..]);
        fields.add(b":path", path, false).map_err(oom)?;
    }
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(b"TE") {
            if has_token(value, b"trailers") {
                fields.add(name, b"trailers", true).map_err(oom)?;
            }
        } else if !NOT_FIELDS.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            fields.add(name, value, true).map_err(oom)?;
        }
    }
    Ok(fields)
}

/// The fields of a CONNECT-UDP to a proxy that speaks HTTP/2 (RFC 9298's
/// extended `CONNECT`; `http_proxy_create_CONNECTUDP`,
/// `Curl_http_req_to_h2`): the proxy's `scheme` and `authority` and the
/// `path` naming the target, then what `head` holds after its request
/// line, the proxy's authorization first if `authorized`, then the
/// protocol asked for and the capsules it is to carry, then the rest.
pub(crate) fn connect_udp_fields(
    head: &[u8],
    authorized: bool,
    scheme: &[u8],
    authority: &[u8],
    path: &[u8],
) -> Result<Fields, ErrorKind> {
    let oom = |OutOfMemory| ErrorKind::OutOfMemory;
    let mut fields = Fields::default();
    fields.add(b":method", b"CONNECT", false).map_err(oom)?;
    fields.add(b":scheme", scheme, false).map_err(oom)?;
    fields.add(b":authority", authority, false).map_err(oom)?;
    fields.add(b":path", path, false).map_err(oom)?;
    let mut lines = head
        .split_inclusive(|&b| b == b'\n')
        .map(trim_line)
        .skip(1)
        .take_while(|l| !l.is_empty());
    if authorized && let Some(line) = lines.next() {
        add_line(&mut fields, line)?;
    }
    fields
        .add(b":protocol", b"connect-udp", false)
        .map_err(oom)?;
    fields.add(b"capsule-protocol", b"?1", false).map_err(oom)?;
    for line in lines {
        add_line(&mut fields, line)?;
    }
    Ok(fields)
}

/// A header `line` of an HTTP/1 head added as a field, but those HTTP/2
/// has no use for, `TE` only as `trailers`.
fn add_line(fields: &mut Fields, line: &[u8]) -> Result<(), ErrorKind> {
    let oom = |OutOfMemory| ErrorKind::OutOfMemory;
    let colon = match line.iter().position(|&b| b == b':') {
        Some(0) | None => return Err(ErrorKind::BadFunctionArgument),
        Some(c) => c,
    };
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    let blanks = value
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count();
    let value = &value[blanks..];
    if name.eq_ignore_ascii_case(b"TE") {
        if has_token(value, b"trailers") {
            fields.add(name, b"trailers", true).map_err(oom)?;
        }
    } else if !NOT_FIELDS.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        fields.add(name, value, true).map_err(oom)?;
    }
    Ok(())
}

/// The longest target taken as a URL (`H1_MAX_URL_LEN`).
const MOST_TARGET: usize = 8 * 1024;

/// What a request's target in absolute form names (`Curl_http_req_make2`):
/// its scheme, its host with any port not the scheme's own, and its path
/// with any query.
struct TargetUrl {
    scheme: Option<Vec<u8>>,
    authority: Option<Vec<u8>>,
    path: Vec<u8>,
}

impl TargetUrl {
    fn of(target: &[u8]) -> Result<TargetUrl, ErrorKind> {
        let failed = |e| match e {
            UrlErrorKind::OutOfMemory => ErrorKind::OutOfMemory,
            _ => ErrorKind::UrlMalformat,
        };
        let opts = ParseOptions {
            non_support_scheme: true,
            path_as_is: true,
            allow_space: true,
            ..ParseOptions::NONE
        };
        let url = Url::parse(target, opts).map_err(failed)?;
        let part = |what, opts| match url.get(what, opts) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(
                UrlErrorKind::NoScheme
                | UrlErrorKind::NoHost
                | UrlErrorKind::NoPort
                | UrlErrorKind::NoQuery,
            ) => Ok(None),
            Err(e) => Err(failed(e)),
        };
        let scheme = part(Part::Scheme, GetOptions::NONE)?;
        let no_default = GetOptions {
            no_default_port: true,
            ..GetOptions::NONE
        };
        let authority = match part(Part::Host, GetOptions::NONE)? {
            Some(mut host) => {
                if let Some(port) = part(Part::Port, no_default)? {
                    host.try_push(b':')
                        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
                    host.try_extend_from_slice(&port)
                        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
                }
                Some(host)
            }
            None => None,
        };
        let mut path = part(Part::Path, GetOptions::NONE)?.unwrap_or_default();
        if let Some(query) = part(Part::Query, GetOptions::NONE)? {
            path.try_push(b'?')
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
            path.try_extend_from_slice(&query)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        }
        Ok(TargetUrl {
            scheme,
            authority,
            path,
        })
    }
}

/// A line without its CRLF or LF.
fn trim_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Whether a field's value lists `token` (`http_TE_has_token`).
fn has_token(value: &[u8], token: &[u8]) -> bool {
    value.split(|&b| b == b',').any(|item| {
        let item = item
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .map_or(&[][..], |s| &item[s..]);
        let end = item
            .iter()
            .position(|&b| matches!(b, b' ' | b'\t' | b'\r' | b';'))
            .unwrap_or(item.len());
        item[..end].eq_ignore_ascii_case(token)
    })
}

#[cfg(test)]
mod tests;
