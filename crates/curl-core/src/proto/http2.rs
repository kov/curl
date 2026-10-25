//! HTTP/2 on a connection (`lib/http2.c`): the session a library keeps
//! for it, beside its layers, the bytes it wants sent waiting for the
//! connection to take them, and the request's head turned into fields
//! (`Curl_h1_req_parse_read`, `Curl_http_req_to_h2`).
//!
//! A connection that speaks HTTP/2 serves one request at a time for now,
//! as an HTTP/1 one does: the request's stream lives with the request
//! (`proto::http`), the session with the connection.

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::conn::Conn;
use crate::conn::io::Sent;
use crate::conn::layer::LayerCx;
use crate::error::ErrorKind;
use crate::http2::{BodyRead, Event, FrameError, Heard, Http2, Session, Setting, StreamId};

/// The streams a client lets its peer open at once
/// (`CURLMOPT_MAX_CONCURRENT_STREAMS`'s default).
pub(crate) const MAX_CONCURRENT_STREAMS: u32 = 100;

/// A stream's receive window, as the client opens it
/// (`H2_STREAM_WINDOW_SIZE_INITIAL`).
pub(crate) const STREAM_WINDOW: u32 = 64 * 1024;

/// The connection's receive window: as large as it goes, the streams'
/// own windows doing the flow control (`HTTP2_HUGE_WINDOW_SIZE`).
const CONNECTION_WINDOW: i32 = 100 * 10 * 1024 * 1024;

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
    pub(crate) error: u32,
}

/// The session could not be set up (`cf_h2_ctx_open`'s failures).
fn failed(_: FrameError) -> ErrorKind {
    ErrorKind::Http2
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
            },
            stream,
        ))
    }

    pub(crate) fn session(&mut self) -> &mut dyn Session {
        &mut *self.session
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

    /// Ask the session for what it wants sent, reading bodies with `body`
    /// and telling closes with `events`, and send what the connection
    /// takes (`h2_progress_egress`): whether all of it went.
    pub(crate) fn egress(
        &mut self,
        cx: &mut dyn LayerCx,
        conn: &mut Conn,
        body: &mut dyn FnMut(StreamId, &mut [u8]) -> BodyRead,
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<bool, EgressFailed> {
        loop {
            if !self.flush(cx, conn)? {
                return Ok(false);
            }
            let H2Conn { session, out, .. } = self;
            let mut oom = false;
            session
                .send(
                    &mut |bytes| {
                        if out.try_extend_from_slice(bytes).is_err() {
                            oom = true;
                            return false;
                        }
                        out.len() < OUT_MAX
                    },
                    body,
                    events,
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

    /// Say goodbye as the connection shuts down, once, and send what the
    /// connection takes of it now (`cf_h2_shutdown`): a peer that closed
    /// hears nothing.
    pub(crate) fn goodbye(&mut self, cx: &mut dyn LayerCx, conn: &mut Conn) {
        if self.closed || self.sent_goaway {
            return;
        }
        self.sent_goaway = true;
        if self.session.goaway(0, b"shutdown\0").is_ok() {
            let sent = self.egress(cx, conn, &mut |_, _| BodyRead::Failed, &mut |_| Heard::Fine);
            // What does not go now goes with the connection.
            drop(sent);
        }
    }

    /// Send what the session's output holds, as far as the connection
    /// takes it: whether all of it went.
    fn flush(&mut self, cx: &mut dyn LayerCx, conn: &mut Conn) -> Result<bool, EgressFailed> {
        while self.sent < self.out.len() {
            match conn.send(cx, &self.out[self.sent..]) {
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

/// The settings a client sends (`populate_settings`): no server push, as
/// no application asks for it.
pub(crate) fn settings() -> [Setting; 3] {
    [
        Setting::MaxConcurrentStreams(MAX_CONCURRENT_STREAMS),
        Setting::InitialWindowSize(STREAM_WINDOW),
        Setting::EnablePush(false),
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
    if !connect {
        fields.add(b":scheme", scheme, false).map_err(oom)?;
    }
    let authority = if connect {
        Some(target)
    } else {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(b"Host"))
            .map(|(_, v)| *v)
    };
    if let Some(authority) = authority {
        fields.add(b":authority", authority, false).map_err(oom)?;
    }
    if !connect {
        fields.add(b":path", target, false).map_err(oom)?;
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
