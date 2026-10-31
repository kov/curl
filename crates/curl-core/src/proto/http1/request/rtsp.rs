//! The request head of RTSP (`lib/rtsp.c`'s `rtsp_do`): its own lines in
//! its own order, with the application's after them as HTTP's are sent.

use super::{
    Accepted, Asks, Authorization, Conditional, Out, UserHeaders, accept_encoding, decimal,
};
use crate::auth::creds::Trusted;
use crate::error::ErrorKind;
use crate::options::{Ranged, Resume};
use crate::text::Text;
use std::fmt::Write as _;

/// The most an RTSP request head may be, the terminating byte C's buffer
/// keeps for itself taken off (`DYN_RTSP_REQ_HEADER`).
const MAX_RTSP_HEAD: usize = 64 * 1024 - 1;

/// What an RTSP request says.
#[derive(Debug)]
pub(crate) struct RtspHead<'o> {
    pub(crate) method: &'o [u8],
    /// What the request line names: the stream, or `*`.
    pub(crate) stream_uri: &'o [u8],
    pub(crate) cseq: u32,
    pub(crate) session: Option<&'o [u8]>,
    /// The `Transport:` a SETUP sends from its option; one the
    /// application gives goes with its other headers.
    pub(crate) transport: Option<&'o [u8]>,
    /// `Accept: application/sdp`, a DESCRIBE's unless the application
    /// sends its own.
    pub(crate) accept_sdp: bool,
    /// A DESCRIBE's `Accept-Encoding:`, unless the application sends its
    /// own.
    pub(crate) accept_encoding: Option<Accepted<'o>>,
    /// The range a PLAY, PAUSE or RECORD asks for, unless the application
    /// sends its own.
    pub(crate) range: Option<Ranged<'o>>,
    pub(crate) referer: Option<&'o [u8]>,
    pub(crate) user_agent: Option<&'o [u8]>,
    pub(crate) proxy_authorization: Option<Authorization<'o>>,
    pub(crate) authorization: Option<Authorization<'o>>,
    /// A SETUP's or DESCRIBE's time condition, unless the application
    /// sends its own.
    pub(crate) conditional: Option<Conditional>,
    /// The body's size and type, for a body of a size above 0.
    pub(crate) content: Option<RtspContent>,
    /// The body is left out to probe for authentication: the
    /// application's `Content-Length` goes with it (`authneg`).
    pub(crate) probe: bool,
    pub(crate) headers: &'o UserHeaders,
    /// Which of the application's headers may go to the origin.
    pub(crate) trusted: Option<Trusted>,
}

/// What an RTSP head says of its body (`rtsp_setup_body`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RtspContent {
    pub(crate) length: u64,
    /// The library's `Content-Type:`, unless the application sends its
    /// own.
    pub(crate) typed: Option<&'static [u8]>,
}

/// Write `head` to `out` as RTSP sends it; `TooLarge` past 64 KiB.
pub(crate) fn render_rtsp(head: &RtspHead<'_>, out: &mut Vec<u8>) -> Result<(), ErrorKind> {
    let mut measure = Out {
        buf: None,
        len: out.len(),
        max: MAX_RTSP_HEAD,
    };
    write_rtsp(head, &mut measure)?;
    out.try_reserve_exact(measure.len - out.len())
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let len = out.len();
    write_rtsp(
        head,
        &mut Out {
            buf: Some(out),
            len,
            max: MAX_RTSP_HEAD,
        },
    )
}

fn write_rtsp(head: &RtspHead<'_>, out: &mut Out<'_>) -> Result<(), ErrorKind> {
    let mut digits = [0u8; 20];
    out.line(&[head.method, b" ", head.stream_uri, b" RTSP/1.0"])?;
    out.line(&[b"CSeq: ", decimal(u64::from(head.cseq), &mut digits)])?;
    if let Some(session) = head.session {
        out.line(&[b"Session: ", session])?;
    }
    if let Some(transport) = head.transport {
        out.line(&[b"Transport: ", transport])?;
    }
    if head.accept_sdp {
        out.line(&[b"Accept: application/sdp"])?;
    }
    if let Some(accepted) = head.accept_encoding {
        accept_encoding(accepted, out)?;
    }
    if let Some(range) = head.range {
        let mut digits = [0u8; 20];
        let range: [&[u8]; 2] = match range {
            Ranged::Resume(Resume::At(from)) => [decimal(from.get(), &mut digits), b"-"],
            Ranged::Resume(Resume::AtEnd) => [b"-1-", b""],
            Ranged::Given(given) => [given, b""],
        };
        out.line(&[b"Range: ", range[0], range[1]])?;
    }
    if let Some(referer) = head.referer
        && head.headers.replacing(b"Referer").is_none()
    {
        out.line(&[b"Referer: ", referer])?;
    }
    if let Some(ua) = head.user_agent.filter(|ua| !ua.is_empty())
        && head.headers.replacing(b"User-Agent").is_none()
    {
        out.line(&[b"User-Agent: ", ua])?;
    }
    if let Some(Authorization { method, value }) = head.proxy_authorization {
        out.line(&[b"Proxy-Authorization: ", method.as_bytes(), b" ", value])?;
    }
    if let Some(Authorization { method, value }) = head.authorization {
        out.line(&[b"Authorization: ", method.as_bytes(), b" ", value])?;
    }
    if let Some(c) = head.conditional {
        let mut date = Text::<40>::new();
        write!(date, "{}", c.date).expect("a date fits");
        out.line(&[c.name, b": ", date.bytes()])?;
    }
    custom(head, out)?;
    if let Some(content) = head.content {
        if head.headers.replacing(b"Content-Length").is_none() {
            let mut digits = [0u8; 20];
            out.line(&[b"Content-Length: ", decimal(content.length, &mut digits)])?;
        }
        if let Some(typed) = content.typed
            && head.headers.replacing(b"Content-Type").is_none()
        {
            out.line(&[b"Content-Type: ", typed])?;
        }
    }
    out.put(b"\r\n")
}

/// The application's headers (`Curl_add_custom_headers` with no proxy to
/// send the request on): its Connection is never sent, nor its
/// `Content-Length` while probing, nor its Authorization or Cookie where
/// the origin is not trusted with them; RTSP sends no `Host:` of its own,
/// so the application's goes.
fn custom(head: &RtspHead<'_>, out: &mut Out<'_>) -> Result<(), ErrorKind> {
    for h in head.headers.sendable(head.trusted) {
        if h.asks == Asks::Nothing || h.is(b"Connection") {
            continue;
        }
        if head.probe && h.is(b"Content-Length") {
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
