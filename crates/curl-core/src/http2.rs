//! HTTP/2's framing, as a library speaks it: a client session fed a
//! connection's bytes and asked for the bytes it wants sent, which tells
//! what it read stream by stream (`lib/http2.c`'s use of nghttp2). The
//! core links none; a handle's `Libraries` name the one its build has,
//! and without one HTTP/2 is not built in, as in a C build without
//! nghttp2.

use std::fmt;

use curl_alloc::OutOfMemory;

/// A stream of a session, by its id: odd for the client's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamId(pub i32);

/// What the session read, as it read it.
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// A field of a header block of `stream`: the response's head, an
    /// interim response's, or the trailers.
    Header {
        stream: StreamId,
        name: &'a [u8],
        value: &'a [u8],
    },
    /// A header block of `stream` is over; the stream ends with it if
    /// `end_stream`.
    HeadersDone { stream: StreamId, end_stream: bool },
    /// Body bytes of `stream`.
    Data { stream: StreamId, bytes: &'a [u8] },
    /// A DATA frame of `stream` ended it.
    DataEnd { stream: StreamId },
    /// The peer opened room for more of `stream`'s body, or of the
    /// connection's if none (`WINDOW_UPDATE`).
    WindowUpdate { stream: Option<StreamId> },
    /// `stream` closed, with this error code (`NO_ERROR`: none).
    Closed { stream: StreamId, error: H2Error },
    /// The peer's settings arrived: its limit on streams open at once,
    /// and whether it lets push be used, as they now stand.
    Settings {
        max_concurrent: u32,
        enable_push: bool,
    },
    /// The peer is going away: streams past `last_stream` are not served.
    GoAway {
        last_stream: StreamId,
        error: H2Error,
    },
    /// The peer reset `stream` with this error code.
    Reset { stream: StreamId, error: H2Error },
    /// A field of a PUSH_PROMISE the peer sent on `stream`.
    PushField {
        stream: StreamId,
        name: &'a [u8],
        value: &'a [u8],
    },
    /// The peer promised to push `promised`, in answer to a request it
    /// imagines on `stream`, its fields told before.
    Promised {
        stream: StreamId,
        promised: StreamId,
    },
    /// The session read this frame whole: told before what the frame
    /// means is (`on_frame_recv`), its fields and data after them.
    Received(Frame<'a>),
    /// The session sent this frame (`on_frame_send`).
    Sent(Frame<'a>),
}

/// A frame as the trace describes it (`Curl_nghttp2_fr_print`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The stream it is on; 0 for the connection's own.
    pub stream: StreamId,
    /// Its payload's length.
    pub length: usize,
    /// Its flags, as its header carries them.
    pub flags: u8,
    pub kind: FrameKind<'a>,
}

/// What a frame is, with what its description tells of its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind<'a> {
    Data {
        padlen: usize,
        /// The stream's receive window as the frame left it: what came
        /// on it not given back yet, and its size; -1 for both on a
        /// stream the session no longer knows.
        window: (i32, i32),
    },
    Headers,
    Priority,
    RstStream {
        error: H2Error,
    },
    Settings,
    PushPromise,
    Ping,
    GoAway {
        last_stream: StreamId,
        error: H2Error,
        /// Its debug data, as sent.
        debug: &'a [u8],
    },
    WindowUpdate {
        increment: i32,
    },
    /// A type the description names by its number.
    Other(u8),
}

/// The flag that ends a stream (DATA, HEADERS) and the one that
/// acknowledges (SETTINGS, PING): the same bit.
const FLAG_END_STREAM: u8 = 0x01;
const FLAG_ACK: u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;

/// C's description of a frame (`Curl_nghttp2_fr_print`): a GOAWAY's
/// debug data up to its first zero byte, of at most 127 bytes, a byte
/// not text written as U+FFFD.
impl fmt::Display for Frame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.length;
        let flags = self.flags;
        let bit = |b: u8| u8::from(flags & b != 0);
        match self.kind {
            FrameKind::Data { padlen, .. } => {
                let eos = bit(FLAG_END_STREAM);
                write!(f, "FRAME[DATA, len={len}, eos={eos}, padlen={padlen}]")
            }
            FrameKind::Headers => {
                let (hend, eos) = (bit(FLAG_END_HEADERS), bit(FLAG_END_STREAM));
                write!(f, "FRAME[HEADERS, len={len}, hend={hend}, eos={eos}]")
            }
            FrameKind::Priority => write!(f, "FRAME[PRIORITY, len={len}, flags={flags}]"),
            FrameKind::RstStream { error } => write!(
                f,
                "FRAME[RST_STREAM, len={len}, flags={flags}, error={error}]"
            ),
            FrameKind::Settings if flags & FLAG_ACK != 0 => f.write_str("FRAME[SETTINGS, ack=1]"),
            FrameKind::Settings => write!(f, "FRAME[SETTINGS, len={len}]"),
            FrameKind::PushPromise => {
                let hend = bit(FLAG_END_HEADERS);
                write!(f, "FRAME[PUSH_PROMISE, len={len}, hend={hend}]")
            }
            FrameKind::Ping => {
                let ack = flags & FLAG_ACK;
                write!(f, "FRAME[PING, len={len}, ack={ack}]")
            }
            FrameKind::GoAway {
                last_stream,
                error,
                debug,
            } => {
                let debug = &debug[..debug.len().min(127)];
                let end = debug.iter().position(|&b| b == 0).unwrap_or(debug.len());
                write!(f, "FRAME[GOAWAY, error={error}, reason='")?;
                for chunk in debug[..end].utf8_chunks() {
                    f.write_str(chunk.valid())?;
                    if !chunk.invalid().is_empty() {
                        f.write_str("\u{fffd}")?;
                    }
                }
                write!(f, "', last_stream={}]", last_stream.0)
            }
            FrameKind::WindowUpdate { increment } => {
                write!(f, "FRAME[WINDOW_UPDATE, incr={increment}]")
            }
            FrameKind::Other(kind) => write!(f, "FRAME[{kind}, len={len}, flags={flags}]"),
        }
    }
}

impl Event<'_> {
    /// The stream the event is of; none for the connection's own, and
    /// none for a frame told whole, which the transfer reading or
    /// sending traces, whichever stream it is on.
    pub fn stream(&self) -> Option<StreamId> {
        match *self {
            Event::Header { stream, .. }
            | Event::HeadersDone { stream, .. }
            | Event::Data { stream, .. }
            | Event::DataEnd { stream }
            | Event::Closed { stream, .. }
            | Event::Reset { stream, .. }
            | Event::PushField { stream, .. }
            | Event::Promised { stream, .. } => Some(stream),
            Event::WindowUpdate { stream } => stream,
            Event::Settings { .. } | Event::GoAway { .. } | Event::Received(_) | Event::Sent(_) => {
                None
            }
        }
    }
}

/// What the caller made of an event: a failure stops the session's
/// reading, and the read fails (`NGHTTP2_ERR_CALLBACK_FAILURE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Heard {
    Fine,
    Failed,
}

/// What a read of a request's body gave the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyRead {
    /// This many bytes, more to come.
    Bytes(usize),
    /// This many bytes, the last.
    Last(usize),
    /// Nothing now: the session waits until resumed.
    Later,
    /// The stream fails.
    Failed,
}

/// A setting the client tells its peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    MaxConcurrentStreams(u32),
    InitialWindowSize(u32),
    EnablePush(bool),
}

/// What a session wants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wants {
    /// To read from the connection.
    pub read: bool,
    /// To send on it.
    pub write: bool,
}

/// A failure the library reports: its code, and its text for it
/// (`nghttp2_strerror`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameError {
    pub code: i32,
    pub text: &'static str,
    /// The failure ends the session (`nghttp2_is_fatal`).
    pub fatal: bool,
}

/// An HTTP/2 library, as nghttp2 serves C.
pub trait Http2: fmt::Debug + Send + Sync {
    /// A client session, with C's options: window updates are the
    /// caller's to give, and a field's leading and trailing blanks are
    /// not refused.
    fn client(&self) -> Result<Box<dyn Session>, OutOfMemory>;

    /// The text for an HTTP/2 error code (`nghttp2_http2_strerror`).
    fn error_text(&self, code: H2Error) -> &'static str;

    /// `settings` as the payload of a SETTINGS frame, the `HTTP2-Settings`
    /// an upgrade sends (`nghttp2_pack_settings_payload`), into `out`: its
    /// length.
    fn settings_payload(&self, settings: &[Setting], out: &mut [u8]) -> Result<usize, FrameError>;
}

/// A client session (`nghttp2_session`).
pub trait Session: fmt::Debug + Send {
    /// Queue the client's SETTINGS.
    fn submit_settings(&mut self, settings: &[Setting]) -> Result<(), FrameError>;

    /// Open the connection's receive window to `size`.
    fn set_local_window(&mut self, size: i32) -> Result<(), FrameError>;

    /// Queue a request of `fields`, its pseudo-headers first, with the
    /// stream's `weight`, 1 to 256; with a body if `body`, read as `send`
    /// asks.
    fn submit_request(
        &mut self,
        fields: &[(&[u8], &[u8])],
        body: bool,
        weight: u16,
    ) -> Result<StreamId, FrameError>;

    /// The connection was upgraded from HTTP/1.1, the request having sent
    /// `settings` as its `HTTP2-Settings`: its response comes on stream 1
    /// (`nghttp2_session_upgrade2`). `head` if it was a HEAD.
    fn upgrade(&mut self, settings: &[u8], head: bool) -> Result<StreamId, FrameError>;

    /// Feed the session `bytes` the connection received: what it read is
    /// told to `events`, in order. How many it read.
    fn recv(
        &mut self,
        bytes: &[u8],
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<usize, FrameError>;

    /// The bytes the session wants sent next, given to `out`, which takes
    /// all it is given and says whether it wants more; a body is read
    /// with `body`. A stream that closes as its last frame goes is told
    /// to `events`.
    fn send(
        &mut self,
        out: &mut dyn FnMut(&[u8]) -> bool,
        body: &mut dyn FnMut(StreamId, &mut [u8]) -> BodyRead,
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<(), FrameError>;

    /// Set `stream`'s receive window to `size`, which may tell the peer
    /// if it grows (`nghttp2_session_set_local_window_size`).
    fn set_stream_window(&mut self, stream: StreamId, size: i32) -> Result<(), FrameError>;

    /// `stream`'s receive window as the session keeps it
    /// (`nghttp2_session_get_stream_effective_local_window_size`).
    fn stream_window(&self, stream: StreamId) -> i32;

    /// What the peer sent on `stream` the caller has not consumed yet
    /// (`nghttp2_session_get_stream_effective_recv_data_length`); -1 for
    /// a stream the session does not know.
    fn stream_recv_length(&self, stream: StreamId) -> i32;

    /// The connection's receive window as it stands, what the peer sent
    /// taken off it (`nghttp2_session_get_local_window_size`).
    fn local_window(&self) -> i32;

    /// Whether the peer's settings let push be used
    /// (`NGHTTP2_SETTINGS_ENABLE_PUSH`), as they stand.
    fn peer_enables_push(&self) -> bool;

    /// What the peer lets the client send on the connection, all streams
    /// together (`nghttp2_session_get_remote_window_size`).
    fn remote_window(&self) -> i32;

    /// What the peer lets the client send on `stream`
    /// (`nghttp2_session_get_stream_remote_window_size`).
    fn stream_remote_window(&self, stream: StreamId) -> i32;

    /// Tell the peer it may send `increment` more on `stream`
    /// (`nghttp2_submit_window_update`).
    fn submit_window_update(&mut self, stream: StreamId, increment: i32) -> Result<(), FrameError>;

    /// The caller has used `n` bytes of `stream`'s data: its window opens
    /// by as much.
    fn consume(&mut self, stream: StreamId, n: usize) -> Result<(), FrameError>;

    /// A body that said `Later` has more.
    fn resume(&mut self, stream: StreamId) -> Result<(), FrameError>;

    /// Reset `stream` with `error`.
    fn reset(&mut self, stream: StreamId, error: H2Error) -> Result<(), FrameError>;

    /// Say goodbye with `error` and `debug` data, no stream of the
    /// peer's having been served.
    fn goaway(&mut self, error: H2Error, debug: &[u8]) -> Result<(), FrameError>;

    /// Send a PING.
    fn ping(&mut self) -> Result<(), FrameError>;

    /// What the session wants.
    fn wants(&self) -> Wants;

    /// The peer's limit on streams open at once, as its settings say
    /// (`SETTINGS_MAX_CONCURRENT_STREAMS`); none said, no limit.
    fn max_concurrent(&self) -> u32;
}

/// An HTTP/2 error code, as RST_STREAM and GOAWAY carry it (RFC 9113,
/// section 7); none by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct H2Error(pub u32);

impl H2Error {
    pub const NO_ERROR: H2Error = H2Error(0);
    pub const PROTOCOL_ERROR: H2Error = H2Error(1);
    pub const INTERNAL_ERROR: H2Error = H2Error(2);
    pub const STREAM_CLOSED: H2Error = H2Error(5);
    pub const REFUSED_STREAM: H2Error = H2Error(7);
    pub const CANCEL: H2Error = H2Error(8);
    pub const HTTP_1_1_REQUIRED: H2Error = H2Error(0xd);
    /// What C resets a stream with where its write fails or a window
    /// cannot be set: nghttp2's `NGHTTP2_ERR_CALLBACK_FAILURE`, -902, as
    /// an unsigned code, which no RFC defines. Copied as C sends it.
    pub const C_CALLBACK_FAILURE: H2Error = H2Error(-902_i32 as u32);
}

/// The code's number, as C's messages print it.
impl fmt::Display for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

/// The weight of a stream that asks for none (`NGHTTP2_DEFAULT_WEIGHT`).
pub const DEFAULT_WEIGHT: u16 = 16;

#[cfg(any(test, feature = "test-util"))]
pub mod fake;
