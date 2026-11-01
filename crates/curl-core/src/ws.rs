//! WebSocket frames as the application sends and receives them, over a
//! connection that switched to them from HTTP/1.1 (`ws://`, `wss://`):
//! what a frame is, and what one received says of the bytes it is given
//! (`struct curl_ws_frame`).

use crate::error::ErrorKind;

/// What a frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

/// A frame's type as the application is told of it: its kind, and
/// whether more of its message comes in frames after it, only ever so
/// for text and binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameType {
    pub kind: FrameKind,
    pub more: bool,
}

/// What a WebSocket's handler is told of the bytes it was last given
/// (`curl_ws_meta`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Meta {
    /// No frame has come yet: C's frame, as it is made, all zero.
    Nothing,
    /// The frame they are of.
    Frame(Frame),
}

/// The frame some received bytes are of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameType,
    /// Where in the frame's payload the bytes start.
    pub offset: u64,
    /// The payload left after them.
    pub bytes_left: u64,
    /// How many there are.
    pub len: usize,
}

/// What a frame the application sends is: its kind, if it names one,
/// and whether more of its message is to follow. A frame that names
/// none continues the message under way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendFlags {
    pub kind: Option<FrameKind>,
    pub more: bool,
}

/// How the bytes the application sends make a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameLen {
    /// They are the frame's payload, all of it.
    These,
    /// The frame's payload is this long, of which they are the start;
    /// what follows is sent after them as more of the same frame.
    Total(u64),
}

/// What a send of a frame's bytes did: how many went, or none for now
/// (`CURLE_AGAIN`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    Bytes(usize),
    WouldBlock,
    /// These went, and the connection took no more of what was given,
    /// which goes past the frame (`CURLE_AGAIN`, with a count).
    BytesThenWouldBlock(usize),
}

/// What a receive got: payload bytes of a frame, or none for now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    Frame(Frame),
    WouldBlock,
}

/// What the application asks of the WebSocket its transfer only
/// connected (`CURLOPT_CONNECT_ONLY` 2), once the transfer is done.
#[derive(Debug)]
pub enum Call<'a> {
    /// Receive into the buffer what came of the next frame
    /// (`curl_ws_recv`).
    Recv(&'a mut [u8]),
    /// Send the bytes: a frame of the length given, or more of the frame
    /// under way, as the flags say; as they are if frames are raw
    /// (`curl_ws_send`).
    Send(&'a [u8], FrameLen, SendFlags),
    /// Start a frame this long, its payload to come in the sends after
    /// (`curl_ws_start_frame`).
    StartFrame(SendFlags, u64),
    /// [`Call::Send`], the arguments as a host read them from its own.
    SendAsked(&'a [u8], Asked<'a>),
    /// [`Call::StartFrame`], the arguments as a host read them from its own.
    StartAsked(Asked<'a>),
}

/// What a host's caller asked of a send or a frame's start, for a host that
/// has arguments of its own to read into the core's types: the trace names
/// them as given, and those no frame can have are refused when a frame
/// would start, not before, a send that is more of a frame not reading them.
#[derive(Clone, Copy, Debug)]
pub struct Asked<'a> {
    /// The length, as the trace names it.
    pub length: i64,
    /// The flags, as the trace names them.
    pub flags: u32,
    pub frame: AskedFrame<'a>,
}

/// What an [`Asked`] comes to.
#[derive(Clone, Copy, Debug)]
pub enum AskedFrame<'a> {
    /// A frame, or as the bytes are if frames are raw.
    Frame(FrameLen, SendFlags),
    /// No frame: refused once what waits to go has gone, if a frame would
    /// start or frames are raw.
    None(Refusal<'a>),
    /// No bytes, though the caller said `claimed` of them: refused before
    /// the connection is looked for.
    NoBytes { claimed: usize, why: Refusal<'a> },
}

/// Why a host refuses what it was asked, in its words.
#[derive(Clone, Copy, Debug)]
pub struct Refusal<'a> {
    pub kind: ErrorKind,
    pub why: &'a str,
}

/// What a [`Call`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Received(Received),
    Sent(Sent),
    Started,
}
