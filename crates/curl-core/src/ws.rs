//! WebSocket frames as the application sends and receives them, over a
//! connection that switched to them from HTTP/1.1 (`ws://`, `wss://`):
//! what a frame is, and what one received says of the bytes it is given
//! (`struct curl_ws_frame`).

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
    /// Get ready for a send, as one does first: the connection found, and
    /// what waits to go sent if no frame is under way. A host that has
    /// read arguments no frame can have refuses them only if one would
    /// start now.
    Prepare,
    /// Send the bytes as more of the frame under way, which a host found
    /// by `Prepare`; the host says the call's trace lines, in its words.
    SendMore(&'a [u8]),
}

/// What a [`Call::Prepare`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prepared {
    /// A frame is under way: a send is more of it, its flags and length
    /// not read.
    UnderWay,
    /// A send starts a frame.
    NewFrame,
    /// What waits to go did not, for now (`CURLE_AGAIN`).
    WouldBlock,
}

/// What a [`Call`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Received(Received),
    Sent(Sent),
    Started,
    Prepared(Prepared),
}
