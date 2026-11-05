//! What the test protocol `script:` delivers, piece by piece: each piece is
//! one client write, as a protocol makes them.

use curl_alloc::{OutOfMemory, TryArc};

/// One client write.
#[derive(Debug)]
pub enum Piece {
    /// A status line, with its line ending.
    Status(Vec<u8>),
    /// A header line, with its line ending.
    Header(Vec<u8>),
    /// A header line of a proxy's answer to CONNECT.
    Connect(Vec<u8>),
    Body(Vec<u8>),
    /// The body's size, as a response announces it.
    Size(u64),
    /// Nothing more until the next step, as if waiting for the network.
    Yield,
    /// One read of at most this many bytes of the body, sent.
    Send(usize),
    /// The rest of the body, read and sent.
    SendAll,
    /// The body from its start again, as for a request sent again.
    Rewind,
    /// The body, not yet read, from this many bytes in, as for an upload
    /// resumed there.
    Resume(u64),
    /// A content coding to undo from here on, one that makes this many
    /// bytes of each it is given, as a decompressor may make far more than
    /// it reads.
    Expand(usize),
    /// Before the request: the protocol's connect waits a step
    /// (PROTOCONNECTING).
    ProtoConnecting,
    /// Before the request is made: its first half takes another step
    /// (DOING), or, in its second half, goes back to it (DOMORE_GOBACK).
    Doing,
    /// Before the request is made: its second half takes a step
    /// (DOING_MORE).
    DoingMore,
    /// `tcp:` keeps state on its connection as it connects, which says
    /// these bytes as the connection shuts down.
    Goodbye(Vec<u8>),
    /// As `Goodbye`, and then awaits a line in answer, as a pingpong
    /// protocol's goodbye does.
    GoodbyeAwaits(Vec<u8>),
}

/// The pieces, shared by every copy of the options.
#[derive(Clone, Debug)]
pub struct Script(TryArc<Vec<Piece>>);

impl Script {
    pub fn new(pieces: Vec<Piece>) -> Result<Script, OutOfMemory> {
        Ok(Script(TryArc::try_new(pieces)?))
    }

    pub(crate) fn get(&self, i: usize) -> Option<&Piece> {
        self.0.get(i)
    }
}
