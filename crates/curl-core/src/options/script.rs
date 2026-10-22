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
    /// A content coding to undo from here on, one that makes this many
    /// bytes of each it is given, as a decompressor may make far more than
    /// it reads.
    Expand(usize),
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
