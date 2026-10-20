//! What the test protocol `script:` delivers, piece by piece: each piece is
//! one client write, as a protocol makes them.

use curl_alloc::{OutOfMemory, TryRc};

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
}

/// The pieces, shared by every copy of the options.
#[derive(Clone, Debug)]
pub struct Script(TryRc<Vec<Piece>>);

impl Script {
    pub fn new(pieces: Vec<Piece>) -> Result<Script, OutOfMemory> {
        Ok(Script(TryRc::try_new(pieces)?))
    }

    pub(crate) fn get(&self, i: usize) -> Option<&Piece> {
        self.0.get(i)
    }
}
