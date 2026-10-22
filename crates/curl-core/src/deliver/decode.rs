//! Undoing a body's content codings, and the gate in front of them that
//! holds what they would undo while a handler pauses (`lib/cw-pause.c`):
//! a decoder may make far more than it is given, so paused output is kept
//! as it came, and handed on in small pieces.

use std::fmt;

use super::held::{HeldOutput, OutKind};
use crate::error::ErrorKind;

/// The most body a decoder is given at once behind the gate
/// (`CW_PAUSE_DEC_WRITE_CHUNK`).
pub(crate) const GATE_PIECE: usize = 4096;

/// A content coding being undone (C's unencoding writers).
pub(crate) trait Decoder: fmt::Debug {
    /// Undo `input`, giving what it makes to `out` as it is made.
    fn decode(
        &mut self,
        input: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), ErrorKind>,
    ) -> Result<(), ErrorKind>;

    /// What it makes may be far larger than what it is given
    /// (`CURL_CW_FLAG_BLOWUP`): the gate goes in front of it.
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(dead_code, reason = "only the test protocol adds one yet")
    )]
    fn blows_up(&self) -> bool;
}

/// Run `input` through `chain`, the last added first (C adds each writer
/// in front of its phase), and what the first added makes into `last`.
pub(crate) fn run(
    chain: &mut [Box<dyn Decoder>],
    input: &[u8],
    last: &mut dyn FnMut(&[u8]) -> Result<(), ErrorKind>,
) -> Result<(), ErrorKind> {
    match chain.split_last_mut() {
        None => last(input),
        Some((first, rest)) => first.decode(input, &mut |piece| run(rest, piece, &mut *last)),
    }
}

/// What is past the gate: the decoders, then the handlers.
pub(crate) trait Onward {
    /// A handler paused: nothing more goes on (`Curl_cwriter_is_paused`).
    fn paused(&self) -> bool;
    fn take(&mut self, kind: OutKind, bytes: &[u8]) -> Result<(), ErrorKind>;
}

/// Output held in front of the decoders while a handler pauses
/// (`cw_pause_ctx`): header lines too, so they stay behind the body that
/// came before them. What it holds is the encoded body, without a limit.
#[derive(Debug)]
pub(crate) struct Gate {
    held: HeldOutput,
}

impl Default for Gate {
    fn default() -> Gate {
        Gate {
            held: HeldOutput::limited(usize::MAX),
        }
    }
}

impl Gate {
    /// Hand `bytes` on unless a handler paused or the gate holds output
    /// still, body in pieces of at most `GATE_PIECE`; hold what does not
    /// go (`cw_pause_write`).
    pub(crate) fn write(
        &mut self,
        kind: OutKind,
        mut bytes: &[u8],
        onward: &mut dyn Onward,
    ) -> Result<(), ErrorKind> {
        if !self.held.is_empty() && !onward.paused() {
            self.flush(onward)?;
        }
        while self.held.is_empty() && !onward.paused() {
            let n = piece(kind, bytes.len());
            onward.take(kind, &bytes[..n])?;
            bytes = &bytes[n..];
            if bytes.is_empty() {
                return Ok(());
            }
        }
        self.held.append(kind, bytes)
    }

    /// Hand on what is held, in the order it came, until it is all gone
    /// or a handler pauses (`cw_pause_flush_do`).
    pub(crate) fn flush(&mut self, onward: &mut dyn Onward) -> Result<(), ErrorKind> {
        while !onward.paused() {
            let Some((kind, bytes)) = self.held.front() else {
                break;
            };
            let n = piece(kind, bytes.len());
            onward.take(kind, &bytes[..n])?;
            self.held.consume(n);
        }
        Ok(())
    }

    pub(crate) fn holds_output(&self) -> bool {
        !self.held.is_empty()
    }
}

/// How much of `len` bytes of `kind` go on at once: body in small pieces,
/// so what a decoder makes of each stays small; a header line whole.
fn piece(kind: OutKind, len: usize) -> usize {
    match kind {
        OutKind::Body => len.min(GATE_PIECE),
        OutKind::Header(_) => len,
    }
}
