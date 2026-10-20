//! `script:`, the test protocol that delivers its transfer's
//! `Options::script` as a real protocol's client writes would.

use crate::deliver::Pipeline;
use crate::error::ErrorKind;
use crate::handler::HeaderOrigin;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::script::Piece;

use super::ProtoStep;

/// How far into its script a transfer is.
#[derive(Debug, Default)]
pub(crate) struct Player {
    next: usize,
    pipeline: Pipeline,
}

impl Player {
    /// Deliver the rest of the script; done at its end.
    pub(crate) fn step<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<ProtoStep, ErrorKind> {
        loop {
            // Read again for every piece: a handler may change the options.
            let Some(script) = cx.easy().options().script.clone() else {
                return Ok(ProtoStep::Done);
            };
            let Some(piece) = script.get(self.next) else {
                return Ok(ProtoStep::Done);
            };
            self.next += 1;
            match piece {
                Piece::Status(line) => self.pipeline.status(cx, line)?,
                Piece::Header(line) => self.pipeline.header(cx, line, HeaderOrigin::Header)?,
                Piece::Connect(line) => self.pipeline.header(cx, line, HeaderOrigin::Connect)?,
                Piece::Body(bytes) => self.pipeline.body(cx, bytes)?,
            }
        }
    }
}
