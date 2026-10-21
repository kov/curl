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
#[derive(Debug)]
pub(crate) struct Player {
    next: usize,
    pipeline: Pipeline,
}

impl Default for Player {
    fn default() -> Player {
        Player {
            next: 0,
            pipeline: Pipeline::new(true),
        }
    }
}

impl Player {
    #[cfg(debug_assertions)]
    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    /// Replay what is held, then deliver the rest of the script while the
    /// transfer receives; done at its end, once nothing is held.
    pub(crate) fn step<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<ProtoStep, ErrorKind> {
        self.pipeline.flush(cx)?;
        loop {
            // A paused transfer reads nothing more.
            if cx.pause().recv_paused() {
                return Ok(ProtoStep::Blocked);
            }
            // Read again for every piece: a handler may change the options.
            let Some(script) = cx.easy().options().script.clone() else {
                return Ok(ProtoStep::Done);
            };
            let Some(piece) = script.get(self.next) else {
                // The flush above delivered it all, or the pause stopped us.
                assert!(!self.pipeline.holds_output(), "done with output held");
                return Ok(ProtoStep::Done);
            };
            self.next += 1;
            match piece {
                Piece::Status(line) => self.pipeline.status(cx, line)?,
                Piece::Header(line) => self.pipeline.header(cx, line, HeaderOrigin::Header)?,
                Piece::Connect(line) => self.pipeline.header(cx, line, HeaderOrigin::Connect)?,
                Piece::Body(bytes) => self.pipeline.body(cx, bytes)?,
                Piece::Size(size) => self.pipeline.announce_size(cx, Some(*size)),
                Piece::Yield => return Ok(ProtoStep::Blocked),
            }
        }
    }
}
