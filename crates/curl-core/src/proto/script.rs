//! `script:`, the test protocol that delivers its transfer's
//! `Options::script` as a real protocol's client writes would.

use curl_alloc::TryVec;

use crate::deliver::{Pipeline, Reach};
use crate::error::ErrorKind;
use crate::handler::HeaderOrigin;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::Options;
use crate::options::script::Piece;
use crate::report::Timer;
use crate::upload::{self, Upload};

use super::ProtoStep;

/// The most a send piece reads at once.
const SEND_BUFFER: usize = 16384;

/// How far into its script a transfer is.
#[derive(Debug)]
pub(crate) struct Player {
    next: usize,
    pipeline: Pipeline,
    /// The body to send, from the first piece that sends.
    upload: Option<Upload>,
    send_buffer: Vec<u8>,
    /// The whole body is sent.
    uploaded: bool,
}

impl Default for Player {
    fn default() -> Player {
        Player {
            next: 0,
            pipeline: Pipeline::new(Reach::Network),
            upload: None,
            send_buffer: Vec::new(),
            uploaded: false,
        }
    }
}

/// Whether a script sends anything: its request has a body.
pub(crate) fn wants_send(options: &Options) -> bool {
    let Some(script) = &options.script else {
        return false;
    };
    (0..)
        .map_while(|i| script.get(i))
        .any(|p| matches!(p, Piece::Send(_) | Piece::SendAll))
}

impl Player {
    #[cfg(debug_assertions)]
    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    /// Replay what is held, then play the rest of the script, each piece
    /// while its direction is not paused; done at its end, once nothing is
    /// held.
    pub(crate) fn step<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<ProtoStep, ErrorKind> {
        self.pipeline.flush(cx)?;
        loop {
            // Read again for every piece: a handler may change the options.
            let Some(script) = cx.easy().options().script.clone() else {
                return Ok(ProtoStep::Done);
            };
            let piece = script.get(self.next);
            let sends = matches!(piece, Some(Piece::Send(_) | Piece::SendAll));
            // A paused direction moves nothing more.
            if (sends && cx.pause().send_paused()) || (!sends && cx.pause().recv_paused()) {
                return Ok(ProtoStep::Blocked);
            }
            let Some(piece) = piece else {
                // The flush above delivered it all, or the pause stopped us.
                assert!(!self.pipeline.holds_output(), "done with output held");
                return Ok(ProtoStep::Done);
            };
            match piece {
                Piece::Send(n) => {
                    if self.send(cx, *n)?.is_none() {
                        return Ok(ProtoStep::Blocked);
                    }
                }
                Piece::SendAll => loop {
                    match self.send(cx, SEND_BUFFER)? {
                        None => return Ok(ProtoStep::Blocked),
                        Some(true) => break,
                        Some(false) => {}
                    }
                },
                Piece::Rewind => self.upload(cx)?.rewind(cx)?,
                Piece::Status(line) => self.pipeline.status(cx, line)?,
                Piece::Header(line) => self.pipeline.header(cx, line, HeaderOrigin::Header)?,
                Piece::Connect(line) => self.pipeline.header(cx, line, HeaderOrigin::Connect)?,
                Piece::Body(bytes) => self.pipeline.body(cx, bytes)?,
                Piece::Size(size) => self.pipeline.announce_size(cx, Some(*size)),
                Piece::Yield => {
                    self.next += 1;
                    return Ok(ProtoStep::Blocked);
                }
            }
            self.next += 1;
        }
    }

    /// The body, from its start the first time.
    fn upload<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<&mut Upload, ErrorKind> {
        if self.upload.is_none() {
            let upload = Upload::new(&cx.easy().options().upload);
            upload::announce_size(cx, upload.size());
            self.upload = Some(upload);
        }
        Ok(self.upload.as_mut().expect("just made"))
    }

    /// Read up to `n` bytes of the body and send them; whether the body is
    /// complete, or `None` if the read paused, the piece to be played
    /// again.
    fn send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        n: usize,
    ) -> Result<Option<bool>, ErrorKind> {
        if self.send_buffer.is_empty() {
            self.send_buffer
                .try_extend_from_slice(&[0; SEND_BUFFER])
                .map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let pausable = self.pipeline.pausable();
        self.upload(cx)?;
        let upload = self.upload.as_mut().expect("just made");
        let buf = &mut self.send_buffer[..n.clamp(1, SEND_BUFFER)];
        let got = upload.read(cx, buf, pausable)?;
        if got.n == 0 && !got.eos {
            return Ok(None);
        }
        upload::sent(cx, &buf[..got.n]);
        if got.eos && !self.uploaded {
            // The request is sent (`req_set_upload_done`).
            self.uploaded = true;
            cx.directions_mut().send = false;
            cx.mark(Timer::PostTransfer);
        }
        Ok(Some(got.eos))
    }
}
