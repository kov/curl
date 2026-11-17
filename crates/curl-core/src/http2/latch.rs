//! A session the library has said is ended is called no more
//! (`ngh2_shim`): nghttp2 allows no call into a session after one
//! failed fatally, so the first fatal failure is kept, and every later
//! call answers it without reaching the library.

use super::{BodyRead, Event, FrameError, H2Error, Heard, Session, Setting, StreamId, Took, Wants};

/// A library's session, and the fatal failure that ended it, once one
/// has. The only way the layers reach a session.
#[derive(Debug)]
pub(crate) struct Latched {
    session: Box<dyn Session>,
    ended: Option<FrameError>,
}

impl Latched {
    pub(crate) fn new(session: Box<dyn Session>) -> Latched {
        Latched {
            session,
            ended: None,
        }
    }

    /// The fatal failure that ended the session, if one has
    /// (`Curl_ngh2_valid`'s negation).
    pub(crate) fn ended(&self) -> Option<FrameError> {
        self.ended
    }

    /// `f` called on the session, unless it has ended, which answers
    /// the failure that ended it instead; a fatal failure of `f`'s ends
    /// it (`ngh2_check`).
    fn call<T>(
        &mut self,
        f: impl FnOnce(&mut dyn Session) -> Result<T, FrameError>,
    ) -> Result<T, FrameError> {
        if let Some(e) = self.ended {
            return Err(e);
        }
        let r = f(&mut *self.session);
        if let Err(e) = r
            && e.fatal
        {
            self.ended = Some(e);
        }
        r
    }

    /// What `f` asks of the session, or `none` once it has ended.
    fn ask<T>(&self, none: T, f: impl FnOnce(&dyn Session) -> T) -> T {
        if self.ended.is_some() {
            none
        } else {
            f(&*self.session)
        }
    }
}

impl Session for Latched {
    fn submit_settings(&mut self, settings: &[Setting]) -> Result<(), FrameError> {
        self.call(|s| s.submit_settings(settings))
    }

    fn set_local_window(&mut self, size: i32) -> Result<(), FrameError> {
        self.call(|s| s.set_local_window(size))
    }

    fn submit_request(
        &mut self,
        fields: &[(&[u8], &[u8])],
        body: bool,
        weight: u16,
    ) -> Result<StreamId, FrameError> {
        self.call(|s| s.submit_request(fields, body, weight))
    }

    fn upgrade(&mut self, settings: &[u8], head: bool) -> Result<StreamId, FrameError> {
        self.call(|s| s.upgrade(settings, head))
    }

    fn recv(
        &mut self,
        bytes: &[u8],
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<usize, FrameError> {
        self.call(|s| s.recv(bytes, events))
    }

    fn send(
        &mut self,
        out: &mut dyn FnMut(&[u8]) -> Took,
        body: &mut dyn FnMut(StreamId, &mut [u8]) -> BodyRead,
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<(), FrameError> {
        self.call(|s| s.send(out, body, events))
    }

    fn set_stream_window(&mut self, stream: StreamId, size: i32) -> Result<(), FrameError> {
        self.call(|s| s.set_stream_window(stream, size))
    }

    fn stream_window(&self, stream: StreamId) -> i32 {
        self.ask(0, |s| s.stream_window(stream))
    }

    fn stream_recv_length(&self, stream: StreamId) -> i32 {
        self.ask(0, |s| s.stream_recv_length(stream))
    }

    fn local_window(&self) -> i32 {
        self.ask(0, |s| s.local_window())
    }

    fn peer_enables_push(&self) -> bool {
        self.ask(false, |s| s.peer_enables_push())
    }

    fn remote_window(&self) -> i32 {
        self.ask(0, |s| s.remote_window())
    }

    fn stream_remote_window(&self, stream: StreamId) -> i32 {
        self.ask(0, |s| s.stream_remote_window(stream))
    }

    fn submit_window_update(&mut self, stream: StreamId, increment: i32) -> Result<(), FrameError> {
        self.call(|s| s.submit_window_update(stream, increment))
    }

    fn consume(&mut self, stream: StreamId, n: usize) -> Result<(), FrameError> {
        self.call(|s| s.consume(stream, n))
    }

    fn resume(&mut self, stream: StreamId) -> Result<(), FrameError> {
        self.call(|s| s.resume(stream))
    }

    fn reset(&mut self, stream: StreamId, error: H2Error) -> Result<(), FrameError> {
        self.call(|s| s.reset(stream, error))
    }

    fn goaway(&mut self, error: H2Error, debug: &[u8]) -> Result<(), FrameError> {
        self.call(|s| s.goaway(error, debug))
    }

    fn ping(&mut self) -> Result<(), FrameError> {
        self.call(|s| s.ping())
    }

    fn wants(&self) -> Wants {
        self.ask(
            Wants {
                read: false,
                write: false,
            },
            |s| s.wants(),
        )
    }

    fn max_concurrent(&self) -> u32 {
        self.ask(0, |s| s.max_concurrent())
    }
}

#[cfg(test)]
mod tests;
