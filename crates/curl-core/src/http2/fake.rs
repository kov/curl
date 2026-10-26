//! A test library that frames HTTP/2 as lines a test can write and read:
//! no binary framing, no windows, but streams, their fields, bodies, ends,
//! resets and a GOAWAY, read over any split of the input.
//!
//! The client sends, and the server is written as, these frames:
//!
//! - `S\n`: SETTINGS; the client's with its settings, `S MCS=100;...\n`,
//!   the server's with its limit on streams open at once, `S <n>\n`.
//! - `H <id> <end>\n` then `name: value\n` per field and `\n`: a header
//!   block; `<end>` is 1 if it ends the stream.
//! - `D <id> <len> <end>\n` then `<len>` bytes: DATA.
//! - `R <id> <code>\n`: RST_STREAM.
//! - `G <last> <code>\n`: GOAWAY.
//! - `U <id>\n`: WINDOW_UPDATE; the client's says by how much,
//!   `U <id> <n>\n`. Each stream's receive window starts at 64 KiB, and
//!   the server is not held to it; as with nghttp2, a closed stream's
//!   window is no one's, and an update queued for it is not sent. What
//!   the client says it used of a stream's data goes as an update once it
//!   comes to half the stream's window, as nghttp2 sends it without
//!   automatic updates; a window shut to nothing gets none.
//! - `P\n`: PING.
//! - `PP <id> <promised>\n` then `name: value\n` per field and `\n`: a
//!   PUSH_PROMISE on stream `<id>`, which the client cannot have closed.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::collections::VecDeque;
use std::fmt::Write as _;

use curl_alloc::OutOfMemory;

use super::{BodyRead, Event, FrameError, Heard, Http2, Session, Setting, StreamId, Wants};

/// The fake library.
#[derive(Debug, Default)]
pub struct FakeH2;

impl Http2 for FakeH2 {
    fn client(&self) -> Result<Box<dyn Session>, OutOfMemory> {
        Ok(Box::new(FakeSession::default()))
    }

    fn error_text(&self, code: u32) -> &'static str {
        match code {
            0 => "NO_ERROR",
            1 => "PROTOCOL_ERROR",
            2 => "INTERNAL_ERROR",
            5 => "STREAM_CLOSED",
            7 => "REFUSED_STREAM",
            8 => "CANCEL",
            _ => "unknown",
        }
    }

    fn settings_payload(&self, settings: &[Setting], out: &mut [u8]) -> Result<usize, FrameError> {
        let text = settings_text(settings);
        let n = text.len();
        out.get_mut(..n)
            .ok_or(FrameError {
                code: -501,
                text: "Insufficient buffer size given to function",
                fatal: false,
            })?
            .copy_from_slice(text.as_bytes());
        Ok(n)
    }
}

fn settings_text(settings: &[Setting]) -> String {
    let mut text = String::new();
    for s in settings {
        match s {
            Setting::MaxConcurrentStreams(n) => write!(text, "MCS={n};"),
            Setting::InitialWindowSize(n) => write!(text, "IWS={n};"),
            Setting::EnablePush(b) => write!(text, "EP={};", u8::from(*b)),
        }
        .unwrap();
    }
    text
}

/// A block of fields, ending at an empty line: the fields, and how far
/// the block goes; none until it is whole.
fn block(rest: &[u8]) -> Option<(Vec<&[u8]>, usize)> {
    let mut fields = Vec::new();
    let mut at = 0;
    loop {
        let e = rest[at..].iter().position(|&b| b == b'\n')?;
        let field = &rest[at..at + e];
        at += e + 1;
        if field.is_empty() {
            return Some((fields, at));
        }
        fields.push(field);
    }
}

/// A field's name and value; a pseudo-header's name starts with its colon.
fn split_field(field: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = field.iter().position(|&b| b == b':')?;
    let colon = if colon == 0 {
        1 + field[1..].iter().position(|&b| b == b':')?
    } else {
        colon
    };
    let value = &field[colon + 1..];
    Some((&field[..colon], value.strip_prefix(b" ").unwrap_or(value)))
}

/// A stream's state, as the client sees it.
#[derive(Debug, Default)]
struct Stream {
    /// The client's side is done: its last frame went.
    local_end: bool,
    /// The server's side is done.
    remote_end: bool,
    /// Its body waits to be resumed.
    deferred: bool,
    /// It has a body to read.
    body: bool,
    closed: bool,
    /// Its receive window, less 64 KiB, its start.
    window: i32,
    /// What the client used of its data and did not tell the peer yet.
    consumed: i32,
}

/// Each stream's receive window as it opens.
const STREAM_WINDOW: i32 = 64 * 1024;

/// A fake session.
#[derive(Debug, Default)]
pub struct FakeSession {
    next: i32,
    streams: Vec<(i32, Stream)>,
    /// Frames queued to go, before any body.
    queued: VecDeque<Vec<u8>>,
    /// Input not yet a whole frame.
    input: Vec<u8>,
    goaway: bool,
    /// Streams the client reset, told closed as their RST_STREAM goes.
    resets: Vec<(i32, u32)>,
    /// The server's limit on streams open at once, as its `S <n>` said.
    max_concurrent: Option<u32>,
}

impl FakeSession {
    fn stream(&mut self, id: i32) -> Option<&mut Stream> {
        self.streams
            .iter_mut()
            .find(|(i, _)| *i == id)
            .map(|(_, s)| s)
    }

    /// `id`, while it is open.
    fn open(&mut self, id: i32) -> Option<&mut Stream> {
        self.stream(id).filter(|s| !s.closed)
    }

    /// Whether `frame` is a WINDOW_UPDATE for a stream since closed.
    fn stale_update(&mut self, frame: &[u8]) -> bool {
        let Some(rest) = frame.strip_prefix(b"U ") else {
            return false;
        };
        let id = rest.split(|&b| b == b' ').next().unwrap_or_default();
        let id: i32 = std::str::from_utf8(id).unwrap().parse().unwrap();
        id != 0 && self.open(id).is_none()
    }

    /// Close `id` if both its sides are done, telling `events`.
    fn maybe_close(&mut self, id: i32, events: &mut dyn FnMut(Event<'_>) -> Heard) -> Heard {
        let Some(s) = self.stream(id) else {
            return Heard::Fine;
        };
        if s.local_end && s.remote_end && !s.closed {
            s.closed = true;
            return events(Event::Closed {
                stream: StreamId(id),
                error: 0,
            });
        }
        Heard::Fine
    }

    /// One whole frame from the front of the input, read and told: how
    /// many bytes it was, or none if it is not all there.
    fn frame(
        &mut self,
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<Option<usize>, FrameError> {
        let input = std::mem::take(&mut self.input);
        let r = self.frame_of(&input, events);
        self.input = input;
        r
    }

    fn frame_of(
        &mut self,
        input: &[u8],
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<Option<usize>, FrameError> {
        let bad = FrameError {
            code: -505,
            text: "Received bad client magic byte string",
            fatal: true,
        };
        let failed = FrameError {
            code: -902,
            text: "The user callback function failed",
            fatal: true,
        };
        let Some(nl) = input.iter().position(|&b| b == b'\n') else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&input[..nl]).map_err(|_| bad)?;
        let words: Vec<&str> = line.split(' ').collect();
        let num = |i: usize| -> Result<i64, FrameError> {
            words.get(i).and_then(|w| w.parse().ok()).ok_or(bad)
        };
        let check = |h: Heard| {
            if h == Heard::Failed {
                Err(failed)
            } else {
                Ok(())
            }
        };
        match words[0] {
            "S" => {
                if words.len() > 1 {
                    self.max_concurrent = Some(u32::try_from(num(1)?).map_err(|_| bad)?);
                }
                check(events(Event::Settings))?;
                Ok(Some(nl + 1))
            }
            "P" => Ok(Some(nl + 1)),
            "U" => {
                let id = num(1)? as i32;
                if let Some(s) = self.stream(id)
                    && s.deferred
                {
                    s.deferred = false;
                }
                check(events(Event::WindowUpdate {
                    stream: StreamId(id),
                }))?;
                Ok(Some(nl + 1))
            }
            "PP" => {
                let id = num(1)? as i32;
                let promised = num(2)? as i32;
                let Some((fields, at)) = block(&input[nl + 1..]) else {
                    return Ok(None);
                };
                for field in fields {
                    let (name, value) = split_field(field).ok_or(bad)?;
                    check(events(Event::PushField {
                        stream: StreamId(id),
                        name,
                        value,
                    }))?;
                }
                // The client sends nothing on a pushed stream.
                self.streams.push((
                    promised,
                    Stream {
                        local_end: true,
                        ..Stream::default()
                    },
                ));
                check(events(Event::Promised {
                    stream: StreamId(id),
                    promised: StreamId(promised),
                }))?;
                Ok(Some(nl + 1 + at))
            }
            "H" => {
                let id = num(1)? as i32;
                let end = num(2)? == 1;
                let Some((fields, at)) = block(&input[nl + 1..]) else {
                    return Ok(None);
                };
                for field in fields {
                    let (name, value) = split_field(field).ok_or(bad)?;
                    check(events(Event::Header {
                        stream: StreamId(id),
                        name,
                        value,
                    }))?;
                }
                check(events(Event::HeadersDone {
                    stream: StreamId(id),
                    end_stream: end,
                }))?;
                if end && let Some(s) = self.stream(id) {
                    s.remote_end = true;
                }
                check(self.maybe_close(id, events))?;
                Ok(Some(nl + 1 + at))
            }
            "D" => {
                let id = num(1)? as i32;
                let len = num(2)? as usize;
                let end = num(3)? == 1;
                let Some(bytes) = input.get(nl + 1..nl + 1 + len) else {
                    return Ok(None);
                };
                if !bytes.is_empty() {
                    check(events(Event::Data {
                        stream: StreamId(id),
                        bytes,
                    }))?;
                }
                if end {
                    check(events(Event::DataEnd {
                        stream: StreamId(id),
                    }))?;
                    if let Some(s) = self.stream(id) {
                        s.remote_end = true;
                    }
                    check(self.maybe_close(id, events))?;
                }
                Ok(Some(nl + 1 + len))
            }
            "R" => {
                let id = num(1)? as i32;
                let code = num(2)? as u32;
                check(events(Event::Reset {
                    stream: StreamId(id),
                    error: code,
                }))?;
                if let Some(s) = self.stream(id)
                    && !s.closed
                {
                    s.closed = true;
                    check(events(Event::Closed {
                        stream: StreamId(id),
                        error: code,
                    }))?;
                }
                Ok(Some(nl + 1))
            }
            "G" => {
                let last = num(1)? as i32;
                let code = num(2)? as u32;
                self.goaway = true;
                check(events(Event::GoAway {
                    last_stream: StreamId(last),
                    error: code,
                }))?;
                let refused: Vec<i32> = self
                    .streams
                    .iter()
                    .filter(|(i, s)| *i > last && !s.closed)
                    .map(|(i, _)| *i)
                    .collect();
                for id in refused {
                    self.stream(id).unwrap().closed = true;
                    check(events(Event::Closed {
                        stream: StreamId(id),
                        error: super::code::REFUSED_STREAM,
                    }))?;
                }
                Ok(Some(nl + 1))
            }
            _ => Err(bad),
        }
    }
}

impl Session for FakeSession {
    fn submit_settings(&mut self, settings: &[Setting]) -> Result<(), FrameError> {
        self.queued
            .push_back(format!("S {}\n", settings_text(settings)).into_bytes());
        Ok(())
    }

    fn set_local_window(&mut self, _: i32) -> Result<(), FrameError> {
        Ok(())
    }

    fn submit_request(
        &mut self,
        fields: &[(&[u8], &[u8])],
        body: bool,
        weight: u16,
    ) -> Result<StreamId, FrameError> {
        self.next = if self.next == 0 { 1 } else { self.next + 2 };
        let id = self.next;
        let mut frame = format!("H {id} {}\n", u8::from(!body)).into_bytes();
        // A weight not the default goes with the head, as PRIORITY does.
        if weight != super::code::DEFAULT_WEIGHT {
            frame.extend_from_slice(format!("weight: {weight}\n").as_bytes());
        }
        for (name, value) in fields {
            frame.extend_from_slice(name);
            frame.extend_from_slice(b": ");
            frame.extend_from_slice(value);
            frame.push(b'\n');
        }
        frame.push(b'\n');
        self.queued.push_back(frame);
        self.streams.push((
            id,
            Stream {
                local_end: !body,
                body,
                ..Stream::default()
            },
        ));
        Ok(StreamId(id))
    }

    fn upgrade(&mut self, _: &[u8], _: bool) -> Result<StreamId, FrameError> {
        self.next = 1;
        self.streams.push((
            1,
            Stream {
                local_end: true,
                ..Stream::default()
            },
        ));
        Ok(StreamId(1))
    }

    fn recv(
        &mut self,
        bytes: &[u8],
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<usize, FrameError> {
        self.input.extend_from_slice(bytes);
        while let Some(n) = self.frame(events)? {
            self.input.drain(..n);
        }
        Ok(bytes.len())
    }

    fn send(
        &mut self,
        out: &mut dyn FnMut(&[u8]) -> bool,
        body: &mut dyn FnMut(StreamId, &mut [u8]) -> BodyRead,
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<(), FrameError> {
        // A stream the client reset closes as its RST_STREAM goes, as
        // nghttp2 tells it.
        for (id, error) in std::mem::take(&mut self.resets) {
            events(Event::Closed {
                stream: StreamId(id),
                error,
            });
        }
        while let Some(frame) = self.queued.pop_front() {
            if self.stale_update(&frame) {
                continue;
            }
            if !out(&frame) {
                return Ok(());
            }
        }
        let open: Vec<i32> = self
            .streams
            .iter()
            .filter(|(_, s)| s.body && !s.local_end && !s.deferred && !s.closed)
            .map(|(i, _)| *i)
            .collect();
        for id in open {
            loop {
                let mut room = [0u8; 16384];
                let (n, last) = match body(StreamId(id), &mut room) {
                    BodyRead::Bytes(n) => (n, false),
                    BodyRead::Last(n) => (n, true),
                    BodyRead::Later => {
                        self.stream(id).unwrap().deferred = true;
                        break;
                    }
                    BodyRead::Failed => {
                        self.queued.push_back(format!("R {id} 2\n").into_bytes());
                        let s = self.stream(id).unwrap();
                        s.closed = true;
                        events(Event::Closed {
                            stream: StreamId(id),
                            error: 2,
                        });
                        break;
                    }
                };
                let mut frame = format!("D {id} {n} {}\n", u8::from(last)).into_bytes();
                frame.extend_from_slice(&room[..n]);
                let more = out(&frame);
                if last {
                    self.stream(id).unwrap().local_end = true;
                    self.maybe_close(id, events);
                    break;
                }
                if !more {
                    return Ok(());
                }
            }
        }
        while let Some(frame) = self.queued.pop_front() {
            if self.stale_update(&frame) {
                continue;
            }
            if !out(&frame) {
                return Ok(());
            }
        }
        Ok(())
    }

    fn consume(&mut self, stream: StreamId, n: usize) -> Result<(), FrameError> {
        let id = stream.0;
        let Some(s) = self.open(id) else {
            return Ok(());
        };
        s.consumed += i32::try_from(n).expect("a read fits a window");
        let window = s.window + STREAM_WINDOW;
        if window > 0 && s.consumed >= window / 2 {
            let by = std::mem::take(&mut s.consumed);
            self.queued.push_back(format!("U {id} {by}\n").into_bytes());
        }
        Ok(())
    }

    fn set_stream_window(&mut self, stream: StreamId, size: i32) -> Result<(), FrameError> {
        let Some(s) = self.open(stream.0) else {
            return Ok(());
        };
        s.window = size - STREAM_WINDOW;
        Ok(())
    }

    fn stream_window(&self, stream: StreamId) -> i32 {
        self.streams
            .iter()
            .find(|(i, s)| *i == stream.0 && !s.closed)
            .map_or(-1, |(_, s)| s.window + STREAM_WINDOW)
    }

    /// The fake keeps no send windows: the peer always has room.
    fn remote_window(&self) -> i32 {
        i32::MAX
    }

    fn stream_remote_window(&self, stream: StreamId) -> i32 {
        self.streams
            .iter()
            .find(|(i, s)| *i == stream.0 && !s.closed)
            .map_or(-1, |_| i32::MAX)
    }

    fn submit_window_update(&mut self, stream: StreamId, by: i32) -> Result<(), FrameError> {
        let id = stream.0;
        if self.open(id).is_none() {
            return Ok(());
        }
        self.queued.push_back(format!("U {id} {by}\n").into_bytes());
        Ok(())
    }

    fn resume(&mut self, stream: StreamId) -> Result<(), FrameError> {
        if let Some(s) = self.stream(stream.0) {
            s.deferred = false;
        }
        Ok(())
    }

    fn reset(&mut self, stream: StreamId, error: u32) -> Result<(), FrameError> {
        let id = stream.0;
        self.queued
            .push_back(format!("R {id} {error}\n").into_bytes());
        if let Some(s) = self.stream(id)
            && !s.closed
        {
            s.closed = true;
            self.resets.push((id, error));
        }
        Ok(())
    }

    fn goaway(&mut self, error: u32, _: &[u8]) -> Result<(), FrameError> {
        self.queued.push_back(format!("G 0 {error}\n").into_bytes());
        self.goaway = true;
        Ok(())
    }

    fn ping(&mut self) -> Result<(), FrameError> {
        self.queued.push_back(b"P\n".to_vec());
        Ok(())
    }

    fn max_concurrent(&self) -> u32 {
        self.max_concurrent.unwrap_or(u32::MAX)
    }

    fn wants(&self) -> Wants {
        let body = self
            .streams
            .iter()
            .any(|(_, s)| s.body && !s.local_end && !s.deferred && !s.closed);
        Wants {
            read: !self.goaway || self.streams.iter().any(|(_, s)| !s.closed),
            write: !self.queued.is_empty() || body,
        }
    }
}
