//! HTTP/2 framing from nghttp2, as C's `lib/http2.c` uses it: a client
//! session fed the connection's bytes and asked for the bytes it wants
//! sent, telling what it read stream by stream.
//!
//! The session is made with C's options: window updates are the
//! caller's to give (`nghttp2_option_set_no_auto_window_update`), and a
//! field's leading and trailing blanks are not refused
//! (`..._no_rfc9113_leading_and_trailing_ws_validation`).

#![allow(unsafe_code)]

mod sys;

use core::ffi::{CStr, c_int, c_void};
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use curl_core::http2::Http2;
pub use curl_core::http2::{BodyRead, Event, FrameError, Heard, Setting, StreamId, Wants};

/// The library, as the handles are given it.
pub static NGHTTP2: Nghttp2 = Nghttp2;

/// nghttp2, as a library the core speaks HTTP/2 through.
#[derive(Debug)]
pub struct Nghttp2;

impl Http2 for Nghttp2 {
    fn client(&self) -> Result<Box<dyn curl_core::http2::Session>, OutOfMemory> {
        let session = Session::client().map_err(|SessionError::OutOfMemory| OutOfMemory)?;
        Ok(try_box(session)?)
    }

    fn error_text(&self, code: u32) -> &'static str {
        http2_error_text(code)
    }

    fn settings_payload(&self, settings: &[Setting], out: &mut [u8]) -> Result<usize, FrameError> {
        let (iv, n) = entries(settings);
        // SAFETY: `out`'s bytes, and `n` entries.
        let len = unsafe {
            sys::nghttp2_pack_settings_payload2(out.as_mut_ptr(), out.len(), iv.as_ptr(), n)
        };
        usize::try_from(len)
            .map_err(|_| error(c_int::try_from(len).unwrap_or(sys::NGHTTP2_ERR_NOMEM)))
    }
}

/// `settings` as the library's entries, and how many.
fn entries(settings: &[Setting]) -> ([sys::nghttp2_settings_entry; 8], usize) {
    let mut iv = [sys::nghttp2_settings_entry {
        settings_id: 0,
        value: 0,
    }; 8];
    assert!(settings.len() <= iv.len(), "at most eight settings");
    for (to, setting) in iv.iter_mut().zip(settings) {
        let (id, value) = match *setting {
            Setting::MaxConcurrentStreams(n) => (sys::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, n),
            Setting::InitialWindowSize(n) => (sys::NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, n),
            Setting::EnablePush(on) => (sys::NGHTTP2_SETTINGS_ENABLE_PUSH, u32::from(on)),
        };
        *to = sys::nghttp2_settings_entry {
            settings_id: id,
            value,
        };
    }
    (iv, settings.len())
}

/// The library's failure `code`, with its words for it
/// (`nghttp2_strerror`) and whether it ends the session.
fn error(code: c_int) -> FrameError {
    // SAFETY: `nghttp2_strerror` takes any code.
    let p = unsafe { sys::nghttp2_strerror(code) };
    // SAFETY: and returns a static C string for it.
    let text = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("unknown");
    // SAFETY: it takes any code.
    let fatal = unsafe { sys::nghttp2_is_fatal(code) } != 0;
    FrameError { code, text, fatal }
}

/// The text of an HTTP/2 error code (`nghttp2_http2_strerror`).
pub fn http2_error_text(code: u32) -> &'static str {
    // SAFETY: it takes any code.
    let p = unsafe { sys::nghttp2_http2_strerror(code) };
    // SAFETY: and returns a static C string for it.
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str().unwrap_or("unknown")
}

/// The library's version, as `curl -V` names it (`nghttp2_version`).
pub fn version() -> &'static str {
    version_c().to_str().unwrap_or("unknown")
}

/// The library's own description of itself (`nghttp2_version`).
fn info() -> &'static sys::nghttp2_info {
    // SAFETY: with 0, `nghttp2_version` returns the library's own static
    // description.
    let info = unsafe { sys::nghttp2_version(0) };
    // SAFETY: as above, never NULL with 0.
    unsafe { &*info }
}

/// The library's version, as `curl_version_info` gives it.
pub fn version_c() -> &'static CStr {
    // SAFETY: its version string is a static C string.
    unsafe { CStr::from_ptr(info().version_str) }
}

/// The library's version as a number, `0x010A00` for 1.10.0.
pub fn version_number() -> u32 {
    u32::try_from(info().version_num).unwrap_or(0)
}

/// What the callbacks reach while a call into the session runs: the
/// caller's sinks, lent for the call.
struct Lent {
    events: Option<*mut EventSink>,
    body: Option<*mut BodySource>,
}

/// What hears what the session read.
type EventSink = dyn FnMut(Event<'_>) -> Heard;

/// What reads a request's body: the stream's, into the room given.
type BodySource = dyn FnMut(StreamId, &mut [u8]) -> BodyRead;

/// A client session (`nghttp2_session`).
pub struct Session {
    raw: NonNull<sys::nghttp2_session>,
    /// Where the callbacks find what is lent; boxed, so its address is
    /// the session's user data for its life.
    lent: Box<Lent>,
}

// SAFETY: the session is used by one thread at a time, through `&mut`;
// nghttp2 keeps no thread-local state.
unsafe impl Send for Session {}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Session")
    }
}

/// Which end a session is.
#[derive(Clone, Copy)]
enum End {
    Client,
    #[cfg(test)]
    Server,
}

impl Session {
    /// A client session, with C's options.
    pub fn client() -> Result<Session, SessionError> {
        Session::new(End::Client)
    }

    fn new(end: End) -> Result<Session, SessionError> {
        let lent = try_box(Lent {
            events: None,
            body: None,
        })?;
        let mut callbacks = ptr::null_mut();
        // SAFETY: an out pointer to fill.
        check(unsafe { sys::nghttp2_session_callbacks_new(&mut callbacks) })?;
        let callbacks = Owned(callbacks, sys::nghttp2_session_callbacks_del);
        let mut option = ptr::null_mut();
        // SAFETY: an out pointer to fill.
        check(unsafe { sys::nghttp2_option_new(&mut option) })?;
        let option = Owned(option, sys::nghttp2_option_del);
        // SAFETY: the callbacks and option just made, and functions of
        // the types each setter takes.
        unsafe {
            sys::nghttp2_session_callbacks_set_on_frame_recv_callback(
                callbacks.0,
                Some(on_frame_recv),
            );
        }
        // SAFETY: as above.
        unsafe {
            sys::nghttp2_session_callbacks_set_on_header_callback(callbacks.0, Some(on_header))
        };
        // SAFETY: as above.
        unsafe {
            sys::nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
                callbacks.0,
                Some(on_data),
            )
        };
        // SAFETY: as above.
        unsafe {
            sys::nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.0, Some(on_close))
        };
        // SAFETY: as above.
        unsafe { sys::nghttp2_option_set_no_auto_window_update(option.0, 1) };
        // SAFETY: as above.
        unsafe {
            sys::nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(option.0, 1)
        };
        let mut raw = ptr::null_mut();
        let user = ptr::from_ref::<Lent>(&lent).cast_mut().cast::<c_void>();
        let made = match end {
            // SAFETY: the callbacks and option made above, which the
            // session copies; the user data outlives the session.
            End::Client => unsafe {
                sys::nghttp2_session_client_new2(&mut raw, callbacks.0, user, option.0)
            },
            #[cfg(test)]
            // SAFETY: as above.
            End::Server => unsafe {
                sys::nghttp2_session_server_new2(&mut raw, callbacks.0, user, option.0)
            },
        };
        check(made)?;
        let raw = NonNull::new(raw).ok_or(SessionError::OutOfMemory)?;
        Ok(Session { raw, lent })
    }
}

impl curl_core::http2::Session for Session {
    fn submit_settings(&mut self, settings: &[Setting]) -> Result<(), FrameError> {
        let (iv, n) = entries(settings);
        // SAFETY: the session, and `n` entries.
        check_h2(unsafe { sys::nghttp2_submit_settings(self.raw.as_ptr(), 0, iv.as_ptr(), n) })
    }

    fn set_local_window(&mut self, size: i32) -> Result<(), FrameError> {
        // SAFETY: the session; stream 0 is the connection.
        check_h2(unsafe {
            sys::nghttp2_session_set_local_window_size(self.raw.as_ptr(), 0, 0, size)
        })
    }

    fn submit_request(
        &mut self,
        fields: &[(&[u8], &[u8])],
        body: bool,
        weight: u16,
    ) -> Result<StreamId, FrameError> {
        let mut nva = Vec::new();
        nva.try_reserve_exact(fields.len())
            .map_err(|_| error(sys::NGHTTP2_ERR_NOMEM))?;
        for &(name, value) in fields {
            let pushed = nva.try_push(sys::nghttp2_nv {
                name: name.as_ptr().cast_mut(),
                value: value.as_ptr().cast_mut(),
                namelen: name.len(),
                valuelen: value.len(),
                // The session copies them as it queues the request.
                flags: sys::NGHTTP2_NV_FLAG_NONE,
            });
            pushed.expect("reserved above");
        }
        let provider = sys::nghttp2_data_provider2 {
            source: sys::nghttp2_data_source {
                ptr: ptr::null_mut(),
            },
            read_callback: Some(read_body),
        };
        let prd = if body {
            ptr::from_ref(&provider)
        } else {
            ptr::null()
        };
        // No dependency, and the weight asked (`h2_pri_spec`).
        let priority = sys::nghttp2_priority_spec {
            stream_id: 0,
            weight: i32::from(weight),
            exclusive: 0,
        };
        // SAFETY: the session, the priority and the fields, which outlive
        // the call, and a provider whose callback reads through what
        // `send` lends.
        let id = unsafe {
            sys::nghttp2_submit_request2(
                self.raw.as_ptr(),
                &priority,
                nva.as_ptr(),
                nva.len(),
                prd,
                ptr::null_mut(),
            )
        };
        if id < 0 {
            return Err(error(id));
        }
        Ok(StreamId(id))
    }

    fn upgrade(&mut self, settings: &[u8], head: bool) -> Result<StreamId, FrameError> {
        // SAFETY: the session and the payload, which outlives the call.
        check_h2(unsafe {
            sys::nghttp2_session_upgrade2(
                self.raw.as_ptr(),
                settings.as_ptr(),
                settings.len(),
                c_int::from(head),
                ptr::null_mut(),
            )
        })?;
        Ok(StreamId(1))
    }

    fn recv(
        &mut self,
        bytes: &[u8],
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<usize, FrameError> {
        let events: *mut (dyn FnMut(Event<'_>) -> Heard + '_) = events;
        // SAFETY: lent for the call only; taken back below, before
        // `events` goes out of scope.
        self.lent.events = Some(unsafe {
            core::mem::transmute::<*mut (dyn FnMut(Event<'_>) -> Heard + '_), *mut EventSink>(
                events,
            )
        });
        // SAFETY: the session and the bytes, which outlive the call.
        let n = unsafe {
            sys::nghttp2_session_mem_recv2(self.raw.as_ptr(), bytes.as_ptr(), bytes.len())
        };
        self.lent.events = None;
        usize::try_from(n).map_err(|_| error(c_int::try_from(n).unwrap_or(sys::NGHTTP2_ERR_NOMEM)))
    }

    fn send(
        &mut self,
        out: &mut dyn FnMut(&[u8]) -> bool,
        body: &mut dyn FnMut(StreamId, &mut [u8]) -> BodyRead,
        events: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<(), FrameError> {
        let body: *mut (dyn FnMut(StreamId, &mut [u8]) -> BodyRead + '_) = body;
        // SAFETY: lent for the call only, taken back below.
        self.lent.body = Some(unsafe {
            core::mem::transmute::<
                *mut (dyn FnMut(StreamId, &mut [u8]) -> BodyRead + '_),
                *mut BodySource,
            >(body)
        });
        let events: *mut (dyn FnMut(Event<'_>) -> Heard + '_) = events;
        // SAFETY: as above.
        self.lent.events = Some(unsafe {
            core::mem::transmute::<*mut (dyn FnMut(Event<'_>) -> Heard + '_), *mut EventSink>(
                events,
            )
        });
        let r = loop {
            let mut data = ptr::null();
            // SAFETY: the session and an out pointer to fill.
            let n = unsafe { sys::nghttp2_session_mem_send2(self.raw.as_ptr(), &mut data) };
            let Ok(len) = usize::try_from(n) else {
                break Err(error(c_int::try_from(n).unwrap_or(sys::NGHTTP2_ERR_NOMEM)));
            };
            if len == 0 {
                break Ok(());
            }
            // SAFETY: the session's own bytes, valid until its next call.
            let bytes = unsafe { core::slice::from_raw_parts(data, len) };
            if !out(bytes) {
                break Ok(());
            }
        };
        self.lent.body = None;
        self.lent.events = None;
        r
    }

    fn consume(&mut self, stream: StreamId, n: usize) -> Result<(), FrameError> {
        // SAFETY: the session.
        check_h2(unsafe { sys::nghttp2_session_consume(self.raw.as_ptr(), stream.0, n) })
    }

    fn resume(&mut self, stream: StreamId) -> Result<(), FrameError> {
        // SAFETY: the session.
        check_h2(unsafe { sys::nghttp2_session_resume_data(self.raw.as_ptr(), stream.0) })
    }

    fn reset(&mut self, stream: StreamId, code: u32) -> Result<(), FrameError> {
        // SAFETY: the session.
        check_h2(unsafe { sys::nghttp2_submit_rst_stream(self.raw.as_ptr(), 0, stream.0, code) })
    }

    fn goaway(&mut self, code: u32, debug: &[u8]) -> Result<(), FrameError> {
        // SAFETY: the session, and the debug data, which it copies.
        check_h2(unsafe {
            sys::nghttp2_submit_goaway(self.raw.as_ptr(), 0, 0, code, debug.as_ptr(), debug.len())
        })
    }

    fn ping(&mut self) -> Result<(), FrameError> {
        // SAFETY: the session; no opaque data, which the library zeroes.
        check_h2(unsafe { sys::nghttp2_submit_ping(self.raw.as_ptr(), 0, ptr::null()) })
    }

    fn wants(&self) -> Wants {
        // SAFETY: the session.
        let read = unsafe { sys::nghttp2_session_want_read(self.raw.as_ptr()) } != 0;
        // SAFETY: the session.
        let write = unsafe { sys::nghttp2_session_want_write(self.raw.as_ptr()) } != 0;
        Wants { read, write }
    }

    /// The peer's limit on streams open at once
    /// (`NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS`).
    fn max_concurrent(&self) -> u32 {
        // SAFETY: the session.
        unsafe {
            sys::nghttp2_session_get_remote_settings(
                self.raw.as_ptr(),
                sys::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
            )
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "the tests' peer allocates as it likes"
)]
impl Session {
    /// A server session, for the tests' peer.
    fn server() -> Result<Session, SessionError> {
        Session::new(End::Server)
    }

    /// Queue a response of `fields` on `stream`, with a body if `body`.
    fn submit_response(
        &mut self,
        stream: StreamId,
        fields: &[(&[u8], &[u8])],
        body: bool,
    ) -> Result<(), FrameError> {
        let nva: Vec<sys::nghttp2_nv> = fields
            .iter()
            .map(|&(name, value)| sys::nghttp2_nv {
                name: name.as_ptr().cast_mut(),
                value: value.as_ptr().cast_mut(),
                namelen: name.len(),
                valuelen: value.len(),
                flags: sys::NGHTTP2_NV_FLAG_NONE,
            })
            .collect();
        let provider = sys::nghttp2_data_provider2 {
            source: sys::nghttp2_data_source {
                ptr: ptr::null_mut(),
            },
            read_callback: Some(read_body),
        };
        let prd = if body {
            ptr::from_ref(&provider)
        } else {
            ptr::null()
        };
        // SAFETY: the session, the fields, which outlive the call, and a
        // provider reading through what `send` lends.
        check_h2(unsafe {
            sys::nghttp2_submit_response2(self.raw.as_ptr(), stream.0, nva.as_ptr(), nva.len(), prd)
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: the session, not used again.
        unsafe { sys::nghttp2_session_del(self.raw.as_ptr()) };
    }
}

/// Why a session could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    OutOfMemory,
}

impl From<OutOfMemory> for SessionError {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        SessionError::OutOfMemory
    }
}

fn check(rc: c_int) -> Result<(), SessionError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(SessionError::OutOfMemory)
    }
}

fn check_h2(rc: c_int) -> Result<(), FrameError> {
    if rc == 0 { Ok(()) } else { Err(error(rc)) }
}

/// An object of the library's, freed by its function as it goes.
struct Owned<T>(*mut T, unsafe extern "C" fn(*mut T));

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: made by the library and freed once, here.
        unsafe { (self.1)(self.0) };
    }
}

/// The caller's event sink, if one is lent.
///
/// # Safety
///
/// `user` is the session's user data, its `Lent`.
unsafe fn tell(user: *mut c_void, event: Event<'_>) -> c_int {
    // SAFETY: as the caller guarantees.
    let lent = unsafe { &*user.cast::<Lent>() };
    match lent.events {
        // SAFETY: lent by `recv` or `send` for the call that runs this
        // callback.
        Some(events) => match unsafe { (*events)(event) } {
            Heard::Fine => 0,
            Heard::Failed => sys::NGHTTP2_ERR_CALLBACK_FAILURE,
        },
        None => 0,
    }
}

/// # Safety
///
/// Called by the library with its frame and the session's user data.
unsafe extern "C" fn on_frame_recv(
    _session: *mut sys::nghttp2_session,
    frame: *const sys::nghttp2_frame,
    user: *mut c_void,
) -> c_int {
    // SAFETY: the frame the library read, valid for the call.
    let frame = unsafe { &*frame };
    // SAFETY: every frame starts with its header.
    let hd = unsafe { frame.hd };
    let stream = StreamId(hd.stream_id);
    let event = match hd.r#type {
        sys::NGHTTP2_HEADERS => Event::HeadersDone {
            stream,
            end_stream: hd.flags & sys::NGHTTP2_FLAG_END_STREAM != 0,
        },
        sys::NGHTTP2_DATA if hd.flags & sys::NGHTTP2_FLAG_END_STREAM != 0 => {
            Event::DataEnd { stream }
        }
        sys::NGHTTP2_SETTINGS if hd.flags & sys::NGHTTP2_FLAG_ACK == 0 => Event::Settings,
        sys::NGHTTP2_WINDOW_UPDATE => Event::WindowUpdate { stream },
        sys::NGHTTP2_GOAWAY => {
            // SAFETY: a GOAWAY frame, as its header says.
            let g = unsafe { frame.goaway };
            Event::GoAway {
                last_stream: StreamId(g.last_stream_id),
                error: g.error_code,
            }
        }
        sys::NGHTTP2_RST_STREAM => {
            // SAFETY: an RST_STREAM frame, as its header says.
            let r = unsafe { frame.rst_stream };
            Event::Reset {
                stream,
                error: r.error_code,
            }
        }
        _ => return 0,
    };
    // SAFETY: the session's user data.
    unsafe { tell(user, event) }
}

/// # Safety
///
/// Called by the library with a field it read and the session's user
/// data.
unsafe extern "C" fn on_header(
    _session: *mut sys::nghttp2_session,
    frame: *const sys::nghttp2_frame,
    name: *const u8,
    namelen: usize,
    value: *const u8,
    valuelen: usize,
    _flags: u8,
    user: *mut c_void,
) -> c_int {
    // SAFETY: the frame the library read, valid for the call.
    let frame = unsafe { &*frame };
    // SAFETY: every frame starts with its header.
    let stream = StreamId(unsafe { frame.hd }.stream_id);
    // SAFETY: the field's bytes, valid for the call.
    let name = unsafe { core::slice::from_raw_parts(name, namelen) };
    // SAFETY: as above.
    let value = unsafe { core::slice::from_raw_parts(value, valuelen) };
    // SAFETY: the session's user data.
    unsafe {
        tell(
            user,
            Event::Header {
                stream,
                name,
                value,
            },
        )
    }
}

/// # Safety
///
/// Called by the library with body bytes it read and the session's user
/// data.
unsafe extern "C" fn on_data(
    _session: *mut sys::nghttp2_session,
    _flags: u8,
    stream: i32,
    data: *const u8,
    len: usize,
    user: *mut c_void,
) -> c_int {
    // SAFETY: the bytes, valid for the call.
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    // SAFETY: the session's user data.
    unsafe {
        tell(
            user,
            Event::Data {
                stream: StreamId(stream),
                bytes,
            },
        )
    }
}

/// # Safety
///
/// Called by the library as a stream closes, with the session's user
/// data.
unsafe extern "C" fn on_close(
    _session: *mut sys::nghttp2_session,
    stream: i32,
    error: u32,
    user: *mut c_void,
) -> c_int {
    // SAFETY: the session's user data.
    unsafe {
        tell(
            user,
            Event::Closed {
                stream: StreamId(stream),
                error,
            },
        )
    }
}

/// # Safety
///
/// Called by the library to read a request's body, with the session's
/// user data.
unsafe extern "C" fn read_body(
    _session: *mut sys::nghttp2_session,
    stream: i32,
    buf: *mut u8,
    length: usize,
    data_flags: *mut u32,
    _source: *mut sys::nghttp2_data_source,
    user: *mut c_void,
) -> sys::nghttp2_ssize {
    // SAFETY: the session's user data.
    let lent = unsafe { &*user.cast::<Lent>() };
    let Some(body) = lent.body else {
        return sys::NGHTTP2_ERR_DEFERRED as sys::nghttp2_ssize;
    };
    // SAFETY: the library's buffer of `length` bytes, for the call.
    let room = unsafe { core::slice::from_raw_parts_mut(buf, length) };
    // SAFETY: lent by `send` for the call that runs this callback.
    let read = unsafe { (*body)(StreamId(stream), room) };
    let (n, last) = match read {
        BodyRead::Bytes(n) => (n, false),
        BodyRead::Last(n) => (n, true),
        BodyRead::Later => return sys::NGHTTP2_ERR_DEFERRED as sys::nghttp2_ssize,
        BodyRead::Failed => {
            return sys::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE as sys::nghttp2_ssize;
        }
    };
    if last {
        // SAFETY: the flags the library lends.
        unsafe { *data_flags |= sys::NGHTTP2_DATA_FLAG_EOF };
    }
    n.min(length) as sys::nghttp2_ssize
}

#[cfg(test)]
mod tests;
