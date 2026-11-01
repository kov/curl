//! The WebSocket calls (`include/curl/websockets.h`): a frame's bytes
//! received and sent on the connection a transfer switched, from inside
//! its write or read callback or, once a transfer that only connected is
//! done, from outside (`curl_ws_recv`, `curl_ws_send`,
//! `curl_ws_start_frame`), and what the write callback's bytes are of
//! (`curl_ws_meta`). C's flags and lengths are read here into the core's
//! types, and refused here when they are none.

#![allow(unsafe_code)]

use core::ffi::{c_uint, c_void};
use core::ptr;
use core::slice;

use curl_core::error::ErrorKind;
use curl_core::ws::{
    Answer, Asked, AskedFrame, Call, Frame, FrameKind, FrameLen, Meta, Received, Refusal,
    SendFlags, Sent,
};

use crate::callbacks::Held;
use crate::easy::{ShimEasy, handle};
use crate::error_codes::easy_code;
use crate::ffi::{
    self, CURL, CURLE_AGAIN, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_OK, CURLE_RECURSIVE_API_CALL,
    CURLcode, curl_off_t, curl_ws_frame,
};
use crate::gate::{EasyCall, Frame as GateFrame, Reach};

/// The kind and continuation `flags` name, `CURLWS_OFFSET` aside; none
/// for bits that name no frame (`ws_frame_flags2firstbyte`'s default).
fn send_flags(flags: c_uint) -> Option<SendFlags> {
    let bits = flags & !(ffi::CURLWS_OFFSET as c_uint);
    let more = bits & ffi::CURLWS_CONT as c_uint != 0;
    let kind = match bits & !(ffi::CURLWS_CONT as c_uint) {
        0 => None,
        b if b == ffi::CURLWS_TEXT as c_uint => Some(FrameKind::Text),
        b if b == ffi::CURLWS_BINARY as c_uint => Some(FrameKind::Binary),
        b if b == ffi::CURLWS_CLOSE as c_uint => Some(FrameKind::Close),
        b if b == ffi::CURLWS_PING as c_uint => Some(FrameKind::Ping),
        b if b == ffi::CURLWS_PONG as c_uint => Some(FrameKind::Pong),
        _ => return None,
    };
    Some(SendFlags { kind, more })
}

/// A reason in C's words.
struct Why {
    bytes: [u8; 80],
    len: usize,
}

impl Why {
    fn new(args: core::fmt::Arguments<'_>) -> Why {
        let mut bytes = [0u8; 80];
        let len = write_into(&mut bytes, args);
        Why { bytes, len }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).expect("C's reasons are ASCII")
    }
}

/// Why a frame of `length`, and `flags`, can be no frame, as C finds it
/// (`ws_enc_add_frame`): the length first.
fn no_frame(length: Option<curl_off_t>, flags: c_uint) -> Option<(ErrorKind, Why)> {
    if let Some(length) = length.filter(|l| *l < 0) {
        let why = Why::new(format_args!(
            "[WS] starting new frame with negative payload length {length}"
        ));
        return Some((ErrorKind::SendError, why));
    }
    if send_flags(flags).is_none() {
        let why = Why::new(format_args!("[WS] unknown flags: {flags:x}"));
        return Some((ErrorKind::BadFunctionArgument, why));
    }
    None
}

/// `frame` as C's `struct curl_ws_frame` says it.
fn c_frame(frame: Frame) -> curl_ws_frame {
    let kind = match frame.kind.kind {
        FrameKind::Text => ffi::CURLWS_TEXT,
        FrameKind::Binary => ffi::CURLWS_BINARY,
        FrameKind::Close => ffi::CURLWS_CLOSE,
        FrameKind::Ping => ffi::CURLWS_PING,
        FrameKind::Pong => ffi::CURLWS_PONG,
    };
    let more = if frame.kind.more { ffi::CURLWS_CONT } else { 0 };
    curl_ws_frame {
        age: 0,
        flags: kind | more,
        offset: curl_off_t::try_from(frame.offset).unwrap_or(curl_off_t::MAX),
        bytesleft: curl_off_t::try_from(frame.bytes_left).unwrap_or(curl_off_t::MAX),
        len: frame.len,
    }
}

/// Make `call` on the handle's WebSocket, wherever its transfer is:
/// inside one of its own callbacks, the connection lent; else on the
/// connection it only made, once done.
fn reach(easy: &ShimEasy, call: Call<'_>) -> Result<Result<Answer, ErrorKind>, CURLcode> {
    let mut held = Held::default();
    let done = reach_noting(easy, call, &mut |kind, bytes| held.note(kind, bytes));
    held.say(easy);
    done
}

/// `reach`, what a call from outside a callback traces going to `notes`,
/// the handle borrowed meanwhile.
fn reach_noting(
    easy: &ShimEasy,
    call: Call<'_>,
    notes: curl_core::multi::raw::Notes<'_>,
) -> Result<Result<Answer, ErrorKind>, CURLcode> {
    match easy.added() {
        None => {
            let private = easy.private_multi();
            let done = easy.with_detached(|e| match private {
                Some(m) => {
                    // SAFETY: the handle owns its private multi.
                    let m = unsafe { m.as_ref() };
                    // SAFETY: nothing runs on it once its perform is done.
                    unsafe { m.core_mut() }.ws_for(e, call, notes)
                }
                None => e.ws(call, notes),
            });
            done.ok_or(CURLE_RECURSIVE_API_CALL)
        }
        Some((multi, id)) => {
            // SAFETY: the handle's multi outlives its `Added`.
            let m = unsafe { multi.as_ref() };
            match m.stack.reach() {
                // SAFETY: nothing runs on the multi.
                Ok(Reach::Direct) => Ok(unsafe { m.core_mut() }
                    .ws(id, call, notes)
                    .expect("an added handle is in its multi")),
                Ok(Reach::Frame(GateFrame::Transfer(cx))) => {
                    // SAFETY: the callback lent its context and does not
                    // use it until it returns.
                    let cx = unsafe { &mut *cx.as_ptr() };
                    if cx.me() != id {
                        return Err(CURLE_BAD_FUNCTION_ARGUMENT);
                    }
                    Ok(match call {
                        Call::Recv(buf) => cx.ws_recv(buf).map(Answer::Received),
                        Call::Send(bytes, len, flags) => {
                            cx.ws_send(bytes, len, flags).map(Answer::Sent)
                        }
                        Call::SendAsked(bytes, asked) => {
                            cx.ws_send_asked(bytes, &asked).map(Answer::Sent)
                        }
                        Call::StartFrame(flags, len) => {
                            cx.ws_start_frame(flags, len).map(|()| Answer::Started)
                        }
                        Call::StartAsked(asked) => {
                            cx.ws_start_asked(&asked).map(|()| Answer::Started)
                        }
                    })
                }
                Ok(Reach::Frame(_)) | Err(_) => Err(CURLE_RECURSIVE_API_CALL),
            }
        }
    }
}

/// Whether the handle's frames are raw (`CURLWS_RAW_MODE`).
fn raw_mode(easy: &ShimEasy) -> Result<bool, CURLcode> {
    easy.with_options(|o| o.ws.raw)
        .map_err(|_| CURLE_RECURSIVE_API_CALL)
}

/// Receive what came of the next frame.
///
/// # Safety
///
/// `curl` is a handle `curl_easy_init` made or null; `buffer` has room
/// for `buflen` bytes; `recv` and `meta` point where a `size_t` and a
/// pointer can be written, or are null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_ws_recv(
    curl: *mut CURL,
    buffer: *mut c_void,
    buflen: usize,
    recv: *mut usize,
    meta: *mut *const curl_ws_frame,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::WsRecv) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    if recv.is_null() || meta.is_null() || (buflen > 0 && buffer.is_null()) {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: it points where a `size_t` can be written.
    unsafe { recv.write(0) };
    // SAFETY: it points where a pointer can be written.
    unsafe { meta.write(ptr::null()) };
    let buf: &mut [u8] = if buflen == 0 {
        &mut []
    } else {
        // SAFETY: the buffer has room for `buflen` bytes, the
        // application's alone during the call.
        unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), buflen) }
    };
    let answer = match reach(easy, Call::Recv(buf)) {
        Ok(a) => a,
        Err(code) => return code,
    };
    match answer {
        Ok(Answer::Received(Received::Frame(frame))) => {
            let Some(kept) = easy.ws_frame() else {
                return ffi::CURLE_OUT_OF_MEMORY;
            };
            // SAFETY: the handle's frame is its own, and nothing holds a
            // reference to it: the application reads it through the
            // pointer handed out.
            unsafe { kept.write(c_frame(frame)) };
            // SAFETY: as above.
            unsafe { recv.write(frame.len) };
            // SAFETY: as above.
            unsafe { meta.write(kept.cast_const()) };
            CURLE_OK
        }
        Ok(Answer::Received(Received::WouldBlock)) => CURLE_AGAIN,
        Ok(_) => unreachable!("a receive receives"),
        Err(kind) => easy_code(kind),
    }
}
const _: ffi::proto::curl_ws_recv = curl_ws_recv;

/// Send a frame's bytes.
///
/// # Safety
///
/// `curl` is a handle `curl_easy_init` made or null; `buffer` holds
/// `buflen` bytes or is null; `sent` points where a `size_t` can be
/// written, or is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_ws_send(
    curl: *mut CURL,
    buffer: *const c_void,
    buflen: usize,
    sent: *mut usize,
    fragsize: curl_off_t,
    flags: c_uint,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::WsSend) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    if !sent.is_null() {
        // SAFETY: it points where a `size_t` can be written.
        unsafe { sent.write(0) };
    }
    let raw = match raw_mode(easy) {
        Ok(raw) => raw,
        Err(code) => return code,
    };
    let bad = |why| Refusal {
        kind: ErrorKind::BadFunctionArgument,
        why,
    };
    let length = (flags & ffi::CURLWS_OFFSET as c_uint != 0).then_some(fragsize);
    let no = no_frame(length, flags);
    let frame = if buffer.is_null() && buflen > 0 {
        AskedFrame::NoBytes {
            claimed: buflen,
            why: bad("[WS] buffer is NULL when buflen is not"),
        }
    } else if raw && buffer.is_null() {
        AskedFrame::None(bad("[WS] buffer is NULL in raw mode"))
    } else if raw && sent.is_null() {
        AskedFrame::None(bad("[WS] sent is NULL in raw mode"))
    } else if raw {
        let none = SendFlags {
            kind: None,
            more: false,
        };
        AskedFrame::Frame(FrameLen::These, none)
    } else if let Some((kind, why)) = &no {
        AskedFrame::None(Refusal {
            kind: *kind,
            why: why.as_str(),
        })
    } else {
        let typed = send_flags(flags).expect("no_frame read them");
        let len = match length.map(u64::try_from) {
            Some(Ok(total)) => FrameLen::Total(total),
            Some(Err(_)) => unreachable!("no_frame read it"),
            None => FrameLen::These,
        };
        AskedFrame::Frame(len, typed)
    };
    let bytes: &[u8] = if buflen == 0 || buffer.is_null() {
        &[]
    } else {
        // SAFETY: the buffer holds `buflen` bytes.
        unsafe { slice::from_raw_parts(buffer.cast::<u8>(), buflen) }
    };
    let asked = Asked {
        length: fragsize,
        flags,
        frame,
    };
    let answer = reach(easy, Call::SendAsked(bytes, asked));
    let answer = match answer {
        Ok(a) => a,
        Err(code) => return code,
    };
    match answer {
        Ok(Answer::Sent(Sent::Bytes(n))) => {
            if !sent.is_null() {
                // SAFETY: as above.
                unsafe { sent.write(n) };
            }
            CURLE_OK
        }
        Ok(Answer::Sent(Sent::WouldBlock)) => CURLE_AGAIN,
        Ok(Answer::Sent(Sent::BytesThenWouldBlock(n))) => {
            if !sent.is_null() {
                // SAFETY: as above.
                unsafe { sent.write(n) };
            }
            CURLE_AGAIN
        }
        Ok(_) => unreachable!("a send sends"),
        Err(kind) => easy_code(kind),
    }
}
const _: ffi::proto::curl_ws_send = curl_ws_send;

/// Start a frame whose payload the sends after give.
///
/// # Safety
///
/// `curl` is a handle `curl_easy_init` made or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_ws_start_frame(
    curl: *mut CURL,
    flags: c_uint,
    frame_len: curl_off_t,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::WsStartFrame) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    let no = no_frame(Some(frame_len), flags);
    let frame = match &no {
        Some((kind, why)) => AskedFrame::None(Refusal {
            kind: *kind,
            why: why.as_str(),
        }),
        None => AskedFrame::Frame(
            FrameLen::Total(frame_len as u64),
            send_flags(flags).expect("no_frame read them"),
        ),
    };
    let asked = Asked {
        length: frame_len,
        flags,
        frame,
    };
    match reach(easy, Call::StartAsked(asked)) {
        Ok(a) => match a {
            Ok(_) => CURLE_OK,
            Err(kind) => easy_code(kind),
        },
        Err(code) => code,
    }
}
const _: ffi::proto::curl_ws_start_frame = curl_ws_start_frame;

/// What the bytes the write callback is given are of, inside it.
///
/// # Safety
///
/// `curl` is a handle `curl_easy_init` made or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_ws_meta(curl: *mut CURL) -> *const curl_ws_frame {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return ptr::null();
    };
    let Some((multi, id)) = easy.added() else {
        return ptr::null();
    };
    // SAFETY: the handle's multi outlives its `Added`.
    let m = unsafe { multi.as_ref() };
    let Ok(Reach::Frame(GateFrame::Transfer(cx))) = m.stack.reach() else {
        return ptr::null();
    };
    // SAFETY: the callback lent its context and does not use it until it
    // returns.
    let cx = unsafe { &*cx.as_ptr() };
    let Some(meta) = cx.ws_meta().filter(|_| cx.me() == id) else {
        return ptr::null();
    };
    let Some(kept) = easy.ws_frame() else {
        return ptr::null();
    };
    let said = match meta {
        Meta::Frame(frame) => c_frame(frame),
        // As C's is before its first frame: made zeroed (`calloc`).
        Meta::Nothing => curl_ws_frame {
            age: 0,
            flags: 0,
            offset: 0,
            bytesleft: 0,
            len: 0,
        },
    };
    // SAFETY: as in `curl_ws_recv`.
    unsafe { kept.write(said) };
    kept.cast_const()
}
const _: ffi::proto::curl_ws_meta = curl_ws_meta;

fn write_into(out: &mut [u8], args: core::fmt::Arguments<'_>) -> usize {
    use core::fmt::Write as _;
    struct At<'a>(&'a mut [u8], usize);
    impl core::fmt::Write for At<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let room = self.0.len() - self.1;
            let n = s.len().min(room);
            self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
            self.1 += n;
            Ok(())
        }
    }
    let mut at = At(out, 0);
    let _cut = at.write_fmt(args);
    at.1
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_int;

    /// Each kind C names, with or without `CURLWS_CONT` and
    /// `CURLWS_OFFSET`, reads as it; two kinds or a bit no frame has do
    /// not.
    #[test]
    fn flags_read_as_c_names_them() {
        let f = |kind, more| Some(SendFlags { kind, more });
        let cont = ffi::CURLWS_CONT as c_uint;
        let offset = ffi::CURLWS_OFFSET as c_uint;
        assert_eq!(send_flags(0), f(None, false));
        assert_eq!(send_flags(cont), f(None, true));
        assert_eq!(send_flags(offset), f(None, false));
        let text = ffi::CURLWS_TEXT as c_uint;
        assert_eq!(
            send_flags(text | cont | offset),
            f(Some(FrameKind::Text), true)
        );
        assert_eq!(
            send_flags(ffi::CURLWS_PONG as c_uint),
            f(Some(FrameKind::Pong), false)
        );
        assert_eq!(send_flags(text | ffi::CURLWS_BINARY as c_uint), None);
        assert_eq!(send_flags(0x100), None);
        let c = c_frame(Frame {
            kind: curl_core::ws::FrameType {
                kind: FrameKind::Binary,
                more: true,
            },
            offset: 3,
            bytes_left: 4,
            len: 5,
        });
        assert_eq!(c.flags, ffi::CURLWS_BINARY | ffi::CURLWS_CONT);
        assert_eq!((c.offset, c.bytesleft, c.len), (3, 4, 5));
        let _: c_int = c.age;
    }

    /// What can be no frame is found as C finds it: the length first, and
    /// its reason said in C's words.
    #[test]
    fn no_frame_says_why_in_c_s_words() {
        let text = ffi::CURLWS_TEXT as c_uint;
        let bad = text | ffi::CURLWS_BINARY as c_uint;
        let found = |length, flags| {
            let (kind, why) = no_frame(length, flags).expect("no frame");
            (kind, std::string::String::from(why.as_str()))
        };
        assert_eq!(
            found(None, bad),
            (
                ErrorKind::BadFunctionArgument,
                "[WS] unknown flags: 3".into()
            )
        );
        assert_eq!(
            found(Some(-1), bad),
            (
                ErrorKind::SendError,
                "[WS] starting new frame with negative payload length -1".into()
            )
        );
        assert!(no_frame(None, text).is_none(), "the length is not read");
        assert!(no_frame(Some(0), text).is_none());
    }

    /// A reason longer than its buffer is cut, never past it.
    #[test]
    fn a_reason_stays_in_its_buffer() {
        let mut short = [0u8; 10];
        let n = write_into(&mut short, format_args!("[WS] starting"));
        assert_eq!(&short[..n], b"[WS] start");
    }
}
