//! zlib's inflate, undoing the `deflate` and `gzip` content codings as C's
//! zlib writers do (`lib/content_encoding.c`), behind
//! `curl_core::coding::Decoder`. zlib allocates through the Rust allocator,
//! as C's goes through curl's.

// The binding: zlib's stream and calls.
#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use std::alloc::{self, Layout};
use std::ffi::{CStr, c_char, c_int, c_uint, c_ulong, c_void};
use std::ptr;

use curl_alloc::try_box;
use curl_core::coding::{Decoder, Sink};
use curl_core::error::ErrorKind;

/// zlib's `z_stream`, as `zlib.h` lays it out.
#[repr(C)]
struct ZStream {
    next_in: *const u8,
    avail_in: c_uint,
    total_in: c_ulong,
    next_out: *mut u8,
    avail_out: c_uint,
    total_out: c_ulong,
    msg: *const c_char,
    state: *mut c_void,
    zalloc: Option<unsafe extern "C" fn(*mut c_void, c_uint, c_uint) -> *mut c_void>,
    zfree: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    opaque: *mut c_void,
    data_type: c_int,
    adler: c_ulong,
    reserved: c_ulong,
}

const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_DATA_ERROR: c_int = -3;
const Z_BUF_ERROR: c_int = -5;
const Z_BLOCK: c_int = 5;
const MAX_WBITS: c_int = 15;

unsafe extern "C" {
    fn zlibVersion() -> *const c_char;
    fn inflateInit2_(
        strm: *mut ZStream,
        window_bits: c_int,
        version: *const c_char,
        stream_size: c_int,
    ) -> c_int;
    fn inflate(strm: *mut ZStream, flush: c_int) -> c_int;
    fn inflateEnd(strm: *mut ZStream) -> c_int;
    fn inflateReset2(strm: *mut ZStream, window_bits: c_int) -> c_int;
}

/// The library's version, as `curl -V` names it.
pub fn version() -> &'static str {
    // SAFETY: zlibVersion has no preconditions.
    let p = unsafe { zlibVersion() };
    // SAFETY: zlibVersion returns a pointer to a static NUL-terminated
    // string, valid for the life of the process.
    let v = unsafe { CStr::from_ptr(p) };
    v.to_str().unwrap_or("")
}

/// Space before each block zlib is given, holding the block's size.
const HEADER: usize = 16;

/// zlib's allocator: zeroed, as C's `zalloc_cb` gives it `calloc`.
///
/// # Safety
///
/// Called by zlib only.
unsafe extern "C" fn zalloc(_: *mut c_void, items: c_uint, size: c_uint) -> *mut c_void {
    let Some(total) = (items as usize)
        .checked_mul(size as usize)
        .and_then(|n| n.checked_add(HEADER))
    else {
        return ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, HEADER) else {
        return ptr::null_mut();
    };
    // SAFETY: the layout's size is at least HEADER, never zero.
    let base = unsafe { alloc::alloc_zeroed(layout) };
    if base.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the block is at least HEADER bytes and aligned to HEADER,
    // so a usize fits at its start.
    unsafe { base.cast::<usize>().write(total) };
    // SAFETY: the block is at least HEADER bytes long.
    unsafe { base.add(HEADER).cast() }
}

/// zlib's deallocator, for blocks `zalloc` gave.
///
/// # Safety
///
/// Called by zlib only, with null or a pointer `zalloc` returned.
unsafe extern "C" fn zfree(_: *mut c_void, block: *mut c_void) {
    if block.is_null() {
        return;
    }
    // SAFETY: zalloc returned `block` HEADER bytes into its allocation.
    let base = unsafe { block.cast::<u8>().sub(HEADER) };
    // SAFETY: zalloc wrote the allocation's size at its start.
    let total = unsafe { base.cast::<usize>().read() };
    // SAFETY: zalloc made this block with this size and alignment, which
    // it checked make a layout.
    let layout = unsafe { Layout::from_size_align_unchecked(total, HEADER) };
    // SAFETY: zalloc made this block with this layout.
    unsafe { alloc::dealloc(base, layout) };
}

/// Where a stream is (C's `zlibInitState`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Ended, or never begun: nothing more is inflated.
    Uninit,
    /// Begun, with nothing out yet: a `deflate` body may still turn out
    /// to be raw.
    Init,
    Inflating,
    /// The stream ended; this many bytes more of trailer are let by.
    ExternalTrailer,
    /// zlib reads the gzip framing itself.
    InitGzip,
}

/// The most a stream makes at once (`DECOMPRESS_BUFFER_SIZE`).
const BUFFER: usize = 16384;

/// The output asked for between two checks of the time (1 MiB).
const ROUNDS_PER_CHECK: u32 = (1024 * 1024 / BUFFER) as u32;

/// An inflating stream (C's `zlib_writer`).
struct Inflater {
    /// Boxed: zlib's state points back at the stream, which must not move.
    z: Box<ZStream>,
    state: State,
    /// What a `gzip` or `deflate` body starts in once it has made output.
    started: State,
    /// Bytes of trailer let by after a raw stream.
    trailer: u32,
    buffer: Box<[u8; BUFFER]>,
}

impl std::fmt::Debug for Inflater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inflater")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// A decoder of the `deflate` coding: zlib's format, or a raw deflate
/// stream where a server sends one (`deflate_encoding`).
pub fn deflate() -> Result<Box<dyn Decoder>, ErrorKind> {
    Ok(
        try_box(Inflater::new(MAX_WBITS, State::Init, State::Inflating)?)
            .map_err(|_| ErrorKind::OutOfMemory)?,
    )
}

/// A decoder of the `gzip` coding (`gzip_encoding`).
pub fn gzip() -> Result<Box<dyn Decoder>, ErrorKind> {
    Ok(try_box(Inflater::new(
        MAX_WBITS + 32,
        State::InitGzip,
        State::InitGzip,
    )?)
    .map_err(|_| ErrorKind::OutOfMemory)?)
}

impl Inflater {
    fn new(window_bits: c_int, state: State, started: State) -> Result<Inflater, ErrorKind> {
        let oom = |_| ErrorKind::OutOfMemory;
        let mut z = try_box(ZStream {
            next_in: ptr::null(),
            avail_in: 0,
            total_in: 0,
            next_out: ptr::null_mut(),
            avail_out: 0,
            total_out: 0,
            msg: ptr::null(),
            state: ptr::null_mut(),
            zalloc: Some(zalloc),
            zfree: Some(zfree),
            opaque: ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        })
        .map_err(oom)?;
        let buffer = try_box([0u8; BUFFER]).map_err(oom)?;
        let size = c_int::try_from(size_of::<ZStream>()).expect("a small struct");
        // SAFETY: zlibVersion has no preconditions.
        let version = unsafe { zlibVersion() };
        // SAFETY: `z` is a zeroed stream with our allocator, boxed so it
        // does not move while zlib's state points at it; the version is
        // the linked library's own, so its check passes on layout alone.
        let rc = unsafe { inflateInit2_(&mut *z, window_bits, version, size) };
        if rc != Z_OK {
            // `process_zlib_error`, without the transfer to say it to.
            return Err(if rc == -4 {
                ErrorKind::OutOfMemory
            } else {
                ErrorKind::BadContentEncoding
            });
        }
        Ok(Inflater {
            z,
            state,
            started,
            trailer: 0,
            buffer,
        })
    }

    /// The failure zlib reports, said (`process_zlib_error`).
    fn zlib_error(&self, out: &mut dyn Sink) -> ErrorKind {
        let msg = (!self.z.msg.is_null()).then(|| {
            // SAFETY: zlib sets `msg` to null or a static NUL-terminated
            // string.
            unsafe { CStr::from_ptr(self.z.msg) }
        });
        let said = msg.map_or(
            &b"Unknown failure within decompression software."[..],
            CStr::to_bytes,
        );
        out.fail(
            ErrorKind::BadContentEncoding,
            format_args!(
                "Error while processing content unencoding: {}",
                String::from_utf8_lossy(said)
            ),
        )
    }

    /// End the stream, if it has not ended; a failure to is the result
    /// unless there is one already (`exit_zlib`).
    fn exit(&mut self, out: &mut dyn Sink, result: Result<(), ErrorKind>) -> Result<(), ErrorKind> {
        if self.state == State::Uninit {
            return result;
        }
        self.state = State::Uninit;
        // SAFETY: the stream was initialised and is not ended.
        let rc = unsafe { inflateEnd(&mut *self.z) };
        if rc != Z_OK && result.is_ok() {
            return Err(self.zlib_error(out));
        }
        result
    }

    /// Let by what is left of a trailer; anything after it is an error
    /// (`process_trailer`).
    fn trailer(&mut self, out: &mut dyn Sink) -> Result<(), ErrorKind> {
        let len = self.z.avail_in.min(self.trailer);
        self.trailer -= len;
        self.z.avail_in -= len;
        // SAFETY: `len` is no more than what is left of the input.
        self.z.next_in = unsafe { self.z.next_in.add(len as usize) };
        let result = if self.z.avail_in > 0 {
            Err(ErrorKind::WriteError)
        } else {
            Ok(())
        };
        if result.is_err() || self.trailer == 0 {
            return self.exit(out, result);
        }
        self.state = State::ExternalTrailer;
        result
    }

    /// Inflate `input` into the buffer and on, a buffer at a time, until
    /// zlib has nothing more to make of it (`inflate_stream`).
    fn inflate(&mut self, input: &[u8], out: &mut dyn Sink) -> Result<(), ErrorKind> {
        if !matches!(self.state, State::Init | State::Inflating | State::InitGzip) {
            return self.exit(out, Err(ErrorKind::WriteError));
        }
        let mut result = Ok(());
        let mut rounds = 0;
        let mut done = false;
        while !done {
            done = true;
            rounds += 1;
            if rounds > ROUNDS_PER_CHECK {
                rounds = 0;
                if out.timed_out() {
                    let e = out.fail(
                        ErrorKind::OperationTimedout,
                        format_args!("Operation timed out while decoding payload"),
                    );
                    return self.exit(out, Err(e));
                }
            }
            self.z.next_out = self.buffer.as_mut_ptr();
            self.z.avail_out = BUFFER as c_uint;
            // SAFETY: the stream is initialised; its input points into
            // `input` and its output into the buffer, both alive here.
            let status = unsafe { inflate(&mut *self.z, Z_BLOCK) };
            let made = BUFFER - self.z.avail_out as usize;
            if made > 0 && (status == Z_OK || status == Z_STREAM_END) {
                self.state = self.started;
                if let Err(e) = out.write(&self.buffer[..made]) {
                    // The write's failure stands over the ending's.
                    let _ended = self.exit(out, Err(e));
                    result = Err(e);
                    break;
                }
            }
            match status {
                // There may be output zlib holds yet.
                Z_OK => done = false,
                // Nothing more to make.
                Z_BUF_ERROR => {}
                Z_STREAM_END => {
                    let rest = &input[input.len() - self.z.avail_in as usize..];
                    if self.started == State::InitGzip && rest.starts_with(&[0x1f, 0x8b]) {
                        let e = out.fail(
                            ErrorKind::WriteError,
                            format_args!("Multi-member gzip response not supported"),
                        );
                        result = self.exit(out, Err(e));
                    } else {
                        result = self.trailer(out);
                    }
                }
                // A server that sends raw deflate without zlib's framing:
                // read it again as that.
                Z_DATA_ERROR if self.state == State::Init => {
                    // SAFETY: the stream is initialised.
                    if unsafe { inflateReset2(&mut *self.z, -MAX_WBITS) } == Z_OK {
                        self.z.next_in = input.as_ptr();
                        self.z.avail_in = input.len() as c_uint;
                        self.state = State::Inflating;
                        // Up to 4 bytes of an unknown trailer are let by.
                        self.trailer = 4;
                        done = false;
                    } else {
                        // inflateReset2 failing ended the stream.
                        self.state = State::Uninit;
                        result = Err(self.zlib_error(out));
                    }
                }
                _ => {
                    let e = self.zlib_error(out);
                    result = self.exit(out, Err(e));
                }
            }
        }
        // What was read is not seen again: a stream that made nothing of
        // it cannot be read as raw on the next call.
        if !input.is_empty() && self.state == State::Init {
            self.state = self.started;
        }
        result
    }
}

// SAFETY: the stream and its state are this decoder's alone, reached only
// through `&mut self`; zlib keeps no tie to the thread that made them.
unsafe impl Send for Inflater {}

impl Decoder for Inflater {
    fn decode(&mut self, input: &[u8], out: &mut dyn Sink) -> Result<(), ErrorKind> {
        let Ok(len) = c_uint::try_from(input.len()) else {
            return Err(ErrorKind::WriteError);
        };
        self.z.next_in = input.as_ptr();
        self.z.avail_in = len;
        if self.state == State::ExternalTrailer {
            return self.trailer(out);
        }
        if self.started == State::InitGzip && self.state != State::InitGzip {
            return self.exit(out, Err(ErrorKind::WriteError));
        }
        self.inflate(input, out)
    }
}

impl Drop for Inflater {
    fn drop(&mut self) {
        if self.state != State::Uninit {
            // SAFETY: the stream was initialised and is not ended.
            unsafe { inflateEnd(&mut *self.z) };
        }
    }
}

#[cfg(test)]
mod tests;
