//! zstd's streaming decoder, undoing the `zstd` content coding as C's zstd
//! writer does (`lib/content_encoding.c`), behind
//! `curl_core::coding::Decoder`. zstd allocates through the system's
//! allocator, as C's does built without `ZSTD_STATIC_LINKING_ONLY`.

// The binding: zstd's stream and calls.
#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use std::ffi::{c_uint, c_void};
use std::fmt;
use std::ptr::NonNull;

use curl_alloc::try_box;
use curl_core::coding::{Decoder, Sink};
use curl_core::error::ErrorKind;

/// `ZSTD_DStream`, opaque.
#[repr(C)]
struct DStream {
    _private: [u8; 0],
}

/// `ZSTD_inBuffer`.
#[repr(C)]
struct InBuffer {
    src: *const c_void,
    size: usize,
    pos: usize,
}

/// `ZSTD_outBuffer`.
#[repr(C)]
struct OutBuffer {
    dst: *mut c_void,
    size: usize,
    pos: usize,
}

unsafe extern "C" {
    fn ZSTD_createDStream() -> *mut DStream;
    fn ZSTD_freeDStream(zds: *mut DStream) -> usize;
    fn ZSTD_decompressStream(
        zds: *mut DStream,
        output: *mut OutBuffer,
        input: *mut InBuffer,
    ) -> usize;
    fn ZSTD_isError(code: usize) -> c_uint;
    fn ZSTD_versionNumber() -> c_uint;
}

/// The library's version number, as `curl_version_info` gives it.
pub fn version_number() -> u32 {
    // SAFETY: ZSTD_versionNumber has no preconditions.
    unsafe { ZSTD_versionNumber() }
}

/// The library's version, as `curl -V` names it (`zstd_version`).
pub fn version() -> impl fmt::Display {
    let v = version_number();
    Version(v / 10000, v / 100 % 100, v % 100)
}

struct Version(u32, u32, u32);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The most a stream makes at once (`DECOMPRESS_BUFFER_SIZE`).
const BUFFER: usize = 16384;

/// The output asked for between two checks of the time (1 MiB).
const ROUNDS_PER_CHECK: u32 = (1024 * 1024 / BUFFER) as u32;

/// A decoding stream (C's `zstd_writer`).
struct Zstd {
    zds: NonNull<DStream>,
    buffer: Box<[u8; BUFFER]>,
}

impl fmt::Debug for Zstd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Zstd").finish_non_exhaustive()
    }
}

/// A decoder of the `zstd` coding (`zstd_encoding`).
pub fn decoder() -> Result<Box<dyn Decoder>, ErrorKind> {
    let buffer = try_box([0u8; BUFFER]).map_err(|_| ErrorKind::OutOfMemory)?;
    // SAFETY: ZSTD_createDStream has no preconditions.
    let zds = unsafe { ZSTD_createDStream() };
    let zds = NonNull::new(zds).ok_or(ErrorKind::OutOfMemory)?;
    // Made before the box, so that a failed box still frees the stream.
    let zstd = Zstd { zds, buffer };
    Ok(try_box(zstd).map_err(|_| ErrorKind::OutOfMemory)?)
}

// SAFETY: the stream is this decoder's alone, reached only through
// `&mut self`; zstd keeps no tie to the thread that made it.
unsafe impl Send for Zstd {}

impl Decoder for Zstd {
    fn decode(&mut self, input: &[u8], out: &mut dyn Sink) -> Result<(), ErrorKind> {
        let mut input = InBuffer {
            src: input.as_ptr().cast(),
            size: input.len(),
            pos: 0,
        };
        let mut rounds = 0;
        loop {
            rounds += 1;
            if rounds > ROUNDS_PER_CHECK {
                rounds = 0;
                if out.timed_out() {
                    return Err(out.fail(
                        ErrorKind::OperationTimedout,
                        format_args!("Operation timed out while decoding payload"),
                    ));
                }
            }
            let mut output = OutBuffer {
                dst: self.buffer.as_mut_ptr().cast(),
                size: BUFFER,
                pos: 0,
            };
            // SAFETY: the stream is live; the buffers point at the input
            // and the output buffer, both alive here, with their sizes.
            let code = unsafe { ZSTD_decompressStream(self.zds.as_ptr(), &mut output, &mut input) };
            // SAFETY: ZSTD_isError reads only its argument.
            if unsafe { ZSTD_isError(code) } != 0 {
                return Err(ErrorKind::BadContentEncoding);
            }
            if output.pos > 0 {
                out.write(&self.buffer[..output.pos])?;
            }
            if input.pos == input.size && output.pos < output.size {
                return Ok(());
            }
        }
    }
}

impl Drop for Zstd {
    fn drop(&mut self) {
        // SAFETY: the stream was created and is freed once.
        unsafe { ZSTD_freeDStream(self.zds.as_ptr()) };
    }
}

#[cfg(test)]
mod tests;
