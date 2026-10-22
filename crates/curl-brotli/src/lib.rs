//! brotli's decoder, undoing the `br` content coding as C's brotli writer
//! does (`lib/content_encoding.c`), behind `curl_core::coding::Decoder`.
//! brotli allocates through the system's allocator, as C's does.

// The binding: brotli's decoder state and calls.
#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use std::ffi::{c_int, c_void};
use std::fmt;
use std::ptr::{self, NonNull};

use curl_alloc::try_box;
use curl_core::coding::{Decoder, Sink};
use curl_core::error::ErrorKind;

/// `BrotliDecoderState`, opaque.
#[repr(C)]
struct State {
    _private: [u8; 0],
}

const RESULT_SUCCESS: c_int = 1;
const RESULT_NEEDS_MORE_INPUT: c_int = 2;
const RESULT_NEEDS_MORE_OUTPUT: c_int = 3;

unsafe extern "C" {
    fn BrotliDecoderCreateInstance(
        alloc: *const c_void,
        free: *const c_void,
        opaque: *mut c_void,
    ) -> *mut State;
    fn BrotliDecoderDestroyInstance(state: *mut State);
    fn BrotliDecoderDecompressStream(
        state: *mut State,
        available_in: *mut usize,
        next_in: *mut *const u8,
        available_out: *mut usize,
        next_out: *mut *mut u8,
        total_out: *mut usize,
    ) -> c_int;
    fn BrotliDecoderGetErrorCode(state: *const State) -> c_int;
    fn BrotliDecoderVersion() -> u32;
}

/// The library's version number, as `curl_version_info` gives it.
pub fn version_number() -> u32 {
    // SAFETY: BrotliDecoderVersion has no preconditions.
    unsafe { BrotliDecoderVersion() }
}

/// The library's version, as `curl -V` names it (`brotli_version`).
pub fn version() -> impl fmt::Display {
    let v = version_number();
    Version(v >> 24, (v & 0x00ff_ffff) >> 12, v & 0xfff)
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

/// A decoding stream (C's `brotli_writer`); `None` once it has ended.
struct Brotli {
    state: Option<NonNull<State>>,
    buffer: Box<[u8; BUFFER]>,
}

impl fmt::Debug for Brotli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Brotli")
            .field("ended", &self.state.is_none())
            .finish_non_exhaustive()
    }
}

/// A decoder of the `br` coding (`brotli_encoding`).
pub fn decoder() -> Result<Box<dyn Decoder>, ErrorKind> {
    let buffer = try_box([0u8; BUFFER]).map_err(|_| ErrorKind::OutOfMemory)?;
    // SAFETY: null allocators ask for the system's; nothing else is read.
    let state = unsafe { BrotliDecoderCreateInstance(ptr::null(), ptr::null(), ptr::null_mut()) };
    let state = NonNull::new(state).ok_or(ErrorKind::OutOfMemory)?;
    // Made before the box, so that a failed box still frees it.
    let brotli = Brotli {
        state: Some(state),
        buffer,
    };
    Ok(try_box(brotli).map_err(|_| ErrorKind::OutOfMemory)?)
}

/// What a decoder's failure is to the transfer (`brotli_map_error`).
fn map_error(code: c_int) -> ErrorKind {
    match code {
        // The format's errors C names, and the dictionary's and the
        // arguments'.
        -1 | -15..=-3 | -20..=-18 => ErrorKind::BadContentEncoding,
        -21 | -22 | -25 | -26 | -27 | -30 => ErrorKind::OutOfMemory,
        _ => ErrorKind::WriteError,
    }
}

impl Brotli {
    fn end(&mut self) {
        if let Some(state) = self.state.take() {
            // SAFETY: the instance was created and is destroyed once.
            unsafe { BrotliDecoderDestroyInstance(state.as_ptr()) };
        }
    }
}

impl Decoder for Brotli {
    fn decode(&mut self, input: &[u8], out: &mut dyn Sink) -> Result<(), ErrorKind> {
        let Some(state) = self.state else {
            // The stream ended.
            return Err(ErrorKind::WriteError);
        };
        let mut next_in = input.as_ptr();
        let mut left = input.len();
        let mut r = RESULT_NEEDS_MORE_OUTPUT;
        let mut rounds = 0;
        while left > 0 || r == RESULT_NEEDS_MORE_OUTPUT {
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
            let mut next_out = self.buffer.as_mut_ptr();
            let mut room = BUFFER;
            // SAFETY: the instance is live; the input points at `left`
            // bytes of `input` and the output at `room` bytes of the
            // buffer, both alive here; the total is not asked for.
            r = unsafe {
                BrotliDecoderDecompressStream(
                    state.as_ptr(),
                    &mut left,
                    &mut next_in,
                    &mut room,
                    &mut next_out,
                    ptr::null_mut(),
                )
            };
            // Written even when it made nothing, as C writes it.
            out.write(&self.buffer[..BUFFER - room])?;
            match r {
                RESULT_NEEDS_MORE_OUTPUT | RESULT_NEEDS_MORE_INPUT => {}
                RESULT_SUCCESS => {
                    self.end();
                    return if left > 0 {
                        Err(ErrorKind::WriteError)
                    } else {
                        Ok(())
                    };
                }
                _ => {
                    // SAFETY: the instance is live.
                    let code = unsafe { BrotliDecoderGetErrorCode(state.as_ptr()) };
                    return Err(map_error(code));
                }
            }
        }
        Ok(())
    }
}

impl Drop for Brotli {
    fn drop(&mut self) {
        self.end();
    }
}

#[cfg(test)]
mod tests;
