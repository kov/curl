//! `curl_mprintf` and the rest of the family.
//!
//! The format is parsed and rendered by the safe `format` module. This
//! module reads the variadic arguments, follows the pointers among them and
//! writes to the C destinations: buffers, `FILE *` streams and memory from
//! the application's allocator.

#![allow(unsafe_code)]

mod format;

use core::ffi::{CStr, VaList, c_char, c_int, c_long, c_short, c_uint, c_ulong};
use core::ptr;

use curl_alloc::TryVec;

use crate::ffi::{self, FILE};
use crate::root;
use format::{ArgType, Args, BUFFSIZE, CountSize, MAX_PARAMETERS, Parsed, Sink};

/// `curl_maprintf` results are capped, as libcurl's are, at this size
/// including the NUL.
const APRINTF_MAX: usize = 8_000_000;

/// Arguments read from a `va_list`, each kept as the 64 bits libcurl's C
/// union holds.
struct Values {
    bits: [u64; MAX_PARAMETERS],
}

/// Type tags of `csrc/va_fetch.c`.
#[repr(u8)]
#[derive(Clone, Copy)]
enum Tag {
    Int = 0,
    UInt = 1,
    Long = 2,
    ULong = 3,
    LongLong = 4,
    ULongLong = 5,
    Double = 6,
    LongDouble = 7,
    Ptr = 8,
}

fn tag(ty: ArgType) -> Tag {
    match ty {
        ArgType::Int | ArgType::Width | ArgType::Precision => Tag::Int,
        ArgType::UInt => Tag::UInt,
        ArgType::Long => Tag::Long,
        ArgType::ULong => Tag::ULong,
        ArgType::LongLong => Tag::LongLong,
        ArgType::ULongLong => Tag::ULongLong,
        ArgType::Double => Tag::Double,
        ArgType::LongDouble => Tag::LongDouble,
        ArgType::Str | ArgType::Ptr | ArgType::IntPtr => Tag::Ptr,
    }
}

unsafe extern "C" {
    /// `csrc/va_fetch.c`.
    fn curl_rs_va_fetch(ap: VaList<'_>, types: *const u8, n: usize, out: *mut u64);
}

/// Whether Rust can read a `long double` itself: nightly's `f128` is the
/// `long double` of aarch64 Linux.
const RUST_READS_LONG_DOUBLE: bool = cfg!(all(feature = "nightly", target_arch = "aarch64"));

#[cfg(all(feature = "nightly", target_arch = "aarch64"))]
unsafe fn long_double(ap: &mut VaList<'_>) -> u64 {
    // SAFETY: the caller's format says the next argument is a `long
    // double`, which is `f128` here.
    let v = unsafe { ap.next_arg::<f128>() };
    (v as f64).to_bits()
}

#[cfg(not(all(feature = "nightly", target_arch = "aarch64")))]
unsafe fn long_double(_ap: &mut VaList<'_>) -> u64 {
    unreachable!("`long double` arguments are read by the C helper")
}

/// Read the next argument as `tag` says, widened to 64 bits.
///
/// # Safety
///
/// The next argument in `ap` has the C type `tag` names.
unsafe fn next(ap: &mut VaList<'_>, tag: Tag) -> u64 {
    match tag {
        // SAFETY: the caller guarantees an `int` is next.
        Tag::Int => i64::from(unsafe { ap.next_arg::<c_int>() }) as u64,
        // SAFETY: the caller guarantees an `unsigned int` is next.
        Tag::UInt => u64::from(unsafe { ap.next_arg::<c_uint>() }),
        // SAFETY: the caller guarantees a `long` is next.
        Tag::Long => (unsafe { ap.next_arg::<c_long>() }) as u64,
        #[allow(
            clippy::unnecessary_cast,
            reason = "`c_ulong` is 32 bits on some targets"
        )]
        Tag::ULong => {
            // SAFETY: the caller guarantees an `unsigned long` is next.
            (unsafe { ap.next_arg::<c_ulong>() }) as u64
        }
        // SAFETY: the caller guarantees a 64-bit integer is next.
        Tag::LongLong => (unsafe { ap.next_arg::<i64>() }) as u64,
        // SAFETY: the caller guarantees an unsigned 64-bit integer is next.
        Tag::ULongLong => unsafe { ap.next_arg::<u64>() },
        // SAFETY: the caller guarantees a `double` is next.
        Tag::Double => unsafe { ap.next_arg::<f64>() }.to_bits(),
        // SAFETY: the caller guarantees a `long double` is next.
        Tag::LongDouble => unsafe { long_double(ap) },
        // SAFETY: the caller guarantees a pointer is next.
        Tag::Ptr => (unsafe { ap.next_arg::<*mut core::ffi::c_void>() }) as u64,
    }
}

/// Read the arguments `parsed` describes.
///
/// # Safety
///
/// `ap` holds at least the arguments the format names, of the types it
/// names, as a C caller of a printf function must ensure.
unsafe fn fetch(parsed: &Parsed, mut ap: VaList<'_>) -> Values {
    let inputs = parsed.inputs();
    let mut v = Values {
        bits: [0; MAX_PARAMETERS],
    };
    if !RUST_READS_LONG_DOUBLE && inputs.contains(&ArgType::LongDouble) {
        let mut tags = [0u8; MAX_PARAMETERS];
        for (t, &ty) in tags.iter_mut().zip(inputs) {
            *t = tag(ty) as u8;
        }
        // SAFETY: `tags` and `v.bits` hold `inputs.len()` entries; the
        // helper reads that many arguments of the types the caller
        // guarantees are there.
        unsafe { curl_rs_va_fetch(ap, tags.as_ptr(), inputs.len(), v.bits.as_mut_ptr()) };
        return v;
    }
    for (b, &ty) in v.bits.iter_mut().zip(inputs) {
        // SAFETY: the caller guarantees the next argument has the type the
        // format gives it, which is the type `next` reads.
        *b = unsafe { next(&mut ap, tag(ty)) };
    }
    v
}

impl Args for Values {
    fn bits(&self, i: usize) -> u64 {
        self.bits[i]
    }

    fn string(&self, i: usize, limit: Option<usize>) -> Option<&[u8]> {
        let p = self.bits[i] as usize as *const u8;
        if p.is_null() {
            return None;
        }
        Some(match limit {
            // SAFETY: the caller passed a C string for this `%s`.
            None => unsafe { CStr::from_ptr(p.cast()) }.to_bytes(),
            Some(limit) => {
                // With a precision the string need not be NUL-terminated:
                // read no further than the precision or the first NUL.
                let mut n = 0;
                while n < limit {
                    // SAFETY: the byte is within the first `limit` and
                    // before any NUL, which the caller made readable.
                    if unsafe { p.wrapping_add(n).read() } == 0 {
                        break;
                    }
                    n += 1;
                }
                // SAFETY: the `n` bytes were just read one by one.
                unsafe { core::slice::from_raw_parts(p, n) }
            }
        })
    }

    fn store_count(&mut self, i: usize, count: i32, size: CountSize) {
        let p = self.bits[i] as usize;
        match size {
            // SAFETY: the caller passed a `short *` for `%hn`.
            CountSize::Short => unsafe { (p as *mut c_short).write(count as c_short) },
            // SAFETY: the caller passed an `int *` for `%n`.
            CountSize::Int => unsafe { (p as *mut c_int).write(count) },
            // SAFETY: the caller passed a `long *` for `%ln`.
            CountSize::Long => unsafe { (p as *mut c_long).write(c_long::from(count)) },
            // SAFETY: the caller passed a 64-bit integer pointer for `%lln`.
            CountSize::LongLong => unsafe { (p as *mut i64).write(i64::from(count)) },
        }
    }

    fn format_double(&self, spec: &[u8], value: f64, out: &mut [u8; BUFFSIZE + 2]) -> usize {
        let mut fmt = [0u8; 33];
        fmt[..spec.len()].copy_from_slice(spec);
        // SAFETY: `fmt` is a NUL-terminated format with one double
        // conversion, built by the formatter; `out` has room for `BUFFSIZE`
        // bytes, the size passed, and the width and precision in `fmt` are
        // clamped to fit it.
        let n = unsafe {
            libc::snprintf(
                out.as_mut_ptr().cast(),
                BUFFSIZE,
                fmt.as_ptr().cast(),
                value,
            )
        };
        usize::try_from(n).unwrap_or(0).min(BUFFSIZE - 1)
    }
}

/// Parse `format`, read the arguments and render into `sink`. A NULL or
/// invalid format outputs nothing.
///
/// # Safety
///
/// `format` is NULL or a C string, and `ap` matches it.
unsafe fn formatf(sink: &mut impl Sink, format: *const c_char, ap: VaList<'_>) -> c_int {
    if format.is_null() {
        return 0;
    }
    // SAFETY: the caller passes a C string.
    let fmt = unsafe { CStr::from_ptr(format) }.to_bytes();
    let Some(parsed) = format::parse(fmt) else {
        return 0;
    };
    // SAFETY: the caller's arguments match the format.
    let mut args = unsafe { fetch(&parsed, ap) };
    format::render(fmt, &parsed, &mut args, sink)
}

/// A buffer of known size, as for `snprintf`.
struct Bounded<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Sink for Bounded<'_> {
    fn write(&mut self, bytes: &[u8]) -> usize {
        let n = bytes.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        n
    }
}

/// A buffer the caller promises is large enough, as for `sprintf`.
struct Unbounded {
    at: *mut u8,
}

impl Sink for Unbounded {
    fn write(&mut self, bytes: &[u8]) -> usize {
        // SAFETY: the caller of `curl_msprintf` guarantees the buffer holds
        // the whole output.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), self.at, bytes.len()) };
        // SAFETY: as above, the advanced pointer stays within the buffer.
        self.at = unsafe { self.at.add(bytes.len()) };
        bytes.len()
    }
}

/// A C stream.
struct Stream {
    file: *mut libc::FILE,
    error: bool,
}

impl Sink for Stream {
    fn write(&mut self, bytes: &[u8]) -> usize {
        // SAFETY: `file` is the caller's open stream, `bytes` is readable.
        let n = unsafe { libc::fwrite(bytes.as_ptr().cast(), 1, bytes.len(), self.file) };
        self.error = n != bytes.len();
        n
    }
}

/// A growing buffer for `curl_maprintf`.
struct Growing {
    buf: Vec<u8>,
    failed: bool,
}

impl Sink for Growing {
    fn write(&mut self, bytes: &[u8]) -> usize {
        // Bytes beyond the cap are refused one byte short of it, leaving
        // room for the NUL, as libcurl's dynbuf does.
        let room = APRINTF_MAX - 1 - self.buf.len();
        let n = bytes.len().min(room);
        if self.buf.try_extend_from_slice(&bytes[..n]).is_err() {
            self.failed = true;
            return 0;
        }
        if n < bytes.len() {
            self.failed = true;
        }
        n
    }
}

fn snprintf_into(
    buffer: *mut c_char,
    maxlength: usize,
    f: impl FnOnce(&mut Bounded<'_>) -> c_int,
) -> c_int {
    let buf: &mut [u8] = if buffer.is_null() || maxlength == 0 {
        &mut []
    } else {
        // SAFETY: the caller of `curl_msnprintf` gives a writable buffer of
        // `maxlength` bytes.
        unsafe { core::slice::from_raw_parts_mut(buffer.cast(), maxlength) }
    };
    let mut sink = Bounded { buf, len: 0 };
    let mut n = f(&mut sink);
    if !sink.buf.is_empty() {
        if sink.len == sink.buf.len() {
            // Full: the last byte becomes the NUL and is not counted.
            sink.buf[sink.len - 1] = 0;
            n -= 1;
        } else {
            sink.buf[sink.len] = 0;
        }
    }
    n
}

/// # Safety
///
/// As C's `vsnprintf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mvsnprintf(
    buffer: *mut c_char,
    maxlength: usize,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    // SAFETY: the caller's format and arguments match.
    snprintf_into(buffer, maxlength, |sink| unsafe {
        formatf(sink, format, args)
    })
}
const _: ffi::proto::curl_mvsnprintf = curl_mvsnprintf;

/// # Safety
///
/// As C's `snprintf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_msnprintf(
    buffer: *mut c_char,
    maxlength: usize,
    format: *const c_char,
    args: ...
) -> c_int {
    // SAFETY: forwarded from the caller.
    unsafe { curl_mvsnprintf(buffer, maxlength, format, args) }
}
const _: ffi::proto::curl_msnprintf = curl_msnprintf;

/// # Safety
///
/// As C's `vsprintf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mvsprintf(
    buffer: *mut c_char,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    let mut sink = Unbounded { at: buffer.cast() };
    // SAFETY: the caller's format and arguments match.
    let n = unsafe { formatf(&mut sink, format, args) };
    // SAFETY: the buffer has room for the output and its NUL.
    unsafe { sink.at.write(0) };
    n
}
const _: ffi::proto::curl_mvsprintf = curl_mvsprintf;

/// # Safety
///
/// As C's `sprintf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_msprintf(
    buffer: *mut c_char,
    format: *const c_char,
    args: ...
) -> c_int {
    // SAFETY: forwarded from the caller.
    unsafe { curl_mvsprintf(buffer, format, args) }
}
const _: ffi::proto::curl_msprintf = curl_msprintf;

/// # Safety
///
/// As C's `vfprintf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mvfprintf(
    fd: *mut FILE,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    let mut sink = Stream {
        file: fd.cast(),
        error: false,
    };
    // SAFETY: the caller's format and arguments match.
    let n = unsafe { formatf(&mut sink, format, args) };
    if sink.error { -1 } else { n }
}
const _: ffi::proto::curl_mvfprintf = curl_mvfprintf;

/// # Safety
///
/// As C's `fprintf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mfprintf(fd: *mut FILE, format: *const c_char, args: ...) -> c_int {
    // SAFETY: forwarded from the caller.
    unsafe { curl_mvfprintf(fd, format, args) }
}
const _: ffi::proto::curl_mfprintf = curl_mfprintf;

unsafe extern "C" {
    /// The C library's standard output stream, shared with the
    /// application's own `printf`.
    static stdout: *mut libc::FILE;
}

/// # Safety
///
/// As C's `vprintf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mvprintf(format: *const c_char, args: VaList<'_>) -> c_int {
    // SAFETY: `stdout` is initialised by the C library before any code
    // runs; the format and arguments are the caller's.
    unsafe { curl_mvfprintf(stdout.cast(), format, args) }
}
const _: ffi::proto::curl_mvprintf = curl_mvprintf;

/// # Safety
///
/// As C's `printf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mprintf(format: *const c_char, args: ...) -> c_int {
    // SAFETY: forwarded from the caller.
    unsafe { curl_mvprintf(format, args) }
}
const _: ffi::proto::curl_mprintf = curl_mprintf;

/// # Safety
///
/// As `curl_mvaprintf(3)`: the format and arguments match.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mvaprintf(format: *const c_char, args: VaList<'_>) -> *mut c_char {
    let mut sink = Growing {
        buf: Vec::new(),
        failed: false,
    };
    // SAFETY: the caller's format and arguments match.
    unsafe { formatf(&mut sink, format, args) };
    if sink.failed {
        return ptr::null_mut();
    }
    root::allocator().c_string(&sink.buf)
}
const _: ffi::proto::curl_mvaprintf = curl_mvaprintf;

/// # Safety
///
/// As `curl_maprintf(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_maprintf(format: *const c_char, args: ...) -> *mut c_char {
    // SAFETY: forwarded from the caller.
    unsafe { curl_mvaprintf(format, args) }
}
const _: ffi::proto::curl_maprintf = curl_maprintf;
