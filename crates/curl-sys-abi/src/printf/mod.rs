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

use crate::ffi::{self, FILE};
use crate::root;
use format::{ArgType, Args, BUFFSIZE, CountSize, MAX, Parsed, Sink, Unparsed};

/// `curl_maprintf` results are capped, as libcurl's are, at this size
/// including the NUL.
const APRINTF_MAX: usize = 8_000_000;

/// Arguments read from a `va_list`, each kept as the 64 bits libcurl's C
/// union holds: room for `N`, as the format's `Parsed<N>` has.
struct Values<const N: usize> {
    bits: [u64; N],
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
    /// `csrc/va_fetch.c`: reads `n` arguments of `ap`, of the types the `n`
    /// `Tag`s at `types` name, widened into the `n` entries at `out`.
    /// Callers uphold what the tags say of `ap` and the room at both
    /// pointers (`fetch`).
    fn curl_rs_va_fetch(ap: VaList<'_>, types: *const u8, n: usize, out: *mut u64);
}

/// Whether Rust can read a `long double` itself: nightly's `f128` is the
/// `long double` of aarch64 Linux.
const RUST_READS_LONG_DOUBLE: bool = cfg!(all(feature = "nightly", target_arch = "aarch64"));

/// Read the next argument, a `long double`, as a `double`'s bits.
///
/// # Safety
///
/// The next argument in `ap` is a `long double`: `next`'s caller knows it
/// from the format, whose match with the arguments is the C caller's to
/// ensure, as for any printf function.
#[cfg(all(feature = "nightly", target_arch = "aarch64"))]
unsafe fn long_double(ap: &mut VaList<'_>) -> u64 {
    // SAFETY: a `long double` is next, as this function's caller
    // guarantees, and it is `f128` on this target.
    let v = unsafe { ap.next_arg::<f128>() };
    (v as f64).to_bits()
}

/// Never reached: without Rust's `f128`, `fetch` hands a format with a
/// `long double` to the C helper whole.
///
/// # Safety
///
/// None needed: it reads nothing. Declared `unsafe` to match the reader
/// above, so `next` calls either the same way.
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
unsafe fn fetch<const N: usize>(parsed: &Parsed<N>, mut ap: VaList<'_>, v: &mut Values<N>) {
    let inputs = parsed.inputs();
    if !RUST_READS_LONG_DOUBLE && inputs.contains(&ArgType::LongDouble) {
        let mut tags = [0u8; N];
        for (t, &ty) in tags.iter_mut().zip(inputs) {
            *t = tag(ty) as u8;
        }
        // SAFETY: `tags` and `v.bits` hold `inputs.len()` entries; the
        // helper reads that many arguments of the types the caller
        // guarantees are there.
        unsafe { curl_rs_va_fetch(ap, tags.as_ptr(), inputs.len(), v.bits.as_mut_ptr()) };
        return;
    }
    for (b, &ty) in v.bits.iter_mut().zip(inputs) {
        // SAFETY: the caller guarantees the next argument has the type the
        // format gives it, which is the type `next` reads.
        *b = unsafe { next(&mut ap, tag(ty)) };
    }
}

impl<const N: usize> Args for Values<N> {
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
    // Room for a common format first: the room is filled on every call.
    let mut small = Parsed::<SMALL>::new();
    match format::parse(fmt, &mut small) {
        // SAFETY: the caller's arguments match the format.
        Ok(()) => unsafe { fetch_and_render(sink, fmt, &small, ap) },
        // SAFETY: as the caller guarantees.
        Err(Unparsed::Full) => unsafe { formatf_large(sink, fmt, ap) },
        Err(Unparsed::Rejected) => 0,
    }
}

/// `formatf` with libcurl's whole room: apart, so that the common call's
/// stack frame does not hold it.
///
/// # Safety
///
/// As `formatf`'s.
#[inline(never)]
unsafe fn formatf_large(sink: &mut impl Sink, fmt: &[u8], ap: VaList<'_>) -> c_int {
    let mut parsed = Parsed::<MAX>::new();
    match format::parse(fmt, &mut parsed) {
        // SAFETY: the caller's arguments match the format.
        Ok(()) => unsafe { fetch_and_render(sink, fmt, &parsed, ap) },
        Err(Unparsed::Rejected) => 0,
        Err(Unparsed::Full) => unreachable!("libcurl's room is never too small"),
    }
}

/// The room tried first, in segments and arguments.
const SMALL: usize = 16;

/// Read the arguments `parsed` names and render it into `sink`.
///
/// # Safety
///
/// `ap` matches the format `parsed` was parsed from.
unsafe fn fetch_and_render<const N: usize>(
    sink: &mut impl Sink,
    fmt: &[u8],
    parsed: &Parsed<N>,
    ap: VaList<'_>,
) -> c_int {
    let mut args = Values { bits: [0; N] };
    // SAFETY: the caller's arguments match the format.
    unsafe { fetch(parsed, ap, &mut args) };
    format::render(fmt, parsed, &mut args, sink)
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

/// The first allocation of a `DynBuf` that needs less (`MIN_FIRST_ALLOC`).
const MIN_FIRST_ALLOC: usize = 32;

/// libcurl's dynbuf as `curl_maprintf` grows it (`lib/curlx/dynbuf.c`):
/// memory from the application's allocator, NUL-terminated after every
/// append, allocated as C's is so that the allocator sees the same calls,
/// and handed to the application as it is.
struct DynBuf {
    alloc: root::Allocator,
    /// NULL until the first append.
    ptr: *mut u8,
    /// Bytes held, before the NUL.
    len: usize,
    /// Bytes allocated.
    size: usize,
}

/// Why an append failed: the output is dropped either way.
struct Refused;

impl DynBuf {
    fn new(alloc: root::Allocator) -> DynBuf {
        DynBuf {
            alloc,
            ptr: ptr::null_mut(),
            len: 0,
            size: 0,
        }
    }

    /// Append `mem` (`curlx_dyn_addn`): the buffer is freed if it would
    /// pass `APRINTF_MAX` with its NUL or cannot grow.
    fn addn(&mut self, mem: &[u8]) -> Result<(), Refused> {
        let fit = mem.len() + self.len + 1;
        if fit > APRINTF_MAX {
            self.free();
            return Err(Refused);
        }
        let size = if self.size == 0 {
            fit.clamp(MIN_FIRST_ALLOC, APRINTF_MAX)
        } else {
            let mut a = self.size;
            while a < fit {
                a *= 2;
            }
            a.min(APRINTF_MAX)
        };
        if size != self.size {
            // SAFETY: `ptr` is NULL or this allocator's block of `size`
            // bytes, replaced by the result when that is not NULL.
            let p = unsafe { self.alloc.realloc(self.ptr.cast(), size) }.cast::<u8>();
            if p.is_null() {
                self.free();
                return Err(Refused);
            }
            self.ptr = p;
            self.size = size;
        }
        // SAFETY: the block holds `size >= fit` bytes, room for the `len`
        // held, `mem` and the NUL; `mem` is the caller's, not in it.
        unsafe {
            ptr::copy_nonoverlapping(mem.as_ptr(), self.ptr.wrapping_add(self.len), mem.len());
        }
        self.len += mem.len();
        // SAFETY: within the `fit` bytes, as above.
        unsafe { self.ptr.wrapping_add(self.len).write(0) };
        Ok(())
    }

    /// Give the buffer back (`curlx_dyn_free`).
    fn free(&mut self) {
        // SAFETY: NULL or this allocator's block, not used again: the
        // pointer is cleared with it.
        unsafe { self.alloc.free(self.ptr.cast()) };
        self.ptr = ptr::null_mut();
        self.len = 0;
        self.size = 0;
    }

    /// The NUL-terminated string, the caller's to free with `curl_free`.
    fn into_c_string(mut self) -> *mut c_char {
        let p = self.ptr;
        self.ptr = ptr::null_mut();
        p.cast()
    }
}

impl Drop for DynBuf {
    fn drop(&mut self) {
        self.free();
    }
}

/// How many bytes `curl_maprintf` stages before appending them to its
/// buffer (`ASPRINTF_STAGE_SIZE`).
const STAGE: usize = 512;

/// The sink of `curl_maprintf`: output staged, then appended to a
/// `DynBuf` a stageful at a time, as C's `alloc_addrun` does.
struct Growing {
    stage: [core::mem::MaybeUninit<u8>; STAGE],
    /// Bytes of `stage` written.
    staged: usize,
    buf: DynBuf,
    failed: bool,
}

impl Growing {
    fn new(alloc: root::Allocator) -> Growing {
        Growing {
            stage: [core::mem::MaybeUninit::uninit(); STAGE],
            staged: 0,
            buf: DynBuf::new(alloc),
            failed: false,
        }
    }

    /// Whether `more` bytes still fit the buffer's limit, counting what
    /// is staged (`alloc_fits`).
    fn fits(&self, more: usize) -> bool {
        self.buf.len + self.staged + more < APRINTF_MAX
    }

    fn stage(&mut self, bytes: &[u8]) {
        self.stage[self.staged..self.staged + bytes.len()].write_copy_of_slice(bytes);
        self.staged += bytes.len();
    }

    fn append(&mut self, bytes: &[u8]) -> bool {
        if self.buf.addn(bytes).is_err() {
            self.failed = true;
            return false;
        }
        true
    }
}

impl Sink for Growing {
    fn write(&mut self, bytes: &[u8]) -> usize {
        let mut accepted = 0;
        while accepted < bytes.len() {
            let mut room = STAGE - self.staged;
            if room == 0 {
                if !self.flush() {
                    return accepted;
                }
                room = STAGE;
            }
            let n = (bytes.len() - accepted).min(room);
            if !self.fits(n) {
                // Stage what fits, then append the first byte that does
                // not on its own, so the limit is reported at that byte.
                let fits = APRINTF_MAX - self.buf.len - self.staged - 1;
                self.stage(&bytes[accepted..accepted + fits]);
                accepted += fits;
                if !self.flush() || !self.append(&bytes[accepted..=accepted]) {
                    return accepted;
                }
                accepted += 1;
                continue;
            }
            self.stage(&bytes[accepted..accepted + n]);
            accepted += n;
        }
        accepted
    }

    fn flush(&mut self) -> bool {
        if self.staged == 0 {
            return true;
        }
        let staged = core::mem::replace(&mut self.staged, 0);
        // SAFETY: the first `staged` bytes of the stage were written by
        // `stage`.
        let bytes = unsafe { self.stage[..staged].assume_init_ref() };
        if self.buf.addn(bytes).is_err() {
            self.failed = true;
            return false;
        }
        true
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

/// # Safety
///
/// As C's `vprintf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mvprintf(format: *const c_char, args: VaList<'_>) -> c_int {
    // The C library's standard output stream, shared with the
    // application's own `printf`.
    let (_, stdout, _) = crate::callbacks::standard();
    // SAFETY: the stream is the C library's, open for the process; the
    // format and arguments are the caller's.
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
    let alloc = root::allocator();
    let mut sink = Growing::new(alloc);
    // SAFETY: the caller's format and arguments match.
    unsafe { formatf(&mut sink, format, args) };
    if !sink.failed {
        sink.flush();
    }
    if sink.failed {
        return ptr::null_mut();
    }
    if sink.buf.len > 0 {
        return sink.buf.into_c_string();
    }
    alloc.c_string(b"")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `curl_msnprintf` into a buffer of 2048 bytes: the count it returns
    /// and the text.
    macro_rules! snprintf {
        ($fmt:expr $(, $arg:expr)* $(,)?) => {{
            let mut buf = [0u8; 2048];
            // SAFETY: a C format whose conversions the arguments match,
            // and a buffer of the size given.
            let n = unsafe {
                curl_msnprintf(buf.as_mut_ptr().cast(), buf.len(), $fmt.as_ptr() $(, $arg)*)
            };
            let len = buf.iter().position(|&b| b == 0).unwrap();
            (n, String::from_utf8(buf[..len].to_vec()).unwrap())
        }};
    }

    /// Precision zeros as many as C's buffer holds, and the conversions
    /// around them, as C's `curl_msnprintf` writes them (each checked
    /// against libcurl's output).
    #[test]
    fn numbers_are_written_as_c_writes_them() {
        let zeros = |n: usize| "0".repeat(n);
        assert_eq!(snprintf!(c"%.330d", 7 as c_int), (325, zeros(324) + "7"));
        assert_eq!(snprintf!(c"%.400u", 7 as c_uint), (325, zeros(324) + "7"));
        assert_eq!(snprintf!(c"%#.400o", 8 as c_uint), (325, zeros(323) + "10"));
        assert_eq!(
            snprintf!(c"%#.330x|", 255 as c_uint),
            (328, format!("0x{}ff|", zeros(323)))
        );
        assert_eq!(
            snprintf!(c"%-340.323d|", -12 as c_int),
            (341, format!("-{}12{}|", zeros(321), " ".repeat(16)))
        );
        assert_eq!(
            snprintf!(
                c"[%#o][%#.0o][%.0d][%5.3d][%-+6d][% 05d][%#X]",
                0 as c_uint,
                0 as c_uint,
                0 as c_int,
                7 as c_int,
                42 as c_int,
                -3 as c_int,
                0xabc as c_uint
            ),
            (37, "[0][0][][  007][+42   ][-0003][0XABC]".into())
        );
        assert_eq!(
            snprintf!(
                c"%llo %llu %lld %llx",
                u64::MAX,
                u64::MAX,
                i64::MIN,
                u64::MAX
            ),
            (
                81,
                "1777777777777777777777 18446744073709551615 -9223372036854775808 ffffffffffffffff"
                    .into()
            )
        );
    }

    /// Formats with more segments or arguments than the room tried
    /// first are written whole, as C writes them; libcurl's own limits
    /// still refuse one.
    #[test]
    fn formats_past_the_first_room_are_written_as_c_writes_them() {
        let (a, b, c, d, e, f) = (
            1 as c_int, 2 as c_int, 3 as c_int, 4 as c_int, 5 as c_int, 6 as c_int,
        );
        assert_eq!(
            snprintf!(
                c"%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d",
                a,
                b,
                c,
                d,
                e,
                f,
                a,
                b,
                c,
                d,
                e,
                f,
                a,
                b,
                c,
                d,
                e
            ),
            (17, "12345612345612345".into())
        );
        assert_eq!(
            snprintf!(c"a%%b%%c%%d%%e%%f%%g%%h%%i%%j%%k%%l%%m%%n%%o%%p%%q%%r"),
            (35, "a%b%c%d%e%f%g%h%i%j%k%l%m%n%o%p%q%r".into())
        );
        let s = |t: &CStr| t.as_ptr();
        assert_eq!(
            snprintf!(
                c"%17$s %1$s %2$s %3$s %4$s %5$s %6$s %7$s %8$s %9$s %10$s %11$s %12$s %13$s %14$s %15$s %16$s",
                s(c"a"), s(c"b"), s(c"c"), s(c"d"), s(c"e"), s(c"f"), s(c"g"), s(c"h"), s(c"i"),
                s(c"j"), s(c"k"), s(c"l"), s(c"m"), s(c"n"), s(c"o"), s(c"p"), s(c"q")
            ),
            (33, "q a b c d e f g h i j k l m n o p".into())
        );
        // An argument left out is refused, past the first room too.
        assert_eq!(snprintf!(c"%16$s|%1$d", 5 as c_int), (0, String::new()));
        // 128 conversions are written, 129 refused.
        let c128 = std::ffi::CString::new("%c".repeat(128)).unwrap();
        let c129 = std::ffi::CString::new("%c".repeat(129)).unwrap();
        let x = c_int::from(b'a');
        macro_rules! with_128 {
            ($f:expr $(, $extra:expr)*) => {
                snprintf!(
                    $f,
                    x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
                    x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
                    x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,
                    x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x
                    $(, $extra)*
                )
            };
        }
        assert_eq!(with_128!(c128), (128, "a".repeat(128)));
        assert_eq!(with_128!(c129, x), (0, String::new()), "129 conversions");
    }

    /// `curl_maprintf`'s buffer grows as C's dynbuf does, behind a stage
    /// of 512 bytes: the application's allocator is asked for the sizes
    /// C asks for, so the block handed over is as large (each checked
    /// against libcurl's).
    #[test]
    fn aprintf_allocates_as_c_does() {
        let big = [b'x'; 3000];
        for (len, size) in [
            (1, 32),
            (31, 32),
            (32, 33),
            (100, 101),
            (511, 512),
            (512, 513),
            (513, 1026),
            (1100, 2052),
            (2999, 4104),
        ] {
            let mut sink = Growing::new(root::allocator());
            assert_eq!(sink.write(&big[..len]), len);
            assert!(sink.flush());
            assert_eq!((sink.buf.len, sink.buf.size), (len, size), "{len}");
            let p = sink.buf.into_c_string();
            // SAFETY: the NUL-terminated block the sink made.
            assert_eq!(unsafe { CStr::from_ptr(p) }.to_bytes(), &big[..len]);
            // SAFETY: handed over above, not used again.
            unsafe { root::curl_free(p.cast()) };
        }
        // `%n` flushes the stage: the buffer is first made for what came
        // before it, at the size C's is.
        let mut sink = Growing::new(root::allocator());
        assert_eq!(sink.write(b"abc"), 3);
        assert!(sink.flush());
        assert_eq!(sink.buf.size, 32);
        assert_eq!(sink.write(&big), big.len());
        assert!(sink.flush());
        assert_eq!((sink.buf.len, sink.buf.size), (3003, 4096));
        // A buffer exactly filled, its NUL included, is not grown.
        let mut sink = Growing::new(root::allocator());
        assert_eq!(sink.write(b"abc"), 3);
        assert!(sink.flush());
        assert_eq!(sink.write(&big[..28]), 28);
        assert!(sink.flush());
        assert_eq!((sink.buf.len, sink.buf.size), (31, 32));
        // Nothing written: the empty string, as C's `strdup("")`.
        // SAFETY: a format without conversions.
        let p = unsafe { curl_maprintf(c"".as_ptr()) };
        // SAFETY: a C string the library made, freed once read.
        assert_eq!(unsafe { CStr::from_ptr(p) }.to_bytes(), b"");
        // SAFETY: as above.
        unsafe { root::curl_free(p.cast()) };
    }

    /// Output reaching `curl_maprintf`'s limit with its NUL is refused at
    /// the byte that passes it, and the buffer given back.
    #[test]
    fn aprintf_refuses_output_at_its_limit() {
        let chunk = vec![b'y'; 1 << 20];
        // The limit met where a stage begins, and where bytes are staged
        // already (the limit is a multiple of the stage).
        for before in [APRINTF_MAX - STAGE, APRINTF_MAX - 300] {
            let mut sink = Growing::new(root::allocator());
            let mut total = 0;
            while total < before {
                let n = chunk.len().min(before - total);
                assert_eq!(sink.write(&chunk[..n]), n);
                total += n;
            }
            // A full stage is flushed by the next write, not at once.
            assert_eq!(sink.staged, (before - 1) % STAGE + 1);
            let room = APRINTF_MAX - 1 - total;
            assert_eq!(sink.write(&chunk), room, "accepted up to the limit");
            assert!(sink.failed);
            assert!(sink.buf.ptr.is_null(), "the buffer is given back");
        }
    }

    /// The buffer takes output up to its limit with the NUL, and
    /// refuses a byte past it, giving the buffer back
    /// (`curlx_dyn_addn`).
    #[test]
    fn dynbuf_takes_output_up_to_its_limit() {
        let mut buf = DynBuf::new(root::allocator());
        let most = vec![b'z'; APRINTF_MAX - 1];
        assert!(buf.addn(&most).is_ok());
        assert_eq!((buf.len, buf.size), (APRINTF_MAX - 1, APRINTF_MAX));
        assert!(buf.addn(b"z").is_err());
        assert!(buf.ptr.is_null(), "the buffer is given back");
    }

    /// A buffer dropped unfinished, or refused memory as it grows, gives
    /// back what it held.
    #[test]
    fn aprintf_frees_what_it_does_not_hand_over() {
        use crate::formdata::tests::{HELD, LEFT, counting};
        counting();
        let held = || HELD.with(core::cell::Cell::get);
        let before = held();
        let mut sink = Growing::new(root::allocator());
        assert_eq!(sink.write(&[b'q'; 2000]), 2000);
        assert!(held() > before);
        drop(sink);
        assert_eq!(held(), before, "dropped");
        // Refused as it grows: what it had is freed with it.
        let mut sink = Growing::new(root::allocator());
        LEFT.with(|l| l.set(Some(1)));
        let took = sink.write(&[b'q'; 2000]);
        LEFT.with(|l| l.set(None));
        assert!(took < 2000, "{took}");
        assert!(sink.failed);
        assert!(sink.buf.ptr.is_null());
        drop(sink);
        assert_eq!(held(), before, "refused");
    }

    /// Literal text of every length up to three words, around and
    /// between conversions, is written as it stands; a format that names
    /// its arguments and then does not is refused, as C's is.
    #[test]
    fn literal_text_is_written_whole() {
        for len in 0..24u8 {
            let text: String = (0..len).map(|i| char::from(b'a' + i)).collect();
            let fmt = std::ffi::CString::new(format!("{text}%d{text}%%{text}")).unwrap();
            let want = format!("{text}7{text}%{text}");
            let n = c_int::try_from(want.len()).unwrap();
            assert_eq!(snprintf!(fmt, 7 as c_int), (n, want), "{len}");
        }
        assert_eq!(
            snprintf!(c"%1$d %d", 5 as c_int, 6 as c_int),
            (0, String::new())
        );
        assert_eq!(
            snprintf!(c"%2$d %1$d %d", 5 as c_int, 6 as c_int, 7 as c_int),
            (0, String::new())
        );
    }
}
