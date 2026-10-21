//! The application's callbacks behind the core's handler traits
//! (`lib/cw-out.c`, `lib/sendf.c`, `lib/progress.c`, `lib/curl_trc.c`).
//!
//! Every adapter names its handle, and reads the function and data the
//! application set at the moment it calls, so a setopt inside a callback
//! applies to the next call. Each lends its context to the handle's
//! multi for as long as the application's code runs.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::num::NonZeroUsize;
use core::ptr::{self, NonNull};

use core::cell::Cell;

use curl_alloc::{OutOfMemory, TryRc, TryVec as _, try_format};
use curl_core::handler::{
    DebugHandler, DebugKind, Handler, HeaderHandler, HeaderOrigin, ProgressHandler, ProgressNow,
    ProgressVerdict, Read, ReadHandler, Rewind, RewindFailed, TextSink, Write, WriteHandler,
};
use curl_core::multi::TransferCx;
use curl_core::options::{Callbacks, Method, Options, Progress, UploadSource};

use crate::easy::ShimEasy;
use crate::ffi::{
    self, CURL_PROGRESSFUNC_CONTINUE, CURL_READFUNC_ABORT, CURL_READFUNC_PAUSE, CURL_SEEKFUNC_OK,
    CURL_WRITEFUNC_ERROR, CURL_WRITEFUNC_PAUSE, CURLIOCMD_RESTARTREAD, CURLIOE_OK,
    curl_debug_callback, curl_infotype, curl_ioctl_callback, curl_progress_callback,
    curl_read_callback, curl_seek_callback, curl_write_callback, curl_xferinfo_callback,
};
use crate::gate::Frame;

unsafe extern "C" {
    // glibc's standard streams.
    static stdin: *mut libc::FILE;
    static stdout: *mut libc::FILE;
    static stderr: *mut libc::FILE;
}

/// The process's standard input, output and error streams.
pub(crate) fn standard() -> (*mut c_void, *mut c_void, *mut libc::FILE) {
    // SAFETY: glibc sets these before any code runs and never changes
    // them.
    unsafe { (stdin.cast(), stdout.cast(), stderr) }
}

/// The application's functions and data, as setopt left them.
#[derive(Clone, Copy)]
pub(crate) struct CCallbacks {
    pub(crate) write: curl_write_callback,
    pub(crate) write_data: *mut c_void,
    pub(crate) header: curl_write_callback,
    pub(crate) header_data: *mut c_void,
    pub(crate) read: curl_read_callback,
    pub(crate) read_data: *mut c_void,
    pub(crate) seek: curl_seek_callback,
    pub(crate) seek_data: *mut c_void,
    pub(crate) ioctl: curl_ioctl_callback,
    pub(crate) ioctl_data: *mut c_void,
    pub(crate) xferinfo: curl_xferinfo_callback,
    pub(crate) progress: curl_progress_callback,
    pub(crate) progress_data: *mut c_void,
    pub(crate) debug: curl_debug_callback,
    pub(crate) debug_data: *mut c_void,
    /// Where text goes without a debug function (`CURLOPT_STDERR`).
    pub(crate) stderr: *mut libc::FILE,
}

impl CCallbacks {
    /// What a new handle has: the standard streams (`Curl_init_userdefined`).
    pub(crate) fn new() -> CCallbacks {
        let (input, output, error) = standard();
        CCallbacks {
            write: None,
            write_data: output,
            header: None,
            header_data: ptr::null_mut(),
            read: None,
            read_data: input,
            seek: None,
            seek_data: ptr::null_mut(),
            ioctl: None,
            ioctl_data: ptr::null_mut(),
            xferinfo: None,
            progress: None,
            progress_data: ptr::null_mut(),
            debug: None,
            debug_data: ptr::null_mut(),
            stderr: error,
        }
    }
}

/// The values setopt keeps that the core holds only combined.
#[derive(Clone, Copy)]
pub(crate) struct CSettings {
    pub(crate) no_progress: bool,
    /// `CURLOPT_INFILESIZE`, -1 for unknown.
    pub(crate) in_file_size: i64,
    pub(crate) low_speed_limit: c_long,
    pub(crate) low_speed_time: c_long,
    pub(crate) private: *mut c_void,
}

impl CSettings {
    pub(crate) fn new() -> CSettings {
        CSettings {
            no_progress: true,
            in_file_size: -1,
            low_speed_limit: 0,
            low_speed_time: 0,
            private: ptr::null_mut(),
        }
    }
}

/// Give `options` the adapters of the handle at `easy` its settings call
/// for, in place of any it had: a copy's are the copy's own. Each looks at
/// the application's choices when it runs.
pub(crate) fn install(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    set: &CSettings,
    ccb: &CCallbacks,
    errbuf: *mut c_char,
) -> Result<(), OutOfMemory> {
    options.callbacks = Callbacks::default();
    // The body always goes through the application's C stream or
    // function, never Rust's own standard output.
    options.callbacks.write = Some(Handler::write(Adapter(easy))?);
    sync_error_buffer(options, easy, errbuf)?;
    install_defaults(options, easy, set, ccb)
}

/// The adapters besides the write and ERRORBUFFER ones: for the settings
/// of a new handle, none.
pub(crate) fn install_defaults(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    set: &CSettings,
    ccb: &CCallbacks,
) -> Result<(), OutOfMemory> {
    sync_text(options, easy, ccb)?;
    sync_progress(options, easy, set, ccb)?;
    sync_upload(options, easy, set)
}

/// The header, debug and text adapters, where the core's own default
/// would differ from C's: headers go nowhere without a header function or
/// data; the trace and text go to standard error, unbuffered in C as in
/// Rust, without a debug function or another STDERR stream. A handle
/// without them makes no allocation for them, as C makes none.
pub(crate) fn sync_text(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    ccb: &CCallbacks,
) -> Result<(), OutOfMemory> {
    let c = &mut options.callbacks;
    let headers = ccb.header.is_some() || !ccb.header_data.is_null();
    match (headers, c.header.is_some()) {
        (true, false) => c.header = Some(Handler::header(Adapter(easy))?),
        (false, true) => c.header = None,
        _ => {}
    }
    match (ccb.debug.is_some(), c.debug.is_some()) {
        (true, false) => c.debug = Some(Handler::debug(Adapter(easy))?),
        (false, true) => c.debug = None,
        _ => {}
    }
    let elsewhere = ccb.stderr != standard().2;
    match (elsewhere, c.stderr.is_some()) {
        (true, false) => c.stderr = Some(Handler::text(Adapter(easy))?),
        (false, true) => c.stderr = None,
        _ => {}
    }
    Ok(())
}

/// The ERRORBUFFER adapter, while the application has given one
/// (`CURLOPT_ERRORBUFFER`).
pub(crate) fn sync_error_buffer(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    errbuf: *mut c_char,
) -> Result<(), OutOfMemory> {
    let c = &mut options.callbacks;
    match (errbuf.is_null(), c.failure.is_some()) {
        (false, false) => c.failure = Some(Handler::text(ErrorBuffer(easy))?),
        (true, true) => c.failure = None,
        _ => {}
    }
    Ok(())
}

/// Copies a transfer's first reason for failing into ERRORBUFFER.
struct ErrorBuffer(NonNull<ShimEasy>);

impl TextSink for ErrorBuffer {
    fn write(&self, why: &[u8]) {
        // SAFETY: as for `Adapter::easy`.
        unsafe { self.0.as_ref() }.fill_error_buffer(why);
    }
}

/// The meter, the application's progress function, or neither
/// (`CURLOPT_NOPROGRESS` and the progress functions).
pub(crate) fn sync_progress(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    set: &CSettings,
    ccb: &CCallbacks,
) -> Result<(), OutOfMemory> {
    options.progress = if set.no_progress {
        Progress::Off
    } else if ccb.xferinfo.is_some() || ccb.progress.is_some() {
        Progress::Handler(Handler::progress(Adapter(easy))?)
    } else {
        Progress::Meter
    };
    Ok(())
}

/// What `CURLOPT_POSTFIELDS`, `CURLOPT_COPYPOSTFIELDS` and
/// `CURLOPT_POSTFIELDSIZE` set, kept whatever the method until set again.
#[derive(Clone)]
pub(crate) struct Post {
    pub(crate) fields: PostFields,
    /// `CURLOPT_POSTFIELDSIZE`, -1 for the fields' length.
    pub(crate) size: i64,
}

impl Post {
    pub(crate) fn new() -> Post {
        Post {
            fields: PostFields::None,
            size: -1,
        }
    }
}

#[derive(Clone)]
pub(crate) enum PostFields {
    /// None: a POST reads the read function.
    None,
    /// The application's bytes, read where they are when sent.
    App(NonNull<u8>),
    /// The handle's copy of them.
    Copied(TryRc<Vec<u8>>),
}

/// The body the method sends (`Curl_pretransfer`'s `infilesize`,
/// `set_reader`): an upload reads the read function, `CURLOPT_INFILESIZE`
/// long; a POST its fields, as long as `CURLOPT_POSTFIELDSIZE` says or
/// up to their zero byte, else the read function, as long as
/// `CURLOPT_POSTFIELDSIZE` says.
pub(crate) fn sync_upload(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    set: &CSettings,
) -> Result<(), OutOfMemory> {
    let read = |size: Option<u64>| -> Result<UploadSource, OutOfMemory> {
        Ok(UploadSource::Read {
            handler: Handler::read(Adapter(easy))?,
            rewind: Some(Handler::rewind(Adapter(easy))?),
            size,
        })
    };
    options.upload = match options.method {
        Method::Upload => read(u64::try_from(set.in_file_size).ok())?,
        Method::Post => {
            // SAFETY: the handle is alive while its options are set.
            let post = unsafe { easy.as_ref() }.post.borrow();
            let size = u64::try_from(post.size).ok();
            match &post.fields {
                // Read from the read function, a body the application asks
                // chunked is read to its end whatever its size
                // (`set_reader`, C's issue 13229).
                PostFields::None if options.http.headers.asks_chunked() == Some(true) => {
                    read(None)?
                }
                PostFields::None => read(size)?,
                PostFields::Copied(bytes) => match size.and_then(|n| usize::try_from(n).ok()) {
                    Some(n) if n < bytes.len() => {
                        let mut prefix = Vec::new();
                        prefix.try_extend_from_slice(&bytes[..n])?;
                        UploadSource::Bytes(TryRc::try_new(prefix)?)
                    }
                    _ => UploadSource::Bytes(bytes.clone()),
                },
                PostFields::App(at) => {
                    let len = match size {
                        Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
                        // SAFETY: the application's fields, without a
                        // size, are a C string.
                        None => unsafe { libc::strlen(at.as_ptr().cast()) },
                    };
                    let fields = Fields(TryRc::try_new(AppFields {
                        at: *at,
                        len,
                        read: Cell::new(0),
                    })?);
                    UploadSource::Read {
                        handler: Handler::read(fields.clone())?,
                        rewind: Some(Handler::rewind(fields)?),
                        size: Some(len as u64),
                    }
                }
            }
        }
        Method::Get | Method::Head => UploadSource::None,
    };
    Ok(())
}

/// The application's `CURLOPT_POSTFIELDS`, read where they are as they
/// are sent, by the read and the rewind both.
#[derive(Clone)]
struct Fields(TryRc<AppFields>);

struct AppFields {
    at: NonNull<u8>,
    len: usize,
    read: Cell<usize>,
}

impl ReadHandler for Fields {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        let fields = &*self.0;
        let read = fields.read.get();
        let n = (fields.len - read).min(buf.len());
        let start = fields.at.as_ptr().wrapping_add(read);
        // SAFETY: the application keeps its fields, `len` bytes, alive and
        // unchanged until the transfer is over, as `CURLOPT_POSTFIELDS`
        // requires; `read + n` is within them.
        let from = unsafe { core::slice::from_raw_parts(start, n) };
        buf[..n].copy_from_slice(from);
        fields.read.set(read + n);
        NonZeroUsize::new(n).map_or(Read::Eof, Read::Data)
    }
}

impl Rewind for Fields {
    fn rewind(&self, _: &mut TransferCx<'_>) -> Result<(), RewindFailed> {
        self.0.read.set(0);
        Ok(())
    }
}

/// Calls the application on behalf of the handle at its pointer.
struct Adapter(NonNull<ShimEasy>);

impl Adapter {
    fn easy(&self) -> &ShimEasy {
        // SAFETY: the handle outlives the options that hold its adapters:
        // it is freed only after its `Easy` is dropped, and a copy of the
        // options is given its own adapters.
        unsafe { self.0.as_ref() }
    }

    /// Call `f`, the application's code, with `cx` lent to the handle's
    /// multi.
    fn call<R>(&self, cx: &mut TransferCx<'_>, f: impl FnOnce() -> R) -> R {
        let frame = Frame::Transfer(NonNull::from(cx).cast());
        match self.easy().multi() {
            // `cx` is not used again until `lend` returns.
            Some(multi) => multi.stack.lend(frame, f),
            None => f(),
        }
    }

    fn handle(&self) -> *mut c_void {
        self.0.as_ptr().cast()
    }
}

/// `fwrite` with C's argument order, the default write function.
unsafe extern "C" fn fwrite(ptr: *mut c_char, size: usize, n: usize, stream: *mut c_void) -> usize {
    if stream.is_null() {
        return 0;
    }
    // SAFETY: `ptr` holds `size * n` bytes, and the application gave
    // `stream` as a `FILE *`.
    unsafe { libc::fwrite(ptr.cast(), size, n, stream.cast()) }
}

/// `fread` with C's argument order, the default read function.
unsafe extern "C" fn fread(ptr: *mut c_char, size: usize, n: usize, stream: *mut c_void) -> usize {
    if stream.is_null() {
        return 0;
    }
    // SAFETY: `ptr` has room for `size * n` bytes, and the application
    // gave `stream` as a `FILE *`.
    unsafe { libc::fread(ptr.cast(), size, n, stream.cast()) }
}

/// The write function's verdict on `len` bytes (`cw_out_cb_write`).
fn write_verdict(cx: &mut TransferCx<'_>, len: usize, wrote: usize) -> Write {
    if wrote == len {
        Write::Accepted
    } else if wrote == CURL_WRITEFUNC_PAUSE as usize {
        Write::Pause
    } else if wrote == CURL_WRITEFUNC_ERROR as usize {
        Write::Fail
    } else {
        // A count of its own: the reason is the shim's to give.
        let why = try_format(format_args!(
            "Failure writing output to destination, passed {len} returned {wrote}"
        ));
        cx.fail(
            why.as_ref()
                .map_or(&b"Failure writing output to destination"[..], |w| {
                    w.as_bytes()
                }),
        );
        Write::Fail
    }
}

impl WriteHandler for Adapter {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
        let ccb = self.easy().ccb.get();
        let f = ccb.write.unwrap_or(fwrite);
        let wrote = self.call(cx, || {
            // SAFETY: the application's write function takes the bytes,
            // which it may not change, as C's does.
            unsafe {
                f(
                    body.as_ptr().cast_mut().cast(),
                    1,
                    body.len(),
                    ccb.write_data,
                )
            }
        });
        write_verdict(cx, body.len(), wrote)
    }
}

impl HeaderHandler for Adapter {
    fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        let ccb = self.easy().ccb.get();
        // The header function, else the write function given header data;
        // with neither, `sync_text` installs no adapter.
        let f = match (ccb.header, ccb.header_data.is_null()) {
            (Some(f), _) => f,
            (None, false) => ccb.write.unwrap_or(fwrite),
            (None, true) => return Write::Accepted,
        };
        let wrote = self.call(cx, || {
            // SAFETY: as for the body.
            unsafe {
                f(
                    line.as_ptr().cast_mut().cast(),
                    1,
                    line.len(),
                    ccb.header_data,
                )
            }
        });
        write_verdict(cx, line.len(), wrote)
    }
}

impl ReadHandler for Adapter {
    fn read(&self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        let ccb = self.easy().ccb.get();
        let f = ccb.read.unwrap_or(fread);
        let len = buf.len();
        let got = self.call(cx, || {
            // SAFETY: `buf` has room for `len` bytes.
            unsafe { f(buf.as_mut_ptr().cast(), 1, len, ccb.read_data) }
        });
        if got == CURL_READFUNC_ABORT as usize {
            Read::Abort
        } else if got == CURL_READFUNC_PAUSE as usize {
            Read::Pause
        } else {
            // Past `len` is the core's to reject.
            NonZeroUsize::new(got).map_or(Read::Eof, Read::Data)
        }
    }
}

impl Rewind for Adapter {
    /// The seek function, else the ioctl function, else `fseek` on the
    /// default read function's stream (`cr_in_rewind`).
    fn rewind(&self, cx: &mut TransferCx<'_>) -> Result<(), RewindFailed> {
        let ccb = self.easy().ccb.get();
        if let Some(seek) = ccb.seek {
            // SAFETY: the application's seek function takes its data.
            let err = self.call(cx, || unsafe { seek(ccb.seek_data, 0, libc::SEEK_SET) });
            if err != CURL_SEEKFUNC_OK {
                let why = try_format(format_args!("seek callback returned error {err}"));
                cx.fail(
                    why.as_ref()
                        .map_or(&b"seek callback returned error"[..], |w| w.as_bytes()),
                );
                return Err(RewindFailed);
            }
            return Ok(());
        }
        if let Some(ioctl) = ccb.ioctl {
            let handle = self.handle();
            let cmd = CURLIOCMD_RESTARTREAD.0;
            // SAFETY: the application's ioctl function takes its data.
            let err = self.call(cx, || unsafe { ioctl(handle, cmd, ccb.ioctl_data) });
            if err != CURLIOE_OK {
                let why = try_format(format_args!("ioctl callback returned error {}", err.0));
                cx.fail(
                    why.as_ref()
                        .map_or(&b"ioctl callback returned error"[..], |w| w.as_bytes()),
                );
                return Err(RewindFailed);
            }
            return Ok(());
        }
        if ccb.read.is_none() && !ccb.read_data.is_null() {
            // SAFETY: the default read function's data is a `FILE *`.
            if unsafe { libc::fseek(ccb.read_data.cast(), 0, libc::SEEK_SET) } != -1 {
                return Ok(());
            }
        }
        Err(RewindFailed)
    }
}

impl ProgressHandler for Adapter {
    fn progress(&self, cx: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
        let ccb = self.easy().ccb.get();
        let off = |n: u64| ffi::curl_off_t::try_from(n).unwrap_or(ffi::curl_off_t::MAX);
        let (dltotal, dlnow) = (off(now.download_total.unwrap_or(0)), off(now.downloaded));
        let (ultotal, ulnow) = (off(now.upload_total.unwrap_or(0)), off(now.uploaded));
        let data = ccb.progress_data;
        let rc = match (ccb.xferinfo, ccb.progress) {
            // SAFETY: the application's progress function takes its data.
            (Some(f), _) => self.call(cx, || unsafe { f(data, dltotal, dlnow, ultotal, ulnow) }),
            (None, Some(f)) => self.call(cx, || {
                let d = |n: ffi::curl_off_t| n as f64;
                // SAFETY: as above.
                unsafe { f(data, d(dltotal), d(dlnow), d(ultotal), d(ulnow)) }
            }),
            (None, None) => return ProgressVerdict::ContinueWithMeter,
        };
        match rc {
            0 => ProgressVerdict::Continue,
            CURL_PROGRESSFUNC_CONTINUE => ProgressVerdict::ContinueWithMeter,
            _ => ProgressVerdict::Abort,
        }
    }
}

/// C's `curl_infotype` for a trace entry.
fn infotype(kind: DebugKind) -> curl_infotype {
    match kind {
        DebugKind::Text => ffi::CURLINFO_TEXT,
        DebugKind::HeaderIn => ffi::CURLINFO_HEADER_IN,
        DebugKind::HeaderOut => ffi::CURLINFO_HEADER_OUT,
        DebugKind::DataIn => ffi::CURLINFO_DATA_IN,
        DebugKind::DataOut => ffi::CURLINFO_DATA_OUT,
        DebugKind::SslDataIn => ffi::CURLINFO_SSL_DATA_IN,
        DebugKind::SslDataOut => ffi::CURLINFO_SSL_DATA_OUT,
    }
}

impl DebugHandler for Adapter {
    /// The debug function (`Curl_debug`).
    fn debug(&self, cx: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        let ccb = self.easy().ccb.get();
        // Without a debug function, `sync_text` installs no adapter.
        let Some(f) = ccb.debug else { return };
        let handle = self.handle();
        // The function's answer is ignored, as C ignores it.
        self.call(cx, || {
            // SAFETY: the application's debug function takes the bytes,
            // which it may not change, as C's does.
            unsafe {
                f(
                    handle,
                    infotype(kind),
                    data.as_ptr().cast_mut().cast(),
                    data.len(),
                    ccb.debug_data,
                )
            }
        });
    }
}

impl TextSink for Adapter {
    fn write(&self, text: &[u8]) {
        to_stream(self.easy().ccb.get().stderr, text);
    }
}

/// Text to a C stream; a failed write has nowhere else to be told.
fn to_stream(stream: *mut libc::FILE, text: &[u8]) {
    // Never NULL: setopt makes a NULL STDERR standard error.
    assert!(!stream.is_null(), "a stream to write to");
    // SAFETY: the application gave `stream` as a `FILE *`, or it is the
    // standard error stream.
    unsafe { libc::fwrite(text.as_ptr().cast(), 1, text.len(), stream) };
}

/// The status a C callback gives the multi's timer (`c_int` -1 aborts).
pub(crate) fn aborts(rc: c_int) -> bool {
    rc == -1
}
