//! The application's callbacks behind the core's handler traits
//! (`lib/cw-out.c`, `lib/sendf.c`, `lib/progress.c`, `lib/curl_trc.c`).
//!
//! Every adapter names its handle, and reads the function and data the
//! application set at the moment it calls, so a setopt inside a callback
//! applies to the next call. Each lends its context to the handle's
//! multi for as long as the application's code runs.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::num::NonZeroUsize;
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_format};
use curl_core::handler::{
    ChunkBegin, ChunkBeginHandler, ChunkEndHandler, DebugHandler, DebugKind, FileInfo, FileType,
    FnMatchHandler, Handler, HeaderHandler, HeaderOrigin, HostKey, KeyMatch, KeyVerdict, LentBytes,
    Matched, ProgressHandler, ProgressNow, ProgressVerdict, Read, ReadHandler, Rewind,
    RewindFailed, SeekFailed, SshKeyHandler, TextSink, TrailerHandler, TrailerLines, Trailers,
    Write, WriteHandler,
};
use curl_core::multi::TransferCx;
use curl_core::options::{Method, Options, Progress, UploadSource};

use crate::easy::ShimEasy;
use crate::ffi::{
    self, CURL_PROGRESSFUNC_CONTINUE, CURL_READFUNC_ABORT, CURL_READFUNC_PAUSE, CURL_SEEKFUNC_OK,
    CURL_WRITEFUNC_ERROR, CURL_WRITEFUNC_PAUSE, CURLIOCMD_RESTARTREAD, CURLIOE_OK,
    curl_debug_callback, curl_infotype, curl_ioctl_callback, curl_progress_callback,
    curl_read_callback, curl_seek_callback, curl_trailer_callback, curl_write_callback,
    curl_xferinfo_callback,
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
    pub(crate) trailer: curl_trailer_callback,
    pub(crate) trailer_data: *mut c_void,
    /// `CURLOPT_SSH_KEYFUNCTION` and `CURLOPT_SSH_KEYDATA`.
    pub(crate) ssh_key: ffi::curl_sshkeycallback,
    pub(crate) ssh_key_data: *mut c_void,
    /// Where text goes without a debug function (`CURLOPT_STDERR`).
    pub(crate) stderr: *mut libc::FILE,
}

/// The application's wildcard download functions and data, as setopt
/// left them.
#[derive(Clone, Copy)]
pub(crate) struct CWildcard {
    pub(crate) chunk_bgn: ffi::curl_chunk_bgn_callback,
    pub(crate) chunk_end: ffi::curl_chunk_end_callback,
    /// Given to both (`CURLOPT_CHUNK_DATA`).
    pub(crate) chunk_data: *mut c_void,
    pub(crate) fnmatch: ffi::curl_fnmatch_callback,
    pub(crate) fnmatch_data: *mut c_void,
}

impl CWildcard {
    /// None set, as a new handle has.
    pub(crate) const NONE: CWildcard = CWildcard {
        chunk_bgn: None,
        chunk_end: None,
        chunk_data: ptr::null_mut(),
        fnmatch: None,
        fnmatch_data: ptr::null_mut(),
    };
}

/// The application's interleave function and data, as setopt left them
/// (`CURLOPT_INTERLEAVEFUNCTION`, `CURLOPT_INTERLEAVEDATA`): RTSP's RTP
/// goes to them.
#[derive(Clone, Copy)]
pub(crate) struct CInterleave {
    pub(crate) function: curl_write_callback,
    pub(crate) data: *mut c_void,
}

impl CInterleave {
    /// None set, as a new handle has.
    pub(crate) const NONE: CInterleave = CInterleave {
        function: None,
        data: ptr::null_mut(),
    };
}

/// The application's HSTS functions and data, as setopt left them.
#[derive(Clone, Copy)]
pub(crate) struct CHsts {
    pub(crate) read: ffi::curl_hstsread_callback,
    pub(crate) read_data: *mut c_void,
    pub(crate) write: ffi::curl_hstswrite_callback,
    pub(crate) write_data: *mut c_void,
}

impl CHsts {
    /// None set, as a new handle has.
    pub(crate) const NONE: CHsts = CHsts {
        read: None,
        read_data: ptr::null_mut(),
        write: None,
        write_data: ptr::null_mut(),
    };
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
            trailer: None,
            trailer_data: ptr::null_mut(),
            ssh_key: None,
            ssh_key_data: ptr::null_mut(),
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
    /// `CURLOPT_TIMECONDITION`, `CURL_TIMECOND_NONE` to `LASTMOD`.
    pub(crate) time_condition: c_long,
    /// `CURLOPT_TIMEVALUE_LARGE`.
    pub(crate) time_value: i64,
    pub(crate) private: *mut c_void,
    /// C's request method and `CURLOPT_NOBODY` (`set.method`,
    /// `set.opt_no_body`), kept apart as C keeps them: a setopt that sets
    /// one leaves the other where C's does, and no body wins as the
    /// request is made (`Curl_http_method`).
    pub(crate) method: Method,
    pub(crate) no_body: bool,
    /// `CURLOPT_CURLU`, as given: C's `set.uh`, read only as a transfer
    /// starts, so a copy of the handle keeps it and a reset forgets it.
    pub(crate) curlu: *const crate::ffi::CURLU,
}

impl CSettings {
    pub(crate) fn new() -> CSettings {
        CSettings {
            no_progress: true,
            in_file_size: -1,
            low_speed_limit: 0,
            low_speed_time: 0,
            time_condition: 0,
            time_value: 0,
            private: ptr::null_mut(),
            method: Method::Get,
            no_body: false,
            curlu: ptr::null(),
        }
    }

    /// The method the core is to use, of C's two values.
    pub(crate) fn method(&self) -> Method {
        if self.no_body {
            Method::Head
        } else {
            self.method
        }
    }
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
    sync_trailer(options, easy, ccb)?;
    sync_ssh_key(options, easy, ccb)?;
    sync_input(options, easy, ccb)?;
    sync_upload(options, easy, set)
}

/// The read adapter TELNET sends from whatever the method, once the
/// application has set a read function or its data; none before, which
/// costs a handle nothing.
pub(crate) fn sync_input(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    ccb: &CCallbacks,
) -> Result<(), OutOfMemory> {
    if ccb.read.is_some() || ccb.read_data != standard().0 {
        options.small.make_mut()?.input = Some(Handler::read(Adapter(easy))?);
    } else if let Some(small) = options.small.made_mut() {
        small.input = None;
    }
    Ok(())
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

// SAFETY: as for `Adapter`.
unsafe impl Send for ErrorBuffer {}
// SAFETY: as for `Adapter`.
unsafe impl Sync for ErrorBuffer {}

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

/// The HSTS reader and writer adapters, while there are functions for
/// them.
pub(crate) fn sync_hsts(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    c: &CHsts,
) -> Result<(), OutOfMemory> {
    let none = c.read.is_none() && c.write.is_none();
    let Some(hsts) = (match options.http.hsts.made_mut() {
        Some(made) => Some(made),
        None if none => None,
        None => Some(options.http.hsts.make_mut()?),
    }) else {
        return Ok(());
    };
    // Made again for `easy`, never kept: a copy's options arrive holding
    // the original's adapters.
    hsts.read = match c.read {
        Some(_) => Some(Handler::hsts_reader(Adapter(easy))?),
        None => None,
    };
    hsts.write = match c.write {
        Some(_) => Some(Handler::hsts_writer(Adapter(easy))?),
        None => None,
    };
    Ok(())
}

/// The trailer adapter, while there is a trailer function.
/// The wildcard download's adapters, one for each function set, made
/// again for `easy`, as for the HSTS functions.
pub(crate) fn sync_wildcard(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    c: &CWildcard,
) -> Result<(), OutOfMemory> {
    let none = c.chunk_bgn.is_none() && c.chunk_end.is_none() && c.fnmatch.is_none();
    let Some(line) = (match options.line.made_mut() {
        Some(made) => Some(made),
        None if none => None,
        None => Some(options.line.make_mut()?),
    }) else {
        return Ok(());
    };
    let ftp = &mut line.ftp;
    ftp.chunk_begin = match c.chunk_bgn {
        Some(_) => Some(Handler::chunk_begin(Adapter(easy))?),
        None => None,
    };
    ftp.chunk_end = match c.chunk_end {
        Some(_) => Some(Handler::chunk_end(Adapter(easy))?),
        None => None,
    };
    ftp.fnmatch = match c.fnmatch {
        Some(_) => Some(Handler::fnmatch(Adapter(easy))?),
        None => None,
    };
    Ok(())
}

pub(crate) fn sync_trailer(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    ccb: &CCallbacks,
) -> Result<(), OutOfMemory> {
    let c = &mut options.callbacks;
    match (ccb.trailer.is_some(), c.trailer.is_some()) {
        (true, false) => c.trailer = Some(Handler::trailer(Adapter(easy))?),
        (false, true) => c.trailer = None,
        _ => {}
    }
    Ok(())
}

/// The interleave adapter, while there is an interleave function: without
/// one, RTP goes to the write function with its data, as C sends it.
pub(crate) fn sync_interleave(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    c: &CInterleave,
) -> Result<(), OutOfMemory> {
    // Made anew each time: a copy of the options keeps the handle's it
    // was copied from.
    if c.function.is_some() {
        options.small.make_mut()?.interleave = Some(Handler::write(Interleave(Adapter(easy)))?);
    } else if let Some(small) = options.small.made_mut() {
        small.interleave = None;
    }
    Ok(())
}

/// The SSH key adapter, while there is a key function.
pub(crate) fn sync_ssh_key(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    ccb: &CCallbacks,
) -> Result<(), OutOfMemory> {
    let set = options
        .ssh
        .made_mut()
        .is_some_and(|s| s.key_handler.is_some());
    match (ccb.ssh_key.is_some(), set) {
        (true, false) => {
            options.ssh.make_mut()?.key_handler = Some(Handler::ssh_key(Adapter(easy))?);
        }
        (false, true) => options.ssh.make_mut()?.key_handler = None,
        _ => {}
    }
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
    Copied(TryArc<Vec<u8>>),
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
            // SAFETY: as above.
            if unsafe { easy.as_ref() }.post_body.get() != crate::easy::PostBody::Own {
                options.upload = UploadSource::Mime(Handler::mime(crate::mime::MimeTree(easy))?);
                return Ok(());
            }
            match &post.fields {
                // Read to its end whatever its size if the request is
                // asked chunked, which the core decides as it builds it.
                PostFields::None => read(size)?,
                PostFields::Copied(bytes) => match size.and_then(|n| usize::try_from(n).ok()) {
                    Some(n) if n < bytes.len() => {
                        let mut prefix = Vec::new();
                        prefix.try_extend_from_slice(&bytes[..n])?;
                        UploadSource::Bytes(TryArc::try_new(prefix)?)
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
                    UploadSource::Lent(Handler::lent(AppFields { at: *at, len })?)
                }
            }
        }
        Method::Get | Method::Head => UploadSource::None,
    };
    Ok(())
}

/// The application's `CURLOPT_POSTFIELDS`, read where they are as they
/// are sent, by the read and the rewind both.
struct AppFields {
    at: NonNull<u8>,
    len: usize,
}

// SAFETY: the fields are the application's, only read, and kept alive and
// unchanged until the transfer is over (`CURLOPT_POSTFIELDS`); the handle
// that sends them is used by one thread at a time, as C requires.
unsafe impl Send for AppFields {}
// SAFETY: as for `Send`: what is shared is only read.
unsafe impl Sync for AppFields {}

impl LentBytes for AppFields {
    fn size(&self) -> u64 {
        self.len as u64
    }

    fn copy_at(&self, at: u64, buf: &mut [u8]) -> usize {
        let at = usize::try_from(at).expect("an offset below the fields' length");
        let n = (self.len - at).min(buf.len());
        // SAFETY: the application keeps its fields, `len` bytes, alive and
        // unchanged until the transfer is over, as `CURLOPT_POSTFIELDS`
        // requires; `at + n` is within them.
        let from = unsafe { core::slice::from_raw_parts(self.at.as_ptr().wrapping_add(at), n) };
        buf[..n].copy_from_slice(from);
        n
    }
}

/// Calls the application on behalf of the handle at its pointer.
pub(crate) struct Adapter(pub(crate) NonNull<ShimEasy>);

// SAFETY: an adapter is its handle's alone (a copy of the options is given
// its own), and is called only by the transfer of that handle, which C
// lets one thread use at a time; what it reaches is the handle's.
unsafe impl Send for Adapter {}
// SAFETY: as for `Send`: no two threads reach one handle at once.
unsafe impl Sync for Adapter {}

impl Adapter {
    pub(crate) fn easy(&self) -> &ShimEasy {
        // SAFETY: the handle outlives the options that hold its adapters:
        // it is freed only after its `Easy` is dropped, and a copy of the
        // options is given its own adapters.
        unsafe { self.0.as_ref() }
    }

    /// Call `f`, the application's code, with `cx` lent to the handle's
    /// multi.
    pub(crate) fn call<R>(&self, cx: &mut TransferCx<'_>, f: impl FnOnce() -> R) -> R {
        let frame = Frame::Transfer(NonNull::from(cx).cast());
        match self.easy().multi() {
            // `cx` is not used again until `lend` returns.
            Some(multi) => multi.stack.lend(frame, f),
            None => f(),
        }
    }

    pub(crate) fn handle(&self) -> *mut c_void {
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
pub(crate) unsafe extern "C" fn fread(
    ptr: *mut c_char,
    size: usize,
    n: usize,
    stream: *mut c_void,
) -> usize {
    if stream.is_null() {
        return 0;
    }
    // SAFETY: `ptr` has room for `size * n` bytes, and the application
    // gave `stream` as a `FILE *`.
    unsafe { libc::fread(ptr.cast(), size, n, stream.cast()) }
}

/// The write function's verdict on what it was given (`cw_out_cb_write`).
fn write_verdict(wrote: usize) -> Write {
    if wrote == CURL_WRITEFUNC_PAUSE as usize {
        Write::Pause
    } else if wrote == CURL_WRITEFUNC_ERROR as usize {
        Write::Fail
    } else {
        Write::Took(wrote)
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
        write_verdict(wrote)
    }
}

/// The application's interleave function, which RTSP's RTP messages go
/// to (`rtp_client_write`).
pub(crate) struct Interleave(pub(crate) Adapter);

impl WriteHandler for Interleave {
    fn write(&self, cx: &mut TransferCx<'_>, message: &[u8]) -> Write {
        let c = self.0.easy().interleave();
        let Some(f) = c.function else {
            // Taken away as setopt runs from a callback: the adapter goes
            // with the next sync, as C reads the option at each message.
            return WriteHandler::write(&self.0, cx, message);
        };
        let wrote = self.0.call(cx, || {
            // SAFETY: the application's interleave function takes the
            // bytes, which it may not change, as its write function does.
            unsafe { f(message.as_ptr().cast_mut().cast(), 1, message.len(), c.data) }
        });
        write_verdict(wrote)
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
        write_verdict(wrote)
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

/// The longest host name and date an HSTS entry holds, and the room for
/// a NUL after each (`MAX_HSTS_HOSTLEN`, `MAX_HSTS_DATELEN`).
const HSTS_NAME: usize = curl_core::hsts::MAX_HOST_LEN;
const HSTS_DATE: usize = curl_core::hsts::MAX_DATE_LEN;

/// An entry with nothing in it.
fn empty_hsts_entry() -> ffi::curl_hstsentry {
    // SAFETY: every field of the entry, a pointer, a length, bits and
    // bytes, is valid as zeros.
    unsafe { core::mem::zeroed() }
}

impl curl_core::hsts::HstsReader for Adapter {
    /// One call of the read function, with an entry whose name and date
    /// the application fills in (`hsts_pull`).
    fn read(
        &self,
        keep: &mut dyn FnMut(
            curl_core::hsts::HstsEntry<'_>,
        ) -> Result<(), curl_core::hsts::BadEntry>,
    ) -> Result<curl_core::hsts::HstsRead, curl_core::hsts::BadEntry> {
        use curl_core::hsts::HstsRead;
        let c = self.easy().hsts();
        let Some(f) = c.read else {
            return Ok(HstsRead::Done);
        };
        let mut name = [0 as c_char; HSTS_NAME + 1];
        let mut e = empty_hsts_entry();
        e.name = name.as_mut_ptr();
        e.namelen = HSTS_NAME;
        // SAFETY: the application's read function fills in the entry it
        // is lent, its name in the room `namelen` says.
        let sc = unsafe { f(self.handle(), &mut e, c.read_data) };
        if sc == ffi::CURLSTS_FAIL {
            return Ok(HstsRead::Abort);
        }
        if sc != ffi::CURLSTS_OK {
            return Ok(HstsRead::Done);
        }
        // Read through the name it left, as C reads it.
        if e.name.is_null() {
            return Ok(HstsRead::Invalid);
        }
        // SAFETY: the name points to the room lent, or one the application
        // gave in its place of at least as much, as C's contract has it.
        let first = unsafe { *e.name };
        // SAFETY: as above: the room's last byte.
        let last = unsafe { *e.name.wrapping_add(HSTS_NAME) };
        if first == 0 || last != 0 || e.expire[HSTS_DATE] != 0 {
            return Ok(HstsRead::Invalid);
        }
        // SAFETY: as above: a NUL is at the end of the room, so this is a
        // C string within it.
        let name = unsafe { CStr::from_ptr(e.name) }.to_bytes();
        // SAFETY: the date's last byte is NUL, checked above.
        let expire = unsafe { CStr::from_ptr(e.expire.as_ptr()) }.to_bytes();
        keep(curl_core::hsts::HstsEntry {
            name,
            expire,
            subdomains: e.includeSubDomains(),
        })?;
        Ok(HstsRead::Given)
    }
}

impl curl_core::hsts::HstsWriter for Adapter {
    /// One call of the write function, with an entry, its place and the
    /// number of them (`hsts_push`).
    fn write(
        &self,
        entry: curl_core::hsts::HstsEntry<'_>,
        index: usize,
        total: usize,
    ) -> curl_core::hsts::HstsWrite {
        use curl_core::hsts::HstsWrite;
        let c = self.easy().hsts();
        let Some(f) = c.write else {
            return HstsWrite::Stop;
        };
        let mut name = [0 as c_char; HSTS_NAME + 1];
        let mut e = empty_hsts_entry();
        for (to, &b) in name.iter_mut().zip(entry.name) {
            *to = b as c_char;
        }
        for (to, &b) in e.expire.iter_mut().zip(entry.expire) {
            *to = b as c_char;
        }
        e.name = name.as_mut_ptr();
        e.namelen = entry.name.len();
        e.set_includeSubDomains(entry.subdomains);
        let mut i = ffi::curl_index { index, total };
        // SAFETY: the application's write function reads the entry and
        // the index it is lent.
        let sc = unsafe { f(self.handle(), &mut e, &mut i, c.write_data) };
        match sc {
            ffi::CURLSTS_OK => HstsWrite::More,
            ffi::CURLSTS_FAIL => HstsWrite::Fail,
            _ => HstsWrite::Stop,
        }
    }
}

impl TrailerHandler for Adapter {
    /// The lines of the list the trailer function builds, which is freed
    /// here whatever it answers (`add_last_chunk`).
    fn trailers(&self, cx: &mut TransferCx<'_>, lines: &mut TrailerLines) -> Trailers {
        let ccb = self.easy().ccb.get();
        let Some(f) = ccb.trailer else {
            return Trailers::Done;
        };
        let mut list: *mut ffi::curl_slist = ptr::null_mut();
        // SAFETY: the application's trailer function takes a list to
        // append to and its data.
        let answer = self.call(cx, || unsafe { f(&mut list, ccb.trailer_data) });
        let mut at = list;
        while let Some(node) = NonNull::new(at) {
            // SAFETY: a list `curl_slist_append` built, alive until freed
            // below.
            let node = unsafe { node.as_ref() };
            if !node.data.is_null() {
                // SAFETY: each item holds a C string.
                let line = unsafe { CStr::from_ptr(node.data) };
                if lines.add(line.to_bytes()).is_err() {
                    break;
                }
            }
            at = node.next;
        }
        // SAFETY: the list is the application's to hand over, made by
        // `curl_slist_append`, and not used again.
        unsafe { crate::strings::curl_slist_free_all(list) };
        if answer == ffi::CURL_TRAILERFUNC_OK {
            Trailers::Done
        } else {
            Trailers::Abort
        }
    }
}

impl SshKeyHandler for Adapter {
    /// The key function, given the known-hosts file's key and the
    /// server's as `struct curl_khkey`, each in base64 ended by a zero
    /// byte, its length the text's as C's libssh code gives it, how they
    /// compare and its data; an answer it has no name for rejects the
    /// key.
    fn check(
        &self,
        cx: &mut TransferCx<'_>,
        known: Option<HostKey<'_>>,
        found: HostKey<'_>,
        matched: KeyMatch,
    ) -> KeyVerdict {
        let ccb = self.easy().ccb.get();
        let Some(f) = ccb.ssh_key else {
            return KeyVerdict::Reject;
        };
        let (Ok(known_text), Ok(found_text)) = (
            known.map(|k| c_text(k.base64)).transpose(),
            c_text(found.base64),
        ) else {
            return KeyVerdict::Reject;
        };
        let khkey = |text: &[u8], kind| ffi::curl_khkey {
            key: text.as_ptr().cast(),
            // Without its zero byte (`strlen`).
            len: text.len() - 1,
            keytype: key_type(kind),
        };
        let known = known.map(|k| khkey(known_text.as_deref().unwrap_or_default(), k.kind));
        let found = khkey(&found_text, found.kind);
        let known_ptr = known.as_ref().map_or(ptr::null(), |k| k as *const _);
        let matched = match matched {
            KeyMatch::Ok => ffi::CURLKHMATCH_OK,
            KeyMatch::Mismatch => ffi::CURLKHMATCH_MISMATCH,
            KeyMatch::Missing => ffi::CURLKHMATCH_MISSING,
        };
        let handle = self.handle();
        // SAFETY: the application's key function takes the handle, the
        // two keys, alive through the call with their texts, how they
        // compare and its data.
        let answer = self.call(cx, || unsafe {
            f(handle, known_ptr, &found, matched, ccb.ssh_key_data)
        });
        match answer {
            a if a == ffi::CURLKHSTAT_FINE_ADD_TO_FILE.0 => KeyVerdict::FineAddToFile,
            a if a == ffi::CURLKHSTAT_FINE.0 => KeyVerdict::Fine,
            a if a == ffi::CURLKHSTAT_DEFER.0 => KeyVerdict::Defer,
            a if a == ffi::CURLKHSTAT_FINE_REPLACE.0 => KeyVerdict::FineReplace,
            _ => KeyVerdict::Reject,
        }
    }
}

/// `text` with a zero byte after it, for C.
fn c_text(text: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_reserve_exact(text.len() + 1)
        .map_err(|_| OutOfMemory)?;
    v.try_extend_from_slice(text)?;
    v.try_push(0)?;
    Ok(v)
}

/// A key's type as `enum curl_khtype` names it.
fn key_type(kind: curl_core::ssh::KeyType) -> ffi::curl_khtype {
    use curl_core::ssh::KeyType;
    match kind {
        KeyType::Rsa => ffi::CURLKHTYPE_RSA,
        KeyType::Rsa1 => ffi::CURLKHTYPE_RSA1,
        KeyType::Ecdsa => ffi::CURLKHTYPE_ECDSA,
        KeyType::Ed25519 => ffi::CURLKHTYPE_ED25519,
        KeyType::Dss => ffi::CURLKHTYPE_DSS,
        KeyType::Other => ffi::CURLKHTYPE_UNKNOWN,
    }
}

/// `text`'s bytes and a zero byte after them, at `at` in `buf`: where
/// they start, and `at` moved past them.
fn put_c_string(buf: &mut [u8], at: &mut usize, text: &[u8]) -> usize {
    let start = *at;
    let end = start + text.len();
    assert!(end < buf.len(), "a file's texts fit its line");
    buf[start..end].copy_from_slice(text);
    buf[end] = 0;
    *at = end + 1;
    start
}

impl ChunkBeginHandler for Adapter {
    /// The chunk begin function, given the file as `struct curl_fileinfo`
    /// with its texts each ended by a zero byte, and the chunk data
    /// (`CURLWC_DOWNLOADING`).
    fn begin(&self, cx: &mut TransferCx<'_>, file: &FileInfo<'_>, remains: usize) -> ChunkBegin {
        let c = self.easy().wildcard();
        let Some(f) = c.chunk_bgn else {
            return ChunkBegin::Get;
        };
        let mut texts = [0u8; FileInfo::MAX_TEXT];
        let mut at = 0;
        let fields = [
            Some(file.name),
            Some(file.time),
            file.perm_text,
            file.user,
            file.group,
            file.target,
        ]
        .map(|text| text.map(|text| put_c_string(&mut texts, &mut at, text)));
        // Each a pointer into the one buffer, filled.
        let base = texts.as_mut_ptr();
        let [filename, time, perm, user, group, target] =
            fields.map(|at| at.map_or(ptr::null_mut(), |at| base.wrapping_add(at).cast()));
        let strings = ffi::curl_fileinfo_strings {
            time,
            perm,
            user,
            group,
            target,
        };
        let known = |known: bool, flag: c_int| if known { flag } else { 0 };
        let flags = known(file.perm.is_some(), ffi::CURLFINFOFLAG_KNOWN_PERM)
            | known(file.size.is_some(), ffi::CURLFINFOFLAG_KNOWN_SIZE)
            | known(
                file.hardlinks.is_some(),
                ffi::CURLFINFOFLAG_KNOWN_HLINKCOUNT,
            );
        let info = ffi::curl_fileinfo {
            filename,
            filetype: match file.kind {
                FileType::File => ffi::CURLFILETYPE_FILE,
                FileType::Directory => ffi::CURLFILETYPE_DIRECTORY,
                FileType::Symlink => ffi::CURLFILETYPE_SYMLINK,
                FileType::DeviceBlock => ffi::CURLFILETYPE_DEVICE_BLOCK,
                FileType::DeviceChar => ffi::CURLFILETYPE_DEVICE_CHAR,
                FileType::NamedPipe => ffi::CURLFILETYPE_NAMEDPIPE,
                FileType::Socket => ffi::CURLFILETYPE_SOCKET,
                FileType::Door => ffi::CURLFILETYPE_DOOR,
            },
            time: 0,
            perm: file.perm.unwrap_or(0),
            uid: 0,
            gid: 0,
            // A size is never more than C's `curl_off_t` holds: the
            // listing's reader reads none bigger.
            size: file
                .size
                .map_or(0, |s| s.try_into().expect("read as an off_t")),
            hardlinks: file.hardlinks.unwrap_or(0),
            strings,
            flags: flags.cast_unsigned(),
            b_data: ptr::null_mut(),
            b_size: 0,
            b_used: 0,
        };
        let remains = c_int::try_from(remains).unwrap_or(c_int::MAX);
        // SAFETY: the application's chunk begin function takes the file's
        // information, alive and unchanged for the call, the chunk data
        // and the count.
        let answer = self.call(cx, || unsafe {
            f(ptr::from_ref(&info).cast(), c.chunk_data, remains)
        });
        match c_int::try_from(answer) {
            Ok(ffi::CURL_CHUNK_BGN_FUNC_SKIP) => ChunkBegin::Skip,
            Ok(ffi::CURL_CHUNK_BGN_FUNC_FAIL) => ChunkBegin::Fail,
            // Any other answer gets the file, as C's switch does.
            _ => ChunkBegin::Get,
        }
    }
}

impl ChunkEndHandler for Adapter {
    /// The chunk end function, given the chunk data; its answer is not
    /// read, as C reads none.
    fn end(&self, cx: &mut TransferCx<'_>) {
        let c = self.easy().wildcard();
        if let Some(f) = c.chunk_end {
            // SAFETY: the application's chunk end function takes its data.
            self.call(cx, || unsafe { f(c.chunk_data) });
        }
    }
}

impl FnMatchHandler for Adapter {
    /// The fnmatch function, given its data, the pattern and the name,
    /// each ended by a zero byte; 0 is a match
    /// (`CURL_FNMATCHFUNC_MATCH`), any other answer none.
    fn matches(
        &self,
        cx: &mut TransferCx<'_>,
        pattern: &[u8],
        name: &[u8],
    ) -> Result<Matched, OutOfMemory> {
        let c = self.easy().wildcard();
        let Some(f) = c.fnmatch else {
            return Ok(Matched::NoMatch);
        };
        // The name is a part of a line of the listing, which the stack
        // holds; a pattern too long for it is copied to memory of its own.
        let mut names = [0u8; FileInfo::MAX_TEXT];
        put_c_string(&mut names, &mut 0, name);
        let name = names.as_ptr().cast();
        let mut short = [0u8; 256];
        let mut long = Vec::new();
        let pattern = if pattern.len() < short.len() {
            put_c_string(&mut short, &mut 0, pattern);
            short.as_ptr().cast()
        } else {
            long.try_reserve_exact(pattern.len() + 1)
                .map_err(|_| OutOfMemory)?;
            long.try_extend_from_slice(pattern)?;
            long.try_push(0)?;
            long.as_ptr().cast()
        };
        // SAFETY: the application's fnmatch function takes its data and
        // two zero-ended strings, alive for the call.
        let answer = self.call(cx, || unsafe { f(c.fnmatch_data, pattern, name) });
        Ok(match answer {
            ffi::CURL_FNMATCHFUNC_MATCH => Matched::Match,
            ffi::CURL_FNMATCHFUNC_FAIL => Matched::Fail,
            _ => Matched::NoMatch,
        })
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

    /// The seek function, to `offset` from the start: `CURL_SEEKFUNC_OK`
    /// moved it, `CURL_SEEKFUNC_CANTSEEK` and no seek function have the
    /// bytes before read and dropped, and any other answer fails the
    /// upload. C sends from where the stream is when there is no seek
    /// function, the wrong bytes; here they are passed over by reading,
    /// as its documentation says they are (DIVERGENCE.md).
    fn seek(&self, cx: &mut TransferCx<'_>, offset: u64) -> Result<(), SeekFailed> {
        let ccb = self.easy().ccb.get();
        let Some(seek) = ccb.seek else {
            return Err(SeekFailed::CantSeek);
        };
        let offset = ffi::curl_off_t::try_from(offset).expect("an offset the application gave");
        // SAFETY: the application's seek function takes its data.
        let err = self.call(cx, || unsafe {
            seek(ccb.seek_data, offset, libc::SEEK_SET)
        });
        match err {
            CURL_SEEKFUNC_OK => Ok(()),
            ffi::CURL_SEEKFUNC_CANTSEEK => Err(SeekFailed::CantSeek),
            _ => Err(SeekFailed::Fail),
        }
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

/// A line of text the handle traces outside a transfer, where no
/// `TransferCx` reaches its debug handler (`infof` from setopt): to the
/// debug function, or without one to the standard error stream after
/// `* `, as `Curl_debug` sends it. Called with nothing of the handle
/// borrowed, so the function may call back into it.
pub(crate) fn trace_text(easy: &ShimEasy, line: &[u8]) {
    trace_as(easy, DebugKind::Text, line);
}

/// A line a verbose handle is told, outside a transfer (`infof`).
pub(crate) fn info(easy: &ShimEasy, line: &[u8]) {
    if easy.with_options(|o| o.output.verbose).unwrap_or(false) {
        trace_text(easy, line);
    }
}

/// `trace_text`, of any kind: only text goes to the standard error stream.
fn trace_as(easy: &ShimEasy, kind: DebugKind, bytes: &[u8]) {
    let ccb = easy.ccb.get();
    match ccb.debug {
        // SAFETY: the application's debug function takes the bytes,
        // which it may not change, as C's does; its answer is ignored,
        // as C ignores it.
        Some(f) => unsafe {
            f(
                ptr::from_ref(easy).cast_mut().cast(),
                infotype(kind),
                bytes.as_ptr().cast_mut().cast(),
                bytes.len(),
                ccb.debug_data,
            );
        },
        None if kind == DebugKind::Text => {
            to_stream(ccb.stderr, b"* ");
            to_stream(ccb.stderr, bytes);
        }
        None => {}
    }
}

/// What a call on the connection a transfer left traced, held until nothing
/// of the handle is borrowed: its debug function may call back into it, as
/// C's may. A piece there is no memory to hold is not said, as a line too
/// long for the trace is cut. Held on the stack, as a call's lines usually
/// fit and C's trace allocates nothing; those past it are kept apart.
pub(crate) struct Held {
    bytes: [u8; Held::BYTES],
    used: usize,
    lines: [(DebugKind, usize); Held::LINES],
    count: usize,
    more: Vec<(DebugKind, Vec<u8>)>,
}

impl Default for Held {
    fn default() -> Self {
        Held {
            bytes: [0; Held::BYTES],
            used: 0,
            lines: [(DebugKind::Text, 0); Held::LINES],
            count: 0,
            more: Vec::new(),
        }
    }
}

impl Held {
    const BYTES: usize = 2048;
    const LINES: usize = 16;

    pub(crate) fn note(&mut self, kind: DebugKind, bytes: &[u8]) {
        use curl_alloc::TryVec as _;
        let room = &mut self.bytes[self.used..];
        if self.more.is_empty() && self.count < Held::LINES && bytes.len() <= room.len() {
            room[..bytes.len()].copy_from_slice(bytes);
            self.used += bytes.len();
            self.lines[self.count] = (kind, bytes.len());
            self.count += 1;
            return;
        }
        let mut copy = Vec::new();
        if copy.try_extend_from_slice(bytes).is_ok() {
            let _not_said = self.more.try_push((kind, copy));
        }
    }

    /// Each piece held, in the order it was traced.
    fn pieces(&self) -> impl Iterator<Item = (DebugKind, &[u8])> {
        let mut left = &self.bytes[..self.used];
        let held = self.lines[..self.count].iter().map(move |&(kind, len)| {
            let (piece, rest) = left.split_at(len);
            left = rest;
            (kind, piece)
        });
        held.chain(self.more.iter().map(|(kind, b)| (*kind, &b[..])))
    }

    /// Say what is held, in the order it was traced, until the debug
    /// function turns the handle's verbose off: C asks before each line.
    pub(crate) fn say(self, easy: &ShimEasy) {
        for (kind, bytes) in self.pieces() {
            if !easy.with_options(|o| o.output.verbose).unwrap_or(true) {
                return;
            }
            trace_as(easy, kind, bytes);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Pieces held keep their order, past what the stack holds too.
    #[test]
    fn held_pieces_keep_their_order() {
        let mut held = Held::default();
        let big = vec![b'b'; Held::BYTES];
        let lines: Vec<Vec<u8>> = (0..Held::LINES + 2)
            .map(|i| vec![b'a' + u8::try_from(i).unwrap()])
            .chain([big.clone(), b"last".to_vec()])
            .collect();
        for line in &lines {
            held.note(DebugKind::HeaderIn, line);
        }
        let said: Vec<&[u8]> = held.pieces().map(|(_, b)| b).collect();
        let want: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
        assert_eq!(said, want);
    }

    /// A few short pieces are held where the trace is, without an
    /// allocation each.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn short_pieces_are_held_without_allocating() {
        let mut held = Held::default();
        let (_, made) = curl_alloc::track::measure(|| {
            for line in [&b"a"[..], b"bb", b"ccc"] {
                held.note(DebugKind::HeaderIn, line);
            }
        });
        assert_eq!(made.allocations, 0);
        assert_eq!(held.pieces().count(), 3);
    }

    /// Without a debug function only text goes to the standard error
    /// stream, after `* `; headers and data go nowhere.
    #[test]
    fn only_text_goes_to_the_error_stream() {
        let c = crate::easy::curl_easy_init();
        // SAFETY: a stream of the C library's, closed below.
        let stream = unsafe { libc::tmpfile() };
        assert!(!stream.is_null());
        // SAFETY: a live handle, and a stream that outlives it.
        let set = unsafe { crate::setopt::curl_easy_setopt(c, crate::ffi::CURLOPT_STDERR, stream) };
        assert_eq!(set, crate::ffi::CURLE_OK);
        // SAFETY: a live handle.
        let easy = unsafe { crate::easy::handle(c) }.unwrap();
        trace_as(easy, DebugKind::HeaderIn, b"head");
        trace_as(easy, DebugKind::Text, b"text");
        let mut got = [0u8; 32];
        // SAFETY: the stream made above.
        unsafe { libc::rewind(stream) };
        // SAFETY: the same stream, read into a buffer of the length given.
        let n = unsafe { libc::fread(got.as_mut_ptr().cast(), 1, got.len(), stream) };
        assert_eq!(&got[..n], b"* text");
        // SAFETY: a live handle, not used again.
        unsafe { crate::easy::curl_easy_cleanup(c) };
        // SAFETY: the stream made above, no longer the handle's.
        unsafe { libc::fclose(stream) };
    }

    /// The application's fields are lent from where a read is, as many
    /// as fit, and no further than their end.
    #[test]
    fn lent_fields_are_copied_from_an_offset_to_their_end() {
        let fields = *b"abcdef";
        let lent = AppFields {
            at: NonNull::from(&fields).cast(),
            len: fields.len(),
        };
        let mut buf = [0u8; 10];
        assert_eq!(lent.copy_at(4, &mut buf), 2);
        assert_eq!(&buf[..2], b"ef");
        assert_eq!(lent.copy_at(1, &mut buf[..3]), 3);
        assert_eq!(&buf[..3], b"bcd");
    }
}
