//! The handles through the C ABI, as a C program calls them: each option
//! as setopt.c checks it, each info against the report it comes from, and
//! each callback adapter against what C does with the function's answer.

#![allow(unsafe_code)]
#![allow(
    clippy::multiple_unsafe_ops_per_block,
    reason = "one contract covers each test's sequence of calls"
)]

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use core::ptr;
use std::time::Duration;

use curl_core::conn::io::Events;
use curl_core::multi::NotifyKind;
use curl_core::options::script::{Piece, Script};
use curl_core::options::{Method, Options, Progress, Resume, UploadSource};
use curl_core::report::TransferReport;

use crate::callbacks::aborts;
use crate::easy::{self, curl_easy_cleanup, curl_easy_init, curl_easy_pause, curl_easy_perform};
use crate::ffi::{
    self, CURL, CURLE_ABORTED_BY_CALLBACK, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_NOT_BUILT_IN,
    CURLE_OK, CURLE_RECURSIVE_API_CALL, CURLE_UNKNOWN_OPTION, CURLINFO, CURLM, CURLM_OK, CURLcode,
    CURLoption, curl_off_t,
};
use crate::getinfo::curl_easy_getinfo;
use crate::multi::{
    curl_multi_add_handle, curl_multi_cleanup, curl_multi_get_offt, curl_multi_info_read,
    curl_multi_init, curl_multi_notify_disable, curl_multi_notify_enable, curl_multi_perform,
    curl_multi_remove_handle, curl_multi_setopt, curl_multi_wait, notify_kind, running,
    wait_events, wait_revents,
};
use crate::setopt::curl_easy_setopt;

type WriteFn = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

fn long(c: *mut CURL, o: CURLoption, v: c_long) -> CURLcode {
    // SAFETY: a live handle and a `long` option, as each caller passes.
    unsafe { curl_easy_setopt(c, o, v) }
}

fn off(c: *mut CURL, o: CURLoption, v: curl_off_t) -> CURLcode {
    // SAFETY: a live handle and an offset option.
    unsafe { curl_easy_setopt(c, o, v) }
}

fn pointer<T>(c: *mut CURL, o: CURLoption, v: *mut T) -> CURLcode {
    // SAFETY: a live handle and a pointer option, whose target outlives
    // the handle's use of it.
    unsafe { curl_easy_setopt(c, o, v.cast::<c_void>()) }
}

/// A function option; `f` is a function of the option's type, or NULL.
fn function(c: *mut CURL, o: CURLoption, f: *const ()) -> CURLcode {
    // SAFETY: a live handle and a function option.
    unsafe { curl_easy_setopt(c, o, f.cast_mut().cast::<c_void>()) }
}

fn options<R>(c: *mut CURL, f: impl FnOnce(&mut Options) -> R) -> R {
    // SAFETY: a live handle.
    let easy = unsafe { easy::handle(c) }.expect("a live handle");
    easy.with_options(f).expect("reachable")
}

fn report<R>(c: *mut CURL, f: impl FnOnce(&TransferReport) -> R) -> R {
    // SAFETY: a live handle.
    let easy = unsafe { easy::handle(c) }.expect("a live handle");
    easy.with_report(f).expect("reachable")
}

fn ccb(c: *mut CURL) -> crate::callbacks::CCallbacks {
    // SAFETY: a live handle.
    unsafe { easy::handle(c) }.expect("a live handle").ccb.get()
}

fn info<T: Default>(c: *mut CURL, i: CURLINFO) -> T {
    let mut v = T::default();
    assert_eq!(
        // SAFETY: a live handle, and a value of the info's type.
        unsafe { curl_easy_getinfo(c, i, &raw mut v) },
        CURLE_OK,
        "{}",
        i.0
    );
    v
}

/// A file of `body`, named by `tag`, and its URL.
fn file(tag: &str, body: &[u8]) -> (std::path::PathBuf, std::ffi::CString) {
    let path = std::env::temp_dir().join(format!("curl-shim-{}-{tag}", std::process::id()));
    std::fs::write(&path, body).unwrap();
    let url = std::ffi::CString::new(format!("file://{}", path.display())).unwrap();
    (path, url)
}

unsafe extern "C" fn sink(_: *mut c_char, size: usize, n: usize, _: *mut c_void) -> usize {
    size * n
}

/// What a C stream got, read back from its start.
fn stream_text(f: *mut libc::FILE) -> String {
    let mut out = Vec::new();
    // SAFETY: a stream from `tmpfile`, open.
    unsafe {
        libc::fflush(f);
        libc::rewind(f);
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::fread(buf.as_mut_ptr().cast(), 1, buf.len(), f);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
    String::from_utf8(out).unwrap()
}

fn tmpfile() -> *mut libc::FILE {
    // SAFETY: no precondition.
    let f = unsafe { libc::tmpfile() };
    assert!(!f.is_null());
    f
}

fn close(f: *mut libc::FILE) {
    // SAFETY: a stream from `tmpfile`, not used again.
    unsafe { libc::fclose(f) };
}

#[test]
fn boolean_options_take_any_nonzero_value() {
    let c = curl_easy_init();
    for (o, get) in [
        (
            ffi::CURLOPT_VERBOSE,
            (|o: &mut Options| o.output.verbose) as fn(&mut Options) -> bool,
        ),
        (ffi::CURLOPT_HEADER, |o| o.output.include_header),
        (ffi::CURLOPT_PATH_AS_IS, |o| o.url_rules.path_as_is),
        (ffi::CURLOPT_DISALLOW_USERNAME_IN_URL, |o| {
            o.url_rules.disallow_user
        }),
    ] {
        for (v, on) in [(1, true), (0, false), (2, true), (-1, true), (0, false)] {
            assert_eq!(long(c, o, v), CURLE_OK);
            assert_eq!(options(c, get), on, "{} = {v}", o.0);
        }
    }
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

#[test]
fn the_method_follows_nobody_and_upload_as_in_c() {
    let c = curl_easy_init();
    let method = |c| options(c, |o| o.method);
    let reads = |c| {
        options(c, |o| match &o.upload {
            UploadSource::Read { size, .. } => Some(*size),
            _ => None,
        })
    };
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 1), CURLE_OK);
    assert_eq!(method(c), Method::Head);
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 0), CURLE_OK);
    assert_eq!(method(c), Method::Get);
    assert_eq!(reads(c), None);
    assert_eq!(long(c, ffi::CURLOPT_UPLOAD, 1), CURLE_OK);
    assert_eq!((method(c), reads(c)), (Method::Upload, Some(None)));
    // No body is not a head once uploading.
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 0), CURLE_OK);
    assert_eq!(method(c), Method::Upload);
    assert_eq!(long(c, ffi::CURLOPT_INFILESIZE, 5), CURLE_OK);
    assert_eq!(reads(c), Some(Some(5)));
    assert_eq!(off(c, ffi::CURLOPT_INFILESIZE_LARGE, 7), CURLE_OK);
    assert_eq!(reads(c), Some(Some(7)));
    for bad in [-2, c_long::MIN] {
        assert_eq!(
            long(c, ffi::CURLOPT_INFILESIZE, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(
            off(c, ffi::CURLOPT_INFILESIZE_LARGE, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    assert_eq!(reads(c), Some(Some(7)), "a refused size changes nothing");
    assert_eq!(long(c, ffi::CURLOPT_INFILESIZE, -1), CURLE_OK);
    assert_eq!(reads(c), Some(None));
    assert_eq!(long(c, ffi::CURLOPT_INFILESIZE, 0), CURLE_OK);
    assert_eq!(reads(c), Some(Some(0)));
    assert_eq!(long(c, ffi::CURLOPT_UPLOAD, 0), CURLE_OK);
    assert_eq!((method(c), reads(c)), (Method::Get, None));
    assert_eq!(long(c, ffi::CURLOPT_PUT, 1), CURLE_OK);
    assert_eq!(method(c), Method::Upload);
    assert_eq!(long(c, ffi::CURLOPT_NOBODY, 1), CURLE_OK);
    assert_eq!((method(c), reads(c)), (Method::Head, None));
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

#[test]
fn limits_are_checked_as_in_c() {
    let c = curl_easy_init();
    let total = |c| options(c, |o| o.limits.total.map(|t| t.duration()));
    let connect = |c| options(c, |o| o.limits.connect.map(|t| t.duration()));
    let ms = Duration::from_millis;
    for (o, get, unit) in [
        (
            ffi::CURLOPT_TIMEOUT,
            total as fn(*mut CURL) -> Option<Duration>,
            1000,
        ),
        (ffi::CURLOPT_TIMEOUT_MS, total, 1),
        (ffi::CURLOPT_CONNECTTIMEOUT, connect, 1000),
        (ffi::CURLOPT_CONNECTTIMEOUT_MS, connect, 1),
    ] {
        assert_eq!(long(c, o, 3), CURLE_OK);
        assert_eq!(get(c), Some(ms(3 * unit)), "{}", o.0);
        assert_eq!(long(c, o, -1), CURLE_BAD_FUNCTION_ARGUMENT);
        assert_eq!(get(c), Some(ms(3 * unit)));
        assert_eq!(long(c, o, 0), CURLE_OK);
        assert_eq!(get(c), None);
    }
    let low = |c| {
        options(c, |o| {
            o.limits.low_speed.map(|l| (l.limit.get(), l.time.get()))
        })
    };
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_LIMIT, 10), CURLE_OK);
    assert_eq!(low(c), None, "no time yet");
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_TIME, 3), CURLE_OK);
    assert_eq!(low(c), Some((10, 3)));
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_TIME, 70000), CURLE_OK);
    assert_eq!(low(c), Some((10, 65535)), "C clamps to USHRT_MAX");
    assert_eq!(
        long(c, ffi::CURLOPT_LOW_SPEED_TIME, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_TIME, 0), CURLE_OK);
    assert_eq!(low(c), None, "no time");
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_TIME, 70000), CURLE_OK);
    assert_eq!(
        long(c, ffi::CURLOPT_LOW_SPEED_LIMIT, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(low(c), Some((10, 65535)));
    assert_eq!(long(c, ffi::CURLOPT_LOW_SPEED_LIMIT, 0), CURLE_OK);
    assert_eq!(low(c), None);
    let max = |c| options(c, |o| o.limits.max_filesize.map(|m| m.get()));
    assert_eq!(long(c, ffi::CURLOPT_MAXFILESIZE, 7), CURLE_OK);
    assert_eq!(max(c), Some(7));
    assert_eq!(
        long(c, ffi::CURLOPT_MAXFILESIZE, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        off(c, ffi::CURLOPT_MAXFILESIZE_LARGE, -1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(max(c), Some(7));
    assert_eq!(off(c, ffi::CURLOPT_MAXFILESIZE_LARGE, 1 << 40), CURLE_OK);
    assert_eq!(max(c), Some(1 << 40));
    assert_eq!(long(c, ffi::CURLOPT_MAXFILESIZE, 0), CURLE_OK);
    assert_eq!(max(c), None);
    let resume = |c| options(c, |o| o.resume);
    assert_eq!(long(c, ffi::CURLOPT_RESUME_FROM, 9), CURLE_OK);
    assert_eq!(resume(c), Some(Resume::At(9.try_into().unwrap())));
    assert_eq!(long(c, ffi::CURLOPT_RESUME_FROM, -1), CURLE_OK);
    assert_eq!(resume(c), Some(Resume::AtEnd));
    assert_eq!(
        long(c, ffi::CURLOPT_RESUME_FROM, -2),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(
        off(c, ffi::CURLOPT_RESUME_FROM_LARGE, -2),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    assert_eq!(resume(c), Some(Resume::AtEnd));
    assert_eq!(off(c, ffi::CURLOPT_RESUME_FROM_LARGE, 1 << 40), CURLE_OK);
    assert_eq!(
        resume(c),
        Some(Resume::At((1u64 << 40).try_into().unwrap()))
    );
    assert_eq!(long(c, ffi::CURLOPT_RESUME_FROM, 0), CURLE_OK);
    assert_eq!(resume(c), None);
    let mode = |c| options(c, |o| o.new_file_mode.bits());
    assert_eq!(long(c, ffi::CURLOPT_NEW_FILE_PERMS, 0o600), CURLE_OK);
    assert_eq!(mode(c), 0o600);
    for bad in [0o1000, -1] {
        assert_eq!(
            long(c, ffi::CURLOPT_NEW_FILE_PERMS, bad),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    assert_eq!(mode(c), 0o600);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

#[test]
fn strings_are_copied_and_bounded() {
    let c = curl_easy_init();
    let url = c"file:///x";
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(
        options(c, |o| o.url().map(<[u8]>::to_vec)),
        Some(b"file:///x".to_vec())
    );
    let scheme = c"file";
    assert_eq!(
        pointer(c, ffi::CURLOPT_DEFAULT_PROTOCOL, scheme.as_ptr().cast_mut()),
        CURLE_OK
    );
    assert_eq!(
        options(c, |o| o.default_protocol().map(<[u8]>::to_vec)),
        Some(b"file".to_vec())
    );
    let mut long_one = vec![b'a'; 8_000_001];
    long_one.push(0);
    for o in [ffi::CURLOPT_URL, ffi::CURLOPT_DEFAULT_PROTOCOL] {
        assert_eq!(
            pointer(c, o, long_one.as_mut_ptr()),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    long_one[8_000_000] = 0;
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, long_one.as_mut_ptr()),
        CURLE_OK,
        "the longest C takes"
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_DEFAULT_PROTOCOL, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    assert_eq!(
        options(c, |o| (o.url().is_none(), o.default_protocol().is_none())),
        (true, true)
    );
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

#[test]
fn callback_options_install_their_adapters() {
    let c = curl_easy_init();
    let installed = |c| {
        options(c, |o| {
            let cb = &o.callbacks;
            (
                cb.header.is_some(),
                cb.debug.is_some(),
                cb.stderr.is_some(),
                cb.failure.is_some(),
            )
        })
    };
    assert_eq!(
        installed(c),
        (false, false, false, false),
        "a new handle needs none"
    );
    let f = sink as WriteFn as *const ();
    let mut data = 0u8;
    assert_eq!(function(c, ffi::CURLOPT_HEADERFUNCTION, f), CURLE_OK);
    assert!(installed(c).0);
    assert_eq!(
        function(c, ffi::CURLOPT_HEADERFUNCTION, ptr::null()),
        CURLE_OK
    );
    assert!(!installed(c).0);
    assert_eq!(pointer(c, ffi::CURLOPT_HEADERDATA, &raw mut data), CURLE_OK);
    assert!(
        installed(c).0,
        "header data alone sends headers to the write function"
    );
    assert_eq!(
        pointer(c, ffi::CURLOPT_HEADERDATA, ptr::null_mut::<u8>()),
        CURLE_OK
    );
    assert!(!installed(c).0);
    let d = debug_count as DebugFn as *const ();
    assert_eq!(function(c, ffi::CURLOPT_DEBUGFUNCTION, d), CURLE_OK);
    assert!(installed(c).1);
    assert_eq!(
        function(c, ffi::CURLOPT_DEBUGFUNCTION, ptr::null()),
        CURLE_OK
    );
    assert!(!installed(c).1);
    let stream = tmpfile();
    assert_eq!(pointer(c, ffi::CURLOPT_STDERR, stream), CURLE_OK);
    assert!(installed(c).2);
    assert_eq!(
        pointer(c, ffi::CURLOPT_STDERR, ptr::null_mut::<libc::FILE>()),
        CURLE_OK
    );
    assert!(!installed(c).2, "NULL is standard error again");
    assert_eq!(ccb(c).stderr, crate::callbacks::standard().2);
    let mut buf = [0 as c_char; 256];
    assert_eq!(
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr()),
        CURLE_OK
    );
    assert!(installed(c).3);
    assert_eq!(
        pointer(c, ffi::CURLOPT_ERRORBUFFER, ptr::null_mut::<c_char>()),
        CURLE_OK
    );
    assert!(!installed(c).3);
    let progress = |c| {
        options(c, |o| match o.progress {
            Progress::Off => 0,
            Progress::Meter => 1,
            Progress::Handler(_) => 2,
        })
    };
    assert_eq!(progress(c), 0);
    assert_eq!(long(c, ffi::CURLOPT_NOPROGRESS, 0), CURLE_OK);
    assert_eq!(progress(c), 1);
    let x = xferinfo as XferFn as *const ();
    assert_eq!(function(c, ffi::CURLOPT_XFERINFOFUNCTION, x), CURLE_OK);
    assert_eq!(progress(c), 2);
    assert_eq!(
        function(c, ffi::CURLOPT_XFERINFOFUNCTION, ptr::null()),
        CURLE_OK
    );
    assert_eq!(progress(c), 1);
    let p = old_progress as ProgressFn as *const ();
    assert_eq!(function(c, ffi::CURLOPT_PROGRESSFUNCTION, p), CURLE_OK);
    assert_eq!(progress(c), 2);
    assert_eq!(long(c, ffi::CURLOPT_NOPROGRESS, 1), CURLE_OK);
    assert_eq!(progress(c), 0);
    // The data options and the rest of the functions are kept for the
    // adapters.
    let mut d2 = 0u8;
    let at = (&raw mut d2).cast::<c_void>();
    for o in [
        ffi::CURLOPT_WRITEDATA,
        ffi::CURLOPT_READDATA,
        ffi::CURLOPT_SEEKDATA,
        ffi::CURLOPT_IOCTLDATA,
        ffi::CURLOPT_XFERINFODATA,
        ffi::CURLOPT_DEBUGDATA,
        ffi::CURLOPT_PRIVATE,
    ] {
        assert_eq!(pointer(c, o, at), CURLE_OK);
    }
    let k = ccb(c);
    assert_eq!(
        [
            k.write_data,
            k.read_data,
            k.seek_data,
            k.ioctl_data,
            k.progress_data,
            k.debug_data
        ],
        [at; 6]
    );
    assert_eq!(info::<*mut c_char>(c, ffi::CURLINFO_PRIVATE).cast(), at);
    for o in [
        ffi::CURLOPT_WRITEFUNCTION,
        ffi::CURLOPT_READFUNCTION,
        ffi::CURLOPT_SEEKFUNCTION,
        ffi::CURLOPT_IOCTLFUNCTION,
    ] {
        assert_eq!(function(c, o, f), CURLE_OK);
    }
    let k = ccb(c);
    assert!(k.write.is_some() && k.read.is_some() && k.seek.is_some() && k.ioctl.is_some());
    close(stream);
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

#[test]
fn ids_are_told_apart_as_c_tells_them() {
    let c = curl_easy_init();
    assert_eq!(long(c, ffi::CURLOPT_PORT, 80), CURLE_NOT_BUILT_IN);
    for unknown in [9999, 10999, 50000] {
        assert_eq!(
            long(c, CURLoption(unknown), 0),
            CURLE_UNKNOWN_OPTION,
            "{unknown}"
        );
    }
    assert_eq!(
        long(ptr::null_mut(), ffi::CURLOPT_VERBOSE, 1),
        CURLE_BAD_FUNCTION_ARGUMENT
    );
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// Every info a file transfer answers, against the report it reads.
#[test]
fn infos_answer_from_the_report() {
    let (path, url) = file("infos", b"hello");
    let c = curl_easy_init();
    // Not run yet: no time is known.
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_FILETIME), -1);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_FILETIME_T), -1);
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    let secs = |d: Duration| d.as_micros() as f64 / 1e6;
    let us = |d: Duration| d.as_micros() as curl_off_t;
    let (times, sizes, speeds, filetime) = report(c, |r| {
        let t = r.timings();
        (
            [
                t.total(),
                t.namelookup(),
                t.connect(),
                t.appconnect(),
                t.pretransfer(),
                t.starttransfer(),
                t.redirect(),
                t.posttransfer(),
                t.queue(),
            ],
            (
                r.sizes().download(),
                r.sizes().delivered(),
                r.sizes().upload(),
            ),
            (r.speeds().download(), r.speeds().upload()),
            r.filetime().expect("a file has one"),
        )
    });
    for (i, t) in [
        ffi::CURLINFO_TOTAL_TIME,
        ffi::CURLINFO_NAMELOOKUP_TIME,
        ffi::CURLINFO_CONNECT_TIME,
        ffi::CURLINFO_APPCONNECT_TIME,
        ffi::CURLINFO_PRETRANSFER_TIME,
        ffi::CURLINFO_STARTTRANSFER_TIME,
        ffi::CURLINFO_REDIRECT_TIME,
    ]
    .into_iter()
    .zip(times)
    {
        assert_eq!(info::<f64>(c, i), secs(t), "{}", i.0);
    }
    for (i, t) in [
        ffi::CURLINFO_TOTAL_TIME_T,
        ffi::CURLINFO_NAMELOOKUP_TIME_T,
        ffi::CURLINFO_CONNECT_TIME_T,
        ffi::CURLINFO_APPCONNECT_TIME_T,
        ffi::CURLINFO_PRETRANSFER_TIME_T,
        ffi::CURLINFO_STARTTRANSFER_TIME_T,
        ffi::CURLINFO_REDIRECT_TIME_T,
        ffi::CURLINFO_POSTTRANSFER_TIME_T,
        ffi::CURLINFO_QUEUE_TIME_T,
    ]
    .into_iter()
    .zip(times)
    {
        assert_eq!(info::<curl_off_t>(c, i), us(t), "{}", i.0);
    }
    assert_eq!(sizes, (5, 5, 0));
    assert_eq!(info::<f64>(c, ffi::CURLINFO_SIZE_DOWNLOAD), 5.0);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_SIZE_DOWNLOAD_T), 5);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_SIZE_DELIVERED), 5);
    assert_eq!(info::<f64>(c, ffi::CURLINFO_SIZE_UPLOAD), 0.0);
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_SIZE_UPLOAD_T), 0);
    assert_eq!(
        info::<f64>(c, ffi::CURLINFO_SPEED_DOWNLOAD),
        speeds.0 as f64
    );
    assert_eq!(
        info::<curl_off_t>(c, ffi::CURLINFO_SPEED_DOWNLOAD_T),
        speeds.0 as curl_off_t
    );
    assert_eq!(info::<f64>(c, ffi::CURLINFO_SPEED_UPLOAD), speeds.1 as f64);
    assert_eq!(
        info::<curl_off_t>(c, ffi::CURLINFO_SPEED_UPLOAD_T),
        speeds.1 as curl_off_t
    );
    assert_eq!(info::<f64>(c, ffi::CURLINFO_CONTENT_LENGTH_DOWNLOAD), 5.0);
    assert_eq!(
        info::<curl_off_t>(c, ffi::CURLINFO_CONTENT_LENGTH_DOWNLOAD_T),
        5
    );
    assert_eq!(info::<f64>(c, ffi::CURLINFO_CONTENT_LENGTH_UPLOAD), -1.0);
    assert_eq!(
        info::<curl_off_t>(c, ffi::CURLINFO_CONTENT_LENGTH_UPLOAD_T),
        -1
    );
    assert_eq!(
        info::<c_long>(c, ffi::CURLINFO_FILETIME),
        filetime as c_long
    );
    assert_eq!(info::<curl_off_t>(c, ffi::CURLINFO_FILETIME_T), filetime);
    assert!(filetime > 1_000_000_000, "{filetime}");
    assert_eq!(
        info::<c_long>(c, ffi::CURLINFO_PROTOCOL),
        ffi::CURLPROTO_FILE
    );
    assert_eq!(info::<c_long>(c, ffi::CURLINFO_RESPONSE_CODE), 0);
    // An info not answered yet, and one of no type.
    let mut v: c_long = 0;
    // SAFETY: a live handle and a `long` to write.
    unsafe {
        assert_eq!(
            curl_easy_getinfo(c, ffi::CURLINFO_EFFECTIVE_URL, &raw mut v),
            CURLE_UNKNOWN_OPTION
        );
        assert_eq!(
            curl_easy_getinfo(c, CURLINFO(5), &raw mut v),
            CURLE_UNKNOWN_OPTION
        );
        let null = ptr::null_mut::<c_long>();
        assert_eq!(
            curl_easy_getinfo(c, ffi::CURLINFO_RESPONSE_CODE, null),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(
            curl_easy_getinfo(ptr::null_mut(), ffi::CURLINFO_RESPONSE_CODE, &raw mut v),
            CURLE_BAD_FUNCTION_ARGUMENT
        );
    }
    std::fs::remove_file(path).unwrap();
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(c) };
}

/// Feeds `left` to the read function.
struct Feed {
    left: Vec<u8>,
    answer: Option<usize>,
}

unsafe extern "C" fn read(buf: *mut c_char, size: usize, n: usize, data: *mut c_void) -> usize {
    // SAFETY: the test passes a `Feed` and the shim room for `size * n`.
    let feed = unsafe { &mut *data.cast::<Feed>() };
    if let Some(a) = feed.answer {
        return a;
    }
    let k = feed.left.len().min(size * n);
    // SAFETY: as above.
    unsafe { ptr::copy_nonoverlapping(feed.left.as_ptr(), buf.cast(), k) };
    feed.left.drain(..k);
    k
}

type ReadFn = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

/// The read function's body is stored, and its abort and pause answers
/// end the upload as file:// ends it.
#[test]
fn the_read_function_feeds_an_upload() {
    let (path, url) = file("upload", b"");
    let run = |answer: Option<usize>| {
        let mut feed = Feed {
            left: b"abc".to_vec(),
            answer,
        };
        let mut buf = [0 as c_char; 256];
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        long(c, ffi::CURLOPT_UPLOAD, 1);
        long(c, ffi::CURLOPT_INFILESIZE, 3);
        function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
        pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        let up = (
            info::<curl_off_t>(c, ffi::CURLINFO_SIZE_UPLOAD_T),
            info::<curl_off_t>(c, ffi::CURLINFO_CONTENT_LENGTH_UPLOAD_T),
        );
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        (code, up)
    };
    assert_eq!(run(None), (CURLE_OK, (3, 3)));
    assert_eq!(std::fs::read(&path).unwrap(), b"abc");
    let abort = ffi::CURL_READFUNC_ABORT as usize;
    assert_eq!(run(Some(abort)).0, CURLE_ABORTED_BY_CALLBACK);
    let pause = ffi::CURL_READFUNC_PAUSE as usize;
    assert_eq!(run(Some(pause)).0, ffi::CURLE_READ_ERROR);
    std::fs::remove_file(path).unwrap();
}

/// How many times the seek or ioctl function ran, and what it answers.
#[derive(Default)]
struct Rewinds {
    calls: u32,
    answer: c_int,
}

unsafe extern "C" fn seek(data: *mut c_void, offset: curl_off_t, origin: c_int) -> c_int {
    // SAFETY: the test passes a `Rewinds`.
    let r = unsafe { &mut *data.cast::<Rewinds>() };
    assert_eq!((offset, origin), (0, libc::SEEK_SET));
    r.calls += 1;
    r.answer
}

unsafe extern "C" fn ioctl(_: *mut CURL, cmd: c_int, data: *mut c_void) -> ffi::curlioerr {
    // SAFETY: the test passes a `Rewinds`.
    let r = unsafe { &mut *data.cast::<Rewinds>() };
    assert_eq!(cmd, ffi::CURLIOCMD_RESTARTREAD.0);
    r.calls += 1;
    ffi::curlioerr(r.answer as _)
}

type SeekFn = unsafe extern "C" fn(*mut c_void, curl_off_t, c_int) -> c_int;
type IoctlFn = unsafe extern "C" fn(*mut CURL, c_int, *mut c_void) -> ffi::curlioerr;

/// A body sent again is rewound by the seek function, else the ioctl
/// function, else `fseek` on the default read function's stream
/// (`cr_in_rewind`); each failure says why.
#[test]
fn a_rewind_asks_the_application() {
    enum How {
        Seek(c_int),
        Ioctl(c_int),
        Stream,
        /// A stream `fseek` cannot rewind.
        Pipe,
        ReadFunction,
    }
    let run = |how: How| {
        let mut rewinds = Rewinds::default();
        let mut feed = Feed {
            left: b"ab".repeat(100),
            answer: None,
        };
        let mut buf = [0 as c_char; 256];
        let stream = tmpfile();
        let mut pipe = ptr::null_mut::<libc::FILE>();
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, c"script://a".as_ptr().cast_mut());
        long(c, ffi::CURLOPT_UPLOAD, 1);
        // A read taken for a pause would wait for ever: fail instead.
        long(c, ffi::CURLOPT_TIMEOUT, 5);
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
        options(c, |o| {
            o.script =
                Some(Script::new(vec![Piece::Send(1), Piece::Rewind, Piece::SendAll]).unwrap());
        });
        match how {
            How::Seek(answer) => {
                rewinds.answer = answer;
                function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
                pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
                function(c, ffi::CURLOPT_SEEKFUNCTION, seek as SeekFn as *const ());
                pointer(c, ffi::CURLOPT_SEEKDATA, &raw mut rewinds);
            }
            How::Ioctl(answer) => {
                rewinds.answer = answer;
                function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
                pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
                function(c, ffi::CURLOPT_IOCTLFUNCTION, ioctl as IoctlFn as *const ());
                pointer(c, ffi::CURLOPT_IOCTLDATA, &raw mut rewinds);
            }
            How::Stream => {
                // SAFETY: a stream from `tmpfile`.
                unsafe { libc::fwrite(b"xy".as_ptr().cast(), 1, 2, stream) };
                pointer(c, ffi::CURLOPT_READDATA, stream);
            }
            How::ReadFunction => {
                function(c, ffi::CURLOPT_READFUNCTION, read as ReadFn as *const ());
                pointer(c, ffi::CURLOPT_READDATA, &raw mut feed);
            }
            How::Pipe => {
                let mut fds = [0; 2];
                // SAFETY: room for the pipe's two descriptors; the write
                // end is closed once written, the read end by `fclose`.
                unsafe {
                    assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
                    libc::write(fds[1], b"xyz".as_ptr().cast(), 3);
                    libc::close(fds[1]);
                    pipe = libc::fdopen(fds[0], c"r".as_ptr());
                }
                pointer(c, ffi::CURLOPT_READDATA, pipe);
            }
        }
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        close(stream);
        if !pipe.is_null() {
            close(pipe);
        }
        // SAFETY: the shim ends what it writes with a zero byte.
        let why = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .unwrap()
            .to_owned();
        (code, rewinds.calls, why)
    };
    let fail = ffi::CURLE_SEND_FAIL_REWIND;
    assert_eq!(
        run(How::Seek(ffi::CURL_SEEKFUNC_OK)),
        (CURLE_OK, 1, String::new())
    );
    let failed = run(How::Seek(ffi::CURL_SEEKFUNC_FAIL));
    assert_eq!(
        failed,
        (fail, 1, "seek callback returned error 1".to_owned())
    );
    assert_eq!(
        run(How::Ioctl(ffi::CURLIOE_OK.0 as c_int)),
        (CURLE_OK, 1, String::new())
    );
    let failed = run(How::Ioctl(ffi::CURLIOE_FAILRESTART.0 as c_int));
    assert_eq!(
        failed,
        (fail, 1, "ioctl callback returned error 2".to_owned())
    );
    // The default read function reads `stream`, which `fseek` rewinds.
    assert_eq!(run(How::Stream).0, CURLE_OK);
    let failed = run(How::Pipe);
    assert_eq!(
        failed,
        (fail, 0, "necessary data rewind was not possible".to_owned())
    );
    let failed = run(How::ReadFunction);
    assert_eq!(
        failed,
        (fail, 0, "necessary data rewind was not possible".to_owned())
    );
}

/// What the write function answers.
struct Answer(usize);

unsafe extern "C" fn answer(_: *mut c_char, _: usize, _: usize, data: *mut c_void) -> usize {
    // SAFETY: the test passes an `Answer`.
    unsafe { (*data.cast::<Answer>()).0 }
}

/// The write function's answers, each failure with C's reason.
#[test]
fn the_write_function_s_answer_decides() {
    let (path, url) = file("answers", b"hello");
    let run = |a: usize| {
        let mut a = Answer(a);
        let mut buf = [0 as c_char; 256];
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(
            c,
            ffi::CURLOPT_WRITEFUNCTION,
            answer as WriteFn as *const (),
        );
        pointer(c, ffi::CURLOPT_WRITEDATA, &raw mut a);
        pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        // SAFETY: the shim ends what it writes with a zero byte.
        (
            code,
            unsafe { CStr::from_ptr(buf.as_ptr()) }
                .to_str()
                .unwrap()
                .to_owned(),
        )
    };
    assert_eq!(run(5), (CURLE_OK, String::new()));
    let short = run(1);
    assert_eq!(
        short,
        (
            ffi::CURLE_WRITE_ERROR,
            "Failure writing output to destination, passed 5 returned 1".to_owned()
        )
    );
    let error = run(ffi::CURL_WRITEFUNC_ERROR as usize);
    assert_eq!(
        error,
        (
            ffi::CURLE_WRITE_ERROR,
            "client returned ERROR on write of 5 bytes".to_owned()
        )
    );
    // file:// cannot pause.
    let pause = run(ffi::CURL_WRITEFUNC_PAUSE as usize);
    assert_eq!(pause.0, ffi::CURLE_WRITE_ERROR);
    assert_ne!(pause.1, error.1);
    assert_ne!(pause.1, short.1);
    std::fs::remove_file(path).unwrap();
}

/// The default write function writes to standard output.
#[test]
fn the_default_write_goes_to_standard_output() {
    let (path, url) = file("stdout", b"");
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_HEADER, 1);
    let out = tmpfile();
    pointer(c, ffi::CURLOPT_WRITEDATA, out);
    // SAFETY: a live handle.
    assert_eq!(unsafe { curl_easy_perform(c) }, CURLE_OK);
    assert!(stream_text(out).starts_with("Content-Length: 0\r\n"));
    close(out);
    // The process's standard output, by default: an empty file writes
    // only headers there, of which there are none without `HEADER`.
    long(c, ffi::CURLOPT_HEADER, 0);
    pointer(c, ffi::CURLOPT_WRITEDATA, crate::callbacks::standard().1);
    assert_eq!(ccb(c).write_data, crate::callbacks::standard().1);
    // SAFETY: a live handle, then not used again.
    unsafe {
        assert_eq!(curl_easy_perform(c), CURLE_OK);
        curl_easy_cleanup(c);
    }
    let fresh = curl_easy_init();
    assert_eq!(ccb(fresh).write_data, crate::callbacks::standard().1);
    assert_eq!(ccb(fresh).read_data, crate::callbacks::standard().0);
    assert!(!crate::callbacks::standard().1.is_null());
    // SAFETY: a live handle, not used again.
    unsafe { curl_easy_cleanup(fresh) };
    std::fs::remove_file(path).unwrap();
}

/// Lines the header function got, by its data.
#[derive(Default)]
struct Lines(Vec<String>);

unsafe extern "C" fn lines(ptr: *mut c_char, size: usize, n: usize, data: *mut c_void) -> usize {
    // SAFETY: the test passes `Lines` and the shim `size * n` bytes.
    let (l, b) = unsafe {
        (
            &mut *data.cast::<Lines>(),
            core::slice::from_raw_parts(ptr.cast::<u8>(), size * n),
        )
    };
    l.0.push(String::from_utf8(b.to_vec()).unwrap());
    size * n
}

/// Headers go to the header function, else to the write function with
/// the header data, else nowhere.
#[test]
fn headers_go_where_c_sends_them() {
    let (path, url) = file("headers", b"hello");
    let run = |header_fn: bool, header_data: bool| {
        let (mut body, mut heads) = (Lines::default(), Lines::default());
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        long(c, ffi::CURLOPT_NOBODY, 1);
        function(c, ffi::CURLOPT_WRITEFUNCTION, lines as WriteFn as *const ());
        pointer(c, ffi::CURLOPT_WRITEDATA, &raw mut body);
        if header_fn {
            function(
                c,
                ffi::CURLOPT_HEADERFUNCTION,
                lines as WriteFn as *const (),
            );
        }
        if header_data {
            pointer(c, ffi::CURLOPT_HEADERDATA, &raw mut heads);
        }
        // SAFETY: a live handle, then not used again.
        unsafe {
            assert_eq!(curl_easy_perform(c), CURLE_OK);
            curl_easy_cleanup(c);
        }
        (body.0.len(), heads.0.first().cloned())
    };
    let first = Some("Content-Length: 5\r\n".to_owned());
    assert_eq!(
        run(false, true),
        (0, first.clone()),
        "to the write function"
    );
    assert_eq!(run(false, false), (0, None), "nowhere");
    assert_eq!(run(true, true), (0, first));
    std::fs::remove_file(path).unwrap();
}

type DebugFn =
    unsafe extern "C" fn(*mut CURL, ffi::curl_infotype, *mut c_char, usize, *mut c_void) -> c_int;

/// What the debug function saw.
#[derive(Default)]
struct Seen {
    handle: usize,
    texts: Vec<String>,
}

unsafe extern "C" fn debug_count(
    h: *mut CURL,
    kind: ffi::curl_infotype,
    ptr: *mut c_char,
    n: usize,
    data: *mut c_void,
) -> c_int {
    if data.is_null() {
        return 0;
    }
    // SAFETY: the test passes a `Seen` and the shim `n` bytes.
    let (s, b) = unsafe {
        (
            &mut *data.cast::<Seen>(),
            core::slice::from_raw_parts(ptr.cast::<u8>(), n),
        )
    };
    s.handle = h as usize;
    if kind == ffi::CURLINFO_TEXT {
        s.texts.push(String::from_utf8(b.to_vec()).unwrap());
    }
    0
}

/// The trace goes to the debug function, with the handle, else to the
/// STDERR stream after `* `.
#[test]
fn the_trace_goes_to_the_debug_function_or_the_stream() {
    let missing = c"file:///nonexistent/curl-shim-trace";
    let mut seen = Seen::default();
    let stream = tmpfile();
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, missing.as_ptr().cast_mut());
    long(c, ffi::CURLOPT_VERBOSE, 1);
    pointer(c, ffi::CURLOPT_STDERR, stream);
    function(
        c,
        ffi::CURLOPT_DEBUGFUNCTION,
        debug_count as DebugFn as *const (),
    );
    pointer(c, ffi::CURLOPT_DEBUGDATA, &raw mut seen);
    let why = "Could not open file /nonexistent/curl-shim-trace\n";
    // SAFETY: a live handle.
    let code = unsafe { curl_easy_perform(c) };
    assert_eq!(code, ffi::CURLE_FILE_COULDNT_READ_FILE);
    assert_eq!(seen.handle, c as usize);
    assert!(seen.texts.iter().any(|t| t == why), "{:?}", seen.texts);
    assert_eq!(stream_text(stream), "");
    function(c, ffi::CURLOPT_DEBUGFUNCTION, ptr::null());
    // SAFETY: a live handle, then not used again.
    unsafe {
        assert_eq!(curl_easy_perform(c), ffi::CURLE_FILE_COULDNT_READ_FILE);
        curl_easy_cleanup(c);
    }
    assert!(
        stream_text(stream).contains(&format!("* {why}")),
        "{}",
        stream_text(stream)
    );
    close(stream);
}

/// A reason longer than ERRORBUFFER keeps its first 255 bytes.
#[test]
fn a_long_reason_is_cut_to_the_buffer() {
    let long_path = format!("file:///nonexistent/{}", "a".repeat(300));
    let url = std::ffi::CString::new(long_path).unwrap();
    let mut buf = [b'x' as c_char; 256];
    let c = curl_easy_init();
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    pointer(c, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
    // SAFETY: a live handle, then not used again.
    unsafe {
        assert_eq!(curl_easy_perform(c), ffi::CURLE_FILE_COULDNT_READ_FILE);
        curl_easy_cleanup(c);
    }
    assert_eq!(buf[255], 0);
    // SAFETY: zero-terminated.
    let why = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(why.len(), 255);
    assert!(why.starts_with(b"Could not open file /nonexistent/aaa"));
}

type XferFn =
    unsafe extern "C" fn(*mut c_void, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> c_int;
type ProgressFn = unsafe extern "C" fn(*mut c_void, f64, f64, f64, f64) -> c_int;

/// How the progress function answers, and what it saw last.
#[derive(Default)]
struct Meter {
    answer: c_int,
    calls: u32,
    last: (f64, f64),
}

unsafe extern "C" fn xferinfo(
    data: *mut c_void,
    dt: curl_off_t,
    dn: curl_off_t,
    _: curl_off_t,
    _: curl_off_t,
) -> c_int {
    if data.is_null() {
        return 0;
    }
    // SAFETY: the test passes a `Meter`.
    let m = unsafe { &mut *data.cast::<Meter>() };
    m.calls += 1;
    m.last = (dt as f64, dn as f64);
    m.answer
}

unsafe extern "C" fn old_progress(data: *mut c_void, dt: f64, dn: f64, _: f64, _: f64) -> c_int {
    if data.is_null() {
        return 0;
    }
    // SAFETY: the test passes a `Meter`.
    let m = unsafe { &mut *data.cast::<Meter>() };
    m.calls += 1;
    m.last = (dt, dn);
    m.answer
}

/// The progress function's answers: go on, go on with the meter, or
/// abort; the old function gets the same counts as doubles.
#[test]
fn the_progress_function_s_answer_decides() {
    let (path, url) = file("progress", b"hello");
    let run = |answer: c_int, old: bool| {
        let mut m = Meter {
            answer,
            ..Meter::default()
        };
        let stream = tmpfile();
        let c = curl_easy_init();
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
        pointer(c, ffi::CURLOPT_STDERR, stream);
        long(c, ffi::CURLOPT_NOPROGRESS, 0);
        if old {
            function(
                c,
                ffi::CURLOPT_PROGRESSFUNCTION,
                old_progress as ProgressFn as *const (),
            );
        } else {
            function(
                c,
                ffi::CURLOPT_XFERINFOFUNCTION,
                xferinfo as XferFn as *const (),
            );
        }
        pointer(c, ffi::CURLOPT_XFERINFODATA, &raw mut m);
        // SAFETY: a live handle, then not used again.
        let code = unsafe { curl_easy_perform(c) };
        // SAFETY: as above.
        unsafe { curl_easy_cleanup(c) };
        let meter = stream_text(stream).contains("% Total");
        close(stream);
        (code, m.calls > 0, m.last, meter)
    };
    assert_eq!(run(0, false), (CURLE_OK, true, (5.0, 5.0), false));
    assert_eq!(run(0, true), (CURLE_OK, true, (5.0, 5.0), false));
    let with_meter = run(ffi::CURL_PROGRESSFUNC_CONTINUE, false);
    assert_eq!((with_meter.0, with_meter.3), (CURLE_OK, true));
    assert_eq!(run(1, false).0, CURLE_ABORTED_BY_CALLBACK);
    assert_eq!(run(-1, true).0, CURLE_ABORTED_BY_CALLBACK);
    std::fs::remove_file(path).unwrap();
}

/// What the multi's callbacks saw.
#[derive(Default)]
struct Calls {
    multi: usize,
    timers: Vec<c_long>,
    timer_answer: c_int,
    /// Set once added: a callback during the add cannot reach the
    /// transfer yet (MILESTONES step 10).
    performing: bool,
    timer_getinfo: Option<CURLcode>,
    timer_pause: Option<CURLcode>,
    easy: usize,
    notes: Vec<(c_uint, usize)>,
    done_size: curl_off_t,
    done_pause: Option<CURLcode>,
}

unsafe extern "C" fn timer(m: *mut CURLM, ms: c_long, data: *mut c_void) -> c_int {
    // SAFETY: the test passes an `Calls`.
    let e = unsafe { &mut *data.cast::<Calls>() };
    e.multi = m as usize;
    e.timers.push(ms);
    if e.easy != 0 && e.performing {
        let c = e.easy as *mut CURL;
        let mut n: curl_off_t = 0;
        // SAFETY: the test's live handle, in this multi.
        unsafe {
            e.timer_getinfo = Some(curl_easy_getinfo(
                c,
                ffi::CURLINFO_SIZE_DOWNLOAD_T,
                &raw mut n,
            ));
            e.timer_pause = Some(curl_easy_pause(c, ffi::CURLPAUSE_CONT));
        }
    }
    e.timer_answer
}

unsafe extern "C" fn notify(m: *mut CURLM, kind: c_uint, easy: *mut CURL, data: *mut c_void) {
    // SAFETY: the test passes an `Calls`.
    let e = unsafe { &mut *data.cast::<Calls>() };
    e.multi = m as usize;
    e.notes.push((kind, easy as usize));
    if kind == ffi::CURLMNOTIFY_EASY_DONE as c_uint {
        // SAFETY: the test's live handle, in this multi.
        unsafe {
            curl_easy_getinfo(easy, ffi::CURLINFO_SIZE_DOWNLOAD_T, &raw mut e.done_size);
            e.done_pause = Some(curl_easy_pause(easy, ffi::CURLPAUSE_CONT));
        }
    }
}

type TimerFn = unsafe extern "C" fn(*mut CURLM, c_long, *mut c_void) -> c_int;
type NotifyFn = unsafe extern "C" fn(*mut CURLM, c_uint, *mut CURL, *mut c_void);

/// The timer callback hears of a new transfer, with the multi, and may
/// read it but not pause it; the notify callback hears the transfer is
/// done, then that a message waits, and may read and pause it. A timer
/// that answers -1 aborts the add.
#[test]
fn the_multi_s_callbacks_run_with_their_frames() {
    let (path, url) = file("events", b"hello");
    let mut e = Calls::default();
    let m = curl_multi_init();
    let c = curl_easy_init();
    e.easy = c as usize;
    pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
    function(c, ffi::CURLOPT_WRITEFUNCTION, sink as WriteFn as *const ());
    // SAFETY: live handles throughout, until their cleanups, and data
    // that outlives them.
    unsafe {
        let t = timer as TimerFn as *const ();
        let n = notify as NotifyFn as *const ();
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_TIMERFUNCTION, t),
            CURLM_OK
        );
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_TIMERDATA, (&raw mut e).cast::<c_void>()),
            CURLM_OK
        );
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_NOTIFYFUNCTION, n),
            CURLM_OK
        );
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_NOTIFYDATA, (&raw mut e).cast::<c_void>()),
            CURLM_OK
        );
        assert_eq!(
            curl_multi_setopt(m, ffi::CURLMOPT_MAXCONNECTS, 1 as c_long),
            ffi::CURLM_UNKNOWN_OPTION
        );
        for k in [ffi::CURLMNOTIFY_INFO_READ, ffi::CURLMNOTIFY_EASY_DONE] {
            assert_eq!(curl_multi_notify_enable(m, k as c_uint), CURLM_OK);
        }
        assert_eq!(curl_multi_notify_enable(m, 2), ffi::CURLM_UNKNOWN_OPTION);
        assert_eq!(curl_multi_notify_disable(m, 2), ffi::CURLM_UNKNOWN_OPTION);
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        assert_eq!(e.multi, m as usize);
        assert_eq!(e.timers.first(), Some(&0), "run at once");
        e.performing = true;
        let mut offt: curl_off_t = -2;
        assert_eq!(
            curl_multi_get_offt(m, ffi::CURLMINFO_XFERS_CURRENT, &raw mut offt),
            CURLM_OK
        );
        assert_eq!(offt, 1);
        let mut running = 1;
        while running > 0 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
        }
        assert_eq!(e.timers.last(), Some(&-1), "nothing more to run");
        assert_eq!(e.timer_getinfo, Some(CURLE_OK));
        assert_eq!(e.timer_pause, Some(CURLE_RECURSIVE_API_CALL));
        e.performing = false;
        let done = ffi::CURLMNOTIFY_EASY_DONE as c_uint;
        let read = ffi::CURLMNOTIFY_INFO_READ as c_uint;
        assert_eq!(e.notes.len(), 2, "{:?}", e.notes);
        assert_eq!(e.notes[0], (done, c as usize));
        assert_eq!(e.notes[1].0, read);
        assert!(
            e.notes[1].1 != 0 && e.notes[1].1 != c as usize,
            "the multi's own handle"
        );
        assert_eq!(e.done_size, 5);
        assert_eq!(
            e.done_pause,
            Some(CURLE_BAD_FUNCTION_ARGUMENT),
            "done: nothing to pause"
        );
        for (i, want) in [
            (ffi::CURLMINFO_XFERS_CURRENT, 1),
            (ffi::CURLMINFO_XFERS_RUNNING, 0),
            (ffi::CURLMINFO_XFERS_PENDING, 0),
            (ffi::CURLMINFO_XFERS_DONE, 1),
            (ffi::CURLMINFO_XFERS_ADDED, 1),
        ] {
            assert_eq!(curl_multi_get_offt(m, i, &raw mut offt), CURLM_OK);
            assert_eq!(offt, want, "{}", i.0);
        }
        let mut q = 0;
        assert!(!curl_multi_info_read(m, &raw mut q).is_null());
        assert_eq!(
            curl_multi_get_offt(m, ffi::CURLMINFO_XFERS_DONE, &raw mut offt),
            CURLM_OK
        );
        assert_eq!(offt, 0, "read");
        assert_eq!(
            curl_multi_get_offt(m, ffi::CURLMinfo_offt(99), &raw mut offt),
            ffi::CURLM_UNKNOWN_OPTION
        );
        assert_eq!(offt, -1);
        let null = ptr::null_mut::<curl_off_t>();
        assert_eq!(
            curl_multi_get_offt(m, ffi::CURLMINFO_XFERS_DONE, null),
            ffi::CURLM_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        // Disabled, a kind is not told.
        for k in [ffi::CURLMNOTIFY_INFO_READ, ffi::CURLMNOTIFY_EASY_DONE] {
            assert_eq!(curl_multi_notify_disable(m, k as c_uint), CURLM_OK);
        }
        e.notes.clear();
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        running = 1;
        while running > 0 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
        }
        assert!(e.notes.is_empty());
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        // A timer that answers -1 aborts the change it was told of.
        e.timer_answer = -1;
        assert_eq!(curl_multi_add_handle(m, c), ffi::CURLM_ABORTED_BY_CALLBACK);
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
    std::fs::remove_file(path).unwrap();
}

/// A handle in a multi that is running a callback may not perform: the
/// multi is busy, though the handle itself is not.
#[test]
fn a_sibling_may_not_perform_inside_a_callback() {
    let (path, url) = file("sibling", b"hello");
    struct Inside {
        other: usize,
        code: Option<CURLcode>,
    }
    unsafe extern "C" fn write(_: *mut c_char, size: usize, n: usize, data: *mut c_void) -> usize {
        // SAFETY: the test passes an `Inside`.
        let i = unsafe { &mut *data.cast::<Inside>() };
        // SAFETY: the test's live handle.
        i.code = Some(unsafe { curl_easy_perform(i.other as *mut CURL) });
        size * n
    }
    let m = curl_multi_init();
    let (a, b) = (curl_easy_init(), curl_easy_init());
    let mut inside = Inside {
        other: b as usize,
        code: None,
    };
    for c in [a, b] {
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut());
        function(c, ffi::CURLOPT_WRITEFUNCTION, write as WriteFn as *const ());
        pointer(c, ffi::CURLOPT_WRITEDATA, &raw mut inside);
    }
    // SAFETY: live handles throughout, until their cleanups.
    unsafe {
        assert_eq!(curl_multi_add_handle(m, b), CURLM_OK);
        // `a` performs alone; `b`'s multi is idle.
        inside.other = b as usize;
        assert_eq!(curl_easy_perform(a), CURLE_OK);
        assert_eq!(inside.code, Some(ffi::CURLE_FAILED_INIT), "added elsewhere");
        // Now `b`'s multi runs `a`'s write.
        assert_eq!(curl_multi_remove_handle(m, b), CURLM_OK);
        assert_eq!(curl_multi_add_handle(m, a), CURLM_OK);
        assert_eq!(curl_multi_add_handle(m, b), CURLM_OK);
        inside.code = None;
        let mut running = 1;
        while running > 0 {
            assert_eq!(curl_multi_perform(m, &raw mut running), CURLM_OK);
        }
        assert_eq!(inside.code, Some(CURLE_RECURSIVE_API_CALL));
        curl_easy_cleanup(a);
        curl_easy_cleanup(b);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
    std::fs::remove_file(path).unwrap();
}

/// A wait polls the application's descriptors and reports what C reports.
#[test]
fn a_wait_reports_the_application_s_descriptors() {
    let (r, w) = std::os::unix::net::UnixStream::pair().unwrap();
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    (&w).write_all(b"x").unwrap();
    let m = curl_multi_init();
    let mut fds = [
        ffi::curl_waitfd {
            fd: r.as_raw_fd(),
            events: ffi::CURL_WAIT_POLLIN as i16,
            revents: 0,
        },
        ffi::curl_waitfd {
            fd: w.as_raw_fd(),
            events: ffi::CURL_WAIT_POLLOUT as i16,
            revents: 0,
        },
    ];
    let mut ret = -1;
    // SAFETY: a live multi and two entries.
    unsafe {
        assert_eq!(
            curl_multi_wait(m, fds.as_mut_ptr(), 2, 1000, &raw mut ret),
            CURLM_OK
        );
        assert_eq!(ret, 2);
        assert_eq!(fds[0].revents, ffi::CURL_WAIT_POLLIN as i16);
        assert_eq!(fds[1].revents, ffi::CURL_WAIT_POLLOUT as i16);
        assert_eq!(
            curl_multi_wait(m, fds.as_mut_ptr(), 2, -1, &raw mut ret),
            ffi::CURLM_BAD_FUNCTION_ARGUMENT
        );
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
}

#[test]
fn c_numbers_translate_both_ways() {
    use ffi::{CURL_WAIT_POLLIN as IN, CURL_WAIT_POLLOUT as OUT, CURL_WAIT_POLLPRI as PRI};
    assert_eq!(wait_events(0), Events::NONE);
    assert_eq!(wait_events(IN as i16), Events::IN);
    assert_eq!(wait_events(PRI as i16), Events::PRI);
    assert_eq!(wait_events(OUT as i16), Events::OUT);
    assert_eq!(
        wait_events((IN | PRI | OUT) as i16),
        Events::IN | Events::PRI | Events::OUT
    );
    assert_eq!(wait_revents(Events::NONE), 0);
    assert_eq!(wait_revents(Events::IN), IN as i16);
    assert_eq!(wait_revents(Events::OUT), OUT as i16);
    assert_eq!(wait_revents(Events::PRI), PRI as i16);
    assert_eq!(
        wait_revents(Events::IN | Events::OUT | Events::PRI | Events::HUP),
        (IN | OUT | PRI) as i16
    );
    assert_eq!(notify_kind(0), Some(NotifyKind::InfoRead));
    assert_eq!(notify_kind(1), Some(NotifyKind::EasyDone));
    assert_eq!(notify_kind(2), None);
    assert_eq!(notify_kind(c_uint::MAX), None);
    assert_eq!(
        (running(0), running(7), running(u32::MAX)),
        (0, 7, c_int::MAX)
    );
    assert!(aborts(-1) && !aborts(0) && !aborts(1));
}

/// `fdset` and `waitfds` list the sockets the transfers wait on, as C's
/// do: a set bit and the highest descriptor, or an entry per socket and
/// the count needed.
#[test]
fn the_transfers_sockets_are_listed() {
    use crate::ffi::{
        CURL_WAIT_POLLOUT, CURLM_BAD_FUNCTION_ARGUMENT, CURLM_OUT_OF_MEMORY, curl_waitfd,
    };
    use crate::multi::{ShimMulti, curl_multi_fdset, curl_multi_waitfds};
    use curl_core::conn::io::{FakeNet, Peer};
    use curl_core::time::ManualClock;

    let clock = ManualClock::new().unwrap();
    let silent = std::net::SocketAddr::from(([127, 0, 0, 1], 3));
    let net = FakeNet::new(clock).with_peer(silent, Peer::Silent);
    let m: *mut CURLM = ShimMulti::boxed_with(Box::new(net))
        .unwrap()
        .as_ptr()
        .cast();
    let fdset = |read: &mut libc::fd_set, write: &mut libc::fd_set| {
        let mut max: c_int = 7;
        // SAFETY: a live multi and the caller's sets.
        let rc = unsafe {
            libc::FD_ZERO(read);
            libc::FD_ZERO(write);
            curl_multi_fdset(
                m,
                ptr::from_mut(read).cast(),
                ptr::from_mut(write).cast(),
                ptr::null_mut(),
                &raw mut max,
            )
        };
        assert_eq!(rc, CURLM_OK);
        max
    };
    let count = |ufds: *mut curl_waitfd, size: c_uint| {
        let mut n: c_uint = 99;
        // SAFETY: a live multi and `size` entries at `ufds`.
        let rc = unsafe { curl_multi_waitfds(m, ufds, size, &raw mut n) };
        (rc, n)
    };
    // SAFETY: zeroed `fd_set`s are valid; FD_ZERO clears them anyway.
    let (mut read, mut write) = unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    assert_eq!(fdset(&mut read, &mut write), -1, "nothing to wait on");
    assert_eq!(count(ptr::null_mut(), 0), (CURLM_OK, 0));
    // SAFETY: a live multi; neither entries nor a count is an error.
    let rc = unsafe { curl_multi_waitfds(m, ptr::null_mut(), 0, ptr::null_mut()) };
    assert_eq!(rc, CURLM_BAD_FUNCTION_ARGUMENT);

    let c = curl_easy_init();
    let url = c"tcp://127.0.0.1:3/";
    assert_eq!(
        pointer(c, ffi::CURLOPT_URL, url.as_ptr().cast_mut()),
        CURLE_OK
    );
    let mut running_now: c_int = 0;
    // SAFETY: a fresh handle, added to the live multi and run once.
    unsafe {
        assert_eq!(curl_multi_add_handle(m, c), CURLM_OK);
        assert_eq!(curl_multi_perform(m, &raw mut running_now), CURLM_OK);
    }
    assert_eq!(running_now, 1, "connecting");
    assert_eq!(fdset(&mut read, &mut write), 1000);
    // SAFETY: the sets `fdset` filled.
    unsafe {
        assert!(libc::FD_ISSET(1000, &write));
        assert!(!libc::FD_ISSET(1000, &read));
    }
    assert_eq!(count(ptr::null_mut(), 0), (CURLM_OK, 1));
    let mut entries = [curl_waitfd {
        fd: -1,
        events: 0,
        revents: 0,
    }; 2];
    assert_eq!(
        count(entries.as_mut_ptr(), 0),
        (CURLM_OUT_OF_MEMORY, 1),
        "no room"
    );
    assert_eq!(count(entries.as_mut_ptr(), 2), (CURLM_OK, 1));
    assert_eq!(
        (entries[0].fd, c_int::from(entries[0].events)),
        (1000, CURL_WAIT_POLLOUT)
    );
    assert_eq!(entries[1].fd, -1, "untouched");
    // SAFETY: the handle and multi made above, done with.
    unsafe {
        assert_eq!(curl_multi_remove_handle(m, c), CURLM_OK);
        curl_easy_cleanup(c);
        assert_eq!(curl_multi_cleanup(m), CURLM_OK);
    }
}
