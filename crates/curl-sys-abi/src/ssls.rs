//! `curl_easy_ssls_import` and `curl_easy_ssls_export`: the shim's side of
//! a handle's TLS sessions going in and out. C's pointers and lengths stop
//! here; the core takes slices.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::slice;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::multi::{ExportFailed, Exporting};
use curl_core::tls::{SessionExport, SessionFor};

use crate::callbacks;
use crate::easy::{HomeRef, ShimEasy, handle};
use crate::error_codes::easy_code;
use crate::ffi::{
    self, CURL, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_OK, CURLE_RECURSIVE_API_CALL, CURLcode,
};
use crate::gate::EasyCall;

/// `len` bytes at `p` as a slice, none for a NULL `p`.
///
/// # Safety
/// `p` is NULL or holds `len` bytes, for `'a`.
unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: as the caller guarantees.
    unsafe { slice::from_raw_parts(p, len) }
}

/// # Safety
///
/// `curl` is NULL or a live handle; `session_key` is NULL or a C string;
/// `shmac` and `sdata` are NULL or hold `shmac_len` and `sdata_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_ssls_import(
    curl: *mut CURL,
    session_key: *const c_char,
    shmac: *const u8,
    shmac_len: usize,
    sdata: *const u8,
    sdata_len: usize,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::SslsImport) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    // SAFETY: as the caller guarantees.
    let packed = unsafe { bytes(sdata, sdata_len) };
    if packed.is_empty() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    let who = if session_key.is_null() {
        // SAFETY: as the caller guarantees.
        SessionFor::SaltedHmac(unsafe { bytes(shmac, shmac_len) })
    } else {
        // SAFETY: a C string, as the caller guarantees.
        SessionFor::Key(unsafe { CStr::from_ptr(session_key) }.to_bytes())
    };
    let mut held = callbacks::Held::default();
    let notes = &mut |kind, b: &[u8]| held.note(kind, b);
    let done = easy.with_home(|home| match home {
        HomeRef::Detached(e) => Some(e.ssls_import(who, packed, notes)),
        HomeRef::Added(multi, id) => Some(
            multi
                .ssls_import(id, who, packed, notes)
                .expect("an added handle is in its multi"),
        ),
        // The multi is running a callback: its cache is out of reach.
        HomeRef::Frame(..) => None,
    });
    held.say(easy);
    match done {
        Ok(Some(Ok(()))) => CURLE_OK,
        Ok(Some(Err(kind))) => easy_code(kind),
        Ok(None) | Err(_) => CURLE_RECURSIVE_API_CALL,
    }
}
const _: ffi::proto::curl_easy_ssls_import = curl_easy_ssls_import;

/// # Safety
///
/// `curl` is NULL or a live handle; `export_fn` may be called with
/// `userptr` for as long as the call lasts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_ssls_export(
    curl: *mut CURL,
    export_fn: Option<ffi::curl_ssls_export_cb>,
    userptr: *mut c_void,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::SslsExport) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    let Some(export_fn) = export_fn else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Some(exporting) = begin(easy) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    // The handle is not borrowed from here: the function may use it as the
    // gate lets it, which is not to touch this cache.
    let multi = easy.added().filter(|_| !exporting.on_share());
    // SAFETY: the handle's multi outlives its `Added`.
    let stack = multi.map(|(m, _)| unsafe { &m.as_ref().stack });
    if let Some(stack) = stack {
        stack.set_exporting(true);
    }
    let done = exporting.deliver(&mut |session| {
        // SAFETY: the function and its pointer, as the caller guarantees.
        unsafe { give(curl, export_fn, userptr, session) }
    });
    if let Some(stack) = stack {
        stack.set_exporting(false);
    }
    let mut held = callbacks::Held::default();
    let notes = &mut |kind, b: &[u8]| held.note(kind, b);
    let ended = easy.with_home(|home| match home {
        HomeRef::Detached(e) => Some(done.end(e, notes)),
        HomeRef::Added(multi, id) => Some(
            multi
                .ssls_export_end(id, done, notes)
                .expect("an added handle is in its multi"),
        ),
        HomeRef::Frame(..) => None,
    });
    held.say(easy);
    match ended {
        Ok(Some(Ok(()))) => CURLE_OK,
        Ok(Some(Err(ExportFailed::Library(kind)))) => easy_code(kind),
        Ok(Some(Err(ExportFailed::Stopped(code)))) => code,
        Ok(None) | Err(_) => CURLE_RECURSIVE_API_CALL,
    }
}
const _: ffi::proto::curl_easy_ssls_export = curl_easy_ssls_export;

/// The sessions of `easy`'s cache, ready to go out; none if the multi it is
/// in is running a callback, whose cache is out of reach.
fn begin(easy: &ShimEasy) -> Option<Exporting> {
    easy.with_home(|home| match home {
        HomeRef::Detached(e) => Some(e.ssls_export()),
        HomeRef::Added(multi, id) => Some(
            multi
                .ssls_export(id)
                .expect("an added handle is in its multi"),
        ),
        HomeRef::Frame(..) => None,
    })
    .ok()
    .flatten()
}

/// `bytes` with the zero byte a C string ends in.
fn c_string(text: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut made = Vec::new();
    made.try_reserve_exact(text.len() + 1)?;
    made.try_extend_from_slice(text)?;
    made.try_push(0)?;
    Ok(made)
}

/// Give the application's function `session`, nonzero stopping the export
/// with that code.
///
/// # Safety
/// `export_fn` may be called with `curl` and `userptr`.
unsafe fn give(
    curl: *mut CURL,
    export_fn: ffi::curl_ssls_export_cb,
    userptr: *mut c_void,
    session: SessionExport<'_>,
) -> Result<(), CURLcode> {
    let oom = |OutOfMemory| ffi::CURLE_OUT_OF_MEMORY;
    let key = session.key.map(c_string).transpose().map_err(oom)?;
    let alpn = session.alpn.map(c_string).transpose().map_err(oom)?;
    let c_of = |s: &Option<Vec<u8>>| s.as_ref().map_or(core::ptr::null(), |v| v.as_ptr().cast());
    // SAFETY: as the caller guarantees; each pointer holds what its length
    // or zero byte says, for the call.
    let code = unsafe {
        export_fn(
            curl,
            userptr,
            c_of(&key),
            session.salted_hmac.as_ptr(),
            session.salted_hmac.len(),
            session.packed.as_ptr(),
            session.packed.len(),
            session.valid_until,
            c_int::from(session.version),
            c_of(&alpn),
            session.earlydata_max,
        )
    };
    if code == CURLE_OK { Ok(()) } else { Err(code) }
}

#[cfg(test)]
#[allow(
    clippy::multiple_unsafe_ops_per_block,
    reason = "one contract covers each test's calls"
)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::easy::{curl_easy_cleanup, curl_easy_init};

    /// Without a handle or with nothing to import or export with, each
    /// says so, as test 1678 asks.
    #[test]
    fn a_missing_argument_is_refused() {
        // SAFETY: a handle made here, and pointers each call reads as NULL
        // or holding what it says.
        unsafe {
            let packet = [1u8];
            let key = c"example.test:443".as_ptr();
            let null = ptr::null();
            let none = ptr::null_mut();
            let bad = CURLE_BAD_FUNCTION_ARGUMENT;
            let p = packet.as_ptr();
            assert_eq!(curl_easy_ssls_import(none, key, null, 0, p, 1), bad);
            assert_eq!(curl_easy_ssls_export(none, None, none), bad);
            let c = curl_easy_init();
            assert_eq!(curl_easy_ssls_import(c, key, null, 0, null, 1), bad);
            assert_eq!(curl_easy_ssls_import(c, key, null, 0, p, 0), bad);
            assert_eq!(curl_easy_ssls_export(c, None, none), bad);
            curl_easy_cleanup(c);
        }
    }

    /// A session imported through a share comes out as C's callback takes
    /// it: its key a C string, what it came with, the export returning what
    /// the function does; a blob that does not parse is refused.
    #[test]
    fn a_session_goes_in_and_comes_out_through_the_abi() {
        use crate::setopt::curl_easy_setopt;
        use crate::share::{curl_share_cleanup, curl_share_init, curl_share_setopt};

        type Session = (Vec<u8>, usize, Vec<u8>, i64, c_int, Vec<u8>, usize);
        #[derive(Default)]
        struct Seen(Vec<Session>);

        unsafe extern "C" fn take(
            _: *mut CURL,
            seen: *mut c_void,
            key: *const c_char,
            shmac: *const u8,
            shmac_len: usize,
            data: *const u8,
            data_len: usize,
            until: ffi::curl_off_t,
            version: c_int,
            alpn: *const c_char,
            early: usize,
        ) -> CURLcode {
            // SAFETY: the pointer the test gave, and what the call says of
            // each of its own.
            unsafe {
                assert!(!shmac.is_null());
                (*seen.cast::<Seen>()).0.push((
                    CStr::from_ptr(key).to_bytes().to_vec(),
                    shmac_len,
                    bytes(data, data_len).to_vec(),
                    until,
                    version,
                    CStr::from_ptr(alpn).to_bytes().to_vec(),
                    early,
                ));
            }
            CURLcode(4242)
        }

        let blob = [
            1, 4, 0, 1, b'T', 2, 3, 4, 3, 0x7f, 0, 0, 0, 0, 0, 0, 9, 5, 0, 3, b'f', b'o', b'o', 6,
            0, 0, 0, 7,
        ];
        // SAFETY: handles made here, with pointers holding what each call
        // says, `seen` outliving the export.
        unsafe {
            let sh = curl_share_init();
            assert_eq!(
                curl_share_setopt(
                    sh,
                    ffi::CURLSHOPT_SHARE,
                    ffi::CURL_LOCK_DATA_SSL_SESSION.0 as c_int
                ),
                ffi::CURLSHE_OK
            );
            let c = curl_easy_init();
            assert_eq!(curl_easy_setopt(c, ffi::CURLOPT_SHARE, sh), CURLE_OK);
            let key = c"peer:G".as_ptr();
            let null = ptr::null();
            let p = blob.as_ptr();
            assert_eq!(
                curl_easy_ssls_import(c, key, null, 0, p, 3),
                ffi::CURLE_READ_ERROR,
                "cut short"
            );
            assert_eq!(
                curl_easy_ssls_import(c, null, null, 0, p, blob.len()),
                CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_easy_ssls_import(c, key, null, 0, p, blob.len()),
                CURLE_OK
            );
            let mut seen = Seen::default();
            let code = curl_easy_ssls_export(c, Some(take), (&raw mut seen).cast());
            assert_eq!(code, CURLcode(4242), "the function's own");
            let got = seen.0.pop().unwrap();
            assert_eq!(got.0, b"peer:G");
            assert_eq!(got.1, 64);
            assert_eq!((got.3, got.4, got.6), (0x7f00_0000_0000_0009, 0x304, 7));
            assert_eq!(got.5, b"foo");
            assert_eq!(got.2[..5], [1, 4, 0, 1, b'T'], "packed");
            curl_easy_cleanup(c);
            curl_share_cleanup(sh);
        }
    }

    /// A handle in a multi using a share: its sessions are the share's, so
    /// that is what is refused, wherever the other handle is, and the multi
    /// goes on. What the function fails with comes back from the multi too.
    #[test]
    fn a_share_s_sessions_go_out_past_a_multi() {
        use crate::multi::{curl_multi_add_handle, curl_multi_cleanup, curl_multi_init};
        use crate::multi::{curl_multi_perform, curl_multi_remove_handle};
        use crate::setopt::curl_easy_setopt;
        use crate::share::{curl_share_cleanup, curl_share_init, curl_share_setopt};

        struct Others {
            other: *mut CURL,
            multi: *mut ffi::CURLM,
            answer: CURLcode,
            calls: u32,
        }

        const BLOB: [u8; 5] = [1, 4, 0, 1, b'T'];

        unsafe extern "C" fn try_them(
            _: *mut CURL,
            others: *mut c_void,
            _: *const c_char,
            _: *const u8,
            _: usize,
            _: *const u8,
            _: usize,
            _: ffi::curl_off_t,
            _: c_int,
            _: *const c_char,
            _: usize,
        ) -> CURLcode {
            // SAFETY: the pointer the test gave, and handles it made.
            unsafe {
                let o = &mut *others.cast::<Others>();
                o.calls += 1;
                let key = c"other:G".as_ptr();
                let got = curl_easy_ssls_import(o.other, key, ptr::null(), 0, BLOB.as_ptr(), 5);
                assert_eq!(got, CURLE_RECURSIVE_API_CALL);
                if !o.multi.is_null() {
                    let mut running = 0;
                    assert_eq!(curl_multi_perform(o.multi, &mut running), ffi::CURLM_OK);
                }
                o.answer
            }
        }

        // SAFETY: handles made here, with pointers holding what each call
        // says, `o` outliving the exports.
        unsafe {
            let sh = curl_share_init();
            let session = ffi::CURL_LOCK_DATA_SSL_SESSION.0 as c_int;
            assert_eq!(
                curl_share_setopt(sh, ffi::CURLSHOPT_SHARE, session),
                ffi::CURLSHE_OK
            );
            let (a, c) = (curl_easy_init(), curl_easy_init());
            for h in [a, c] {
                assert_eq!(curl_easy_setopt(h, ffi::CURLOPT_SHARE, sh), CURLE_OK);
            }
            let m = curl_multi_init();
            assert_eq!(curl_multi_add_handle(m, c), ffi::CURLM_OK);
            let key = c"peer:G".as_ptr();
            assert_eq!(
                curl_easy_ssls_import(a, key, ptr::null(), 0, BLOB.as_ptr(), 5),
                CURLE_OK
            );

            let mut o = Others {
                other: a,
                multi: m,
                answer: CURLE_OK,
                calls: 0,
            };
            let code = curl_easy_ssls_export(c, Some(try_them), (&raw mut o).cast());
            assert_eq!((code, o.calls), (CURLE_OK, 1), "from the multi");

            let mut o = Others {
                other: c,
                multi: ptr::null_mut(),
                answer: CURLE_OK,
                calls: 0,
            };
            let code = curl_easy_ssls_export(a, Some(try_them), (&raw mut o).cast());
            assert_eq!((code, o.calls), (CURLE_OK, 1), "to the multi");

            let failing = ffi::CURLE_WRITE_ERROR;
            let mut o = Others {
                other: a,
                multi: ptr::null_mut(),
                answer: failing,
                calls: 0,
            };
            let code = curl_easy_ssls_export(c, Some(try_them), (&raw mut o).cast());
            assert_eq!((code, o.calls), (failing, 1), "its failure");

            assert_eq!(curl_multi_remove_handle(m, c), ffi::CURLM_OK);
            curl_multi_cleanup(m);
            curl_easy_cleanup(a);
            curl_easy_cleanup(c);
            curl_share_cleanup(sh);
        }
    }

    /// Inside the application's function, another handle using the same
    /// cache is refused what C's gate refuses it, while one using another
    /// cache, and what the rule does not name, go on.
    #[test]
    fn what_uses_the_cache_is_refused_while_it_goes_out() {
        use crate::multi::{curl_multi_add_handle, curl_multi_cleanup, curl_multi_init};
        use crate::multi::{curl_multi_perform, curl_multi_remove_handle};
        use crate::setopt::curl_easy_setopt;
        use crate::share::{curl_share_cleanup, curl_share_init, curl_share_setopt};

        struct Others {
            same: *mut CURL,
            apart: *mut CURL,
            multi: *mut ffi::CURLM,
            calls: u32,
        }

        const BLOB: [u8; 5] = [1, 4, 0, 1, b'T'];

        unsafe extern "C" fn try_them(
            _: *mut CURL,
            others: *mut c_void,
            _: *const c_char,
            _: *const u8,
            _: usize,
            _: *const u8,
            _: usize,
            _: ffi::curl_off_t,
            _: c_int,
            _: *const c_char,
            _: usize,
        ) -> CURLcode {
            // SAFETY: the pointer the test gave, and handles it made.
            unsafe {
                let o = &mut *others.cast::<Others>();
                o.calls += 1;
                let key = c"other:G".as_ptr();
                let null = ptr::null();
                let import = |c| curl_easy_ssls_import(c, key, null, 0, BLOB.as_ptr(), 5);
                assert_eq!(import(o.same), CURLE_RECURSIVE_API_CALL, "the same cache");
                assert_eq!(
                    crate::easy::curl_easy_upkeep(o.same),
                    CURLE_RECURSIVE_API_CALL
                );
                assert_eq!(import(o.apart), CURLE_BAD_FUNCTION_ARGUMENT, "no cache");
                if !o.multi.is_null() {
                    let mut running = 0;
                    assert_eq!(
                        curl_multi_perform(o.multi, &mut running),
                        ffi::CURLM_RECURSIVE_API_CALL
                    );
                }
            }
            CURLE_OK
        }

        let key = c"peer:G".as_ptr();
        let null = ptr::null();
        // SAFETY: handles made here, with pointers holding what each call
        // says, `others` outliving the exports.
        unsafe {
            let sh = curl_share_init();
            let session = ffi::CURL_LOCK_DATA_SSL_SESSION.0 as c_int;
            assert_eq!(
                curl_share_setopt(sh, ffi::CURLSHOPT_SHARE, session),
                ffi::CURLSHE_OK
            );
            let (a, b, apart) = (curl_easy_init(), curl_easy_init(), curl_easy_init());
            for c in [a, b] {
                assert_eq!(curl_easy_setopt(c, ffi::CURLOPT_SHARE, sh), CURLE_OK);
            }
            assert_eq!(
                curl_easy_ssls_import(a, key, null, 0, BLOB.as_ptr(), 5),
                CURLE_OK
            );
            let mut o = Others {
                same: b,
                apart,
                multi: ptr::null_mut(),
                calls: 0,
            };
            let code = curl_easy_ssls_export(a, Some(try_them), (&raw mut o).cast());
            assert_eq!((code, o.calls), (CURLE_OK, 1));
            assert_eq!(
                curl_easy_ssls_import(b, key, null, 0, BLOB.as_ptr(), 5),
                CURLE_OK,
                "free again"
            );

            // A multi's cache, with no share: its other handle, and the multi.
            let m = curl_multi_init();
            let (c, d) = (curl_easy_init(), curl_easy_init());
            assert_eq!(curl_multi_add_handle(m, c), ffi::CURLM_OK);
            assert_eq!(curl_multi_add_handle(m, d), ffi::CURLM_OK);
            assert_eq!(
                curl_easy_ssls_import(c, key, null, 0, BLOB.as_ptr(), 5),
                CURLE_OK
            );
            let mut o = Others {
                same: d,
                apart,
                multi: m,
                calls: 0,
            };
            let code = curl_easy_ssls_export(c, Some(try_them), (&raw mut o).cast());
            assert_eq!((code, o.calls), (CURLE_OK, 1));
            let mut running = 0;
            assert_eq!(
                curl_multi_perform(m, &mut running),
                ffi::CURLM_OK,
                "free again"
            );
            for h in [c, d] {
                assert_eq!(curl_multi_remove_handle(m, h), ffi::CURLM_OK);
                curl_easy_cleanup(h);
            }
            curl_multi_cleanup(m);
            for h in [a, b, apart] {
                curl_easy_cleanup(h);
            }
            curl_share_cleanup(sh);
        }
    }
}
