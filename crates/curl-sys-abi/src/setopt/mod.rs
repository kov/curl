//! `curl_easy_setopt` (`lib/setopt.c`): each option's C argument checked
//! as C checks it and turned into the core's options, or into the
//! callbacks and settings the shim keeps for the adapters.
//!
//! An option the shim does not implement yet is `CURLE_NOT_BUILT_IN` if
//! libcurl knows its id, and `CURLE_UNKNOWN_OPTION` if not, as C answers
//! for options a build leaves out and for ids nobody defined.

#![allow(unsafe_code)]

#[rustfmt::skip]
mod known;

use core::ffi::{CStr, VaList, c_char, c_long, c_void};
use core::num::{NonZeroU16, NonZeroU64};
use core::ptr::NonNull;

use curl_alloc::OutOfMemory;
use curl_core::options::{FileMode, LowSpeed, Method, Options, Resume};
use curl_core::time::TimeLimit;

use crate::callbacks::{self, CCallbacks, CSettings};
use crate::easy::{self, ShimEasy};
use crate::ffi::{
    self, CURL, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_NOT_BUILT_IN, CURLE_OK, CURLE_OUT_OF_MEMORY,
    CURLE_RECURSIVE_API_CALL, CURLE_UNKNOWN_OPTION, CURLcode, CURLoption, curl_off_t,
};
use crate::gate::EasyCall;

/// C's longest string option (`CURL_MAX_INPUT_LENGTH`).
const MAX_INPUT_LENGTH: usize = 8_000_000;

/// A function pointer passed through varargs as a pointer.
///
/// # Safety
///
/// `p` is NULL or a function of the type `F`, an `Option` of a function
/// pointer, describes.
pub(crate) unsafe fn function<F: Copy>(p: *mut c_void) -> F {
    assert_eq!(
        size_of::<F>(),
        size_of::<*mut c_void>(),
        "a function pointer"
    );
    // SAFETY: `F` is a nullable function pointer the size of `p`, and NULL
    // is its `None`, as the caller guarantees.
    unsafe { core::mem::transmute_copy(&p) }
}

/// The C argument an option takes, by its id's class (`CURLOPTTYPE_*`).
enum Arg {
    Long(c_long),
    Ptr(*mut c_void),
    Off(curl_off_t),
}

/// A checked change that failed.
enum Refused {
    Bad,
    OutOfMemory,
    NotBuiltIn,
    Unknown,
}

impl From<OutOfMemory> for Refused {
    fn from(_: OutOfMemory) -> Refused {
        Refused::OutOfMemory
    }
}

/// The string at `p`, or none for NULL; one longer than C takes is refused.
///
/// # Safety
///
/// `p` is NULL or a C string.
unsafe fn string<'a>(p: *mut c_void) -> Result<Option<&'a [u8]>, Refused> {
    if p.is_null() {
        return Ok(None);
    }
    // SAFETY: as the caller guarantees.
    let s = unsafe { CStr::from_ptr(p.cast::<c_char>()) }.to_bytes();
    if s.len() > MAX_INPUT_LENGTH {
        return Err(Refused::Bad);
    }
    Ok(Some(s))
}

/// A time limit of `n` units of `ms` milliseconds (`setopt_set_timeout_*`).
fn time_limit(n: c_long, ms: u64) -> Result<Option<TimeLimit>, Refused> {
    let n = u64::try_from(n).map_err(|_| Refused::Bad)?;
    Ok(TimeLimit::from_millis(n.saturating_mul(ms)))
}

/// A resume offset: -1 is the end, below is refused.
fn resume(n: i64) -> Result<Option<Resume>, Refused> {
    match n {
        -1 => Ok(Some(Resume::AtEnd)),
        n if n < -1 => Err(Refused::Bad),
        n => Ok(NonZeroU64::new(n as u64).map(Resume::At)),
    }
}

/// A size limit: zero is none, below is refused.
fn max_filesize(n: i64) -> Result<Option<NonZeroU64>, Refused> {
    u64::try_from(n)
        .map(NonZeroU64::new)
        .map_err(|_| Refused::Bad)
}

/// The low-speed rule, from its two halves.
fn low_speed(set: &CSettings) -> Option<LowSpeed> {
    Some(LowSpeed {
        limit: NonZeroU64::new(u64::try_from(set.low_speed_limit).ok()?)?,
        time: NonZeroU16::new(u16::try_from(set.low_speed_time).ok()?)?,
    })
}

/// A `long` as the 64 bits an offset has.
#[allow(
    clippy::useless_conversion,
    reason = "`c_long` is 32 bits on some targets"
)]
fn wide(n: c_long) -> i64 {
    i64::from(n)
}

/// The size of the body an upload sends: -1 for unknown, below is refused.
fn in_file_size(
    options: &mut Options,
    me: NonNull<ShimEasy>,
    set: &mut CSettings,
    n: i64,
) -> Result<(), Refused> {
    if n < -1 {
        return Err(Refused::Bad);
    }
    set.in_file_size = n;
    Ok(callbacks::sync_upload(options, me, set)?)
}

/// Apply `option` with `arg` to the handle at `me`.
fn apply(
    me: NonNull<ShimEasy>,
    options: &mut Options,
    ccb: &mut CCallbacks,
    set: &mut CSettings,
    errbuf: &mut *mut c_char,
    option: CURLoption,
    arg: Arg,
) -> Result<(), Refused> {
    use Arg::{Long, Off, Ptr};
    match (option, arg) {
        (ffi::CURLOPT_VERBOSE, Long(n)) => options.output.verbose = n != 0,
        (ffi::CURLOPT_HEADER, Long(n)) => options.output.include_header = n != 0,
        (ffi::CURLOPT_NOPROGRESS, Long(n)) => {
            set.no_progress = n != 0;
            callbacks::sync_progress(options, me, set, ccb)?;
        }
        (ffi::CURLOPT_NOBODY, Long(n)) => {
            if n != 0 {
                options.method = Method::Head;
            } else if options.method == Method::Head {
                options.method = Method::Get;
            }
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_UPLOAD | ffi::CURLOPT_PUT, Long(n)) => {
            options.method = if n != 0 { Method::Upload } else { Method::Get };
            callbacks::sync_upload(options, me, set)?;
        }
        (ffi::CURLOPT_PATH_AS_IS, Long(n)) => options.url_rules.path_as_is = n != 0,
        (ffi::CURLOPT_DISALLOW_USERNAME_IN_URL, Long(n)) => {
            options.url_rules.disallow_user = n != 0;
        }
        (ffi::CURLOPT_TIMEOUT, Long(n)) => options.limits.total = time_limit(n, 1000)?,
        (ffi::CURLOPT_TIMEOUT_MS, Long(n)) => options.limits.total = time_limit(n, 1)?,
        (ffi::CURLOPT_CONNECTTIMEOUT, Long(n)) => options.limits.connect = time_limit(n, 1000)?,
        (ffi::CURLOPT_CONNECTTIMEOUT_MS, Long(n)) => options.limits.connect = time_limit(n, 1)?,
        (ffi::CURLOPT_LOW_SPEED_LIMIT, Long(n)) => {
            if n < 0 {
                return Err(Refused::Bad);
            }
            set.low_speed_limit = n;
            options.limits.low_speed = low_speed(set);
        }
        (ffi::CURLOPT_LOW_SPEED_TIME, Long(n)) => {
            if n < 0 {
                return Err(Refused::Bad);
            }
            set.low_speed_time = n.min(c_long::from(u16::MAX));
            options.limits.low_speed = low_speed(set);
        }
        (ffi::CURLOPT_MAXFILESIZE, Long(n)) => {
            options.limits.max_filesize = max_filesize(wide(n))?;
        }
        (ffi::CURLOPT_MAXFILESIZE_LARGE, Off(n)) => options.limits.max_filesize = max_filesize(n)?,
        (ffi::CURLOPT_RESUME_FROM, Long(n)) => options.resume = resume(wide(n))?,
        (ffi::CURLOPT_RESUME_FROM_LARGE, Off(n)) => options.resume = resume(n)?,
        (ffi::CURLOPT_INFILESIZE, Long(n)) => in_file_size(options, me, set, wide(n))?,
        (ffi::CURLOPT_INFILESIZE_LARGE, Off(n)) => in_file_size(options, me, set, n)?,
        (ffi::CURLOPT_NEW_FILE_PERMS, Long(n)) => {
            let bits = u16::try_from(n).ok().and_then(FileMode::new);
            options.new_file_mode = bits.ok_or(Refused::Bad)?;
        }
        (ffi::CURLOPT_URL, Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            options.set_url(unsafe { string(p) }?)?;
        }
        (ffi::CURLOPT_DEFAULT_PROTOCOL, Ptr(p)) => {
            // SAFETY: as above.
            options.set_default_protocol(unsafe { string(p) }?)?;
        }
        (ffi::CURLOPT_ERRORBUFFER, Ptr(p)) => {
            *errbuf = p.cast();
            callbacks::sync_error_buffer(options, me, *errbuf)?;
        }
        (ffi::CURLOPT_PRIVATE, Ptr(p)) => set.private = p,
        (ffi::CURLOPT_STDERR, Ptr(p)) => {
            ccb.stderr = if p.is_null() {
                callbacks::standard().2
            } else {
                p.cast()
            };
            callbacks::sync_text(options, me, ccb)?;
        }
        (ffi::CURLOPT_WRITEDATA, Ptr(p)) => ccb.write_data = p,
        (ffi::CURLOPT_HEADERDATA, Ptr(p)) => {
            ccb.header_data = p;
            callbacks::sync_text(options, me, ccb)?;
        }
        (ffi::CURLOPT_READDATA, Ptr(p)) => ccb.read_data = p,
        (ffi::CURLOPT_SEEKDATA, Ptr(p)) => ccb.seek_data = p,
        (ffi::CURLOPT_IOCTLDATA, Ptr(p)) => ccb.ioctl_data = p,
        (ffi::CURLOPT_XFERINFODATA, Ptr(p)) => ccb.progress_data = p,
        (ffi::CURLOPT_DEBUGDATA, Ptr(p)) => ccb.debug_data = p,
        // SAFETY: the application passes a function of the option's
        // type, or NULL.
        (ffi::CURLOPT_WRITEFUNCTION, Ptr(p)) => ccb.write = unsafe { function(p) },
        (ffi::CURLOPT_HEADERFUNCTION, Ptr(p)) => {
            // SAFETY: as above.
            ccb.header = unsafe { function(p) };
            callbacks::sync_text(options, me, ccb)?;
        }
        // SAFETY: as above.
        (ffi::CURLOPT_READFUNCTION, Ptr(p)) => ccb.read = unsafe { function(p) },
        // SAFETY: as above.
        (ffi::CURLOPT_SEEKFUNCTION, Ptr(p)) => ccb.seek = unsafe { function(p) },
        // SAFETY: as above.
        (ffi::CURLOPT_IOCTLFUNCTION, Ptr(p)) => ccb.ioctl = unsafe { function(p) },
        (ffi::CURLOPT_DEBUGFUNCTION, Ptr(p)) => {
            // SAFETY: as above.
            ccb.debug = unsafe { function(p) };
            callbacks::sync_text(options, me, ccb)?;
        }
        (ffi::CURLOPT_XFERINFOFUNCTION, Ptr(p)) => {
            // SAFETY: as above.
            ccb.xferinfo = unsafe { function(p) };
            callbacks::sync_progress(options, me, set, ccb)?;
        }
        (ffi::CURLOPT_PROGRESSFUNCTION, Ptr(p)) => {
            // SAFETY: as above.
            ccb.progress = unsafe { function(p) };
            callbacks::sync_progress(options, me, set, ccb)?;
        }
        (option, _) if known::KNOWN.binary_search(&option.0).is_ok() => {
            return Err(Refused::NotBuiltIn);
        }
        _ => return Err(Refused::Unknown),
    }
    Ok(())
}

/// The argument of `option`, read as its id's class says C passes it.
///
/// # Safety
///
/// The next argument in `args` is of the option's type.
unsafe fn read_arg(option: CURLoption, args: &mut VaList<'_>) -> Option<Arg> {
    Some(match option.0 / 10000 {
        // SAFETY: as the caller guarantees.
        0 => Arg::Long(unsafe { args.next_arg::<c_long>() }),
        // Objects, functions and blobs are all pointers.
        // SAFETY: as above.
        1 | 2 | 4 => Arg::Ptr(unsafe { args.next_arg::<*mut c_void>() }),
        // SAFETY: as above.
        3 => Arg::Off(unsafe { args.next_arg::<curl_off_t>() }),
        _ => return None,
    })
}

/// # Safety
///
/// `curl` is NULL or a live handle; the argument is of the option's type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_setopt(
    curl: *mut CURL,
    option: CURLoption,
    mut args: ...
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { easy::handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::Setopt) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    // SAFETY: as the caller guarantees.
    let Some(arg) = (unsafe { read_arg(option, &mut args) }) else {
        return CURLE_UNKNOWN_OPTION;
    };
    let me = NonNull::from(easy);
    let (mut ccb, mut set, mut errbuf) = (easy.ccb.get(), easy.set.get(), easy.errbuf.get());
    let applied = easy.with_options(|o| apply(me, o, &mut ccb, &mut set, &mut errbuf, option, arg));
    let code = match applied {
        Ok(Ok(())) => CURLE_OK,
        Ok(Err(Refused::Bad)) => return CURLE_BAD_FUNCTION_ARGUMENT,
        Ok(Err(Refused::OutOfMemory)) => return CURLE_OUT_OF_MEMORY,
        Ok(Err(Refused::NotBuiltIn)) => return CURLE_NOT_BUILT_IN,
        Ok(Err(Refused::Unknown)) => return CURLE_UNKNOWN_OPTION,
        Err(_) => return CURLE_RECURSIVE_API_CALL,
    };
    // Kept only once the change is whole.
    easy.ccb.set(ccb);
    easy.set.set(set);
    easy.errbuf.set(errbuf);
    code
}
const _: ffi::proto::curl_easy_setopt = curl_easy_setopt;

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated list is sorted, for the search, and holds the ids C
    /// defines, aliases' targets among them.
    #[test]
    fn knows_c_ids() {
        assert!(known::KNOWN.windows(2).all(|w| w[0] < w[1]));
        for id in [ffi::CURLOPT_URL, ffi::CURLOPT_PORT, ffi::CURLOPT_SSLCERT] {
            assert!(known::KNOWN.binary_search(&id.0).is_ok(), "{}", id.0);
        }
        assert!(known::KNOWN.binary_search(&9999).is_err());
    }

    #[test]
    fn checks_ranges_as_c() {
        assert!(matches!(resume(-2), Err(Refused::Bad)));
        assert!(matches!(resume(-1), Ok(Some(Resume::AtEnd))));
        assert!(matches!(resume(0), Ok(None)));
        assert!(matches!(max_filesize(-1), Err(Refused::Bad)));
        assert!(matches!(time_limit(-1, 1), Err(Refused::Bad)));
        assert_eq!(
            time_limit(2, 1000).ok().flatten().map(TimeLimit::duration),
            Some(std::time::Duration::from_secs(2))
        );
        let mut set = CSettings::new();
        set.low_speed_limit = 10;
        assert_eq!(low_speed(&set), None);
        set.low_speed_time = 3;
        assert!(low_speed(&set).is_some());
    }
}
