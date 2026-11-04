//! Internationalized host names from ICU's IDNA on Apple's systems
//! (`USE_APPLE_IDN`, `lib/idn.c`'s `mac_idn_to_ascii` and
//! `mac_ascii_to_idn`): a name in the locale's characters converted to
//! UTF-8 with iconv, then to its ASCII form by UTS #46 non-transitional
//! processing with the bidi check; a name in punycode shown back the same
//! way.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_void};

use curl_alloc::TryVec as _;
use curl_core::idn::{Idn, IdnFailure};

/// ICU's IDNA from the system's `icucore`, as C's build with
/// `USE_APPLE_IDN` uses it.
#[derive(Debug)]
pub struct AppleIdn;

/// C's `MAX_HOST_LENGTH`: the names it converts are shorter, and the
/// buffers it converts them into are this long.
const MAX_HOST_LENGTH: usize = 512;

/// `UIDNA_CHECK_BIDI`, `UIDNA_NONTRANSITIONAL_TO_ASCII` and
/// `UIDNA_NONTRANSITIONAL_TO_UNICODE` (`unicode/uidna.h`).
const CHECK_BIDI: u32 = 4;
const NONTRANSITIONAL_TO_ASCII: u32 = 0x10;
const NONTRANSITIONAL_TO_UNICODE: u32 = 0x20;

/// `U_ZERO_ERROR`; any code above it is a failure (`U_FAILURE`).
const U_ZERO_ERROR: c_int = 0;

/// `UIDNAInfo` (`unicode/uidna.h`): its size, set before a call
/// (`UIDNA_INFO_INITIALIZER`), and the errors the conversion found.
#[repr(C)]
struct UidnaInfo {
    size: i16,
    is_transitional_different: i8,
    reserved_b3: i8,
    errors: u32,
    reserved_i2: i32,
    reserved_i3: i32,
}

impl UidnaInfo {
    fn new() -> UidnaInfo {
        UidnaInfo {
            size: size_of::<UidnaInfo>() as i16,
            is_transitional_different: 0,
            reserved_b3: 0,
            errors: 0,
            reserved_i2: 0,
            reserved_i3: 0,
        }
    }
}

/// `nl_langinfo`'s item for the locale's character set (`<langinfo.h>`).
const CODESET: c_int = 0;

/// `ENOMEM`, the errno iconv leaves when it runs out of memory.
const ENOMEM: c_int = 12;

#[link(name = "icucore")]
unsafe extern "C" {
    fn uidna_openUTS46(options: u32, err: *mut c_int) -> *mut c_void;
    fn uidna_close(idna: *mut c_void);
    fn uidna_nameToASCII_UTF8(
        idna: *const c_void,
        name: *const c_char,
        length: i32,
        dest: *mut c_char,
        capacity: i32,
        info: *mut UidnaInfo,
        err: *mut c_int,
    ) -> i32;
    fn uidna_nameToUnicodeUTF8(
        idna: *const c_void,
        name: *const c_char,
        length: i32,
        dest: *mut c_char,
        capacity: i32,
        info: *mut UidnaInfo,
        err: *mut c_int,
    ) -> i32;
}

#[link(name = "iconv")]
unsafe extern "C" {
    fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void;
    fn iconv(
        cd: *mut c_void,
        inbuf: *mut *mut c_char,
        inbytesleft: *mut usize,
        outbuf: *mut *mut c_char,
        outbytesleft: *mut usize,
    ) -> usize;
    fn iconv_close(cd: *mut c_void) -> c_int;
}

unsafe extern "C" {
    fn nl_langinfo(item: c_int) -> *const c_char;
}

/// An ICU IDNA object, closed as it goes.
struct Uidna(*mut c_void);

impl Uidna {
    /// UTS #46 processing with the bidi check and `mode`, or none if ICU
    /// cannot make one.
    fn open(mode: u32) -> Option<Uidna> {
        let mut err = U_ZERO_ERROR;
        // SAFETY: options and an error code ICU sets; it returns an object
        // of its own, or sets the code to a failure.
        let idna = unsafe { uidna_openUTS46(CHECK_BIDI | mode, &raw mut err) };
        (err <= U_ZERO_ERROR && !idna.is_null()).then(|| Uidna(idna))
    }
}

impl Drop for Uidna {
    fn drop(&mut self) {
        // SAFETY: an object `uidna_openUTS46` made, closed once, here.
        unsafe { uidna_close(self.0) };
    }
}

/// `name`, in the locale's character set, as UTF-8 (`iconv_to_utf8`):
/// C converts it into a buffer of `MAX_HOST_LENGTH`, so a longer result is
/// a malformed name, as iconv's `E2BIG` is there.
fn to_utf8(name: &[u8]) -> Result<Vec<u8>, IdnFailure> {
    // SAFETY: the locale's character set, a string the C library keeps.
    let codeset = unsafe { nl_langinfo(CODESET) };
    // SAFETY: two C strings naming character sets.
    let cd = unsafe { iconv_open(c"UTF-8".as_ptr(), codeset) };
    if cd as isize == -1 {
        return Err(if errno() == ENOMEM {
            IdnFailure::OutOfMemory
        } else {
            // C's `CURLE_FAILED_INIT`, which the transfer reports as it
            // reports a name that does not convert.
            IdnFailure::Malformed
        });
    }
    let mut out = [0u8; MAX_HOST_LENGTH];
    let mut in_ptr = name.as_ptr().cast_mut().cast::<c_char>();
    let mut in_left = name.len();
    let mut out_ptr = out.as_mut_ptr().cast::<c_char>();
    let mut out_left = out.len();
    // SAFETY: a descriptor iconv opened; the input and output pointers and
    // their room describe `name` and `out`, which outlive the call. iconv
    // does not write through the input pointer.
    let rc = unsafe {
        iconv(
            cd,
            &raw mut in_ptr,
            &raw mut in_left,
            &raw mut out_ptr,
            &raw mut out_left,
        )
    };
    let failed_errno = (rc == usize::MAX).then(errno);
    // SAFETY: the descriptor, closed once.
    unsafe { iconv_close(cd) };
    if let Some(e) = failed_errno {
        return Err(if e == ENOMEM {
            IdnFailure::OutOfMemory
        } else {
            IdnFailure::Malformed
        });
    }
    let made = out.len() - out_left;
    let mut v = Vec::new();
    v.try_extend_from_slice(&out[..made])?;
    Ok(v)
}

/// The thread's errno, as C reads it after iconv.
fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// What ICU wrote into `buffer`, up to its first NUL, as C's `strdup`
/// copies it.
fn copied(buffer: &[u8]) -> Result<Vec<u8>, IdnFailure> {
    let text = CStr::from_bytes_until_nul(buffer)
        .map(CStr::to_bytes)
        .unwrap_or(buffer);
    let mut v = Vec::new();
    v.try_extend_from_slice(text)?;
    Ok(v)
}

impl Idn for AppleIdn {
    fn to_ascii(&self, name: &[u8]) -> Result<Vec<u8>, IdnFailure> {
        // C measures the name with `strlen`: a NUL ends it.
        let name = name.split(|&b| b == 0).next().unwrap_or_default();
        if name.len() >= MAX_HOST_LENGTH {
            return Err(IdnFailure::Malformed);
        }
        let utf8 = to_utf8(name)?;
        let Some(idna) = Uidna::open(NONTRANSITIONAL_TO_ASCII) else {
            return Err(IdnFailure::Malformed);
        };
        let mut info = UidnaInfo::new();
        let mut err = U_ZERO_ERROR;
        let mut buffer = [0u8; MAX_HOST_LENGTH];
        // SAFETY: the IDNA object; the UTF-8 name and its length; a buffer
        // with room for one less than its size, as C leaves its last byte
        // for the NUL; and the info and error code ICU sets.
        unsafe {
            uidna_nameToASCII_UTF8(
                idna.0,
                utf8.as_ptr().cast(),
                utf8.len() as i32,
                buffer.as_mut_ptr().cast(),
                (buffer.len() - 1) as i32,
                &raw mut info,
                &raw mut err,
            )
        };
        drop(idna);
        if err > U_ZERO_ERROR || info.errors != 0 {
            return Err(IdnFailure::Malformed);
        }
        copied(&buffer)
    }

    fn to_unicode(&self, ascii: &[u8]) -> Result<Vec<u8>, IdnFailure> {
        let ascii = ascii.split(|&b| b == 0).next().unwrap_or_default();
        if ascii.len() >= MAX_HOST_LENGTH {
            return Err(IdnFailure::Malformed);
        }
        let Some(idna) = Uidna::open(NONTRANSITIONAL_TO_UNICODE) else {
            return Err(IdnFailure::Malformed);
        };
        let mut info = UidnaInfo::new();
        let mut err = U_ZERO_ERROR;
        let mut buffer = [0u8; MAX_HOST_LENGTH];
        // SAFETY: as in `to_ascii`, the name given with its length rather
        // than C's NUL; ICU reads no further than the length.
        unsafe {
            uidna_nameToUnicodeUTF8(
                idna.0,
                ascii.as_ptr().cast(),
                ascii.len() as i32,
                buffer.as_mut_ptr().cast(),
                (buffer.len() - 1) as i32,
                &raw mut info,
                &raw mut err,
            )
        };
        drop(idna);
        // Unlike the other way, C does not look at the info's errors here.
        if err > U_ZERO_ERROR {
            return Err(IdnFailure::Malformed);
        }
        copied(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names convert as C's build with `USE_APPLE_IDN` converts them, in a
    /// UTF-8 locale; one ICU refuses, or too long for C's buffer, does not;
    /// and punycode shows back in Unicode.
    #[test]
    fn names_convert_as_c_s_apple_build_converts_them() {
        // SAFETY: a C string naming a locale; no other test of this crate
        // reads the locale while it changes.
        let set = unsafe { libc::setlocale(libc::LC_CTYPE, c"en_US.UTF-8".as_ptr()) };
        assert!(!set.is_null(), "the system has en_US.UTF-8");
        let idn = AppleIdn;
        assert_eq!(
            idn.to_ascii("www.åäö.se".as_bytes()),
            Ok(b"www.xn--4cab6c.se".to_vec())
        );
        // Non-transitional: ß is kept, not mapped to "ss".
        assert_eq!(
            idn.to_ascii("www.große.de".as_bytes()),
            Ok(b"www.xn--groe-xna.de".to_vec())
        );
        assert_eq!(
            idn.to_ascii("a\u{308}.test".as_bytes()),
            idn.to_ascii("\u{e4}.test".as_bytes())
        );
        assert_eq!(
            idn.to_ascii(b"invalid-utf8-\xe2\x90.local"),
            Err(IdnFailure::Malformed)
        );
        // ICU converts these, saying what is wrong with them only in the
        // info's errors, which C refuses them for: an empty label, and
        // one that starts with a hyphen.
        assert_eq!(
            idn.to_ascii("å..test".as_bytes()),
            Err(IdnFailure::Malformed)
        );
        assert_eq!(
            idn.to_ascii("-å.test".as_bytes()),
            Err(IdnFailure::Malformed)
        );
        let long = "å".repeat(MAX_HOST_LENGTH / 2);
        assert_eq!(idn.to_ascii(long.as_bytes()), Err(IdnFailure::Malformed));
        assert_eq!(
            idn.to_unicode(b"www.xn--4cab6c.se"),
            Ok("www.åäö.se".as_bytes().to_vec())
        );
    }
}
