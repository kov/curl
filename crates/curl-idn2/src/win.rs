//! Internationalized host names from Windows' `IdnToAscii` and
//! `IdnToUnicode` (`USE_WIN32_IDN`, `lib/idn.c`'s `win32_idn_to_ascii`
//! and `win32_ascii_to_idn`): a name read as UTF-8 into UTF-16, converted
//! by the system, and written back as UTF-8. The locale and the ANSI code
//! page play no part.

#![allow(unsafe_code)]

use curl_alloc::TryVec as _;
use curl_core::idn::{Idn, IdnFailure};
use windows_sys::Win32::Globalization::{
    CP_UTF8, IdnToAscii, IdnToUnicode, MB_ERR_INVALID_CHARS, MultiByteToWideChar,
    WideCharToMultiByte,
};

/// Windows' IDN conversions in `normaliz`, as C's build with
/// `USE_WIN32_IDN` uses them.
#[derive(Debug)]
pub struct WinIdn;

/// C's `IDN_MAX_LENGTH`: the UTF-16 buffers it converts names in hold this
/// many units, the terminating NUL among them.
const IDN_MAX_LENGTH: usize = 255;

/// A name in UTF-16 with its NUL, as C passes it to the conversion.
struct Wide {
    units: [u16; IDN_MAX_LENGTH],
    /// How many of `units` hold the name, its NUL counted.
    len: usize,
}

impl Wide {
    fn as_slice(&self) -> &[u16] {
        &self.units[..self.len]
    }
}

/// `name`, read as UTF-8 up to a NUL as C's `strlen` reads it, in UTF-16
/// with its NUL. None for a name that is not UTF-8, or does not fit C's
/// buffer with the NUL.
fn utf16(name: &[u8]) -> Result<Option<Wide>, IdnFailure> {
    let name = name.split(|&b| b == 0).next().unwrap_or_default();
    // C hands the converter its C string with `-1`, the NUL converted
    // with the rest: the same as the bytes and their NUL, counted.
    let mut z = Vec::new();
    z.try_reserve_exact(name.len() + 1)
        .map_err(|_| IdnFailure::OutOfMemory)?;
    z.try_extend_from_slice(name)?;
    z.try_push(0)?;
    let Ok(z_len) = i32::try_from(z.len()) else {
        return Ok(None);
    };
    let mut wide = Wide {
        units: [0; IDN_MAX_LENGTH],
        len: 0,
    };
    // SAFETY: `z` holds `z_len` bytes, and `wide.units` room for
    // `IDN_MAX_LENGTH` units, both alive across the call; the converter
    // writes no more than that room and fails if the name needs more.
    let n = unsafe {
        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            z.as_ptr(),
            z_len,
            wide.units.as_mut_ptr(),
            IDN_MAX_LENGTH as i32,
        )
    };
    let Ok(n @ 1..) = usize::try_from(n) else {
        return Ok(None);
    };
    wide.len = n;
    Ok(Some(wide))
}

/// `units` written as UTF-8 (`idn_curlx_convert_wchar_to_UTF8`), up to the
/// NUL the conversion kept, as C then uses it as a C string. C reports a
/// conversion that makes nothing as it reports running out of memory.
fn utf8(units: &[u16]) -> Result<Vec<u8>, IdnFailure> {
    let count = units.len() as i32;
    // SAFETY: `units` holds `count` units; with no output buffer the
    // converter only measures.
    let bytes = unsafe {
        WideCharToMultiByte(
            CP_UTF8,
            0,
            units.as_ptr(),
            count,
            core::ptr::null_mut(),
            0,
            core::ptr::null(),
            core::ptr::null_mut(),
        )
    };
    let Ok(bytes @ 1..) = usize::try_from(bytes) else {
        return Err(IdnFailure::OutOfMemory);
    };
    let mut out = Vec::new();
    out.try_resize(bytes, 0)?;
    // SAFETY: `units` as above; `out` has room for the `bytes` the
    // converter measured, and lives across the call.
    let written = unsafe {
        WideCharToMultiByte(
            CP_UTF8,
            0,
            units.as_ptr(),
            count,
            out.as_mut_ptr(),
            bytes as i32,
            core::ptr::null(),
            core::ptr::null_mut(),
        )
    };
    if written == 0 {
        return Err(IdnFailure::OutOfMemory);
    }
    let end = out.iter().position(|&b| b == 0).unwrap_or(out.len());
    out.truncate(end);
    Ok(out)
}

/// The system's conversion `convert` of `name`, between C's two buffers.
fn converted(
    name: &[u8],
    convert: unsafe extern "system" fn(u32, *const u16, i32, *mut u16, i32) -> i32,
) -> Result<Vec<u8>, IdnFailure> {
    let Some(wide) = utf16(name)? else {
        return Err(IdnFailure::Malformed);
    };
    let input = wide.as_slice();
    let mut out = [0u16; IDN_MAX_LENGTH];
    // SAFETY: `input` holds the name and its NUL, `out` room for
    // `IDN_MAX_LENGTH` units, both alive across the call; the system
    // writes no more than that room, and fails if the result needs more.
    // No flags, as C passes none.
    let chars = unsafe {
        convert(
            0,
            input.as_ptr(),
            input.len() as i32,
            out.as_mut_ptr(),
            IDN_MAX_LENGTH as i32,
        )
    };
    let Ok(chars @ 1..) = usize::try_from(chars) else {
        return Err(IdnFailure::Malformed);
    };
    utf8(&out[..chars.min(IDN_MAX_LENGTH)])
}

impl Idn for WinIdn {
    fn to_ascii(&self, name: &[u8]) -> Result<Vec<u8>, IdnFailure> {
        converted(name, IdnToAscii)
    }

    fn to_unicode(&self, ascii: &[u8]) -> Result<Vec<u8>, IdnFailure> {
        converted(ascii, IdnToUnicode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names convert as C's build with `USE_WIN32_IDN` converts them: read
    /// as UTF-8 whatever the code page, refused if they are not UTF-8 or
    /// do not fit C's buffers, and shown back in Unicode from punycode.
    #[test]
    fn names_convert_as_c_s_winidn_build_converts_them() {
        let idn = WinIdn;
        assert_eq!(
            idn.to_ascii("www.åäö.se".as_bytes()),
            Ok(b"www.xn--4cab6c.se".to_vec())
        );
        assert_eq!(
            idn.to_ascii("räksmörgås.se".as_bytes()),
            Ok(b"xn--rksmrgs-5wao1o.se".to_vec())
        );
        // Ending at a NUL, as C's string does.
        assert_eq!(
            idn.to_ascii("åäö.test\0ignored".as_bytes()),
            Ok(b"xn--4cab6c.test".to_vec())
        );
        // The ANSI code page's å is no UTF-8.
        assert_eq!(idn.to_ascii(b"\xe5.test"), Err(IdnFailure::Malformed));
        assert_eq!(
            idn.to_ascii(b"invalid-utf8-\xe2\x90.local"),
            Err(IdnFailure::Malformed)
        );
        // C's buffers hold 254 units and the NUL; one more does not fit,
        // nor does a character outside the BMP that needs two where one is
        // left.
        let len = |name: &[u8]| utf16(name).map(|w| w.map(|w| w.len));
        let fits = "å".repeat(254);
        assert_eq!(len(fits.as_bytes()), Ok(Some(255)));
        assert_eq!(len((fits.clone() + "å").as_bytes()), Ok(None));
        let two_short = "å".repeat(253);
        assert_eq!(len((two_short.clone() + "a").as_bytes()), Ok(Some(255)));
        assert_eq!(len((two_short + "\u{1f600}").as_bytes()), Ok(None));
        // Read strictly: bytes that are not UTF-8 are refused, not
        // replaced, before the system sees them (`MB_ERR_INVALID_CHARS`).
        assert_eq!(len(b"\xe5.test"), Ok(None));
        assert_eq!(len(b"\xed\xa0\x80.test"), Ok(None));
        let long = "å".repeat(IDN_MAX_LENGTH);
        assert_eq!(idn.to_ascii(long.as_bytes()), Err(IdnFailure::Malformed));
        // The result, too, fits in 254 units and the NUL, or is refused.
        let near =
            |m: usize| ("a".repeat(60) + ".").repeat(3) + &"a".repeat(m) + ".å" + &"a".repeat(20);
        assert_eq!(idn.to_ascii(near(42).as_bytes()).map(|a| a.len()), Ok(254));
        assert_eq!(
            idn.to_ascii(near(43).as_bytes()),
            Err(IdnFailure::Malformed)
        );
        assert_eq!(
            idn.to_unicode(b"www.xn--4cab6c.se"),
            Ok("www.åäö.se".as_bytes().to_vec())
        );
        assert_eq!(
            idn.to_unicode(b"xn--rksmrgs-5wao1o.se"),
            Ok("räksmörgås.se".as_bytes().to_vec())
        );
        assert_eq!(idn.to_unicode(b"example.com"), Ok(b"example.com".to_vec()));
    }
}
