//! Rust's bytes as the C strings and lists of them an LDAP library is
//! handed, for every library bound here, and as the UTF-16 ones WinLDAP's
//! wide calls take in C's Unicode build.

use core::ffi::c_char;
use core::ptr;

use curl_alloc::{OutOfMemory, TryVec as _};

/// `text` with a NUL after it, for the library; none for one with a NUL
/// inside, which the library could not be given.
pub(crate) fn terminated(text: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if text.contains(&0) {
        return Ok(None);
    }
    let mut z = Vec::new();
    z.try_reserve_exact(text.len() + 1)?;
    z.try_extend_from_slice(text)?;
    z.try_push(0)?;
    Ok(Some(z))
}

/// A NULL-terminated list of the C strings `zs` hold.
pub(crate) fn c_list(zs: &[Vec<u8>]) -> Result<Vec<*mut c_char>, OutOfMemory> {
    let mut list = Vec::new();
    list.try_reserve_exact(zs.len() + 1)?;
    for z in zs {
        list.try_push(z.as_ptr().cast_mut().cast::<c_char>())?;
    }
    list.try_push(ptr::null_mut())?;
    Ok(list)
}

/// UTF-8 `text`, which has no NUL, as UTF-16 with a NUL after it, as C's
/// Unicode build converts a string for the library
/// (`curlx_convert_UTF8_to_wchar`); none for text that is not UTF-8,
/// which C cannot convert either.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn wide_terminated(text: &[u8]) -> Result<Option<Vec<u16>>, OutOfMemory> {
    assert!(!text.contains(&0), "the caller refuses a NUL first");
    let Ok(text) = core::str::from_utf8(text) else {
        return Ok(None);
    };
    let mut z = Vec::new();
    z.try_reserve_exact(text.encode_utf16().count() + 1)?;
    for unit in text.encode_utf16() {
        z.try_push(unit)?;
    }
    z.try_push(0)?;
    Ok(Some(z))
}

/// The library's UTF-16 `units` as UTF-8, a unit that is no character
/// as U+FFFD, as C's Unicode build reads them
/// (`curlx_convert_wchar_to_UTF8`, `WideCharToMultiByte`).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn utf8_of_wide(units: &[u16]) -> Result<Vec<u8>, OutOfMemory> {
    let chars = || char::decode_utf16(units.iter().copied()).map(|c| c.unwrap_or('\u{fffd}'));
    let mut text = Vec::new();
    text.try_reserve_exact(chars().map(char::len_utf8).sum())?;
    let mut buf = [0; 4];
    for c in chars() {
        text.try_extend_from_slice(c.encode_utf8(&mut buf).as_bytes())?;
    }
    Ok(text)
}

#[cfg(test)]
#[allow(clippy::disallowed_macros)]
mod tests {
    use super::*;

    /// UTF-8 converts to UTF-16 and back; bytes that are not UTF-8 do not
    /// convert, and a unit that is no character reads as U+FFFD.
    #[test]
    fn text_converts_as_c_s_unicode_build_converts_it() {
        let w = wide_terminated("café 𝄞".as_bytes()).unwrap().unwrap();
        assert_eq!(w.last(), Some(&0));
        assert_eq!(w.len(), "café 𝄞".encode_utf16().count() + 1);
        assert_eq!(
            utf8_of_wide(&w[..w.len() - 1]).unwrap(),
            "café 𝄞".as_bytes()
        );
        assert_eq!(wide_terminated(b"").unwrap(), Some(vec![0]));
        assert_eq!(wide_terminated(b"caf\xe9").unwrap(), None);
        assert_eq!(wide_terminated(b"\xed\xa0\x80").unwrap(), None);
        assert_eq!(
            utf8_of_wide(&[0x61, 0xd800, 0x62]).unwrap(),
            "a\u{fffd}b".as_bytes()
        );
    }
}
