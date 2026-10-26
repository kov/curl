//! Server push through the C ABI: the fields a push callback is given
//! (`struct curl_pushheaders`) and the functions that read them.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char};
use core::ptr;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::multi::PushFields;

use crate::ffi::{self, curl_pushheaders};

/// Marks the fields as what a push callback was given, as C checks its
/// struct's handle.
const MAGIC: u32 = 0x7075_7368;

/// A promise's fields as a push callback reads them: each `name:value`,
/// ended by a zero byte, for the length of the call (C's `push_headers`).
pub(crate) struct Headers {
    magic: u32,
    lines: Vec<Vec<u8>>,
}

impl Headers {
    pub(crate) fn of(fields: &PushFields) -> Result<Headers, OutOfMemory> {
        let mut lines = Vec::new();
        lines
            .try_reserve_exact(fields.len())
            .map_err(|_| OutOfMemory)?;
        for n in 0..fields.len() {
            let field = fields.get(n).expect("one of the fields");
            let mut line = Vec::new();
            line.try_extend_from_slice(field)?;
            line.try_push(0)?;
            lines.try_push(line)?;
        }
        Ok(Headers {
            magic: MAGIC,
            lines,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.lines.len()
    }

    /// The pointer the callback is given.
    pub(crate) fn as_c(&self) -> *mut curl_pushheaders {
        ptr::from_ref(self).cast_mut().cast()
    }
}

/// The fields `h` points to, if it is what a push callback was given.
///
/// # Safety
///
/// `h` is NULL or the pointer a running push callback was given.
unsafe fn headers<'a>(h: *mut curl_pushheaders) -> Option<&'a Headers> {
    // SAFETY: as the caller guarantees: `Headers` outlives the callback.
    let h = unsafe { h.cast::<Headers>().as_ref() }?;
    (h.magic == MAGIC).then_some(h)
}

/// The `num`th field, as `name:value` (`curl_pushheader_bynum`): only
/// from within the push callback.
///
/// # Safety
///
/// `h` is NULL or the pointer a running push callback was given.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_pushheader_bynum(
    h: *mut curl_pushheaders,
    num: usize,
) -> *mut c_char {
    // SAFETY: as the caller guarantees.
    let Some(h) = (unsafe { headers(h) }) else {
        return ptr::null_mut();
    };
    h.lines
        .get(num)
        .map_or(ptr::null_mut(), |line| line.as_ptr().cast_mut().cast())
}
const _: ffi::proto::curl_pushheader_bynum = curl_pushheader_bynum;

/// The value of the first field named `name` (`curl_pushheader_byname`):
/// none for an empty name, `:` alone, or one with a colon past its first
/// byte, which could match inside a value.
///
/// # Safety
///
/// `h` is NULL or the pointer a running push callback was given; `name`
/// is NULL or a string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_pushheader_byname(
    h: *mut curl_pushheaders,
    name: *const c_char,
) -> *mut c_char {
    // SAFETY: as the caller guarantees.
    let Some(h) = (unsafe { headers(h) }) else {
        return ptr::null_mut();
    };
    if name.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a string, as the caller guarantees.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    if name.is_empty() || name == b":" || name[1..].contains(&b':') {
        return ptr::null_mut();
    }
    h.lines
        .iter()
        .find(|line| line.starts_with(name) && line.get(name.len()) == Some(&b':'))
        .map_or(ptr::null_mut(), |line| {
            line[name.len() + 1..].as_ptr().cast_mut().cast()
        })
}
const _: ffi::proto::curl_pushheader_byname = curl_pushheader_byname;

#[cfg(test)]
#[allow(
    clippy::multiple_unsafe_ops_per_block,
    clippy::disallowed_methods,
    reason = "one contract covers each test's calls; a test allocates as it likes"
)]
mod tests {
    use super::*;

    /// The fields read by number and by name as C reads them: a name must
    /// be followed by its colon, and names C would match inside a value
    /// are refused, as is anything but the fields a callback was given.
    #[test]
    fn the_fields_are_read_by_number_and_by_name() {
        let line = |s: &str| [s.as_bytes(), b"\0"].concat();
        let h = Headers {
            magic: MAGIC,
            lines: vec![line(":method:GET"), line(":path:/x"), line("accept:*/*")],
        };
        let text = |p: *mut c_char| {
            // SAFETY: a field's text, ended by its zero byte.
            (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
        };
        // SAFETY: the fields as a callback is given them, live for the
        // calls, and strings for names.
        unsafe {
            let c = h.as_c();
            assert_eq!(
                text(curl_pushheader_bynum(c, 1)).as_deref(),
                Some(&b":path:/x"[..])
            );
            assert!(curl_pushheader_bynum(c, 3).is_null());
            assert_eq!(
                text(curl_pushheader_byname(c, c":path".as_ptr())).as_deref(),
                Some(&b"/x"[..])
            );
            assert_eq!(
                text(curl_pushheader_byname(c, c"accept".as_ptr())).as_deref(),
                Some(&b"*/*"[..])
            );
            assert!(curl_pushheader_byname(c, c":pat".as_ptr()).is_null());
            assert!(curl_pushheader_byname(c, c":".as_ptr()).is_null());
            assert!(curl_pushheader_byname(c, c"".as_ptr()).is_null());
            assert!(curl_pushheader_byname(c, c":path:/".as_ptr()).is_null());
            assert!(curl_pushheader_byname(c, ptr::null()).is_null());
            let null = ptr::null_mut();
            assert!(curl_pushheader_bynum(null, 0).is_null());
            assert!(curl_pushheader_byname(null, c"x".as_ptr()).is_null());
            let other = Headers {
                magic: 0,
                lines: h.lines.clone(),
            };
            assert!(curl_pushheader_bynum(other.as_c(), 0).is_null());
        }
    }
}
