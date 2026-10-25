//! The easy options told by name and id (`curl_easy_option_by_name`,
//! `curl_easy_option_by_id`, `curl_easy_option_next`), over C's table in
//! `easyoptions.rs`.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_uint};
use core::mem::size_of;
use core::ptr;

use crate::easyoptions::ROWS;
use crate::ffi::{self, CURLOT_LONG, CURLoption, curl_easyoption, curl_easytype};

/// A row of the table: an option C names, or the row of nothing that
/// ends it.
#[repr(transparent)]
pub(crate) struct Row(curl_easyoption);

// SAFETY: a row is never written, and its name points at a static C
// string, which is never written either.
unsafe impl Sync for Row {}

impl Row {
    pub(crate) const fn new(
        name: &'static CStr,
        id: CURLoption,
        kind: curl_easytype,
        flags: c_uint,
    ) -> Row {
        Row(curl_easyoption {
            name: name.as_ptr(),
            id,
            r#type: kind,
            flags,
        })
    }

    /// The row that ends the table.
    pub(crate) const END: Row = Row(curl_easyoption {
        name: ptr::null(),
        id: CURLoption(0),
        r#type: CURLOT_LONG,
        flags: 0,
    });

    fn name(&self) -> Option<&'static CStr> {
        // SAFETY: a row's name is NULL or one of the table's static C
        // strings.
        (!self.0.name.is_null()).then(|| unsafe { CStr::from_ptr(self.0.name) })
    }

    fn alias(&self) -> bool {
        self.0.flags & ffi::CURLOT_FLAG_ALIAS as c_uint != 0
    }
}

/// The options: every row but the last.
fn options() -> &'static [Row] {
    &ROWS[..ROWS.len() - 1]
}

/// # Safety
///
/// `name` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_option_by_name(name: *const c_char) -> *const curl_easyoption {
    if name.is_null() {
        return ptr::null();
    }
    // SAFETY: a C string, as the caller guarantees.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    options()
        .iter()
        .find(|r| {
            r.name()
                .is_some_and(|n| n.to_bytes().eq_ignore_ascii_case(name))
        })
        .map_or(ptr::null(), |r| &raw const r.0)
}
const _: ffi::proto::curl_easy_option_by_name = curl_easy_option_by_name;

/// The option `id` names, not an alias of it.
#[unsafe(no_mangle)]
pub extern "C" fn curl_easy_option_by_id(id: CURLoption) -> *const curl_easyoption {
    if id.0 == 0 {
        return ptr::null();
    }
    options()
        .iter()
        .find(|r| r.0.id == id && !r.alias())
        .map_or(ptr::null(), |r| &raw const r.0)
}
const _: ffi::proto::curl_easy_option_by_id = curl_easy_option_by_id;

/// The option after `prev`, the first after none; none after the last,
/// nor after a row not of the table.
#[unsafe(no_mangle)]
pub extern "C" fn curl_easy_option_next(prev: *const curl_easyoption) -> *const curl_easyoption {
    if prev.is_null() {
        return &raw const ROWS[0].0;
    }
    // Where `prev` is in the table, by its address alone: it is not read
    // unless it is a row of it.
    let base = ROWS.as_ptr() as usize;
    let at = (prev as usize).wrapping_sub(base);
    if !at.is_multiple_of(size_of::<Row>()) {
        return ptr::null();
    }
    let next = at / size_of::<Row>() + 1;
    match options().get(next) {
        Some(row) => &raw const row.0,
        None => ptr::null(),
    }
}
const _: ffi::proto::curl_easy_option_next = curl_easy_option_next;

#[cfg(test)]
#[allow(
    clippy::multiple_unsafe_ops_per_block,
    reason = "one contract covers each test's calls"
)]
mod tests {
    use super::*;

    /// A name is found in any case, an id by its option and not an alias
    /// of it, an alias by its own name; the walk goes over every option
    /// once, in C's order.
    #[test]
    fn options_are_found_as_c_finds_them() {
        // SAFETY: a C string.
        let url = unsafe { curl_easy_option_by_name(c"url".as_ptr()) };
        // SAFETY: a row of the table, which lives for ever.
        let url = unsafe { &*url };
        assert_eq!(
            (url.id, url.r#type, url.flags),
            (ffi::CURLOPT_URL, ffi::CURLOT_STRING, 0)
        );
        // SAFETY: as above.
        let alias = unsafe { curl_easy_option_by_name(c"FTPLISTONLY".as_ptr()) };
        // SAFETY: as above.
        let alias = unsafe { &*alias };
        assert_eq!((alias.id, alias.flags), (ffi::CURLOPT_DIRLISTONLY, 1));
        // SAFETY: as above.
        unsafe {
            assert!(curl_easy_option_by_name(c"NOSUCH".as_ptr()).is_null());
            assert!(curl_easy_option_by_name(ptr::null()).is_null());
        }
        // SAFETY: the table's rows live for ever.
        let by_id = unsafe { &*curl_easy_option_by_id(ffi::CURLOPT_DIRLISTONLY) };
        // SAFETY: a static C string.
        assert_eq!(unsafe { CStr::from_ptr(by_id.name) }, c"DIRLISTONLY");
        assert!(curl_easy_option_by_id(CURLoption(0)).is_null());
        assert!(curl_easy_option_by_id(CURLoption(99_999)).is_null());
        let mut walked = 0;
        let mut o = curl_easy_option_next(ptr::null());
        while !o.is_null() {
            walked += 1;
            o = curl_easy_option_next(o);
        }
        assert_eq!(walked, ROWS.len() - 1);
        let first = curl_easy_option_next(ptr::null());
        // SAFETY: a row of the table, its name a static C string.
        let first = unsafe { CStr::from_ptr((*first).name) };
        assert_eq!(first, c"ABSTRACT_UNIX_SOCKET");
        let elsewhere = curl_easyoption {
            name: ptr::null(),
            id: CURLoption(0),
            r#type: CURLOT_LONG,
            flags: 0,
        };
        assert!(curl_easy_option_next(&raw const elsewhere).is_null());
    }
}
