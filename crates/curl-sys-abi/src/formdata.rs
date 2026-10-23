//! The form API (`lib/formdata.c`): `curl_formadd` builds a chain of
//! `curl_httppost` the application holds, `curl_formfree` frees it, and
//! `curl_formget` reads it whole. A handle posting one
//! (`CURLOPT_HTTPPOST`) turns it into a `curl_mime` tree the first time a
//! request needs it, through the tree's own API, as `Curl_getformdata`
//! does, and keeps that tree until the option is set again.
//!
//! The chain's nodes and the strings it copies come from the allocator the
//! application installed, as C's do, and only `curl_formfree` frees them.

#![allow(unsafe_code)]

use core::ffi::{CStr, VaList, c_char, c_int, c_long, c_void};
use core::ptr::{self, NonNull};

use curl_alloc::TryVec as _;

use crate::ffi::{
    self, CURL_FORMADD_ILLEGAL_ARRAY, CURL_FORMADD_INCOMPLETE, CURL_FORMADD_MEMORY,
    CURL_FORMADD_NULL, CURL_FORMADD_OK, CURL_FORMADD_OPTION_TWICE, CURL_FORMADD_UNKNOWN_OPTION,
    CURL_HTTPPOST_BUFFER, CURL_HTTPPOST_CALLBACK, CURL_HTTPPOST_FILENAME, CURL_HTTPPOST_LARGE,
    CURL_HTTPPOST_PTRBUFFER, CURL_HTTPPOST_PTRCONTENTS, CURL_HTTPPOST_PTRNAME,
    CURL_HTTPPOST_READFILE, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_OK, CURLE_OUT_OF_MEMORY,
    CURLFORMcode, CURLcode, CURLformoption, curl_formget_callback, curl_forms, curl_httppost,
    curl_mime, curl_off_t, curl_read_callback, curl_slist,
};
use crate::{mime, root};

const PTRNAME: c_long = CURL_HTTPPOST_PTRNAME as c_long;
const FILENAME: c_long = CURL_HTTPPOST_FILENAME as c_long;
const PTRCONTENTS: c_long = CURL_HTTPPOST_PTRCONTENTS as c_long;
const READFILE: c_long = CURL_HTTPPOST_READFILE as c_long;
const PTRBUFFER: c_long = CURL_HTTPPOST_PTRBUFFER as c_long;
const CALLBACK: c_long = CURL_HTTPPOST_CALLBACK as c_long;
const BUFFER: c_long = CURL_HTTPPOST_BUFFER as c_long;
const LARGE: c_long = CURL_HTTPPOST_LARGE as c_long;

/// The type a file gets when its name suggests none
/// (`FILE_CONTENTTYPE_DEFAULT`).
const DEFAULT_TYPE: &CStr = c"application/octet-stream";

/// A value `curl_formadd` was given (C's `bufref`): the application's,
/// or a copy from the allocator, which the chain owns once it is made.
#[derive(Clone, Copy)]
enum Field {
    None,
    Lent(*mut c_char),
    Owned(*mut c_char),
}

impl Field {
    fn ptr(self) -> *mut c_char {
        match self {
            Field::None => ptr::null_mut(),
            Field::Lent(p) | Field::Owned(p) => p,
        }
    }

    fn is_set(self) -> bool {
        !self.ptr().is_null()
    }

    /// Point it at `p`, the application's, letting go of a copy it held.
    fn lend(&mut self, p: *mut c_char) {
        self.free();
        *self = Field::Lent(p);
    }

    /// Make it a copy of `len` bytes at `p` and a zero byte
    /// (`Curl_bufref_memdup0`): whether the copy could be made.
    ///
    /// # Safety
    ///
    /// `p` points to `len` readable bytes.
    unsafe fn copy(&mut self, p: *const c_char, len: usize) -> bool {
        // SAFETY: as the caller guarantees.
        let copy = unsafe { memdup0(p, len) };
        if copy.is_null() {
            return false;
        }
        self.free();
        *self = Field::Owned(copy);
        true
    }

    /// Make it a copy of the C string `p`.
    ///
    /// # Safety
    ///
    /// `p` is a C string.
    unsafe fn copy_c(&mut self, p: *const c_char) -> bool {
        // SAFETY: as the caller guarantees.
        let len = unsafe { libc::strlen(p) };
        // SAFETY: as above, `len` bytes before its zero.
        unsafe { self.copy(p, len) }
    }

    /// Let go of a copy it holds (`Curl_bufref_free`).
    fn free(&mut self) {
        if let Field::Owned(p) = *self {
            // SAFETY: a copy from the allocator, which nothing else holds.
            unsafe { root::allocator().free(p.cast()) };
        }
        *self = Field::None;
    }
}

/// `len` bytes at `p` and a zero byte, from the allocator; NULL if it
/// cannot give them.
///
/// # Safety
///
/// `p` points to `len` readable bytes.
unsafe fn memdup0(p: *const c_char, len: usize) -> *mut c_char {
    let Some(size) = len.checked_add(1) else {
        return ptr::null_mut();
    };
    let copy = root::allocator().malloc(size).cast::<c_char>();
    if !copy.is_null() {
        // SAFETY: `copy` has room for `len + 1` bytes, and `p` holds `len`;
        // they are disjoint, one being fresh.
        unsafe { ptr::copy_nonoverlapping(p, copy, len) };
        // SAFETY: as above, the last of the `len + 1` bytes.
        unsafe { copy.wrapping_add(len).write(0) };
    }
    copy
}

/// What one form part is being given (`struct FormInfo`).
struct FormInfo {
    name: Field,
    namelength: usize,
    value: Field,
    contentslength: curl_off_t,
    contenttype: Field,
    showfilename: Field,
    buffer: *mut c_char,
    bufferlength: usize,
    flags: c_long,
    contentheader: *mut curl_slist,
    userp: *mut c_void,
}

impl FormInfo {
    fn new() -> FormInfo {
        FormInfo {
            name: Field::None,
            namelength: 0,
            value: Field::None,
            contentslength: 0,
            contenttype: Field::None,
            showfilename: Field::None,
            buffer: ptr::null_mut(),
            bufferlength: 0,
            flags: 0,
            contentheader: ptr::null_mut(),
            userp: ptr::null_mut(),
        }
    }
}

/// Where the next option's value comes from: the call's own arguments,
/// or the value of the `curl_forms` entry just read.
///
/// # Safety
///
/// Without an entry, the next argument is a pointer.
unsafe fn ptr_arg<T>(entry: Option<*const c_char>, args: &mut VaList<'_>) -> *mut T {
    match entry {
        Some(v) => v.cast_mut().cast(),
        // SAFETY: as the caller guarantees.
        None => unsafe { args.next_arg::<*mut T>() },
    }
}

/// A `long` option's value; in an array, the pointer's bits.
///
/// # Safety
///
/// Without an entry, the next argument is a `long`.
unsafe fn long_arg(entry: Option<*const c_char>, args: &mut VaList<'_>) -> c_long {
    match entry {
        Some(v) => v as usize as c_long,
        // SAFETY: as the caller guarantees.
        None => unsafe { args.next_arg::<c_long>() },
    }
}

/// A `curl_off_t` option's value; in an array, the pointer's bits.
///
/// # Safety
///
/// Without an entry, the next argument is a `curl_off_t`.
unsafe fn off_arg(entry: Option<*const c_char>, args: &mut VaList<'_>) -> curl_off_t {
    match entry {
        Some(v) => v as usize as curl_off_t,
        // SAFETY: as the caller guarantees.
        None => unsafe { args.next_arg::<curl_off_t>() },
    }
}

/// A new part after the last, given one more file or one more type for
/// the same field (`forminfo_add`): it is a file's.
fn add_after(forms: &mut Vec<FormInfo>, form: FormInfo) -> Result<(), FormInfo> {
    let mut form = form;
    form.flags |= FILENAME;
    if forms.try_reserve(1).is_err() {
        return Err(form);
    }
    if forms.try_push(form).is_err() {
        unreachable!("reserved above");
    }
    Ok(())
}

/// Read the options of one `curl_formadd` call into `forms`, the first
/// part already there (the loop of `formadd`).
///
/// # Safety
///
/// `args` holds options and values as `curl_formadd` documents them;
/// a `CURLFORM_ARRAY` points to entries ended by `CURLFORM_END`.
unsafe fn read_options(forms: &mut Vec<FormInfo>, args: &mut VaList<'_>) -> CURLFORMcode {
    let mut array: *const curl_forms = ptr::null();
    loop {
        let (option, entry) = if array.is_null() {
            // SAFETY: as the caller guarantees: an `int` comes next.
            let option = CURLformoption(unsafe { args.next_arg::<c_int>() });
            if option == ffi::CURLFORM_END {
                return CURL_FORMADD_OK;
            }
            (option, None)
        } else {
            // SAFETY: as the caller guarantees, the array goes on to its end.
            let at = unsafe { array.read() };
            // SAFETY: as above, one more entry at least follows one that
            // is not the end.
            array = unsafe { array.add(1) };
            if at.option == ffi::CURLFORM_END {
                array = ptr::null();
                continue;
            }
            (at.option, Some(at.value))
        };
        let curr = forms.last_mut().expect("a part is being given");
        let code = match option {
            ffi::CURLFORM_ARRAY => {
                if entry.is_some() {
                    // No array within an array.
                    CURL_FORMADD_ILLEGAL_ARRAY
                } else {
                    // SAFETY: as the caller guarantees.
                    array = unsafe { args.next_arg::<*const curl_forms>() };
                    if array.is_null() {
                        CURL_FORMADD_NULL
                    } else {
                        CURL_FORMADD_OK
                    }
                }
            }
            ffi::CURLFORM_PTRNAME | ffi::CURLFORM_COPYNAME => {
                if option == ffi::CURLFORM_PTRNAME {
                    curr.flags |= PTRNAME;
                }
                if curr.name.is_set() {
                    CURL_FORMADD_OPTION_TWICE
                } else {
                    // SAFETY: as the caller guarantees.
                    let v = unsafe { ptr_arg::<c_char>(entry, args) };
                    if v.is_null() {
                        CURL_FORMADD_NULL
                    } else {
                        // Copied once the call is checked.
                        curr.name.lend(v);
                        CURL_FORMADD_OK
                    }
                }
            }
            ffi::CURLFORM_NAMELENGTH => {
                if curr.namelength != 0 {
                    CURL_FORMADD_OPTION_TWICE
                } else {
                    // SAFETY: as the caller guarantees.
                    curr.namelength = unsafe { long_arg(entry, args) } as usize;
                    CURL_FORMADD_OK
                }
            }
            ffi::CURLFORM_PTRCONTENTS | ffi::CURLFORM_COPYCONTENTS => {
                if option == ffi::CURLFORM_PTRCONTENTS {
                    curr.flags |= PTRCONTENTS;
                }
                if curr.value.is_set() {
                    CURL_FORMADD_OPTION_TWICE
                } else {
                    // SAFETY: as the caller guarantees.
                    let v = unsafe { ptr_arg::<c_char>(entry, args) };
                    if v.is_null() {
                        CURL_FORMADD_NULL
                    } else {
                        curr.value.lend(v);
                        CURL_FORMADD_OK
                    }
                }
            }
            ffi::CURLFORM_CONTENTSLENGTH => {
                // SAFETY: as the caller guarantees.
                let len = unsafe { long_arg(entry, args) };
                if len < 0 {
                    CURL_FORMADD_INCOMPLETE
                } else {
                    curr.contentslength = len;
                    CURL_FORMADD_OK
                }
            }
            ffi::CURLFORM_CONTENTLEN => {
                // SAFETY: as the caller guarantees.
                let len = unsafe { off_arg(entry, args) };
                if len < 0 {
                    CURL_FORMADD_INCOMPLETE
                } else {
                    curr.flags |= LARGE;
                    curr.contentslength = len;
                    CURL_FORMADD_OK
                }
            }
            ffi::CURLFORM_FILECONTENT => {
                if curr.flags & (PTRCONTENTS | READFILE) != 0 {
                    CURL_FORMADD_OPTION_TWICE
                } else {
                    // SAFETY: as the caller guarantees.
                    let v = unsafe { ptr_arg::<c_char>(entry, args) };
                    if v.is_null() {
                        CURL_FORMADD_NULL
                    // SAFETY: the application's file name is a C string.
                    } else if !unsafe { curr.value.copy_c(v) } {
                        CURL_FORMADD_MEMORY
                    } else {
                        curr.flags |= READFILE;
                        CURL_FORMADD_OK
                    }
                }
            }
            ffi::CURLFORM_FILE => {
                // SAFETY: as the caller guarantees.
                let v = unsafe { ptr_arg::<c_char>(entry, args) };
                if curr.value.is_set() {
                    if curr.flags & FILENAME == 0 {
                        CURL_FORMADD_OPTION_TWICE
                    } else if v.is_null() {
                        CURL_FORMADD_NULL
                    } else {
                        // One more file for the same field.
                        let mut form = FormInfo::new();
                        // SAFETY: the application's file name is a C
                        // string.
                        if !unsafe { form.value.copy_c(v) } {
                            CURL_FORMADD_MEMORY
                        } else {
                            match add_after(forms, form) {
                                Ok(()) => CURL_FORMADD_OK,
                                Err(mut form) => {
                                    form.value.free();
                                    CURL_FORMADD_MEMORY
                                }
                            }
                        }
                    }
                } else if v.is_null() {
                    CURL_FORMADD_NULL
                // SAFETY: as above.
                } else if !unsafe { curr.value.copy_c(v) } {
                    CURL_FORMADD_MEMORY
                } else {
                    curr.flags |= FILENAME;
                    CURL_FORMADD_OK
                }
            }
            ffi::CURLFORM_BUFFERPTR => {
                curr.flags |= PTRBUFFER | BUFFER;
                if !curr.buffer.is_null() {
                    CURL_FORMADD_OPTION_TWICE
                } else {
                    // SAFETY: as the caller guarantees.
                    let v = unsafe { ptr_arg::<c_char>(entry, args) };
                    if v.is_null() {
                        CURL_FORMADD_NULL
                    } else {
                        curr.buffer = v;
                        // A value, for the part to be whole.
                        curr.value.lend(v);
                        CURL_FORMADD_OK
                    }
                }
            }
            ffi::CURLFORM_BUFFERLENGTH => {
                if curr.bufferlength != 0 {
                    CURL_FORMADD_OPTION_TWICE
                } else {
                    // SAFETY: as the caller guarantees.
                    curr.bufferlength = unsafe { long_arg(entry, args) } as usize;
                    CURL_FORMADD_OK
                }
            }
            ffi::CURLFORM_STREAM => {
                curr.flags |= CALLBACK;
                if !curr.userp.is_null() {
                    CURL_FORMADD_OPTION_TWICE
                } else {
                    // SAFETY: as the caller guarantees.
                    let v = unsafe { ptr_arg::<c_char>(entry, args) };
                    if v.is_null() {
                        CURL_FORMADD_NULL
                    } else {
                        curr.userp = v.cast();
                        // A value, for the part to be whole.
                        curr.value.lend(v);
                        CURL_FORMADD_OK
                    }
                }
            }
            ffi::CURLFORM_CONTENTTYPE => {
                // SAFETY: as the caller guarantees.
                let v = unsafe { ptr_arg::<c_char>(entry, args) };
                if curr.contenttype.is_set() {
                    if curr.flags & FILENAME == 0 {
                        CURL_FORMADD_OPTION_TWICE
                    } else if v.is_null() {
                        CURL_FORMADD_NULL
                    } else {
                        // The type of one more file, to come.
                        let mut form = FormInfo::new();
                        // SAFETY: the application's type is a C string.
                        if !unsafe { form.contenttype.copy_c(v) } {
                            CURL_FORMADD_MEMORY
                        } else {
                            match add_after(forms, form) {
                                Ok(()) => CURL_FORMADD_OK,
                                Err(mut form) => {
                                    form.contenttype.free();
                                    CURL_FORMADD_MEMORY
                                }
                            }
                        }
                    }
                } else if v.is_null() {
                    CURL_FORMADD_NULL
                // SAFETY: as above.
                } else if !unsafe { curr.contenttype.copy_c(v) } {
                    CURL_FORMADD_MEMORY
                } else {
                    CURL_FORMADD_OK
                }
            }
            ffi::CURLFORM_CONTENTHEADER => {
                // SAFETY: as the caller guarantees.
                let list = unsafe { ptr_arg::<curl_slist>(entry, args) };
                if !curr.contentheader.is_null() {
                    CURL_FORMADD_OPTION_TWICE
                } else {
                    curr.contentheader = list;
                    CURL_FORMADD_OK
                }
            }
            ffi::CURLFORM_FILENAME | ffi::CURLFORM_BUFFER => {
                // SAFETY: as the caller guarantees.
                let v = unsafe { ptr_arg::<c_char>(entry, args) };
                if curr.showfilename.is_set() {
                    CURL_FORMADD_OPTION_TWICE
                } else if v.is_null() {
                    // C reads the length of NULL; it is refused here.
                    CURL_FORMADD_NULL
                // SAFETY: the application's name is a C string.
                } else if !unsafe { curr.showfilename.copy_c(v) } {
                    CURL_FORMADD_MEMORY
                } else {
                    CURL_FORMADD_OK
                }
            }
            _ => CURL_FORMADD_UNKNOWN_OPTION,
        };
        if code != CURL_FORMADD_OK {
            return code;
        }
    }
}

/// Make a field the chain's own copy of what it was lent: `len` bytes, or
/// up to its zero byte for 0 (`forminfo_copyfield`).
fn copy_field(field: &mut Field, len: usize) -> bool {
    let p = field.ptr();
    if p.is_null() {
        return true;
    }
    let len = if len == 0 {
        // SAFETY: a value lent without a length is a C string.
        unsafe { libc::strlen(p) }
    } else {
        len
    };
    // SAFETY: the application's value holds `len` bytes, by its length
    // or its zero byte.
    unsafe { field.copy(p, len) }
}

/// A chain node for `form`, after `parent` in its field's list of files,
/// or else at the end of the chain (`httppost_add`); NULL if it cannot be
/// made.
fn httppost_add(
    form: &FormInfo,
    parent: *mut curl_httppost,
    first: &mut *mut curl_httppost,
    last: &mut *mut curl_httppost,
) -> *mut curl_httppost {
    let name = form.name.ptr();
    let mut namelength = form.namelength;
    if namelength == 0 && !name.is_null() {
        // SAFETY: a name without a length is a C string.
        namelength = unsafe { libc::strlen(name) };
    }
    if form.bufferlength > c_long::MAX as usize || namelength > c_long::MAX as usize {
        return ptr::null_mut();
    }
    let post = root::allocator()
        .malloc(size_of::<curl_httppost>())
        .cast::<curl_httppost>();
    if post.is_null() {
        return post;
    }
    let node = curl_httppost {
        next: ptr::null_mut(),
        name,
        namelength: namelength as c_long,
        contents: form.value.ptr(),
        contentslength: 0,
        buffer: form.buffer,
        bufferlength: form.bufferlength as c_long,
        contenttype: form.contenttype.ptr(),
        contentheader: form.contentheader,
        more: ptr::null_mut(),
        flags: form.flags | LARGE,
        showfilename: form.showfilename.ptr(),
        userp: form.userp,
        contentlen: form.contentslength,
    };
    // SAFETY: a fresh allocation the size of a node, aligned for any
    // object as `malloc`'s are.
    unsafe { post.write(node) };
    if let Some(mut parent) = NonNull::new(parent) {
        // SAFETY: a node of the chain being made, live and ours.
        let parent = unsafe { parent.as_mut() };
        // SAFETY: as above, the new node.
        unsafe { (*post).more = parent.more };
        parent.more = post;
    } else {
        match NonNull::new(*last) {
            // SAFETY: as above.
            Some(mut l) => unsafe { l.as_mut() }.next = post,
            None => *first = post,
        }
        *last = post;
    }
    post
}

/// Check each part given for completeness, make it the copies it owns,
/// and make it a node of a new chain from `first` to `last`
/// (`formadd_check`).
fn formadd_check(
    forms: &mut [FormInfo],
    first: &mut *mut curl_httppost,
    last: &mut *mut curl_httppost,
) -> CURLFORMcode {
    let mut prevtype: *const c_char = ptr::null();
    let mut post: *mut curl_httppost = ptr::null_mut();
    for form in forms {
        let name = form.name.ptr();
        let flags = form.flags;
        if ((name.is_null() || !form.value.is_set()) && post.is_null())
            || (form.contentslength != 0 && flags & FILENAME != 0)
            || (flags & FILENAME != 0 && flags & PTRCONTENTS != 0)
            || (form.buffer.is_null() && flags & BUFFER != 0 && flags & PTRBUFFER != 0)
            || (flags & READFILE != 0 && flags & PTRCONTENTS != 0)
        {
            return CURL_FORMADD_INCOMPLETE;
        }
        if flags & (FILENAME | BUFFER) != 0 && !form.contenttype.is_set() {
            // A type from the name, else the one before, else the default.
            let f = if flags & BUFFER != 0 {
                form.showfilename.ptr()
            } else {
                form.value.ptr()
            };
            let guessed = NonNull::new(f).and_then(|f| {
                // SAFETY: the names a part is given are C strings.
                let f = unsafe { CStr::from_ptr(f.as_ptr()) }.to_bytes();
                curl_core::mime::content_type_for(f)
            });
            let (t, len) = match guessed {
                Some(t) => (t.as_ptr().cast::<c_char>(), t.len()),
                // SAFETY: the type before is a C string the chain owns.
                None if !prevtype.is_null() => (prevtype, unsafe { libc::strlen(prevtype) }),
                None => (DEFAULT_TYPE.as_ptr(), DEFAULT_TYPE.count_bytes()),
            };
            // SAFETY: `t` holds `len` bytes.
            if !unsafe { form.contenttype.copy(t, len) } {
                return CURL_FORMADD_MEMORY;
            }
        }
        if !name.is_null() && form.namelength != 0 {
            // SAFETY: a name given a length holds that many bytes.
            let named = unsafe { core::slice::from_raw_parts(name.cast::<u8>(), form.namelength) };
            if named.contains(&0) {
                return CURL_FORMADD_NULL;
            }
        }
        if flags & PTRNAME == 0 && !copy_field(&mut form.name, form.namelength) {
            return CURL_FORMADD_MEMORY;
        }
        if flags & (FILENAME | READFILE | PTRCONTENTS | PTRBUFFER | CALLBACK) == 0
            && !copy_field(&mut form.value, form.contentslength as usize)
        {
            return CURL_FORMADD_MEMORY;
        }
        post = httppost_add(form, post, first, last);
        if post.is_null() {
            return CURL_FORMADD_MEMORY;
        }
        if form.contenttype.is_set() {
            prevtype = form.contenttype.ptr();
        }
    }
    CURL_FORMADD_OK
}

/// Free the nodes of a chain, and not what they point to (`free_chain`),
/// without recursing.
fn free_chain(chain: *mut curl_httppost) {
    let mut field = chain;
    while let Some(head) = NonNull::new(field) {
        // SAFETY: a node of a chain being made, ours.
        field = unsafe { head.as_ref() }.next;
        let mut at = head.as_ptr();
        while let Some(node) = NonNull::new(at) {
            // SAFETY: as above.
            at = unsafe { node.as_ref() }.more;
            // SAFETY: as above, from the allocator, not used again.
            unsafe { root::allocator().free(node.as_ptr().cast()) };
        }
    }
}

/// # Safety
///
/// `httppost` and `last_post` point to the application's first and last
/// node pointers, both NULL for a new chain; the arguments are options
/// and values as `curl_formadd` documents them, ended by `CURLFORM_END`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_formadd(
    httppost: *mut *mut curl_httppost,
    last_post: *mut *mut curl_httppost,
    mut args: ...
) -> CURLFORMcode {
    let mut forms = Vec::new();
    if forms.try_push(FormInfo::new()).is_err() {
        return CURL_FORMADD_MEMORY;
    }
    // SAFETY: as the caller guarantees.
    let mut code = unsafe { read_options(&mut forms, &mut args) };
    let (mut first, mut last) = (ptr::null_mut(), ptr::null_mut());
    if code == CURL_FORMADD_OK {
        code = formadd_check(&mut forms, &mut first, &mut last);
    }
    if code != CURL_FORMADD_OK {
        // The copies made go, then the nodes that pointed to them.
        for form in &mut forms {
            form.name.free();
            form.value.free();
            form.contenttype.free();
            form.showfilename.free();
        }
        free_chain(first);
        return code;
    }
    // SAFETY: as the caller guarantees: the application's last node, if
    // any, is live.
    let had = NonNull::new(unsafe { *last_post });
    match had {
        // SAFETY: as above.
        Some(mut l) => unsafe { l.as_mut() }.next = first,
        // SAFETY: as above.
        None => unsafe { *httppost = first },
    }
    // SAFETY: as above.
    unsafe { *last_post = last };
    CURL_FORMADD_OK
}
const _: unsafe extern "C" fn(
    *mut *mut curl_httppost,
    *mut *mut curl_httppost,
    ...
) -> CURLFORMcode = curl_formadd;

/// # Safety
///
/// `form` is NULL or a chain from `curl_formadd`, not used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_formfree(form: *mut curl_httppost) {
    let alloc = root::allocator();
    // Each field's list of files, and the chain, walked without
    // recursing.
    let mut field = form;
    while let Some(head) = NonNull::new(field) {
        // SAFETY: as the caller guarantees, a live node.
        field = unsafe { head.as_ref() }.next;
        let mut at = head.as_ptr();
        while let Some(node) = NonNull::new(at) {
            // SAFETY: as above.
            let n = unsafe { node.as_ptr().read() };
            // What the node owns came from the allocator, as the node did,
            // and nothing else frees them.
            let mut owned = [
                n.contenttype,
                n.showfilename,
                ptr::null_mut(),
                ptr::null_mut(),
            ];
            if n.flags & PTRNAME == 0 {
                owned[2] = n.name;
            }
            if n.flags & (PTRCONTENTS | BUFFER | CALLBACK) == 0 {
                owned[3] = n.contents;
            }
            for p in owned {
                // SAFETY: as above.
                unsafe { alloc.free(p.cast()) };
            }
            // SAFETY: as above.
            unsafe { alloc.free(at.cast()) };
            at = n.more;
        }
    }
}
const _: ffi::proto::curl_formfree = curl_formfree;

/// Why a chain could not be made a tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NotConverted(pub(crate) CURLcode);

/// `curl_mime_*`'s answer, as the conversion goes on or stops.
fn ok(code: CURLcode) -> Result<(), NotConverted> {
    if code == CURLE_OK {
        Ok(())
    } else {
        Err(NotConverted(code))
    }
}

/// Name a part with `len` bytes of `name`, or up to its zero byte for 0
/// (`setname`).
///
/// # Safety
///
/// `part` is a live part; `name` is NULL or holds `len` bytes, or is a C
/// string for 0.
unsafe fn set_name(
    part: *mut ffi::curl_mimepart,
    name: *const c_char,
    len: usize,
) -> Result<(), NotConverted> {
    if name.is_null() || len == 0 {
        // SAFETY: as the caller guarantees.
        return ok(unsafe { mime::curl_mime_name(part, name) });
    }
    // SAFETY: as the caller guarantees.
    let copy = unsafe { memdup0(name, len) };
    if copy.is_null() {
        return Err(NotConverted(CURLE_OUT_OF_MEMORY));
    }
    // SAFETY: a live part and a C string.
    let code = unsafe { mime::curl_mime_name(part, copy) };
    // SAFETY: from the allocator, copied by the part.
    unsafe { root::allocator().free(copy.cast()) };
    ok(code)
}

/// `curl_mime_*`'s new nodes, or out of memory.
fn made<T>(p: *mut T) -> Result<*mut T, NotConverted> {
    if p.is_null() {
        Err(NotConverted(CURLE_OUT_OF_MEMORY))
    } else {
        Ok(p)
    }
}

/// `fseek` on the `FILE *` a part reads, as its seek function.
unsafe extern "C" fn seek_file(arg: *mut c_void, offset: curl_off_t, origin: c_int) -> c_int {
    // SAFETY: the part's argument is the `FILE *` it reads.
    unsafe { libc::fseeko(arg.cast(), offset, origin) }
}

/// A tree of the chain from `post`, attached to nothing, its streams read
/// by `read` (`Curl_getformdata`); none for no chain.
///
/// # Safety
///
/// `post` is NULL or a live chain whose strings, buffers and lists live
/// while this runs.
pub(crate) unsafe fn tree_of(
    post: *mut curl_httppost,
    read: curl_read_callback,
) -> Result<Option<NonNull<mime::ShimMime>>, NotConverted> {
    if post.is_null() {
        return Ok(None);
    }
    // SAFETY: NULL is a handle C's tree does not need.
    let form = made(unsafe { mime::curl_mime_init(ptr::null_mut()) })?;
    // SAFETY: as the caller guarantees.
    let filled = unsafe { fill(form, post, read) };
    if let Err(e) = filled {
        // SAFETY: the tree just made, attached to nothing.
        unsafe { mime::curl_mime_free(form) };
        return Err(e);
    }
    Ok(NonNull::new(form.cast()))
}

/// Add the chain's parts to `form`.
///
/// # Safety
///
/// As for `tree_of`; `form` is a live tree.
unsafe fn fill(
    form: *mut curl_mime,
    mut post: *mut curl_httppost,
    read: curl_read_callback,
) -> Result<(), NotConverted> {
    while let Some(p) = NonNull::new(post) {
        // SAFETY: as the caller guarantees, a live node.
        let p = unsafe { p.as_ref() };
        post = p.next;
        // More than one file: a part of its own parts.
        let multipart = if p.more.is_null() {
            form
        } else {
            // SAFETY: a live tree.
            let part = made(unsafe { mime::curl_mime_addpart(form) })?;
            // SAFETY: the node's name holds its length, or is a C string.
            unsafe { set_name(part, p.name, p.namelength as usize) }?;
            // SAFETY: NULL is a handle C's tree does not need.
            let sub = made(unsafe { mime::curl_mime_init(ptr::null_mut()) })?;
            // SAFETY: a live part and a new tree, attached to nothing.
            let code = unsafe { mime::curl_mime_subparts(part, sub) };
            if code != CURLE_OK {
                // SAFETY: the new tree, still attached to nothing.
                unsafe { mime::curl_mime_free(sub) };
                return Err(NotConverted(code));
            }
            sub
        };
        let mut at: *const curl_httppost = p;
        while let Some(file) = NonNull::new(at.cast_mut()) {
            // SAFETY: as the caller guarantees, a live node.
            let file = unsafe { file.as_ref() };
            at = file.more;
            // SAFETY: a live tree.
            let part = made(unsafe { mime::curl_mime_addpart(multipart) })?;
            // SAFETY: a live part, given the node's list, not to own.
            ok(unsafe { mime::curl_mime_headers(part, file.contentheader, 0) })?;
            if !file.contenttype.is_null() {
                // SAFETY: a live part; the type is a C string.
                ok(unsafe { mime::curl_mime_type(part, file.contenttype) })?;
            }
            if p.more.is_null() {
                // SAFETY: as above, for the name.
                unsafe { set_name(part, p.name, p.namelength as usize) }?;
            }
            // SAFETY: as the caller guarantees, the node's fields are live.
            unsafe { set_content(part, p, file, read) }?;
            if !p.showfilename.is_null()
                && (!p.more.is_null() || p.flags & (FILENAME | BUFFER | CALLBACK) != 0)
            {
                // SAFETY: a live part; the name is a C string.
                ok(unsafe { mime::curl_mime_filename(part, p.showfilename) })?;
            }
        }
    }
    Ok(())
}

/// Give `part` the content of `file`, one of the files of the field `p`:
/// the field's flags and lengths say what it is.
///
/// # Safety
///
/// `part` is a live part; the nodes' strings and buffers are live.
unsafe fn set_content(
    part: *mut ffi::curl_mimepart,
    p: &curl_httppost,
    file: &curl_httppost,
    read: curl_read_callback,
) -> Result<(), NotConverted> {
    let clen = if p.flags & LARGE != 0 {
        p.contentlen
    } else {
        p.contentslength
    };
    let code = if p.flags & (FILENAME | READFILE) != 0 {
        let code = if file.contents.is_null() {
            // A type given past the last file: C reads NULL; here the part
            // has no content.
            CURLE_OK
        // SAFETY: a file's name is a C string.
        } else if unsafe { CStr::from_ptr(file.contents) }.to_bytes() == b"-" {
            let (stdin, _, _) = crate::callbacks::standard();
            let fread = Some(crate::callbacks::fread as unsafe extern "C" fn(_, _, _, _) -> _);
            // SAFETY: a live part, and standard input for the functions.
            unsafe { mime::curl_mime_data_cb(part, -1, fread, Some(seek_file), None, stdin) }
        } else {
            // SAFETY: a live part and a C string.
            unsafe { mime::curl_mime_filedata(part, file.contents) }
        };
        if code == CURLE_OK && p.flags & READFILE != 0 {
            // SAFETY: a live part.
            unsafe { mime::curl_mime_filename(part, ptr::null()) }
        } else {
            code
        }
    } else if p.flags & BUFFER != 0 {
        let len = match p.bufferlength {
            0 => ffi::CURL_ZERO_TERMINATED as usize,
            n => n as usize,
        };
        // SAFETY: a live part; the buffer holds its length, or is a C
        // string without one.
        unsafe { mime::curl_mime_data(part, p.buffer, len) }
    } else if p.flags & CALLBACK != 0 {
        let size = if clen == 0 { -1 } else { clen };
        // SAFETY: a live part; the read function takes the stream's
        // argument.
        unsafe { mime::curl_mime_data_cb(part, size, read, None, None, p.userp) }
    } else {
        let len = match clen {
            0 => ffi::CURL_ZERO_TERMINATED as usize,
            n => n as usize,
        };
        // SAFETY: a live part; the contents hold their length, or are a C
        // string without one.
        unsafe { mime::curl_mime_data(part, p.contents, len) }
    };
    ok(code)
}

/// # Safety
///
/// `form` is NULL or a live chain; `append` takes `arg`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_formget(
    form: *mut curl_httppost,
    arg: *mut c_void,
    append: curl_formget_callback,
) -> c_int {
    let Some(append) = append else {
        return CURLE_BAD_FUNCTION_ARGUMENT.0 as c_int;
    };
    // No read function: a stream has nothing to read here.
    // SAFETY: as the caller guarantees.
    let tree = match unsafe { tree_of(form, None) } {
        Ok(tree) => tree,
        Err(NotConverted(code)) => return code.0 as c_int,
    };
    let code = match tree {
        // An empty form: its type alone.
        None => {
            let empty = b"Content-Type: multipart/form-data\r\n\r\n";
            // SAFETY: the application's function takes `arg`.
            let took = unsafe { append(arg, empty.as_ptr().cast(), empty.len()) };
            if took == empty.len() {
                CURLE_OK
            } else {
                ffi::CURLE_READ_ERROR
            }
        }
        Some(tree) => {
            // SAFETY: the tree just made, live until freed below.
            let code = match mime::whole(unsafe { tree.as_ref() }) {
                Ok(mime) => curl_core::mime::read_whole(mime, &mut |piece| {
                    // SAFETY: as above.
                    unsafe { append(arg, piece.as_ptr().cast(), piece.len()) }
                })
                .map_or_else(crate::error_codes::easy_code, |()| CURLE_OK),
                Err(code) => code,
            };
            // SAFETY: the tree just made, attached to nothing.
            unsafe { mime::curl_mime_free(tree.as_ptr().cast()) };
            code
        }
    };
    code.0 as c_int
}
const _: ffi::proto::curl_formget = curl_formget;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "one contract covers each test's sequence of calls"
    )]

    use core::ffi::{c_char, c_int, c_long, c_void};
    use core::ptr::{self, NonNull};

    use curl_core::mime::{Content, MimeSource as _};

    use super::{curl_formadd, curl_formfree};
    use crate::easy::{self, curl_easy_cleanup, curl_easy_init};
    use crate::ffi::{
        self, CURL_FORMADD_INCOMPLETE, CURL_FORMADD_NULL, CURL_FORMADD_OK,
        CURL_FORMADD_OPTION_TWICE, CURLE_OK, curl_httppost,
    };
    use crate::mime::MimeTree;
    use crate::setopt::curl_easy_setopt;

    const COPYNAME: c_int = ffi::CURLFORM_COPYNAME.0;
    const PTRCONTENTS: c_int = ffi::CURLFORM_PTRCONTENTS.0;
    const COPYCONTENTS: c_int = ffi::CURLFORM_COPYCONTENTS.0;
    const FILENAME: c_int = ffi::CURLFORM_FILENAME.0;
    const END: c_int = ffi::CURLFORM_END.0;

    /// Refused as C refuses: an option given twice, a part without a
    /// value. A NULL file name to show, whose length C reads, is refused
    /// as a NULL value is.
    #[test]
    fn formadd_refuses_as_c_does() {
        let (mut first, mut last): (*mut curl_httppost, *mut curl_httppost) =
            (ptr::null_mut(), ptr::null_mut());
        let n = |s: &core::ffi::CStr| s.as_ptr();
        // SAFETY: options and values as `curl_formadd` documents them.
        unsafe {
            let twice = curl_formadd(
                &mut first,
                &mut last,
                COPYNAME,
                n(c"a"),
                COPYNAME,
                n(c"b"),
                END,
            );
            assert_eq!(twice, CURL_FORMADD_OPTION_TWICE);
            let bare = curl_formadd(&mut first, &mut last, COPYNAME, n(c"a"), END);
            assert_eq!(bare, CURL_FORMADD_INCOMPLETE);
            let null = curl_formadd(
                &mut first,
                &mut last,
                COPYNAME,
                n(c"a"),
                COPYCONTENTS,
                n(c"v"),
                FILENAME,
                ptr::null::<c_char>(),
                END,
            );
            assert_eq!(null, CURL_FORMADD_NULL);
            assert!(first.is_null() && last.is_null(), "nothing added");
            let ok = curl_formadd(
                &mut first,
                &mut last,
                COPYNAME,
                n(c"a"),
                COPYCONTENTS,
                n(c"v"),
                END,
            );
            assert_eq!(ok, CURL_FORMADD_OK);
            assert_eq!(first, last, "one node, first and last");
            curl_formfree(first);
        }
    }

    /// A type given past a field's last file makes a part with a type
    /// and no file, which C reads as a NULL file name when it makes the
    /// tree, and crashes; here the part has no content.
    #[test]
    fn a_type_past_the_last_file_is_a_part_without_content() {
        unsafe extern "C" fn count(arg: *mut c_void, _: *const c_char, len: usize) -> usize {
            // SAFETY: the test's counter.
            unsafe { *arg.cast::<usize>() += len };
            len
        }
        let (mut first, mut last): (*mut curl_httppost, *mut curl_httppost) =
            (ptr::null_mut(), ptr::null_mut());
        let file = std::env::temp_dir().join("curl-formdata-type-past");
        std::fs::write(&file, b"x").unwrap();
        let path = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
        let mut total = 0usize;
        // SAFETY: options and values as documented; the counter outlives
        // the call.
        unsafe {
            let added = curl_formadd(
                &mut first,
                &mut last,
                COPYNAME,
                c"m".as_ptr(),
                ffi::CURLFORM_FILE.0,
                path.as_ptr(),
                ffi::CURLFORM_CONTENTTYPE.0,
                c"t/1".as_ptr(),
                ffi::CURLFORM_CONTENTTYPE.0,
                c"t/2".as_ptr(),
                END,
            );
            assert_eq!(added, CURL_FORMADD_OK);
            let got = super::curl_formget(first, (&raw mut total).cast(), Some(count));
            assert_eq!(got, 0);
            curl_formfree(first);
        }
        assert!(total > 0);
        std::fs::remove_file(&file).unwrap();
    }

    /// A handle posting a chain makes it a tree at the first request and
    /// keeps that tree, contents copied then, until the chain is set
    /// again, as C keeps `state.formp`.
    #[test]
    fn a_chain_is_made_a_tree_once_each_time_it_is_set() {
        let mut data = *b"one\0";
        let (mut first, mut last): (*mut curl_httppost, *mut curl_httppost) =
            (ptr::null_mut(), ptr::null_mut());
        // SAFETY: options and values as documented; `data` outlives the
        // chain and the handle.
        unsafe {
            let added = curl_formadd(
                &mut first,
                &mut last,
                COPYNAME,
                c"f".as_ptr(),
                PTRCONTENTS,
                data.as_mut_ptr().cast::<c_char>(),
                END,
            );
            assert_eq!(added, CURL_FORMADD_OK);
        }
        let c = curl_easy_init();
        let set = || {
            // SAFETY: a live handle and a live chain.
            let code =
                unsafe { curl_easy_setopt(c, ffi::CURLOPT_HTTPPOST, first.cast::<c_void>()) };
            assert_eq!(code, CURLE_OK);
        };
        let posted = || {
            // SAFETY: a live handle.
            let easy = unsafe { easy::handle(c) }.expect("live");
            let mime = MimeTree(NonNull::from(easy))
                .mime()
                .unwrap()
                .expect("a tree");
            let Content::Bytes(b) = &mime.parts()[0].content else {
                panic!("bytes");
            };
            b.to_vec()
        };
        set();
        assert_eq!(posted(), b"one");
        data[..3].copy_from_slice(b"two");
        assert_eq!(posted(), b"one", "the tree made first");
        set();
        assert_eq!(posted(), b"two", "made again once set again");
        // SAFETY: a `long` option.
        let get = unsafe { curl_easy_setopt(c, ffi::CURLOPT_HTTPGET, 1 as c_long) };
        assert_eq!(get, CURLE_OK);
        // SAFETY: the handle and chain, not used again.
        unsafe {
            curl_easy_cleanup(c);
            curl_formfree(first);
        }
    }
}
