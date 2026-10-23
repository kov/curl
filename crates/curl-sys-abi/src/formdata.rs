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

/// Whether a length is more than a node's `long` holds.
fn past_long(len: usize) -> bool {
    len > c_long::MAX as usize
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
    if past_long(form.bufferlength) || past_long(namelength) {
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

/// Whether a part is a buffer without its buffer, as C checks. It never
/// is: only `CURLFORM_BUFFERPTR` sets these flags, and it refuses NULL.
fn buffer_missing(form: &FormInfo) -> bool {
    form.buffer.is_null() && form.flags & BUFFER != 0 && form.flags & PTRBUFFER != 0
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
        // C's checks. The first and the last are never true: the option
        // that sets the buffer flags refuses NULL, and a file to read
        // and contents a pointer names refuse each other. They are kept
        // apart, so that an `||` between them made `&&` would be seen.
        if buffer_missing(form)
            || ((name.is_null() || !form.value.is_set()) && post.is_null())
            || (form.contentslength != 0 && flags & FILENAME != 0)
            || (flags & FILENAME != 0 && flags & PTRCONTENTS != 0)
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
        // Searched as C searches it, to its first zero byte: a length
        // past the name's end, a negative one made huge among them, finds
        // the zero that ends it.
        let zeroed = !name.is_null() && form.namelength != 0 && {
            // SAFETY: a name given a length holds that many bytes, or a
            // zero byte before their end.
            !unsafe { libc::memchr(name.cast(), 0, form.namelength) }.is_null()
        };
        if zeroed {
            return CURL_FORMADD_NULL;
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

    /// An entry of a `CURLFORM_ARRAY`.
    fn entry(option: ffi::CURLformoption, value: *const c_char) -> ffi::curl_forms {
        ffi::curl_forms { option, value }
    }

    /// A number in an array entry, which carries it in a pointer's bits.
    fn number(n: isize) -> *const c_char {
        n as *const c_char
    }

    /// One `curl_formadd` call of `entries`, through `CURLFORM_ARRAY`: its
    /// code and the chain it made.
    fn add(entries: &[ffi::curl_forms]) -> (ffi::CURLFORMcode, *mut curl_httppost) {
        let mut all = entries.to_vec();
        all.push(entry(ffi::CURLFORM_END, ptr::null()));
        let (mut first, mut last): (*mut curl_httppost, *mut curl_httppost) =
            (ptr::null_mut(), ptr::null_mut());
        // SAFETY: an array of options and values as documented, ended.
        let code = unsafe {
            curl_formadd(
                &mut first,
                &mut last,
                ffi::CURLFORM_ARRAY.0,
                all.as_ptr(),
                END,
            )
        };
        (code, first)
    }

    /// The bytes of a C string a node holds, or `None` for NULL.
    fn text(p: *const c_char) -> Option<Vec<u8>> {
        // SAFETY: the chain's strings are C strings.
        (!p.is_null()).then(|| unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes().to_vec())
    }

    /// What `curl_formget` gives for `form`: its code and bytes.
    fn formget(form: *mut curl_httppost) -> (c_int, Vec<u8>) {
        unsafe extern "C" fn collect(arg: *mut c_void, buf: *const c_char, len: usize) -> usize {
            // SAFETY: the test's buffer, and `len` bytes at `buf`.
            unsafe {
                (*arg.cast::<Vec<u8>>())
                    .extend_from_slice(core::slice::from_raw_parts(buf.cast::<u8>(), len));
            }
            len
        }
        let mut out = Vec::new();
        // SAFETY: a live chain; the buffer outlives the call.
        let code = unsafe { super::curl_formget(form, (&raw mut out).cast(), Some(collect)) };
        (code, out)
    }

    /// Whether `haystack` holds `needle`.
    fn holds(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// A file in the temporary directory, named for the test, and its
    /// name as a C string.
    fn scratch(name: &str) -> (std::path::PathBuf, std::ffi::CString) {
        let path =
            std::env::temp_dir().join(format!("curl-formdata-{}-{name}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        (path, c)
    }

    /// Each part is checked as C's `formadd_check` checks it: a file with
    /// a length, or with contents a pointer names, is incomplete; a name
    /// holding a zero byte within its length is refused, and so is one
    /// whose length is negative, which C reads as huge; contents with a length are cut to
    /// it, and a name without one has its own.
    #[test]
    fn formadd_checks_parts_as_c_does() {
        let (path, file) = scratch("check.txt");
        let name = entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr());
        let incomplete: &[&[ffi::curl_forms]] = &[
            &[
                name,
                entry(ffi::CURLFORM_FILE, file.as_ptr()),
                entry(ffi::CURLFORM_CONTENTSLENGTH, number(1)),
            ],
            // The second type makes a file of its own, which the contents
            // a pointer names then join.
            &[
                name,
                entry(ffi::CURLFORM_FILE, file.as_ptr()),
                entry(ffi::CURLFORM_CONTENTTYPE, c"t/1".as_ptr()),
                entry(ffi::CURLFORM_CONTENTTYPE, c"t/2".as_ptr()),
                entry(ffi::CURLFORM_PTRCONTENTS, c"v".as_ptr()),
            ],
        ];
        for entries in incomplete {
            assert_eq!(add(entries), (CURL_FORMADD_INCOMPLETE, ptr::null_mut()));
        }
        let zeroed = b"a\0b\0";
        let named = add(&[
            entry(ffi::CURLFORM_NAMELENGTH, number(3)),
            entry(ffi::CURLFORM_COPYNAME, zeroed.as_ptr().cast::<c_char>()),
            entry(ffi::CURLFORM_COPYCONTENTS, c"v".as_ptr()),
        ]);
        assert_eq!(named, (CURL_FORMADD_NULL, ptr::null_mut()));
        let negative = add(&[
            entry(ffi::CURLFORM_NAMELENGTH, number(-1)),
            entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
            entry(ffi::CURLFORM_COPYCONTENTS, c"v".as_ptr()),
        ]);
        assert_eq!(
            negative,
            (CURL_FORMADD_NULL, ptr::null_mut()),
            "the zero ending it"
        );

        // Contents with a length: a copy that long, no type.
        let (code, first) = add(&[
            name,
            entry(ffi::CURLFORM_COPYCONTENTS, c"abc".as_ptr()),
            entry(ffi::CURLFORM_CONTENTSLENGTH, number(2)),
        ]);
        assert_eq!(code, CURL_FORMADD_OK);
        // SAFETY: the chain just made.
        let node = unsafe { &*first };
        assert_eq!(text(node.contents), Some(b"ab".to_vec()));
        assert_eq!(text(node.name), Some(b"n".to_vec()));
        assert_eq!(node.namelength, 1, "the name's own length");
        assert!(node.contenttype.is_null());
        // SAFETY: the chain, not used again.
        unsafe { curl_formfree(first) };

        // A name given a length keeps it.
        let (code, first) = add(&[
            entry(ffi::CURLFORM_NAMELENGTH, number(1)),
            entry(ffi::CURLFORM_COPYNAME, c"nm".as_ptr()),
            entry(ffi::CURLFORM_COPYCONTENTS, c"v".as_ptr()),
        ]);
        assert_eq!(code, CURL_FORMADD_OK);
        // SAFETY: as above.
        let node = unsafe { &*first };
        assert_eq!((text(node.name), node.namelength), (Some(b"n".to_vec()), 1));
        // SAFETY: as above.
        unsafe { curl_formfree(first) };
        std::fs::remove_file(path).unwrap();
    }

    /// What a pointer is given lends stays the application's: the name,
    /// the contents, the buffer, the stream. What is copied is not. A
    /// buffer is typed by the name given for it.
    #[test]
    fn formadd_lends_what_c_lends() {
        let mut buf = *b"buf\0";
        let buf = buf.as_mut_ptr().cast::<c_char>();
        let stream = c"stream".as_ptr();
        let (path, file) = scratch("lend.txt");
        let parts: &[(&[ffi::curl_forms], c_long)] = &[
            (
                &[
                    entry(ffi::CURLFORM_PTRNAME, c"n".as_ptr()),
                    entry(ffi::CURLFORM_PTRCONTENTS, c"v".as_ptr()),
                ],
                (ffi::CURL_HTTPPOST_PTRNAME | ffi::CURL_HTTPPOST_PTRCONTENTS) as c_long,
            ),
            (
                &[
                    entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
                    entry(ffi::CURLFORM_BUFFER, c"b.html".as_ptr()),
                    entry(ffi::CURLFORM_BUFFERPTR, buf),
                    entry(ffi::CURLFORM_BUFFERLENGTH, number(3)),
                ],
                (ffi::CURL_HTTPPOST_BUFFER | ffi::CURL_HTTPPOST_PTRBUFFER) as c_long,
            ),
            (
                &[
                    entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
                    entry(ffi::CURLFORM_STREAM, stream),
                ],
                ffi::CURL_HTTPPOST_CALLBACK as c_long,
            ),
            (
                &[
                    entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
                    entry(ffi::CURLFORM_FILECONTENT, file.as_ptr()),
                ],
                ffi::CURL_HTTPPOST_READFILE as c_long,
            ),
        ];
        let given = [c"v".as_ptr(), buf.cast_const(), stream, file.as_ptr()];
        for (&(entries, flags), given) in parts.iter().zip(given) {
            let (code, first) = add(entries);
            assert_eq!(code, CURL_FORMADD_OK);
            // SAFETY: the chain just made.
            let node = unsafe { &*first };
            let large = ffi::CURL_HTTPPOST_LARGE as c_long;
            assert_eq!(node.flags, flags | large);
            let lent = flags & (ffi::CURL_HTTPPOST_READFILE as c_long) == 0;
            assert_eq!(node.contents.cast_const() == given, lent);
            assert_eq!(text(node.contents), text(given));
            let buffer = flags & (ffi::CURL_HTTPPOST_BUFFER as c_long) != 0;
            let typed = buffer.then(|| b"text/html".to_vec());
            assert_eq!(text(node.contenttype), typed, "a buffer typed by its name");
            let ptrname = flags & (ffi::CURL_HTTPPOST_PTRNAME as c_long) != 0;
            assert_eq!(node.name.cast_const() == entries[0].value, ptrname);
            // SAFETY: the chain, not used again.
            unsafe { curl_formfree(first) };
        }
        std::fs::remove_file(path).unwrap();
    }

    /// More files for one field are a list after its node, each a file
    /// typed by its name, else by the type before it, else the default.
    #[test]
    fn formadd_types_each_file_as_c_does() {
        let (txt, txt_c) = scratch("files.txt");
        let (bare, bare_c) = scratch("files");
        let (code, first) = add(&[
            entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
            entry(ffi::CURLFORM_FILE, txt_c.as_ptr()),
            entry(ffi::CURLFORM_FILE, bare_c.as_ptr()),
        ]);
        assert_eq!(code, CURL_FORMADD_OK);
        // SAFETY: the chain just made.
        let node = unsafe { &*first };
        assert!(node.next.is_null());
        assert_eq!(text(node.contenttype), Some(b"text/plain".to_vec()));
        // SAFETY: as above, its list of files.
        let more = unsafe { &*node.more };
        assert!(more.more.is_null() && more.name.is_null());
        assert_eq!(text(more.contents), text(bare_c.as_ptr()));
        assert_eq!(text(more.contenttype), Some(b"text/plain".to_vec()));
        let file = ffi::CURL_HTTPPOST_FILENAME as c_long;
        assert_eq!(more.flags & file, file);
        // SAFETY: the chain, not used again.
        unsafe { curl_formfree(first) };
        let (code, first) = add(&[
            entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
            entry(ffi::CURLFORM_FILE, bare_c.as_ptr()),
        ]);
        assert_eq!(code, CURL_FORMADD_OK);
        // SAFETY: as above.
        let node = unsafe { &*first };
        assert_eq!(
            text(node.contenttype),
            Some(b"application/octet-stream".to_vec())
        );
        // SAFETY: as above.
        unsafe { curl_formfree(first) };
        std::fs::remove_file(txt).unwrap();
        std::fs::remove_file(bare).unwrap();
    }

    /// `CURLFORM_CONTENTLEN` cuts contents a pointer names to its length,
    /// a large one; a buffer longer than a `long` holds is refused; a file
    /// that is not there fails the read.
    #[test]
    fn lengths_and_files_reach_what_formget_reads() {
        let (code, first) = add(&[
            entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
            entry(ffi::CURLFORM_PTRCONTENTS, c"abc".as_ptr()),
            entry(ffi::CURLFORM_CONTENTLEN, number(2)),
        ]);
        assert_eq!(code, CURL_FORMADD_OK);
        // SAFETY: the chain just made.
        let node = unsafe { &*first };
        assert_eq!((node.contentlen, node.contentslength), (2, 0));
        let (got, bytes) = formget(first);
        assert_eq!(got, 0);
        assert!(holds(&bytes, b"\r\n\r\nab\r\n"), "{}", bytes.escape_ascii());
        // SAFETY: the chain, not used again.
        unsafe { curl_formfree(first) };
        let mut buf = *b"buf\0";
        let buf = buf.as_mut_ptr().cast::<c_char>();
        let buffer = |len: isize| {
            add(&[
                entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
                entry(ffi::CURLFORM_BUFFER, c"b".as_ptr()),
                entry(ffi::CURLFORM_BUFFERPTR, buf),
                entry(ffi::CURLFORM_BUFFERLENGTH, number(len)),
            ])
        };
        let (code, first) = buffer(c_long::MAX as isize);
        assert_eq!(code, CURL_FORMADD_OK);
        // SAFETY: the chain just made.
        assert_eq!(unsafe { &*first }.bufferlength, c_long::MAX);
        // SAFETY: as above.
        unsafe { curl_formfree(first) };
        assert_eq!(buffer(-1), (ffi::CURL_FORMADD_MEMORY, ptr::null_mut()));
        let (code, first) = add(&[
            entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
            entry(ffi::CURLFORM_FILE, c"/nonexistent/curl-formdata".as_ptr()),
        ]);
        assert_eq!(code, CURL_FORMADD_OK);
        assert_eq!(formget(first).0, ffi::CURLE_READ_ERROR.0 as c_int);
        // SAFETY: as above.
        unsafe { curl_formfree(first) };
    }

    std::thread_local! {
        /// Blocks this thread holds from the counting allocator.
        static HELD: core::cell::Cell<isize> = const { core::cell::Cell::new(0) };
        /// How many more allocations this thread may make before one is
        /// refused, if any is.
        static LEFT: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
    }

    /// Whether this allocation is the one refused.
    fn refused() -> bool {
        LEFT.with(|left| match left.get() {
            Some(0) => true,
            Some(n) => {
                left.set(Some(n - 1));
                false
            }
            None => false,
        })
    }

    fn held(p: *mut c_void) -> *mut c_void {
        if !p.is_null() {
            HELD.with(|h| h.set(h.get() + 1));
        }
        p
    }

    unsafe extern "C" fn counted_malloc(size: usize) -> *mut c_void {
        if refused() {
            return ptr::null_mut();
        }
        // SAFETY: any size.
        held(unsafe { libc::malloc(size) })
    }

    unsafe extern "C" fn counted_free(p: *mut c_void) {
        if !p.is_null() {
            HELD.with(|h| h.set(h.get() - 1));
        }
        // SAFETY: as `curl_free`'s caller guarantees, from `malloc`.
        unsafe { libc::free(p) };
    }

    unsafe extern "C" fn counted_realloc(p: *mut c_void, size: usize) -> *mut c_void {
        if refused() {
            return ptr::null_mut();
        }
        // SAFETY: as the caller guarantees.
        let q = unsafe { libc::realloc(p, size) };
        if p.is_null() { held(q) } else { q }
    }

    unsafe extern "C" fn counted_strdup(s: *const c_char) -> *mut c_char {
        if refused() {
            return ptr::null_mut();
        }
        // SAFETY: as the caller guarantees, a C string.
        held(unsafe { libc::strdup(s) }.cast()).cast()
    }

    unsafe extern "C" fn counted_calloc(n: usize, size: usize) -> *mut c_void {
        if refused() {
            return ptr::null_mut();
        }
        // SAFETY: any sizes.
        held(unsafe { libc::calloc(n, size) })
    }

    /// Install, once for the process, an allocator that counts each
    /// thread's blocks and can refuse one: it hands out `malloc`'s, so
    /// the other tests' frees still find their blocks.
    fn counting() {
        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            let code = crate::root::curl_global_init_mem(
                0,
                Some(counted_malloc),
                Some(counted_free),
                Some(counted_realloc),
                Some(counted_strdup),
                Some(counted_calloc),
            );
            assert_eq!(code, CURLE_OK);
        });
        let before = HELD.with(core::cell::Cell::get);
        let p = crate::root::allocator().malloc(1);
        assert_eq!(HELD.with(core::cell::Cell::get), before + 1, "installed");
        // SAFETY: just allocated.
        unsafe { crate::root::allocator().free(p) };
    }

    /// A call refused for want of memory at any of its allocations frees
    /// what it made before: the copies, then the nodes; one that succeeds,
    /// allocating as often as C's, makes a chain `curl_formfree` frees
    /// whole.
    #[test]
    fn formadd_frees_what_it_made_when_refused() {
        counting();
        let (txt, txt_c) = scratch("refused.txt");
        let (bare, bare_c) = scratch("refused");
        for limit in 0.. {
            let before = HELD.with(core::cell::Cell::get);
            LEFT.with(|l| l.set(Some(limit)));
            let (code, first) = add(&[
                entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
                entry(ffi::CURLFORM_FILE, txt_c.as_ptr()),
                entry(ffi::CURLFORM_FILE, bare_c.as_ptr()),
            ]);
            LEFT.with(|l| l.set(None));
            if code == CURL_FORMADD_OK {
                // As many as C's: two file names, their types, the
                // name, two nodes.
                assert_eq!(limit, 7, "{limit} allocations sufficed");
                // SAFETY: the chain just made, not used again.
                unsafe { curl_formfree(first) };
                assert_eq!(HELD.with(core::cell::Cell::get), before, "all freed");
                break;
            }
            assert_eq!((code, first), (ffi::CURL_FORMADD_MEMORY, ptr::null_mut()));
            assert_eq!(
                HELD.with(core::cell::Cell::get),
                before,
                "freed, refused after {limit}"
            );
        }
        std::fs::remove_file(txt).unwrap();
        std::fs::remove_file(bare).unwrap();
    }

    /// With `CURL_ENTROPY` set, a debug build draws each tree's boundary
    /// from it, the numbers going on from one tree to the next, as C's
    /// debug build gives them to the same calls. Checked in a process of
    /// its own, the variable set there.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn a_debug_build_draws_boundaries_from_curl_entropy() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "formdata::tests::boundaries_drawn_from_curl_entropy",
                "--ignored",
            ])
            .env("CURL_ENTROPY", "12345678")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}");
        assert!(stdout.contains("1 passed"), "the test ran: {stdout}");
    }

    #[cfg(feature = "debug-hooks")]
    #[test]
    #[ignore = "run by a_debug_build_draws_boundaries_from_curl_entropy, CURL_ENTROPY set"]
    fn boundaries_drawn_from_curl_entropy() {
        let (code, first) = add(&[
            entry(ffi::CURLFORM_COPYNAME, c"n".as_ptr()),
            entry(ffi::CURLFORM_COPYCONTENTS, c"v".as_ptr()),
        ]);
        assert_eq!(code, CURL_FORMADD_OK);
        for want in ["qrstuvwxyz0123456789AB", "CDEFGHIJKLMNOPQRSTUVWX"] {
            let (got, bytes) = formget(first);
            assert_eq!(got, 0);
            let line = format!("\r\n--------------------------{want}\r\n");
            assert!(holds(&bytes, line.as_bytes()), "{}", bytes.escape_ascii());
        }
        // SAFETY: the chain, not used again.
        unsafe { curl_formfree(first) };
    }
}
