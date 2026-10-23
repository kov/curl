//! `curl_mime_*` and `CURLOPT_MIMEPOST` (`lib/mime.c`): the tree as C's
//! API shapes it, and the core `Mime` built from it at each request.
//!
//! The application holds pointers to every node and may change any of
//! them between transfers, attach a tree under a part, or free one that a
//! handle or a part still names. So the nodes live here, boxed, with the
//! links C's API needs: each tree knows what it is attached to, and is
//! taken from there when it is freed, so nothing is left pointing at it.
//! The core never sees these: it asks the handle's `MimeTree` for a
//! `Mime` each time it builds a request, as it reads a header list again.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::num::NonZeroUsize;
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};
use curl_core::handler::{Handler, Read, ReadHandler, Rewind, RewindFailed};
use curl_core::mime::{
    Boundary, Content, Encoder, FileData, FileError, MAX_LEVELS, Mime, MimeError, MimeSource, Part,
    Reached, SentHead,
};
use curl_core::multi::TransferCx;

use crate::callbacks::Adapter;
use crate::easy::{PostBody, ShimEasy};
use crate::ffi::{
    self, CURL, CURL_READFUNC_ABORT, CURL_READFUNC_PAUSE, CURL_SEEKFUNC_OK,
    CURLE_BAD_FUNCTION_ARGUMENT, CURLE_OK, CURLE_OUT_OF_MEMORY, CURLE_READ_ERROR,
    CURLE_SEND_FAIL_REWIND, CURLcode, curl_free_callback, curl_mime, curl_mimepart, curl_off_t,
    curl_read_callback, curl_seek_callback, curl_slist,
};

/// A `curl_mime`: parts between boundaries.
pub(crate) struct ShimMime {
    boundary: Boundary,
    parts: Vec<NonNull<ShimPart>>,
    parent: Parent,
}

/// What a tree is attached to (`curl_mime`'s `parent`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Parent {
    None,
    /// A part's subparts, owned by it.
    Part(NonNull<ShimPart>),
    /// A handle's body (`CURLOPT_MIMEPOST`), the application's.
    Easy(NonNull<ShimEasy>),
    /// A handle's body, a copy the handle made and owns
    /// (`curl_easy_duphandle`).
    OwnedBy(NonNull<ShimEasy>),
    /// Being freed: the tree to free after it.
    Freeing(Option<NonNull<ShimMime>>),
}

/// A `curl_mimepart`.
pub(crate) struct ShimPart {
    /// The tree it is in.
    mime: NonNull<ShimMime>,
    name: Option<Vec<u8>>,
    filename: Option<Vec<u8>>,
    mime_type: Option<Vec<u8>>,
    encoder: Option<Encoder>,
    /// `curl_mime_headers`: the application's list, freed with the part
    /// if it gave it to the part.
    headers: *mut curl_slist,
    headers_owned: bool,
    content: PartContent,
    /// A request's reading reached it since it last started over: C's
    /// part state past its start, kept across the trees built of it.
    reached: Reached,
}

#[derive(Default)]
enum PartContent {
    #[default]
    None,
    Data(TryArc<Vec<u8>>),
    File(FileData),
    Callback(Callback),
    /// Subparts, owned by the part.
    Subparts(NonNull<ShimMime>),
}

/// `curl_mime_data_cb`'s functions and their argument.
#[derive(Clone, Copy)]
struct Callback {
    read: unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize,
    seek: curl_seek_callback,
    free: curl_free_callback,
    arg: *mut c_void,
    size: Option<u64>,
}

/// The tree behind a pointer the application passed, if not NULL.
///
/// # Safety
///
/// `mime` is NULL or a live tree from `curl_mime_init`.
unsafe fn tree<'a>(mime: *mut curl_mime) -> Option<&'a mut ShimMime> {
    // SAFETY: as the caller guarantees; C lets one thread use a tree at a
    // time.
    unsafe { mime.cast::<ShimMime>().as_mut() }
}

/// # Safety
///
/// `part` is NULL or a live part from `curl_mime_addpart`.
unsafe fn part_at<'a>(part: *mut curl_mimepart) -> Option<&'a mut ShimPart> {
    // SAFETY: as the caller guarantees.
    unsafe { part.cast::<ShimPart>().as_mut() }
}

/// A copy of a C string, or none for NULL.
///
/// # Safety
///
/// `s` is NULL or a C string.
unsafe fn copy_c(s: *const c_char) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if s.is_null() {
        return Ok(None);
    }
    // SAFETY: as the caller guarantees.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    copy(bytes).map(Some)
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes)?;
    Ok(v)
}

/// A boundary drawn as C's debug build draws it: from `CURL_ENTROPY` if
/// set, else from the kernel.
fn new_boundary() -> Option<Boundary> {
    #[cfg(feature = "debug-hooks")]
    if crate::root::forced_entropy_set() {
        return Boundary::draw(|| crate::root::forced_entropy().ok_or(())).ok();
    }
    Boundary::random().ok()
}

/// A new tree, with no parts and a boundary of its own.
fn new_tree() -> Option<NonNull<ShimMime>> {
    let boundary = new_boundary()?;
    let mime = try_box(ShimMime {
        boundary,
        parts: Vec::new(),
        parent: Parent::None,
    })
    .ok()?;
    Some(NonNull::from(Box::leak(mime)))
}

/// # Safety
///
/// `easy` is NULL or a live handle; it is used for nothing but the
/// boundary's randomness, as in C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_init(_easy: *mut CURL) -> *mut curl_mime {
    new_tree().map_or(ptr::null_mut(), |m| m.as_ptr().cast())
}
const _: ffi::proto::curl_mime_init = curl_mime_init;

/// Append a part to `mime`.
fn add_part(mime: &mut ShimMime) -> Option<NonNull<ShimPart>> {
    mime.parts.try_reserve(1).ok()?;
    let part = try_box(ShimPart {
        mime: NonNull::from(&mut *mime),
        name: None,
        filename: None,
        mime_type: None,
        encoder: None,
        headers: ptr::null_mut(),
        headers_owned: false,
        content: PartContent::None,
        reached: Reached::new().ok()?,
    })
    .ok()?;
    let part = NonNull::from(Box::leak(part));
    mime.parts.try_push(part).expect("reserved above");
    Some(part)
}

/// # Safety
///
/// `mime` is NULL or a live tree.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_addpart(mime: *mut curl_mime) -> *mut curl_mimepart {
    // SAFETY: as the caller guarantees.
    let Some(mime) = (unsafe { tree(mime) }) else {
        return ptr::null_mut();
    };
    add_part(mime).map_or(ptr::null_mut(), |p| p.as_ptr().cast())
}
const _: ffi::proto::curl_mime_addpart = curl_mime_addpart;

/// Set one of a part's strings to a copy of `value`, or none.
///
/// # Safety
///
/// `p` is NULL or a live part; `value` is NULL or a C string.
unsafe fn set_string(
    p: *mut curl_mimepart,
    value: *const c_char,
    field: fn(&mut ShimPart) -> &mut Option<Vec<u8>>,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(p) = (unsafe { part_at(p) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    *field(p) = None;
    // SAFETY: as the caller guarantees.
    match unsafe { copy_c(value) } {
        Ok(v) => {
            *field(p) = v;
            CURLE_OK
        }
        Err(OutOfMemory) => CURLE_OUT_OF_MEMORY,
    }
}

/// # Safety
///
/// `part` is NULL or a live part; `name` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_name(part: *mut curl_mimepart, name: *const c_char) -> CURLcode {
    // SAFETY: as the caller guarantees.
    unsafe { set_string(part, name, |p| &mut p.name) }
}
const _: ffi::proto::curl_mime_name = curl_mime_name;

/// # Safety
///
/// `part` is NULL or a live part; `filename` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_filename(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    unsafe { set_string(part, filename, |p| &mut p.filename) }
}
const _: ffi::proto::curl_mime_filename = curl_mime_filename;

/// # Safety
///
/// `part` is NULL or a live part; `mimetype` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_type(
    part: *mut curl_mimepart,
    mimetype: *const c_char,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    unsafe { set_string(part, mimetype, |p| &mut p.mime_type) }
}
const _: ffi::proto::curl_mime_type = curl_mime_type;

/// # Safety
///
/// `part` is NULL or a live part; `encoding` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_encoder(
    part: *mut curl_mimepart,
    encoding: *const c_char,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(p) = (unsafe { part_at(part) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    p.encoder = None;
    if encoding.is_null() {
        return CURLE_OK;
    }
    // SAFETY: as the caller guarantees.
    let name = unsafe { CStr::from_ptr(encoding) }.to_bytes();
    match Encoder::from_name(name) {
        Some(e) => {
            p.encoder = Some(e);
            CURLE_OK
        }
        None => CURLE_BAD_FUNCTION_ARGUMENT,
    }
}
const _: ffi::proto::curl_mime_encoder = curl_mime_encoder;

/// Let go of a part's content (`cleanup_part_content`): the free function
/// called, subparts freed.
fn clear_content(p: &mut ShimPart) {
    match core::mem::take(&mut p.content) {
        PartContent::Callback(cb) => {
            if let Some(free) = cb.free {
                // SAFETY: the application's free function takes its
                // argument, once the part no longer reads it.
                unsafe { free(cb.arg) };
            }
        }
        // SAFETY: the part owned its subparts, which nothing else frees.
        PartContent::Subparts(sub) => unsafe { free_tree(sub) },
        PartContent::None | PartContent::Data(_) | PartContent::File(_) => {}
    }
    p.reached.set(false);
}

/// # Safety
///
/// `part` is NULL or a live part; `data` is NULL, or `datasize` readable
/// bytes, or a C string for `CURL_ZERO_TERMINATED`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_data(
    part: *mut curl_mimepart,
    data: *const c_char,
    datasize: usize,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(p) = (unsafe { part_at(part) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    clear_content(p);
    if data.is_null() {
        return CURLE_OK;
    }
    let bytes = if datasize as u64 == ffi::CURL_ZERO_TERMINATED {
        // SAFETY: as the caller guarantees.
        unsafe { CStr::from_ptr(data) }.to_bytes()
    } else {
        // SAFETY: as the caller guarantees.
        unsafe { core::slice::from_raw_parts(data.cast::<u8>(), datasize) }
    };
    match copy(bytes).and_then(TryArc::try_new) {
        Ok(d) => {
            p.content = PartContent::Data(d);
            CURLE_OK
        }
        Err(OutOfMemory) => CURLE_OUT_OF_MEMORY,
    }
}
const _: ffi::proto::curl_mime_data = curl_mime_data;

/// The last part of a path, as POSIX `basename` gives it: trailing
/// slashes dropped, `/` for slashes alone, `.` for nothing.
fn basename(path: &[u8]) -> &[u8] {
    let trimmed = match path.iter().rposition(|&b| b != b'/') {
        Some(end) => &path[..=end],
        None if path.is_empty() => return b".",
        None => return b"/",
    };
    match trimmed.iter().rposition(|&b| b == b'/') {
        Some(at) => &trimmed[at + 1..],
        None => trimmed,
    }
}

/// # Safety
///
/// `part` is NULL or a live part; `filename` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_filedata(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(p) = (unsafe { part_at(part) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    clear_content(p);
    if filename.is_null() {
        return CURLE_OK;
    }
    // SAFETY: as the caller guarantees.
    let path = unsafe { CStr::from_ptr(filename) }.to_bytes();
    match FileData::new(path) {
        Ok(f) => p.content = PartContent::File(f),
        Err(FileError::Unreadable) => return CURLE_READ_ERROR,
        Err(FileError::OutOfMemory) => return CURLE_OUT_OF_MEMORY,
    }
    // The part is named after the file, unless named otherwise later.
    match copy(basename(path)) {
        Ok(name) => {
            p.filename = Some(name);
            CURLE_OK
        }
        Err(OutOfMemory) => CURLE_OUT_OF_MEMORY,
    }
}
const _: ffi::proto::curl_mime_filedata = curl_mime_filedata;

/// # Safety
///
/// `part` is NULL or a live part; the functions take `arg`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_data_cb(
    part: *mut curl_mimepart,
    datasize: curl_off_t,
    readfunc: curl_read_callback,
    seekfunc: curl_seek_callback,
    freefunc: curl_free_callback,
    arg: *mut c_void,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(p) = (unsafe { part_at(part) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    clear_content(p);
    if let Some(read) = readfunc {
        p.content = PartContent::Callback(Callback {
            read,
            seek: seekfunc,
            free: freefunc,
            arg,
            size: u64::try_from(datasize).ok(),
        });
    }
    CURLE_OK
}
const _: ffi::proto::curl_mime_data_cb = curl_mime_data_cb;

/// # Safety
///
/// `part` is NULL or a live part; `headers` is NULL or a list from
/// `curl_slist_append`, which the part frees if `take_ownership`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_headers(
    part: *mut curl_mimepart,
    headers: *mut curl_slist,
    take_ownership: c_int,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(p) = (unsafe { part_at(part) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    if p.headers_owned {
        // The same list given again stays.
        if p.headers != headers {
            // SAFETY: the part was given the list to free.
            unsafe { crate::strings::curl_slist_free_all(p.headers) };
        }
        p.headers_owned = false;
    }
    p.headers = headers;
    p.headers_owned = !headers.is_null() && take_ownership != 0;
    CURLE_OK
}
const _: ffi::proto::curl_mime_headers = curl_mime_headers;

/// Start over the parts of `mime` a request reached since they last
/// started over, as a tree attached anew is (`mime_subparts_seek`), as the
/// core does as a request starts: whether all could be.
fn rewind_tree(mime: &ShimMime) -> bool {
    let mut ok = true;
    for &p in &mime.parts {
        // SAFETY: a tree's parts live as long as it does.
        let p = unsafe { p.as_ref() };
        if !p.reached.get() {
            continue;
        }
        let over = match &p.content {
            // Nothing to start over, where C fails (DIVERGENCE.md).
            PartContent::None | PartContent::Data(_) => true,
            // Not a regular file: no way back.
            PartContent::File(f) => f.size().is_some(),
            PartContent::Callback(cb) => seek(cb),
            // SAFETY: as above, for its subparts.
            PartContent::Subparts(sub) => rewind_tree(unsafe { sub.as_ref() }),
        };
        if over {
            p.reached.set(false);
        }
        ok &= over;
    }
    ok
}

/// Start a callback part over with its seek function
/// (`mime_part_rewind`): whether it could be.
fn seek(cb: &Callback) -> bool {
    let Some(seek) = cb.seek else {
        return false;
    };
    // SAFETY: the application's seek function takes its argument.
    unsafe { seek(cb.arg, 0, libc::SEEK_SET) == CURL_SEEKFUNC_OK }
}

/// # Safety
///
/// `part` is NULL or a live part; `subparts` is NULL or a live tree,
/// which the part owns from now on.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_subparts(
    part: *mut curl_mimepart,
    subparts: *mut curl_mime,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(p) = (unsafe { part_at(part) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let sub = NonNull::new(subparts.cast::<ShimMime>());
    // The same subparts given again stay.
    if let (PartContent::Subparts(have), Some(sub)) = (&p.content, sub)
        && *have == sub
    {
        return CURLE_OK;
    }
    clear_content(p);
    let Some(sub) = sub else {
        return CURLE_OK;
    };
    // SAFETY: as the caller guarantees.
    let tree = unsafe { &mut *sub.as_ptr() };
    if tree.parent != Parent::None {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // Not under itself: its root is the topmost tree above the part.
    let mut root = p.mime;
    // SAFETY: a part's tree and the parts trees are attached to outlive
    // them.
    while let Parent::Part(up) = unsafe { root.as_ref() }.parent {
        // SAFETY: as above.
        root = unsafe { up.as_ref() }.mime;
    }
    if root == sub {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if !rewind_tree(tree) {
        return CURLE_SEND_FAIL_REWIND;
    }
    tree.parent = Parent::Part(NonNull::from(&mut *p));
    p.content = PartContent::Subparts(sub);
    CURLE_OK
}
const _: ffi::proto::curl_mime_subparts = curl_mime_subparts;

/// Free a tree and everything under it, without recursing: each tree of
/// subparts is queued through its `parent` (`curl_mime_free`).
///
/// # Safety
///
/// `mime` is a live tree, attached to nothing that will use it again.
unsafe fn free_tree(mime: NonNull<ShimMime>) {
    // SAFETY: as the caller guarantees.
    unsafe { (*mime.as_ptr()).parent = Parent::Freeing(None) };
    let mut next = Some(mime);
    while let Some(m) = next {
        // SAFETY: queued trees are live and freed only here.
        let tree = unsafe { &mut *m.as_ptr() };
        next = match tree.parent {
            Parent::Freeing(after) => after,
            _ => unreachable!("a queued tree says what follows it"),
        };
        for p in core::mem::take(&mut tree.parts) {
            // SAFETY: made by `Box::leak` in `add_part`, owned by the tree.
            let mut part = unsafe { Box::from_raw(p.as_ptr()) };
            if let PartContent::Subparts(sub) = part.content {
                part.content = PartContent::None;
                // SAFETY: the part owned it; queued to be freed.
                unsafe { (*sub.as_ptr()).parent = Parent::Freeing(next) };
                next = Some(sub);
            }
            clear_content(&mut part);
            if part.headers_owned {
                // SAFETY: the part was given the list to free.
                unsafe { crate::strings::curl_slist_free_all(part.headers) };
            }
        }
        // SAFETY: made by `Box::leak` in `new_tree`, freed once.
        drop(unsafe { Box::from_raw(m.as_ptr()) });
    }
}

/// # Safety
///
/// `mime` is NULL or a live tree, not used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_mime_free(mime: *mut curl_mime) {
    let Some(m) = NonNull::new(mime.cast::<ShimMime>()) else {
        return;
    };
    // Taken from what it is attached to (`mime_subparts_unbind`).
    // SAFETY: as the caller guarantees.
    match unsafe { m.as_ref() }.parent {
        Parent::Easy(easy) | Parent::OwnedBy(easy) => {
            // SAFETY: a handle a tree is attached to is live.
            if let Some(posted) = unsafe { easy.as_ref() }.posted() {
                posted.mime.set(None);
            }
        }
        Parent::Part(mut p) => {
            // SAFETY: a part subparts are attached to is live; its content
            // is this tree, freed below and not here.
            unsafe { p.as_mut() }.content = PartContent::None;
        }
        Parent::None | Parent::Freeing(_) => {}
    }
    // SAFETY: as the caller guarantees, now attached to nothing.
    unsafe { free_tree(m) };
}
const _: ffi::proto::curl_mime_free = curl_mime_free;

/// What `CURLOPT_MIMEPOST` refuses.
pub(crate) enum Refused {
    /// The tree is attached elsewhere already.
    Attached,
    OutOfMemory,
    /// A part read before could not be rewound.
    Rewind,
}

/// `CURLOPT_MIMEPOST`: the handle posts `mime`, the application's, or
/// nothing (`setopt_mimepost`). What it posted before is let go of first.
///
/// # Safety
///
/// `mime` is NULL or a live tree.
pub(crate) unsafe fn set_post(easy: NonNull<ShimEasy>, mime: *mut c_void) -> Result<(), Refused> {
    // SAFETY: the handle is live while its options are set.
    let shim = unsafe { easy.as_ref() };
    let mime = NonNull::new(mime.cast::<ShimMime>());
    let have = shim.posted().and_then(|p| p.mime.get());
    if let (Some(have), Some(m)) = (have, mime)
        && have == m
    {
        return Ok(());
    }
    detach(shim);
    let Some(m) = mime else {
        return Ok(());
    };
    let posted = shim.posted_or_make().map_err(|_| Refused::OutOfMemory)?;
    // SAFETY: as the caller guarantees.
    let tree = unsafe { &mut *m.as_ptr() };
    if tree.parent != Parent::None {
        return Err(Refused::Attached);
    }
    if !rewind_tree(tree) {
        return Err(Refused::Rewind);
    }
    tree.parent = Parent::Easy(easy);
    posted.mime.set(Some(m));
    Ok(())
}

/// Let go of what the handle posts: the application's tree unbound, the
/// handle's own copy freed.
pub(crate) fn detach(shim: &ShimEasy) {
    let Some(m) = shim.posted().and_then(|p| p.mime.take()) else {
        return;
    };
    // SAFETY: a tree a handle posts is live until freed, which takes it
    // from the handle first.
    let tree = unsafe { &mut *m.as_ptr() };
    match tree.parent {
        Parent::Easy(_) => tree.parent = Parent::None,
        // SAFETY: the handle's own, which nothing else names.
        Parent::OwnedBy(_) => unsafe { free_tree(m) },
        Parent::None | Parent::Part(_) | Parent::Freeing(_) => {
            unreachable!("a tree a handle posts says so")
        }
    }
}

/// How deep a tree's parts nest, its own counted as 1.
fn depth(mime: &ShimMime) -> usize {
    1 + mime
        .parts
        .iter()
        .map(|p| {
            // SAFETY: a tree's parts live as long as it does.
            match &unsafe { p.as_ref() }.content {
                // SAFETY: as above.
                PartContent::Subparts(sub) => depth(unsafe { sub.as_ref() }),
                _ => 0,
            }
        })
        .max()
        .unwrap_or(0)
}

/// Why a handle's tree could not be copied.
pub(crate) enum DupError {
    OutOfMemory,
    /// Past `MAX_LEVELS`.
    TooDeep,
}

/// Give `to`, a copy of `from`, a copy of the tree `from` posts
/// (`Curl_mime_duppart`).
pub(crate) fn duplicate(from: &ShimEasy, to: NonNull<ShimEasy>) -> Result<(), DupError> {
    let Some(m) = from.posted().and_then(|p| p.mime.get()) else {
        return Ok(());
    };
    // SAFETY: a tree a handle posts is live.
    let tree = unsafe { m.as_ref() };
    // The handle's part above the tree is a level of its own.
    if 1 + depth(tree) > MAX_LEVELS {
        return Err(DupError::TooDeep);
    }
    // SAFETY: the copy is live.
    let posted = unsafe { to.as_ref() }
        .posted_or_make()
        .map_err(|_| DupError::OutOfMemory)?;
    let copy = copy_tree(tree).ok_or(DupError::OutOfMemory)?;
    // SAFETY: just made, attached to nothing.
    unsafe { (*copy.as_ptr()).parent = Parent::OwnedBy(to) };
    posted.mime.set(Some(copy));
    Ok(())
}

/// A copy of a tree, with a boundary of its own; a part's file read
/// again, and left empty if it cannot be.
fn copy_tree(from: &ShimMime) -> Option<NonNull<ShimMime>> {
    let to = new_tree()?;
    let copied = (|| {
        for &p in &from.parts {
            // SAFETY: a tree's parts live as long as it does.
            let src = unsafe { p.as_ref() };
            // SAFETY: just made and owned here.
            let mut dst = add_part(unsafe { &mut *to.as_ptr() })?;
            // SAFETY: as above.
            let dst = unsafe { dst.as_mut() };
            dst.content = match &src.content {
                PartContent::None => PartContent::None,
                PartContent::Data(d) => PartContent::Data(d.clone()),
                PartContent::File(f) => match FileData::new(f.path()) {
                    Ok(f) => PartContent::File(f),
                    Err(FileError::Unreadable) => PartContent::None,
                    Err(FileError::OutOfMemory) => return None,
                },
                PartContent::Callback(cb) => PartContent::Callback(*cb),
                PartContent::Subparts(sub) => {
                    // SAFETY: as above.
                    let sub = copy_tree(unsafe { sub.as_ref() })?;
                    // SAFETY: just made.
                    unsafe { (*sub.as_ptr()).parent = Parent::Part(NonNull::from(&mut *dst)) };
                    PartContent::Subparts(sub)
                }
            };
            if !src.headers.is_null() {
                dst.headers = duplicate_list(src.headers)?;
                dst.headers_owned = true;
            }
            dst.encoder = src.encoder;
            dst.mime_type = src.mime_type.as_deref().map(copy).transpose().ok()?;
            dst.name = src.name.as_deref().map(copy).transpose().ok()?;
            dst.filename = src.filename.as_deref().map(copy).transpose().ok()?;
        }
        Some(())
    })();
    if copied.is_none() {
        // SAFETY: the partial copy is attached to nothing.
        unsafe { free_tree(to) };
        return None;
    }
    Some(to)
}

/// A copy of a list, its nodes the application's to free.
fn duplicate_list(list: *mut curl_slist) -> Option<*mut curl_slist> {
    let mut copy: *mut curl_slist = ptr::null_mut();
    let mut at = list;
    while let Some(node) = NonNull::new(at) {
        // SAFETY: a live list's nodes.
        let node = unsafe { node.as_ref() };
        // SAFETY: `copy` is NULL or the list built so far; `data` a C
        // string.
        let grown = unsafe { crate::strings::curl_slist_append(copy, node.data) };
        if grown.is_null() {
            // SAFETY: the list built so far, ours.
            unsafe { crate::strings::curl_slist_free_all(copy) };
            return None;
        }
        copy = grown;
        at = node.next;
    }
    Some(copy)
}

/// What a handle may post besides its own body.
pub(crate) struct Posted {
    /// The tree a MIME POST sends (`CURLOPT_MIMEPOST`).
    pub(crate) mime: Cell<Option<NonNull<ShimMime>>>,
    /// The chain a form POST sends (`CURLOPT_HTTPPOST`), the
    /// application's.
    pub(crate) chain: Cell<*mut ffi::curl_httppost>,
    /// The tree made of that chain for the first request that sent it,
    /// the handle's own, until the chain is set again (`state.formp`).
    pub(crate) form: Cell<Option<NonNull<ShimMime>>>,
    /// The head lines the last request that posted a tree sent, until
    /// the post is set again (`state.mimepost`'s `curlheaders`).
    sent: SentHead,
}

impl Posted {
    pub(crate) fn new() -> Posted {
        Posted {
            mime: Cell::new(None),
            chain: Cell::new(ptr::null_mut()),
            form: Cell::new(None),
            sent: SentHead::default(),
        }
    }
}

/// The tree a handle posts, as the core reads it: built from the
/// application's nodes each time a request is.
pub(crate) struct MimeTree(pub(crate) NonNull<ShimEasy>);

// SAFETY: as for `callbacks::Adapter`: the handle's alone, used by one
// thread at a time.
unsafe impl Send for MimeTree {}
// SAFETY: as for `Send`.
unsafe impl Sync for MimeTree {}

impl MimeSource for MimeTree {
    fn sent_head(&self) -> Option<&SentHead> {
        // SAFETY: the handle outlives the options that hold its adapters.
        let shim = unsafe { self.0.as_ref() };
        shim.posted().map(|p| &p.sent)
    }

    fn mime(&self) -> Result<Option<TryArc<Mime>>, MimeError> {
        // SAFETY: the handle outlives the options that hold its adapters.
        let shim = unsafe { self.0.as_ref() };
        let tree = match shim.post_body.get() {
            PostBody::Mime => shim.posted().and_then(|p| p.mime.get()),
            PostBody::Form => form_tree(shim)?,
            PostBody::Own => None,
        };
        let Some(m) = tree else {
            return Ok(None);
        };
        let easy = self.0;
        let mut handlers = |part: NonNull<ShimPart>, cb: &Callback| -> Result<Content, MimeError> {
            Ok(Content::Read {
                handler: Handler::read(PartAdapter { part, easy })?,
                rewind: Some(Handler::rewind(PartAdapter { part, easy })?),
                size: cb.size,
            })
        };
        // SAFETY: a tree a handle posts is live.
        let mime = build(unsafe { m.as_ref() }, &mut handlers, 1)?;
        Ok(Some(TryArc::try_new(mime)?))
    }
}

/// The tree the handle made of its form chain, made now if not yet
/// (`set_post_reader`'s `Curl_getformdata`), its streams read by the read
/// function set now; kept until the chain is set again.
fn form_tree(shim: &ShimEasy) -> Result<Option<NonNull<ShimMime>>, MimeError> {
    // Made when the chain was set.
    let Some(posted) = shim.posted() else {
        return Ok(None);
    };
    if let Some(tree) = posted.form.get() {
        return Ok(Some(tree));
    }
    let read = shim.ccb.get().read.or(Some(crate::callbacks::fread));
    // SAFETY: the application keeps the chain it set alive and unchanged
    // while the handle may post it, as C requires.
    match unsafe { crate::formdata::tree_of(posted.chain.get(), read) } {
        Ok(tree) => {
            posted.form.set(tree);
            Ok(tree)
        }
        Err(crate::formdata::NotConverted(CURLE_OUT_OF_MEMORY)) => Err(MimeError::OutOfMemory),
        // A file it names cannot be read.
        Err(_) => Err(MimeError::Unreadable),
    }
}

/// Let go of what the handle made of its post as it is set again: the
/// tree made of its form chain and the head lines last sent
/// (`state.formp`, `state.mimepost`).
pub(crate) fn forget_post_state(shim: &ShimEasy) {
    let Some(posted) = shim.posted() else {
        return;
    };
    posted.sent.clear();
    if let Some(tree) = posted.form.take() {
        // SAFETY: the handle's own, which nothing else names.
        unsafe { free_tree(tree) };
    }
}

/// The core's tree of `tree`, outside any transfer (`curl_formget`): a
/// part a function reads is read whole now, as there is no transfer to
/// call it in later. Failing, the code to return.
pub(crate) fn whole(tree: &ShimMime) -> Result<TryArc<Mime>, CURLcode> {
    let mut failed = CURLE_OK;
    let mut read_now = |_: NonNull<ShimPart>, cb: &Callback| -> Result<Content, MimeError> {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let room = match cb.size {
                Some(size) => (size.saturating_sub(bytes.len() as u64)).min(buf.len() as u64),
                None => buf.len() as u64,
            } as usize;
            if room == 0 {
                break;
            }
            // SAFETY: `buf` has room for `room` bytes; the function takes
            // its argument.
            let got = unsafe { (cb.read)(buf.as_mut_ptr().cast(), 1, room, cb.arg) };
            if got == 0 {
                break;
            }
            if got > room {
                failed = if got == CURL_READFUNC_ABORT as usize {
                    ffi::CURLE_ABORTED_BY_CALLBACK
                } else {
                    CURLE_READ_ERROR
                };
                return Err(MimeError::Unreadable);
            }
            bytes.try_extend_from_slice(&buf[..got])?;
        }
        Ok(Content::Bytes(TryArc::try_new(bytes)?))
    };
    let built = build(tree, &mut read_now, 1).and_then(|m| Ok(TryArc::try_new(m)?));
    match built {
        Ok(mime) => Ok(mime),
        Err(_) if failed != CURLE_OK => Err(failed),
        Err(MimeError::OutOfMemory) => Err(CURLE_OUT_OF_MEMORY),
        Err(MimeError::TooDeep) => Err(ffi::CURLE_TOO_LARGE),
        Err(MimeError::Unreadable) => Err(CURLE_READ_ERROR),
    }
}

/// What a part a function reads holds in the core's tree.
type CallbackContent<'a> =
    dyn FnMut(NonNull<ShimPart>, &Callback) -> Result<Content, MimeError> + 'a;

/// The core's tree of the application's, `depth` levels down, the content
/// of a part a function reads made by `callback`.
fn build(
    from: &ShimMime,
    callback: &mut CallbackContent<'_>,
    depth: usize,
) -> Result<Mime, MimeError> {
    // Deeper than the core makes: refused before it would be.
    if depth > MAX_LEVELS + 1 {
        return Err(MimeError::TooDeep);
    }
    let mut mime = Mime::new(from.boundary);
    for &p in &from.parts {
        // SAFETY: a tree's parts live as long as it does.
        let src = unsafe { p.as_ref() };
        let content = match &src.content {
            PartContent::None => Content::None,
            PartContent::Data(d) => Content::Bytes(d.clone()),
            PartContent::File(f) => Content::File(f.try_clone()?),
            PartContent::Callback(cb) => callback(p, cb)?,
            PartContent::Subparts(sub) => {
                // SAFETY: a part's subparts live as long as it does.
                Content::Parts(build(unsafe { sub.as_ref() }, callback, depth + 1)?)
            }
        };
        let mut headers = Vec::new();
        let mut at = src.headers;
        while let Some(node) = NonNull::new(at) {
            // SAFETY: the application's live list.
            let node = unsafe { node.as_ref() };
            if !node.data.is_null() {
                // SAFETY: each node holds a C string.
                let line = unsafe { CStr::from_ptr(node.data) }.to_bytes();
                headers.try_push(copy(line)?)?;
            }
            at = node.next;
        }
        mime.add(Part {
            name: src.name.as_deref().map(copy).transpose()?,
            filename: src.filename.as_deref().map(copy).transpose()?,
            mime_type: src.mime_type.as_deref().map(copy).transpose()?,
            headers,
            encoder: src.encoder,
            content,
            reached: src.reached.clone(),
        })?;
    }
    Ok(mime)
}

/// A callback part's functions, called for the handle's transfer.
struct PartAdapter {
    part: NonNull<ShimPart>,
    easy: NonNull<ShimEasy>,
}

// SAFETY: as for `MimeTree`.
unsafe impl Send for PartAdapter {}
// SAFETY: as for `MimeTree`.
unsafe impl Sync for PartAdapter {}

impl PartAdapter {
    /// The part's functions, if it still has them.
    fn callback(&self) -> Option<Callback> {
        // SAFETY: the tree outlives the request that reads it, as C
        // requires of a tree a handle posts.
        let p = unsafe { self.part.as_ref() };
        match &p.content {
            PartContent::Callback(cb) => Some(*cb),
            _ => None,
        }
    }
}

impl ReadHandler for PartAdapter {
    fn read(&self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        let Some(cb) = self.callback() else {
            return Read::Fail;
        };
        let len = buf.len();
        let got = Adapter(self.easy).call(cx, || {
            // SAFETY: `buf` has room for `len` bytes; the function takes
            // its argument.
            unsafe { (cb.read)(buf.as_mut_ptr().cast(), 1, len, cb.arg) }
        });
        if got == CURL_READFUNC_ABORT as usize {
            Read::Abort
        } else if got == CURL_READFUNC_PAUSE as usize {
            Read::Pause
        } else if got >= usize::MAX - 1 {
            // C's `READ_ERROR`, and its `STOP_FILLING`, which it would ask
            // again for ever.
            Read::Fail
        } else {
            NonZeroUsize::new(got).map_or(Read::Eof, Read::Data)
        }
    }
}

impl Rewind for PartAdapter {
    fn rewind(&self, cx: &mut TransferCx<'_>) -> Result<(), RewindFailed> {
        let Some(cb) = self.callback() else {
            return Err(RewindFailed);
        };
        let ok = Adapter(self.easy).call(cx, || seek(&cb));
        if ok { Ok(()) } else { Err(RewindFailed) }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "one contract covers each test's sequence of calls"
    )]

    use core::ffi::{c_char, c_void};
    use core::ptr::{self, NonNull};
    use std::cell::Cell;

    use curl_core::mime::{Content, MimeSource as _};
    use curl_core::options::UploadSource;

    use super::{
        MimeTree, basename, curl_mime_addpart, curl_mime_data, curl_mime_data_cb,
        curl_mime_encoder, curl_mime_filedata, curl_mime_free, curl_mime_init, curl_mime_name,
        curl_mime_subparts,
    };
    use crate::easy::{self, curl_easy_cleanup, curl_easy_duphandle, curl_easy_init};
    use crate::ffi::{
        self, CURL, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_OK, CURLE_READ_ERROR,
        CURLE_SEND_FAIL_REWIND, curl_mime,
    };
    use crate::setopt::curl_easy_setopt;

    /// POSIX's `basename`, as glibc's libgen gives it to C.
    #[test]
    fn basename_is_posix_s() {
        for (path, base) in [
            (&b"/a/b.txt"[..], &b"b.txt"[..]),
            (b"b", b"b"),
            (b"a/b/", b"b"),
            (b"/", b"/"),
            (b"//", b"/"),
            (b"", b"."),
        ] {
            assert_eq!(basename(path), base, "{}", path.escape_ascii());
        }
    }

    fn post(c: *mut CURL, mime: *mut curl_mime) -> ffi::CURLcode {
        // SAFETY: a live handle, and a live tree or NULL.
        unsafe { curl_easy_setopt(c, ffi::CURLOPT_MIMEPOST, mime.cast::<c_void>()) }
    }

    /// The tree the core is given for the handle's next request.
    fn posted(c: *mut CURL) -> Option<curl_alloc::TryArc<curl_core::mime::Mime>> {
        // SAFETY: a live handle.
        let easy = unsafe { easy::handle(c) }.expect("a live handle");
        MimeTree(NonNull::from(easy)).mime().expect("built")
    }

    /// A tree of one part named `name` holding `data`.
    fn form(name: &core::ffi::CStr, data: &[u8]) -> *mut curl_mime {
        // SAFETY: a new tree and part, each call given live pointers.
        unsafe {
            let m = curl_mime_init(ptr::null_mut());
            let p = curl_mime_addpart(m);
            assert_eq!(curl_mime_name(p, name.as_ptr()), CURLE_OK);
            assert_eq!(
                curl_mime_data(p, data.as_ptr().cast::<c_char>(), data.len()),
                CURLE_OK
            );
            m
        }
    }

    /// `CURLOPT_MIMEPOST` makes the handle a POST of the tree, read
    /// again at each request; freeing the tree takes it from the handle,
    /// which then posts nothing (`mime_subparts_unbind`).
    #[test]
    fn a_freed_tree_leaves_the_handle_posting_nothing() {
        let c = curl_easy_init();
        let m = form(c"f", b"v");
        assert_eq!(post(c, m), CURLE_OK);
        // SAFETY: a live handle.
        let easy = unsafe { easy::handle(c) }.expect("live");
        easy.with_options(|o| assert!(matches!(o.upload, UploadSource::Mime(_))))
            .expect("reachable");
        let mime = posted(c).expect("a tree");
        assert_eq!(mime.parts().len(), 1);
        assert_eq!(mime.parts()[0].name.as_deref(), Some(&b"f"[..]));
        assert!(matches!(&mime.parts()[0].content, Content::Bytes(b) if b[..] == b"v"[..]));
        // SAFETY: the tree, not used again.
        unsafe { curl_mime_free(m) };
        assert!(posted(c).is_none(), "the handle let go of it");
        // SAFETY: a live handle, not used again.
        unsafe { curl_easy_cleanup(c) };
    }

    /// `CURLOPT_MIMEPOST` makes the handle a MIME POST, of nothing for
    /// NULL; `CURLOPT_POST` and `CURLOPT_POSTFIELDS` make it a POST of its
    /// own again, the tree kept by the handle (`HTTPREQ_POST_MIME`).
    #[test]
    fn the_post_options_say_which_post() {
        let c = curl_easy_init();
        // SAFETY: a live handle.
        let easy = unsafe { easy::handle(c) }.expect("live");
        let mime = || {
            easy.with_options(|o| {
                (
                    matches!(o.upload, UploadSource::Mime(_)),
                    o.method == curl_core::options::Method::Post,
                )
            })
            .expect("reachable")
        };
        assert_eq!(post(c, ptr::null_mut()), CURLE_OK);
        assert_eq!(mime(), (true, true));
        assert!(posted(c).is_none());
        let m = form(c"f", b"v");
        assert_eq!(post(c, m), CURLE_OK);
        // SAFETY: a live handle; a C string that outlives it.
        unsafe {
            assert_eq!(
                curl_easy_setopt(c, ffi::CURLOPT_POSTFIELDS, c"a=b".as_ptr()),
                CURLE_OK
            );
        }
        assert_eq!(mime(), (false, true));
        assert!(posted(c).is_none(), "the core is given none");
        let kept = easy.posted().and_then(|p| p.mime.get());
        assert_eq!(
            kept.map(NonNull::as_ptr),
            Some(m.cast()),
            "still the handle's"
        );
        assert_eq!(post(c, m), CURLE_OK);
        assert_eq!(mime(), (true, true));
        // SAFETY: a live handle, and a `long` option.
        let set = unsafe { curl_easy_setopt(c, ffi::CURLOPT_POST, 1 as core::ffi::c_long) };
        assert_eq!(set, CURLE_OK);
        assert_eq!(mime(), (false, true));
        // SAFETY: the tree and the handle, not used again.
        unsafe {
            curl_mime_free(m);
            curl_easy_cleanup(c);
        }
    }

    /// A tree goes in one place: a second handle, or a part, is refused
    /// it while the first has it, and a part is refused its own tree or
    /// one above it.
    #[test]
    fn a_tree_is_attached_once() {
        let (a, b) = (curl_easy_init(), curl_easy_init());
        let m = form(c"f", b"v");
        assert_eq!(post(a, m), CURLE_OK);
        assert_eq!(post(b, m), CURLE_BAD_FUNCTION_ARGUMENT);
        // SAFETY: live trees and parts throughout.
        unsafe {
            let top = curl_mime_init(ptr::null_mut());
            let p = curl_mime_addpart(top);
            assert_eq!(curl_mime_subparts(p, m), CURLE_BAD_FUNCTION_ARGUMENT);
            assert_eq!(curl_mime_subparts(p, top), CURLE_BAD_FUNCTION_ARGUMENT);
            let sub = curl_mime_init(ptr::null_mut());
            assert_eq!(curl_mime_subparts(p, sub), CURLE_OK);
            let q = curl_mime_addpart(sub);
            assert_eq!(curl_mime_subparts(q, top), CURLE_BAD_FUNCTION_ARGUMENT);
            // Let go of by the first handle, it may go to the second.
            assert_eq!(post(a, ptr::null_mut()), CURLE_OK);
            assert_eq!(post(b, m), CURLE_OK);
            curl_mime_free(top);
            curl_mime_free(m);
            curl_easy_cleanup(a);
            curl_easy_cleanup(b);
        }
    }

    /// Freeing subparts takes them from their part, and freeing a tree
    /// frees what is under it, each free function called once.
    #[test]
    fn frees_call_each_free_function_once() {
        thread_local!(static FREED: Cell<u32> = const { Cell::new(0) });
        unsafe extern "C" fn read(_: *mut c_char, _: usize, _: usize, _: *mut c_void) -> usize {
            0
        }
        unsafe extern "C" fn free(_: *mut c_void) {
            FREED.with(|f| f.set(f.get() + 1));
        }
        // SAFETY: live trees and parts throughout.
        unsafe {
            let top = curl_mime_init(ptr::null_mut());
            let mut m = top;
            for _ in 0..3 {
                let p = curl_mime_addpart(m);
                let q = curl_mime_addpart(m);
                assert_eq!(
                    curl_mime_data_cb(q, 0, Some(read), None, Some(free), ptr::null_mut()),
                    CURLE_OK
                );
                let sub = curl_mime_init(ptr::null_mut());
                assert_eq!(curl_mime_subparts(p, sub), CURLE_OK);
                m = sub;
            }
            // A part's content replaced: its free function called.
            let p = curl_mime_addpart(m);
            assert_eq!(
                curl_mime_data_cb(p, 0, Some(read), None, Some(free), ptr::null_mut()),
                CURLE_OK
            );
            assert_eq!(curl_mime_data(p, c"x".as_ptr(), 1), CURLE_OK);
            assert_eq!(FREED.with(Cell::get), 1);
            // The innermost tree freed on its own, then the rest.
            curl_mime_free(m);
            curl_mime_free(top);
        }
        assert_eq!(FREED.with(Cell::get), 4);
    }

    /// A part a request reached is started over before the
    /// tree is posted again, and a tree that cannot be is refused
    /// (`mime_subparts_seek`).
    #[test]
    fn a_tree_read_before_is_rewound_when_posted() {
        thread_local!(static SEEKS: Cell<u32> = const { Cell::new(0) });
        unsafe extern "C" fn read(_: *mut c_char, _: usize, _: usize, _: *mut c_void) -> usize {
            0
        }
        unsafe extern "C" fn seek(
            _: *mut c_void,
            at: ffi::curl_off_t,
            _: core::ffi::c_int,
        ) -> core::ffi::c_int {
            assert_eq!(at, 0);
            SEEKS.with(|s| s.set(s.get() + 1));
            ffi::CURL_SEEKFUNC_OK
        }
        let c = curl_easy_init();
        // SAFETY: live trees and parts throughout.
        unsafe {
            let m = curl_mime_init(ptr::null_mut());
            let p = curl_mime_addpart(m);
            assert_eq!(
                curl_mime_data_cb(p, -1, Some(read), Some(seek), None, ptr::null_mut()),
                CURLE_OK
            );
            // Never read: no seek.
            assert_eq!(post(c, m), CURLE_OK);
            assert_eq!(SEEKS.with(Cell::get), 0);
            let part = &*p.cast::<super::ShimPart>();
            part.reached.set(true);
            assert_eq!(post(c, ptr::null_mut()), CURLE_OK);
            assert_eq!(post(c, m), CURLE_OK);
            assert_eq!(SEEKS.with(Cell::get), 1);
            assert!(!part.reached.get());
            // Without a seek function, a part read cannot be.
            assert_eq!(
                curl_mime_data_cb(p, -1, Some(read), None, None, ptr::null_mut()),
                CURLE_OK
            );
            part.reached.set(true);
            assert_eq!(post(c, ptr::null_mut()), CURLE_OK);
            assert_eq!(post(c, m), CURLE_SEND_FAIL_REWIND);
            curl_mime_free(m);
            curl_easy_cleanup(c);
        }
    }

    /// Setting the post again forgets the head lines a probe would send
    /// again, as C forgets `state.mimepost`.
    #[test]
    fn setting_the_post_again_forgets_the_head_sent() {
        let c = curl_easy_init();
        // SAFETY: a live handle and tree throughout.
        unsafe {
            let m = form(c"f", b"v");
            assert_eq!(post(c, m), CURLE_OK);
            let easy = easy::handle(c).expect("a live handle");
            let source = MimeTree(NonNull::from(easy));
            let sent = source.sent_head().expect("kept");
            sent.keep(&[b"Content-Type: x".to_vec()]).unwrap();
            assert_eq!(sent.lines().unwrap().len(), 1);
            assert_eq!(post(c, m), CURLE_OK);
            assert!(sent.lines().unwrap().is_empty());
            curl_mime_free(m);
            curl_easy_cleanup(c);
        }
    }

    /// A copy of the handle posts a copy of its tree, the copy's own,
    /// each level with a boundary of its own; a tree nested past the
    /// most levels is not copied, nor the handle (`Curl_mime_duppart`).
    #[test]
    fn a_copied_handle_posts_a_copy_of_the_tree() {
        let c = curl_easy_init();
        // SAFETY: live trees, parts and handles throughout.
        unsafe {
            let m = form(c"f", b"v");
            let p = curl_mime_addpart(m);
            let sub = form(c"g", b"w");
            assert_eq!(curl_mime_subparts(p, sub), CURLE_OK);
            assert_eq!(post(c, m), CURLE_OK);
            let d = curl_easy_duphandle(c);
            assert!(!d.is_null());
            curl_mime_free(m);
            assert!(posted(c).is_none());
            let copy = posted(d).expect("the copy's own");
            assert_eq!(copy.parts().len(), 2);
            assert_eq!(copy.parts()[0].name.as_deref(), Some(&b"f"[..]));
            let Content::Parts(inner) = &copy.parts()[1].content else {
                panic!("subparts copied");
            };
            assert_eq!(inner.parts()[0].name.as_deref(), Some(&b"g"[..]));
            assert_ne!(inner.boundary(), copy.boundary());
            curl_easy_cleanup(d);

            // 40 levels under the handle's part: one too many to copy.
            let top = curl_mime_init(ptr::null_mut());
            let mut at = top;
            for _ in 0..39 {
                let sub = curl_mime_init(ptr::null_mut());
                assert_eq!(curl_mime_subparts(curl_mime_addpart(at), sub), CURLE_OK);
                at = sub;
            }
            assert_eq!(post(c, top), CURLE_OK);
            assert!(
                curl_easy_duphandle(c).is_null(),
                "40 levels below the handle"
            );
            curl_mime_free(top);
            curl_easy_cleanup(c);
        }
    }

    /// The encoders C knows, by name in any case; another is refused.
    /// A file that cannot be read is refused, and names the part after
    /// itself when it can be.
    #[test]
    fn encoders_and_files_are_checked_when_set() {
        // SAFETY: a live tree and part throughout.
        unsafe {
            let m = curl_mime_init(ptr::null_mut());
            let p = curl_mime_addpart(m);
            assert_eq!(curl_mime_encoder(p, c"BASE64".as_ptr()), CURLE_OK);
            assert_eq!(
                curl_mime_encoder(p, c"uuencode".as_ptr()),
                CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_filedata(p, c"/nonexistent/file".as_ptr()),
                CURLE_READ_ERROR
            );
            let dir = std::env::temp_dir().join("curl-mime-filedata");
            std::fs::write(&dir, b"abc").unwrap();
            let path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(curl_mime_filedata(p, path.as_ptr()), CURLE_OK);
            let part = &*p.cast::<super::ShimPart>();
            assert_eq!(part.filename.as_deref(), Some(&b"curl-mime-filedata"[..]));
            std::fs::remove_file(&dir).unwrap();
            curl_mime_free(m);
        }
    }
}
