//! `CURL *`, the easy handle (`lib/easy.c`).
//!
//! A `ShimEasy` is what the application's pointer points to. Its `Easy`
//! lives in it while the handle is on its own and in a multi while it is
//! added there; `Home` says which, and every call reaches the `Easy` where
//! it is. `curl_easy_perform` runs the handle in a multi of its own, kept
//! for the next perform.

#![allow(unsafe_code)]

use core::cell::{Cell, RefCell, UnsafeCell};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, try_box};
use curl_core::easy::Easy;
use curl_core::error::{ErrorKind, MultiErrorKind};
use curl_core::multi::{PauseRequest, TransferId, drive_to_completion};
use curl_core::options::Options;
use curl_core::report::TransferReport;

use crate::callbacks::{self, CCallbacks, CSettings};
use crate::error_codes::easy_code;
use crate::ffi::{
    self, CURL, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_FAILED_INIT, CURLE_OK, CURLE_OUT_OF_MEMORY,
    CURLE_RECURSIVE_API_CALL, CURLcode,
};
use crate::gate::{EasyCall, EasyStack, Frame, MultiCall, MultiStack, Reach, Recursive};
use crate::multi::{ShimEvents, ShimMulti};

/// C's `CURLEASY_MAGIC_NUMBER`, which tells a live handle.
const MAGIC: u32 = 0xc0de_dbad;

/// C's `CURL_ERROR_SIZE`: the room `CURLOPT_ERRORBUFFER` has.
const ERROR_SIZE: usize = 256;

pub(crate) struct ShimEasy {
    magic: Cell<u32>,
    /// A multi's own handle, which the application may not use (C's
    /// `state.internal`).
    internal: bool,
    pub(crate) stack: EasyStack,
    home: RefCell<Home>,
    pub(crate) ccb: Cell<CCallbacks>,
    pub(crate) set: Cell<CSettings>,
    /// What a POST sends, if not read from the read function.
    pub(crate) post: RefCell<callbacks::Post>,
    /// `CURLOPT_ERRORBUFFER`.
    pub(crate) errbuf: Cell<*mut c_char>,
    /// The multi `curl_easy_perform` runs in, between performs.
    private: Cell<Option<NonNull<ShimMulti>>>,
    /// What `curl_multi_info_read` points to.
    pub(crate) msg: UnsafeCell<ffi::CURLMsg>,
    /// What the string infos point to, each ended by a zero byte:
    /// replaced only by a different text, so a pointer handed out lives
    /// until a later transfer's differs, or the handle goes.
    pub(crate) effective_url: RefCell<Vec<u8>>,
    pub(crate) content_type: RefCell<Vec<u8>>,
    pub(crate) redirect_url: RefCell<Vec<u8>>,
    pub(crate) primary_ip: RefCell<Vec<u8>>,
    pub(crate) local_ip: RefCell<Vec<u8>>,
    /// What `curl_easy_header` and `curl_easy_nextheader` hand out.
    pub(crate) headers_out: [crate::headers::HeaderOut; 2],
}

/// Where the handle's transfer is.
#[expect(
    clippy::large_enum_variant,
    reason = "the handle is boxed whole; the transfer lives in it while on its own"
)]
enum Home {
    Detached(Easy),
    Added {
        multi: NonNull<ShimMulti>,
        id: TransferId,
    },
    /// Moved for a moment, or a multi's own handle, which has none.
    Nowhere,
}

impl ShimEasy {
    /// A handle, in memory of its own, for `easy` with `ccb`, `set` and
    /// `errbuf`.
    fn boxed(
        easy: Easy,
        ccb: CCallbacks,
        set: CSettings,
        post: callbacks::Post,
        errbuf: *mut c_char,
    ) -> Result<NonNull<ShimEasy>, OutOfMemory> {
        let shim = try_box(ShimEasy::empty(false, ccb, set))?;
        let shim = NonNull::from(Box::leak(shim));
        // SAFETY: just made, and reached only through this pointer.
        let me = unsafe { shim.as_ref() };
        me.errbuf.set(errbuf);
        *me.post.borrow_mut() = post;
        let mut easy = easy;
        if let Err(e) = callbacks::install(easy.options_mut(), shim, &set, &ccb, errbuf) {
            // SAFETY: made above by `Box::leak`, used nowhere else.
            drop(unsafe { Box::from_raw(shim.as_ptr()) });
            return Err(e);
        }
        *me.home.borrow_mut() = Home::Detached(easy);
        Ok(shim)
    }

    /// A multi's own handle, which no call may use.
    pub(crate) fn internal() -> ShimEasy {
        ShimEasy::empty(true, CCallbacks::new(), CSettings::new())
    }

    fn empty(internal: bool, ccb: CCallbacks, set: CSettings) -> ShimEasy {
        ShimEasy {
            magic: Cell::new(MAGIC),
            internal,
            stack: EasyStack::default(),
            home: RefCell::new(Home::Nowhere),
            ccb: Cell::new(ccb),
            set: Cell::new(set),
            post: RefCell::new(callbacks::Post::new()),
            errbuf: Cell::new(ptr::null_mut()),
            private: Cell::new(None),
            // SAFETY: a `CURLMsg` of zeroes is its empty value.
            msg: UnsafeCell::new(unsafe { core::mem::zeroed() }),
            effective_url: RefCell::new(Vec::new()),
            content_type: RefCell::new(Vec::new()),
            redirect_url: RefCell::new(Vec::new()),
            primary_ip: RefCell::new(Vec::new()),
            local_ip: RefCell::new(Vec::new()),
            headers_out: crate::headers::slots(),
        }
    }

    /// The multi the handle's transfer is in, if it is in one.
    pub(crate) fn multi(&self) -> Option<&ShimMulti> {
        match *self.home.borrow() {
            // SAFETY: a multi frees its transfers' handles' `Added` before
            // it is freed itself.
            Home::Added { multi, .. } => Some(unsafe { multi.as_ref() }),
            Home::Detached(_) | Home::Nowhere => None,
        }
    }

    fn multi_stack(&self) -> Option<&MultiStack> {
        self.multi().map(|m| &m.stack)
    }

    /// Admit `call` on the handle.
    pub(crate) fn enter(&self, call: EasyCall) -> Result<crate::gate::EasyEntry<'_>, Recursive> {
        self.stack.enter(call, self.multi_stack())
    }

    /// The handle's transfer, to add to a multi.
    pub(crate) fn detach(&self) -> Easy {
        match self.home.replace(Home::Nowhere) {
            Home::Detached(easy) => easy,
            Home::Added { .. } | Home::Nowhere => unreachable!("a handle on its own"),
        }
    }

    /// The transfer is in `multi` as `id` now.
    pub(crate) fn attach(&self, multi: NonNull<ShimMulti>, id: TransferId) {
        let was = self.home.replace(Home::Added { multi, id });
        assert!(matches!(was, Home::Nowhere), "attached once detached");
    }

    /// Where the handle is: its multi and id, if in one.
    pub(crate) fn added(&self) -> Option<(NonNull<ShimMulti>, TransferId)> {
        match *self.home.borrow() {
            Home::Added { multi, id } => Some((multi, id)),
            Home::Detached(_) | Home::Nowhere => None,
        }
    }

    /// Run `f` on the handle's `Easy`, wherever it is: in the handle, in
    /// its multi's core, or through the context of the callback running.
    pub(crate) fn with_easy<R>(&self, f: impl FnOnce(EasyRef<'_>) -> R) -> Result<R, Recursive> {
        let added = self.added();
        let Some((multi, id)) = added else {
            let mut home = self.home.borrow_mut();
            // Being added, the transfer is in neither place: a callback the
            // add runs cannot reach it.
            let Home::Detached(easy) = &mut *home else {
                return Err(Recursive);
            };
            return Ok(f(EasyRef::Easy(easy)));
        };
        // SAFETY: the handle's multi outlives its `Added`.
        let multi = unsafe { multi.as_ref() };
        Ok(match multi.stack.reach()? {
            // SAFETY: nothing runs on the multi, so its core is not
            // borrowed.
            Reach::Direct => f(EasyRef::Easy(
                unsafe { multi.core_mut() }
                    .easy_mut(id)
                    .expect("an added handle is in its multi"),
            )),
            Reach::Frame(frame) => f(EasyRef::Frame(frame, id)),
        })
    }

    /// Run `f` on the handle's options, wherever they are.
    pub(crate) fn with_options<R>(
        &self,
        f: impl FnOnce(&mut Options) -> R,
    ) -> Result<R, Recursive> {
        self.with_easy(|e| match e {
            EasyRef::Easy(easy) => f(easy.options_mut()),
            EasyRef::Frame(frame, id) => {
                // SAFETY: the frame is the multi's innermost, and the
                // borrow ends with this call, inside its callback.
                let options = unsafe { frame.options_mut(id) };
                f(options.expect("an added handle is in its multi"))
            }
        })
    }

    /// Run `f` on what the handle's transfer reports.
    pub(crate) fn with_report<R>(
        &self,
        f: impl FnOnce(&TransferReport) -> R,
    ) -> Result<R, Recursive> {
        self.with_easy(|e| match e {
            EasyRef::Easy(easy) => f(easy.report()),
            EasyRef::Frame(frame, id) => {
                // SAFETY: as in `with_options`.
                let report = unsafe { frame.info(id) };
                f(report.expect("an added handle is in its multi"))
            }
        })
    }

    /// Copy a transfer's first reason for failing into ERRORBUFFER, as it
    /// is given (`Curl_failf`).
    pub(crate) fn fill_error_buffer(&self, why: &[u8]) {
        let buf = self.errbuf.get();
        if buf.is_null() {
            return;
        }
        // SAFETY: the application gave a buffer of `CURL_ERROR_SIZE` bytes,
        // which nothing else holds during the call.
        let buf = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), ERROR_SIZE) };
        // The core cuts every reason to fit, as `failf` does: one too long
        // fails the copy, loudly.
        buf[..why.len()].copy_from_slice(why);
        buf[why.len()] = 0;
    }

    /// Empty ERRORBUFFER, for a new transfer (`Curl_reset_fail`).
    pub(crate) fn clear_error_buffer(&self) {
        let buf = self.errbuf.get();
        if !buf.is_null() {
            // SAFETY: the application gave a buffer of at least one byte.
            unsafe { *buf = 0 };
        }
    }
}

/// A handle's `Easy`, where it was reached.
pub(crate) enum EasyRef<'a> {
    Easy(&'a mut Easy),
    Frame(Frame, TransferId),
}

/// The live handle `curl` points to, if it is one the application may use.
///
/// # Safety
///
/// `curl` is NULL or a pointer `curl_easy_init` or `curl_easy_duphandle`
/// returned, as C requires.
pub(crate) unsafe fn handle<'a>(curl: *mut CURL) -> Option<&'a ShimEasy> {
    let easy = NonNull::new(curl.cast::<ShimEasy>())?;
    // SAFETY: as the caller guarantees.
    let easy = unsafe { easy.as_ref() };
    (easy.magic.get() == MAGIC && !easy.internal).then_some(easy)
}

#[unsafe(no_mangle)]
pub extern "C" fn curl_easy_init() -> *mut CURL {
    // C initialises the library for a program that did not.
    match ShimEasy::boxed(
        Easy::new(),
        CCallbacks::new(),
        CSettings::new(),
        callbacks::Post::new(),
        ptr::null_mut(),
    ) {
        Ok(easy) => easy.as_ptr().cast(),
        Err(OutOfMemory) => ptr::null_mut(),
    }
}
const _: ffi::proto::curl_easy_init = curl_easy_init;

/// # Safety
///
/// `curl` is NULL or a live handle, not used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_cleanup(curl: *mut CURL) {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return;
    };
    let Ok(entry) = easy.enter(EasyCall::Cleanup) else {
        return;
    };
    // One added to a multi leaves it first (multi.c:753).
    if let Some((multi, _)) = easy.added() {
        // SAFETY: the handle's multi outlives its `Added`.
        let multi = unsafe { multi.as_ref() };
        // Cleanup does not recurse: nothing runs on the multi.
        if crate::multi::remove(multi, Reach::Direct, easy).is_err() {
            return;
        }
    }
    drop(entry);
    let private = easy.private.take();
    easy.magic.set(0);
    // SAFETY: the handle came from `Box::leak` in `ShimEasy::boxed`, and
    // the caller does not use it again.
    drop(unsafe { Box::from_raw(curl.cast::<ShimEasy>()) });
    if let Some(private) = private {
        // SAFETY: made by `ShimMulti::private`, owned by the handle alone.
        unsafe { ShimMulti::free(private) };
    }
}
const _: ffi::proto::curl_easy_cleanup = curl_easy_cleanup;

/// # Safety
///
/// `curl` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_duphandle(curl: *mut CURL) -> *mut CURL {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return ptr::null_mut();
    };
    let Ok(_entry) = easy.enter(EasyCall::Duphandle) else {
        return ptr::null_mut();
    };
    let copy = easy.with_easy(|e| match e {
        EasyRef::Easy(easy) => easy.try_clone(),
        EasyRef::Frame(frame, id) => {
            // SAFETY: as in `with_options`.
            let copy = unsafe { frame.duplicate(id) };
            copy.expect("an added handle is in its multi")
        }
    });
    let Ok(Ok(copy)) = copy else {
        return ptr::null_mut();
    };
    // The copy's adapters are its own (`install` replaces the original's).
    let post = easy.post.borrow().clone();
    match ShimEasy::boxed(
        copy,
        easy.ccb.get(),
        easy.set.get(),
        post,
        easy.errbuf.get(),
    ) {
        Ok(dup) => dup.as_ptr().cast(),
        Err(OutOfMemory) => ptr::null_mut(),
    }
}
const _: ffi::proto::curl_easy_duphandle = curl_easy_duphandle;

/// # Safety
///
/// `curl` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_reset(curl: *mut CURL) {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return;
    };
    let Ok(_entry) = easy.enter(EasyCall::Reset) else {
        return;
    };
    let me = NonNull::from(easy);
    let (ccb, set) = (CCallbacks::new(), CSettings::new());
    easy.ccb.set(ccb);
    easy.set.set(set);
    *easy.post.borrow_mut() = callbacks::Post::new();
    easy.errbuf.set(ptr::null_mut());
    // The write adapter stays, reading the reset callbacks; the defaults
    // need no other, so a reset allocates nothing, and cannot fail, as
    // C's cannot.
    let fresh = |options: &mut Options| {
        let write = options.callbacks.write.take();
        *options = Options::default();
        options.callbacks.write = write;
        callbacks::install_defaults(options, me, &set, &ccb)
            .expect("the defaults allocate no adapter");
    };
    let reset = easy.with_easy(|e| match e {
        EasyRef::Easy(easy) => {
            let mut options = core::mem::take(easy.options_mut());
            easy.reset();
            fresh(&mut options);
            *easy.options_mut() = options;
        }
        // Inside a callback the report is the transfer's own until it
        // ends; the options are reset now.
        EasyRef::Frame(frame, id) => {
            // SAFETY: as in `with_options`.
            let options = unsafe { frame.options_mut(id) };
            fresh(options.expect("an added handle is in its multi"));
        }
    });
    match reset {
        // A handle being added has no transfer to reset.
        Ok(()) | Err(Recursive) => {}
    }
}
const _: ffi::proto::curl_easy_reset = curl_easy_reset;

/// # Safety
///
/// `curl` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_perform(curl: *mut CURL) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::Perform) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    if easy.added().is_some() {
        // "easy handle already used in multi handle"
        return CURLE_FAILED_INIT;
    }
    perform(easy)
}
const _: ffi::proto::curl_easy_perform = curl_easy_perform;

/// Run the handle's transfer to its end in its own multi (`easy_perform`).
fn perform(easy: &ShimEasy) -> CURLcode {
    let multi = match easy.private.take() {
        Some(multi) => multi,
        None => match ShimMulti::private() {
            Ok(multi) => multi,
            Err(OutOfMemory) => return CURLE_OUT_OF_MEMORY,
        },
    };
    easy.private.set(Some(multi));
    // SAFETY: the handle owns its private multi.
    let m = unsafe { multi.as_ref() };
    // The handle's limit is its multi's (`easy_perform`).
    let max = easy
        .with_options(|o| o.limits.reuse.max_connects)
        .expect("perform is not called from a callback");
    // SAFETY: nothing else runs on the private multi.
    unsafe { m.core_mut() }.conn_limits_mut().max_connects = Some(max);
    // Nothing but this call runs on the private multi.
    if let Err(e) = crate::multi::add(m, Reach::Direct, easy) {
        return match e {
            MultiErrorKind::OutOfMemory => CURLE_OUT_OF_MEMORY,
            _ => CURLE_BAD_FUNCTION_ARGUMENT,
        };
    }
    let (_, id) = easy.added().expect("just added");
    let outcome = {
        let entry = m
            .stack
            .enter(MultiCall::Perform)
            .expect("a private multi runs one call");
        assert!(matches!(entry.reach, Reach::Direct));
        // SAFETY: nothing else runs on the private multi.
        let core = unsafe { m.core_mut() };
        drive_to_completion(core, id, &mut ShimEvents::new(m))
    };
    let result = match outcome {
        Ok(result) => result,
        Err(MultiErrorKind::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        Err(_) => Err(ErrorKind::BadFunctionArgument),
    };
    // The handle has its transfer back for the next call.
    let removed = crate::multi::remove(m, Reach::Direct, easy);
    assert!(removed.is_ok(), "a private multi's handle comes out");
    match result {
        Ok(()) => CURLE_OK,
        Err(kind) => easy_code(kind),
    }
}

impl ShimEasy {
    /// The transfer the multi gave back.
    pub(crate) fn return_home(&self, easy: Easy) {
        self.home.replace(Home::Detached(easy));
    }

    /// Drop the private multi, as adding the handle to another does.
    pub(crate) fn drop_private(&self) {
        if let Some(private) = self.private.take() {
            // SAFETY: made by `ShimMulti::private`, owned by the handle.
            unsafe { ShimMulti::free(private) };
        }
    }

    pub(crate) fn as_c(&self) -> *mut CURL {
        ptr::from_ref(self).cast_mut().cast::<c_void>()
    }
}

/// # Safety
///
/// `curl` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_pause(curl: *mut CURL, action: c_int) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(EasyCall::Pause) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    let req = PauseRequest {
        recv: action & ffi::CURLPAUSE_RECV != 0,
        send: action & ffi::CURLPAUSE_SEND != 0,
    };
    // A handle on its own has no connection to pause.
    let Some((multi, id)) = easy.added() else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    // SAFETY: the handle's multi outlives its `Added`.
    let m = unsafe { multi.as_ref() };
    let Ok(reach) = m.stack.reach() else {
        return CURLE_RECURSIVE_API_CALL;
    };
    let paused = match reach {
        // SAFETY: nothing runs on the multi.
        Reach::Direct => unsafe { m.core_mut() }.pause(id, req, &mut ShimEvents::new(m)),
        // SAFETY: the callback lent its context and does not use it until
        // it returns.
        Reach::Frame(Frame::Transfer(cx)) => unsafe { &mut *cx.as_ptr() }.pause(id, req),
        Reach::Frame(Frame::Notify(cx)) => {
            // SAFETY: as above.
            unsafe { &mut *cx.as_ptr() }.pause(id, req, &mut ShimEvents::new(m))
        }
        // The gate refuses a pause in the event callbacks.
        Reach::Frame(Frame::Event(_)) => unreachable!("refused by the gate"),
    };
    match paused {
        Ok(()) => CURLE_OK,
        Err(kind) => easy_code(kind),
    }
}
const _: ffi::proto::curl_easy_pause = curl_easy_pause;

/// Bytes from a `CURLOPT_CONNECT_ONLY` connection: no handle has one,
/// as that option is not built in (`easy_connection`).
///
/// # Safety
///
/// `curl` is NULL or a live handle; `n` is NULL or points at a `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_recv(
    curl: *mut CURL,
    buffer: *mut c_void,
    buflen: usize,
    n: *mut usize,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    unsafe { connect_only(curl, EasyCall::Recv, buffer.is_null(), buflen, n) }
}
const _: ffi::proto::curl_easy_recv = curl_easy_recv;

/// Bytes to a `CURLOPT_CONNECT_ONLY` connection, which no handle has.
///
/// # Safety
///
/// As `curl_easy_recv`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_easy_send(
    curl: *mut CURL,
    buffer: *const c_void,
    buflen: usize,
    n: *mut usize,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    unsafe { connect_only(curl, EasyCall::Send, buffer.is_null(), buflen, n) }
}
const _: ffi::proto::curl_easy_send = curl_easy_send;

/// `curl_easy_recv` and `curl_easy_send` on a handle without a
/// `CURLOPT_CONNECT_ONLY` connection: refused inside a callback, and
/// otherwise `CURLE_UNSUPPORTED_PROTOCOL` with nothing moved.
///
/// # Safety
///
/// As `curl_easy_recv`.
unsafe fn connect_only(
    curl: *mut CURL,
    call: EasyCall,
    no_buffer: bool,
    buflen: usize,
    n: *mut usize,
) -> CURLcode {
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { handle(curl) }) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let Ok(_entry) = easy.enter(call) else {
        return CURLE_RECURSIVE_API_CALL;
    };
    if n.is_null() || (buflen > 0 && no_buffer) {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: `n` points at a `size_t`, as the caller guarantees.
    unsafe { n.write(0) };
    ffi::CURLE_UNSUPPORTED_PROTOCOL
}

#[cfg(test)]
#[allow(
    clippy::multiple_unsafe_ops_per_block,
    reason = "one contract covers each test's sequence of calls"
)]
mod tests {
    use core::ffi::c_long;

    use super::*;
    use crate::multi::{
        curl_multi_add_handle, curl_multi_cleanup, curl_multi_info_read, curl_multi_init,
        curl_multi_perform, curl_multi_remove_handle,
    };

    /// What the write callback saw and got back from the calls it made.
    #[derive(Default)]
    struct Inside {
        curl: usize,
        body: Vec<u8>,
        getinfo: Option<CURLcode>,
        size: ffi::curl_off_t,
        setopt: Option<CURLcode>,
        perform: Option<CURLcode>,
        cleanup_ran: bool,
    }

    unsafe extern "C" fn write(
        ptr: *mut c_char,
        size: usize,
        n: usize,
        data: *mut c_void,
    ) -> usize {
        // SAFETY: the test passes an `Inside` and the shim `size * n` bytes.
        let (inside, bytes) = unsafe {
            (
                &mut *data.cast::<Inside>(),
                core::slice::from_raw_parts(ptr.cast::<u8>(), size * n),
            )
        };
        inside.body.extend_from_slice(bytes);
        let curl = inside.curl as *mut CURL;
        // SAFETY: the test's live handle, with arguments of each option's
        // and info's type.
        unsafe {
            inside.getinfo = Some(crate::getinfo::curl_easy_getinfo(
                curl,
                ffi::CURLINFO_SIZE_DOWNLOAD_T,
                &mut inside.size as *mut ffi::curl_off_t,
            ));
            inside.setopt = Some(crate::setopt::curl_easy_setopt(
                curl,
                ffi::CURLOPT_VERBOSE,
                0 as c_long,
            ));
            inside.perform = Some(curl_easy_perform(curl));
            // Refused: the handle is in use. The handle stays.
            curl_easy_cleanup(curl);
            inside.cleanup_ran = handle(curl).is_some();
        }
        size * n
    }

    unsafe extern "C" fn sink(_: *mut c_char, size: usize, n: usize, _: *mut c_void) -> usize {
        size * n
    }

    fn file(body: &[u8]) -> (std::path::PathBuf, std::ffi::CString) {
        let path =
            std::env::temp_dir().join(format!("curl-shim-{}-{}", std::process::id(), body.len()));
        std::fs::write(&path, body).unwrap();
        let url = std::ffi::CString::new(format!("file://{}", path.display())).unwrap();
        (path, url)
    }

    /// A callback inside a perform reaches its own handle through the
    /// frame its adapter lent: getinfo and setopt run, a perform and a
    /// cleanup are refused, as api.c refuses them.
    #[test]
    fn calls_from_a_callback_reach_the_running_transfer() {
        let (path, url) = file(b"hello");
        let mut inside = Inside::default();
        let curl = curl_easy_init();
        inside.curl = curl as usize;
        // SAFETY: a live handle, with arguments of each option's type.
        let code = unsafe {
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_URL, url.as_ptr());
            let f: unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize = write;
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_WRITEFUNCTION, f);
            crate::setopt::curl_easy_setopt(
                curl,
                ffi::CURLOPT_WRITEDATA,
                (&raw mut inside).cast::<c_void>(),
            );
            curl_easy_perform(curl)
        };
        std::fs::remove_file(path).unwrap();
        assert_eq!(code, CURLE_OK);
        assert_eq!(inside.body, b"hello");
        assert_eq!(inside.getinfo, Some(CURLE_OK));
        assert_eq!(inside.size, 0, "counted once the write returns");
        assert_eq!(inside.setopt, Some(CURLE_OK));
        assert_eq!(inside.perform, Some(CURLE_RECURSIVE_API_CALL));
        assert!(inside.cleanup_ran, "the refused cleanup left the handle");
        let mut size: ffi::curl_off_t = 0;
        // SAFETY: a live handle and an info of this type.
        unsafe {
            assert_eq!(
                crate::getinfo::curl_easy_getinfo(curl, ffi::CURLINFO_SIZE_DOWNLOAD_T, &mut size),
                CURLE_OK
            );
            curl_easy_cleanup(curl);
        }
        assert_eq!(size, 5);
    }

    /// A handle goes to a multi and back, its transfer with it, and a
    /// multi's cleanup leaves the handle usable on its own.
    #[test]
    fn a_handle_moves_between_multis() {
        let (path, url) = file(b"in a multi");
        let curl = curl_easy_init();
        let (a, b) = (curl_multi_init(), curl_multi_init());
        // SAFETY: live handles throughout, until their cleanups.
        unsafe {
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_URL, url.as_ptr());
            let f: unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize = sink;
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_WRITEFUNCTION, f);
            assert_eq!(curl_multi_add_handle(a, curl), ffi::CURLM_OK);
            assert_eq!(curl_multi_add_handle(b, curl), ffi::CURLM_ADDED_ALREADY);
            assert_eq!(
                curl_multi_remove_handle(b, curl),
                ffi::CURLM_BAD_EASY_HANDLE
            );
            assert_eq!(curl_easy_perform(curl), CURLE_FAILED_INIT);
            let mut running = 1;
            while running > 0 {
                assert_eq!(curl_multi_perform(a, &mut running), ffi::CURLM_OK);
            }
            let mut queued = -1;
            let msg = curl_multi_info_read(a, &mut queued);
            assert!(!msg.is_null());
            assert_eq!(
                ((*msg).easy_handle, (*msg).data.result, queued),
                (curl, CURLE_OK, 0)
            );
            assert_eq!(curl_multi_cleanup(a), ffi::CURLM_OK);
            // On its own again: it performs, and joins another multi.
            assert_eq!(curl_easy_perform(curl), CURLE_OK);
            assert_eq!(curl_multi_add_handle(b, curl), ffi::CURLM_OK);
            curl_easy_cleanup(curl);
            assert_eq!(curl_multi_cleanup(b), ffi::CURLM_OK);
        }
        std::fs::remove_file(path).unwrap();
    }

    /// ERRORBUFFER holds the first reason as it is given, in a multi too,
    /// before the message is read; a new transfer starts it empty, and a
    /// copy of the handle writes to the same buffer.
    #[test]
    fn the_error_buffer_fills_as_the_transfer_fails() {
        let mut buf = [b'x' as c_char; ERROR_SIZE];
        let text = |buf: &[c_char; ERROR_SIZE]| {
            // SAFETY: the shim ends what it writes with a zero byte.
            unsafe { core::ffi::CStr::from_ptr(buf.as_ptr()) }
                .to_bytes()
                .to_vec()
        };
        let missing = c"file:///nonexistent/curl-shim-test";
        let curl = curl_easy_init();
        let m = curl_multi_init();
        // SAFETY: live handles throughout, until their cleanups, and a
        // buffer of `CURL_ERROR_SIZE` that outlives them.
        unsafe {
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_URL, missing.as_ptr());
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_ERRORBUFFER, buf.as_mut_ptr());
            assert_eq!(curl_multi_add_handle(m, curl), ffi::CURLM_OK);
            assert_eq!(text(&buf), b"", "emptied when added");
            let mut running = 1;
            while running > 0 {
                assert_eq!(curl_multi_perform(m, &mut running), ffi::CURLM_OK);
            }
            let why = text(&buf);
            assert_eq!(why, b"Could not open file /nonexistent/curl-shim-test");
            assert_eq!(curl_multi_remove_handle(m, curl), ffi::CURLM_OK);
            buf[0] = b'x' as c_char;
            let dup = curl_easy_duphandle(curl);
            assert_eq!(curl_easy_perform(dup), ffi::CURLE_FILE_COULDNT_READ_FILE);
            assert_eq!(text(&buf), why, "the copy's reason, in the same buffer");
            curl_easy_cleanup(dup);
            curl_easy_reset(curl);
            buf[0] = 0;
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_URL, missing.as_ptr());
            assert_eq!(curl_easy_perform(curl), ffi::CURLE_FILE_COULDNT_READ_FILE);
            assert_eq!(text(&buf), b"", "a reset handle has no buffer");
            curl_easy_cleanup(curl);
            assert_eq!(curl_multi_cleanup(m), ffi::CURLM_OK);
        }
    }

    unsafe extern "C" fn count_debug(
        _: *mut CURL,
        _: ffi::curl_infotype,
        _: *mut c_char,
        _: usize,
        data: *mut c_void,
    ) -> c_int {
        // SAFETY: the test passes a `u32`.
        unsafe { *data.cast::<u32>() += 1 };
        0
    }

    /// A copy's adapters are its own: they call its callbacks with its
    /// data, whatever the original's become.
    #[test]
    fn a_copy_calls_back_with_its_own_data() {
        let (mut mine, mut theirs) = (0u32, 0u32);
        let missing = c"file:///nonexistent/curl-shim-test";
        let curl = curl_easy_init();
        // SAFETY: live handles throughout, until their cleanups, and data
        // that outlives them.
        unsafe {
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_URL, missing.as_ptr());
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_VERBOSE, 1 as c_long);
            let f: unsafe extern "C" fn(
                *mut CURL,
                ffi::curl_infotype,
                *mut c_char,
                usize,
                *mut c_void,
            ) -> c_int = count_debug;
            crate::setopt::curl_easy_setopt(curl, ffi::CURLOPT_DEBUGFUNCTION, f);
            crate::setopt::curl_easy_setopt(
                curl,
                ffi::CURLOPT_DEBUGDATA,
                (&raw mut mine).cast::<c_void>(),
            );
            let dup = curl_easy_duphandle(curl);
            crate::setopt::curl_easy_setopt(
                curl,
                ffi::CURLOPT_DEBUGDATA,
                (&raw mut theirs).cast::<c_void>(),
            );
            assert_eq!(curl_easy_perform(dup), ffi::CURLE_FILE_COULDNT_READ_FILE);
            assert!(mine > 0 && theirs == 0, "{mine} {theirs}");
            curl_easy_cleanup(dup);
            curl_easy_cleanup(curl);
        }
    }
}
