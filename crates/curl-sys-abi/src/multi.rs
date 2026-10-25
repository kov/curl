//! `CURLM *`, the multi handle (`lib/multi.c`).
//!
//! A `ShimMulti` holds its core behind the gate: a call borrows the core
//! only when no other call on the multi is under way; one made from inside
//! a callback reaches the multi through the context that callback was
//! lent. The waker is outside the core, for `curl_multi_wakeup` from
//! another thread.

#![allow(unsafe_code)]

use core::cell::{Cell, UnsafeCell};
use core::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use core::num::NonZeroU32;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU32, Ordering};
use std::os::fd::BorrowedFd;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, TryVec, try_box};
use curl_core::conn::io::{Events, Net, PollFd, SocketKey, SystemNet, Waker};
use curl_core::error::MultiErrorKind;
use curl_core::id::ArenaPolicy;
use curl_core::multi::{
    Abort, ConnLimits, Env, EventCx, Host, Message, Multi, MultiEvents, Notification, NotifyCx,
    NotifyKind, SocketEvent, SocketFor, SocketWhat, TimerChange, TransferId, UnknownSocket,
    WaitMode,
};
use curl_core::time::SystemClock;

use crate::easy::{self, ShimEasy};
use crate::error_codes::{MultiError, easy_code, multi_code};
use crate::ffi::{
    self, CURL, CURL_SOCKET_TIMEOUT, CURL_WAIT_POLLIN, CURL_WAIT_POLLOUT, CURL_WAIT_POLLPRI, CURLM,
    CURLM_BAD_EASY_HANDLE, CURLM_BAD_FUNCTION_ARGUMENT, CURLM_BAD_HANDLE, CURLM_OK,
    CURLM_OUT_OF_MEMORY, CURLM_RECURSIVE_API_CALL, CURLM_UNKNOWN_OPTION, CURLM_WAKEUP_FAILURE,
    CURLMSG_DONE, CURLMcode, CURLMinfo_offt, CURLMoption, CURLMsg, curl_multi_timer_callback,
    curl_notify_callback, curl_off_t, curl_socket_callback, curl_socket_t, curl_waitfd,
};
use crate::gate::{Frame, MultiCall, MultiEntry, MultiStack, Reach, Recursive};
use crate::setopt::function;

/// C's `CURL_MULTI_HANDLE`, which tells a live multi.
const MAGIC: u32 = 0x000b_ab1e;

/// What the core holds for each transfer: the application's handle.
pub(crate) struct CHost;

impl Host for CHost {
    type Transfer = NonNull<ShimEasy>;
    /// The socket's `socketp` (`curl_multi_assign`).
    type Socket = *mut c_void;
}

/// The application's multi callbacks, as setopt left them.
#[derive(Clone, Copy)]
struct MultiCallbacks {
    socket: curl_socket_callback,
    socket_data: *mut c_void,
    timer: curl_multi_timer_callback,
    timer_data: *mut c_void,
    notify: curl_notify_callback,
    notify_data: *mut c_void,
}

pub(crate) struct ShimMulti {
    /// Atomic: `curl_multi_wakeup` reads it from other threads.
    magic: AtomicU32,
    pub(crate) stack: MultiStack,
    core: UnsafeCell<Multi<CHost>>,
    waker: Option<TryArc<Waker>>,
    cb: Cell<MultiCallbacks>,
    /// The handle a notification about the multi itself names, and the
    /// socket callback a socket of the multi's own work, a connection
    /// shutting down (C's `multi->admin`).
    admin: ShimEasy,
}

impl ShimMulti {
    /// A multi with the system's clock and network. Without a waker, which
    /// takes a descriptor, `curl_multi_wakeup` fails, as in C.
    fn new() -> Result<ShimMulti, OutOfMemory> {
        // A multi whose resolver cannot be set up is not made
        // (`Curl_multi_handle`'s `goto error`).
        let net = SystemNet::for_multi(curl_core::conn::threaded::Threads::MULTI)
            .map_err(|_| OutOfMemory)?;
        ShimMulti::with_net(try_box(net)?)
    }

    fn with_net(net: Box<dyn Net + Send>) -> Result<ShimMulti, OutOfMemory> {
        let waker = match Waker::new() {
            Ok(w) => Some(TryArc::try_new(w)?),
            Err(_) => None,
        };
        let env = Env {
            clock: try_box(SystemClock::new())?,
            net,
            // Row 0 is C's admin handle's, so ids equal C's.
            arena: ArenaPolicy::new(16, 1).expect("a valid policy"),
            waker: waker.clone(),
        };
        Ok(ShimMulti {
            magic: AtomicU32::new(MAGIC),
            stack: MultiStack::default(),
            core: UnsafeCell::new(Multi::new(env)?),
            waker,
            cb: Cell::new(MultiCallbacks {
                socket: None,
                socket_data: ptr::null_mut(),
                timer: None,
                timer_data: ptr::null_mut(),
                notify: None,
                notify_data: ptr::null_mut(),
            }),
            admin: ShimEasy::internal(),
        })
    }

    fn boxed() -> Result<NonNull<ShimMulti>, OutOfMemory> {
        Ok(NonNull::from(Box::leak(try_box(ShimMulti::new()?)?)))
    }

    /// As `curl_multi_init`, over `net`.
    #[cfg(test)]
    pub(crate) fn boxed_with(net: Box<dyn Net + Send>) -> Result<NonNull<ShimMulti>, OutOfMemory> {
        Ok(NonNull::from(Box::leak(try_box(ShimMulti::with_net(
            net,
        )?)?)))
    }

    /// The multi `curl_easy_perform` runs a handle in.
    pub(crate) fn private() -> Result<NonNull<ShimMulti>, OutOfMemory> {
        ShimMulti::boxed()
    }

    /// Free a multi with no transfers in it.
    ///
    /// # Safety
    ///
    /// `multi` came from `boxed` and is not used again.
    pub(crate) unsafe fn free(multi: NonNull<ShimMulti>) {
        // SAFETY: as the caller guarantees.
        let m = unsafe { multi.as_ref() };
        // SAFETY: nothing runs on a multi being freed.
        let core = unsafe { m.core_mut() };
        assert!(core.next_transfer(None).is_none(), "a multi is freed empty");
        m.magic.store(0, Ordering::Relaxed);
        // SAFETY: as the caller guarantees.
        drop(unsafe { Box::from_raw(multi.as_ptr()) });
    }

    /// The core, borrowed.
    ///
    /// # Safety
    ///
    /// The gate's reach is `Direct`: no call on the multi is under way, so
    /// nothing else borrows the core until this borrow ends.
    #[expect(clippy::mut_from_ref, reason = "the gate keeps the borrow unique")]
    pub(crate) unsafe fn core_mut(&self) -> &mut Multi<CHost> {
        // SAFETY: as the caller guarantees.
        unsafe { &mut *self.core.get() }
    }

    pub(crate) fn as_c(&self) -> *mut CURLM {
        ptr::from_ref(self).cast_mut().cast()
    }
}

/// The live multi `m` points to.
///
/// # Safety
///
/// `m` is NULL or a pointer `curl_multi_init` returned.
unsafe fn handle<'a>(m: *mut CURLM) -> Option<&'a ShimMulti> {
    let multi = NonNull::new(m.cast::<ShimMulti>())?;
    // SAFETY: as the caller guarantees.
    let multi = unsafe { multi.as_ref() };
    (multi.magic.load(Ordering::Relaxed) == MAGIC).then_some(multi)
}

/// Admit `call` on the multi at `m`, as `CURL_MAPI_ENTER` does.
///
/// # Safety
///
/// As `handle`.
unsafe fn enter<'a>(m: *mut CURLM, call: MultiCall) -> Result<MultiEntry<'a>, CURLMcode> {
    // SAFETY: as the caller guarantees.
    let multi = unsafe { handle(m) }.ok_or(CURLM_BAD_HANDLE)?;
    multi
        .stack
        .enter(call)
        .map_err(|Recursive| CURLM_RECURSIVE_API_CALL)
}

/// The multi the entry admitted a call on.
///
/// # Safety
///
/// `m` is the handle `enter` admitted the call on.
pub(crate) unsafe fn multi<'a>(m: *mut CURLM) -> &'a ShimMulti {
    // SAFETY: as the caller guarantees.
    unsafe { &*m.cast::<ShimMulti>() }
}

/// The application's multi callbacks behind the core's events.
pub(crate) struct ShimEvents<'a> {
    multi: &'a ShimMulti,
}

impl<'a> ShimEvents<'a> {
    pub(crate) fn new(multi: &'a ShimMulti) -> ShimEvents<'a> {
        ShimEvents { multi }
    }
}

impl MultiEvents<CHost> for ShimEvents<'_> {
    /// The handle is in the multi from here, so the add's timer callback
    /// reaches it (a setopt on it, for one); an add the timer refuses
    /// sends it home again.
    fn added(&mut self, id: TransferId, owner: &NonNull<ShimEasy>) {
        // SAFETY: a transfer's owner is its live handle, which the add
        // borrows.
        unsafe { owner.as_ref() }.attach(NonNull::from(self.multi), id);
    }

    fn timer(&mut self, cx: &mut EventCx<'_, CHost>, change: TimerChange) -> Result<(), Abort> {
        let cb = self.multi.cb.get();
        let Some(f) = cb.timer else { return Ok(()) };
        let ms = match change {
            // C's timeout is an `int`.
            TimerChange::Set(d) => {
                c_int::try_from(d.as_millis()).map_or(c_long::from(c_int::MAX), c_long::from)
            }
            TimerChange::Clear => -1,
        };
        let frame = Frame::Event(NonNull::from(cx).cast());
        let me = self.multi.as_c();
        // `cx` is not used again until `lend` returns.
        let rc = self.multi.stack.lend(frame, || {
            // SAFETY: the application's timer function takes its data.
            unsafe { f(me, ms, cb.timer_data) }
        });
        if crate::callbacks::aborts(rc) {
            Err(Abort)
        } else {
            Ok(())
        }
    }

    fn notify(&mut self, cx: &mut NotifyCx<'_, CHost>, n: Notification) {
        let cb = self.multi.cb.get();
        let Some(f) = cb.notify else { return };
        let (kind, easy) = match n {
            Notification::InfoRead => (ffi::CURLMNOTIFY_INFO_READ, self.multi.admin.as_c()),
            Notification::EasyDone(id) => (
                ffi::CURLMNOTIFY_EASY_DONE,
                cx.owner(id).map_or(ptr::null_mut(), |e| e.as_ptr().cast()),
            ),
        };
        let frame = Frame::Notify(NonNull::from(cx).cast());
        let me = self.multi.as_c();
        self.multi.stack.lend(frame, || {
            // SAFETY: the application's notify function takes its data.
            unsafe { f(me, kind as c_uint, easy, cb.notify_data) }
        });
    }

    fn wants_timer(&self) -> bool {
        self.multi.cb.get().timer.is_some()
    }

    fn socket(
        &mut self,
        cx: &mut EventCx<'_, CHost>,
        who: SocketFor,
        s: SocketKey,
        what: SocketWhat,
        assigned: Option<*mut c_void>,
    ) -> Result<(), Abort> {
        let cb = self.multi.cb.get();
        let Some(f) = cb.socket else { return Ok(()) };
        let what = match what {
            SocketWhat::In => ffi::CURL_POLL_IN,
            SocketWhat::Out => ffi::CURL_POLL_OUT,
            SocketWhat::InOut => ffi::CURL_POLL_INOUT,
            SocketWhat::Remove => ffi::CURL_POLL_REMOVE,
        };
        let easy: *mut CURL = match who {
            SocketFor::Transfer(id) => cx.owner(id).map_or(ptr::null_mut(), |e| e.as_ptr().cast()),
            SocketFor::Multi => self.multi.admin.as_c(),
        };
        let socketp = assigned.unwrap_or(ptr::null_mut());
        let frame = Frame::Event(NonNull::from(cx).cast());
        // `cx` is not used again until `lend` returns.
        let rc = self.multi.stack.lend(frame, || {
            // SAFETY: the application's socket function takes its data.
            unsafe { f(easy, s.get(), what, cb.socket_data, socketp) }
        });
        if crate::callbacks::aborts(rc) {
            Err(Abort)
        } else {
            Ok(())
        }
    }

    fn wants_sockets(&self) -> bool {
        self.multi.cb.get().socket.is_some()
    }
}

/// The application's callbacks as `curl_multi_cleanup` calls them: the
/// socket callback only.
struct Cleanup<'a>(ShimEvents<'a>);

impl MultiEvents<CHost> for Cleanup<'_> {
    fn socket(
        &mut self,
        cx: &mut EventCx<'_, CHost>,
        who: SocketFor,
        s: SocketKey,
        what: SocketWhat,
        assigned: Option<*mut c_void>,
    ) -> Result<(), Abort> {
        self.0.socket(cx, who, s, what, assigned)
    }

    fn wants_sockets(&self) -> bool {
        self.0.wants_sockets()
    }
}

/// What adds and removes transfers: the multi's core, or the context a
/// notification lends; other callbacks cannot reach it.
enum Core<'a> {
    Direct(&'a mut Multi<CHost>),
    Notify(&'a mut NotifyCx<'static, CHost>),
}

impl Core<'_> {
    fn of(multi: &ShimMulti, reach: Reach) -> Result<Core<'_>, Recursive> {
        match reach {
            // SAFETY: the reach is direct: nothing else borrows the core.
            Reach::Direct => Ok(Core::Direct(unsafe { multi.core_mut() })),
            // SAFETY: the notification lent its context and does not use
            // it until its callback returns.
            Reach::Frame(Frame::Notify(cx)) => Ok(Core::Notify(unsafe { &mut *cx.as_ptr() })),
            Reach::Frame(Frame::Event(_) | Frame::Transfer(_)) => Err(Recursive),
        }
    }
}

/// Add the handle `easy` to `multi`, reached as the gate said
/// (`Curl_multi_add_handle`).
pub(crate) fn add(multi: &ShimMulti, reach: Reach, easy: &ShimEasy) -> Result<(), MultiError> {
    if easy.added().is_some() {
        return Err(MultiError::AddedAlready);
    }
    let core = Core::of(multi, reach).map_err(|_| MultiError::RecursiveApiCall)?;
    // Cleared as early as possible (multi.c:516).
    easy.clear_error_buffer();
    let (mut transfer, owner) = (easy.detach(), NonNull::from(easy));
    // The body is sized as the transfer starts, the application's fields
    // as they are now (`Curl_pretransfer`).
    let set = easy.set.get();
    if crate::callbacks::sync_upload(transfer.options_mut(), owner, &set).is_err() {
        easy.return_home(transfer);
        return Err(MultiErrorKind::OutOfMemory.into());
    }
    let mut ev = ShimEvents::new(multi);
    let added = match core {
        Core::Direct(core) => core.add(transfer, owner, &mut ev),
        Core::Notify(cx) => cx.add(transfer, owner, &mut ev),
    };
    match added {
        Ok(id) => {
            assert_eq!(
                easy.added(),
                Some((NonNull::from(multi), id)),
                "attached as added"
            );
            Ok(())
        }
        Err(e) => {
            easy.return_home(e.easy);
            Err(e.kind.into())
        }
    }
}

/// Take the handle `easy` out of `multi`, reached as the gate said
/// (`Curl_multi_remove_handle`): one in no multi is out already.
pub(crate) fn remove(multi: &ShimMulti, reach: Reach, easy: &ShimEasy) -> Result<(), MultiError> {
    let Some((home, id)) = easy.added() else {
        return Ok(());
    };
    if home != NonNull::from(multi) {
        return Err(MultiErrorKind::BadEasyHandle.into());
    }
    let core = Core::of(multi, reach).map_err(|_| MultiError::RecursiveApiCall)?;
    let mut ev = ShimEvents::new(multi);
    let removed = match core {
        Core::Direct(core) => core.remove(id, &mut ev),
        Core::Notify(cx) => cx.remove(id, &mut ev),
    }
    .expect("an added handle is in its multi");
    easy.return_home(removed.easy);
    removed.status.map_err(MultiError::from)
}

#[unsafe(no_mangle)]
pub extern "C" fn curl_multi_init() -> *mut CURLM {
    match ShimMulti::boxed() {
        Ok(multi) => multi.as_ptr().cast(),
        Err(OutOfMemory) => ptr::null_mut(),
    }
}
const _: ffi::proto::curl_multi_init = curl_multi_init;

/// # Safety
///
/// `m` is NULL or a live multi, not used again on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_cleanup(m: *mut CURLM) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, MultiCall::Cleanup) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    // SAFETY: admitted on `m`.
    let multi = unsafe { multi(m) };
    // SAFETY: cleanup does not recurse, so nothing else runs on the multi.
    let core = unsafe { multi.core_mut() };
    // The handles stay the application's, on their own again; the timer
    // is not told (multi.c's cleanup removes nothing through it), but the
    // socket callback hears of each socket that closes.
    let mut ev = Cleanup(ShimEvents::new(multi));
    while let Some(id) = core.next_transfer(None) {
        let removed = core.remove(id, &mut ev).expect("just found");
        // SAFETY: a transfer's owner is a live handle while it is added.
        unsafe { removed.owner.as_ref() }.return_home(removed.easy);
    }
    // Then its connections, the socket callback told of each socket as
    // the multi's own (`Curl_cpool_destroy`, `Curl_cshutdn_destroy`).
    core.close_connections(&mut ev);
    drop(entry);
    // SAFETY: made by `boxed`; the caller does not use it again.
    unsafe { ShimMulti::free(NonNull::from(multi)) };
    CURLM_OK
}
const _: ffi::proto::curl_multi_cleanup = curl_multi_cleanup;

/// # Safety
///
/// `m` is NULL or a live multi; `curl` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_add_handle(m: *mut CURLM, curl: *mut CURL) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, MultiCall::AddHandle) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { easy::handle(curl) }) else {
        return CURLM_BAD_EASY_HANDLE;
    };
    if easy.added().is_none() {
        // The handle's own multi goes (multi.c:521).
        easy.drop_private();
    }
    // SAFETY: admitted on `m`.
    match add(unsafe { multi(m) }, entry.reach, easy) {
        Ok(()) => CURLM_OK,
        Err(kind) => multi_code(kind),
    }
}
const _: ffi::proto::curl_multi_add_handle = curl_multi_add_handle;

/// # Safety
///
/// `m` is NULL or a live multi; `curl` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_remove_handle(m: *mut CURLM, curl: *mut CURL) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, MultiCall::RemoveHandle) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    // SAFETY: as the caller guarantees.
    let Some(easy) = (unsafe { easy::handle(curl) }) else {
        return CURLM_BAD_EASY_HANDLE;
    };
    // SAFETY: admitted on `m`.
    match remove(unsafe { multi(m) }, entry.reach, easy) {
        Ok(()) => CURLM_OK,
        Err(kind) => multi_code(kind),
    }
}
const _: ffi::proto::curl_multi_remove_handle = curl_multi_remove_handle;

/// Write `n` through `out`, if the application gave somewhere to.
///
/// # Safety
///
/// `out` is NULL or valid for a write.
unsafe fn put<T>(out: *mut T, n: T) {
    if !out.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe { out.write(n) };
    }
}

pub(crate) fn running(n: u32) -> c_int {
    c_int::try_from(n).unwrap_or(c_int::MAX)
}

/// # Safety
///
/// `m` is NULL or a live multi; `running_handles` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_perform(
    m: *mut CURLM,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, MultiCall::Perform) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    assert!(
        matches!(entry.reach, Reach::Direct),
        "perform does not recurse"
    );
    // SAFETY: admitted on `m`, which nothing else runs on.
    let multi = unsafe { multi(m) };
    // SAFETY: as above.
    let result = unsafe { multi.core_mut() }.perform(&mut ShimEvents::new(multi));
    match result {
        Ok(n) => {
            // SAFETY: as the caller guarantees.
            unsafe { put(running_handles, running(n)) };
            CURLM_OK
        }
        Err(kind) => multi_code(kind),
    }
}
const _: ffi::proto::curl_multi_perform = curl_multi_perform;

/// # Safety
///
/// `m` is NULL or a live multi; `running_handles` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_socket_action(
    m: *mut CURLM,
    s: curl_socket_t,
    _ev_bitmask: c_int,
    running_handles: *mut c_int,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, MultiCall::SocketAction) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    assert!(
        matches!(entry.reach, Reach::Direct),
        "socket_action does not recurse"
    );
    let what = if s == CURL_SOCKET_TIMEOUT {
        SocketEvent::Timeout
    } else {
        SocketEvent::Socket(SocketKey::new(s))
    };
    // SAFETY: admitted on `m`, which nothing else runs on.
    let multi = unsafe { multi(m) };
    // SAFETY: as above.
    let core = unsafe { multi.core_mut() };
    let result = core.socket_action(what, &mut ShimEvents::new(multi));
    // Told even when a callback aborted (`multi_socket`'s `out`).
    // SAFETY: as the caller guarantees.
    unsafe { put(running_handles, running(core.counts().running)) };
    match result {
        Ok(_) => CURLM_OK,
        Err(kind) => multi_code(kind),
    }
}

/// # Safety
///
/// `m` is NULL or a live multi.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_assign(
    m: *mut CURLM,
    s: curl_socket_t,
    socketp: *mut c_void,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, MultiCall::Assign) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    let key = SocketKey::new(s);
    let value = (!socketp.is_null()).then_some(socketp);
    let assigned = match entry.reach {
        Reach::Direct => {
            // SAFETY: admitted on `m`, which nothing else runs on.
            let multi = unsafe { multi(m) };
            // SAFETY: as above.
            unsafe { multi.core_mut() }.assign(key, value)
        }
        // SAFETY: the callback lent its context and does not use it until
        // it returns.
        Reach::Frame(Frame::Event(cx)) => unsafe { &mut *cx.as_ptr() }.assign(key, value),
        // SAFETY: as above.
        Reach::Frame(Frame::Notify(cx)) => unsafe { &mut *cx.as_ptr() }.assign(key, value),
        // A transfer's handler reaches only its transfers.
        Reach::Frame(Frame::Transfer(_)) => Err(UnknownSocket),
    };
    match assigned {
        Ok(()) => CURLM_OK,
        Err(UnknownSocket) => ffi::CURLM_BAD_SOCKET,
    }
}
const _: ffi::proto::curl_multi_assign = curl_multi_assign;
const _: ffi::proto::curl_multi_socket_action = curl_multi_socket_action;

/// The message to point the application at, kept in the transfer's
/// handle until the next one.
fn message(m: Option<Message<'_, CHost>>, queued: &mut c_int) -> *mut CURLMsg {
    let Some(m) = m else { return ptr::null_mut() };
    *queued = c_int::try_from(m.remaining).unwrap_or(c_int::MAX);
    // SAFETY: a transfer's owner is a live handle while it is added.
    let easy = unsafe { m.owner.as_ref() };
    let code = match m.result {
        Ok(()) => ffi::CURLE_OK,
        Err(kind) => easy_code(kind),
    };
    let msg = easy.msg.get();
    // SAFETY: the message is the handle's, written only here, and read by
    // the application until the next call.
    unsafe {
        msg.write(CURLMsg {
            msg: CURLMSG_DONE,
            easy_handle: easy.as_c(),
            data: ffi::CURLMsg_data { result: code },
        })
    };
    msg
}

/// # Safety
///
/// `m` is NULL or a live multi; `msgs_in_queue` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_info_read(
    m: *mut CURLM,
    msgs_in_queue: *mut c_int,
) -> *mut CURLMsg {
    let mut queued = 0;
    let msg = (|| {
        // SAFETY: as the caller guarantees.
        let entry = unsafe { enter(m, MultiCall::InfoRead) }.ok()?;
        // SAFETY: admitted on `m`.
        let multi = unsafe { multi(m) };
        let msg = match entry.reach {
            // SAFETY: the reach is direct.
            Reach::Direct => message(unsafe { multi.core_mut() }.info_read(), &mut queued),
            Reach::Frame(Frame::Event(cx)) => {
                // SAFETY: the callback lent its context and does not use
                // it until it returns.
                message(unsafe { &mut *cx.as_ptr() }.info_read(), &mut queued)
            }
            Reach::Frame(Frame::Notify(cx)) => {
                // SAFETY: as above.
                message(unsafe { &mut *cx.as_ptr() }.info_read(), &mut queued)
            }
            // A transfer's handler reaches only its transfers.
            Reach::Frame(Frame::Transfer(_)) => ptr::null_mut(),
        };
        Some(msg)
    })()
    .unwrap_or(ptr::null_mut());
    // SAFETY: as the caller guarantees.
    unsafe { put(msgs_in_queue, queued) };
    msg
}
const _: ffi::proto::curl_multi_info_read = curl_multi_info_read;

/// # Safety
///
/// `m` is NULL or a live multi; `timeout_ms` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_timeout(m: *mut CURLM, timeout_ms: *mut c_long) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, MultiCall::Timeout) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    // SAFETY: admitted on `m`.
    let multi = unsafe { multi(m) };
    let due = match entry.reach {
        // SAFETY: the reach is direct.
        Reach::Direct => unsafe { multi.core_mut() }.timeout_traced(&mut ShimEvents::new(multi)),
        // SAFETY: as in `curl_multi_info_read`.
        Reach::Frame(Frame::Notify(cx)) => unsafe { &*cx.as_ptr() }.timeout(),
        Reach::Frame(Frame::Event(_) | Frame::Transfer(_)) => return CURLM_RECURSIVE_API_CALL,
    };
    // C's timeout is an `int`.
    let ms = due.map_or(-1, |d| {
        c_int::try_from(d.as_millis()).map_or(c_long::from(c_int::MAX), c_long::from)
    });
    // SAFETY: as the caller guarantees.
    unsafe { put(timeout_ms, ms) };
    CURLM_OK
}
const _: ffi::proto::curl_multi_timeout = curl_multi_timeout;

/// # Safety
///
/// `m` is NULL or a live multi; `pvalue` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_get_offt(
    m: *mut CURLM,
    info: CURLMinfo_offt,
    pvalue: *mut curl_off_t,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, MultiCall::GetOfft) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    if pvalue.is_null() {
        return CURLM_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: admitted on `m`.
    let multi = unsafe { multi(m) };
    let census = match entry.reach {
        // SAFETY: the reach is direct.
        Reach::Direct => unsafe { multi.core_mut() }.census(),
        // SAFETY: as in `curl_multi_info_read`.
        Reach::Frame(Frame::Event(cx)) => unsafe { &*cx.as_ptr() }.census(),
        // SAFETY: as above.
        Reach::Frame(Frame::Notify(cx)) => unsafe { &*cx.as_ptr() }.census(),
        // SAFETY: as above.
        Reach::Frame(Frame::Transfer(cx)) => unsafe { &*cx.as_ptr() }.census(),
    };
    let off = |n: u64| curl_off_t::try_from(n).unwrap_or(curl_off_t::MAX);
    let value = match info {
        ffi::CURLMINFO_XFERS_CURRENT => off(census.counts.current.into()),
        ffi::CURLMINFO_XFERS_RUNNING => off(census.working().into()),
        ffi::CURLMINFO_XFERS_PENDING => off(census.pending.into()),
        ffi::CURLMINFO_XFERS_DONE => off(census.unread.into()),
        ffi::CURLMINFO_XFERS_ADDED => off(census.counts.added_ever),
        _ => {
            // SAFETY: checked non-NULL above.
            unsafe { pvalue.write(-1) };
            return CURLM_UNKNOWN_OPTION;
        }
    };
    // SAFETY: as above.
    unsafe { pvalue.write(value) };
    CURLM_OK
}
const _: ffi::proto::curl_multi_get_offt = curl_multi_get_offt;

/// The kind of notification C's number names.
pub(crate) fn notify_kind(n: c_uint) -> Option<NotifyKind> {
    match c_int::try_from(n).ok()? {
        ffi::CURLMNOTIFY_INFO_READ => Some(NotifyKind::InfoRead),
        ffi::CURLMNOTIFY_EASY_DONE => Some(NotifyKind::EasyDone),
        _ => None,
    }
}

/// # Safety
///
/// `m` is NULL or a live multi.
unsafe fn set_notify(m: *mut CURLM, call: MultiCall, n: c_uint, on: bool) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, call) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    let Some(kind) = notify_kind(n) else {
        return CURLM_UNKNOWN_OPTION;
    };
    // SAFETY: admitted on `m`.
    let multi = unsafe { multi(m) };
    match entry.reach {
        // SAFETY: the reach is direct.
        Reach::Direct => unsafe { multi.core_mut() }.set_notify(kind, on),
        // SAFETY: as in `curl_multi_info_read`.
        Reach::Frame(Frame::Event(cx)) => unsafe { &mut *cx.as_ptr() }.set_notify(kind, on),
        // SAFETY: as above.
        Reach::Frame(Frame::Notify(cx)) => unsafe { &mut *cx.as_ptr() }.set_notify(kind, on),
        Reach::Frame(Frame::Transfer(_)) => return CURLM_RECURSIVE_API_CALL,
    }
    CURLM_OK
}

/// # Safety
///
/// `m` is NULL or a live multi.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_notify_enable(
    m: *mut CURLM,
    notification: c_uint,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    unsafe { set_notify(m, MultiCall::NotifyEnable, notification, true) }
}
const _: ffi::proto::curl_multi_notify_enable = curl_multi_notify_enable;

/// # Safety
///
/// `m` is NULL or a live multi.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_notify_disable(
    m: *mut CURLM,
    notification: c_uint,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    unsafe { set_notify(m, MultiCall::NotifyDisable, notification, false) }
}
const _: ffi::proto::curl_multi_notify_disable = curl_multi_notify_disable;

/// # Safety
///
/// `m` is NULL or a live multi; the argument is of the option's type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_setopt(
    m: *mut CURLM,
    option: CURLMoption,
    mut args: ...
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, MultiCall::Setopt) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    // SAFETY: admitted on `m`.
    let multi = unsafe { multi(m) };
    if matches!(
        option,
        ffi::CURLMOPT_MAXCONNECTS
            | ffi::CURLMOPT_MAX_HOST_CONNECTIONS
            | ffi::CURLMOPT_MAX_TOTAL_CONNECTIONS
    ) {
        // SAFETY: the application passes a long, the type of each.
        let n = unsafe { args.next_arg::<c_long>() };
        let limits = match entry.reach {
            // SAFETY: the reach is direct.
            Reach::Direct => unsafe { multi.core_mut() }.conn_limits_mut(),
            // SAFETY: as in `curl_multi_info_read`.
            Reach::Frame(Frame::Event(cx)) => unsafe { &mut *cx.as_ptr() }.conn_limits_mut(),
            // SAFETY: as above.
            Reach::Frame(Frame::Notify(cx)) => unsafe { &mut *cx.as_ptr() }.conn_limits_mut(),
            Reach::Frame(Frame::Transfer(_)) => return CURLM_RECURSIVE_API_CALL,
        };
        return set_limit(limits, option, n);
    }
    let mut cb = multi.cb.get();
    // SAFETY: the application passes a pointer, the type of each of these
    // options, and a function of the option's type.
    let p = unsafe { args.next_arg::<*mut c_void>() };
    match option {
        // SAFETY: as above.
        ffi::CURLMOPT_SOCKETFUNCTION => cb.socket = unsafe { function(p) },
        ffi::CURLMOPT_SOCKETDATA => cb.socket_data = p,
        // SAFETY: as above.
        ffi::CURLMOPT_TIMERFUNCTION => cb.timer = unsafe { function(p) },
        ffi::CURLMOPT_TIMERDATA => cb.timer_data = p,
        // SAFETY: as above.
        ffi::CURLMOPT_NOTIFYFUNCTION => cb.notify = unsafe { function(p) },
        ffi::CURLMOPT_NOTIFYDATA => cb.notify_data = p,
        // The connection limits and the rest come with connections.
        _ => return CURLM_UNKNOWN_OPTION,
    }
    multi.cb.set(cb);
    CURLM_OK
}
const _: ffi::proto::curl_multi_setopt = curl_multi_setopt;

/// One of the multi's connection limits from its long, as C takes it:
/// 0 for none.
fn set_limit(limits: &mut ConnLimits, option: CURLMoption, n: c_long) -> CURLMcode {
    if option == ffi::CURLMOPT_MAXCONNECTS {
        // Read unsigned: past `UINT32_MAX`, a negative one among them,
        // changes nothing; 0 is the guess.
        if let Ok(n) = u32::try_from(n as c_ulong) {
            limits.max_connects = NonZeroU32::new(n);
        }
        return CURLM_OK;
    }
    // Negative is refused and taken as 0; past `UINT32_MAX` is it.
    let (n, code) = match u64::try_from(n) {
        Ok(n) => (n, CURLM_OK),
        Err(_) => (0, CURLM_BAD_FUNCTION_ARGUMENT),
    };
    let max = NonZeroU32::new(u32::try_from(n).unwrap_or(u32::MAX));
    if option == ffi::CURLMOPT_MAX_HOST_CONNECTIONS {
        limits.max_host = max;
    } else {
        limits.max_total = max;
    }
    code
}

/// What C polls an extra descriptor for.
pub(crate) fn wait_events(events: i16) -> Events {
    let events = c_int::from(events);
    let mut e = Events::NONE;
    if events & CURL_WAIT_POLLIN != 0 {
        e = e | Events::IN;
    }
    if events & CURL_WAIT_POLLPRI != 0 {
        e = e | Events::PRI;
    }
    if events & CURL_WAIT_POLLOUT != 0 {
        e = e | Events::OUT;
    }
    e
}

/// What C reports for an extra descriptor.
pub(crate) fn wait_revents(r: Events) -> i16 {
    let mut mask = 0;
    if r.contains(Events::IN) {
        mask |= CURL_WAIT_POLLIN;
    }
    if r.contains(Events::OUT) {
        mask |= CURL_WAIT_POLLOUT;
    }
    if r.contains(Events::PRI) {
        mask |= CURL_WAIT_POLLPRI;
    }
    mask as i16
}

/// `curl_multi_wait` and `curl_multi_poll` (`multi_wait`).
///
/// # Safety
///
/// `m` is NULL or a live multi; `extra` holds `n` entries; `ret` is NULL
/// or writable.
unsafe fn wait(
    m: *mut CURLM,
    call: MultiCall,
    extra: *mut curl_waitfd,
    n: c_uint,
    timeout_ms: c_int,
    ret: *mut c_int,
    mode: WaitMode,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    let entry = match unsafe { enter(m, call) } {
        Ok(entry) => entry,
        Err(code) => return code,
    };
    assert!(
        matches!(entry.reach, Reach::Direct),
        "a wait does not recurse"
    );
    let Ok(timeout) = u64::try_from(timeout_ms) else {
        return CURLM_BAD_FUNCTION_ARGUMENT;
    };
    let extra: &mut [curl_waitfd] = if n == 0 || extra.is_null() {
        &mut []
    } else {
        // SAFETY: the application gave `n` entries.
        unsafe { core::slice::from_raw_parts_mut(extra, n as usize) }
    };
    let polled = extra.iter().map(|e| {
        // SAFETY: the application keeps its descriptors open for the
        // call.
        let fd = unsafe { BorrowedFd::borrow_raw(e.fd) };
        PollFd::new(fd, wait_events(e.events))
    });
    // A few on the stack, as C's `a_few_on_stack`, so a loop of waits
    // allocates nothing.
    const ON_STACK: usize = 10;
    let mut few;
    let mut more = Vec::new();
    let fds: &mut [PollFd<'_>] = match polled.clone().next() {
        None => &mut [],
        Some(any) if extra.len() <= ON_STACK => {
            few = [any; ON_STACK];
            for (slot, fd) in few.iter_mut().zip(polled) {
                *slot = fd;
            }
            &mut few[..extra.len()]
        }
        Some(_) => {
            if more.try_reserve_exact(extra.len()).is_err() {
                return CURLM_OUT_OF_MEMORY;
            }
            for fd in polled {
                more.try_push(fd).expect("reserved");
            }
            &mut more
        }
    };
    // SAFETY: admitted on `m`, which nothing else runs on.
    let multi = unsafe { multi(m) };
    // SAFETY: as above.
    let ready = unsafe { multi.core_mut() }.wait(
        fds,
        Duration::from_millis(timeout),
        mode,
        &mut ShimEvents::new(multi),
    );
    for (e, fd) in extra.iter_mut().zip(fds.iter()) {
        e.revents = wait_revents(fd.revents());
    }
    match ready {
        Ok(ready) => {
            // SAFETY: as the caller guarantees.
            unsafe { put(ret, running(ready)) };
            CURLM_OK
        }
        Err(kind) => multi_code(kind),
    }
}

/// # Safety
///
/// As `wait`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_wait(
    m: *mut CURLM,
    extra_fds: *mut curl_waitfd,
    extra_nfds: c_uint,
    timeout_ms: c_int,
    ret: *mut c_int,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    unsafe {
        wait(
            m,
            MultiCall::Wait,
            extra_fds,
            extra_nfds,
            timeout_ms,
            ret,
            WaitMode::Wait,
        )
    }
}
const _: ffi::proto::curl_multi_wait = curl_multi_wait;

/// # Safety
///
/// As `wait`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_poll(
    m: *mut CURLM,
    extra_fds: *mut curl_waitfd,
    extra_nfds: c_uint,
    timeout_ms: c_int,
    ret: *mut c_int,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    unsafe {
        wait(
            m,
            MultiCall::Poll,
            extra_fds,
            extra_nfds,
            timeout_ms,
            ret,
            WaitMode::Poll,
        )
    }
}
const _: ffi::proto::curl_multi_poll = curl_multi_poll;

/// # Safety
///
/// `m` is NULL or a live multi, which may be in use on another thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_wakeup(m: *mut CURLM) -> CURLMcode {
    // No gate: the waker is outside the core and never changes.
    // SAFETY: as the caller guarantees.
    let Some(multi) = (unsafe { handle(m) }) else {
        return CURLM_BAD_HANDLE;
    };
    match multi.waker.as_deref().map(Waker::wake) {
        Some(Ok(())) => CURLM_OK,
        Some(Err(_)) | None => CURLM_WAKEUP_FAILURE,
    }
}
const _: ffi::proto::curl_multi_wakeup = curl_multi_wakeup;

/// # Safety
///
/// `m` is NULL or a live multi; the sets are NULL or valid; `max_fd` is
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_fdset(
    m: *mut CURLM,
    read_fd_set: *mut ffi::fd_set,
    write_fd_set: *mut ffi::fd_set,
    _exc_fd_set: *mut ffi::fd_set,
    max_fd: *mut c_int,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    if let Err(code) = unsafe { enter(m, MultiCall::Fdset) } {
        return code;
    }
    // SAFETY: admitted on `m`, which nothing else runs on.
    let multi = unsafe { multi(m) };
    let mut highest = -1;
    // SAFETY: as above.
    unsafe { multi.core_mut() }.sockets(&mut ShimEvents::new(multi), |key, events| {
        let fd = key.get();
        // One a set cannot hold is left out (`FDSET_SOCK`).
        if usize::try_from(fd).is_ok_and(|fd| fd < libc::FD_SETSIZE) {
            for (wanted, set) in [(Events::IN, read_fd_set), (Events::OUT, write_fd_set)] {
                if events.contains(wanted) && !set.is_null() {
                    // SAFETY: `set` is the caller's `fd_set`, and `fd` is
                    // within it.
                    unsafe { libc::FD_SET(fd, set.cast::<libc::fd_set>()) };
                }
            }
            highest = highest.max(fd);
        }
    });
    // SAFETY: as the caller guarantees.
    unsafe { put(max_fd, highest) };
    CURLM_OK
}
const _: ffi::proto::curl_multi_fdset = curl_multi_fdset;

/// # Safety
///
/// `m` is NULL or a live multi; `fd_count` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_multi_waitfds(
    m: *mut CURLM,
    ufds: *mut curl_waitfd,
    size: c_uint,
    fd_count: *mut c_uint,
) -> CURLMcode {
    // SAFETY: as the caller guarantees.
    if let Err(code) = unsafe { enter(m, MultiCall::Waitfds) } {
        return code;
    }
    if ufds.is_null() && (size > 0 || fd_count.is_null()) {
        return CURLM_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: admitted on `m`, which nothing else runs on.
    let multi = unsafe { multi(m) };
    let mut wfds = WaitFds {
        // SAFETY: the caller gives `size` entries at `ufds`.
        wfds: (!ufds.is_null())
            .then(|| unsafe { std::slice::from_raw_parts_mut(ufds, size as usize) }),
        n: 0,
    };
    let mut need: c_uint = 0;
    // SAFETY: as above.
    unsafe { multi.core_mut() }.sockets(&mut ShimEvents::new(multi), |key, events| {
        // A pollset reads and writes, nothing else.
        let wanted = wait_revents(events);
        if wanted != 0 {
            need = need.saturating_add(wfds.add(key.get(), wanted));
        }
    });
    // SAFETY: as the caller guarantees.
    unsafe { put(fd_count, need) };
    if !ufds.is_null() && need as usize != wfds.n {
        // Too few entries: the count says how many are needed.
        return CURLM_OUT_OF_MEMORY;
    }
    CURLM_OK
}
const _: ffi::proto::curl_multi_waitfds = curl_multi_waitfds;

/// The application's entries as `curl_multi_waitfds` fills them
/// (`struct Curl_waitfds`).
struct WaitFds<'a> {
    /// The entries, or none when the application asks only for the count.
    wfds: Option<&'a mut [curl_waitfd]>,
    /// How many of them are filled.
    n: usize,
}

impl WaitFds<'_> {
    /// List `fd` waiting for `events`, and say how many entries that needs
    /// (`cwfds_add_sock`). A socket already listed gains the events and
    /// needs none; one that does not fit is left out but still counted.
    /// With no entries, every socket counts, a repeat too.
    fn add(&mut self, fd: curl_socket_t, events: i16) -> c_uint {
        let Some(wfds) = self.wfds.as_deref_mut() else {
            return 1;
        };
        if let Some(entry) = wfds[..self.n].iter_mut().rev().find(|e| e.fd == fd) {
            entry.events |= events;
            return 0;
        }
        if let Some(entry) = wfds.get_mut(self.n) {
            entry.fd = fd;
            entry.events = events;
            self.n += 1;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A socket listed twice is one entry with both waits, as C's
    /// `cwfds_add_sock` folds it; one that did not fit is counted again;
    /// with no entries, every listing counts. The numbers are what C's
    /// function gives for the same four listings.
    #[test]
    fn a_socket_listed_twice_is_folded() {
        let (r, w) = (CURL_WAIT_POLLIN as i16, CURL_WAIT_POLLOUT as i16);
        let list = |wfds: Option<&mut [curl_waitfd]>| {
            let mut wfds = WaitFds { wfds, n: 0 };
            let need: c_uint = [(5, r), (6, w), (6, r), (5, w)]
                .into_iter()
                .map(|(fd, events)| wfds.add(fd, events))
                .sum();
            (need, wfds.n)
        };
        let blank = curl_waitfd {
            fd: -1,
            events: 0,
            revents: 0,
        };
        let entries = |e: &[curl_waitfd]| e.iter().map(|e| (e.fd, e.events)).collect::<Vec<_>>();

        let mut room = [blank; 3];
        assert_eq!(list(Some(&mut room)), (2, 2));
        assert_eq!(entries(&room), [(5, r | w), (6, r | w), (-1, 0)]);

        let mut one = [blank; 1];
        assert_eq!(list(Some(&mut one)), (3, 1), "6 never fit, twice");
        assert_eq!(entries(&one), [(5, r | w)]);

        assert_eq!(list(None), (4, 0), "no entries: each listing counts");
    }
}
