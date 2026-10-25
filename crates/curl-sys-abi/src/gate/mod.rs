//! The one gate every exported call into a handle passes (`lib/api.c`):
//! which calls may run while another call on the same handle is under
//! way, or inside one of its callbacks, and how a call that may reaches
//! the multi the callback runs inside.
//!
//! A multi's core is borrowed for as long as one of its calls runs. A
//! callback the core makes runs inside that borrow: its adapter lends the
//! context the core gave it as the multi's frame, and a call the
//! callback makes into the same multi goes through the frame, never
//! through the core. Without a frame, no call is under way and the core
//! may be borrowed.

#![allow(unsafe_code)]

#[rustfmt::skip]
#[allow(dead_code, reason = "the table lists every call; the shim exports them step by step")]
mod table;

use core::cell::Cell;
use core::ptr::NonNull;

use curl_alloc::OutOfMemory;
use curl_core::easy::Easy;
use curl_core::multi::{EventCx, NotifyCx, TransferCx, TransferId};
use curl_core::options::Options;
use curl_core::report::TransferReport;
use curl_core::tls::TlsNative;

use crate::multi::CHost;

pub(crate) use table::{EASY_MAX_DEPTH, EasyCall, MULTI_MAX_DEPTH, MultiCall};

/// What api.c allows an easy call (`Curl_eapi_fn_props`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EasyRules {
    /// The call ends the handle.
    pub(crate) kills: bool,
    /// The call may run while another call on the handle, or on its
    /// multi, is under way.
    pub(crate) recurse: bool,
    /// The call is refused inside the multi's socket and timer callbacks.
    pub(crate) not_in_event: bool,
}

/// What api.c allows a multi call (`Curl_mapi_fn_props`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MultiRules {
    /// The call ends the handle.
    pub(crate) kills: bool,
    /// The call may run while another call on the multi is under way.
    pub(crate) recurse: bool,
    /// The call may run inside a notify callback, whatever `recurse` says.
    pub(crate) in_notify: bool,
}

/// The context a running callback's adapter lent: its lifetime is erased,
/// and it is reached only between the adapter's push and pop, while the
/// adapter does not use its own reference.
#[derive(Clone, Copy)]
pub(crate) enum Frame {
    /// A transfer's own callback: write, header, read, progress, debug.
    Transfer(NonNull<TransferCx<'static>>),
    /// The timer (or socket) callback.
    Event(NonNull<EventCx<'static, CHost>>),
    /// A notification.
    Notify(NonNull<NotifyCx<'static, CHost>>),
}

impl Frame {
    /// A transfer's options, through the context lent.
    ///
    /// # Safety
    ///
    /// The frame is the multi's innermost, and the borrow ends before its
    /// callback returns.
    pub(crate) unsafe fn options_mut<'a>(self, id: TransferId) -> Option<&'a mut Options> {
        match self {
            Frame::Transfer(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &mut *cx.as_ptr() }.options_mut(id)
            }
            Frame::Event(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &mut *cx.as_ptr() }.options_mut(id)
            }
            Frame::Notify(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &mut *cx.as_ptr() }.options_mut(id)
            }
        }
    }

    /// What a transfer reports, through the context lent.
    ///
    /// # Safety
    ///
    /// As `options_mut`.
    pub(crate) unsafe fn info<'a>(self, id: TransferId) -> Option<&'a TransferReport> {
        match self {
            Frame::Transfer(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &*cx.as_ptr() }.info(id)
            }
            Frame::Event(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &*cx.as_ptr() }.info(id)
            }
            Frame::Notify(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &*cx.as_ptr() }.info(id)
            }
        }
    }

    /// The TLS library's objects of the connection a transfer holds,
    /// through the context lent.
    ///
    /// # Safety
    ///
    /// As `options_mut`.
    pub(crate) unsafe fn tls_native(self, id: TransferId) -> Option<TlsNative> {
        match self {
            Frame::Transfer(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &*cx.as_ptr() }.tls_native(id)
            }
            Frame::Event(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &*cx.as_ptr() }.tls_native(id)
            }
            Frame::Notify(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &*cx.as_ptr() }.tls_native(id)
            }
        }
    }

    /// A copy of a transfer's `Easy`, through the context lent, `prepare`
    /// given its options as `Easy::try_clone_with` does.
    ///
    /// # Safety
    ///
    /// As `options_mut`.
    pub(crate) unsafe fn duplicate(
        self,
        id: TransferId,
        prepare: &mut dyn FnMut(&mut Options) -> Result<(), OutOfMemory>,
    ) -> Option<Result<Easy, OutOfMemory>> {
        match self {
            Frame::Transfer(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &*cx.as_ptr() }.duplicate_with(id, prepare)
            }
            Frame::Event(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &*cx.as_ptr() }.duplicate_with(id, prepare)
            }
            Frame::Notify(cx) => {
                // SAFETY: as the caller guarantees, the adapter that lent
                // the context does not use it until its callback returns.
                unsafe { &*cx.as_ptr() }.duplicate_with(id, prepare)
            }
        }
    }
}

/// A call refused by the gate (`CURLE_RECURSIVE_API_CALL`,
/// `CURLM_RECURSIVE_API_CALL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Recursive;

/// What a multi's calls in progress leave reachable (C's
/// `multi->callstack`).
#[derive(Default)]
pub(crate) struct MultiStack {
    /// API calls under way on the multi and callbacks running inside them.
    depth: Cell<u8>,
    /// The innermost callback's context.
    frame: Cell<Option<Frame>>,
    /// Socket and timer callbacks running.
    events: Cell<u8>,
    /// Notify callbacks running.
    notifies: Cell<u8>,
}

/// How a call admitted by the gate reaches the multi.
#[derive(Clone, Copy)]
pub(crate) enum Reach {
    /// Nothing runs: the core may be borrowed.
    Direct,
    /// Through the context a callback was lent.
    Frame(Frame),
}

/// An admitted multi call; leaving it pops the call.
pub(crate) struct MultiEntry<'a> {
    stack: &'a MultiStack,
    pub(crate) reach: Reach,
}

impl Drop for MultiEntry<'_> {
    fn drop(&mut self) {
        self.stack.depth.set(self.stack.depth.get() - 1);
    }
}

impl MultiStack {
    /// Admit `call`, as `Curl_mapi_enter` does.
    pub(crate) fn enter(&self, call: MultiCall) -> Result<MultiEntry<'_>, Recursive> {
        let rules = call.rules();
        let in_notify = rules.in_notify && self.notifies.get() > 0;
        if !in_notify && !rules.recurse && self.depth.get() > 0 {
            return Err(Recursive);
        }
        let reach = self.reach()?;
        if self.depth.get() >= MULTI_MAX_DEPTH {
            return Err(Recursive);
        }
        self.depth.set(self.depth.get() + 1);
        Ok(MultiEntry { stack: self, reach })
    }

    /// How a call admitted now reaches the core. A call under way without
    /// a callback running is one on another thread, which the gate cannot
    /// let in.
    pub(crate) fn reach(&self) -> Result<Reach, Recursive> {
        match self.frame.get() {
            Some(frame) => Ok(Reach::Frame(frame)),
            None if self.depth.get() == 0 => Ok(Reach::Direct),
            None => Err(Recursive),
        }
    }

    /// A multi call or callback is under way: easy calls that may not
    /// recurse are refused.
    pub(crate) fn busy(&self) -> bool {
        self.depth.get() > 0
    }

    /// A socket or timer callback is running.
    pub(crate) fn in_event(&self) -> bool {
        self.events.get() > 0
    }

    /// Run `f` with `frame` lent, as `Curl_cbapi_enter` pushes a callback.
    /// Past the depth limit the callback runs without counting, as in C.
    pub(crate) fn lend<R>(&self, frame: Frame, f: impl FnOnce() -> R) -> R {
        let counted = self.depth.get() < MULTI_MAX_DEPTH;
        if counted {
            self.depth.set(self.depth.get() + 1);
        }
        let (events, notifies) = match frame {
            Frame::Transfer(_) => (0, 0),
            Frame::Event(_) => (1, 0),
            Frame::Notify(_) => (0, 1),
        };
        self.events.set(self.events.get() + events);
        self.notifies.set(self.notifies.get() + notifies);
        let outer = self.frame.replace(Some(frame));
        // Panics abort, so the restore below always runs.
        let r = f();
        self.frame.set(outer);
        self.events.set(self.events.get() - events);
        self.notifies.set(self.notifies.get() - notifies);
        if counted {
            self.depth.set(self.depth.get() - 1);
        }
        r
    }
}

/// An easy handle's calls in progress (C's `data->callstack`).
#[derive(Default)]
pub(crate) struct EasyStack {
    depth: Cell<u8>,
}

/// An admitted easy call; leaving it pops the call.
pub(crate) struct EasyEntry<'a> {
    stack: &'a EasyStack,
}

impl Drop for EasyEntry<'_> {
    fn drop(&mut self) {
        self.stack.depth.set(self.stack.depth.get() - 1);
    }
}

impl EasyStack {
    /// Admit `call` on a handle in `multi`, if it is in one, as
    /// `Curl_eapi_enter` does.
    pub(crate) fn enter(
        &self,
        call: EasyCall,
        multi: Option<&MultiStack>,
    ) -> Result<EasyEntry<'_>, Recursive> {
        let rules = call.rules();
        let multi_busy = multi.is_some_and(MultiStack::busy);
        if !rules.recurse && (self.depth.get() > 0 || multi_busy) {
            return Err(Recursive);
        }
        if rules.not_in_event && multi.is_some_and(MultiStack::in_event) {
            return Err(Recursive);
        }
        if self.depth.get() >= EASY_MAX_DEPTH {
            return Err(Recursive);
        }
        self.depth.set(self.depth.get() + 1);
        Ok(EasyEntry { stack: self })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A few rows, against lib/api.c as read by hand.
    #[test]
    fn reads_api_c() {
        let pause = EasyCall::Pause.rules();
        assert!(pause.recurse && pause.not_in_event && !pause.kills);
        assert!(EasyCall::Cleanup.rules().kills);
        assert!(!EasyCall::Perform.rules().recurse);
        assert!(EasyCall::Setopt.rules().recurse);
        let add = MultiCall::AddHandle.rules();
        assert!(!add.recurse && add.in_notify);
        assert!(MultiCall::Cleanup.rules().kills);
        assert!(!MultiCall::Perform.rules().in_notify);
        assert!(MultiCall::InfoRead.rules().recurse);
        assert_eq!((EASY_MAX_DEPTH, MULTI_MAX_DEPTH), (7, 15));
    }

    fn transfer_frame() -> Frame {
        Frame::Transfer(NonNull::dangling())
    }

    /// Inside a callback, a call that may not recurse is refused and one
    /// that may reaches the frame; outside, the core.
    #[test]
    fn admits_as_api_c() {
        let m = MultiStack::default();
        let entry = m.enter(MultiCall::Perform).unwrap();
        assert!(matches!(entry.reach, Reach::Direct));
        // A call under way with no callback running: another thread.
        assert_eq!(m.enter(MultiCall::InfoRead).err(), Some(Recursive));
        m.lend(transfer_frame(), || {
            assert_eq!(m.enter(MultiCall::Perform).err(), Some(Recursive));
            let info = m.enter(MultiCall::InfoRead).unwrap();
            assert!(matches!(info.reach, Reach::Frame(Frame::Transfer(_))));
            let e = EasyStack::default();
            assert_eq!(e.enter(EasyCall::Perform, Some(&m)).err(), Some(Recursive));
            assert!(e.enter(EasyCall::Pause, Some(&m)).is_ok());
            // Not on a handle outside the multi.
            assert!(e.enter(EasyCall::Perform, None).is_ok());
        });
        drop(entry);
        assert!(!m.busy());
        let e = EasyStack::default();
        assert!(e.enter(EasyCall::Perform, Some(&m)).is_ok());
    }

    /// The event callbacks refuse a pause; a notification lets the calls
    /// api.c allows it in.
    #[test]
    fn knows_the_callback_kinds() {
        let m = MultiStack::default();
        let _perform = m.enter(MultiCall::Perform).unwrap();
        m.lend(Frame::Event(NonNull::dangling()), || {
            let e = EasyStack::default();
            assert_eq!(e.enter(EasyCall::Pause, Some(&m)).err(), Some(Recursive));
            assert!(e.enter(EasyCall::Getinfo, Some(&m)).is_ok());
            assert_eq!(m.enter(MultiCall::AddHandle).err(), Some(Recursive));
        });
        m.lend(Frame::Notify(NonNull::dangling()), || {
            assert!(m.enter(MultiCall::AddHandle).is_ok());
            assert_eq!(m.enter(MultiCall::Perform).err(), Some(Recursive));
            let e = EasyStack::default();
            assert!(e.enter(EasyCall::Pause, Some(&m)).is_ok());
        });
        assert!(!m.in_event());
        // Out of the notification, an add may not recurse again.
        m.lend(transfer_frame(), || {
            assert_eq!(m.enter(MultiCall::AddHandle).err(), Some(Recursive));
        });
    }

    /// Calls nest no deeper than C lets them.
    #[test]
    fn limits_the_depth() {
        let m = MultiStack::default();
        let _perform = m.enter(MultiCall::Perform).unwrap();
        m.lend(transfer_frame(), || {
            let entries: Vec<_> = (2..MULTI_MAX_DEPTH)
                .map(|_| m.enter(MultiCall::InfoRead).unwrap())
                .collect();
            assert_eq!(m.enter(MultiCall::InfoRead).err(), Some(Recursive));
            drop(entries);
            assert!(m.enter(MultiCall::InfoRead).is_ok());
        });
        let e = EasyStack::default();
        let entries: Vec<_> = (0..EASY_MAX_DEPTH)
            .map(|_| e.enter(EasyCall::Getinfo, None).unwrap())
            .collect();
        assert_eq!(e.enter(EasyCall::Getinfo, None).err(), Some(Recursive));
        drop(entries);
        assert!(e.enter(EasyCall::Getinfo, None).is_ok());
    }
}
