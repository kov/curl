//! What an application gives a transfer to call: where its output goes.
//!
//! Each handler is shared, as C's callback and its userdata pointer are: a
//! copy of the `Easy` (`curl_easy_duphandle`) calls the same one. So a
//! handler is called through `&self` and keeps its state in cells.

use std::fmt;
use std::ops::Deref;

use curl_alloc::{OutOfMemory, TryRc, try_box};

use crate::multi::TransferCx;

/// What a write or header handler did with what it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Write {
    Accepted,
    /// Stop delivering; what was given is delivered again once unpaused
    /// (`CURL_WRITEFUNC_PAUSE`).
    Pause,
    /// The transfer fails with a write error.
    Fail,
}

/// Where a header line came from (`CURLH_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderOrigin {
    /// The response's head.
    Header,
    /// After the body (`CURLH_TRAILER`).
    Trailer,
    /// A proxy's answer to CONNECT (`CURLH_CONNECT`).
    Connect,
    /// An informational response, 1xx (`CURLH_1XX`).
    Interim,
}

/// Takes the body (`CURLOPT_WRITEFUNCTION`).
pub trait WriteHandler {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write;
}

/// Takes each header line whole, with its line ending
/// (`CURLOPT_HEADERFUNCTION`).
pub trait HeaderHandler {
    fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], origin: HeaderOrigin) -> Write;
}

/// A handler as a transfer holds it: shared by every copy of the `Easy`.
pub struct Handler<T: ?Sized>(TryRc<Box<T>>);

impl<T: ?Sized> Handler<T> {
    /// A handler already boxed; `Handler::write` and the like box one.
    pub fn new(handler: Box<T>) -> Result<Handler<T>, OutOfMemory> {
        Ok(Handler(TryRc::try_new(handler)?))
    }

    /// Whether `a` and `b` are the same handler.
    pub fn ptr_eq(a: &Handler<T>, b: &Handler<T>) -> bool {
        TryRc::ptr_eq(&a.0, &b.0)
    }
}

impl Handler<dyn WriteHandler> {
    pub fn write(handler: impl WriteHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn HeaderHandler> {
    pub fn header(handler: impl HeaderHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl<T: ?Sized> Clone for Handler<T> {
    fn clone(&self) -> Handler<T> {
        Handler(self.0.clone())
    }
}

impl<T: ?Sized> Deref for Handler<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> fmt::Debug for Handler<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Handler")
    }
}
