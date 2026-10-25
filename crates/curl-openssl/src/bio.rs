//! The BIO OpenSSL reads and writes a connection through, and its trace
//! of the records (`lib/vtls/openssl.c`'s `ossl_bio_cf_*` and
//! `ossl_trace`): each read and write goes to the layers below the TLS
//! layer, through the `TlsIo` of the one call into the library under
//! way.
//!
//! For the length of each call into the library that may read or write
//! (`call`), the BIO's data points at a `Slot` on the caller's stack: the
//! call's `TlsIo`, the session's flags the callbacks keep, what the last
//! read or write below came to, and the trust store to set up before the
//! peer's first bytes. The pointer is set before the call and cleared
//! after it, the callbacks run only inside that call, on its thread, and
//! nothing else holds the slot while they do.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr::{self, NonNull};

use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::tls::{KeyLog, TlsIo, TlsWay};
use openssl_sys::{BIO, BIO_METHOD, SSL, SSL_SESSION};

use crate::ffi;
use crate::text;

/// What a session's BIO notes across calls (`ssl_connect_data`'s bits).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Flags {
    /// Bytes were given to the library since its last read gave out
    /// nothing (`input_pending`): a read may give some now.
    pub(crate) input_pending: bool,
    /// The connection below ended (`peer_closed`).
    pub(crate) peer_closed: bool,
    /// The trust store is set up (`x509_store_setup`).
    pub(crate) store_ready: bool,
}

/// What the last read or write below came to (`io_result`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Below {
    Ok,
    /// It would have blocked (`CURLE_AGAIN`).
    Again,
    /// The socket failed, with this error number (0 if it had none).
    Failed(i32),
    /// The trust store could not be set up.
    Store(ErrorKind),
}

/// Sets the trust store up, at the first read, with the call's `TlsIo`.
pub(crate) type StoreSetup<'s> = &'s mut dyn FnMut(&mut TlsIo<'_>) -> Result<(), ErrorKind>;

/// What the BIO's callbacks reach during one call into the library.
pub(crate) struct Slot<'s, 'a> {
    pub(crate) io: &'s mut TlsIo<'a>,
    pub(crate) flags: &'s mut Flags,
    pub(crate) below: Below,
    /// Sets the trust store up, unless `flags.store_ready`.
    pub(crate) store: StoreSetup<'s>,
    /// Where the secrets the library tells of are logged, if anywhere.
    pub(crate) keylog: Option<&'s KeyLog>,
}

/// The BIO method (`ossl_bio_cf_method_create`), one per session, as C
/// makes one per connection.
pub(crate) struct Method(NonNull<BIO_METHOD>);

// SAFETY: the method is a table of function pointers the library only
// reads once made; it is freed once, by its owner.
unsafe impl Send for Method {}

impl Method {
    /// A method of this module's callbacks, or none if the library
    /// could not make one (out of memory).
    pub(crate) fn new() -> Option<Method> {
        // SAFETY: a type of the library's own and a name it keeps a
        // pointer to: a static C string.
        let m = unsafe { openssl_sys::BIO_meth_new(ffi::BIO_TYPE_MEM, c"OpenSSL CF BIO".as_ptr()) };
        let m = Method(NonNull::new(m)?);
        let p = m.0.as_ptr();
        // SAFETY: `p` is a method just made, and each callback has
        // the signature the library calls it with.
        unsafe { openssl_sys::BIO_meth_set_write__fixed_rust(p, Some(out_write)) };
        // SAFETY: as above.
        unsafe { openssl_sys::BIO_meth_set_read__fixed_rust(p, Some(in_read)) };
        // SAFETY: as above.
        unsafe { openssl_sys::BIO_meth_set_ctrl__fixed_rust(p, Some(ctrl)) };
        // SAFETY: as above.
        unsafe { openssl_sys::BIO_meth_set_create__fixed_rust(p, Some(create)) };
        // SAFETY: as above.
        unsafe { openssl_sys::BIO_meth_set_destroy__fixed_rust(p, Some(destroy)) };
        Some(m)
    }

    /// A BIO of this method, or none if the library could not make one.
    /// The caller hands it to an `SSL`, which then owns it.
    pub(crate) fn bio(&self) -> Option<NonNull<BIO>> {
        // SAFETY: the method is alive as long as `self`; the BIO made
        // with it is only used while its SSL is, which the session drops
        // before the method.
        NonNull::new(unsafe { openssl_sys::BIO_new(self.0.as_ptr()) })
    }
}

impl Drop for Method {
    fn drop(&mut self) {
        // SAFETY: made by `BIO_meth_new`, freed once, after every BIO
        // made with it (the session frees its SSL first).
        unsafe { openssl_sys::BIO_meth_free(self.0.as_ptr()) };
    }
}

/// Run `op`, a call into the library on `ssl`, with `slot` as what its
/// BIO and its trace reach: set before, cleared after.
///
/// `ssl`'s read BIO must be one of a `Method`'s, its data unset outside
/// `call`; `op` must not reach `slot` itself.
pub(crate) fn call<R>(
    ssl: NonNull<SSL>,
    slot: &mut Slot<'_, '_>,
    op: impl FnOnce(*mut SSL) -> R,
) -> R {
    // SAFETY: the session's SSL, alive while the session is; its read
    // BIO is its write BIO, one of a `Method`'s.
    let bio = unsafe { openssl_sys::SSL_get_rbio(ssl.as_ptr()) };
    assert!(!bio.is_null(), "a session's SSL has its BIO");
    let p: *mut Slot<'_, '_> = slot;
    // SAFETY: the slot outlives the call; the callbacks read it only
    // during `op`, and nothing else uses it until `op` returns.
    unsafe { openssl_sys::BIO_set_data(bio, p.cast()) };
    let r = op(ssl.as_ptr());
    // SAFETY: as above; no callback runs after `op` returns.
    unsafe { openssl_sys::BIO_set_data(bio, ptr::null_mut()) };
    r
}

/// The slot of the call under way, from its BIO's data.
///
/// # Safety
/// Only from a callback of the library during `call`: the data is then a
/// live `Slot` no one else is using.
unsafe fn slot_of<'r>(bio: *mut BIO) -> Option<&'r mut Slot<'r, 'r>> {
    // SAFETY: `bio` is the BIO the library calls back for.
    let data = unsafe { openssl_sys::BIO_get_data(bio) };
    // SAFETY: as the caller says: a `Slot` that `call` set, used by this
    // callback alone until it returns; the lifetimes are the callback's,
    // shorter than the slot's, and nothing is stored in it.
    unsafe { data.cast::<Slot<'r, 'r>>().as_mut() }
}

/// The slot of the call under way on `ssl`, from its read BIO's data.
///
/// # Safety
/// As `slot_of`: only from a callback of the library on `ssl`, whose read
/// BIO is a `Method`'s.
unsafe fn slot_of_ssl<'r>(ssl: *const SSL) -> Option<&'r mut Slot<'r, 'r>> {
    // SAFETY: the SSL the library calls back for.
    let bio = unsafe { openssl_sys::SSL_get_rbio(ssl) };
    if bio.is_null() {
        return None;
    }
    // SAFETY: as the caller says; outside a call the data is unset.
    unsafe { slot_of(bio) }
}

/// The library tells of a secret, a line of the key log's
/// (`ossl_keylog_callback`).
pub(crate) unsafe extern "C" fn keylog_line(ssl: *const SSL, line: *const c_char) {
    if line.is_null() {
        return;
    }
    // SAFETY: the library calls back during a call on `ssl`.
    let Some(slot) = (unsafe { slot_of_ssl(ssl) }) else {
        return;
    };
    if let Some(log) = slot.keylog {
        // SAFETY: the library hands a C string, alive for the callback.
        log.write_line(unsafe { CStr::from_ptr(line) }.to_bytes());
    }
}

/// The peer gave a session to resume (`ossl_new_session_cb`): kept in the
/// transfer's cache as the library's DER of it. The library keeps its
/// own (0: not taken).
pub(crate) unsafe extern "C" fn new_session(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int {
    // SAFETY: the library calls back during a call on `ssl`.
    let Some(slot) = (unsafe { slot_of_ssl(ssl) }) else {
        return 0;
    };
    if !slot.io.caches_sessions() {
        return 0;
    }
    // SAFETY: the SSL and the session the library calls back with, alive
    // for the callback.
    let ticket = unsafe { crate::ssl::ticket_of(ssl, session, slot.io) };
    // Out of memory, the session is not kept, as C goes on without it.
    if let Ok(ticket) = ticket {
        slot.io.keep_session(ticket);
    }
    0
}

/// The library writes `blen` bytes from `buf` (`ossl_bio_cf_out_write`).
unsafe extern "C" fn out_write(bio: *mut BIO, buf: *const c_char, blen: c_int) -> c_int {
    let Ok(len) = usize::try_from(blen) else {
        return 0;
    };
    // SAFETY: called back during `call`.
    let slot = unsafe { slot_of(bio) }.expect("the BIO writes only during a call");
    // A write of nothing need not point anywhere.
    let bytes = if len == 0 {
        &[][..]
    } else {
        // SAFETY: the library hands `blen` bytes at `buf`, alive and not
        // written to for the callback's length.
        unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), len) }
    };
    let got = if bytes.is_empty() {
        Ok(Sent::WouldBlock)
    } else {
        slot.io.send(bytes)
    };
    let (code, n) = match &got {
        Ok(Sent::Bytes(n)) => (0, n.get()),
        Ok(Sent::WouldBlock) => (AGAIN, 0),
        Err(_) => (ErrorKind::SendError.number(), 0),
    };
    slot.io.trace(format_args!(
        "ossl_bio_cf_out_write(len={blen}) -> {code}, {n}"
    ));
    // SAFETY: `bio` is the library's.
    unsafe { openssl_sys::BIO_clear_retry_flags(bio) };
    match got {
        Ok(Sent::Bytes(n)) => {
            slot.below = Below::Ok;
            c_int::try_from(n.get()).expect("no more than asked")
        }
        Ok(Sent::WouldBlock) => {
            slot.below = Below::Again;
            // SAFETY: as above.
            unsafe { openssl_sys::BIO_set_retry_write(bio) };
            -1
        }
        Err(e) => {
            slot.below = Below::Failed(e.raw_os_error().unwrap_or(0));
            -1
        }
    }
}

/// `CURLE_AGAIN`, as the trace numbers a read or write that would block.
pub(crate) const AGAIN: u16 = 81;

/// The library reads up to `blen` bytes into `buf` (`ossl_bio_cf_in_read`).
/// Before the peer's first bytes reach it, the trust store is set up, so
/// the ClientHello goes out first.
unsafe extern "C" fn in_read(bio: *mut BIO, buf: *mut c_char, blen: c_int) -> c_int {
    if buf.is_null() {
        return 0;
    }
    let Ok(len) = usize::try_from(blen) else {
        return 0;
    };
    // SAFETY: called back during `call`.
    let slot = unsafe { slot_of(bio) }.expect("the BIO reads only during a call");
    let got = if len == 0 {
        // Nothing asked: nothing read, and not the end.
        Ok(Recv::WouldBlock)
    } else {
        // SAFETY: the library hands `blen` bytes of room at `buf`.
        let room = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), len) };
        slot.io.recv(room)
    };
    let (code, n) = match &got {
        Ok(Recv::Data(n)) => (0, n.get()),
        Ok(Recv::Eof) => (0, 0),
        Ok(Recv::WouldBlock) => (AGAIN, 0),
        Err(_) => (ErrorKind::RecvError.number(), 0),
    };
    slot.io.trace(format_args!(
        "ossl_bio_cf_in_read(len={blen}) -> {code}, {n}"
    ));
    // SAFETY: `bio` is the library's.
    unsafe { openssl_sys::BIO_clear_retry_flags(bio) };
    let read = match got {
        Ok(Recv::Data(n)) => {
            slot.below = Below::Ok;
            slot.flags.input_pending = true;
            c_int::try_from(n.get()).expect("no more than asked")
        }
        Ok(Recv::Eof) => {
            slot.below = Below::Ok;
            slot.flags.input_pending = true;
            slot.flags.peer_closed = true;
            0
        }
        Ok(Recv::WouldBlock) => {
            slot.below = Below::Again;
            // SAFETY: as above.
            unsafe { openssl_sys::BIO_set_retry_read(bio) };
            -1
        }
        Err(e) => {
            slot.below = Below::Failed(e.raw_os_error().unwrap_or(0));
            -1
        }
    };
    if !slot.flags.store_ready {
        if let Err(kind) = (slot.store)(slot.io) {
            // SAFETY: as above.
            unsafe { openssl_sys::BIO_clear_retry_flags(bio) };
            slot.below = Below::Store(kind);
            return -1;
        }
        slot.flags.store_ready = true;
    }
    read
}

/// `BIO_CTRL_GET_CLOSE`, `BIO_CTRL_SET_CLOSE`, `BIO_CTRL_DUP` (`bio.h`).
const BIO_CTRL_GET_CLOSE: c_int = 8;
const BIO_CTRL_SET_CLOSE: c_int = 9;
const BIO_CTRL_DUP: c_int = 12;

/// `ossl_bio_cf_ctrl`.
unsafe extern "C" fn ctrl(bio: *mut BIO, cmd: c_int, num: c_long, _ptr: *mut c_void) -> c_long {
    match cmd {
        // SAFETY: `bio` is the library's.
        BIO_CTRL_GET_CLOSE => c_long::from(unsafe { ffi::BIO_get_shutdown(bio) }),
        BIO_CTRL_SET_CLOSE => {
            // SAFETY: as above. C truncates the number as this does.
            unsafe { ffi::BIO_set_shutdown(bio, num as c_int) };
            1
        }
        openssl_sys::BIO_CTRL_FLUSH | BIO_CTRL_DUP => 1,
        openssl_sys::BIO_CTRL_EOF => {
            // SAFETY: the library asks this only during a call; outside
            // one there is nothing to say.
            match unsafe { slot_of(bio) } {
                Some(slot) => c_long::from(slot.flags.peer_closed),
                None => 0,
            }
        }
        _ => 0,
    }
}

/// `ossl_bio_cf_create`.
unsafe extern "C" fn create(bio: *mut BIO) -> c_int {
    // SAFETY: a BIO the library is making, not yet used.
    unsafe { ffi::BIO_set_shutdown(bio, 1) };
    // SAFETY: as above.
    unsafe { openssl_sys::BIO_set_init(bio, 1) };
    // SAFETY: as above; the data is set only for the length of a call.
    unsafe { openssl_sys::BIO_set_data(bio, ptr::null_mut()) };
    1
}

/// `ossl_bio_cf_destroy`.
unsafe extern "C" fn destroy(bio: *mut BIO) -> c_int {
    c_int::from(!bio.is_null())
}

/// The library's trace of a record it sent or read (`ossl_trace`): its
/// name as a line of text, then its bytes as SSL data, for a transfer
/// with a debug handler.
pub(crate) unsafe extern "C" fn trace(
    direction: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    ssl: *mut SSL,
    _arg: *mut c_void,
) {
    // SAFETY: the SSL the library calls back for, whose read BIO is a
    // `Method`'s.
    let bio = unsafe { openssl_sys::SSL_get_rbio(ssl) };
    if bio.is_null() {
        return;
    }
    // SAFETY: the library traces only during a call into it on `ssl`;
    // outside one the BIO has no slot and nothing is traced.
    let Some(slot) = (unsafe { slot_of(bio) }) else {
        return;
    };
    if !slot.io.debugs() || !(direction == 0 || direction == 1) {
        return;
    }
    let bytes = if len == 0 || buf.is_null() {
        &[][..]
    } else {
        // SAFETY: the library hands `len` bytes at `buf`, alive for the
        // callback's length.
        unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), len) }
    };
    let way = if direction == 1 {
        TlsWay::Out
    } else {
        TlsWay::In
    };
    if version != 0 && content_type != text::HEADER && content_type != text::INNER_CONTENT_TYPE {
        let major = version >> 8;
        let record = if major == 3 && content_type != 0 {
            text::record_type(content_type)
        } else {
            ""
        };
        let (name, msg_type) = match content_type {
            text::CHANGE_CIPHER_SPEC if !bytes.is_empty() => {
                ("Change cipher spec", c_int::from(bytes[0]))
            }
            text::ALERT if bytes.len() >= 2 => {
                let t = (c_int::from(bytes[0]) << 8) + c_int::from(bytes[1]);
                // SAFETY: a function of no state, for any value.
                let desc = unsafe { ffi::SSL_alert_desc_string_long(t) };
                // SAFETY: the library's static text, never null.
                let desc = unsafe { CStr::from_ptr(desc) };
                (desc.to_str().unwrap_or("unknown"), t)
            }
            text::CHANGE_CIPHER_SPEC | text::ALERT => ("Truncated message", 0),
            _ if !bytes.is_empty() => {
                let t = c_int::from(bytes[0]);
                (text::message_type(major, t), t)
            }
            _ => ("Truncated message", 0),
        };
        let dir = if direction == 1 { "OUT" } else { "IN" };
        let version = text::Version(version);
        slot.io.info(format_args!(
            "{version} ({dir}), {record}, {name} ({msg_type}):"
        ));
    }
    slot.io.record(way, bytes);
}
