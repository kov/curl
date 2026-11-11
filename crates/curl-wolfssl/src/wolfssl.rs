//! The library's calls, as `library.rs`'s traits ask them: the context,
//! the session's object, the BIO it reads and writes the connection
//! through, the store of certificates, and the callbacks that reach the
//! call under way through the BIO; and a QUIC session's calls driven by
//! the QUIC library, whose crypto has the session's application data.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};
use curl_core::error::ErrorKind;
use curl_core::tls::{DriveCall, TlsCx, TlsKind, TlsNative};

use crate::library::{
    self, AlpnGot, Call, FileType, Moved, NewSession, NoCtx, PeerCert, Rc, Resume, Tls12Keys, Words,
};
use crate::sys;

/// The library itself.
#[derive(Debug)]
pub(crate) struct Real;

/// The library, for the sessions to call.
pub(crate) static WOLFSSL: Real = Real;

/// The bytes of a C string the library keeps, to its zero; none for
/// null.
///
/// # Safety
/// `p` is null or a C string alive for `'a`.
unsafe fn c_text<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: as the caller says.
    let p = unsafe { p.as_ref() }?;
    // SAFETY: as the caller says: a C string from `p`.
    Some(unsafe { CStr::from_ptr(p) }.to_bytes())
}

/// The library's version, as it says it (`wolfSSL_lib_version`).
pub(crate) fn version() -> &'static [u8] {
    // SAFETY: no requirement; a static string.
    let v = unsafe { sys::wolfSSL_lib_version() };
    // SAFETY: the library's static string.
    unsafe { c_text(v) }.unwrap_or_default()
}

/// Initialise the library (`wolfSSL_Init`): whether it could.
pub(crate) fn init() -> bool {
    // SAFETY: no requirement; balanced by `cleanup`.
    unsafe { sys::wolfSSL_Init() == sys::WOLFSSL_SUCCESS }
}

/// Let the library go (`wolfSSL_Cleanup`).
pub(crate) fn cleanup() {
    // SAFETY: after `init`; the library frees what it made itself, and
    // a session alive keeps nothing of it that this frees.
    unsafe { sys::wolfSSL_Cleanup() };
}

/// The BIO method of the sessions' connections (`wssl_bio_cf_init_methods`):
/// writes, reads and controls through the call under way.
#[derive(Debug)]
pub(crate) struct Method(NonNull<sys::WOLFSSL_BIO_METHOD>);

// SAFETY: the method is a table the library only reads once it is made,
// from any thread.
unsafe impl Send for Method {}
// SAFETY: as above.
unsafe impl Sync for Method {}

impl Method {
    /// The method made, its callbacks set; none out of memory.
    pub(crate) fn new() -> Option<Method> {
        // SAFETY: a static name, which the method points at.
        let m = unsafe {
            sys::wolfSSL_BIO_meth_new(sys::WOLFSSL_BIO_MEMORY, c"wolfSSL CF BIO".as_ptr())
        };
        let m = Method(NonNull::new(m)?);
        // SAFETY: the method just made, and callbacks of its types.
        unsafe { sys::wolfSSL_BIO_meth_set_write(m.0.as_ptr(), Some(bio_write)) };
        // SAFETY: as above.
        unsafe { sys::wolfSSL_BIO_meth_set_read(m.0.as_ptr(), Some(bio_read)) };
        // SAFETY: as above.
        unsafe { sys::wolfSSL_BIO_meth_set_ctrl(m.0.as_ptr(), Some(bio_ctrl)) };
        // SAFETY: as above.
        unsafe { sys::wolfSSL_BIO_meth_set_create(m.0.as_ptr(), Some(bio_create)) };
        Some(m)
    }
}

impl Drop for Method {
    fn drop(&mut self) {
        // SAFETY: made by `new`, freed once, after every BIO of it: each
        // session's object holds the method as long as it lives.
        unsafe { sys::wolfSSL_BIO_meth_free(self.0.as_ptr()) };
    }
}

/// A counted reference to a store of certificates.
#[derive(Debug)]
pub(crate) struct Store(NonNull<sys::WOLFSSL_X509_STORE>);

// SAFETY: the library counts a store's references atomically and locks
// it as it is used; this crate changes a store only as a context it was
// given to loads it, before the multi shares it.
unsafe impl Send for Store {}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: a reference this crate holds, given back once.
        unsafe { sys::wolfSSL_X509_STORE_free(self.0.as_ptr()) };
    }
}

impl Store {
    /// Another reference to `store`, if the library could count it.
    fn up(store: NonNull<sys::WOLFSSL_X509_STORE>) -> Option<Store> {
        // SAFETY: a store alive while this runs: a context's, or one this
        // crate holds a reference to.
        (unsafe { sys::wolfSSL_X509_STORE_up_ref(store.as_ptr()) } == sys::WOLFSSL_SUCCESS)
            .then_some(Store(store))
    }
}

impl library::Store for Store {
    fn another(&self) -> Option<Store> {
        Store::up(self.0)
    }
}

impl library::Wolfssl for Real {
    type Ctx = Ctx;
    type Store = Store;
    type Method = Method;

    fn ctx(&self, method: &TryArc<Method>) -> Result<Ctx, NoCtx> {
        // SAFETY: no requirement; the library's static method table.
        let m = unsafe { sys::wolfTLS_client_method() };
        if m.is_null() {
            return Err(NoCtx::Method);
        }
        // SAFETY: the method just had, which the context takes over.
        let ctx = unsafe { sys::wolfSSL_CTX_new(m) };
        let ctx = NonNull::new(ctx).ok_or(NoCtx::Context)?;
        Ok(Ctx {
            ctx,
            method: method.clone(),
        })
    }

    fn new_store(&self) -> Option<Store> {
        // SAFETY: no requirement.
        NonNull::new(unsafe { sys::wolfSSL_X509_STORE_new() }).map(Store)
    }

    fn strerror(&self, error: u32) -> Words {
        let mut buf = [0u8; 256];
        // SAFETY: a buffer of its length, which the library writes a C
        // string into.
        unsafe {
            sys::wolfSSL_ERR_error_string_n(
                error.into(),
                buf.as_mut_ptr().cast(),
                buf.len() as core::ffi::c_ulong,
            );
        };
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Words::new(&buf[..len], error)
    }

    fn cipher(&self, index: usize) -> Option<&'static [u8]> {
        let i = c_int::try_from(index).ok()?;
        // SAFETY: any number; a name of the library's static table, or
        // null past its end.
        let p = unsafe { sys::wolfSSL_get_cipher_list(i) };
        // SAFETY: as above.
        unsafe { c_text(p) }
    }
}

/// A context, freed as it goes; the session objects made from it hold
/// references of their own to it.
pub(crate) struct Ctx {
    ctx: NonNull<sys::WOLFSSL_CTX>,
    method: TryArc<Method>,
}

// SAFETY: the context is changed only through `&mut self`, from one thread
// at a time; the library lets a context move between threads, and counts
// its references atomically.
unsafe impl Send for Ctx {}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: made by `ctx`, this reference given back once; a
        // session object made from it holds its own.
        unsafe { sys::wolfSSL_CTX_free(self.ctx.as_ptr()) };
    }
}

impl Ctx {
    fn p(&self) -> *mut sys::WOLFSSL_CTX {
        self.ctx.as_ptr()
    }
}

/// `kind`, as the library numbers it; -1 for one it does not know, as C
/// hands it.
fn format(kind: FileType) -> c_int {
    match kind {
        FileType::Pem => sys::WOLFSSL_FILETYPE_PEM,
        FileType::Asn1 => sys::WOLFSSL_FILETYPE_ASN1,
        FileType::Unknown => -1,
    }
}

/// A length, as the library's `long` takes it: past it, the most it
/// takes, as C's cast cuts it.
fn long_len(bytes: &[u8]) -> c_long {
    c_long::try_from(bytes.len()).unwrap_or(c_long::MAX)
}

impl library::Ctx for Ctx {
    type Store = Store;
    type Ssl = Ssl;

    fn min_version(&mut self, version: u16) -> bool {
        // SAFETY: the context.
        let rc = unsafe { sys::wolfSSL_CTX_set_min_proto_version(self.p(), version.into()) };
        rc == sys::WOLFSSL_SUCCESS
    }

    fn max_version(&mut self, version: u16) -> bool {
        // SAFETY: the context.
        let rc = unsafe { sys::wolfSSL_CTX_set_max_proto_version(self.p(), version.into()) };
        rc == sys::WOLFSSL_SUCCESS
    }

    fn cipher_list(&mut self, list: Option<&CStr>) -> bool {
        let p = list.map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: the context, and a C string or null, which the library
        // copies what it needs of.
        unsafe { sys::wolfSSL_CTX_set_cipher_list(self.p(), p) != 0 }
    }

    fn groups(&mut self, list: &CStr) -> bool {
        // SAFETY: the context, and a C string the library reads.
        unsafe { sys::wolfSSL_CTX_set1_groups_list(self.p(), list.as_ptr()) != 0 }
    }

    fn cert_chain_buffer(&mut self, pem: &[u8]) -> Rc {
        // SAFETY: the context, and bytes the library copies.
        unsafe {
            sys::wolfSSL_CTX_use_certificate_chain_buffer(self.p(), pem.as_ptr(), long_len(pem))
        }
    }

    fn cert_chain_file(&mut self, file: &CStr) -> Rc {
        // SAFETY: the context, and a C string.
        unsafe { sys::wolfSSL_CTX_use_certificate_chain_file(self.p(), file.as_ptr()) }
    }

    fn cert_buffer(&mut self, cert: &[u8], kind: FileType) -> Rc {
        // SAFETY: the context, and bytes the library copies.
        unsafe {
            sys::wolfSSL_CTX_use_certificate_buffer(
                self.p(),
                cert.as_ptr(),
                long_len(cert),
                format(kind),
            )
        }
    }

    fn cert_file(&mut self, file: &CStr, kind: FileType) -> Rc {
        // SAFETY: the context, and a C string.
        unsafe { sys::wolfSSL_CTX_use_certificate_file(self.p(), file.as_ptr(), format(kind)) }
    }

    fn key_buffer(&mut self, key: &[u8], kind: FileType) -> Rc {
        // SAFETY: the context, and bytes the library copies.
        unsafe {
            sys::wolfSSL_CTX_use_PrivateKey_buffer(
                self.p(),
                key.as_ptr(),
                long_len(key),
                format(kind),
            )
        }
    }

    fn key_file(&mut self, file: &CStr, kind: FileType) -> Rc {
        // SAFETY: the context, and a C string.
        unsafe { sys::wolfSSL_CTX_use_PrivateKey_file(self.p(), file.as_ptr(), format(kind)) }
    }

    fn verify(&mut self, peer: bool) {
        let mode = if peer {
            sys::WOLFSSL_VERIFY_PEER
        } else {
            sys::WOLFSSL_VERIFY_NONE
        };
        // SAFETY: the context, and no callback.
        unsafe { sys::wolfSSL_CTX_set_verify(self.p(), mode, None) };
    }

    fn sni(&mut self, name: &[u8]) -> bool {
        let Ok(len) = u16::try_from(name.len()) else {
            return false;
        };
        // SAFETY: the context, and `len` bytes the library copies.
        unsafe {
            sys::wolfSSL_CTX_UseSNI(
                self.p(),
                sys::WOLFSSL_SNI_HOST_NAME,
                name.as_ptr().cast(),
                len,
            ) == 1
        }
    }

    fn tell_sessions(&mut self) {
        // SAFETY: the context, and a callback of its type, which reaches
        // only the call under way through the session's BIO.
        unsafe { sys::wolfSSL_CTX_sess_set_new_cb(self.p(), Some(new_session)) };
    }

    fn system_ca(&mut self) -> bool {
        // SAFETY: the context.
        unsafe { sys::wolfSSL_CTX_load_system_CA_certs(self.p()) == sys::WOLFSSL_SUCCESS }
    }

    fn ca_buffer(&mut self, pem: &[u8]) -> bool {
        // SAFETY: the context, and bytes the library copies.
        unsafe {
            sys::wolfSSL_CTX_load_verify_buffer(
                self.p(),
                pem.as_ptr(),
                long_len(pem),
                sys::WOLFSSL_FILETYPE_PEM,
            ) == sys::WOLFSSL_SUCCESS
        }
    }

    fn ca_locations(&mut self, file: Option<&CStr>, path: Option<&CStr>) -> bool {
        let f = file.map_or(ptr::null(), CStr::as_ptr);
        let p = path.map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: the context, and C strings or null.
        unsafe {
            sys::wolfSSL_CTX_load_verify_locations_ex(
                self.p(),
                f,
                p,
                sys::WOLFSSL_LOAD_FLAG_IGNORE_ERR,
            ) == sys::WOLFSSL_SUCCESS
        }
    }

    fn uses_store(&self, store: &Store) -> bool {
        // SAFETY: the context.
        unsafe { sys::wolfSSL_CTX_get_cert_store(self.p()) == store.0.as_ptr() }
    }

    fn store(&self) -> Option<Store> {
        // SAFETY: the context.
        let store = unsafe { sys::wolfSSL_CTX_get_cert_store(self.p()) };
        Store::up(NonNull::new(store)?)
    }

    fn set_store(&mut self, store: Store) {
        let store = core::mem::ManuallyDrop::new(store);
        // SAFETY: the context, and a reference this crate holds, which
        // the context now owns.
        unsafe { sys::wolfSSL_CTX_set_cert_store(self.p(), store.0.as_ptr()) };
    }

    fn native(&self, ssl: Option<&Ssl>) -> TlsNative {
        let ssl = ssl.map(|s| s.ssl.cast());
        // SAFETY: a `WOLFSSL_CTX` and a `WOLFSSL` wolfSSL made, the
        // library `WolfSsl` names, freed as they drop, which the
        // backend's session holds while its connection lives.
        unsafe { TlsNative::new(TlsKind::WolfSsl, self.ctx.cast(), ssl) }
    }

    fn ssl(&mut self) -> Result<Ssl, OutOfMemory> {
        let slot = try_box(Slot(Cell::new(ptr::null_mut())))?;
        // SAFETY: the context, which the session object takes a reference
        // to.
        let ssl = unsafe { sys::wolfSSL_new(self.p()) };
        let ssl = NonNull::new(ssl).ok_or(OutOfMemory)?;
        let slot = NonNull::from(Box::leak(slot));
        // The application data is left alone: over QUIC it is ngtcp2's
        // crypto's, and the callbacks find the slot through the BIO.
        Ok(Ssl {
            ssl,
            slot,
            method: self.method.clone(),
        })
    }
}

/// What the callbacks of the call under way reach: the `Call`, or null
/// between calls.
struct Slot(Cell<*mut c_void>);

/// A session's object, freed as it goes, with its BIO.
pub(crate) struct Ssl {
    ssl: NonNull<sys::WOLFSSL>,
    slot: NonNull<Slot>,
    /// The method its BIO is of, which must outlive it.
    method: TryArc<Method>,
}

// SAFETY: the object is changed only through `&mut self`, from one thread
// at a time, and the library lets it move between threads.
unsafe impl Send for Ssl {}

impl Drop for Ssl {
    fn drop(&mut self) {
        // SAFETY: made by `Ctx::ssl`, freed once, its BIO with it; no call
        // is under way, so no callback reaches the slot after.
        unsafe { sys::wolfSSL_free(self.ssl.as_ptr()) };
        // SAFETY: made by `Box::leak` in `Ctx::ssl`, freed once; the
        // object that pointed at it is gone.
        drop(unsafe { Box::from_raw(self.slot.as_ptr()) });
    }
}

impl Ssl {
    fn p(&self) -> *mut sys::WOLFSSL {
        self.ssl.as_ptr()
    }

    /// Run `op`, a call on the session that may read or write, with
    /// `call` what its callbacks reach: set before, cleared after; the
    /// thread's errors cleared first, as C clears them before each such
    /// call.
    fn with_call<R>(
        &mut self,
        call: &mut Call<'_, '_>,
        op: impl FnOnce(*mut sys::WOLFSSL) -> R,
    ) -> R {
        let p: *mut Call<'_, '_> = call;
        // SAFETY: the slot, alive as long as the object.
        let slot = unsafe { self.slot.as_ref() };
        slot.0.set(p.cast());
        // SAFETY: no requirement: the thread's own queue.
        unsafe { sys::wolfSSL_ERR_clear_error() };
        let r = op(self.p());
        slot.0.set(ptr::null_mut());
        r
    }

    /// The peer's certificate while `f` runs, freed after.
    fn with_peer<R>(&self, f: impl FnOnce(NonNull<sys::WOLFSSL_X509>) -> R) -> Option<R> {
        // SAFETY: the session object; a certificate of its own.
        let x = NonNull::new(unsafe { sys::wolfSSL_get_peer_certificate(self.p()) })?;
        let r = f(x);
        // SAFETY: the certificate just had, freed once.
        unsafe { sys::wolfSSL_X509_free(x.as_ptr()) };
        Some(r)
    }
}

/// What a call into the QUIC library is lent while it drives a session:
/// the call its callbacks reach, and the session, each reached through
/// its pointer for the length of one method, as the session's callbacks
/// reach the call, never at the same time as they.
struct Driving<'d, 's, 'a> {
    call: *mut Call<'s, 'a>,
    ssl: *mut Ssl,
    check: &'d mut dyn FnMut(&mut Ssl, &mut TlsCx<'_>) -> Result<(), ErrorKind>,
}

impl DriveCall for Driving<'_, '_, '_> {
    fn handshake_done(&mut self) -> Result<(), ErrorKind> {
        // SAFETY: the call and the session outlive the QUIC library's
        // call, inside which alone this runs; the QUIC library tells of
        // the handshake's end outside any callback of wolfSSL's, so
        // nothing else reaches either while this does, and `drive`, which
        // the pointers came from, uses neither until the call returns.
        let call = unsafe { &mut *self.call };
        // SAFETY: as above.
        let ssl = unsafe { &mut *self.ssl };
        (self.check)(ssl, call.io.cx())
    }

    fn with_cx(&mut self, f: &mut dyn FnMut(&mut TlsCx<'_>)) {
        // SAFETY: as above: the QUIC library's callbacks, which alone
        // call this, run one at a time, and none of wolfSSL's callbacks,
        // which reach the call too, runs while one does.
        let call = unsafe { &mut *self.call };
        f(call.io.cx());
    }
}

/// The call under way, from the pointer the library hands a callback.
///
/// # Safety
/// Only from a callback of the library during `with_call`: the pointer is
/// the session's slot, which then holds a live `Call` no one else is
/// using, or null.
unsafe fn call_of<'r>(p: *mut c_void) -> Option<&'r mut Call<'r, 'r>> {
    // SAFETY: as the caller says: the slot lives as long as the object,
    // longer than the callback.
    let slot = unsafe { p.cast::<Slot>().as_ref() }?;
    // SAFETY: as the caller says; the lifetimes are the callback's,
    // shorter than the call's, and nothing is stored in it.
    unsafe { slot.0.get().cast::<Call<'r, 'r>>().as_mut() }
}

/// A BIO is made (`wssl_bio_cf_create`).
unsafe extern "C" fn bio_create(bio: *mut sys::WOLFSSL_BIO) -> c_int {
    // SAFETY: the BIO the library is making.
    unsafe { sys::wolfSSL_BIO_set_shutdown(bio, 1) };
    // SAFETY: as above.
    unsafe { sys::wolfSSL_BIO_set_data(bio, ptr::null_mut()) };
    1
}

/// The library asks the BIO of its state (`wssl_bio_cf_ctrl`).
unsafe extern "C" fn bio_ctrl(
    bio: *mut sys::WOLFSSL_BIO,
    cmd: c_int,
    num: c_long,
    _ptr: *mut c_void,
) -> c_long {
    match cmd {
        sys::WOLFSSL_BIO_CTRL_GET_CLOSE => {
            // SAFETY: the library's BIO.
            let shut = unsafe { sys::wolfSSL_BIO_get_shutdown(bio) };
            c_long::from(shut)
        }
        sys::WOLFSSL_BIO_CTRL_SET_CLOSE => {
            // SAFETY: the library's BIO; the number C casts.
            unsafe { sys::wolfSSL_BIO_set_shutdown(bio, num as c_int) };
            1
        }
        sys::WOLFSSL_BIO_CTRL_FLUSH | sys::WOLFSSL_BIO_CTRL_DUP => 1,
        sys::WOLFSSL_BIO_CTRL_EOF => {
            // SAFETY: the library's BIO, whose data is the slot.
            let data = unsafe { sys::wolfSSL_BIO_get_data(bio) };
            // SAFETY: called back during `with_call`, or with nothing
            // under way, which reads as not at the end.
            let call = unsafe { call_of(data) };
            c_long::from(call.is_some_and(|c| c.at_eof()))
        }
        _ => 0,
    }
}

/// The library writes `len` bytes from `buf` (`wssl_bio_cf_out_write`).
unsafe extern "C" fn bio_write(
    bio: *mut sys::WOLFSSL_BIO,
    buf: *const c_char,
    len: c_int,
) -> c_int {
    // SAFETY: the library's BIO, whose data is the slot.
    let data = unsafe { sys::wolfSSL_BIO_get_data(bio) };
    // SAFETY: called back during `with_call`.
    let Some(call) = (unsafe { call_of(data) }) else {
        return -1;
    };
    let len = usize::try_from(len).unwrap_or(0);
    let bytes = if len == 0 || buf.is_null() {
        &[][..]
    } else {
        // SAFETY: the library hands `len` bytes at `buf`, alive and not
        // written to for the callback's length.
        unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), len) }
    };
    let moved = call.send(bytes);
    // SAFETY: the library's BIO.
    unsafe { sys::wolfSSL_BIO_clear_retry_flags(bio) };
    match moved {
        Moved::Bytes(n) => c_int::try_from(n).expect("no more than the library wrote"),
        Moved::Again => {
            // SAFETY: the library's BIO.
            unsafe {
                sys::wolfSSL_BIO_set_flags(
                    bio,
                    sys::WOLFSSL_BIO_FLAG_RETRY | sys::WOLFSSL_BIO_FLAG_WRITE,
                );
            };
            -1
        }
        Moved::Failed | Moved::Refused => -1,
    }
}

/// The library reads up to `len` bytes into `buf` (`wssl_bio_cf_in_read`).
unsafe extern "C" fn bio_read(bio: *mut sys::WOLFSSL_BIO, buf: *mut c_char, len: c_int) -> c_int {
    // SAFETY: the library's BIO, whose data is the slot.
    let data = unsafe { sys::wolfSSL_BIO_get_data(bio) };
    // SAFETY: called back during `with_call`.
    let Some(call) = (unsafe { call_of(data) }) else {
        return -1;
    };
    let Ok(len) = usize::try_from(len) else {
        call.recv_refused();
        return -1;
    };
    if buf.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: the library hands `len` bytes of room at `buf`.
    let room = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), len) };
    let moved = call.recv(room);
    if moved == Moved::Refused {
        return -1;
    }
    // SAFETY: the library's BIO.
    unsafe { sys::wolfSSL_BIO_clear_retry_flags(bio) };
    match moved {
        Moved::Bytes(n) => c_int::try_from(n).expect("no more than the library asked"),
        Moved::Again => {
            // SAFETY: the library's BIO.
            unsafe {
                sys::wolfSSL_BIO_set_flags(
                    bio,
                    sys::WOLFSSL_BIO_FLAG_RETRY | sys::WOLFSSL_BIO_FLAG_READ,
                );
            };
            -1
        }
        Moved::Failed | Moved::Refused => -1,
    }
}

/// The library made a session (`wssl_vtls_new_session_cb`): its DER
/// written out for the call under way to keep.
unsafe extern "C" fn new_session(
    ssl: *mut sys::WOLFSSL,
    session: *mut sys::WOLFSSL_SESSION,
) -> c_int {
    // SAFETY: the library's session object; its BIO, or null before it
    // has one.
    let bio = unsafe { sys::wolfSSL_SSL_get_rbio(ssl) };
    if bio.is_null() {
        return 0;
    }
    // SAFETY: the session's BIO, whose data is the slot.
    let data = unsafe { sys::wolfSSL_BIO_get_data(bio) };
    // SAFETY: called back during `with_call` or `drive`.
    let Some(call) = (unsafe { call_of(data) }) else {
        return 0;
    };
    if session.is_null() {
        return 0;
    }
    // SAFETY: the library's session, measured.
    let len = unsafe { sys::wolfSSL_i2d_SSL_SESSION(session, ptr::null_mut()) };
    let Some(size) = usize::try_from(len).ok().filter(|&n| n > 0) else {
        call.new_session(NewSession::Unsized(len.cast_unsigned()));
        return 0;
    };
    let mut der: Vec<u8> = Vec::new();
    if der.try_reserve_exact(size).is_err() {
        call.new_session(NewSession::NoRoom(len.cast_unsigned()));
        return 0;
    }
    let mut at = der.as_mut_ptr();
    // SAFETY: the session, written into room for the size it measured.
    let written = unsafe { sys::wolfSSL_i2d_SSL_SESSION(session, &raw mut at) };
    let Some(written) = usize::try_from(written)
        .ok()
        .filter(|&n| n > 0 && n <= size)
    else {
        call.new_session(NewSession::Unwritten(written.cast_unsigned()));
        return 0;
    };
    // SAFETY: the library wrote `written` bytes, no more than reserved.
    unsafe { der.set_len(written) };
    // SAFETY: the session, read.
    let timeout = unsafe { sys::wolfSSL_SESSION_get_timeout(session) };
    // SAFETY: as above.
    let early_max = unsafe { sys::wolfSSL_SESSION_get_max_early_data(session) };
    // SAFETY: the session object, read.
    let version = unsafe { sys::wolfSSL_version(ssl) };
    call.new_session(NewSession::Made {
        der,
        version: u16::try_from(version).unwrap_or_default(),
        // A `long`, 32 bits on Windows.
        #[allow(clippy::useless_conversion)]
        timeout: i64::from(timeout),
        early_max,
    });
    0
}

impl library::Ssl for Ssl {
    fn resume(&mut self, der: &[u8]) -> Resume {
        let mut p = der.as_ptr();
        // SAFETY: `der`'s bytes, which the library reads to make a session
        // of its own.
        let session =
            unsafe { sys::wolfSSL_d2i_SSL_SESSION(ptr::null_mut(), &raw mut p, long_len(der)) };
        if session.is_null() {
            return Resume::Undecoded;
        }
        // SAFETY: the session object, and the session just made, which it
        // copies.
        let rc = unsafe { sys::wolfSSL_set_session(self.p(), session) };
        // SAFETY: the session made above, freed once.
        unsafe { sys::wolfSSL_SESSION_free(session) };
        if rc == sys::WOLFSSL_SUCCESS {
            Resume::Done
        } else {
            Resume::Refused(rc)
        }
    }

    fn version_name(&self) -> &'static [u8] {
        // SAFETY: the session object; a static name.
        let p = unsafe { sys::wolfSSL_get_version(self.p()) };
        // SAFETY: as above.
        unsafe { c_text(p) }.unwrap_or_default()
    }

    fn before_tls13(&self) -> bool {
        // SAFETY: the session object.
        let v = unsafe { sys::wolfSSL_GetVersion(self.p()) };
        (sys::WOLFSSL_SSLV3..=sys::WOLFSSL_TLSV1_2).contains(&v)
    }

    fn cipher_name(&self) -> Option<&'static [u8]> {
        // SAFETY: the session object; a static name, or null.
        let p = unsafe { sys::wolfSSL_get_cipher_name(self.p()) };
        // SAFETY: as above.
        unsafe { c_text(p) }
    }

    fn session_max_early_data(&self) -> u32 {
        // SAFETY: the session object; its session, or null.
        let session = unsafe { sys::wolfSSL_get_session(self.p()) };
        if session.is_null() {
            return 0;
        }
        // SAFETY: the object's session, read.
        unsafe { sys::wolfSSL_SESSION_get_max_early_data(session) }
    }

    fn max_early_data(&mut self, most: u32) {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_set_max_early_data(self.p(), most) };
    }

    fn alpn(&mut self, list: &[u8]) -> bool {
        let Ok(len) = u32::try_from(list.len()) else {
            return false;
        };
        // The library takes the list as mutable, and parses it in place: a
        // copy, with a zero after it, on the stack for the offers this
        // crate makes, which are short.
        let mut stack = [0u8; 64];
        let mut heap = Vec::new();
        let copy: &mut [u8] = if list.len() < stack.len() {
            stack[..list.len()].copy_from_slice(list);
            &mut stack[..=list.len()]
        } else {
            if heap.try_extend_from_slice(list).is_err() || heap.try_push(0).is_err() {
                return false;
            }
            &mut heap
        };
        // SAFETY: the session object, and `len` bytes the library copies.
        unsafe {
            sys::wolfSSL_UseALPN(
                self.p(),
                copy.as_mut_ptr().cast(),
                len,
                sys::WOLFSSL_ALPN_CONTINUE_ON_MISMATCH,
            ) == sys::WOLFSSL_SUCCESS
        }
    }

    fn ech_configs_base64(&mut self, b64: &[u8]) -> bool {
        let Ok(len) = u32::try_from(b64.len()) else {
            return false;
        };
        // The library takes the text as mutable, and reads it whole: a
        // copy.
        let mut copy = Vec::new();
        if copy.try_extend_from_slice(b64).is_err() {
            return false;
        }
        // SAFETY: the session object, and `len` bytes the library decodes
        // into a list of its own.
        let rc =
            unsafe { sys::wolfSSL_SetEchConfigsBase64(self.p(), copy.as_mut_ptr().cast(), len) };
        rc == sys::WOLFSSL_SUCCESS
    }

    fn set_ech_configs(&mut self, list: &[u8]) -> bool {
        let Ok(len) = u32::try_from(list.len()) else {
            return false;
        };
        // SAFETY: the session object, and `len` bytes the library parses
        // into a list of its own.
        unsafe { sys::wolfSSL_SetEchConfigs(self.p(), list.as_ptr(), len) == sys::WOLFSSL_SUCCESS }
    }

    fn ech_configs(&self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 1000];
        let mut len = 1000;
        // SAFETY: the session object, and room for `len` bytes, the most
        // it writes, of which it says how many it wrote.
        let rc = unsafe { sys::wolfSSL_GetEchConfigs(self.p(), buf.as_mut_ptr(), &raw mut len) };
        if rc != sys::WOLFSSL_SUCCESS {
            return None;
        }
        let written = buf.get(..usize::try_from(len).ok()?)?;
        let mut v = Vec::new();
        v.try_extend_from_slice(written).ok()?;
        Some(v)
    }

    fn min_version(&mut self, version: u16) -> bool {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_set_min_proto_version(self.p(), version.into()) == 1 }
    }

    fn keep_arrays(&mut self) {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_KeepArrays(self.p()) };
    }

    fn free_arrays(&mut self) {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_FreeArrays(self.p()) };
    }

    fn tls12_keys(&self) -> Option<Tls12Keys> {
        let (mut ms, mut sr, mut cr) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        let (mut ms_len, mut sr_len, mut cr_len) = (0, 0, 0);
        // SAFETY: the session object, and places for what it answers.
        let rc = unsafe {
            sys::wolfSSL_get_keys(
                self.p(),
                &raw mut ms,
                &raw mut ms_len,
                &raw mut sr,
                &raw mut sr_len,
                &raw mut cr,
                &raw mut cr_len,
            )
        };
        if rc != sys::WOLFSSL_SUCCESS || ms.is_null() || cr.is_null() {
            return None;
        }
        let copy = |p: *mut u8, len: core::ffi::c_uint| -> Option<Vec<u8>> {
            let len = usize::try_from(len).ok()?;
            // SAFETY: the library's arrays, `len` bytes each, alive until
            // they are freed, which the session does after this.
            let bytes = unsafe { core::slice::from_raw_parts(p, len) };
            let mut v = Vec::new();
            v.try_extend_from_slice(bytes).ok()?;
            Some(v)
        };
        Some(Tls12Keys {
            master: copy(ms, ms_len)?,
            client_random: copy(cr, cr_len)?,
        })
    }

    fn check_domain(&mut self, name: &CStr) -> bool {
        // SAFETY: the session object, and a C string it copies.
        unsafe { sys::wolfSSL_check_domain_name(self.p(), name.as_ptr()) == sys::WOLFSSL_SUCCESS }
    }

    fn quic_codepoint(&mut self) {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_set_quic_use_legacy_codepoint(self.p(), 0) };
    }

    fn bio(&mut self) -> Result<(), OutOfMemory> {
        // SAFETY: the method, alive as long as this object.
        let bio = unsafe { sys::wolfSSL_BIO_new(self.method.0.as_ptr()) };
        if bio.is_null() {
            return Err(OutOfMemory);
        }
        // SAFETY: the BIO just made, and the slot, alive as long as the
        // object that owns the BIO.
        unsafe { sys::wolfSSL_BIO_set_data(bio, self.slot.as_ptr().cast()) };
        // SAFETY: the session object, which takes the BIO over for both
        // ways.
        unsafe { sys::wolfSSL_set_bio(self.p(), bio, bio) };
        Ok(())
    }

    fn drive(
        &mut self,
        call: &mut Call<'_, '_>,
        check: &mut dyn FnMut(&mut Ssl, &mut TlsCx<'_>) -> Result<(), ErrorKind>,
        op: &mut dyn FnMut(&mut dyn DriveCall),
    ) {
        let p: *mut Call<'_, '_> = call;
        // SAFETY: the slot, alive as long as the object.
        let slot = unsafe { self.slot.as_ref() };
        // The callbacks and `Driving` reach the call only during `op`, one
        // at a time, and nothing else uses it until `op` returns.
        slot.0.set(p.cast());
        let mut driving = Driving {
            call: p,
            ssl: self,
            check,
        };
        op(&mut driving);
        // SAFETY: as above.
        unsafe { self.slot.as_ref() }.0.set(ptr::null_mut());
    }

    fn connect(&mut self, call: &mut Call<'_, '_>) -> Rc {
        // SAFETY: the session object, its callbacks reaching `call`.
        self.with_call(call, |ssl| unsafe { sys::wolfSSL_connect(ssl) })
    }

    fn error(&self, rc: Rc) -> i32 {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_get_error(self.p(), rc) }
    }

    fn wants_read(&self) -> bool {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_want_read(self.p()) != 0 }
    }

    fn wants_write(&self) -> bool {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_want_write(self.p()) != 0 }
    }

    fn write_early(&mut self, call: &mut Call<'_, '_>, bytes: &[u8]) -> (Rc, usize) {
        let len = c_int::try_from(bytes.len()).unwrap_or(c_int::MAX);
        let mut written: c_int = 0;
        let rc = self.with_call(call, |ssl| {
            // SAFETY: the session object, `len` bytes it reads, and a
            // place for the count; its callbacks reach `call`.
            unsafe {
                sys::wolfSSL_write_early_data(ssl, bytes.as_ptr().cast(), len, &raw mut written)
            }
        });
        (rc, usize::try_from(written).unwrap_or(0))
    }

    fn early_rejected(&self) -> bool {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_get_early_data_status(self.p()) == sys::WOLFSSL_EARLY_DATA_REJECTED }
    }

    fn read(&mut self, call: &mut Call<'_, '_>, buf: &mut [u8]) -> Rc {
        let len = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        let p = buf.as_mut_ptr();
        // SAFETY: the session object, room for `len` bytes; its callbacks
        // reach `call`.
        self.with_call(call, |ssl| unsafe { sys::wolfSSL_read(ssl, p.cast(), len) })
    }

    fn write(&mut self, call: &mut Call<'_, '_>, bytes: &[u8]) -> Rc {
        let len = c_int::try_from(bytes.len()).unwrap_or(c_int::MAX);
        // SAFETY: the session object, `len` bytes it reads; its callbacks
        // reach `call`.
        self.with_call(call, |ssl| unsafe {
            sys::wolfSSL_write(ssl, bytes.as_ptr().cast(), len)
        })
    }

    fn shutdown(&mut self, call: &mut Call<'_, '_>) -> Rc {
        // SAFETY: the session object, its callbacks reaching `call`.
        self.with_call(call, |ssl| unsafe { sys::wolfSSL_shutdown(ssl) })
    }

    fn sent_shutdown(&self) -> bool {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_get_shutdown(self.p()) & sys::WOLFSSL_SENT_SHUTDOWN != 0 }
    }

    fn pending(&self) -> bool {
        // SAFETY: the session object.
        unsafe { sys::wolfSSL_pending(self.p()) != 0 }
    }

    fn peer_cert(&self) -> PeerCert {
        self.with_peer(|x| {
            let mut len: c_int = 0;
            // SAFETY: the certificate, alive while this runs; its DER.
            let der = unsafe { sys::wolfSSL_X509_get_der(x.as_ptr(), &raw mut len) };
            let Some(len) = usize::try_from(len).ok().filter(|_| !der.is_null()) else {
                return PeerCert::NoDer;
            };
            // SAFETY: `len` bytes of the certificate's, alive while it is.
            let bytes = unsafe { core::slice::from_raw_parts(der, len) };
            let mut copy = Vec::new();
            if copy.try_extend_from_slice(bytes).is_err() {
                return PeerCert::NoRoom;
            }
            PeerCert::Der(copy)
        })
        .unwrap_or(PeerCert::None)
    }

    fn check_ip(&self, ip: &CStr) -> Option<Rc> {
        self.with_peer(|x| {
            // SAFETY: the certificate, alive while this runs, and a C
            // string.
            unsafe { sys::wolfSSL_X509_check_ip_asc(x.as_ptr(), ip.as_ptr(), 0) }
        })
    }

    fn check_host(&self, name: &[u8]) -> Option<Rc> {
        self.with_peer(|x| {
            // SAFETY: the certificate, alive while this runs, and `name`'s
            // bytes, which the library reads; no peer name asked back.
            unsafe {
                sys::wolfSSL_X509_check_host(
                    x.as_ptr(),
                    name.as_ptr().cast(),
                    name.len(),
                    0 as c_uint,
                    ptr::null_mut(),
                )
            }
        })
    }

    fn alpn_selected(&self) -> AlpnGot {
        let mut name: *mut c_char = ptr::null_mut();
        let mut size: u16 = 0;
        // SAFETY: the session object, and places for its answer.
        let rc = unsafe { sys::wolfSSL_ALPN_GetProtocol(self.p(), &raw mut name, &raw mut size) };
        if rc == sys::WOLFSSL_SUCCESS {
            if name.is_null() {
                return AlpnGot::Chose(Vec::new());
            }
            // SAFETY: `size` bytes of the session's, alive while it is.
            let bytes = unsafe { core::slice::from_raw_parts(name.cast::<u8>(), size.into()) };
            let mut copy = Vec::new();
            if copy.try_extend_from_slice(bytes).is_err() {
                return AlpnGot::NoRoom;
            }
            AlpnGot::Chose(copy)
        } else if rc == sys::WOLFSSL_ALPN_NOT_FOUND {
            AlpnGot::NotFound
        } else {
            AlpnGot::Failed(rc)
        }
    }
}
