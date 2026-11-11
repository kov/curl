//! GnuTLS itself, as `library.rs` asks it: credentials, sessions and
//! certificates the library makes, each freed as it goes, and the
//! callbacks it makes during a call.
//!
//! For the length of each call that may read or write (`with_call`), and
//! of each call into the QUIC library that drives a QUIC session
//! (`drive`), the session's transport pointer points at a `Slot` on the
//! caller's stack, holding the call's `Call`. The pointer is set before
//! the call and cleared after, the callbacks run only inside that call,
//! on its thread, one at a time, and nothing else holds the slot while
//! they do. The session's user pointer is never this crate's: for a
//! QUIC session it is the QUIC library's crypto's, which finds its
//! connection through it.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr::{self, NonNull};

use curl_alloc::TryVec as _;
use curl_core::error::ErrorKind;
use curl_core::tls::{DriveCall, TlsCx, TlsKind, TlsNative};

use crate::library::{self, Call, Format, Moved, Rc, Stapled};
use crate::sys;

/// The library, as `library::Gnutls` asks it.
#[derive(Debug)]
pub(crate) struct Real;

/// The library.
pub(crate) static GNUTLS: Real = Real;

/// The text of a C string the library returns, or none.
///
/// # Safety
/// `p` is null or a C string alive as long as `'a`.
unsafe fn c_text<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: as the caller says.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
}

/// The library's version, as `gnutls_check_version` says it: `3.8.13`.
pub(crate) fn version() -> &'static [u8] {
    // SAFETY: no requirement, so the library's static version text.
    let v = unsafe { sys::gnutls_check_version(ptr::null()) };
    // SAFETY: the library's static text.
    unsafe { c_text(v) }.unwrap_or_default()
}

/// Initialise the library, as C's global init does (`gtls_init`):
/// whether it could.
pub(crate) fn init() -> bool {
    // SAFETY: no requirement; thread-safe since 3.3.0, and counted, so
    // each call is matched by `deinit`'s.
    unsafe { sys::gnutls_global_init() == 0 }
}

/// Let the library go, as C's global cleanup does (`gtls_cleanup`).
pub(crate) fn deinit() {
    // SAFETY: matches an `init` that succeeded, as the caller ensures.
    unsafe { sys::gnutls_global_deinit() };
}

impl library::Gnutls for Real {
    type Creds = Creds;
    type Session = Session;
    type Cert = Cert;

    fn creds(&self) -> Result<Creds, Rc> {
        let mut c = ptr::null_mut();
        // SAFETY: a pointer to fill in.
        let rc = unsafe { sys::gnutls_certificate_allocate_credentials(&mut c) };
        match NonNull::new(c) {
            Some(c) if rc == 0 => Ok(Creds(c)),
            _ => Err(rc),
        }
    }

    fn session(&self, flags: u32) -> Result<Session, Rc> {
        let mut s = ptr::null_mut();
        // SAFETY: a pointer to fill in, and the flags.
        let rc = unsafe { sys::gnutls_init(&mut s, flags) };
        match NonNull::new(s) {
            Some(s) if rc == 0 => Ok(Session(s)),
            _ => Err(rc),
        }
    }

    fn cert(&self) -> Result<Cert, Rc> {
        let mut c = ptr::null_mut();
        // SAFETY: a pointer to fill in.
        let rc = unsafe { sys::gnutls_x509_crt_init(&mut c) };
        match NonNull::new(c) {
            Some(c) if rc == 0 => Ok(Cert(c)),
            _ => Err(rc),
        }
    }

    fn strerror(&self, rc: Rc) -> &'static [u8] {
        // SAFETY: any number; the answer is the library's static text.
        let t = unsafe { sys::gnutls_strerror(rc) };
        // SAFETY: as above.
        unsafe { c_text(t) }.unwrap_or(b"(null)")
    }

    fn is_fatal(&self, rc: Rc) -> bool {
        // SAFETY: any number.
        unsafe { sys::gnutls_error_is_fatal(rc) != 0 }
    }
}

/// Certificate credentials the library made, freed as they go.
pub(crate) struct Creds(NonNull<sys::gnutls_certificate_credentials_st>);

// SAFETY: the credentials are the library's, changed only while one
// session holds them (`trust::populate` asserts it), and only read by the
// sessions using them after, which GnuTLS allows from any thread (its
// credentials are shared between sessions); they are freed once, by
// their last owner.
unsafe impl Send for Creds {}
// SAFETY: as above: nothing changes them through a shared reference.
unsafe impl Sync for Creds {}

impl Drop for Creds {
    fn drop(&mut self) {
        // SAFETY: made by the library, freed once, after every session
        // pointing at them (each holds them until it is deinitialised).
        unsafe { sys::gnutls_certificate_free_credentials(self.0.as_ptr()) };
    }
}

/// The format's number.
fn format(f: Format) -> c_int {
    match f {
        Format::Der => sys::GNUTLS_X509_FMT_DER,
        Format::Pem => sys::GNUTLS_X509_FMT_PEM,
    }
}

impl library::Creds for Creds {
    fn system_trust(&self) -> Rc {
        // SAFETY: the credentials.
        unsafe { sys::gnutls_certificate_set_x509_system_trust(self.0.as_ptr()) }
    }

    fn trust_mem(&self, pem: &[u8]) -> Rc {
        let Ok(size) = c_uint::try_from(pem.len()) else {
            return sys::GNUTLS_E_SHORT_MEMORY_BUFFER;
        };
        let datum = sys::gnutls_datum_t {
            data: pem.as_ptr().cast_mut(),
            size,
        };
        // SAFETY: the credentials and `size` bytes the library only reads.
        unsafe {
            sys::gnutls_certificate_set_x509_trust_mem(
                self.0.as_ptr(),
                &datum,
                sys::GNUTLS_X509_FMT_PEM,
            )
        }
    }

    fn allow_v1_ca(&self) {
        // SAFETY: the credentials.
        unsafe {
            sys::gnutls_certificate_set_verify_flags(
                self.0.as_ptr(),
                sys::GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
            );
        }
    }

    fn trust_file(&self, file: &CStr) -> Rc {
        // SAFETY: the credentials and a C string.
        unsafe {
            sys::gnutls_certificate_set_x509_trust_file(
                self.0.as_ptr(),
                file.as_ptr(),
                sys::GNUTLS_X509_FMT_PEM,
            )
        }
    }

    fn trust_dir(&self, dir: &CStr) -> Rc {
        // SAFETY: the credentials and a C string.
        unsafe {
            sys::gnutls_certificate_set_x509_trust_dir(
                self.0.as_ptr(),
                dir.as_ptr(),
                sys::GNUTLS_X509_FMT_PEM,
            )
        }
    }

    fn crl_file(&self, file: &CStr) -> Rc {
        // SAFETY: the credentials and a C string.
        unsafe {
            sys::gnutls_certificate_set_x509_crl_file(
                self.0.as_ptr(),
                file.as_ptr(),
                sys::GNUTLS_X509_FMT_PEM,
            )
        }
    }

    fn pkcs12_file(&self, file: &CStr, password: &CStr) -> Rc {
        // SAFETY: the credentials and two C strings.
        unsafe {
            sys::gnutls_certificate_set_x509_simple_pkcs12_file(
                self.0.as_ptr(),
                file.as_ptr(),
                sys::GNUTLS_X509_FMT_DER,
                password.as_ptr(),
            )
        }
    }

    fn key_file(&self, cert: &CStr, key: &CStr, f: Format, password: Option<&CStr>) -> Rc {
        let encryptions = sys::GNUTLS_PKCS_PKCS12_3DES
            | sys::GNUTLS_PKCS_PKCS12_ARCFOUR
            | sys::GNUTLS_PKCS_PKCS12_RC2_40
            | sys::GNUTLS_PKCS_PBES2_3DES
            | sys::GNUTLS_PKCS_PBES2_AES_128
            | sys::GNUTLS_PKCS_PBES2_AES_192
            | sys::GNUTLS_PKCS_PBES2_AES_256;
        let pass = password.map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: the credentials, C strings, and a password or null.
        unsafe {
            sys::gnutls_certificate_set_x509_key_file2(
                self.0.as_ptr(),
                cert.as_ptr(),
                key.as_ptr(),
                format(f),
                pass,
                encryptions,
            )
        }
    }
}

/// A session the library made, deinitialised as it goes.
pub(crate) struct Session(NonNull<sys::gnutls_session_int>);

// SAFETY: a session is used from one thread at a time, which `&mut self`
// ensures, and GnuTLS lets it move between threads.
unsafe impl Send for Session {}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: made by `gnutls_init`, deinitialised once; its
        // credentials outlive it (the owner drops them after).
        unsafe { sys::gnutls_deinit(self.0.as_ptr()) };
    }
}

/// What the callbacks of the call under way reach: the `Call`, and the
/// session, to set its transport's error number on.
struct Slot<'c, 's, 'a> {
    call: &'c mut Call<'s, 'a, Creds>,
    session: sys::gnutls_session_t,
}

impl Session {
    fn s(&self) -> sys::gnutls_session_t {
        self.0.as_ptr()
    }

    /// Run `op`, a call on the session, with `call` what its callbacks
    /// reach: set before, cleared after. `op` must not reach `call`
    /// itself.
    fn with_call<R>(
        &mut self,
        call: &mut Call<'_, '_, Creds>,
        op: impl FnOnce(sys::gnutls_session_t) -> R,
    ) -> R {
        let s = self.s();
        let mut slot = Slot { call, session: s };
        let p: *mut Slot<'_, '_, '_> = &mut slot;
        // SAFETY: the session; the slot outlives the call, the callbacks
        // read it only during `op`, and nothing else uses it until `op`
        // returns.
        unsafe { sys::gnutls_transport_set_ptr(s, p.cast()) };
        let r = op(s);
        // SAFETY: the session; no callback runs after `op` returns.
        unsafe { sys::gnutls_transport_set_ptr(s, ptr::null_mut()) };
        r
    }
}

/// What a call into the QUIC library is lent while it drives a session:
/// the slot of the call, and the session, each reached through its
/// pointer for the length of one method, as the session's callbacks
/// reach the slot, never at the same time as they.
struct Driving<'d, 'c, 's, 'a> {
    slot: *mut Slot<'c, 's, 'a>,
    session: *mut Session,
    check: &'d mut dyn FnMut(&mut Session, &mut TlsCx<'_>) -> Result<(), ErrorKind>,
}

impl DriveCall for Driving<'_, '_, '_, '_> {
    fn handshake_done(&mut self) -> Result<(), ErrorKind> {
        // SAFETY: the slot and the session outlive the QUIC library's
        // call, inside which alone this runs; the QUIC library tells of
        // the handshake's end outside any callback of GnuTLS's, so
        // nothing else reaches either while this does, and `drive`, which
        // the session's pointer came from, uses neither until the call
        // returns.
        let slot = unsafe { &mut *self.slot };
        // SAFETY: as above.
        let session = unsafe { &mut *self.session };
        (self.check)(session, slot.call.io.cx())
    }

    fn with_cx(&mut self, f: &mut dyn FnMut(&mut TlsCx<'_>)) {
        // SAFETY: as above: the QUIC library's callbacks, which alone
        // call this, run one at a time, and none of GnuTLS's callbacks,
        // which reach the slot too, runs while one does.
        let slot = unsafe { &mut *self.slot };
        f(slot.call.io.cx());
    }
}

/// The slot of the call under way, from the pointer the library hands a
/// callback.
///
/// # Safety
/// Only from a callback of the library during `with_call`: the pointer
/// is then null or a live `Slot` no one else is using.
unsafe fn slot_of<'r>(p: *mut c_void) -> Option<&'r mut Slot<'r, 'r, 'r>> {
    // SAFETY: as the caller says; the lifetimes are the callback's,
    // shorter than the slot's, and nothing is stored in it.
    unsafe { p.cast::<Slot<'r, 'r, 'r>>().as_mut() }
}

/// What a push or pull answers the library: a count, or -1 with the
/// transport's error number set.
fn answer(session: sys::gnutls_session_t, moved: Moved) -> isize {
    let errno = match moved {
        Moved::Bytes(n) => return isize::try_from(n).expect("no more than asked"),
        Moved::Again => libc::EAGAIN,
        Moved::Failed => libc::EINVAL,
    };
    // SAFETY: the session of the call under way.
    unsafe { sys::gnutls_transport_set_errno(session, errno) };
    -1
}

/// The library writes `len` bytes from `buf` (`gtls_push`).
unsafe extern "C" fn push(p: *mut c_void, buf: *const c_void, len: usize) -> isize {
    // SAFETY: called back during `with_call`.
    let slot = unsafe { slot_of(p) }.expect("the session writes only during a call");
    let bytes = if len == 0 {
        &[][..]
    } else {
        // SAFETY: the library hands `len` bytes at `buf`, alive and not
        // written to for the callback's length.
        unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), len) }
    };
    let moved = slot.call.push(bytes);
    answer(slot.session, moved)
}

/// The library reads up to `len` bytes into `buf` (`gtls_pull`).
unsafe extern "C" fn pull(p: *mut c_void, buf: *mut c_void, len: usize) -> isize {
    // SAFETY: called back during `with_call`.
    let slot = unsafe { slot_of(p) }.expect("the session reads only during a call");
    let room = if len == 0 || buf.is_null() {
        &mut [][..]
    } else {
        // SAFETY: the library hands `len` bytes of room at `buf`.
        unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), len) }
    };
    let session = slot.session;
    let mut set = |creds: &Creds| {
        // SAFETY: the session of the call under way, pointed at
        // credentials its owner keeps alive as long as it, from inside
        // its pull function, as C points it.
        unsafe {
            sys::gnutls_credentials_set(
                session,
                sys::GNUTLS_CRD_CERTIFICATE,
                creds.0.as_ptr().cast(),
            )
        }
    };
    let moved = slot.call.pull(room, &mut set);
    answer(session, moved)
}

/// The library handled a handshake message (`gtls_handshake_cb`): a
/// session ticket is kept.
unsafe extern "C" fn hook(
    session: sys::gnutls_session_t,
    htype: c_uint,
    when: c_uint,
    incoming: c_uint,
    _msg: *const sys::gnutls_datum_t,
) -> c_int {
    if when == 0 {
        return 0;
    }
    // SAFETY: the session the library calls back for.
    let p = unsafe { sys::gnutls_transport_get_ptr(session) };
    // SAFETY: called back during `with_call` or `drive`, or with no call:
    // null.
    let Some(slot) = (unsafe { slot_of(p) }) else {
        return 0;
    };
    if slot.call.handshake_message(htype, incoming != 0) {
        // Out of memory, the session is not kept, as C goes on without.
        // SAFETY: the session, inside its callback.
        if let Ok(data) = unsafe { session_data(session) } {
            // SAFETY: as above.
            let version = unsafe { sys::gnutls_protocol_get_version(session) };
            // SAFETY: as above.
            let early = unsafe { sys::gnutls_record_get_max_early_data_size(session) };
            slot.call.keep_ticket(data, version, early);
        }
    }
    0
}

/// The library tells of a secret (`keylog_callback`).
unsafe extern "C" fn keylog(
    session: sys::gnutls_session_t,
    label: *const c_char,
    secret: *const sys::gnutls_datum_t,
) -> c_int {
    // SAFETY: the session the library calls back for.
    let p = unsafe { sys::gnutls_transport_get_ptr(session) };
    // SAFETY: called back during `with_call` or `drive`, or with no call:
    // null.
    let Some(slot) = (unsafe { slot_of(p) }) else {
        return 0;
    };
    let mut client = sys::gnutls_datum_t {
        data: ptr::null_mut(),
        size: 0,
    };
    let mut server = client;
    // SAFETY: the session, and two datums the library points at its own.
    unsafe { sys::gnutls_session_get_random(session, &mut client, &mut server) };
    // SAFETY: the library's bytes, alive for the callback.
    let random = unsafe { datum(&client) };
    // SAFETY: the library hands a C string, alive for the callback.
    let label = unsafe { c_text(label) }.unwrap_or_default();
    // SAFETY: the library's datum, alive for the callback.
    let secret = unsafe { secret.as_ref() }.map_or(&[][..], |d| {
        // SAFETY: as above.
        unsafe { datum(d) }
    });
    if slot.call.keylog_secret(label, random, secret) {
        0
    } else {
        -1
    }
}

/// The bytes of `d`.
///
/// # Safety
/// `d` is the library's, its bytes alive as long as `'a`.
unsafe fn datum<'a>(d: &sys::gnutls_datum_t) -> &'a [u8] {
    match usize::try_from(d.size) {
        Ok(n) if n > 0 && !d.data.is_null() => {
            // SAFETY: as the caller says.
            unsafe { core::slice::from_raw_parts(d.data, n) }
        }
        _ => &[],
    }
}

/// The session to resume `session` gives, copied, empty if it has none
/// (`gnutls_session_get_data`, asked its size first).
///
/// # Safety
/// `session` is a live session.
unsafe fn session_data(session: sys::gnutls_session_t) -> Result<Vec<u8>, ErrorKind> {
    let mut len = 0usize;
    // SAFETY: as the caller says; no buffer, so only the size.
    unsafe { sys::gnutls_session_get_data(session, ptr::null_mut(), &mut len) };
    let mut data = Vec::new();
    if len == 0 {
        return Ok(data);
    }
    data.try_reserve_exact(len)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let mut got = len;
    // SAFETY: room for `len` bytes, as asked.
    let rc = unsafe { sys::gnutls_session_get_data(session, data.as_mut_ptr().cast(), &mut got) };
    if rc < 0 || got > len {
        return Ok(Vec::new());
    }
    // SAFETY: the library wrote `got` bytes from the start, within room.
    unsafe { data.set_len(got) };
    Ok(data)
}

impl library::Session for Session {
    type Creds = Creds;
    type Cert = Cert;

    fn server_name(&mut self, name: &[u8]) -> Rc {
        // SAFETY: the session, and `name.len()` bytes it copies.
        unsafe {
            sys::gnutls_server_name_set(
                self.s(),
                sys::GNUTLS_NAME_DNS,
                name.as_ptr().cast(),
                name.len(),
            )
        }
    }

    fn default_priority(&mut self) -> Rc {
        // SAFETY: the session.
        unsafe { sys::gnutls_set_default_priority(self.s()) }
    }

    fn priority<'p>(&mut self, priority: &'p CStr) -> Result<(), (Rc, Option<&'p [u8]>)> {
        let mut err: *const c_char = ptr::null();
        // SAFETY: the session, a C string, and where it says it failed.
        let rc = unsafe { sys::gnutls_priority_set_direct(self.s(), priority.as_ptr(), &mut err) };
        if rc == 0 {
            return Ok(());
        }
        let bytes = priority.to_bytes();
        let at = (err as usize)
            .checked_sub(priority.as_ptr() as usize)
            .filter(|&at| !err.is_null() && at <= bytes.len());
        Err((rc, at.map(|at| &bytes[at..])))
    }

    fn credentials(&mut self, creds: &Creds) -> Rc {
        // SAFETY: the session and the credentials, which the owner keeps
        // alive until the session is deinitialised or points elsewhere.
        unsafe {
            sys::gnutls_credentials_set(
                self.s(),
                sys::GNUTLS_CRD_CERTIFICATE,
                creds.0.as_ptr().cast(),
            )
        }
    }

    fn status_request(&mut self) -> Rc {
        // SAFETY: the session, and no responders or extensions.
        unsafe {
            sys::gnutls_ocsp_status_request_enable_client(
                self.s(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        }
    }

    fn set_data(&mut self, data: &[u8]) -> Rc {
        // SAFETY: the session and `data.len()` bytes it copies.
        unsafe { sys::gnutls_session_set_data(self.s(), data.as_ptr().cast(), data.len()) }
    }

    fn data(&mut self) -> Result<Vec<u8>, ErrorKind> {
        // SAFETY: the session.
        unsafe { session_data(self.s()) }
    }

    fn max_early_data(&mut self) -> usize {
        // SAFETY: the session.
        unsafe { sys::gnutls_record_get_max_early_data_size(self.s()) }
    }

    fn alpn(&mut self, protocols: &[&[u8]]) -> Rc {
        let mut datums = [sys::gnutls_datum_t {
            data: ptr::null_mut(),
            size: 0,
        }; 4];
        assert!(protocols.len() <= datums.len(), "an ALPN offer is short");
        for (d, p) in datums.iter_mut().zip(protocols) {
            d.data = p.as_ptr().cast_mut();
            d.size = c_uint::try_from(p.len()).expect("a protocol's name is short");
        }
        let n = c_uint::try_from(protocols.len()).expect("short");
        // SAFETY: the session and `n` datums it copies, only read.
        unsafe {
            sys::gnutls_alpn_set_protocols(self.s(), datums.as_ptr(), n, sys::GNUTLS_ALPN_MANDATORY)
        }
    }

    fn log_keys(&mut self) {
        // SAFETY: the session, and a callback of the type it calls.
        unsafe { sys::gnutls_session_set_keylog_function(self.s(), Some(keylog)) };
    }

    fn hook(&mut self) {
        let s = self.s();
        // SAFETY: the session, and a callback of the type it calls.
        unsafe {
            sys::gnutls_handshake_set_hook_function(
                s,
                sys::GNUTLS_HANDSHAKE_ANY,
                sys::GNUTLS_HOOK_POST,
                Some(hook),
            );
        }
        // SAFETY: as above.
        unsafe { sys::gnutls_transport_set_push_function(s, Some(push)) };
        // SAFETY: as above.
        unsafe { sys::gnutls_transport_set_pull_function(s, Some(pull)) };
    }

    fn quic_hook(&mut self, tickets: bool) {
        let s = self.s();
        if tickets {
            // SAFETY: the session, and a callback of the type it calls.
            unsafe {
                sys::gnutls_handshake_set_hook_function(
                    s,
                    sys::GNUTLS_HANDSHAKE_ANY,
                    sys::GNUTLS_HOOK_POST,
                    Some(hook),
                );
            }
        }
        // Never called, a QUIC session's records being the QUIC
        // library's: set so that a call would stop the process, not write
        // to a descriptor the transport pointer is not.
        // SAFETY: as above.
        unsafe { sys::gnutls_transport_set_push_function(s, Some(push)) };
        // SAFETY: as above.
        unsafe { sys::gnutls_transport_set_pull_function(s, Some(pull)) };
    }

    fn drive(
        &mut self,
        call: &mut Call<'_, '_, Creds>,
        check: &mut dyn FnMut(&mut Session, &mut TlsCx<'_>) -> Result<(), ErrorKind>,
        op: &mut dyn FnMut(&mut dyn DriveCall),
    ) {
        let s = self.s();
        let session: *mut Session = self;
        let mut slot = Slot { call, session: s };
        let p: *mut Slot<'_, '_, '_> = &mut slot;
        // SAFETY: the session; the slot outlives the call, the callbacks
        // and `Driving` reach it only during `op`, one at a time, and
        // nothing else uses it until `op` returns.
        unsafe { sys::gnutls_transport_set_ptr(s, p.cast()) };
        let mut driving = Driving {
            slot: p,
            session,
            check,
        };
        op(&mut driving);
        // SAFETY: the session; no callback runs after `op` returns.
        unsafe { sys::gnutls_transport_set_ptr(s, ptr::null_mut()) };
    }

    fn handshake(&mut self, call: &mut Call<'_, '_, Creds>) -> Rc {
        // SAFETY: the session, its callbacks reaching `call`.
        self.with_call(call, |s| unsafe { sys::gnutls_handshake(s) })
    }

    fn send(&mut self, call: &mut Call<'_, '_, Creds>, bytes: &[u8]) -> isize {
        let (from, len) = (bytes.as_ptr(), bytes.len());
        // SAFETY: the session and `len` bytes at `from`, the caller's.
        self.with_call(call, |s| unsafe {
            sys::gnutls_record_send(s, from.cast(), len)
        })
    }

    fn recv(&mut self, call: &mut Call<'_, '_, Creds>, buf: &mut [u8]) -> isize {
        let (room, len) = (buf.as_mut_ptr(), buf.len());
        // SAFETY: the session and `len` bytes of room at `room`, the
        // caller's, not otherwise used during the call.
        self.with_call(call, |s| unsafe {
            sys::gnutls_record_recv(s, room.cast(), len)
        })
    }

    fn send_early(&mut self, call: &mut Call<'_, '_, Creds>, bytes: &[u8]) -> isize {
        let (from, len) = (bytes.as_ptr(), bytes.len());
        // SAFETY: the session and `len` bytes at `from`, which it copies.
        self.with_call(call, |s| unsafe {
            sys::gnutls_record_send_early_data(s, from.cast(), len)
        })
    }

    fn bye(&mut self, call: &mut Call<'_, '_, Creds>) -> Rc {
        // SAFETY: the session, its callbacks reaching `call`.
        self.with_call(call, |s| unsafe {
            sys::gnutls_bye(s, sys::GNUTLS_SHUT_RDWR)
        })
    }

    fn wants_write(&mut self) -> bool {
        // SAFETY: the session.
        unsafe { sys::gnutls_record_get_direction(self.s()) != 0 }
    }

    fn alert_name(&mut self) -> Option<&'static [u8]> {
        // SAFETY: the session.
        let alert = unsafe { sys::gnutls_alert_get(self.s()) };
        // SAFETY: any number; the library's static text or null.
        let name = unsafe { sys::gnutls_alert_get_name(alert) };
        // SAFETY: as above.
        unsafe { c_text(name) }
    }

    fn pending(&self) -> bool {
        // SAFETY: the session.
        unsafe { sys::gnutls_record_check_pending(self.s()) != 0 }
    }

    fn version(&mut self) -> i32 {
        // SAFETY: the session.
        unsafe { sys::gnutls_protocol_get_version(self.s()) }
    }

    fn version_name(&mut self) -> Option<&'static [u8]> {
        let v = self.version();
        // SAFETY: any number; the library's static text or null.
        let name = unsafe { sys::gnutls_protocol_get_name(v) };
        // SAFETY: as above.
        unsafe { c_text(name) }
    }

    fn suite_name(&mut self) -> Option<&'static [u8]> {
        let s = self.s();
        // SAFETY: the session.
        let kx = unsafe { sys::gnutls_kx_get(s) };
        // SAFETY: the session.
        let cipher = unsafe { sys::gnutls_cipher_get(s) };
        // SAFETY: the session.
        let mac = unsafe { sys::gnutls_mac_get(s) };
        // SAFETY: any numbers; the library's static text or null.
        let name = unsafe { sys::gnutls_cipher_suite_get_name(kx, cipher, mac) };
        // SAFETY: as above.
        unsafe { c_text(name) }
    }

    fn alpn_selected(&mut self) -> &[u8] {
        let mut d = sys::gnutls_datum_t {
            data: ptr::null_mut(),
            size: 0,
        };
        // SAFETY: the session, and a datum it points at its own.
        if unsafe { sys::gnutls_alpn_get_selected_protocol(self.s(), &mut d) } != 0 {
            return &[];
        }
        // SAFETY: the session's bytes, alive while it is borrowed.
        unsafe { datum(&d) }
    }

    fn early_data_accepted(&mut self) -> bool {
        // SAFETY: the session.
        unsafe { sys::gnutls_session_get_flags(self.s()) & sys::GNUTLS_SFLAGS_EARLY_DATA != 0 }
    }

    fn peers(&self) -> Option<impl ExactSizeIterator<Item = &[u8]> + Clone> {
        let mut n: c_uint = 0;
        // SAFETY: the session; the list is its own.
        let list = unsafe { sys::gnutls_certificate_get_peers(self.s(), &mut n) };
        if list.is_null() {
            return None;
        }
        let n = usize::try_from(n).expect("a count");
        // SAFETY: `n` datums at `list`, the session's while it is
        // borrowed.
        let list = unsafe { core::slice::from_raw_parts(list, n) };
        // SAFETY: each a datum the session holds, as above.
        Some(list.iter().map(|d| unsafe { datum(d) }))
    }

    fn verify_peers(&self) -> Result<u32, Rc> {
        let mut status: c_uint = 0;
        // SAFETY: the session, and the status to fill in.
        let rc = unsafe { sys::gnutls_certificate_verify_peers2(self.s(), &mut status) };
        if rc < 0 { Err(rc) } else { Ok(status) }
    }

    fn stapled_status(&self, cert: &Cert) -> Stapled {
        let mut raw = sys::gnutls_datum_t {
            data: ptr::null_mut(),
            size: 0,
        };
        // SAFETY: the session, and a datum it points at its own.
        let rc = unsafe { sys::gnutls_ocsp_status_request_get(self.s(), &mut raw) };
        if rc == sys::GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE {
            return Stapled::None;
        } else if rc < 0 {
            return Stapled::Invalid;
        }
        let mut resp = ptr::null_mut();
        // SAFETY: a pointer to fill in.
        if unsafe { sys::gnutls_ocsp_resp_init(&mut resp) } < 0 || resp.is_null() {
            return Stapled::InitFailed;
        }
        let resp = Ocsp(resp);
        // SAFETY: the response, and the session's datum, which it reads.
        if unsafe { sys::gnutls_ocsp_resp_import(resp.0, &raw) } < 0 {
            return Stapled::Unparsed;
        }
        // SAFETY: the response.
        if unsafe { sys::gnutls_ocsp_resp_get_status(resp.0) } != sys::GNUTLS_OCSP_RESP_SUCCESSFUL {
            return Stapled::NotSuccessful;
        }
        let mut idx: c_uint = 0;
        let rc = loop {
            // SAFETY: the response and the certificate.
            let rc = unsafe { sys::gnutls_ocsp_resp_check_crt(resp.0, idx, cert.0.as_ptr()) };
            if rc == 0 || rc == sys::GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE {
                break rc;
            }
            idx += 1;
        };
        if rc < 0 {
            return Stapled::NotForPeer;
        }
        let mut status: c_uint = 0;
        // SAFETY: the response, and only the status asked for.
        let rc = unsafe {
            sys::gnutls_ocsp_resp_get_single(
                resp.0,
                idx,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut status,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc < 0 {
            return Stapled::SingleUnparsed;
        }
        Stapled::Status(status)
    }

    fn native(&self) -> TlsNative {
        let s = self.0.cast();
        // SAFETY: a `gnutls_session_t` GnuTLS made, the library `GnuTls`
        // names, which the backend's session holds while its connection
        // lives and frees as it drops.
        unsafe { TlsNative::new(TlsKind::GnuTls, s, Some(s)) }
    }
}

/// An OCSP response the library made, deinitialised as it goes.
struct Ocsp(sys::gnutls_ocsp_resp_t);

impl Drop for Ocsp {
    fn drop(&mut self) {
        // SAFETY: made by `gnutls_ocsp_resp_init`, once.
        unsafe { sys::gnutls_ocsp_resp_deinit(self.0) };
    }
}

/// A certificate the library made, deinitialised as it goes.
pub(crate) struct Cert(NonNull<sys::gnutls_x509_crt_int>);

impl Drop for Cert {
    fn drop(&mut self) {
        // SAFETY: made by `gnutls_x509_crt_init`, once.
        unsafe { sys::gnutls_x509_crt_deinit(self.0.as_ptr()) };
    }
}

/// A datum the library allocated, freed as it goes.
struct Owned(sys::gnutls_datum_t);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the library's `free`, a variable it always sets.
        let free = unsafe { sys::gnutls_free }.expect("the library sets its free function");
        // SAFETY: bytes the library allocated, freed once.
        unsafe { free(self.0.data.cast()) };
    }
}

/// The text of a distinguished name the library writes, copied.
fn dn_text(rc: c_int, d: sys::gnutls_datum_t) -> Result<Vec<u8>, Rc> {
    if rc != 0 {
        return Err(rc);
    }
    let owned = Owned(d);
    // SAFETY: the library's bytes, alive until `owned` goes.
    let bytes = unsafe { datum(&owned.0) };
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes)
        .map_err(|_| sys::GNUTLS_E_SHORT_MEMORY_BUFFER)?;
    Ok(v)
}

/// A public key the library made, deinitialised as it goes.
struct Pubkey(sys::gnutls_pubkey_t);

impl Drop for Pubkey {
    fn drop(&mut self) {
        // SAFETY: made by `gnutls_pubkey_init`, once.
        unsafe { sys::gnutls_pubkey_deinit(self.0) };
    }
}

impl library::Cert for Cert {
    fn import(&mut self, data: &[u8], f: Format) -> Rc {
        let Ok(size) = c_uint::try_from(data.len()) else {
            return sys::GNUTLS_E_SHORT_MEMORY_BUFFER;
        };
        let d = sys::gnutls_datum_t {
            data: data.as_ptr().cast_mut(),
            size,
        };
        // SAFETY: the certificate and `size` bytes the library only reads.
        unsafe { sys::gnutls_x509_crt_import(self.0.as_ptr(), &d, format(f)) }
    }

    fn common_name<'b>(&self, buf: &'b mut [u8; 65]) -> Result<&'b [u8], Rc> {
        let mut size = buf.len();
        // SAFETY: the certificate, a C string, and `size` bytes of room.
        let rc = unsafe {
            sys::gnutls_x509_crt_get_dn_by_oid(
                self.0.as_ptr(),
                sys::GNUTLS_OID_X520_COMMON_NAME.as_ptr(),
                0,
                0,
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(CStr::from_bytes_until_nul(buf).map_or(&buf[..], CStr::to_bytes))
    }

    fn expiration(&self) -> i64 {
        // SAFETY: the certificate.
        let t = unsafe { sys::gnutls_x509_crt_get_expiration_time(self.0.as_ptr()) };
        #[allow(
            clippy::useless_conversion,
            reason = "`time_t` is 32 bits on some systems"
        )]
        i64::from(t)
    }

    fn activation(&self) -> i64 {
        // SAFETY: the certificate.
        let t = unsafe { sys::gnutls_x509_crt_get_activation_time(self.0.as_ptr()) };
        #[allow(
            clippy::useless_conversion,
            reason = "`time_t` is 32 bits on some systems"
        )]
        i64::from(t)
    }

    fn matches_host(&self, name: &CStr) -> bool {
        // SAFETY: the certificate and a C string.
        unsafe { sys::gnutls_x509_crt_check_hostname(self.0.as_ptr(), name.as_ptr()) != 0 }
    }

    fn issued_by(&self, issuer: &Cert) -> bool {
        // SAFETY: two certificates.
        let rc = unsafe { sys::gnutls_x509_crt_check_issuer(self.0.as_ptr(), issuer.0.as_ptr()) };
        // C reads the unsigned answer as an int, `rc <= 0` failing.
        c_int::try_from(rc).is_ok_and(|rc| rc > 0)
    }

    fn key_algorithm(&self) -> Option<&'static [u8]> {
        let mut bits: c_uint = 0;
        // SAFETY: the certificate, and the size to fill in.
        let algo = unsafe { sys::gnutls_x509_crt_get_pk_algorithm(self.0.as_ptr(), &mut bits) };
        // SAFETY: any number; the library's static text or null.
        let name = unsafe { sys::gnutls_pk_algorithm_get_name(algo) };
        // SAFETY: as above.
        unsafe { c_text(name) }
    }

    fn version(&self) -> i32 {
        // SAFETY: the certificate.
        unsafe { sys::gnutls_x509_crt_get_version(self.0.as_ptr()) }
    }

    fn subject(&self) -> Result<Vec<u8>, Rc> {
        let mut d = sys::gnutls_datum_t {
            data: ptr::null_mut(),
            size: 0,
        };
        // SAFETY: the certificate, and a datum it fills with its own
        // allocation.
        let rc = unsafe { sys::gnutls_x509_crt_get_dn2(self.0.as_ptr(), &mut d) };
        dn_text(rc, d)
    }

    fn issuer(&self) -> Result<Vec<u8>, Rc> {
        let mut d = sys::gnutls_datum_t {
            data: ptr::null_mut(),
            size: 0,
        };
        // SAFETY: as above.
        let rc = unsafe { sys::gnutls_x509_crt_get_issuer_dn2(self.0.as_ptr(), &mut d) };
        dn_text(rc, d)
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        let mut k = ptr::null_mut();
        // SAFETY: a pointer to fill in.
        if unsafe { sys::gnutls_pubkey_init(&mut k) } < 0 || k.is_null() {
            return None;
        }
        let key = Pubkey(k);
        // SAFETY: the key and the certificate.
        if unsafe { sys::gnutls_pubkey_import_x509(key.0, self.0.as_ptr(), 0) } < 0 {
            return None;
        }
        let mut len1 = 0usize;
        // SAFETY: the key; no buffer, so only the size.
        let rc = unsafe {
            sys::gnutls_pubkey_export(key.0, sys::GNUTLS_X509_FMT_DER, ptr::null_mut(), &mut len1)
        };
        if rc != sys::GNUTLS_E_SHORT_MEMORY_BUFFER || len1 == 0 {
            return None;
        }
        let mut der: Vec<u8> = Vec::new();
        der.try_reserve_exact(len1).ok()?;
        let mut len2 = len1;
        // SAFETY: room for `len1` bytes, as asked.
        let rc = unsafe {
            sys::gnutls_pubkey_export(
                key.0,
                sys::GNUTLS_X509_FMT_DER,
                der.as_mut_ptr().cast(),
                &mut len2,
            )
        };
        if rc < 0 || len1 != len2 {
            return None;
        }
        // SAFETY: the library wrote `len2` bytes from the start.
        unsafe { der.set_len(len2) };
        Some(der)
    }
}
