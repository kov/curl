//! mbedTLS itself, as `library.rs` asks it: the random number generator,
//! each connection's objects, freed as they go, and the callbacks the
//! library makes during a call.
//!
//! The library's objects are the caller's to allocate: each lives in
//! `Room` of the size and alignment `sys::Layout` gives, zeroed, made
//! once and never moved, so the pointers the library keeps between them
//! (the configuration to the CA chain, the key, the suites and the ALPN
//! names; the context to the configuration) stay good as long as the
//! connection that owns them all.
//!
//! The BIO's and the verify callback's pointer is the connection's
//! `Slot`, made with it and never moved. For the length of each call
//! that may read, write or verify (`with_call`) the slot holds the call's
//! `Call`; it is set before the call and cleared after, the callbacks run
//! only inside that call, on its thread, and nothing else holds the
//! `Call` while they do.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box, try_zeroed};

use crate::library::{self, Call, Chain, KeyCopy, Rc, Resume, Saved, Words};
use crate::sys::{self, Field, Layout, Object, Opaque};

/// The library, as `library::Mbedtls` asks it.
#[derive(Debug)]
pub(crate) struct Real;

/// The library.
pub(crate) static MBEDTLS: Real = Real;

/// The text of a C string the library returns, or none.
///
/// # Safety
/// `p` is null or a C string alive as long as `'a`.
unsafe fn c_text<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: as the caller says.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
}

/// The library's version number (`mbedtls_version_get_number`):
/// `0x03060700` for 3.6.7.
pub(crate) fn version() -> u32 {
    // SAFETY: no requirement.
    unsafe { sys::mbedtls_version_get_number() }
}

/// Its PSA crypto initialised, as C's global init does first
/// (`mbedtls_init`): whether it could.
pub(crate) fn init() -> bool {
    // SAFETY: no requirement; a second call does nothing.
    unsafe { sys::psa_crypto_init() == sys::PSA_SUCCESS }
}

/// Its PSA crypto let go, as C's global cleanup does
/// (`mbedtls_cleanup`).
pub(crate) fn deinit() {
    // SAFETY: no requirement; the library makes nothing new of PSA's
    // until it is initialised again.
    unsafe { sys::mbedtls_psa_crypto_free() };
}

/// Sixteen bytes at the most alignment an object of the library's needs.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Chunk([u8; 16]);

/// Room for one object of the library's, zeroed, at the size and
/// alignment its build gives it. The bytes are never moved: `ptr` points
/// at them as long as the room lives, and nothing reaches them but
/// through it.
struct Room {
    _mem: Vec<Chunk>,
    ptr: NonNull<Opaque>,
}

impl Room {
    fn new(o: Object) -> Result<Room, OutOfMemory> {
        let (size, align) = Layout::size(o);
        assert!(align <= align_of::<Chunk>(), "{o:?} aligns at {align}");
        let n = size.div_ceil(size_of::<Chunk>()).max(1);
        let mut mem = Vec::new();
        mem.try_reserve_exact(n).map_err(|_| OutOfMemory)?;
        for _ in 0..n {
            mem.try_push(Chunk([0; 16]))?;
        }
        let ptr = NonNull::new(mem.as_mut_ptr().cast::<Opaque>()).expect("a vector's room");
        Ok(Room { _mem: mem, ptr })
    }

    fn p(&self) -> *mut Opaque {
        self.ptr.as_ptr()
    }
}

/// A field of an object of the library's, at its offset.
///
/// # Safety
/// `obj` is a live object of the kind `f` is a field of, and `T` the
/// field's type.
unsafe fn field<T>(obj: *const Opaque, f: Field) -> *mut T {
    // SAFETY: as the caller says, the offset is inside the object.
    unsafe {
        obj.cast::<u8>()
            .add(Layout::offset(f))
            .cast::<T>()
            .cast_mut()
    }
}

/// The value of a field of an object of the library's.
///
/// # Safety
/// As `field`'s, the field set.
unsafe fn get<T: Copy>(obj: *const Opaque, f: Field) -> T {
    // SAFETY: as the caller says.
    let at = unsafe { field::<T>(obj, f) };
    // SAFETY: as the caller says: a field of `T`, aligned as the object.
    unsafe { at.read() }
}

/// Set a field of an object of the library's.
///
/// # Safety
/// As `field`'s, nothing else using the object.
unsafe fn set<T>(obj: *mut Opaque, f: Field, value: T) {
    // SAFETY: as the caller says.
    let at = unsafe { field::<T>(obj, f) };
    // SAFETY: as the caller says: a field of `T`, aligned as the object.
    unsafe { at.write(value) }
}

/// The DER of a certificate of the library's (its `raw`), empty if it has
/// none.
///
/// # Safety
/// `crt` is a live certificate, alive as long as `'a`.
unsafe fn raw<'a>(crt: *const Opaque) -> &'a [u8] {
    // SAFETY: as the caller says.
    let len = unsafe { get::<usize>(crt, Field::CrtRawLen) };
    // SAFETY: as the caller says.
    let p = unsafe { get::<*const u8>(crt, Field::CrtRawP) };
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: as the caller says: its `raw` is `len` bytes at `p`.
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// The library's random numbers (C's `rng_context_t`): entropy and the
/// CTR-DRBG seeded from it.
pub(crate) struct Rng {
    entropy: Room,
    drbg: Room,
}

// SAFETY: the generator is called from any thread, which the library
// built with `MBEDTLS_THREADING_C` (checked by `csrc/layout.c`) locks
// for; nothing changes it but those locked calls after it is seeded; it
// is freed once, by its last owner.
unsafe impl Send for Rng {}
// SAFETY: as above.
unsafe impl Sync for Rng {}

impl core::fmt::Debug for Rng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rng")
    }
}

impl Rng {
    fn p(&self) -> *mut c_void {
        self.drbg.p().cast()
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        // SAFETY: initialised by `rng`, freed once, after every session
        // drawing on it (each holds it until it goes).
        unsafe { sys::mbedtls_ctr_drbg_free(self.drbg.p()) };
        // SAFETY: as above; the generator no longer reads it.
        unsafe { sys::mbedtls_entropy_free(self.entropy.p()) };
    }
}

impl library::Explain for Real {
    fn verify_info(&self, flags: u32) -> Words {
        let mut buf = [0u8; 128];
        // SAFETY: a buffer of its length, a C string prefix; the library
        // writes a C string into it.
        unsafe {
            sys::mbedtls_x509_crt_verify_info(
                buf.as_mut_ptr().cast(),
                buf.len(),
                c"".as_ptr(),
                flags,
            )
        };
        Words::new(until_nul(&buf))
    }
}

/// The bytes of `buf` before its first zero byte.
fn until_nul(buf: &[u8]) -> &[u8] {
    buf.split(|&b| b == 0).next().unwrap_or_default()
}

impl library::Mbedtls for Real {
    type Rng = Rng;
    type Conn = Conn;

    fn rng(&self) -> Result<Rng, Rc> {
        let room = |o| Room::new(o).map_err(|OutOfMemory| sys::MBEDTLS_ERR_SSL_ALLOC_FAILED);
        let (entropy, drbg) = (room(Object::Entropy)?, room(Object::CtrDrbg)?);
        // SAFETY: room for each, of the library's size.
        unsafe { sys::mbedtls_ctr_drbg_init(drbg.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_entropy_init(entropy.p()) };
        let rng = Rng { entropy, drbg };
        // SAFETY: the generator, and the entropy its source reads, both
        // initialised and living as long as it; no personalisation.
        let rc = unsafe {
            sys::mbedtls_ctr_drbg_seed(
                rng.drbg.p(),
                sys::mbedtls_entropy_func,
                rng.entropy.p().cast(),
                ptr::null(),
                0,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        // SAFETY: the generator, seeded.
        unsafe {
            sys::mbedtls_ctr_drbg_set_prediction_resistance(
                rng.drbg.p(),
                sys::MBEDTLS_CTR_DRBG_PR_ON,
            )
        };
        Ok(rng)
    }

    fn conn(&self, rng: &TryArc<Rng>) -> Result<Conn, OutOfMemory> {
        let slot = Box::into_raw(try_box(Slot(Cell::new(ptr::null_mut())))?);
        let slot = NonNull::new(slot).expect("a box's pointer");
        let made = (|| {
            Ok::<_, OutOfMemory>(Objects {
                ssl: Room::new(Object::SslContext)?,
                config: Room::new(Object::SslConfig)?,
                cacert: Room::new(Object::X509Crt)?,
                clicert: Room::new(Object::X509Crt)?,
                pk: Room::new(Object::PkContext)?,
                crl: Room::new(Object::X509Crl)?,
            })
        })();
        let objects = match made {
            Ok(o) => o,
            Err(e) => {
                // SAFETY: made by `Box::into_raw` above, and handed to no
                // one.
                drop(unsafe { Box::from_raw(slot.as_ptr()) });
                return Err(e);
            }
        };
        let o = &objects;
        // SAFETY: room for each, of the library's size, initialised once.
        unsafe { sys::mbedtls_ssl_init(o.ssl.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_ssl_config_init(o.config.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_x509_crt_init(o.cacert.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_x509_crt_init(o.clicert.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_pk_init(o.pk.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_x509_crl_init(o.crl.p()) };
        Ok(Conn {
            o: objects,
            rng: rng.clone(),
            slot,
            suites: Vec::new(),
            alpn_names: Vec::new(),
            alpn_list: Vec::new(),
        })
    }

    fn strerror(&self, rc: Rc) -> Words {
        let mut buf = [0u8; 128];
        // SAFETY: a buffer of its length, which the library writes a C
        // string into.
        unsafe { sys::mbedtls_strerror(rc, buf.as_mut_ptr().cast(), buf.len()) };
        Words::new(until_nul(&buf))
    }

    fn suites(&self) -> &'static [i32] {
        // SAFETY: no requirement; the library's static list, ended by 0.
        let list = unsafe { sys::mbedtls_ssl_list_ciphersuites() };
        if list.is_null() {
            return &[];
        }
        let mut n = 0;
        loop {
            // SAFETY: the list goes on to its 0, which is not passed.
            let at = unsafe { list.add(n) };
            // SAFETY: as above.
            if unsafe { at.read() } == 0 {
                break;
            }
            n += 1;
        }
        // SAFETY: `n` numbers before the 0, static.
        unsafe { core::slice::from_raw_parts(list, n) }
    }

    fn suite_name(&self, id: i32) -> &'static [u8] {
        // SAFETY: any number; the library's static name, or a static
        // "unknown".
        let name = unsafe { sys::mbedtls_ssl_get_ciphersuite_name(id) };
        // SAFETY: as above.
        unsafe { c_text(name) }.unwrap_or_default()
    }

    fn public_key(&self, der: &[u8]) -> Result<Vec<u8>, KeyCopy> {
        let copy = Room::new(Object::X509Crt).map_err(|OutOfMemory| KeyCopy::OutOfMemory)?;
        let mut key =
            try_zeroed(sys::PUB_DER_MAX_BYTES).map_err(|OutOfMemory| KeyCopy::OutOfMemory)?;
        let crt = copy.p();
        // SAFETY: room for a certificate.
        unsafe { sys::mbedtls_x509_crt_init(crt) };
        // A copy, as C makes one: the key is written from a certificate
        // of its own.
        // SAFETY: the certificate, and `der`'s bytes, which the library
        // copies.
        let rc = unsafe { sys::mbedtls_x509_crt_parse_der(crt, der.as_ptr(), der.len()) };
        let written = if rc != 0 {
            Err(KeyCopy::Certificate)
        } else {
            // SAFETY: the certificate, parsed: its key a field of it.
            let pk = unsafe { field::<sys::mbedtls_pk_context>(crt, Field::CrtPk) };
            // SAFETY: the key, and a buffer of its length, which the
            // library writes the DER into, at its end.
            let size = unsafe { sys::mbedtls_pk_write_pubkey_der(pk, key.as_mut_ptr(), key.len()) };
            usize::try_from(size)
                .ok()
                .filter(|&s| s > 0 && s <= key.len())
                .ok_or(KeyCopy::Key)
        };
        // SAFETY: initialised above, freed once.
        unsafe { sys::mbedtls_x509_crt_free(crt) };
        let size = written?;
        key.drain(..key.len() - size);
        Ok(key)
    }
}

/// One connection's objects.
struct Objects {
    ssl: Room,
    config: Room,
    cacert: Room,
    clicert: Room,
    pk: Room,
    crl: Room,
}

/// What the callbacks of the call under way reach: the `Call`, or null
/// between calls.
struct Slot(Cell<*mut c_void>);

/// One connection's objects, the library's calls on them.
pub(crate) struct Conn {
    o: Objects,
    /// The generator the configuration and the key draw on.
    rng: TryArc<Rng>,
    slot: NonNull<Slot>,
    /// What the configuration points at, which the library does not copy:
    /// the suites, ended by 0, and the ALPN names as C strings, and the
    /// list of them, ended by null.
    suites: Vec<i32>,
    alpn_names: Vec<Vec<u8>>,
    alpn_list: Vec<*const c_char>,
}

// SAFETY: the connection's objects are its own, used from one thread at a
// time, which `&mut self` ensures for every call that changes them, and
// the library lets them move between threads; the generator is `Sync`.
unsafe impl Send for Conn {}

impl Drop for Conn {
    fn drop(&mut self) {
        let o = &self.o;
        // SAFETY: each initialised by `conn`, freed once: the context
        // first, which points at the configuration, then the
        // configuration, which points at the others.
        unsafe { sys::mbedtls_ssl_free(o.ssl.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_ssl_config_free(o.config.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_x509_crl_free(o.crl.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_x509_crt_free(o.cacert.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_x509_crt_free(o.clicert.p()) };
        // SAFETY: as above.
        unsafe { sys::mbedtls_pk_free(o.pk.p()) };
        // SAFETY: made by `Box::into_raw` in `conn`, freed once; the
        // context that pointed at it is gone.
        drop(unsafe { Box::from_raw(self.slot.as_ptr()) });
    }
}

impl Conn {
    fn ssl(&self) -> *mut Opaque {
        self.o.ssl.p()
    }

    fn conf(&self) -> *mut Opaque {
        self.o.config.p()
    }

    fn slot_ptr(&self) -> *mut c_void {
        self.slot.as_ptr().cast()
    }

    /// Run `op`, a call on the connection, with `call` what its callbacks
    /// reach: set before, cleared after. `op` must not reach `call`
    /// itself.
    fn with_call<R>(&mut self, call: &mut Call<'_, '_>, op: impl FnOnce(*mut Opaque) -> R) -> R {
        let p: *mut Call<'_, '_> = call;
        // SAFETY: the slot, alive as long as the connection.
        let slot = unsafe { self.slot.as_ref() };
        slot.0.set(p.cast());
        let r = op(self.ssl());
        slot.0.set(ptr::null_mut());
        r
    }
}

/// The call under way, from the pointer the library hands a callback.
///
/// # Safety
/// Only from a callback of the library during `with_call`: the pointer is
/// the connection's slot, which then holds a live `Call` no one else is
/// using, or null.
unsafe fn call_of<'r>(p: *mut c_void) -> Option<&'r mut Call<'r, 'r>> {
    // SAFETY: as the caller says: the slot lives as long as the
    // connection, longer than the callback.
    let slot = unsafe { p.cast::<Slot>().as_ref() }?;
    // SAFETY: as the caller says; the lifetimes are the callback's,
    // shorter than the call's, and nothing is stored in it.
    unsafe { slot.0.get().cast::<Call<'r, 'r>>().as_mut() }
}

/// The library writes `len` bytes from `buf` (`mbedtls_bio_cf_write`).
unsafe extern "C" fn bio_send(p: *mut c_void, buf: *const u8, len: usize) -> c_int {
    // SAFETY: called back during `with_call`.
    let Some(call) = (unsafe { call_of(p) }) else {
        return 0;
    };
    let bytes = if len == 0 || buf.is_null() {
        &[][..]
    } else {
        // SAFETY: the library hands `len` bytes at `buf`, alive and not
        // written to for the callback's length.
        unsafe { core::slice::from_raw_parts(buf, len) }
    };
    call.send(bytes).rc(sys::MBEDTLS_ERR_SSL_WANT_WRITE)
}

/// The library reads up to `len` bytes into `buf` (`mbedtls_bio_cf_read`).
unsafe extern "C" fn bio_recv(p: *mut c_void, buf: *mut u8, len: usize) -> c_int {
    // SAFETY: called back during `with_call`.
    let Some(call) = (unsafe { call_of(p) }) else {
        return 0;
    };
    // OpenSSL catches this case, so C does too.
    if buf.is_null() {
        return 0;
    }
    let room = if len == 0 {
        &mut [][..]
    } else {
        // SAFETY: the library hands `len` bytes of room at `buf`.
        unsafe { core::slice::from_raw_parts_mut(buf, len) }
    };
    call.recv(room).rc(sys::MBEDTLS_ERR_SSL_WANT_READ)
}

/// The library checked a certificate of the peer's chain
/// (`mbed_verify_cb`).
unsafe extern "C" fn verify_cb(
    p: *mut c_void,
    crt: *mut sys::mbedtls_x509_crt,
    depth: c_int,
    flags: *mut u32,
) -> c_int {
    // SAFETY: called back during `with_call`, from the handshake.
    let Some(call) = (unsafe { call_of(p) }) else {
        return 0;
    };
    // SAFETY: the library's flags, ours to change for the callback's
    // length.
    let Some(flags) = (unsafe { flags.as_mut() }) else {
        return 0;
    };
    let Some(crt) = NonNull::new(crt) else {
        return 0;
    };
    call.verify(depth, &Crt(crt), flags);
    0
}

/// A certificate of the library's, and those after it in its chain,
/// alive for the callback's length.
struct Crt(NonNull<sys::mbedtls_x509_crt>);

impl Chain for Crt {
    fn info(&self) -> Option<Vec<u8>> {
        let mut buf = try_zeroed(16384).ok()?;
        // SAFETY: a buffer of its length, a C string prefix, and the
        // certificate.
        let n = unsafe {
            sys::mbedtls_x509_crt_info(
                buf.as_mut_ptr().cast(),
                buf.len(),
                c" ".as_ptr(),
                self.0.as_ptr(),
            )
        };
        let n = usize::try_from(n).ok().filter(|&n| n > 0)?;
        buf.truncate(n.min(buf.len()));
        Some(buf)
    }

    fn ders(&self, most: usize) -> Result<Vec<&[u8]>, OutOfMemory> {
        let mut ders = Vec::new();
        let mut cur: *const Opaque = self.0.as_ptr();
        while !cur.is_null() && ders.len() < most {
            // SAFETY: a certificate of the chain, alive for the callback.
            let der = unsafe { raw(cur) };
            ders.try_push(der)?;
            // SAFETY: as above; the next of the chain, or null.
            cur = unsafe { get::<*const Opaque>(cur, Field::CrtNext) };
        }
        Ok(ders)
    }
}

impl library::Conn for Conn {
    fn ca_parse(&mut self, data: &[u8]) -> Rc {
        // SAFETY: the CA chain, and bytes the library copies.
        unsafe { sys::mbedtls_x509_crt_parse(self.o.cacert.p(), data.as_ptr(), data.len()) }
    }

    fn ca_parse_file(&mut self, file: &CStr) -> Rc {
        // SAFETY: the CA chain, and a C string.
        unsafe { sys::mbedtls_x509_crt_parse_file(self.o.cacert.p(), file.as_ptr()) }
    }

    fn ca_parse_path(&mut self, dir: &CStr) -> Rc {
        // SAFETY: as above.
        unsafe { sys::mbedtls_x509_crt_parse_path(self.o.cacert.p(), dir.as_ptr()) }
    }

    fn cert_parse_file(&mut self, file: &CStr) -> Rc {
        // SAFETY: the client's certificate, and a C string.
        unsafe { sys::mbedtls_x509_crt_parse_file(self.o.clicert.p(), file.as_ptr()) }
    }

    fn cert_parse(&mut self, data: &[u8]) -> Rc {
        // SAFETY: the client's certificate, and bytes the library copies.
        unsafe { sys::mbedtls_x509_crt_parse(self.o.clicert.p(), data.as_ptr(), data.len()) }
    }

    fn key_parse_file(&mut self, file: &CStr, password: Option<&CStr>) -> Rc {
        let pass = password.map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: the key, C strings or null, and the generator, alive as
        // long as the connection.
        unsafe {
            sys::mbedtls_pk_parse_keyfile(
                self.o.pk.p(),
                file.as_ptr(),
                pass,
                sys::mbedtls_ctr_drbg_random,
                self.rng.p(),
            )
        }
    }

    fn key_parse(&mut self, key: &[u8], password: Option<&[u8]>) -> Rc {
        let (pass, pass_len) = password.map_or((ptr::null(), 0), |p| (p.as_ptr(), p.len()));
        // SAFETY: the key, bytes the library reads for the call, and the
        // generator, alive as long as the connection.
        unsafe {
            sys::mbedtls_pk_parse_key(
                self.o.pk.p(),
                key.as_ptr(),
                key.len(),
                pass,
                pass_len,
                sys::mbedtls_ctr_drbg_random,
                self.rng.p(),
            )
        }
    }

    fn key_signs(&self) -> bool {
        // SAFETY: the key.
        let can = |kind| unsafe { sys::mbedtls_pk_can_do(self.o.pk.p(), kind) } != 0;
        can(sys::MBEDTLS_PK_RSA) || can(sys::MBEDTLS_PK_ECKEY)
    }

    fn crl_parse_file(&mut self, file: &CStr) -> Rc {
        // SAFETY: the revocation list, and a C string.
        unsafe { sys::mbedtls_x509_crl_parse_file(self.o.crl.p(), file.as_ptr()) }
    }

    fn defaults(&mut self) -> Rc {
        // SAFETY: the configuration.
        unsafe {
            sys::mbedtls_ssl_config_defaults(
                self.conf(),
                sys::MBEDTLS_SSL_IS_CLIENT,
                sys::MBEDTLS_SSL_TRANSPORT_STREAM,
                sys::MBEDTLS_SSL_PRESET_DEFAULT,
            )
        }
    }

    fn signal_tickets(&mut self) {
        #[cfg(mbedtls_signal_tickets)]
        // SAFETY: the configuration.
        unsafe {
            sys::mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(
                self.conf(),
                sys::MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED,
            );
        }
    }

    fn verify_hook(&mut self) {
        // SAFETY: the configuration, a callback of the library's
        // signature, and the slot, alive as long as the connection.
        unsafe { sys::mbedtls_ssl_conf_verify(self.conf(), verify_cb, self.slot_ptr()) };
    }

    fn verify_required(&mut self) {
        // SAFETY: the configuration.
        unsafe { sys::mbedtls_ssl_conf_authmode(self.conf(), sys::MBEDTLS_SSL_VERIFY_REQUIRED) };
    }

    fn profile_next(&mut self) {
        // SAFETY: the configuration, and the library's static profile.
        unsafe {
            sys::mbedtls_ssl_conf_cert_profile(
                self.conf(),
                &raw const sys::mbedtls_x509_crt_profile_next,
            )
        };
    }

    fn versions(&mut self, min: i32, max: i32) {
        // What the inline `mbedtls_ssl_conf_min_tls_version` and
        // `..._max_...` set, at the offsets the headers give.
        // SAFETY: the configuration, and its fields, `int`s.
        unsafe { set::<c_int>(self.conf(), Field::ConfMinVersion, min) };
        // SAFETY: as above.
        unsafe { set::<c_int>(self.conf(), Field::ConfMaxVersion, max) };
    }

    fn use_rng(&mut self) {
        // SAFETY: the configuration, and the generator, alive as long as
        // the connection.
        unsafe {
            sys::mbedtls_ssl_conf_rng(self.conf(), sys::mbedtls_ctr_drbg_random, self.rng.p())
        };
    }

    fn setup(&mut self) -> Rc {
        // SAFETY: the context and the configuration, which outlives it.
        unsafe { sys::mbedtls_ssl_setup(self.ssl(), self.conf()) }
    }

    fn bio(&mut self) {
        // SAFETY: the context, callbacks of the library's signature, and
        // the slot, alive as long as the connection.
        unsafe {
            sys::mbedtls_ssl_set_bio(
                self.ssl(),
                self.slot_ptr(),
                Some(bio_send),
                Some(bio_recv),
                None,
            )
        };
    }

    fn ciphersuites(&mut self, suites: Vec<i32>) -> Result<(), OutOfMemory> {
        assert_eq!(suites.last(), Some(&0), "a list ended by 0");
        self.suites = suites;
        // SAFETY: the configuration, and the list, which the connection
        // keeps unchanged as long as it.
        unsafe { sys::mbedtls_ssl_conf_ciphersuites(self.conf(), self.suites.as_ptr()) };
        Ok(())
    }

    fn default_ciphersuites(&mut self) {
        // SAFETY: no requirement; the library's static list.
        let list = unsafe { sys::mbedtls_ssl_list_ciphersuites() };
        // SAFETY: the configuration, and the static list.
        unsafe { sys::mbedtls_ssl_conf_ciphersuites(self.conf(), list) };
    }

    fn renegotiation(&mut self) {
        // SAFETY: the configuration.
        unsafe {
            sys::mbedtls_ssl_conf_renegotiation(self.conf(), sys::MBEDTLS_SSL_RENEGOTIATION_ENABLED)
        };
    }

    fn tickets_off(&mut self) {
        // SAFETY: the configuration.
        unsafe {
            sys::mbedtls_ssl_conf_session_tickets(
                self.conf(),
                sys::MBEDTLS_SSL_SESSION_TICKETS_DISABLED,
            )
        };
    }

    fn resume(&mut self, data: &[u8]) -> Resume {
        // C's session is on its stack; out of room here, it is the
        // library's own failure to allocate.
        let Ok(room) = Room::new(Object::SslSession) else {
            return Resume::Load(sys::MBEDTLS_ERR_SSL_ALLOC_FAILED);
        };
        let s = room.p();
        // SAFETY: room for a session.
        unsafe { sys::mbedtls_ssl_session_init(s) };
        // SAFETY: the session, and the bytes the library reads for the
        // call.
        let rc = unsafe { sys::mbedtls_ssl_session_load(s, data.as_ptr(), data.len()) };
        let done = if rc != 0 {
            Resume::Load(rc)
        } else {
            // SAFETY: the context, and the session, which it copies.
            match unsafe { sys::mbedtls_ssl_set_session(self.ssl(), s) } {
                0 => Resume::Done,
                rc => Resume::Set(rc),
            }
        };
        // SAFETY: initialised above, freed once.
        unsafe { sys::mbedtls_ssl_session_free(s) };
        done
    }

    fn ca_chain(&mut self) {
        // SAFETY: the configuration, and the chain and list, which live as
        // long as it.
        unsafe { sys::mbedtls_ssl_conf_ca_chain(self.conf(), self.o.cacert.p(), self.o.crl.p()) };
    }

    fn own_cert(&mut self) {
        // SAFETY: the configuration, and the certificate and key, which
        // live as long as it. C does not look at what it answers: a key
        // the library takes no certificate with fails the handshake.
        let _answer: c_int = unsafe {
            sys::mbedtls_ssl_conf_own_cert(self.conf(), self.o.clicert.p(), self.o.pk.p())
        };
    }

    fn hostname(&mut self, name: &CStr) -> Rc {
        // SAFETY: the context, and a C string, which the library copies.
        unsafe { sys::mbedtls_ssl_set_hostname(self.ssl(), name.as_ptr()) }
    }

    fn alpn(&mut self, names: &[&[u8]]) -> Result<Rc, OutOfMemory> {
        let mut owned = Vec::new();
        for name in names {
            let c = library::c_string(name).map_err(|_| OutOfMemory)?;
            owned.try_push(c)?;
        }
        let mut list = Vec::new();
        list.try_reserve_exact(owned.len() + 1)
            .map_err(|_| OutOfMemory)?;
        for name in &owned {
            list.try_push(name.as_ptr().cast::<c_char>())?;
        }
        list.try_push(ptr::null())?;
        self.alpn_names = owned;
        self.alpn_list = list;
        // SAFETY: the configuration, and a list of C strings ended by
        // null, which the connection keeps unchanged as long as it.
        Ok(unsafe {
            sys::mbedtls_ssl_conf_alpn_protocols(self.conf(), self.alpn_list.as_mut_ptr())
        })
    }

    fn config(&self) -> NonNull<c_void> {
        self.o.config.ptr.cast()
    }

    fn native(&self) -> NonNull<c_void> {
        self.o.ssl.ptr.cast()
    }

    fn handshake(&mut self, call: &mut Call<'_, '_>) -> Rc {
        // SAFETY: the context, set up, during the call's slot.
        self.with_call(call, |ssl| unsafe { sys::mbedtls_ssl_handshake(ssl) })
    }

    fn read(&mut self, call: &mut Call<'_, '_>, buf: &mut [u8]) -> Rc {
        // SAFETY: the context, and room for `buf.len()` bytes, during the
        // call's slot.
        self.with_call(call, |ssl| unsafe {
            sys::mbedtls_ssl_read(ssl, buf.as_mut_ptr(), buf.len())
        })
    }

    fn write(&mut self, call: &mut Call<'_, '_>, bytes: &[u8]) -> Rc {
        // SAFETY: the context, and `bytes`, during the call's slot.
        self.with_call(call, |ssl| unsafe {
            sys::mbedtls_ssl_write(ssl, bytes.as_ptr(), bytes.len())
        })
    }

    fn close_notify(&mut self, call: &mut Call<'_, '_>) -> Rc {
        // SAFETY: the context, during the call's slot.
        self.with_call(call, |ssl| unsafe { sys::mbedtls_ssl_close_notify(ssl) })
    }

    fn suite(&self) -> i32 {
        // SAFETY: the context.
        unsafe { sys::mbedtls_ssl_get_ciphersuite_id_from_ssl(self.ssl()) }
    }

    fn version_name(&self) -> &'static [u8] {
        // SAFETY: the context; the name is the library's static text.
        let name = unsafe { sys::mbedtls_ssl_get_version(self.ssl()) };
        // SAFETY: as above.
        unsafe { c_text(name) }.unwrap_or_default()
    }

    fn version(&self) -> i32 {
        // What the inline `mbedtls_ssl_get_version_number` reads.
        // SAFETY: the context, and its field, an `int`.
        unsafe { get::<c_int>(self.ssl(), Field::SslVersion) }
    }

    fn alpn_selected(&self) -> Option<&[u8]> {
        // SAFETY: the context; the name is one of the list it was given,
        // which the connection keeps, or null.
        let name = unsafe { sys::mbedtls_ssl_get_alpn_protocol(self.ssl()) };
        // SAFETY: as above.
        unsafe { c_text(name) }
    }

    fn peer_cert(&self) -> Option<&[u8]> {
        // SAFETY: the context; the certificate is its own, kept until it
        // goes, or null.
        let crt = unsafe { sys::mbedtls_ssl_get_peer_cert(self.ssl()) };
        if crt.is_null() {
            return None;
        }
        // SAFETY: as above.
        let der = unsafe { raw(crt) };
        (!der.is_empty()).then_some(der)
    }

    fn saved(&mut self) -> Result<Saved, OutOfMemory> {
        let room = Room::new(Object::SslSession)?;
        let s = room.p();
        // SAFETY: room for a session.
        unsafe { sys::mbedtls_ssl_session_init(s) };
        // SAFETY: the context, and the session to copy it into.
        let rc = unsafe { sys::mbedtls_ssl_get_session(self.ssl(), s) };
        let saved = if rc != 0 {
            Ok(Saved::GetFailed(rc))
        } else {
            let mut len = 0usize;
            // Its length, which the library says as it fails for want of
            // room.
            // SAFETY: the session; no buffer, and its length.
            let _short: c_int =
                unsafe { sys::mbedtls_ssl_session_save(s, ptr::null_mut(), 0, &mut len) };
            if len == 0 {
                Ok(Saved::Empty)
            } else {
                match try_zeroed(len) {
                    Err(e) => Err(e),
                    Ok(mut data) => {
                        // SAFETY: the session, and a buffer of its length.
                        let rc = unsafe {
                            sys::mbedtls_ssl_session_save(
                                s,
                                data.as_mut_ptr(),
                                data.len(),
                                &mut len,
                            )
                        };
                        if rc != 0 {
                            Ok(Saved::SaveFailed(rc))
                        } else {
                            data.truncate(len);
                            Ok(Saved::Data(data))
                        }
                    }
                }
            }
        };
        // A session the library had no room to copy into is not freed,
        // as C does not free it (`msession_alloced`).
        if rc != sys::MBEDTLS_ERR_SSL_ALLOC_FAILED {
            // SAFETY: initialised above, freed once.
            unsafe { sys::mbedtls_ssl_session_free(s) };
        }
        saved
    }

    fn pending(&self) -> bool {
        // SAFETY: the context.
        unsafe { sys::mbedtls_ssl_get_bytes_avail(self.ssl()) != 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::{Explain as _, Mbedtls as _};

    /// The real library: initialised, it seeds a generator, makes and
    /// frees a connection's objects, names its suites (TLS 1.3's among
    /// them) and says its numbers and flags in its words.
    #[test]
    // Calls into C, which Miri cannot run.
    #[cfg_attr(miri, ignore)]
    fn the_library_makes_and_says_what_c_s_build_asks_of_it() {
        assert!(init());
        let rng = TryArc::try_new(MBEDTLS.rng().expect("seeded")).unwrap();
        let conn = MBEDTLS.conn(&rng).expect("room");
        drop(conn);
        let suites = MBEDTLS.suites();
        assert!(!suites.is_empty());
        assert!(
            suites
                .iter()
                .any(|&id| MBEDTLS.suite_name(id).starts_with(b"TLS1-3"))
        );
        assert_eq!(
            MBEDTLS
                .strerror(sys::MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
                .bytes(),
            b"X509 - Certificate verification failed, e.g. CRL, CA or signature check failed"
        );
        assert_eq!(
            MBEDTLS
                .verify_info(sys::MBEDTLS_X509_BADCERT_CN_MISMATCH)
                .bytes(),
            b"The certificate Common Name (CN) does not match with the expected CN\n"
        );
        assert_eq!(version() >> 24, 3);
        backend_over_the_library();
    }

    /// The backend makes sessions only between its `init` and its
    /// `cleanup`, and names the library as C does. Run from the test
    /// above, as the library's initialisation is the process's.
    fn backend_over_the_library() {
        use curl_core::options::{ColdGroup as _, TlsOptions};
        use curl_core::tls::{
            Alpn, CaDefaults, TlsBackend as _, TlsIdentity, TlsPeer, TlsPeerKind, TlsShared,
        };
        let id = TryArc::try_new(TlsIdentity {
            verify_peer: true,
            verify_host: true,
            options: TlsOptions::NONE,
            ca_defaults: CaDefaults::NONE,
        })
        .unwrap();
        let peer = TlsPeer {
            name: b"example.com",
            port: 443,
            kind: TlsPeerKind::Name,
            early_data: false,
            ech_configs: None,
        };
        let shared = TlsShared::testing();
        let tls = crate::MbedTls::new();
        let made = |tls: &crate::MbedTls| tls.session(&id, &peer, Alpn::None, &shared).err();
        assert_eq!(made(&tls), Some(curl_core::error::ErrorKind::FailedInit));
        assert!(tls.init());
        assert_eq!(made(&tls), None);
        let named = format!("mbedTLS/{}.{}.", version() >> 24, (version() >> 16) & 0xff);
        assert!(crate::version().to_string().starts_with(&named), "{named}");
        assert_eq!(tls.id().to_string(), crate::version().to_string());
        tls.cleanup();
        assert_eq!(made(&tls), Some(curl_core::error::ErrorKind::FailedInit));
    }
}
