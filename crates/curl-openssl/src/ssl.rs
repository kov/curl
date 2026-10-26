//! OpenSSL as the core's TLS library (`lib/vtls/openssl.c`): a session per
//! connection, its context and SSL made at the first step of the
//! handshake as C makes them (`ossl_connect_step1`, `Curl_ossl_ctx_init`),
//! the handshake (`ossl_connect_step2`), the peer's certificate checked
//! (`ossl_connect_step3`), then the records both ways (`ossl_recv`,
//! `ossl_send`).

#![allow(unsafe_code)]

use core::ffi::{c_int, c_long, c_ulong, c_void};
use core::ptr::{self, NonNull};
use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::{SslOptions, TlsMaxVersion, TlsMinVersion};
use curl_core::tls::{
    Alpn, CaDefaults, Chosen, Deferred, Handshake, HandshakeCheck, KeyLog, QuicTls, SharedKeyLog,
    TlsBackend, TlsCx, TlsIdentity, TlsIo, TlsNative, TlsPeer, TlsPeerKind, TlsSession, TlsShared,
    TlsTicket, TlsWait,
};
use curl_os::error::ErrorText;
use openssl_sys::{SSL, SSL_CTX, SSL_SESSION};

use crate::bio::{self, Below, Flags, Method, Slot};
use crate::engine::Crypto;
use crate::ffi;
use crate::text;
use crate::x509::{self, ErrText};

/// The CA bundle and path the build found (`build.rs`).
mod ca {
    include!(concat!(env!("OUT_DIR"), "/ca.rs"));
}

/// OpenSSL, as the core's TLS library, logging the secrets of its
/// connections to a key log if it is given one. Each session it makes
/// holds the key log too, so it lasts as long as the session.
#[derive(Debug)]
pub struct OpenSsl {
    keylog: Option<SharedKeyLog>,
}

/// OpenSSL, logging no secrets.
pub static OPENSSL: OpenSsl = OpenSsl { keylog: None };

impl OpenSsl {
    /// OpenSSL logging the secrets of its connections to `keylog`
    /// (`SSLKEYLOGFILE`) while it is open.
    pub const fn logging_keys_to(keylog: SharedKeyLog) -> OpenSsl {
        OpenSsl {
            keylog: Some(keylog),
        }
    }
}

/// The library's name and version, as `version` says it.
struct Id;

impl core::fmt::Display for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", crate::sys::version())
    }
}

impl TlsBackend for OpenSsl {
    fn id(&self) -> &dyn core::fmt::Display {
        &Id
    }

    fn session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        shared: &TlsShared,
    ) -> Result<Box<dyn TlsSession>, ErrorKind> {
        // A library this build does not work with is one it does not
        // have: what the shim and the tool name is checked at their init.
        crate::sys::ready().map_err(|_| ErrorKind::SslConnectError)?;
        let session = self.new_session(identity, peer, alpn, shared, false)?;
        Ok(try_box(session).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?)
    }

    /// A QUIC connection's session, its context and SSL made at once
    /// (`Curl_ossl_ctx_init` with QUIC's transport).
    fn quic_session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        shared: &TlsShared,
        cx: &mut TlsCx<'_>,
    ) -> Result<Box<dyn QuicTls>, ErrorKind> {
        crate::sys::ready().map_err(|_| ErrorKind::QuicConnectError)?;
        let mut session = self.new_session(identity, peer, Alpn::H3, shared, true)?;
        session.make(cx)?;
        // The BIO is never read or written: the QUIC library carries the
        // records. It carries what the callbacks reach, as a stream
        // session's does.
        session.attach_bio()?;
        Ok(try_box(QuicSession(session)).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?)
    }

    fn ca_defaults(&self) -> CaDefaults {
        CaDefaults {
            file: ca::CA_BUNDLE,
            path: ca::CA_PATH,
        }
    }

    /// The engines of the library, made ready first, which loads its
    /// built-in ones; none for a library this build does not work with.
    fn engines(&self) -> Result<Vec<Vec<u8>>, OutOfMemory> {
        match crate::sys::ready() {
            Ok(()) => crate::engine::ids(),
            Err(_) => Ok(Vec::new()),
        }
    }
}

impl OpenSsl {
    /// A session for one connection to `peer`, over QUIC if `quic`,
    /// nothing of the library's made yet.
    fn new_session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        shared: &TlsShared,
        quic: bool,
    ) -> Result<Session, ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(peer.name)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        Ok(Session {
            ssl: None,
            ctx: None,
            password: None,
            crypto: Crypto::default(),
            method: None,
            identity: identity.clone(),
            shared: Some(shared.clone()),
            host,
            port: peer.port,
            kind: peer.kind,
            alpn,
            step: Step::Init,
            flags: Flags::default(),
            waits: TlsWait::Nothing,
            blocked_write: None,
            shut: false,
            keylog: self.keylog.clone(),
            reused: false,
            // QUIC's early data is the QUIC library's to send.
            early_data: peer.early_data && !quic,
            deferred: None,
            early: Early::None,
            quic,
            resumed: None,
        })
    }
}

/// An `SSL_CTX` this crate made, freed as it goes.
struct Ctx(NonNull<SSL_CTX>);

/// An `SSL` this crate made, and the BIO it owns, freed as it goes.
struct Ssl(NonNull<SSL>);

// SAFETY: OpenSSL lets an SSL and its context be used from any thread,
// one thread at a time, which a session's `&mut self` ensures; the
// session moves between threads only whole.
unsafe impl Send for Ctx {}
// SAFETY: as above.
unsafe impl Send for Ssl {}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: made by `SSL_CTX_new`, freed once; an SSL made of it
        // holds a reference of its own.
        unsafe { openssl_sys::SSL_CTX_free(self.0.as_ptr()) };
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        // SAFETY: made by `SSL_new`, freed once, with its BIO, whose
        // method the session drops after it.
        unsafe { openssl_sys::SSL_free(self.0.as_ptr()) };
    }
}

/// Where a handshake put off for early data is (`earlydata_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Early {
    /// None put off, or it waits for its early data.
    None,
    /// Writing it, this much written.
    Sending(usize),
    /// Written, the handshake going on.
    Sent,
    /// The handshake is done, the peer taking the early data or not.
    Over { accepted: bool },
}

/// How far a session's handshake has come (`connecting_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Nothing made yet: the context and SSL are made at the first step.
    Init,
    /// The handshake runs.
    Handshake,
    /// The handshake is done; the peer's certificate is to be checked.
    Check,
    Done,
}

/// One connection's OpenSSL.
struct Session {
    // Dropped in this order: the SSL, which frees its BIO, before the
    // BIO's method; the context after the SSL made of it.
    ssl: Option<Ssl>,
    ctx: Option<Ctx>,
    /// The client key's password as a C string, which the context points
    /// at: dropped after it.
    password: Option<Vec<u8>>,
    /// The engine or provider the context was made with: dropped after
    /// it.
    crypto: Crypto,
    method: Option<Method>,
    identity: TryArc<TlsIdentity>,
    /// What the library keeps for the multi, until the trust store is
    /// set up: the store it may take, and keep its own in.
    shared: Option<TlsShared>,
    /// The origin's name as the URL gives it, without brackets.
    host: Vec<u8>,
    port: u16,
    kind: TlsPeerKind,
    alpn: Alpn,
    step: Step,
    flags: Flags,
    waits: TlsWait,
    /// The length of a write the library could not finish, which it must
    /// be given again (`blocked_ssl_write_len`).
    blocked_write: Option<c_int>,
    /// The goodbye is over, or failed (the filter's `shutdown`).
    shut: bool,
    /// Where the secrets are logged, if anywhere.
    keylog: Option<SharedKeyLog>,
    /// The handshake resumes a session the cache kept
    /// (`reused_session`).
    reused: bool,
    /// The transfer may send early data.
    early_data: bool,
    /// The handshake is put off for early data, as the session resumed
    /// allows (`ssl_connection_deferred`).
    deferred: Option<Deferred>,
    early: Early,
    /// A QUIC connection's: the QUIC library carries its records, and
    /// TLS 1.3 is the least it speaks (`TRNSPRT_QUIC`).
    quic: bool,
    /// A QUIC connection's session the cache kept, which it resumes:
    /// kept here for the early data it allows, as TLS 1.3's are taken
    /// from the cache to serve one connection.
    resumed: Option<TlsTicket>,
}

/// The library's major error codes C tells apart.
pub(crate) fn error_lib(e: c_ulong) -> c_int {
    // `ERR_GET_LIB`: the library is the 8 bits above the 23 of the
    // reason, unless the error is a system error.
    if e & (1 << 31) != 0 {
        2
    } else {
        ((e >> 23) & 0xff) as c_int
    }
}

/// `ERR_GET_REASON`.
pub(crate) fn error_reason(e: c_ulong) -> c_int {
    if e & (1 << 31) != 0 {
        (e & 0x7fff_ffff) as c_int
    } else {
        (e & 0x7f_ffff) as c_int
    }
}

/// A C string of `bytes`, for a call that takes one.
fn c_string(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut c = Vec::new();
    c.try_reserve_exact(bytes.len() + 1)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    c.try_extend_from_slice(bytes)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    c.try_push(0)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    Ok(c)
}

/// Bytes as C's `%s` shows them.
struct Text<'a>(&'a [u8]);

impl core::fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for &b in chunk.invalid() {
                write!(f, "{}", char::from(b))?;
            }
        }
        Ok(())
    }
}

/// An error the session said why it failed for: what the core reads as
/// the read's or the send's failure, its reason given already.
fn said(errno: i32) -> io::Error {
    if errno != 0 {
        io::Error::from_raw_os_error(errno)
    } else {
        io::ErrorKind::Other.into()
    }
}

/// The error number of the socket's last failure below, if it failed
/// (C reads `errno` there).
fn errno_of(below: Below) -> i32 {
    match below {
        Below::Failed(n) => n,
        Below::Ok | Below::Again | Below::Store(_) => 0,
    }
}

impl Session {
    /// Run `op` on the SSL with the BIO reaching `io` (`bio::call`).
    fn call<R>(&mut self, io: &mut TlsIo<'_>, op: impl FnOnce(*mut SSL) -> R) -> (R, Below) {
        let ssl = self.ssl.as_ref().expect("made at the first step").0;
        let ctx = self.ctx.as_ref().expect("made at the first step").0;
        let identity = &self.identity;
        let shared = self.shared.as_ref();
        let mut setup = |cx: &mut TlsCx<'_>| x509::setup_store(ctx, identity, shared, cx);
        let mut slot = Slot {
            io: bio::Reach::Stream(io),
            flags: &mut self.flags,
            below: Below::Ok,
            store: &mut setup,
            keylog: self.keylog.as_deref(),
            quic_params: None,
        };
        let r = bio::call(ssl, &mut slot, op);
        (r, slot.below)
    }

    fn ssl(&self) -> NonNull<SSL> {
        self.ssl.as_ref().expect("made at the first step").0
    }

    /// Make the context and the SSL, reading and writing through the
    /// layers below, as C does (`ossl_connect_step1`).
    fn step1(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        self.make(io)?;
        self.attach_bio()?;
        if let Some(offer) = self.alpn.offer().filter(|_| self.deferred.is_none()) {
            io.info(format_args!("ALPN: curl offers {offer}"));
        }
        Ok(())
    }

    /// Give the SSL a BIO of this crate's, which reads and writes through
    /// the layers below a stream session and carries what the callbacks
    /// reach (`ossl_bio_cf_method_create`).
    fn attach_bio(&mut self) -> Result<(), ErrorKind> {
        let ssl = self.ssl();
        let method = Method::new().ok_or(ErrorKind::OutOfMemory)?;
        let bio = method.bio().ok_or(ErrorKind::OutOfMemory)?;
        self.method = Some(method);
        // The SSL takes a reference to the BIO for each of its ends, the
        // second taken here, and frees them with itself.
        // SAFETY: a BIO just made.
        unsafe { ffi::BIO_up_ref(bio.as_ptr()) };
        // SAFETY: the SSL, and a reference to the BIO it now owns.
        unsafe { ffi::SSL_set0_rbio(ssl.as_ptr(), bio.as_ptr()) };
        // SAFETY: as above, the other reference.
        unsafe { ffi::SSL_set0_wbio(ssl.as_ptr(), bio.as_ptr()) };
        Ok(())
    }

    /// Make the context and the SSL as C does (`Curl_ossl_ctx_init`): for
    /// a stream, or for QUIC.
    fn make(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        // SAFETY: asks the library whether it is seeded.
        if unsafe { openssl_sys::RAND_status() } == 0 {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("Insufficient randomness"),
            ));
        }
        let identity = self.identity.clone();
        let options = &identity.options;
        if let Some(name) = options.engine.as_deref() {
            self.crypto = Crypto::select(name, io)?;
        }
        if options.engine_default {
            self.crypto.set_default(io)?;
        }
        if self.crypto.has_libctx() {
            // A store loaded in a provider's library context cannot
            // outlive it in the multi (`USING_PROVIDER`).
            self.shared = None;
        }
        // Not verified until the peer is checked (`!X509_V_OK`).
        io.verified(1);
        // QUIC speaks TLS 1.3 at least, which the transfer may not cap
        // lower (`ossl_init_method`).
        if self.quic
            && !matches!(
                options.max_version,
                TlsMaxVersion::None | TlsMaxVersion::Default | TlsMaxVersion::Tls1_3
            )
        {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("QUIC needs at least TLS version 1.3"),
            ));
        }
        let min_version = if self.quic {
            TlsMinVersion::Tls1_3
        } else {
            options.min_version
        };
        let method = if self.quic {
            // SAFETY: the library's static method.
            unsafe { openssl_sys::TLS_method() }
        } else {
            // SAFETY: the library's static client method.
            unsafe { openssl_sys::TLS_client_method() }
        };
        // A context of that method, owned by `Ctx` below.
        let ctx = self.crypto.new_ctx(method);
        let Some(ctx) = NonNull::new(ctx) else {
            // SAFETY: the thread's error queue, looked at.
            let e = ErrText::of(unsafe { ffi::ERR_peek_error() });
            return Err(io.fail(
                ErrorKind::OutOfMemory,
                format_args!("SSL: could not create a context: {e}"),
            ));
        };
        self.ctx = Some(Ctx(ctx));
        // QUIC's records are not TLS's, which the trace reads.
        if io.debugs() && !self.quic {
            // SAFETY: the context, and a callback of the library's
            // signature, which reaches only the BIO's slot.
            unsafe { ffi::SSL_CTX_set_msg_callback(ctx.as_ptr(), Some(bio::trace)) };
        }
        let mut ctx_options: u64 = openssl_sys::SSL_OP_ALL
            | openssl_sys::SSL_OP_NO_TICKET
            | openssl_sys::SSL_OP_NO_COMPRESSION;
        if !options.ssl_options.contains(SslOptions::ALLOW_BEAST) {
            ctx_options &= !openssl_sys::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
        }
        // Any TLS version as the floor allows no SSL version (OpenSSL 3
        // has no SSLv2 to turn off).
        ctx_options |= openssl_sys::SSL_OP_NO_SSLv3;
        let min = match min_version {
            TlsMinVersion::Tls1 | TlsMinVersion::Tls1_0 => 0x301,
            TlsMinVersion::Tls1_1 => 0x302,
            TlsMinVersion::Tls1_2 => 0x303,
            TlsMinVersion::Tls1_3 => 0x304,
        };
        // 0: the newest the library has.
        let max = match options.max_version {
            TlsMaxVersion::Tls1_0 => 0x301,
            TlsMaxVersion::Tls1_1 => 0x302,
            TlsMaxVersion::Tls1_2 => 0x303,
            TlsMaxVersion::Tls1_3 => 0x304,
            TlsMaxVersion::None | TlsMaxVersion::Default => 0,
        };
        let c = ctx.as_ptr();
        // SAFETY: the context, and the command of the macro C calls
        // (`SSL_CTX_set_min_proto_version`), which takes no pointer.
        let set_min = unsafe {
            openssl_sys::SSL_CTX_ctrl(c, ffi::SSL_CTRL_SET_MIN_PROTO_VERSION, min, ptr::null_mut())
        };
        // SAFETY: as above (`SSL_CTX_set_max_proto_version`).
        let set_max = || unsafe {
            openssl_sys::SSL_CTX_ctrl(c, ffi::SSL_CTRL_SET_MAX_PROTO_VERSION, max, ptr::null_mut())
        };
        if set_min == 0 || set_max() == 0 {
            return Err(ErrorKind::SslConnectError);
        }
        // The options, a read ahead, a read buffer of four records and
        // writes retried from another address, as C sets them.
        // SAFETY: the context, and plain values.
        unsafe { openssl_sys::SSL_CTX_set_options(c, ctx_options as _) };
        // SAFETY: as above (`SSL_CTX_set_read_ahead`).
        unsafe { openssl_sys::SSL_CTX_ctrl(c, ffi::SSL_CTRL_SET_READ_AHEAD, 1, ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_default_read_buffer_len(c, 0x401e * 4) };
        let mode = openssl_sys::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
        // SAFETY: as above (`SSL_CTX_set_mode`).
        unsafe { openssl_sys::SSL_CTX_ctrl(c, ffi::SSL_CTRL_MODE, mode, ptr::null_mut()) };
        if let Some(ciphers) = &options.ciphers
            && min_version != TlsMinVersion::Tls1_3
        {
            let c = c_string(ciphers)?;
            // SAFETY: the context and a C string alive for the call.
            if unsafe { openssl_sys::SSL_CTX_set_cipher_list(ctx.as_ptr(), c.as_ptr().cast()) } == 0
            {
                return Err(io.fail(
                    ErrorKind::SslCipher,
                    format_args!("failed setting cipher list: {}", Text(ciphers)),
                ));
            }
            io.info(format_args!("Cipher selection: {}", Text(ciphers)));
        }
        if let Some(ciphers) = &options.tls13_ciphers
            && matches!(
                options.max_version,
                TlsMaxVersion::None | TlsMaxVersion::Default | TlsMaxVersion::Tls1_3
            )
        {
            let c = c_string(ciphers)?;
            // SAFETY: as above.
            if unsafe { openssl_sys::SSL_CTX_set_ciphersuites(ctx.as_ptr(), c.as_ptr().cast()) }
                == 0
            {
                return Err(io.fail(
                    ErrorKind::SslCipher,
                    format_args!("failed setting TLS 1.3 cipher suite: {}", Text(ciphers)),
                ));
            }
            io.info(format_args!("TLS 1.3 cipher selection: {}", Text(ciphers)));
        }
        if options.cert.is_some() || options.cert_blob.is_some() || options.cert_type.is_some() {
            // Kept as long as the context, which OpenSSL hands it from.
            self.password = options
                .key_password
                .as_deref()
                .map(x509::c_string)
                .transpose()?;
            crate::cert::client_cert(ctx, options, self.password.as_ref(), &mut self.crypto, io)?;
        }
        // SAFETY: the context. OpenSSL 1.1.1 and later need the client
        // to opt in to authenticating after the handshake.
        unsafe { openssl_sys::SSL_CTX_set_post_handshake_auth(ctx.as_ptr(), 1) };
        for (list, command, what) in [
            (
                &options.curves,
                ffi::SSL_CTRL_SET_GROUPS_LIST,
                "curves list",
            ),
            (
                &options.signature_algorithms,
                ffi::SSL_CTRL_SET_SIGALGS_LIST,
                "signature algorithms",
            ),
        ] {
            let Some(list) = list else { continue };
            let c = c_string(list)?;
            // SAFETY: the context, a C string alive for the call.
            let set = unsafe {
                openssl_sys::SSL_CTX_ctrl(
                    ctx.as_ptr(),
                    command,
                    0,
                    c.as_ptr().cast_mut().cast::<c_void>(),
                )
            };
            if set == 0 {
                return Err(io.fail(
                    ErrorKind::SslCipher,
                    format_args!("failed setting {what}: '{}'", Text(list)),
                ));
            }
        }
        // OpenSSL verifies whatever is asked; C checks its result after.
        // SAFETY: the context, no callback.
        unsafe {
            openssl_sys::SSL_CTX_set_verify(ctx.as_ptr(), openssl_sys::SSL_VERIFY_NONE, None)
        };
        if self.keylog.as_deref().is_some_and(KeyLog::enabled) {
            // SAFETY: the context, and a callback of the library's
            // signature, which reaches only the BIO's slot.
            unsafe { openssl_sys::SSL_CTX_set_keylog_callback(c, Some(bio::keylog_line)) };
        }
        // The sessions the peer gives are told of, and kept by the
        // transfer's cache alone, none in the context's
        // (`SSL_SESS_CACHE_NO_INTERNAL`).
        let mode = openssl_sys::SSL_SESS_CACHE_CLIENT | openssl_sys::SSL_SESS_CACHE_NO_INTERNAL;
        // SAFETY: the context, and a plain value.
        unsafe { openssl_sys::SSL_CTX_set_session_cache_mode(c, mode) };
        // SAFETY: the context, and a callback of the library's signature,
        // which reaches only the BIO's slot.
        unsafe { openssl_sys::SSL_CTX_sess_set_new_cb(c, Some(bio::new_session)) };
        // The application's turn at the context (`ssl_fsslctx`), made
        // whole first, its trust store too (C's #11800).
        if io.configures_context() {
            if !self.flags.store_ready {
                x509::setup_store(ctx, &self.identity, self.shared.as_ref(), io)?;
                self.flags.store_ready = true;
            }
            io.configure_context(TlsNative::new(ctx.cast(), None))?;
        }
        // The SSL (`ossl_init_ssl`).
        // SAFETY: the context.
        let ssl = unsafe { openssl_sys::SSL_new(ctx.as_ptr()) };
        let Some(ssl) = NonNull::new(ssl) else {
            return Err(io.fail(
                ErrorKind::OutOfMemory,
                format_args!("SSL: could not create a context (handle)"),
            ));
        };
        self.ssl = Some(Ssl(ssl));
        if options.verify_status {
            crate::ocsp::request(ssl);
        }
        // SAFETY: the SSL.
        unsafe { openssl_sys::SSL_set_connect_state(ssl.as_ptr()) };
        if self.kind == TlsPeerKind::Name {
            // RFC 6066 3: the name without a trailing dot, in lower case,
            // shorter than 64 KiB.
            let name = self.host.strip_suffix(b".").unwrap_or(&self.host);
            if name.len() < usize::from(u16::MAX) {
                let mut sni = c_string(name)?;
                sni.make_ascii_lowercase();
                // SAFETY: the SSL, a C string alive for the call, which
                // the library copies.
                let set = unsafe {
                    openssl_sys::SSL_ctrl(
                        ssl.as_ptr(),
                        ffi::SSL_CTRL_SET_TLSEXT_HOSTNAME,
                        ffi::TLSEXT_NAMETYPE_HOST_NAME,
                        sni.as_mut_ptr().cast(),
                    )
                };
                if set == 0 {
                    return Err(io.fail(ErrorKind::SslConnectError, format_args!("Failed set SNI")));
                }
            }
        }
        // A session the cache kept for the peer is resumed, unless the
        // peer's status is to be checked, which a resumed one would not
        // send (`ossl_init_session_and_alpns`).
        self.reused = false;
        if io.caches_sessions() && !options.verify_status {
            let taken = io.take_session();
            if let Some(t) = taken.as_ref().filter(|t| !t.data.is_empty()) {
                self.resume(ssl, t, io);
            }
            if self.quic && self.reused {
                // Kept for the early data it allows; a TLS 1.3 session
                // given back would be dropped.
                self.resumed = taken;
            } else {
                io.return_session(taken);
            }
        }
        // Put off, only what the session resumed agreed is offered
        // (`Curl_alpn_restrict_to`).
        let wire = match self.deferred {
            Some(d) => d.alpn.wire(),
            None => self.alpn.wire(),
        };
        if !wire.is_empty() {
            let len = u32::try_from(wire.len()).expect("a short list");
            // SAFETY: the SSL, and the list, which the library copies.
            if unsafe { openssl_sys::SSL_set_alpn_protos(ssl.as_ptr(), wire.as_ptr(), len) } != 0 {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("Error setting ALPN"),
                ));
            }
        }
        Ok(())
    }

    /// Move the handshake on (`ossl_connect_step2`).
    fn step2(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        self.waits = TlsWait::Nothing;
        // SAFETY: the thread's error queue.
        unsafe { openssl_sys::ERR_clear_error() };
        // SAFETY: the session's SSL, its BIO reaching `io`.
        let (err, below) = self.call(io, |ssl| unsafe { openssl_sys::SSL_connect(ssl) });
        if !self.flags.store_ready {
            // The ClientHello went out without a read: the store is set
            // up for the certificate to come.
            let ctx = self.ctx.as_ref().expect("made at the first step").0;
            x509::setup_store(ctx, &self.identity, self.shared.as_ref(), io)?;
            self.flags.store_ready = true;
        }
        if self.flags.store_ready {
            // Not needed past the store: the connection does not keep the
            // multi's state alive, wherever it goes.
            self.shared = None;
        }
        if err == 1 {
            self.report_handshake(io);
            if !self.alpn.wire().is_empty() {
                self.negotiated(io)?;
            }
            return Ok(Handshake::Done);
        }
        let ssl = self.ssl();
        // SAFETY: the SSL and what its call returned.
        let detail = unsafe { openssl_sys::SSL_get_error(ssl.as_ptr(), err) };
        io.trace(format_args!("SSL_connect() -> err={err}, detail={detail}"));
        match detail {
            openssl_sys::SSL_ERROR_WANT_READ => {
                io.trace(format_args!("SSL_connect() -> want recv"));
                self.waits = TlsWait::Recv;
                return Ok(Handshake::Waiting);
            }
            openssl_sys::SSL_ERROR_WANT_WRITE => {
                io.trace(format_args!("SSL_connect() -> want send"));
                self.waits = TlsWait::Send;
                return Ok(Handshake::Waiting);
            }
            SSL_ERROR_WANT_ASYNC => {
                io.trace(format_args!("SSL_connect() -> want async"));
                self.waits = TlsWait::Recv;
                return Ok(Handshake::Waiting);
            }
            SSL_ERROR_WANT_RETRY_VERIFY => {
                // A verify callback the application installed waits for
                // its verdict: the transfer's receiving pauses, and the
                // handshake goes on once the application unpauses it.
                io.trace(format_args!("SSL_connect() -> want retry_verify"));
                io.pause_recv();
                return Ok(Handshake::Waiting);
            }
            _ => {}
        }
        // SAFETY: the thread's error queue: its earliest entry, taken.
        let errdetail = unsafe { openssl_sys::ERR_get_error() };
        let lib = error_lib(errdetail);
        let reason = error_reason(errdetail);
        let kind = if lib == ffi::ERR_LIB_SSL
            && (reason == ffi::SSL_R_CERTIFICATE_VERIFY_FAILED
                || reason == ffi::SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED)
        {
            // SAFETY: the SSL.
            let verified = unsafe { openssl_sys::SSL_get_verify_result(ssl.as_ptr()) };
            if verified != c_long::from(openssl_sys::X509_V_OK) {
                io.verified(verified);
                // SAFETY: a function of no state, for any number.
                let why = unsafe { openssl_sys::X509_verify_cert_error_string(verified) };
                // SAFETY: the library's static text, or null.
                let why = unsafe { c_text(why) }.unwrap_or_default();
                io.fail(
                    ErrorKind::PeerFailedVerification,
                    format_args!("SSL certificate problem: {}", Text(why)),
                )
            } else {
                io.fail(
                    ErrorKind::PeerFailedVerification,
                    format_args!("SSL certificate verification failed"),
                )
            }
        } else if lib == ffi::ERR_LIB_SSL && reason == ffi::SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED
        {
            let e = ErrText::of(errdetail);
            io.fail(
                ErrorKind::SslClientcert,
                format_args!("TLS cert problem: {e}"),
            )
        } else {
            let e = ErrText::of(errdetail);
            io.fail(
                ErrorKind::SslConnectError,
                format_args!("TLS connect error: {e}"),
            )
        };
        if kind == ErrorKind::SslConnectError && errdetail == 0 {
            // OpenSSL said nothing: say what the socket did, or what
            // OpenSSL's answer was.
            let errno = errno_of(below);
            let host = Text(&self.host);
            let port = self.port;
            if errno != 0 && detail == openssl_sys::SSL_ERROR_SYSCALL {
                let why = ErrorText::of_code(errno);
                io.fail(
                    kind,
                    format_args!(
                        "OpenSSL SSL_connect: {} in connection to {host}:{port} ",
                        Text(why.as_bytes())
                    ),
                );
            } else {
                io.fail(
                    kind,
                    format_args!(
                        "OpenSSL SSL_connect: {} in connection to {host}:{port} ",
                        text::ssl_error(detail)
                    ),
                );
            }
        }
        Err(kind)
    }

    fn report_handshake(&self, io: &mut TlsCx<'_>) {
        // SAFETY: the session's SSL, alive while it is; called once its
        // handshake is done.
        unsafe { report_handshake(self.ssl(), io) };
    }

    /// The name the peer chose of the ALPN offer, empty if none; the
    /// library refuses a choice not offered.
    fn selected(&self) -> &[u8] {
        let mut proto: *const u8 = ptr::null();
        let mut len: u32 = 0;
        // SAFETY: the SSL; the protocol is its own, alive while it is.
        unsafe { openssl_sys::SSL_get0_alpn_selected(self.ssl().as_ptr(), &mut proto, &mut len) };
        match usize::try_from(len) {
            // SAFETY: `len` bytes at `proto`, the SSL's while `self` is
            // borrowed.
            Ok(n) if n > 0 && !proto.is_null() => unsafe { core::slice::from_raw_parts(proto, n) },
            _ => &[],
        }
    }

    /// What the peer chose of the ALPN offer (`Curl_alpn_set_negotiated`).
    fn negotiated(&self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let chosen = self.selected();
        // Asked of the peer again, put off, it must agree to it again.
        if let Some(d) = self.deferred {
            let asked = d.alpn.name();
            if chosen.is_empty() {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!(
                        "ALPN: asked for '{asked}' from previous session, but server did not confirm it. Refusing to continue."
                    ),
                ));
            }
            if chosen != asked.as_bytes() {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!(
                        "ALPN: asked for '{asked}' from previous session, but server selected '{}'. Refusing to continue.",
                        Text(chosen)
                    ),
                ));
            }
            io.info(format_args!("ALPN: server confirmed to use '{asked}'"));
            return Ok(());
        }
        if chosen.is_empty() {
            io.info(format_args!(
                "ALPN: server did not agree on a protocol. Uses default."
            ));
        } else if chosen.contains(&0) {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("ALPN: server selected protocol contains NUL. Refusing to continue."),
            ));
        } else {
            io.info(format_args!("ALPN: server accepted {}", Text(chosen)));
        }
        Ok(())
    }
}

/// `Curl_ossl_report_handshake`: the version, cipher, group and the
/// peer's signature type.
///
/// # Safety
/// `ssl` is a session's SSL, its handshake done, alive for the call.
unsafe fn report_handshake(ssl: NonNull<SSL>, io: &mut TlsCx<'_>) {
    let mut nid: c_int = 0;
    let s = ssl.as_ptr();
    // SAFETY: as the caller says; the texts are the library's, static or
    // alive while the SSL is, which outlives this function.
    unsafe { ffi::SSL_get_peer_signature_type_nid(s, &mut nid) };
    // SAFETY: as above.
    let version = unsafe { openssl_sys::SSL_get_version(s) };
    // SAFETY: as above.
    let version = unsafe { c_text(version) };
    // SAFETY: as above.
    let cipher = unsafe { openssl_sys::SSL_get_current_cipher(s) };
    // SAFETY: as above; a null cipher has a null name.
    let cipher = unsafe { openssl_sys::SSL_CIPHER_get_name(cipher) };
    // SAFETY: as above.
    let cipher = unsafe { c_text(cipher) };
    // SAFETY: as above.
    let group = unsafe { group_name(ssl) };
    // SAFETY: a function of no state, for any number.
    let signature = unsafe { openssl_sys::OBJ_nid2sn(nid) };
    // SAFETY: the library's static text, or null.
    let signature = unsafe { c_text(signature) };
    io.info(format_args!(
        "SSL connection using {} / {} / {} / {}",
        Text(version.unwrap_or(b"(null)")),
        Text(cipher.unwrap_or(b"(null)")),
        Text(group.unwrap_or(b"[blank]")),
        Text(signature.unwrap_or(b"(null)"))
    ));
}

/// The most early data a handshake holds to send (`CURL_SSL_EARLY_MAX`).
const EARLY_MOST: usize = 64 * 1024;

impl Session {
    /// Put the handshake off for early data, resuming a session that
    /// allows `most` bytes of it and agreed `chosen` by ALPN, if the
    /// transfer offers it (`Curl_on_session_reuse`).
    fn defer(&mut self, most: usize, chosen: Chosen, io: &mut TlsCx<'_>) {
        if most == 0 {
            io.trace(format_args!("SSL session does not allow earlydata"));
        } else if !self.alpn.offers(chosen) {
            io.trace(format_args!(
                "SSL session has different ALPN, no early data"
            ));
        } else {
            let name = chosen.name();
            io.info(format_args!(
                "SSL session allows {most} bytes of early data, reusing ALPN '{name}'"
            ));
            self.deferred = Some(Deferred {
                most: most.min(EARLY_MOST),
                alpn: chosen,
            });
            io.info(format_args!(
                "ALPN: deferred handshake for early data using '{name}'."
            ));
        }
    }

    /// Write `early` as early data, from `sent` on
    /// (`ossl_send_earlydata`): done, or waiting with what went kept.
    fn write_early(
        &mut self,
        io: &mut TlsIo<'_>,
        early: &[u8],
        mut sent: usize,
    ) -> Result<Handshake, ErrorKind> {
        while sent < early.len() {
            let mut written = 0usize;
            let rest = &early[sent..];
            let (from, len) = (rest.as_ptr(), rest.len());
            // SAFETY: the SSL, `len` bytes at `from`, the caller's, and
            // the count the library writes.
            let (rc, below) = self.call(io, |ssl| unsafe {
                openssl_sys::SSL_write_early_data(ssl, from.cast(), len, &mut written)
            });
            io.trace(format_args!(
                "SSL_write_early_data(len={len}) -> {rc}, {written}"
            ));
            if rc <= 0 {
                self.early = Early::Sending(sent);
                // SAFETY: the SSL and what its call returned.
                let err = unsafe { openssl_sys::SSL_get_error(self.ssl().as_ptr(), rc) };
                let errno = errno_of(below);
                return match err {
                    openssl_sys::SSL_ERROR_WANT_READ => {
                        self.waits = TlsWait::Recv;
                        Ok(Handshake::Waiting)
                    }
                    openssl_sys::SSL_ERROR_WANT_WRITE => {
                        self.waits = TlsWait::Send;
                        Ok(Handshake::Waiting)
                    }
                    openssl_sys::SSL_ERROR_SYSCALL if below == Below::Again => {
                        Ok(Handshake::Waiting)
                    }
                    openssl_sys::SSL_ERROR_SYSCALL => {
                        // SAFETY: the thread's error queue, its earliest
                        // taken.
                        let e = unsafe { openssl_sys::ERR_get_error() };
                        Err(if e != 0 {
                            let e = ErrText::of(e);
                            io.fail(
                                ErrorKind::SendError,
                                format_args!(
                                    "OpenSSL SSL_write:early_data: {}, errno {errno}",
                                    e.versioned()
                                ),
                            )
                        } else if errno != 0 {
                            let why = ErrorText::of_code(errno);
                            io.fail(
                                ErrorKind::SendError,
                                format_args!(
                                    "OpenSSL SSL_write:early_data: {}, errno {errno}",
                                    Text(why.as_bytes())
                                ),
                            )
                        } else {
                            io.fail(
                                ErrorKind::SendError,
                                format_args!(
                                    "OpenSSL SSL_write:early_data: {}, errno {errno}",
                                    text::ssl_error(err)
                                ),
                            )
                        })
                    }
                    openssl_sys::SSL_ERROR_SSL => {
                        let e = ErrText::last();
                        Err(io.fail(
                            ErrorKind::SendError,
                            format_args!("SSL_write_early_data() error: {e}"),
                        ))
                    }
                    _ => Err(io.fail(
                        ErrorKind::SendError,
                        format_args!(
                            "OpenSSL SSL_write_early_data: {}, errno {errno}",
                            text::ssl_error(err)
                        ),
                    )),
                };
            }
            sent += written;
        }
        io.info(format_args!(
            "SSL sending {} bytes of early data",
            early.len()
        ));
        self.early = Early::Sent;
        Ok(Handshake::Done)
    }

    /// Resume `ticket` on `ssl`, if the library takes it and, for a peer
    /// to verify, its connection was verified (`ossl_apply_session`).
    fn resume(&mut self, ssl: NonNull<SSL>, ticket: &TlsTicket, io: &mut TlsCx<'_>) {
        let mut der = ticket.data.as_ptr();
        let len = c_long::try_from(ticket.data.len()).unwrap_or(c_long::MAX);
        // SAFETY: `len` bytes at `der`, the ticket's; the session made is
        // this function's, freed below.
        let session = unsafe { openssl_sys::d2i_SSL_SESSION(ptr::null_mut(), &mut der, len) };
        if session.is_null() {
            io.info(format_args!(
                "SSL session not accepted by OpenSSL, continuing without"
            ));
            return;
        }
        let s = ssl.as_ptr();
        // SAFETY: the SSL and the session, which it takes a reference to.
        if unsafe { openssl_sys::SSL_set_session(s, session) } == 0 {
            // SAFETY: the thread's error queue, its earliest taken.
            let e = ErrText::of(unsafe { openssl_sys::ERR_get_error() });
            io.info(format_args!(
                "SSL: SSL_set_session not accepted, continuing without: {e}"
            ));
        } else {
            // SAFETY: the SSL, its session just set.
            let verified = unsafe { openssl_sys::SSL_get_verify_result(s) };
            if self.identity.verify_peer && verified != c_long::from(openssl_sys::X509_V_OK) {
                // Made unverified: it cannot serve a peer to verify.
                // SAFETY: the SSL; no session, its reference let go.
                unsafe { openssl_sys::SSL_set_session(s, ptr::null_mut()) };
                io.info(format_args!("SSL session not peer verified, not reusing"));
            } else {
                let alpn = ticket.alpn.map_or("-", Chosen::name);
                io.info(format_args!("SSL reusing session with ALPN '{alpn}'"));
                self.reused = true;
                io.info(format_args!("SSL verify result: {verified:x}"));
                // SAFETY: the session, alive until freed below.
                let allows = unsafe { openssl_sys::SSL_SESSION_get_max_early_data(session) };
                // SAFETY: the SSL.
                let version = unsafe { openssl_sys::SSL_version(s) };
                if let Some(chosen) = ticket.alpn
                    && self.early_data
                    && allows > 0
                    && version == openssl_sys::TLS1_3_VERSION
                {
                    self.defer(ticket.earlydata_max, chosen, io);
                }
            }
        }
        // SAFETY: the session made above, the SSL holding its own
        // reference if it took it.
        unsafe { openssl_sys::SSL_SESSION_free(session) };
    }
}

/// The session the library made, as the cache keeps it
/// (`Curl_ossl_add_session`): its DER, the version of its connection, the
/// protocol ALPN chose there, the early data it allows, and until when it
/// is good, by the library's timeout from now.
///
/// # Safety
/// `ssl` and `session` are the library's, alive for the call: a callback's.
pub(crate) unsafe fn ticket_of(
    ssl: *mut SSL,
    session: *mut SSL_SESSION,
    io: &TlsCx<'_>,
) -> Result<TlsTicket, OutOfMemory> {
    // SAFETY: as the caller says; no pointer, so only the length.
    let len = unsafe { openssl_sys::i2d_SSL_SESSION(session, ptr::null_mut()) };
    let len = usize::try_from(len)
        .ok()
        .filter(|&n| n > 0)
        .ok_or(OutOfMemory)?;
    let mut der: Vec<u8> = Vec::new();
    der.try_reserve_exact(len)?;
    let mut at = der.as_mut_ptr();
    // SAFETY: room for the `len` bytes the call said it writes, at `at`.
    let wrote = unsafe { openssl_sys::i2d_SSL_SESSION(session, &mut at) };
    let wrote = usize::try_from(wrote).ok().filter(|&n| n > 0 && n <= len);
    let wrote = wrote.ok_or(OutOfMemory)?;
    // SAFETY: the call wrote `wrote` bytes from the start, within the room.
    unsafe { der.set_len(wrote) };
    // SAFETY: as the caller says.
    let version = unsafe { openssl_sys::SSL_version(ssl) };
    // SAFETY: as the caller says.
    let early = unsafe { openssl_sys::SSL_SESSION_get_max_early_data(session) };
    // SAFETY: as the caller says.
    let timeout = unsafe { openssl_sys::SSL_SESSION_get_timeout(session) };
    let mut proto: *const u8 = ptr::null();
    let mut proto_len: u32 = 0;
    // SAFETY: as the caller says; the protocol is the SSL's.
    unsafe { openssl_sys::SSL_get0_alpn_selected(ssl, &mut proto, &mut proto_len) };
    let alpn = match usize::try_from(proto_len) {
        Ok(n) if n > 0 && !proto.is_null() => {
            // SAFETY: `n` bytes at `proto`, the SSL's for the callback.
            let name = unsafe { core::slice::from_raw_parts(proto, n) };
            Chosen::named(name)
        }
        _ => None,
    };
    #[allow(
        clippy::useless_conversion,
        reason = "a `long` is 32 bits on some targets"
    )]
    let timeout = i64::from(timeout);
    Ok(TlsTicket::new(
        der,
        u16::try_from(version).unwrap_or(0),
        alpn,
        usize::try_from(early).unwrap_or(usize::MAX),
        io.unix_time().saturating_add(timeout),
    ))
}

/// `SSL_ERROR_WANT_ASYNC`.
const SSL_ERROR_WANT_ASYNC: c_int = 9;
/// `SSL_ERROR_WANT_RETRY_VERIFY`, OpenSSL 3.0's.
const SSL_ERROR_WANT_RETRY_VERIFY: c_int = 12;

/// The text of a C string the library returns, or none.
///
/// # Safety
/// `p` is null or a C string alive while the result is used.
unsafe fn c_text<'a>(p: *const core::ffi::c_char) -> Option<&'a [u8]> {
    // SAFETY: as the caller says.
    (!p.is_null()).then(|| unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes())
}

/// The group the handshake agreed on, by name.
///
/// # Safety
/// `ssl`'s handshake is done; the name lives while it does.
#[cfg(ossl320)]
unsafe fn group_name<'a>(ssl: NonNull<SSL>) -> Option<&'a [u8]> {
    // SAFETY: as the caller says.
    let name = unsafe { ffi::SSL_get0_group_name(ssl.as_ptr()) };
    // SAFETY: the SSL's text, or null, alive as the caller says.
    unsafe { c_text(name) }
}

/// The group the handshake agreed on, by name, as C finds it before 3.2.
///
/// # Safety
/// As above.
#[cfg(not(ossl320))]
unsafe fn group_name<'a>(ssl: NonNull<SSL>) -> Option<&'a [u8]> {
    let command = ffi::SSL_CTRL_GET_NEGOTIATED_GROUP;
    // SAFETY: as the caller says (`SSL_get_negotiated_group`).
    let group = unsafe { openssl_sys::SSL_ctrl(ssl.as_ptr(), command, 0, ptr::null_mut()) };
    // SAFETY: a function of no state, for any number.
    let name = unsafe { openssl_sys::OBJ_nid2sn((group & 0xffff) as c_int) };
    // SAFETY: the library's static text, or null.
    unsafe { c_text(name) }
}

impl TlsSession for Session {
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        if self.step == Step::Done {
            return Ok(Handshake::Done);
        }
        self.waits = TlsWait::Nothing;
        if self.step == Step::Init {
            io.trace(format_args!("ossl_connect, step1"));
            self.step1(io)?;
            self.step = Step::Handshake;
        }
        if self.step == Step::Handshake {
            io.trace(format_args!("ossl_connect, step2"));
            // Put off, it waits for its early data.
            if self.deferred.is_some() && self.early == Early::None {
                return Ok(Handshake::Done);
            }
            match self.step2(io)? {
                Handshake::Waiting => return Ok(Handshake::Waiting),
                Handshake::Done => self.step = Step::Check,
            }
        }
        io.trace(format_args!("ossl_connect, step3"));
        let checked = x509::check_peer(
            self.ssl(),
            &self.identity,
            &self.host,
            self.kind,
            self.reused,
            io,
        );
        if let Err(kind) = checked {
            // The sessions kept for the peer go with it.
            io.forget_sessions();
            return Err(kind);
        }
        if self.early == Early::Sent {
            // SAFETY: the SSL, its handshake done.
            let status = unsafe { ffi::SSL_get_early_data_status(self.ssl().as_ptr()) };
            self.early = Early::Over {
                accepted: status == ffi::SSL_EARLY_DATA_ACCEPTED,
            };
        }
        self.step = Step::Done;
        io.trace(format_args!("ossl_connect, done"));
        if let Some(log) = &self.keylog {
            log.with_name(|name| {
                io.info(format_args!(
                    "SSLKEYLOGFILE set, all TLS secrets are logged to '{}'",
                    Text(name)
                ));
            });
        }
        Ok(Handshake::Done)
    }

    fn recv(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        // SAFETY: the thread's error queue.
        unsafe { openssl_sys::ERR_clear_error() };
        self.waits = TlsWait::Nothing;
        let size = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        let room = buf.as_mut_ptr();
        // SAFETY: the SSL, and `size` bytes of room at `room`, the
        // caller's buffer, not otherwise used during the call.
        let (nread, below) = self.call(io, |ssl| unsafe {
            openssl_sys::SSL_read(ssl, room.cast(), size)
        });
        let got = self.read_result(io, nread, below);
        if matches!(got, Ok(Recv::Eof | Recv::WouldBlock)) {
            // Nothing given out: what the library held is read.
            self.flags.input_pending = false;
        }
        let (code, n) = match &got {
            Ok(Recv::Data(n)) => (0, n.get()),
            Ok(Recv::Eof) => (0, 0),
            Ok(Recv::WouldBlock) => (bio::AGAIN, 0),
            Err(_) => (ErrorKind::RecvError.number(), 0),
        };
        io.trace(format_args!(
            "ossl_recv(len={}) -> {code}, {n} (in_pending={})",
            buf.len(),
            u8::from(self.flags.input_pending)
        ));
        got
    }

    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent> {
        // SAFETY: the thread's error queue.
        unsafe { openssl_sys::ERR_clear_error() };
        self.waits = TlsWait::Nothing;
        let mut len = c_int::try_from(bytes.len()).unwrap_or(c_int::MAX);
        if let Some(blocked) = self.blocked_write.take() {
            // The library is given the write it could not finish again,
            // which the transfer never sends less of.
            assert!(blocked <= len, "a blocked write is sent again whole");
            len = blocked;
        }
        let from = bytes.as_ptr();
        // SAFETY: the SSL, and `len` bytes at `from`, the caller's.
        let (n, below) = self.call(io, |ssl| unsafe {
            openssl_sys::SSL_write(ssl, from.cast(), len)
        });
        if n > 0 {
            if n > len {
                io.fail(
                    ErrorKind::SendError,
                    format_args!("SSL_write(len={len}) returned {n}"),
                );
                return Err(said(0));
            }
            let n = usize::try_from(n).expect("positive");
            return Ok(Sent::Bytes(NonZeroUsize::new(n).expect("positive")));
        }
        // SAFETY: the SSL and what its call returned.
        let err = unsafe { openssl_sys::SSL_get_error(self.ssl().as_ptr(), n) };
        let errno = errno_of(below);
        match err {
            openssl_sys::SSL_ERROR_WANT_READ => {
                self.waits = TlsWait::Recv;
                self.blocked_write = Some(len);
                Ok(Sent::WouldBlock)
            }
            openssl_sys::SSL_ERROR_WANT_WRITE => {
                self.blocked_write = Some(len);
                Ok(Sent::WouldBlock)
            }
            openssl_sys::SSL_ERROR_SYSCALL => {
                if below == Below::Again {
                    self.blocked_write = Some(len);
                    return Ok(Sent::WouldBlock);
                }
                // SAFETY: the thread's error queue, its earliest taken.
                let e = unsafe { openssl_sys::ERR_get_error() };
                if e != 0 {
                    let e = ErrText::of(e);
                    io.fail(
                        ErrorKind::SendError,
                        format_args!("OpenSSL SSL_write: {}, errno {errno}", e.versioned()),
                    );
                } else if errno != 0 {
                    let why = ErrorText::of_code(errno);
                    io.fail(
                        ErrorKind::SendError,
                        format_args!("OpenSSL SSL_write: {}, errno {errno}", Text(why.as_bytes())),
                    );
                } else {
                    io.fail(
                        ErrorKind::SendError,
                        format_args!("OpenSSL SSL_write: {}, errno {errno}", text::ssl_error(err)),
                    );
                }
                Err(said(errno))
            }
            openssl_sys::SSL_ERROR_SSL => {
                let e = ErrText::last();
                io.fail(ErrorKind::SendError, format_args!("SSL_write() error: {e}"));
                Err(said(errno))
            }
            _ => {
                io.fail(
                    ErrorKind::SendError,
                    format_args!("OpenSSL SSL_write: {}, errno {errno}", text::ssl_error(err)),
                );
                Err(said(errno))
            }
        }
    }

    /// The goodbye (`ssl_cf_shutdown`): only for a handshake that was
    /// done, once; the bytes it holds are given up as it waits or ends.
    fn shutdown(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        if self.step != Step::Done || self.shut {
            return Ok(Handshake::Done);
        }
        self.waits = TlsWait::Nothing;
        let done = self.goodbye(io);
        self.shut = done;
        if done || self.waits != TlsWait::Nothing {
            self.flags.input_pending = false;
        }
        Ok(if done {
            Handshake::Done
        } else {
            Handshake::Waiting
        })
    }

    fn waits(&self) -> TlsWait {
        self.waits
    }

    fn pending(&self) -> bool {
        self.flags.input_pending
    }

    /// What the peer chose, which is none before the handshake chose it,
    /// but for one put off: what the session resumed chose.
    fn chosen(&self) -> Option<Chosen> {
        self.ssl.as_ref()?;
        match self.deferred {
            Some(d) if self.step != Step::Done => Some(d.alpn),
            _ => Chosen::named(self.selected()),
        }
    }

    fn deferred(&self) -> Option<Deferred> {
        self.deferred.filter(|_| self.early == Early::None)
    }

    fn handshake_early(
        &mut self,
        io: &mut TlsIo<'_>,
        early: &[u8],
    ) -> Result<Handshake, ErrorKind> {
        assert!(self.deferred.is_some(), "a handshake put off");
        self.waits = TlsWait::Nothing;
        if self.early == Early::None {
            self.early = Early::Sending(0);
        }
        if let Early::Sending(sent) = self.early
            && self.write_early(io, early, sent)? == Handshake::Waiting
        {
            return Ok(Handshake::Waiting);
        }
        self.handshake(io)
    }

    fn early_accepted(&self) -> bool {
        self.early == (Early::Over { accepted: true })
    }

    /// The `SSL_CTX`, and the `SSL` once made, as C hands them out.
    fn native(&self) -> Option<TlsNative> {
        let ctx = self.ctx.as_ref()?.0;
        let ssl = self.ssl.as_ref().map(|s| s.0.cast());
        Some(TlsNative::new(ctx.cast(), ssl))
    }

    /// The binding of the peer's certificate, none before the session is
    /// made.
    fn channel_binding(
        &self,
        notes: &mut dyn curl_core::tls::BindingNotes,
    ) -> Result<Option<Vec<u8>>, ErrorKind> {
        match self.ssl.as_ref() {
            Some(ssl) => crate::x509::channel_binding(ssl.0, notes),
            None => Ok(None),
        }
    }
}

/// One QUIC connection's OpenSSL: a session whose records the QUIC
/// library carries, driving its handshake through the SSL the session
/// hands it (`cf-ngtcp2`'s `curl_tls_ctx`).
struct QuicSession(Session);

impl QuicTls for QuicSession {
    fn native(&self) -> TlsNative {
        self.0.native().expect("made as the session is")
    }

    fn resumed(&self) -> Option<&TlsTicket> {
        self.0.resumed.as_ref()
    }

    fn before_recv(&mut self, cx: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let s = &mut self.0;
        if !s.flags.store_ready {
            let ctx = s.ctx.as_ref().expect("made as the session is").0;
            x509::setup_store(ctx, &s.identity, s.shared.as_ref(), cx)?;
            s.flags.store_ready = true;
            // Not needed past the store, as for a stream session.
            s.shared = None;
        }
        Ok(())
    }

    fn drive(
        &mut self,
        cx: &mut TlsCx<'_>,
        params: &mut dyn FnMut() -> Option<Vec<u8>>,
        call: &mut dyn FnMut(&mut dyn HandshakeCheck),
    ) {
        let s = &mut self.0;
        let ssl = s.ssl();
        let ctx = s.ctx.as_ref().expect("made as the session is").0;
        let identity = &s.identity;
        let shared = s.shared.as_ref();
        let mut setup = |cx: &mut TlsCx<'_>| x509::setup_store(ctx, identity, shared, cx);
        let mut slot = Slot {
            io: bio::Reach::Quic(cx),
            flags: &mut s.flags,
            below: Below::Ok,
            store: &mut setup,
            keylog: s.keylog.as_deref(),
            quic_params: Some(params),
        };
        let mut check = Check {
            ssl,
            identity,
            host: &s.host,
            kind: s.kind,
            reused: s.reused,
        };
        bio::call(ssl, &mut slot, |_| call(&mut check));
    }
}

/// A QUIC session's check once its handshake is done, which reaches the
/// transfer through the slot of the call under way.
struct Check<'s> {
    ssl: NonNull<SSL>,
    identity: &'s TlsIdentity,
    host: &'s [u8],
    kind: TlsPeerKind,
    reused: bool,
}

impl HandshakeCheck for Check<'_> {
    /// The handshake reported, then the peer checked as a stream
    /// session's is, the peer's sessions forgotten if it fails
    /// (`cb_ngtcp2_handshake_completed`).
    fn handshake_done(&mut self) -> Result<(), ErrorKind> {
        let Check {
            ssl,
            identity,
            host,
            kind,
            reused,
        } = *self;
        // SAFETY: the session's SSL, alive while the check is.
        let finished = unsafe { openssl_sys::SSL_is_init_finished(ssl.as_ptr()) };
        assert_eq!(
            finished, 1,
            "the QUIC library says a handshake is done once it is"
        );
        let check = |cx: &mut TlsCx<'_>| {
            // SAFETY: the session's SSL, its handshake done.
            unsafe { report_handshake(ssl, cx) };
            match x509::check_peer(ssl, identity, host, kind, reused, cx) {
                Ok(_) => Ok(()),
                Err(kind) => {
                    cx.forget_sessions();
                    Err(kind)
                }
            }
        };
        // SAFETY: a `Check` lives only inside `drive`'s call, whose slot
        // is the SSL's BIO's while it runs, on this thread.
        unsafe { bio::with_cx(ssl, check) }
    }
}

impl Session {
    /// One try at the goodbye (`ossl_shutdown`, sending close_notify):
    /// the peer's close_notify read first if it came, and nothing sent to
    /// a peer that closed after it; then ours, then the peer's waited for.
    /// Done, or waiting for what `waits` says.
    fn goodbye(&mut self, io: &mut TlsIo<'_>) -> bool {
        let ssl = self.ssl().as_ptr();
        let mut buf = [0u8; 1024];
        let mut read = |s: &mut Session, io: &mut TlsIo<'_>| s.read_into(io, &mut buf);
        // SAFETY: the SSL.
        let sent =
            || unsafe { openssl_sys::SSL_get_shutdown(ssl) } & openssl_sys::SSL_SENT_SHUTDOWN;
        if sent() == 0 {
            // Not started from our side: the peer may have said goodbye.
            // SAFETY: the thread's error queue.
            unsafe { openssl_sys::ERR_clear_error() };
            let mut nread = -1;
            for _ in 0..10 {
                nread = read(self, io).0;
                io.trace(format_args!("SSL shutdown not sent, read -> {nread}"));
                if nread <= 0 {
                    break;
                }
            }
            // SAFETY: the SSL and what its call returned.
            let err = unsafe { openssl_sys::SSL_get_error(ssl, nread) };
            if nread == 0 && err == openssl_sys::SSL_ERROR_ZERO_RETURN && !io.peer_alive() {
                // It closed after its close_notify: it wants none of ours.
                self.flags.peer_closed = true;
                io.trace(format_args!("peer closed connection"));
                return true;
            }
        }
        if sent() == 0 {
            // SAFETY: the thread's error queue.
            unsafe { openssl_sys::ERR_clear_error() };
            io.trace(format_args!("send SSL close notify"));
            // SAFETY: the session's SSL, its BIO reaching `io`.
            let (rc, _) = self.call(io, |ssl| unsafe { openssl_sys::SSL_shutdown(ssl) });
            if rc == 1 {
                io.trace(format_args!("SSL shutdown finished"));
                return true;
            }
            // SAFETY: the SSL and what its call returned.
            if unsafe { openssl_sys::SSL_get_error(ssl, rc) } == openssl_sys::SSL_ERROR_WANT_WRITE {
                io.trace(format_args!("SSL shutdown still wants to send"));
                self.waits = TlsWait::Send;
                return false;
            }
        }
        // Ours sent: the peer's is read for.
        let (mut nread, mut below) = (-1, Below::Ok);
        for _ in 0..10 {
            // SAFETY: the thread's error queue.
            unsafe { openssl_sys::ERR_clear_error() };
            (nread, below) = read(self, io);
            io.trace(format_args!("SSL shutdown read -> {nread}"));
            if nread <= 0 {
                break;
            }
        }
        // SAFETY: the SSL and what its call returned.
        match unsafe { openssl_sys::SSL_get_error(ssl, nread) } {
            openssl_sys::SSL_ERROR_ZERO_RETURN => {
                // SAFETY: the session's SSL, its BIO reaching `io`.
                let (rc, _) = self.call(io, |ssl| unsafe { openssl_sys::SSL_shutdown(ssl) });
                if rc == 1 {
                    io.trace(format_args!("SSL shutdown finished"));
                } else {
                    io.trace(format_args!("SSL shutdown not received, but closed"));
                }
                true
            }
            openssl_sys::SSL_ERROR_NONE | openssl_sys::SSL_ERROR_WANT_READ => {
                io.trace(format_args!("SSL shutdown sent, want receive"));
                self.waits = TlsWait::Recv;
                false
            }
            openssl_sys::SSL_ERROR_WANT_WRITE => {
                io.trace(format_args!("SSL shutdown send blocked"));
                self.waits = TlsWait::Send;
                false
            }
            err => {
                // It closed without its close_notify.
                // SAFETY: the thread's error queue, its earliest taken.
                let e = unsafe { openssl_sys::ERR_get_error() };
                let errno = errno_of(below);
                if e != 0 {
                    let e = ErrText::of(e);
                    io.trace(format_args!(
                        "SSL shutdown, ignore recv error: '{}', errno {errno}",
                        e.versioned()
                    ));
                } else {
                    io.trace(format_args!(
                        "SSL shutdown, ignore recv error: '{}', errno {errno}",
                        text::ssl_error(err)
                    ));
                }
                true
            }
        }
    }

    /// `SSL_read` into `buf`, which is dropped: what it returned, and
    /// what came of the read below.
    fn read_into(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> (c_int, Below) {
        let size = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        let room = buf.as_mut_ptr();
        // SAFETY: the SSL, and `size` bytes of room at `room`, not
        // otherwise used during the call.
        self.call(io, |ssl| unsafe {
            openssl_sys::SSL_read(ssl, room.cast(), size)
        })
    }

    /// What `SSL_read` returning `nread` comes to (`ossl_recv`).
    fn read_result(&mut self, io: &mut TlsIo<'_>, nread: c_int, below: Below) -> io::Result<Recv> {
        if let Some(n) = usize::try_from(nread).ok().and_then(NonZeroUsize::new) {
            return Ok(Recv::Data(n));
        }
        // SAFETY: the SSL and what its call returned.
        let err = unsafe { openssl_sys::SSL_get_error(self.ssl().as_ptr(), nread) };
        let errno = errno_of(below);
        match err {
            openssl_sys::SSL_ERROR_NONE => Ok(Recv::Eof),
            openssl_sys::SSL_ERROR_ZERO_RETURN => {
                io.trace(format_args!("TLS close_notify"));
                Ok(Recv::Eof)
            }
            openssl_sys::SSL_ERROR_WANT_READ => {
                self.waits = TlsWait::Recv;
                Ok(Recv::WouldBlock)
            }
            openssl_sys::SSL_ERROR_WANT_WRITE => {
                self.waits = TlsWait::Send;
                Ok(Recv::WouldBlock)
            }
            _ if below == Below::Again => Ok(Recv::WouldBlock),
            _ => {
                // SAFETY: the thread's error queue, its earliest taken.
                let e = unsafe { openssl_sys::ERR_get_error() };
                if nread < 0 || e != 0 {
                    if e != 0 {
                        let e = ErrText::of(e);
                        io.fail(
                            ErrorKind::RecvError,
                            format_args!("OpenSSL SSL_read: {}, errno {errno}", e.versioned()),
                        );
                    } else if errno != 0 && err == openssl_sys::SSL_ERROR_SYSCALL {
                        let why = ErrorText::of_code(errno);
                        io.fail(
                            ErrorKind::RecvError,
                            format_args!(
                                "OpenSSL SSL_read: {}, errno {errno}",
                                Text(why.as_bytes())
                            ),
                        );
                    } else {
                        io.fail(
                            ErrorKind::RecvError,
                            format_args!(
                                "OpenSSL SSL_read: {}, errno {errno}",
                                text::ssl_error(err)
                            ),
                        );
                    }
                    return Err(said(errno));
                }
                if err == openssl_sys::SSL_ERROR_SYSCALL {
                    match below {
                        // Said below already.
                        Below::Failed(n) => return Err(said(n)),
                        // The store failed at a read after the handshake,
                        // which set it up: said as it failed.
                        Below::Store(_) => return Err(said(0)),
                        Below::Ok | Below::Again => {}
                    }
                    if self.flags.peer_closed {
                        io.fail(
                            ErrorKind::RecvError,
                            format_args!("Connection closed abruptly"),
                        );
                    } else {
                        io.fail(
                            ErrorKind::RecvError,
                            format_args!(
                                "OpenSSL SSL_read: Connection closed abruptly, errno {errno}"
                            ),
                        );
                    }
                    return Err(said(errno));
                }
                Ok(Recv::Eof)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use curl_core::options::{ColdGroup as _, TlsOptions};
    use curl_core::tls::Notes;

    use super::*;

    fn identity(change: impl FnOnce(&mut TlsIdentity)) -> TryArc<TlsIdentity> {
        let mut id = TlsIdentity {
            verify_peer: true,
            verify_host: true,
            options: TlsOptions::NONE,
            ca_defaults: CaDefaults::default(),
        };
        change(&mut id);
        TryArc::try_new(id).unwrap()
    }

    const PEER: TlsPeer<'static> = TlsPeer {
        name: b"localhost",
        port: 443,
        kind: TlsPeerKind::Name,
        early_data: false,
    };

    /// QUIC's session, made at once from the identity: TLS 1.3 the least
    /// it speaks whatever the transfer's floor (`ossl_init_method`), and
    /// a cap below it refused as C refuses it.
    #[test]
    fn a_quic_session_speaks_tls_1_3_at_least() {
        let floor = identity(|i| i.options.min_version = TlsMinVersion::Tls1_0);
        let mut notes = Notes::default();
        let made = TlsCx::testing(&floor, b"localhost", &mut notes, |shared, cx| {
            OPENSSL.quic_session(&floor, &PEER, shared, cx)
        });
        let session = made.unwrap();
        let ssl = session.native().session().unwrap().cast::<SSL>();
        // SAFETY: the session's SSL, alive while it is; the command
        // (`SSL_get_min_proto_version`) takes no pointer.
        let min = unsafe {
            openssl_sys::SSL_ctrl(
                ssl.as_ptr(),
                SSL_CTRL_GET_MIN_PROTO_VERSION,
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(min, 0x304);
        assert!(session.resumed().is_none());
        drop(session);

        let capped = identity(|i| i.options.max_version = TlsMaxVersion::Tls1_2);
        let mut notes = Notes::default();
        let made = TlsCx::testing(&capped, b"localhost", &mut notes, |shared, cx| {
            OPENSSL.quic_session(&capped, &PEER, shared, cx)
        });
        assert_eq!(made.err(), Some(ErrorKind::SslConnectError));
        assert_eq!(
            notes.0,
            ["fail: SslConnectError: QUIC needs at least TLS version 1.3"]
        );
    }

    /// The check a QUIC session's `drive` hands its call is for a
    /// handshake that is done: asked before, the QUIC library is wrong,
    /// and it says so rather than read what the SSL has not made.
    #[test]
    #[should_panic = "the QUIC library says a handshake is done once it is"]
    fn a_quic_session_s_check_needs_its_handshake_done() {
        let id = identity(|_| {});
        let mut notes = Notes::default();
        TlsCx::testing(&id, b"localhost", &mut notes, |shared, cx| {
            let mut session = OPENSSL.quic_session(&id, &PEER, shared, cx).unwrap();
            session.drive(cx, &mut || None, &mut |check| {
                assert!(check.handshake_done().is_err());
            });
        });
    }

    /// `SSL_CTRL_GET_MIN_PROTO_VERSION` (`ssl.h`).
    const SSL_CTRL_GET_MIN_PROTO_VERSION: c_int = 130;
}
