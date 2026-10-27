//! HTTP/3 over QUIC from ngtcp2 and nghttp3, as C's `lib/vquic` uses
//! them (`cf-ngtcp2.c`, `cf-ngtcp2-cmn.c`): a client connection with C's
//! settings, over a TLS session ngtcp2's OpenSSL crypto drives, its
//! HTTP/3 set up as the 1-RTT keys arrive.
//!
//! The two libraries' callbacks find the connection's state through their
//! user data, an `Inner` reached by one raw pointer, and the transfer and
//! the caller's events through what a call into them lends it. No
//! reference to the state is held across a call into either library,
//! whose callbacks nest (ngtcp2's reading of stream data calls nghttp3,
//! which tells of headers and data).
//!
//! Only reading, writing and the timers lend: the other calls fire none
//! of the callbacks that tell. Submitting a request queues its frames,
//! the body read as packets are written; cancelling a stream queues its
//! reset and its stop (`conn_shutdown_stream_write`, `_read`), closing
//! it only as a later packet's acknowledgement arrives; opening a window,
//! resuming a stream and writing the close set or write and tell nothing;
//! freeing the connection calls ngtcp2's crypto's callbacks alone. A
//! callback that tells outside a call is a broken assumption of these,
//! and stops the process.

#![allow(unsafe_code)]

mod sys;

use core::ffi::{CStr, c_int, c_void};
use core::ptr::{self, NonNull};
use std::fmt;
use std::mem::ManuallyDrop;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};
use curl_core::error::ErrorKind;
use curl_core::http3::{
    BODY_HELD, ClientSetup, CloseError, ConnectFailed, Event, Events, Expiry, H3Error, Heard,
    Http3, Layer, QuicError, StreamId, SubmitFailed,
};
use curl_core::time::Instant;
use curl_core::tls::{DriveCall, QuicTls, TlsCx};

/// The libraries, as the handles are given them.
pub static NGTCP2: Ngtcp2 = Ngtcp2;

/// ngtcp2 and nghttp3, as a library the core speaks HTTP/3 through.
#[derive(Debug)]
pub struct Ngtcp2;

impl Http3 for Ngtcp2 {
    fn client(
        &self,
        setup: &ClientSetup,
        tls: Box<dyn QuicTls>,
    ) -> Result<Box<dyn curl_core::http3::Connection>, ConnectFailed> {
        let conn = Connection::client(setup, tls)?;
        Ok(try_box(conn)?)
    }

    fn version(&self) -> &dyn fmt::Display {
        &Versions
    }
}

/// The two libraries' versions, as curl's version says them:
/// `ngtcp2/1.25.0 nghttp3/1.18.0`.
pub fn version() -> impl fmt::Display {
    Versions
}

/// See [`version`].
struct Versions;

impl fmt::Display for Versions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ngtcp2/{} nghttp3/{}",
            ngtcp2_version(),
            nghttp3_version()
        )
    }
}

/// ngtcp2's version (`ngtcp2_version`).
pub fn ngtcp2_version() -> &'static str {
    // SAFETY: with 0, it returns the library's own static description.
    let info = unsafe { sys::ngtcp2_version(0) };
    // SAFETY: as above, never NULL with 0.
    let version = unsafe { (*info).version_str };
    // SAFETY: whose version is a static C string.
    unsafe { CStr::from_ptr(version) }
        .to_str()
        .unwrap_or("unknown")
}

/// nghttp3's version (`nghttp3_version`).
pub fn nghttp3_version() -> &'static str {
    // SAFETY: as above.
    let info = unsafe { sys::nghttp3_version(0) };
    // SAFETY: as above.
    let version = unsafe { (*info).version_str };
    // SAFETY: as above.
    unsafe { CStr::from_ptr(version) }
        .to_str()
        .unwrap_or("unknown")
}

/// The QUIC library's failure `code` in `call`.
fn quic_error(call: &'static str, code: c_int) -> QuicError {
    // SAFETY: it takes any code.
    let text = unsafe { sys::ngtcp2_strerror(code) };
    // SAFETY: and returns a static C string for it.
    let text = unsafe { CStr::from_ptr(text) };
    QuicError {
        layer: Layer::Quic,
        call,
        code,
        text: text.to_str().unwrap_or("unknown"),
        crypto: code == sys::NGTCP2_ERR_CRYPTO,
    }
}

/// The HTTP/3 library's failure `code` in `call`.
fn h3_error(call: &'static str, code: c_int) -> QuicError {
    // SAFETY: as above.
    let text = unsafe { sys::nghttp3_strerror(code) };
    // SAFETY: as above.
    let text = unsafe { CStr::from_ptr(text) };
    QuicError {
        layer: Layer::Http3,
        call,
        code,
        text: text.to_str().unwrap_or("unknown"),
        crypto: false,
    }
}

/// `now` on ngtcp2's clock, in nanoseconds.
fn ts(now: Instant) -> u64 {
    u64::try_from(now.since(Instant::EPOCH).as_nanos()).unwrap_or(u64::MAX)
}

/// A duration on ngtcp2's clock.
fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// ngtcp2's crypto, set up once in the process (`Curl_vquic_init`): it
/// fetches the ciphers QUIC uses.
fn crypto_init() {
    static DONE: OnceLock<()> = OnceLock::new();
    DONE.get_or_init(|| {
        // SAFETY: no arguments; what it fails to fetch it leaves unset,
        // which the library handles.
        unsafe { sys::ngtcp2_crypto_ossl_init() };
    });
}

/// A socket address as the libraries take it.
#[derive(Clone, Copy)]
struct Addr {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

impl Addr {
    fn new(addr: SocketAddr) -> Addr {
        // SAFETY: all zeroes is a valid `sockaddr_storage`.
        let mut storage: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(a) => {
                let sin = libc::sockaddr_in {
                    sin_family: libc::sa_family_t::try_from(libc::AF_INET).expect("fits"),
                    sin_port: a.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(a.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                // SAFETY: a `sockaddr_in` fits in the storage, which is
                // aligned for any address.
                unsafe { ptr::write(ptr::from_mut(&mut storage).cast(), sin) };
                core::mem::size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(a) => {
                let sin6 = libc::sockaddr_in6 {
                    sin6_family: libc::sa_family_t::try_from(libc::AF_INET6).expect("fits"),
                    sin6_port: a.port().to_be(),
                    sin6_flowinfo: a.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: a.ip().octets(),
                    },
                    sin6_scope_id: a.scope_id(),
                };
                // SAFETY: as above.
                unsafe { ptr::write(ptr::from_mut(&mut storage).cast(), sin6) };
                core::mem::size_of::<libc::sockaddr_in6>()
            }
        };
        Addr {
            storage,
            len: libc::socklen_t::try_from(len).expect("an address's length fits"),
        }
    }

    fn ngtcp2(&mut self) -> sys::ngtcp2_addr {
        sys::ngtcp2_addr {
            addr: ptr::from_mut(&mut self.storage).cast(),
            addrlen: self.len,
        }
    }
}

/// The size of a chunk of a request body (`H3_STREAM_CHUNK_SIZE`).
const CHUNK: usize = 64 * 1024;

/// A request body the HTTP/3 library sends from: chunks whose bytes stay
/// where they are until the peer acknowledges them, as the library
/// points at them until then (`sendbuf`).
struct Body {
    stream: i64,
    /// Each at most `CHUNK` long, its room reserved when it is made, so
    /// that what is added never moves what is there.
    chunks: Vec<Vec<u8>>,
    /// The bytes of the first chunk the peer acknowledged.
    acked: usize,
    /// The bytes handed to the library and not yet acknowledged.
    in_flight: usize,
    /// The body ends after what is held.
    ended: bool,
    /// The stream was cancelled: the body waits for the stream to close,
    /// as the library may point at it until then.
    cancelled: bool,
}

impl Body {
    /// The bytes held, acknowledged ones gone.
    fn buffered(&self) -> usize {
        self.chunks.iter().map(Vec::len).sum::<usize>() - self.acked
    }

    /// Take what of `bytes` fits in the chunks there may be.
    fn write(&mut self, mut bytes: &[u8]) -> Result<usize, OutOfMemory> {
        let mut n = 0;
        while !bytes.is_empty() {
            if self.chunks.last().is_none_or(|c| c.len() == CHUNK) {
                if self.chunks.len() == BODY_HELD / CHUNK {
                    break;
                }
                let mut chunk = Vec::new();
                chunk.try_reserve_exact(CHUNK)?;
                self.chunks.try_reserve(1)?;
                self.chunks.try_push(chunk).expect("reserved above");
            }
            let chunk = self.chunks.last_mut().expect("made above");
            let take = bytes.len().min(CHUNK - chunk.len());
            chunk
                .try_extend_from_slice(&bytes[..take])
                .expect("within the room reserved");
            bytes = &bytes[take..];
            n += take;
        }
        Ok(n)
    }

    /// The peer acknowledged `n` bytes: the chunks they emptied go.
    fn ack(&mut self, n: usize) {
        let mut n = n.min(self.in_flight);
        self.in_flight -= n;
        while n > 0 {
            let first = self
                .chunks
                .first()
                .expect("acknowledged bytes are held")
                .len();
            let take = n.min(first - self.acked);
            self.acked += take;
            n -= take;
            if self.acked == CHUNK {
                self.chunks.remove(0);
                self.acked = 0;
            }
        }
    }

    /// The bytes not yet handed, as pieces for the library: how many
    /// pieces and bytes, at most `vecs.len()` pieces.
    fn hand(&mut self, vecs: &mut [sys::nghttp3_vec]) -> (usize, usize) {
        let mut skip = self.acked + self.in_flight;
        let (mut count, mut total) = (0, 0);
        for chunk in &mut self.chunks {
            if count == vecs.len() {
                break;
            }
            if skip >= chunk.len() {
                skip -= chunk.len();
                continue;
            }
            // A pointer, not a slice: the library holds the chunk's earlier
            // bytes, which no reference made here may claim.
            // SAFETY: `skip` is within the chunk's bytes.
            let base = unsafe { chunk.as_mut_ptr().add(skip) };
            let len = chunk.len() - skip;
            skip = 0;
            vecs[count] = sys::nghttp3_vec { base, len };
            count += 1;
            total += len;
        }
        self.in_flight += total;
        (count, total)
    }
}

/// What the libraries' callbacks reach: the connection's state, and what
/// a call lends.
struct Inner {
    conn: *mut sys::ngtcp2_conn,
    /// Made as the 1-RTT keys arrive.
    h3: *mut sys::nghttp3_conn,
    /// What ngtcp2's crypto finds the connection by, the `SSL`'s
    /// application data while the connection lives.
    conn_ref: sys::ngtcp2_crypto_conn_ref,
    lent: Option<Lent>,
    bodies: Vec<Body>,
    /// What the connection closes with (`last_error`).
    last_error: sys::ngtcp2_ccerr,
    local: Addr,
}

/// What a call into the libraries lends their callbacks.
#[derive(Clone, Copy)]
struct Lent {
    call: *mut (dyn DriveCall + 'static),
    events: *mut EventSink,
}

/// What hears what the connection read.
type EventSink = dyn FnMut(&mut TlsCx<'_>, Event<'_>) -> Heard;

/// An `Inner` owned through one raw pointer alone (made by `Box::leak`,
/// freed as this goes), the libraries' user data for their lives.
struct UserData(NonNull<Inner>);

impl UserData {
    fn ptr(&self) -> *mut Inner {
        self.0.as_ptr()
    }
}

impl Drop for UserData {
    fn drop(&mut self) {
        // SAFETY: made by `Box::leak` in `Connection::client`, freed once,
        // here, after the libraries that held it are gone.
        drop(unsafe { Box::from_raw(self.0.as_ptr()) });
    }
}

/// The body of `stream`, if it has one.
fn body_of(bodies: &mut [Body], stream: i64) -> Option<&mut Body> {
    bodies.iter_mut().find(|b| b.stream == stream)
}

/// Tell the caller of the call under way of `event`.
///
/// # Safety
/// From a callback of a call that lent `inner` what it reaches, holding
/// no reference into it.
unsafe fn tell(inner: *mut Inner, event: Event<'_>) -> Heard {
    // SAFETY: as the caller says.
    let lent = unsafe { (*inner).lent }.expect("the libraries call back during a call");
    let mut heard = Heard::Fine;
    // SAFETY: lent for the call under way, by the caller of the library,
    // which uses neither until the call returns; the event sink is not
    // reached from inside itself, which cannot call the connection.
    let events = unsafe { &mut *lent.events };
    let mut event = Some(event);
    // SAFETY: as above.
    unsafe { &mut *lent.call }.with_cx(&mut |cx| {
        heard = events(cx, event.take().expect("told once"));
    });
    heard
}

/// The `len` bytes at `p`, which a library may give as NULL when there
/// are none.
///
/// # Safety
/// Unless `len` is 0, `p` points at `len` bytes alive for `'a`.
unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    // SAFETY: as the caller says.
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// The state behind `user_data`.
fn inner_of(user_data: *mut c_void) -> *mut Inner {
    user_data.cast()
}

/// A client connection (`ngtcp2_conn` and `nghttp3_conn`).
pub struct Connection {
    inner: UserData,
    ossl_ctx: *mut sys::ngtcp2_crypto_ossl_ctx,
    /// The session ngtcp2's crypto drives, freed first as C frees it.
    tls: ManuallyDrop<Box<dyn QuicTls>>,
}

// SAFETY: the connection is used by one thread at a time, through
// `&mut`; neither library keeps thread-local state.
unsafe impl Send for Connection {}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Connection")
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: dropped once, here, as C frees the session first
        // (`Curl_cf_ngtcp2_ctx_cleanup`); nothing calls it after.
        unsafe { ManuallyDrop::drop(&mut self.tls) };
        let inner = self.inner.ptr();
        // SAFETY: the state, alive until `inner` goes after this.
        let h3 = unsafe { (*inner).h3 };
        let conn = self.conn();
        if !h3.is_null() {
            // SAFETY: made by `nghttp3_conn_client_new`, freed once.
            unsafe { sys::nghttp3_conn_del(h3) };
        }
        // SAFETY: made by `ngtcp2_conn_client_new`, freed once.
        unsafe { sys::ngtcp2_conn_del(conn) };
        // SAFETY: made by `ngtcp2_crypto_ossl_ctx_new`, freed once, after
        // the connection that used it.
        unsafe { sys::ngtcp2_crypto_ossl_ctx_del(self.ossl_ctx) };
    }
}

/// The callbacks ngtcp2 is given (`ng_callbacks`).
static CALLBACKS: sys::ngtcp2_callbacks = sys::ngtcp2_callbacks {
    client_initial: Some(sys::ngtcp2_crypto_client_initial_cb),
    recv_client_initial: None,
    recv_crypto_data: Some(sys::ngtcp2_crypto_recv_crypto_data_cb),
    handshake_completed: Some(handshake_completed),
    recv_version_negotiation: None,
    encrypt: Some(sys::ngtcp2_crypto_encrypt_cb),
    decrypt: Some(sys::ngtcp2_crypto_decrypt_cb),
    hp_mask: Some(sys::ngtcp2_crypto_hp_mask_cb),
    recv_stream_data: Some(recv_stream_data),
    acked_stream_data_offset: Some(acked_stream_data_offset),
    stream_open: None,
    stream_close: None,
    recv_stateless_reset: None,
    recv_retry: Some(sys::ngtcp2_crypto_recv_retry_cb),
    extend_max_local_streams_bidi: Some(extend_max_local_streams_bidi),
    extend_max_local_streams_uni: None,
    rand: Some(rand),
    get_new_connection_id: None,
    remove_connection_id: None,
    update_key: Some(sys::ngtcp2_crypto_update_key_cb),
    path_validation: None,
    select_preferred_addr: None,
    stream_reset: Some(stream_reset),
    extend_max_remote_streams_bidi: None,
    extend_max_remote_streams_uni: None,
    extend_max_stream_data: Some(extend_max_stream_data),
    dcid_status: None,
    handshake_confirmed: None,
    recv_new_token: None,
    delete_crypto_aead_ctx: Some(sys::ngtcp2_crypto_delete_crypto_aead_ctx_cb),
    delete_crypto_cipher_ctx: Some(sys::ngtcp2_crypto_delete_crypto_cipher_ctx_cb),
    recv_datagram: None,
    ack_datagram: None,
    lost_datagram: None,
    get_path_challenge_data: None,
    stream_stop_sending: Some(stream_stop_sending),
    version_negotiation: None,
    recv_rx_key: Some(recv_rx_key),
    recv_tx_key: None,
    tls_early_data_rejected: None,
    begin_path_validation: None,
    recv_stateless_reset2: None,
    get_new_connection_id2: Some(get_new_connection_id2),
    dcid_status2: None,
    get_path_challenge_data2: Some(sys::ngtcp2_crypto_get_path_challenge_data2_cb),
    recv_stop_sending: None,
    stream_close2: Some(stream_close2),
};

/// The callbacks nghttp3 is given (`ngh3_callbacks`).
static H3_CALLBACKS: sys::nghttp3_callbacks = sys::nghttp3_callbacks {
    acked_stream_data: Some(h3_acked_req_body),
    stream_close: Some(h3_stream_close),
    recv_data: Some(h3_recv_data),
    deferred_consume: Some(h3_deferred_consume),
    begin_headers: None,
    recv_header: Some(h3_recv_header),
    end_headers: Some(h3_end_headers),
    begin_trailers: None,
    recv_trailer: Some(h3_recv_header),
    end_trailers: None,
    stop_sending: Some(h3_stop_sending),
    end_stream: None,
    reset_stream: Some(h3_reset_stream),
    shutdown: None,
    recv_settings: None,
    recv_origin: None,
    end_origin: None,
    rand: None,
    recv_settings2: None,
    stream_close2: None,
};

impl Connection {
    /// A client connection with C's settings (`cf_connect_start`,
    /// `quic_settings`).
    fn client(setup: &ClientSetup, tls: Box<dyn QuicTls>) -> Result<Connection, ConnectFailed> {
        crypto_init();
        let mut dcid = sys::ngtcp2_cid {
            datalen: sys::NGTCP2_MAX_CIDLEN,
            data: [0; sys::NGTCP2_MAX_CIDLEN],
        };
        let mut scid = dcid;
        curl_os::random::fill(&mut dcid.data).map_err(|_| ConnectFailed::Refused)?;
        curl_os::random::fill(&mut scid.data).map_err(|_| ConnectFailed::Refused)?;

        // SAFETY: all zeroes is a valid value of each; the library sets
        // its defaults over it.
        let mut settings: sys::ngtcp2_settings = unsafe { core::mem::zeroed() };
        // SAFETY: a settings of the version named.
        unsafe {
            sys::ngtcp2_settings_default_versioned(sys::NGTCP2_SETTINGS_VERSION, &mut settings)
        };
        // SAFETY: as above.
        let mut params: sys::ngtcp2_transport_params = unsafe { core::mem::zeroed() };
        // SAFETY: parameters of the version named.
        unsafe {
            sys::ngtcp2_transport_params_default_versioned(
                sys::NGTCP2_TRANSPORT_PARAMS_VERSION,
                &mut params,
            )
        };
        settings.log_printf = None;
        settings.initial_ts = ts(setup.now);
        settings.handshake_timeout = nanos(setup.handshake_timeout);
        settings.max_window = setup.max_window;
        // Not ngtcp2's tuning of the window: the caller opens it.
        settings.max_stream_window = 0;
        settings.no_pmtud = 0;
        // Ten times ngtcp2's, for Caddy.
        settings.glitch_ratelim_burst = 1000 * 10;
        settings.glitch_ratelim_rate = 33 * 10;
        params.initial_max_data = settings.max_window;
        params.initial_max_stream_data_bidi_local = setup.stream_window;
        params.initial_max_stream_data_bidi_remote = setup.stream_window;
        params.initial_max_stream_data_uni = params.initial_max_data;
        params.initial_max_streams_bidi = setup.max_streams;
        params.initial_max_streams_uni = setup.max_streams;
        // No idle timeout of ours.
        params.max_idle_timeout = 0;

        let inner = try_box(Inner {
            conn: ptr::null_mut(),
            h3: ptr::null_mut(),
            conn_ref: sys::ngtcp2_crypto_conn_ref {
                get_conn: Some(get_conn),
                user_data: ptr::null_mut(),
            },
            lent: None,
            bodies: Vec::new(),
            // SAFETY: all zeroes is a valid value; set below.
            last_error: unsafe { core::mem::zeroed() },
            local: Addr::new(setup.local),
        })?;
        let inner = UserData(NonNull::from(Box::leak(inner)));
        let p = inner.ptr();
        let mut remote = Addr::new(setup.remote);
        // SAFETY: the state just made, which nothing else reaches yet.
        let local = unsafe { (*p).local.ngtcp2() };
        let path = sys::ngtcp2_path {
            local,
            remote: remote.ngtcp2(),
            user_data: ptr::null_mut(),
        };
        let mut conn = ptr::null_mut();
        // SAFETY: the ids, path, callbacks, settings and parameters, of
        // the versions named, which the library copies; the user data
        // outlives the connection.
        let rc = unsafe {
            sys::ngtcp2_conn_client_new_versioned(
                &mut conn,
                &dcid,
                &scid,
                &path,
                sys::NGTCP2_PROTO_VER_V1,
                sys::NGTCP2_CALLBACKS_VERSION,
                &CALLBACKS,
                sys::NGTCP2_SETTINGS_VERSION,
                &settings,
                sys::NGTCP2_TRANSPORT_PARAMS_VERSION,
                &params,
                ptr::null(),
                p.cast(),
            )
        };
        if rc != 0 {
            return Err(ConnectFailed::Refused);
        }
        // SAFETY: the state, which no callback reaches outside a call.
        let state = unsafe { &mut *p };
        state.conn = conn;
        state.conn_ref.user_data = p.cast();
        // SAFETY: the error, to set to "none".
        unsafe { sys::ngtcp2_ccerr_default(&mut state.last_error) };
        let conn_ref = ptr::from_mut(&mut state.conn_ref);
        let mut made = Connection {
            inner,
            ossl_ctx: ptr::null_mut(),
            tls: ManuallyDrop::new(tls),
        };
        let ssl = made
            .tls
            .native()
            .session()
            .expect("a QUIC session is made with its SSL")
            .as_ptr();
        // SAFETY: the session's SSL, alive while `made` is; its
        // application data is ngtcp2's crypto's, which finds the
        // connection through it, until the SSL goes.
        unsafe { sys::ssl_set_app_data(ssl, conn_ref.cast()) };
        // SAFETY: an out pointer, and the session's SSL.
        if unsafe { sys::ngtcp2_crypto_ossl_ctx_new(&mut made.ossl_ctx, ssl) } != 0 {
            return Err(ConnectFailed::Crypto {
                why: "ngtcp2_crypto_ossl_ctx_new failed",
            });
        }
        // SAFETY: the connection, and the crypto context, which outlives
        // it.
        unsafe { sys::ngtcp2_conn_set_tls_native_handle(conn, made.ossl_ctx.cast()) };
        // SAFETY: the session's SSL.
        if unsafe { sys::ngtcp2_crypto_ossl_configure_client_session(ssl) } != 0 {
            return Err(ConnectFailed::Crypto {
                why: "ngtcp2_crypto_ossl_configure_client_session failed",
            });
        }
        Ok(made)
    }

    fn conn(&self) -> *mut sys::ngtcp2_conn {
        // SAFETY: the state; its connection is set once, when made.
        unsafe { (*self.inner.ptr()).conn }
    }

    fn h3(&self) -> *mut sys::nghttp3_conn {
        // SAFETY: the state, which no callback touches between calls.
        unsafe { (*self.inner.ptr()).h3 }
    }

    /// Run `op`, a call into the libraries, inside the session's drive,
    /// with what their callbacks reach lent for it.
    fn call<R>(
        &mut self,
        cx: &mut TlsCx<'_>,
        events: Events<'_>,
        op: impl FnOnce(*mut Inner) -> R,
    ) -> R {
        let inner = self.inner.ptr();
        let conn = self.conn();
        let mut params = || encode_params(conn);
        let events: *mut (dyn FnMut(&mut TlsCx<'_>, Event<'_>) -> Heard + '_) = events;
        // SAFETY: the sink is lent for this call alone, taken back below
        // before it goes out of scope; only the lifetime is erased.
        let events = unsafe {
            core::mem::transmute::<
                *mut (dyn FnMut(&mut TlsCx<'_>, Event<'_>) -> Heard + '_),
                *mut EventSink,
            >(events)
        };
        let mut op = Some(op);
        let mut out = None;
        self.tls.drive(cx, &mut params, &mut |dc| {
            let dc: *mut (dyn DriveCall + '_) = dc;
            // SAFETY: as above: lent for `op` alone.
            let call = unsafe {
                core::mem::transmute::<*mut (dyn DriveCall + '_), *mut (dyn DriveCall + 'static)>(
                    dc,
                )
            };
            // SAFETY: the state; no callback runs outside `op`.
            unsafe { (*inner).lent = Some(Lent { call, events }) };
            out = Some(op.take().expect("the session drives a call once")(inner));
            // SAFETY: as above.
            unsafe { (*inner).lent = None };
        });
        out.expect("the session drives the call")
    }
}

/// The transport parameters a session the peer gives is kept with, for
/// early data on its resumption (`quic_ossl_new_session_cb`).
fn encode_params(conn: *mut sys::ngtcp2_conn) -> Option<Vec<u8>> {
    let mut buf = [0u8; 256];
    // SAFETY: the connection, and the buffer's bytes.
    let n =
        unsafe { sys::ngtcp2_conn_encode_0rtt_transport_params(conn, buf.as_mut_ptr(), buf.len()) };
    let n = usize::try_from(n).ok()?;
    let mut params = Vec::new();
    params.try_extend_from_slice(&buf[..n]).ok()?;
    Some(params)
}

impl curl_core::http3::Connection for Connection {
    fn read_packet(
        &mut self,
        cx: &mut TlsCx<'_>,
        now: Instant,
        from: SocketAddr,
        ecn: u8,
        packet: &[u8],
        events: Events<'_>,
    ) -> Result<(), QuicError> {
        let conn = self.conn();
        let mut remote = Addr::new(from);
        self.call(cx, events, |inner| {
            // SAFETY: the state's local address, read and copied before the
            // call; no callback writes it.
            let local = unsafe { (*inner).local.ngtcp2() };
            let path = sys::ngtcp2_path {
                local,
                remote: remote.ngtcp2(),
                user_data: ptr::null_mut(),
            };
            let pi = sys::ngtcp2_pkt_info { ecn };
            // SAFETY: the connection, path, packet info and packet, which
            // outlive the call.
            let rv = unsafe {
                sys::ngtcp2_conn_read_pkt_versioned(
                    conn,
                    &path,
                    sys::NGTCP2_PKT_INFO_VERSION,
                    &pi,
                    packet.as_ptr(),
                    packet.len(),
                    ts(now),
                )
            };
            if rv == 0 {
                Ok(())
            } else {
                Err(quic_error("ngtcp2_conn_read_pkt", rv))
            }
        })
    }

    fn write_packet(
        &mut self,
        cx: &mut TlsCx<'_>,
        now: Instant,
        buf: &mut [u8],
        events: Events<'_>,
    ) -> Result<Option<usize>, QuicError> {
        let conn = self.conn();
        self.call(cx, events, |inner| write_packet(inner, conn, ts(now), buf))
    }

    fn before_recv(&mut self, cx: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        self.tls.before_recv(cx)
    }

    fn sent_at(&mut self, now: Instant) {
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_update_pkt_tx_time(self.conn(), ts(now)) };
    }

    fn max_payload(&self) -> usize {
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_get_max_tx_udp_payload_size(self.conn()) }
    }

    fn path_max_payload(&self) -> usize {
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_get_path_max_tx_udp_payload_size(self.conn()) }
    }

    fn send_quantum(&self) -> usize {
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_get_send_quantum(self.conn()) }
    }

    fn expiry(&self, now: Instant) -> Expiry {
        // SAFETY: the connection.
        let at = unsafe { sys::ngtcp2_conn_get_expiry(self.conn()) };
        let now = ts(now);
        if at == u64::MAX {
            Expiry::Never
        } else if at <= now {
            Expiry::Due
        } else {
            Expiry::In(Duration::from_nanos(at - now))
        }
    }

    fn handle_expiry(
        &mut self,
        cx: &mut TlsCx<'_>,
        now: Instant,
        events: Events<'_>,
    ) -> Result<(), QuicError> {
        let conn = self.conn();
        self.call(cx, events, |_| {
            // SAFETY: the connection.
            let rv = unsafe { sys::ngtcp2_conn_handle_expiry(conn, ts(now)) };
            if rv == 0 {
                Ok(())
            } else {
                Err(quic_error("ngtcp2_conn_handle_expiry", rv))
            }
        })
    }

    fn handshake_done(&self) -> bool {
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_get_handshake_completed(self.conn()) != 0 }
    }

    fn draining(&self) -> bool {
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_in_draining_period(self.conn()) != 0 }
    }

    fn peer_idle_timeout(&self) -> Option<Duration> {
        // SAFETY: the connection; its peer's parameters, or none yet.
        let rp = unsafe { sys::ngtcp2_conn_get_remote_transport_params(self.conn()) };
        // SAFETY: none, or the connection's, alive until its next call.
        let rp = unsafe { rp.as_ref() }?;
        (rp.max_idle_timeout != 0).then(|| Duration::from_nanos(rp.max_idle_timeout))
    }

    fn set_keep_alive(&mut self, every: Option<Duration>) {
        let timeout = every.map_or(u64::MAX, nanos);
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_set_keep_alive_timeout(self.conn(), timeout) };
    }

    fn send_room(&self) -> bool {
        let conn = self.conn();
        // SAFETY: the connection.
        let cwnd = unsafe { sys::ngtcp2_conn_get_cwnd_left(conn) };
        // SAFETY: the connection.
        let data = unsafe { sys::ngtcp2_conn_get_max_data_left(conn) };
        cwnd > 0 && data > 0
    }

    fn failed(&mut self, error: QuicError) -> bool {
        let conn = self.conn();
        let inner = self.inner.ptr();
        // SAFETY: the state, between calls.
        let last = unsafe { &mut (*inner).last_error };
        match error.layer {
            Layer::Quic => {
                if last.error_code == 0 {
                    if error.code == sys::NGTCP2_ERR_CRYPTO {
                        // SAFETY: the connection.
                        let alert = unsafe { sys::ngtcp2_conn_get_tls_alert(conn) };
                        // SAFETY: the error, and no reason.
                        unsafe { sys::ngtcp2_ccerr_set_tls_alert(last, alert, ptr::null(), 0) };
                    } else {
                        // SAFETY: as above.
                        unsafe { sys::ngtcp2_ccerr_set_liberr(last, error.code, ptr::null(), 0) };
                    }
                }
                error.code <= sys::NGTCP2_ERR_FATAL
                    || error.code == sys::NGTCP2_ERR_DROP_CONN
                    || error.code == sys::NGTCP2_ERR_IDLE_CLOSE
            }
            Layer::Http3 => {
                set_h3_error(last, error.code);
                error.code <= sys::NGHTTP3_ERR_FATAL
                    || error.code == sys::NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM
            }
        }
    }

    fn close_error(&self) -> CloseError {
        // SAFETY: the state, between calls.
        let last = unsafe { &(*self.inner.ptr()).last_error };
        CloseError {
            kind: last.r#type,
            code: last.error_code,
        }
    }

    fn closed_with(&self) -> Option<CloseError> {
        // SAFETY: the connection; what it closed with, or NULL.
        let cerr = unsafe { sys::ngtcp2_conn_get_ccerr(self.conn()) };
        // SAFETY: none, or the connection's, alive until its next call.
        let cerr = unsafe { cerr.as_ref() }?;
        Some(CloseError {
            kind: cerr.r#type,
            code: cerr.error_code,
        })
    }

    fn write_close(&mut self, now: Instant, buf: &mut [u8]) -> Result<usize, QuicError> {
        let conn = self.conn();
        // SAFETY: the state, between calls.
        let last: *const sys::ngtcp2_ccerr = unsafe { &(*self.inner.ptr()).last_error };
        // SAFETY: the connection, the buffer's bytes and the error kept,
        // which no callback of this call touches.
        let n = unsafe {
            sys::ngtcp2_conn_write_connection_close_versioned(
                conn,
                ptr::null_mut(),
                sys::NGTCP2_PKT_INFO_VERSION,
                ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len(),
                last,
                ts(now),
            )
        };
        usize::try_from(n).map_err(|_| {
            quic_error(
                "ngtcp2_conn_write_connection_close",
                c_int::try_from(n).unwrap_or(sys::NGTCP2_ERR_FATAL),
            )
        })
    }

    fn submit_request(
        &mut self,
        fields: &[(&[u8], &[u8])],
        body: bool,
    ) -> Result<StreamId, SubmitFailed> {
        let (conn, h3) = (self.conn(), self.h3());
        assert!(!h3.is_null(), "a request goes once the connection is up");
        let mut nva = Vec::new();
        nva.try_reserve_exact(fields.len())
            .map_err(|_| SubmitFailed::OutOfMemory)?;
        for &(name, value) in fields {
            let pushed = nva.try_push(sys::nghttp3_nv {
                name: name.as_ptr(),
                value: value.as_ptr(),
                namelen: name.len(),
                valuelen: value.len(),
                flags: sys::NGHTTP3_NV_FLAG_NONE,
            });
            pushed.expect("reserved above");
        }
        // SAFETY: the state, between calls.
        let bodies = unsafe { &mut (*self.inner.ptr()).bodies };
        if body {
            bodies
                .try_reserve(1)
                .map_err(|_| SubmitFailed::OutOfMemory)?;
        }
        let mut sid = -1;
        // SAFETY: the connection, and an out pointer.
        if unsafe { sys::ngtcp2_conn_open_bidi_stream(conn, &mut sid, ptr::null_mut()) } != 0 {
            return Err(SubmitFailed::NoStream);
        }
        let reader = sys::nghttp3_data_reader {
            read_data: Some(h3_read_req_body),
        };
        let dr = if body {
            ptr::from_ref(&reader)
        } else {
            ptr::null()
        };
        if body {
            let pushed = bodies.try_push(Body {
                stream: sid,
                chunks: Vec::new(),
                acked: 0,
                in_flight: 0,
                ended: false,
                cancelled: false,
            });
            pushed.expect("reserved above");
        }
        // SAFETY: the HTTP/3 connection, the fields, which it copies, and
        // the reader, which it copies.
        let rc = unsafe {
            sys::nghttp3_conn_submit_request(h3, sid, nva.as_ptr(), nva.len(), dr, ptr::null_mut())
        };
        if rc != 0 {
            return Err(SubmitFailed::Refused {
                stream: StreamId(sid),
                error: h3_error("nghttp3_conn_submit_request", rc),
                closing: rc == sys::NGHTTP3_ERR_CONN_CLOSING,
            });
        }
        Ok(StreamId(sid))
    }

    fn write_body(&mut self, stream: StreamId, bytes: &[u8]) -> Result<usize, OutOfMemory> {
        // SAFETY: the state, between calls.
        let bodies = unsafe { &mut (*self.inner.ptr()).bodies };
        body_of(bodies, stream.0)
            .expect("a body is written to a stream submitted with one")
            .write(bytes)
    }

    fn end_body(&mut self, stream: StreamId) {
        // SAFETY: the state, between calls.
        let bodies = unsafe { &mut (*self.inner.ptr()).bodies };
        body_of(bodies, stream.0)
            .expect("a body ends on a stream submitted with one")
            .ended = true;
    }

    fn body_in_flight(&self, stream: StreamId) -> usize {
        // SAFETY: the state, between calls.
        let bodies = unsafe { &mut (*self.inner.ptr()).bodies };
        body_of(bodies, stream.0).map_or(0, |b| b.in_flight)
    }

    fn body_buffered(&self, stream: StreamId) -> usize {
        // SAFETY: the state, between calls.
        let bodies = unsafe { &mut (*self.inner.ptr()).bodies };
        body_of(bodies, stream.0).map_or(0, |b| b.buffered())
    }

    fn resume(&mut self, stream: StreamId) {
        // SAFETY: the HTTP/3 connection; a stream it does not know is
        // refused, which C ignores.
        unsafe { sys::nghttp3_conn_resume_stream(self.h3(), stream.0) };
    }

    fn cancel(&mut self, stream: StreamId, error: H3Error) {
        // SAFETY: the state, between calls.
        let bodies = unsafe { &mut (*self.inner.ptr()).bodies };
        if let Some(body) = body_of(bodies, stream.0) {
            body.cancelled = true;
        }
        // SAFETY: the connection; a stream gone already is refused, which
        // C ignores.
        unsafe { sys::ngtcp2_conn_shutdown_stream(self.conn(), 0, stream.0, error.0) };
    }

    fn extend_stream_window(&mut self, stream: StreamId, n: u64) {
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_extend_max_stream_offset(self.conn(), stream.0, n) };
    }
}

/// The next packet to send (`read_pkt_to_send`).
fn write_packet(
    inner: *mut Inner,
    conn: *mut sys::ngtcp2_conn,
    now: u64,
    buf: &mut [u8],
) -> Result<Option<usize>, QuicError> {
    loop {
        let mut vecs = [sys::nghttp3_vec {
            base: ptr::null_mut(),
            len: 0,
        }; 16];
        let mut count = 0;
        let mut sid: i64 = -1;
        let mut fin: c_int = 0;
        // SAFETY: the state's HTTP/3 connection, read before any call.
        let h3 = unsafe { (*inner).h3 };
        // SAFETY: the connection.
        if !h3.is_null() && unsafe { sys::ngtcp2_conn_get_max_data_left(conn) } > 0 {
            // SAFETY: the HTTP/3 connection, out pointers and the pieces.
            let n = unsafe {
                sys::nghttp3_conn_writev_stream(
                    h3,
                    &mut sid,
                    &mut fin,
                    vecs.as_mut_ptr(),
                    vecs.len(),
                )
            };
            count = usize::try_from(n).map_err(|_| {
                h3_error(
                    "nghttp3_conn_writev_stream",
                    c_int::try_from(n).unwrap_or(sys::NGHTTP3_ERR_FATAL),
                )
            })?;
        }
        let mut flags = sys::NGTCP2_WRITE_STREAM_FLAG_MORE;
        if fin != 0 {
            flags |= sys::NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
        let mut ndatalen: sys::ngtcp2_ssize = -1;
        // SAFETY: the connection, the buffer's bytes, and `count` pieces,
        // laid out as ngtcp2's are.
        let n = unsafe {
            sys::ngtcp2_conn_writev_stream_versioned(
                conn,
                ptr::null_mut(),
                sys::NGTCP2_PKT_INFO_VERSION,
                ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut ndatalen,
                flags,
                sid,
                vecs.as_ptr().cast::<sys::ngtcp2_vec>(),
                count,
                now,
            )
        };
        let n = match c_int::try_from(n) {
            Ok(0) => return Ok(None),
            Ok(sys::NGTCP2_ERR_STREAM_DATA_BLOCKED) => {
                // SAFETY: the HTTP/3 connection, which wrote for `sid`.
                unsafe { sys::nghttp3_conn_block_stream(h3, sid) };
                // SAFETY: inside the call, holding nothing of the state.
                unsafe {
                    tell(
                        inner,
                        Event::Blocked {
                            stream: StreamId(sid),
                        },
                    )
                };
                0
            }
            Ok(sys::NGTCP2_ERR_STREAM_SHUT_WR) => {
                // SAFETY: as above.
                unsafe { sys::nghttp3_conn_shutdown_stream_write(h3, sid) };
                0
            }
            Ok(sys::NGTCP2_ERR_WRITE_MORE) => 0,
            Ok(e) if e < 0 => return Err(quic_error("ngtcp2_conn_writev_stream", e)),
            _ => usize::try_from(n).expect("a packet's length"),
        };
        if sid >= 0
            && let Ok(written) = usize::try_from(ndatalen)
        {
            // SAFETY: the HTTP/3 connection, which wrote for `sid`.
            let rv = unsafe { sys::nghttp3_conn_add_write_offset(h3, sid, written) };
            if rv != 0 {
                return Err(h3_error("nghttp3_conn_add_write_offset", rv));
            }
        }
        if n > 0 {
            return Ok(Some(n));
        }
    }
}

/// Set what the connection closes with to the HTTP/3 library's failure
/// `code`, if nothing is set (`Curl_cf_ngtcp2_h3_err_set`).
fn set_h3_error(last: &mut sys::ngtcp2_ccerr, code: c_int) {
    if last.error_code == 0 {
        // SAFETY: it takes any code.
        let app = unsafe { sys::nghttp3_err_infer_quic_app_error_code(code) };
        // SAFETY: the error, and no reason.
        unsafe { sys::ngtcp2_ccerr_set_application_error(last, app, ptr::null(), 0) };
    }
}

/// ngtcp2's crypto finds the connection (`get_conn`).
unsafe extern "C" fn get_conn(conn_ref: *mut sys::ngtcp2_crypto_conn_ref) -> *mut sys::ngtcp2_conn {
    // SAFETY: the state's own `conn_ref`, whose user data is the state.
    let inner = inner_of(unsafe { (*conn_ref).user_data });
    // SAFETY: as above.
    unsafe { (*inner).conn }
}

/// The handshake is done: the peer checked inside it, and the caller
/// told (`cb_ngtcp2_handshake_completed`).
unsafe extern "C" fn handshake_completed(
    conn: *mut sys::ngtcp2_conn,
    user_data: *mut c_void,
) -> c_int {
    let inner = inner_of(user_data);
    // SAFETY: lent for the call under way.
    let lent = unsafe { (*inner).lent }.expect("the handshake completes during a call");
    // SAFETY: as above; not inside its own `with_cx`.
    let checked = unsafe { &mut *lent.call }.handshake_done();
    // SAFETY: the connection; its peer's parameters, which a completed
    // handshake has.
    let rp = unsafe { sys::ngtcp2_conn_get_remote_transport_params(conn) };
    // SAFETY: as above: never NULL then, alive until the next call.
    let rp = unsafe { &*rp };
    let event = Event::HandshakeDone {
        checked,
        max_udp_payload: rp.max_udp_payload_size,
        initial_max_data: rp.initial_max_data,
        early_data: None,
    };
    // SAFETY: inside the call, holding nothing of the state.
    let heard = unsafe { tell(inner, event) };
    if checked.is_err() || heard == Heard::Failed {
        sys::NGTCP2_ERR_CALLBACK_FAILURE
    } else {
        0
    }
}

/// Stream data arrived: the HTTP/3 library reads it, and the windows open
/// by the framing it took (`cb_recv_stream_data`).
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn recv_stream_data(
    conn: *mut sys::ngtcp2_conn,
    flags: u32,
    stream_id: i64,
    _offset: u64,
    data: *const u8,
    datalen: usize,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let inner = inner_of(user_data);
    // SAFETY: the state, read and copied.
    let h3 = unsafe { (*inner).h3 };
    if h3.is_null() {
        return sys::NGTCP2_ERR_CALLBACK_FAILURE;
    }
    let fin = c_int::from(flags & sys::NGTCP2_STREAM_DATA_FLAG_FIN != 0);
    // SAFETY: the HTTP/3 connection, and the library's bytes.
    let rc = unsafe { sys::nghttp3_conn_read_stream(h3, stream_id, data, datalen, fin) };
    let Ok(consumed) = u64::try_from(rc) else {
        return sys::NGTCP2_ERR_CALLBACK_FAILURE;
    };
    if consumed > 0 {
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_extend_max_stream_offset(conn, stream_id, consumed) };
        // SAFETY: the connection.
        unsafe { sys::ngtcp2_conn_extend_max_offset(conn, consumed) };
        let event = Event::Consumed {
            stream: StreamId(stream_id),
            n: consumed,
        };
        // SAFETY: inside the call, holding nothing of the state.
        unsafe { tell(inner, event) };
    }
    0
}

/// The peer acknowledged stream data (`cb_acked_stream_data_offset`).
unsafe extern "C" fn acked_stream_data_offset(
    _conn: *mut sys::ngtcp2_conn,
    stream_id: i64,
    _offset: u64,
    datalen: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    // SAFETY: the state, read and copied.
    let h3 = unsafe { (*inner_of(user_data)).h3 };
    // SAFETY: the HTTP/3 connection, which sent it.
    let rv = unsafe { sys::nghttp3_conn_add_ack_offset(h3, stream_id, datalen) };
    if rv != 0 && rv != sys::NGHTTP3_ERR_STREAM_NOT_FOUND {
        return sys::NGTCP2_ERR_CALLBACK_FAILURE;
    }
    0
}

/// A stream closed (`cb_stream_close2`).
unsafe extern "C" fn stream_close2(
    _conn: *mut sys::ngtcp2_conn,
    flags: u32,
    stream_id: i64,
    rx_app_error_code: u64,
    _tx_app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let inner = inner_of(user_data);
    let code = if flags & sys::NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET != 0 {
        rx_app_error_code
    } else {
        sys::NGHTTP3_H3_NO_ERROR
    };
    // SAFETY: the state, read and copied.
    let h3 = unsafe { (*inner).h3 };
    // SAFETY: the HTTP/3 connection.
    let rv = unsafe { sys::nghttp3_conn_close_stream(h3, stream_id, code) };
    {
        // SAFETY: the state, no other reference into it held: the
        // HTTP/3 library has returned.
        let bodies = unsafe { &mut (*inner).bodies };
        if let Some(i) = bodies.iter().position(|b| b.stream == stream_id) {
            bodies.remove(i);
        }
    }
    let event = Event::QuicClosed {
        stream: StreamId(stream_id),
        error: H3Error(code),
        rv,
    };
    // SAFETY: inside the call, holding nothing of the state.
    unsafe { tell(inner, event) };
    if rv != 0 && rv != sys::NGHTTP3_ERR_STREAM_NOT_FOUND {
        // SAFETY: the state, no other reference into it held.
        set_h3_error(unsafe { &mut (*inner).last_error }, rv);
        return sys::NGTCP2_ERR_CALLBACK_FAILURE;
    }
    0
}

/// The peer reset a stream (`cb_stream_reset`).
unsafe extern "C" fn stream_reset(
    _conn: *mut sys::ngtcp2_conn,
    stream_id: i64,
    _final_size: u64,
    _app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let inner = inner_of(user_data);
    // SAFETY: the state, read and copied.
    let h3 = unsafe { (*inner).h3 };
    // SAFETY: the HTTP/3 connection.
    let rv = unsafe { sys::nghttp3_conn_shutdown_stream_read(h3, stream_id) };
    let event = Event::QuicReset {
        stream: StreamId(stream_id),
        rv,
    };
    // SAFETY: inside the call, holding nothing of the state.
    unsafe { tell(inner, event) };
    if rv != 0 && rv != sys::NGHTTP3_ERR_STREAM_NOT_FOUND {
        return sys::NGTCP2_ERR_CALLBACK_FAILURE;
    }
    0
}

/// The peer asked a stream to stop sending (`cb_stream_stop_sending`).
unsafe extern "C" fn stream_stop_sending(
    _conn: *mut sys::ngtcp2_conn,
    stream_id: i64,
    _app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    // SAFETY: the state, read and copied.
    let h3 = unsafe { (*inner_of(user_data)).h3 };
    // SAFETY: the HTTP/3 connection.
    let rv = unsafe { sys::nghttp3_conn_shutdown_stream_read(h3, stream_id) };
    if rv != 0 && rv != sys::NGHTTP3_ERR_STREAM_NOT_FOUND {
        return sys::NGTCP2_ERR_CALLBACK_FAILURE;
    }
    0
}

/// The peer allows more streams (`cb_extend_max_local_streams_bidi`).
unsafe extern "C" fn extend_max_local_streams_bidi(
    _conn: *mut sys::ngtcp2_conn,
    max_streams: u64,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: inside the call, holding nothing of the state.
    unsafe { tell(inner_of(user_data), Event::MaxBidiStreams(max_streams)) };
    0
}

/// The peer lets a stream send more (`cb_extend_max_stream_data`).
unsafe extern "C" fn extend_max_stream_data(
    _conn: *mut sys::ngtcp2_conn,
    stream_id: i64,
    _max_data: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let inner = inner_of(user_data);
    // SAFETY: the state, read and copied.
    let h3 = unsafe { (*inner).h3 };
    // SAFETY: the HTTP/3 connection.
    let rv = unsafe { sys::nghttp3_conn_unblock_stream(h3, stream_id) };
    if rv != 0 && rv != sys::NGHTTP3_ERR_STREAM_NOT_FOUND {
        return sys::NGTCP2_ERR_CALLBACK_FAILURE;
    }
    // SAFETY: inside the call, holding nothing of the state.
    unsafe {
        tell(
            inner,
            Event::Unblocked {
                stream: StreamId(stream_id),
            },
        )
    };
    0
}

/// Random bytes, for what is not cryptographic (`cb_rand`): zeroes if
/// the kernel gives none, as C's.
unsafe extern "C" fn rand(dest: *mut u8, destlen: usize, _rand_ctx: *const sys::ngtcp2_rand_ctx) {
    if destlen == 0 {
        return;
    }
    // SAFETY: the library's buffer of `destlen` bytes, not NULL as there
    // are some.
    let out = unsafe { core::slice::from_raw_parts_mut(dest, destlen) };
    if curl_os::random::fill(out).is_err() {
        out.fill(0);
    }
}

/// A new connection id and its reset token (`cb_get_new_connection_id2`).
unsafe extern "C" fn get_new_connection_id2(
    _conn: *mut sys::ngtcp2_conn,
    cid: *mut sys::ngtcp2_cid,
    token: *mut sys::ngtcp2_stateless_reset_token,
    cidlen: usize,
    _user_data: *mut c_void,
) -> c_int {
    // SAFETY: the library's id to fill, of at most `NGTCP2_MAX_CIDLEN`.
    let cid = unsafe { &mut *cid };
    // SAFETY: the library's token to fill.
    let token = unsafe { &mut *token };
    let Some(data) = cid.data.get_mut(..cidlen) else {
        return sys::NGTCP2_ERR_CALLBACK_FAILURE;
    };
    if curl_os::random::fill(data).is_err() || curl_os::random::fill(&mut token.data).is_err() {
        return sys::NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid.datalen = cidlen;
    0
}

/// Keys arrived: with the 1-RTT ones, HTTP/3 is set up
/// (`cb_recv_rx_key`, `init_ngh3_conn`).
unsafe extern "C" fn recv_rx_key(
    conn: *mut sys::ngtcp2_conn,
    level: c_int,
    user_data: *mut c_void,
) -> c_int {
    let inner = inner_of(user_data);
    // SAFETY: the state, read and copied.
    if level != sys::NGTCP2_ENCRYPTION_LEVEL_1RTT || !unsafe { (*inner).h3 }.is_null() {
        return 0;
    }
    match init_h3(conn, user_data) {
        Ok(h3) => {
            // SAFETY: the state, no other reference into it held.
            unsafe { (*inner).h3 = h3 };
            0
        }
        Err(event) => {
            // SAFETY: inside the call, holding nothing of the state.
            unsafe { tell(inner, event) };
            sys::NGTCP2_ERR_CALLBACK_FAILURE
        }
    }
}

/// The HTTP/3 connection over `conn`, its control and QPACK streams bound
/// (`init_ngh3_conn`, `Curl_cf_ngtcp2_h3_init_ctrls`); or why not.
fn init_h3(
    conn: *mut sys::ngtcp2_conn,
    user_data: *mut c_void,
) -> Result<*mut sys::nghttp3_conn, Event<'static>> {
    let failed = |why, detail| Event::H3Failed {
        why,
        detail,
        out_of_memory: false,
    };
    // SAFETY: the connection.
    if unsafe { sys::ngtcp2_conn_get_streams_uni_left(conn) } < 3 {
        return Err(failed(
            "QUIC connection lacks 3 uni streams to run HTTP/3",
            None,
        ));
    }
    // SAFETY: all zeroes is a valid value; the library sets its defaults
    // over it.
    let mut settings: sys::nghttp3_settings = unsafe { core::mem::zeroed() };
    // SAFETY: settings of the version named.
    unsafe {
        sys::nghttp3_settings_default_versioned(sys::NGHTTP3_SETTINGS_VERSION, &mut settings)
    };
    let mut h3 = ptr::null_mut();
    // SAFETY: the callbacks and settings, of the versions named, which
    // the library copies; its user data is the QUIC connection's.
    let rc = unsafe {
        sys::nghttp3_conn_client_new_versioned(
            &mut h3,
            sys::NGHTTP3_CALLBACKS_VERSION,
            &H3_CALLBACKS,
            sys::NGHTTP3_SETTINGS_VERSION,
            &settings,
            ptr::null(),
            user_data,
        )
    };
    if rc != 0 {
        return Err(Event::H3Failed {
            why: "error creating nghttp3 connection instance",
            detail: None,
            out_of_memory: true,
        });
    }
    let close = |event| {
        // SAFETY: made above, not yet handed out.
        unsafe { sys::nghttp3_conn_del(h3) };
        Err(event)
    };
    let mut ids = [0i64; 3];
    let whys = [
        "error creating HTTP/3 control stream",
        "error creating HTTP/3 qpack encoding stream",
        "error creating HTTP/3 qpack decoding stream",
    ];
    for (i, why) in whys.into_iter().enumerate() {
        // SAFETY: the connection, and an out pointer.
        let rc = unsafe { sys::ngtcp2_conn_open_uni_stream(conn, &mut ids[i], ptr::null_mut()) };
        if rc != 0 {
            return close(failed(why, Some(quic_error("", rc).text)));
        }
        if i == 0 {
            // SAFETY: the HTTP/3 connection.
            let rc = unsafe { sys::nghttp3_conn_bind_control_stream(h3, ids[0]) };
            if rc != 0 {
                // C says it in ngtcp2's words, whatever the code.
                return close(failed(
                    "error binding HTTP/3 control stream",
                    Some(quic_error("", rc).text),
                ));
            }
        }
    }
    // SAFETY: the HTTP/3 connection.
    let rc = unsafe { sys::nghttp3_conn_bind_qpack_streams(h3, ids[1], ids[2]) };
    if rc != 0 {
        return close(failed(
            "error binding HTTP/3 qpack streams",
            Some(quic_error("", rc).text),
        ));
    }
    Ok(h3)
}

/// The peer acknowledged request body (`cb_h3_acked_req_body`).
unsafe extern "C" fn h3_acked_req_body(
    conn: *mut sys::nghttp3_conn,
    stream_id: i64,
    datalen: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let more = {
        // SAFETY: the state, no other reference into it held.
        let bodies = unsafe { &mut (*inner_of(user_data)).bodies };
        let Some(body) = body_of(bodies, stream_id) else {
            return 0;
        };
        body.ack(usize::try_from(datalen).unwrap_or(usize::MAX));
        body.in_flight < body.buffered()
    };
    if more {
        // SAFETY: the HTTP/3 connection.
        let rv = unsafe { sys::nghttp3_conn_resume_stream(conn, stream_id) };
        if rv != 0 && rv != sys::NGHTTP3_ERR_STREAM_NOT_FOUND {
            return sys::NGHTTP3_ERR_CALLBACK_FAILURE;
        }
    }
    0
}

/// A stream closed (`cb_h3_stream_close`).
unsafe extern "C" fn h3_stream_close(
    _conn: *mut sys::nghttp3_conn,
    stream_id: i64,
    app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let event = Event::Closed {
        stream: StreamId(stream_id),
        error: H3Error(app_error_code),
    };
    // SAFETY: inside the call, holding nothing of the state.
    unsafe { tell(inner_of(user_data), event) };
    0
}

/// Body bytes of a stream (`cb_h3_recv_data`).
unsafe extern "C" fn h3_recv_data(
    _conn: *mut sys::nghttp3_conn,
    stream_id: i64,
    data: *const u8,
    datalen: usize,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let inner = inner_of(user_data);
    // SAFETY: the state, read and copied.
    let conn = unsafe { (*inner).conn };
    // SAFETY: the library's bytes, alive for the callback.
    let bytes = unsafe { bytes(data, datalen) };
    let event = Event::Data {
        stream: StreamId(stream_id),
        bytes,
    };
    // SAFETY: inside the call, holding nothing of the state.
    if unsafe { tell(inner, event) } == Heard::Failed {
        return sys::NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    // SAFETY: the connection.
    unsafe { sys::ngtcp2_conn_extend_max_offset(conn, datalen as u64) };
    0
}

/// The HTTP/3 library took framing it had deferred
/// (`cb_h3_deferred_consume`).
unsafe extern "C" fn h3_deferred_consume(
    _conn: *mut sys::nghttp3_conn,
    stream_id: i64,
    consumed: usize,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let inner = inner_of(user_data);
    // SAFETY: the state, read and copied.
    let conn = unsafe { (*inner).conn };
    let n = consumed as u64;
    // SAFETY: the connection.
    unsafe { sys::ngtcp2_conn_extend_max_stream_offset(conn, stream_id, n) };
    // SAFETY: the connection.
    unsafe { sys::ngtcp2_conn_extend_max_offset(conn, n) };
    let event = Event::Consumed {
        stream: StreamId(stream_id),
        n,
    };
    // SAFETY: inside the call, holding nothing of the state.
    unsafe { tell(inner, event) };
    0
}

/// A field of a header block (`cb_h3_recv_header`).
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn h3_recv_header(
    _conn: *mut sys::nghttp3_conn,
    stream_id: i64,
    token: i32,
    name: *mut sys::nghttp3_rcbuf,
    value: *mut sys::nghttp3_rcbuf,
    _flags: u8,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    // SAFETY: the library's buffers, alive for the callback.
    let name = unsafe { sys::nghttp3_rcbuf_get_buf(name) };
    // SAFETY: as above.
    let value = unsafe { sys::nghttp3_rcbuf_get_buf(value) };
    // SAFETY: as above: their bytes.
    let name = unsafe { bytes(name.base, name.len) };
    // SAFETY: as above.
    let value = unsafe { bytes(value.base, value.len) };
    let event = Event::Header {
        stream: StreamId(stream_id),
        name,
        value,
        status: token == sys::NGHTTP3_QPACK_TOKEN__STATUS,
    };
    // SAFETY: inside the call, holding nothing of the state.
    match unsafe { tell(inner_of(user_data), event) } {
        Heard::Fine => 0,
        Heard::Failed => sys::NGHTTP3_ERR_CALLBACK_FAILURE,
    }
}

/// A header block ended (`cb_h3_end_headers`).
unsafe extern "C" fn h3_end_headers(
    _conn: *mut sys::nghttp3_conn,
    stream_id: i64,
    _fin: c_int,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let event = Event::HeadersDone {
        stream: StreamId(stream_id),
    };
    // SAFETY: inside the call, holding nothing of the state.
    unsafe { tell(inner_of(user_data), event) };
    0
}

/// The peer asked a stream to stop sending (`cb_h3_stop_sending`).
unsafe extern "C" fn h3_stop_sending(
    _conn: *mut sys::nghttp3_conn,
    stream_id: i64,
    app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    // SAFETY: the state, read and copied.
    let conn = unsafe { (*inner_of(user_data)).conn };
    // SAFETY: the connection.
    let rv = unsafe { sys::ngtcp2_conn_shutdown_stream_read(conn, 0, stream_id, app_error_code) };
    if rv != 0 && rv != sys::NGTCP2_ERR_STREAM_NOT_FOUND {
        return sys::NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    0
}

/// The peer reset a stream's sending (`cb_h3_reset_stream`).
unsafe extern "C" fn h3_reset_stream(
    _conn: *mut sys::nghttp3_conn,
    stream_id: i64,
    app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let inner = inner_of(user_data);
    // SAFETY: the state, read and copied.
    let conn = unsafe { (*inner).conn };
    // SAFETY: the connection.
    let rv = unsafe { sys::ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, app_error_code) };
    let event = Event::H3Reset {
        stream: StreamId(stream_id),
        rv,
    };
    // SAFETY: inside the call, holding nothing of the state.
    unsafe { tell(inner, event) };
    if rv != 0 && rv != sys::NGTCP2_ERR_STREAM_NOT_FOUND {
        return sys::NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    0
}

/// The HTTP/3 library reads request body to send
/// (`cb_h3_read_req_body`).
unsafe extern "C" fn h3_read_req_body(
    _conn: *mut sys::nghttp3_conn,
    stream_id: i64,
    vec: *mut sys::nghttp3_vec,
    veccnt: usize,
    pflags: *mut u32,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> sys::nghttp3_ssize {
    let inner = inner_of(user_data);
    let (count, n, eof, buffered) = {
        // SAFETY: the state, no other reference into it held.
        let bodies = unsafe { &mut (*inner).bodies };
        let Some(body) = body_of(bodies, stream_id) else {
            return sys::NGHTTP3_ERR_CALLBACK_FAILURE as sys::nghttp3_ssize;
        };
        let vecs: &mut [sys::nghttp3_vec] = if veccnt == 0 {
            &mut []
        } else {
            // SAFETY: the library's `veccnt` pieces to fill, some.
            unsafe { core::slice::from_raw_parts_mut(vec, veccnt) }
        };
        let (count, n) = body.hand(vecs);
        let eof = body.ended && body.in_flight == body.buffered();
        (count, n, eof, body.buffered())
    };
    if eof {
        // SAFETY: the library's flags to set.
        unsafe { *pflags = sys::NGHTTP3_DATA_FLAG_EOF };
    }
    let event = Event::BodyRead {
        stream: StreamId(stream_id),
        vecs: count,
        n,
        eof,
        buffered,
    };
    // SAFETY: inside the call, holding nothing of the state.
    unsafe { tell(inner, event) };
    if !eof && n == 0 {
        return sys::NGHTTP3_ERR_WOULDBLOCK;
    }
    sys::nghttp3_ssize::try_from(count).expect("at most the pieces given")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_macros)]

    use super::*;

    fn body() -> Body {
        Body {
            stream: 0,
            chunks: Vec::new(),
            acked: 0,
            in_flight: 0,
            ended: false,
            cancelled: false,
        }
    }

    fn empty() -> [sys::nghttp3_vec; 4] {
        [sys::nghttp3_vec {
            base: ptr::null_mut(),
            len: 0,
        }; 4]
    }

    /// A body holds ten chunks at most, as C's buffer does; what is
    /// handed is what was not, piece by chunk, and what was handed stays
    /// where it was as more is written.
    #[test]
    fn a_body_hands_what_it_holds_once_and_keeps_it_in_place() {
        let mut b = body();
        let big = vec![7u8; BODY_HELD + 10];
        assert_eq!(b.write(&big[..CHUNK + 5]).unwrap(), CHUNK + 5);
        let mut vecs = empty();
        assert_eq!(b.hand(&mut vecs), (2, CHUNK + 5));
        let (first, second) = (vecs[0].base, vecs[1].base);
        assert_eq!((vecs[0].len, vecs[1].len), (CHUNK, 5));
        assert_eq!(b.hand(&mut empty()), (0, 0));
        // More fills the second chunk's room first, and moves nothing:
        // what the library was handed still reads.
        assert_eq!(b.write(&big[..BODY_HELD]).unwrap(), BODY_HELD - CHUNK - 5);
        // SAFETY: handed pieces, which the body keeps until acknowledged.
        let last = unsafe { second.add(4) };
        // SAFETY: as above.
        assert_eq!(unsafe { *first }, 7);
        // SAFETY: as above.
        assert_eq!(unsafe { *last }, 7);
        let mut vecs = empty();
        let (n, total) = b.hand(&mut vecs);
        assert_eq!((n, total), (4, 4 * CHUNK - 5));
        assert_eq!(vecs[0].len, CHUNK - 5);
        assert_eq!(b.buffered(), BODY_HELD);
        assert_eq!(b.in_flight, 5 * CHUNK);
    }

    /// The peer's acknowledgement frees whole chunks alone, and never more
    /// than was handed.
    #[test]
    fn an_acknowledged_chunk_goes_and_room_comes_back() {
        let mut b = body();
        let big = vec![1u8; BODY_HELD];
        assert_eq!(b.write(&big).unwrap(), BODY_HELD);
        assert_eq!(b.write(b"x").unwrap(), 0);
        let mut vecs = empty();
        b.hand(&mut vecs);
        b.ack(CHUNK - 1);
        assert_eq!(b.chunks.len(), 10);
        assert_eq!(b.write(b"x").unwrap(), 0);
        b.ack(1);
        assert_eq!(b.chunks.len(), 9);
        assert_eq!(b.buffered(), BODY_HELD - CHUNK);
        assert_eq!(b.write(b"xy").unwrap(), 2);
        // An acknowledgement past what was handed takes only that.
        b.ack(usize::MAX);
        assert_eq!(b.in_flight, 0);
        assert_eq!(b.buffered(), BODY_HELD - CHUNK + 2 - 3 * CHUNK);
    }
}
