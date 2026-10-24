//! TLS, as the core asks it of the library bound beside it (C's
//! `vtls`): the settings a connection's handshake is made with, which
//! decide which connections a transfer may reuse, and the seam a TLS
//! library implements. The library makes a session for each connection
//! (`TlsBackend`), and the core drives it as a layer over the
//! connection's stream (`TlsSession`), handing it the layers below to
//! read and write through (`TlsIo`). The core names no library's types.

use std::any::Any;
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::ptr::NonNull;
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc, try_box};

use crate::components::Component;
use crate::conn::Peer;
use crate::conn::io::{Recv, Sent};
use crate::conn::layer::{Below, LayerCx};
use crate::error::ErrorKind;
use crate::handler::DebugKind;
use crate::options::{CaSetting, Tls, TlsOptions};
use crate::report::CertInfo;
use crate::time::Instant;

pub use crate::conn::layer::Handshake;
pub(crate) use cache::SessionCache;
pub use cache::{SessionPeer, TLS1_3, TlsTicket};
pub use keylog::KeyLog;
pub use pin::pin_peer_pubkey;

mod cache;
mod keylog;
mod pin;

/// A test double: a TLS library of text lines and scrambled records.
#[cfg(any(test, feature = "test-util"))]
pub mod fake;

/// A TLS library (C's `struct Curl_ssl`). Whoever builds a handle names
/// one in its `Libraries`; without one, no scheme that needs TLS is
/// built in.
pub trait TlsBackend: Send + Sync {
    /// A client session for one connection to `peer`, made with the
    /// settings `identity` holds and offering `alpn` (C's
    /// `ssl_connect_data` and its backend's context, made as the SSL
    /// filter is added). The session keeps the identity as long as it
    /// needs it, and `shared` too: what the library keeps across the
    /// connections of the multi the session's connection belongs to.
    fn session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        shared: &TlsShared,
    ) -> Result<Box<dyn TlsSession>, ErrorKind>;

    /// Where it finds the certificates to trust when a transfer names
    /// none, as its build found them.
    fn ca_defaults(&self) -> CaDefaults;

    /// Its name and version, as a session's key in the cache names the
    /// library (`ssl_impl->version`): `OpenSSL/3.5.9`.
    fn id(&self) -> &dyn fmt::Display;

    /// The ids of the crypto engines it has (`Curl_ssl_engines_list`):
    /// none for a library without engines.
    fn engines(&self) -> Result<Vec<Vec<u8>>, OutOfMemory> {
        Ok(Vec::new())
    }
}

/// Where a TLS library finds the certificates to trust when a transfer
/// names none: a file of them and a directory of them, decided as the
/// library was built (CMake's `CURL_CA_BUNDLE` and `CURL_CA_PATH`), or
/// none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaDefaults {
    pub file: Option<&'static str>,
    pub path: Option<&'static str>,
}

/// What a TLS library keeps for one multi across the connections made
/// from it, which only the library knows the shape of (C keeps
/// OpenSSL's CA store in `multi->proto_hash`). The multi holds it, made
/// as its first TLS session is, and hands it to each session it asks
/// for; the library makes what goes in it the first time it needs it.
/// It goes with the multi and the connections it owns.
#[derive(Clone)]
pub struct TlsShared(TryArc<Mutex<Option<Box<dyn Any + Send>>>>);

impl TlsShared {
    pub(crate) fn new() -> Result<TlsShared, OutOfMemory> {
        TryArc::try_new(Mutex::new(None)).map(TlsShared)
    }

    /// Run `f` on the library's state, of its own type `T`, made by
    /// `make` the first time. A multi whose handles name two libraries
    /// keeps the state of the first that asked: for the other, `f` is not
    /// run, and none comes back.
    pub fn with<T: Any + Send, R>(
        &self,
        make: impl FnOnce() -> T,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<Option<R>, OutOfMemory> {
        let mut state = self.0.lock().expect("panics abort");
        if state.is_none() {
            let made: Box<dyn Any + Send> = try_box(make())?;
            *state = Some(made);
        }
        let state = state.as_mut().expect("made above");
        Ok(state.downcast_mut::<T>().map(f))
    }

    /// The state is the same one: two sessions were handed the same
    /// multi's.
    pub fn same(&self, other: &TlsShared) -> bool {
        TryArc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for TlsShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TlsShared")
    }
}

impl fmt::Debug for dyn TlsBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TlsBackend")
    }
}

/// One connection's TLS, which the core drives (C's SSL filter): the
/// handshake, then the records both ways, then the goodbye. Each call
/// reads and writes the connection through `io` as it needs, and says
/// what it waits for when it cannot go on.
pub trait TlsSession: Send {
    /// Move the handshake on: done, or waiting for what `waits` says.
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind>;

    /// Read into `buf`, which is not empty, at most its length of what
    /// the peer sent.
    fn recv(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv>;

    /// Send from `bytes`, which is not empty.
    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent>;

    /// Move the goodbye on (close_notify, and the peer's).
    fn shutdown(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind>;

    /// What its last call that could not go on waits for on the socket
    /// (C's `io_need`): to read, or to write, which it may need while it
    /// reads.
    fn waits(&self) -> TlsWait;

    /// It holds bytes it read and has not given out, which a poll of the
    /// socket cannot see.
    fn pending(&self) -> bool;

    /// What the peer chose of the ALPN offer, once the handshake is over
    /// and if it chose (`connssl->negotiated.alpn`).
    fn chosen(&self) -> Option<Chosen> {
        None
    }

    /// The library's own objects for the session, once it made them.
    fn native(&self) -> Option<TlsNative> {
        None
    }
}

/// A TLS library's own objects for one connection, which an application
/// using that library itself may be handed (`CURLINFO_TLS_SSL_PTR`,
/// `CURLINFO_TLS_SESSION`, `CURLOPT_SSL_CTX_FUNCTION`): the context the
/// session is made from, and the session's own object once it is made.
/// The core passes them on and never looks through them: what they are
/// is the library's to say, and they live while the connection does,
/// which a transfer reaches only while it holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsNative {
    context: NonNull<c_void>,
    session: Option<NonNull<c_void>>,
}

impl TlsNative {
    pub fn new(context: NonNull<c_void>, session: Option<NonNull<c_void>>) -> TlsNative {
        TlsNative { context, session }
    }

    /// The context the session is made from (OpenSSL's `SSL_CTX`).
    pub fn context(self) -> NonNull<c_void> {
        self.context
    }

    /// The session's own object (OpenSSL's `SSL`), once it is made.
    pub fn session(self) -> Option<NonNull<c_void>> {
        self.session
    }
}

/// What a TLS session waits for on the socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsWait {
    /// Nothing: what the transfer wants goes as it is.
    #[default]
    Nothing,
    /// To read, whatever the transfer wants.
    Recv,
    /// To write, whatever the transfer wants: its reads wait on it.
    Send,
}

/// The protocols a session offers its peer by ALPN, as the transfer's
/// HTTP version asks (`alpn_get_spec`, in a build without HTTP/2):
/// HTTP/1.0 offers HTTP/1.1 too, as some HTTP/1.0 servers know only it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alpn {
    /// None (`CURLOPT_SSL_ENABLE_ALPN` off).
    None,
    Http11,
    Http10,
}

impl Alpn {
    /// The offer as ALPN puts it on the wire: each name after its length.
    pub fn wire(self) -> &'static [u8] {
        match self {
            Alpn::None => b"",
            Alpn::Http11 => b"\x08http/1.1",
            Alpn::Http10 => b"\x08http/1.0\x08http/1.1",
        }
    }

    /// The offer as C traces it (`ALPN: curl offers ...`), if any.
    pub fn offer(self) -> Option<&'static str> {
        match self {
            Alpn::None => None,
            Alpn::Http11 => Some("http/1.1"),
            Alpn::Http10 => Some("http/1.0,http/1.1"),
        }
    }
}

/// A protocol a peer may choose of an ALPN offer: one this build
/// offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chosen {
    Http11,
    Http10,
}

impl Chosen {
    /// The protocol whose ALPN name is `name`, if one this build offers;
    /// a library checks the peer chose of the offer.
    pub fn named(name: &[u8]) -> Option<Chosen> {
        match name {
            b"http/1.1" => Some(Chosen::Http11),
            b"http/1.0" => Some(Chosen::Http10),
            _ => None,
        }
    }

    /// Its ALPN name.
    pub fn name(self) -> &'static str {
        match self {
            Chosen::Http11 => "http/1.1",
            Chosen::Http10 => "http/1.0",
        }
    }
}

/// Which way a TLS record went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsWay {
    /// From the peer.
    In,
    /// To the peer.
    Out,
}

/// Who a TLS session talks to: the origin as the URL names it (C's
/// `ssl_peer`), whose name the handshake sends and checks the
/// certificate against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsPeer<'a> {
    /// The host, an IPv6 address without its brackets.
    pub name: &'a [u8],
    pub port: u16,
    pub kind: TlsPeerKind,
}

/// What a TLS peer's name is: an address names no server (no SNI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsPeerKind {
    Name,
    Ipv4,
    Ipv6,
}

impl<'a> TlsPeer<'a> {
    pub(crate) fn of(peer: &'a Peer) -> TlsPeer<'a> {
        let name = peer.name();
        let kind = if peer.ipv6() {
            TlsPeerKind::Ipv6
        } else if std::str::from_utf8(name).is_ok_and(|n| n.parse::<Ipv4Addr>().is_ok()) {
            TlsPeerKind::Ipv4
        } else {
            TlsPeerKind::Name
        };
        TlsPeer {
            name,
            port: peer.port(),
            kind,
        }
    }
}

/// What a TLS session reaches while it works, for the one call it is
/// given to: the layers below it, down to the socket, and the transfer
/// it works for. The bytes the connection received before the session
/// was made, after a proxy's answer, are read first.
pub struct TlsIo<'a> {
    below: Below<'a>,
    cx: &'a mut dyn LayerCx,
    early: &'a mut Vec<u8>,
    component: Component,
    /// Who the connection's sessions are kept for.
    peer: &'a SessionPeer,
}

impl TlsIo<'_> {
    /// Read into `buf`, which is not empty, from what came before the
    /// session, else from below, whose socket traces the receive and says
    /// why it failed (`cf_socket_recv`'s `Recv failure:`).
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<Recv> {
        assert!(!buf.is_empty(), "a receive needs room");
        if let Some(n) = std::num::NonZeroUsize::new(self.early.len().min(buf.len())) {
            buf[..n.get()].copy_from_slice(&self.early[..n.get()]);
            self.early.drain(..n.get());
            return Ok(Recv::Data(n));
        }
        self.below.reborrow().recv(self.cx, buf)
    }

    /// Send from `bytes`, which is not empty, through the layers below,
    /// whose socket traces the send and says why it failed (`Send
    /// failure:`).
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<Sent> {
        self.below.reborrow().send(self.cx, bytes)
    }

    /// The transfer fails with `kind`, for the reason `why` (`failf`):
    /// kept if it is the first, and traced; `kind` back.
    pub fn fail(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        self.cx.fails(kind, why)
    }

    /// The bytes of a TLS record that went `way`, for the transfer's
    /// debug handler (`CURLINFO_SSL_DATA_IN`, `CURLINFO_SSL_DATA_OUT`).
    pub fn record(&mut self, way: TlsWay, bytes: &[u8]) {
        let kind = match way {
            TlsWay::In => DebugKind::SslDataIn,
            TlsWay::Out => DebugKind::SslDataOut,
        };
        self.cx.bytes(kind, bytes);
    }

    /// The transfer traces to a debug handler (C's `data->set.fdebug`
    /// and `verbose`), which a library's trace of its records is for.
    pub fn debugs(&self) -> bool {
        self.cx.debugs()
    }

    /// Trace a line of the layer's (`CURL_TRC_CF`), if its component is
    /// traced.
    pub fn trace(&mut self, line: fmt::Arguments<'_>) {
        self.cx.of(self.component, line);
    }

    /// A line of the transfer's verbose output (`infof`).
    pub fn info(&mut self, line: fmt::Arguments<'_>) {
        self.cx.info(line);
    }

    /// A line only C's debug build says (`DEBUGF(infof(...))`): `info`
    /// in the debug-hooks build, nothing in any other.
    pub(crate) fn debug_info(&mut self, line: fmt::Arguments<'_>) {
        if cfg!(feature = "debug-hooks") {
            self.cx.info(line);
        }
    }

    /// What the library made of the peer's certificate, its own code, 0
    /// being verified (`CURLINFO_SSL_VERIFYRESULT`). The origin's alone:
    /// a proxy's has its own info (43i).
    pub fn verified(&mut self, result: impl Into<i64>) {
        if self.component == Component::Ssl {
            self.cx.tls_verified(result.into());
        }
    }

    /// The transfer asked for its peer's chain (`CURLOPT_CERTINFO`).
    pub fn wants_certinfo(&mut self) -> bool {
        self.cx.certinfo_report().is_some()
    }

    /// Report `info` as the peer's chain, in place of any before it, or
    /// none (`Curl_ssl_init_certinfo`, `Curl_ssl_free_certinfo`), if the
    /// transfer asked for it.
    pub fn set_certinfo(&mut self, info: Option<CertInfo>) -> Result<(), ErrorKind> {
        if let Some(report) = self.cx.certinfo_report() {
            report.set_certinfo(None);
            let boxed = info.map(try_box).transpose();
            report.set_certinfo(boxed.map_err(|_| ErrorKind::OutOfMemory)?);
        }
        Ok(())
    }

    /// The time of the multi's pass the call is made in (C's
    /// `Curl_pgrs_now`), on the multi's clock.
    pub fn now(&self) -> Instant {
        self.cx.now()
    }

    /// The transfer's application sets each context up itself
    /// (`CURLOPT_SSL_CTX_FUNCTION`): a library makes the context whole,
    /// its trust store too, before it hands it over.
    pub fn configures_context(&self) -> bool {
        self.cx.configures_tls()
    }

    /// Hand the context in `native` to the application to set up
    /// (`CURLOPT_SSL_CTX_FUNCTION`). If it says no, the transfer fails
    /// with the kind it gave, said as C says it.
    pub fn configure_context(&mut self, native: TlsNative) -> Result<(), ErrorKind> {
        self.cx.configure_tls(native).map_err(|kind| {
            self.cx
                .fails(kind, format_args!("error signaled by SSL ctx callback"))
        })
    }

    /// Stop the transfer receiving, until the application unpauses it: a
    /// handshake waiting for the application's word waits on that, not on
    /// the socket (`Curl_xfer_pause_recv`).
    pub fn pause_recv(&mut self) {
        self.cx.pause_recv();
    }

    /// The time of day, in seconds since 1970 (`time(NULL)`), which a
    /// session's lifetime counts from.
    pub fn unix_time(&self) -> i64 {
        self.cx.unix_time()
    }

    /// The transfer has a cache of sessions and the connection keeps its
    /// own there (`Curl_ssl_scache_use`).
    pub fn caches_sessions(&self) -> bool {
        self.cx.has_tls_sessions() && self.peer.caches()
    }

    /// A session to resume, taken from the transfer's cache
    /// (`Curl_ssl_scache_take`).
    pub fn take_session(&mut self) -> Option<TlsTicket> {
        let now = self.cx.unix_time();
        let peer = self.peer;
        let mut taken = None;
        self.cx.tls_sessions(&mut |cache, cx| {
            taken = cache.take(peer, now, &mut |line| cx.of(Component::Ssls, line));
        });
        taken
    }

    /// Keep `ticket` in the transfer's cache, if the connection keeps its
    /// sessions (`Curl_ssl_scache_put`). Out of memory, it is said, and
    /// the transfer goes on without it.
    pub fn keep_session(&mut self, ticket: TlsTicket) {
        if !self.peer.caches() {
            return;
        }
        let now = self.cx.unix_time();
        let peer = self.peer;
        let mut ticket = Some(ticket);
        self.cx.tls_sessions(&mut |cache, cx| {
            let ticket = ticket.take().expect("called once");
            let kept = cache.put(peer, ticket, now, &mut |line| cx.of(Component::Ssls, line));
            if kept.is_err() {
                let key = cache::Shown(peer.key());
                cx.fails(
                    ErrorKind::OutOfMemory,
                    format_args!("[SCACHE] failed to add session for {key}, error=27"),
                );
            }
        });
    }

    /// Give back a session taken that was not resumed, or was: one before
    /// TLS 1.3 is kept again, one of TLS 1.3 dropped, as a ticket is not to
    /// serve two connections (RFC 8446 C.4, `Curl_ssl_scache_return`).
    pub fn return_session(&mut self, ticket: Option<TlsTicket>) {
        if let Some(t) = ticket.filter(|t| t.version < TLS1_3) {
            self.keep_session(t);
        }
    }

    /// Forget the sessions kept for the connection's peer, as its check
    /// failed (`Curl_ssl_scache_remove_all`).
    pub fn forget_sessions(&mut self) {
        let peer = self.peer;
        self.cx.tls_sessions(&mut |cache, cx| {
            cache.remove_all(peer, &mut |line| cx.of(Component::Ssls, line));
        });
    }

    /// The connection below seems usable: the peer has not closed it
    /// (`is_alive` of the filter below).
    pub fn peer_alive(&mut self) -> bool {
        matches!(
            self.below.reborrow().alive(self.cx),
            crate::conn::layer::Alive::Alive { .. }
        )
    }
}

impl<'a> TlsIo<'a> {
    pub(crate) fn new(
        below: Below<'a>,
        cx: &'a mut dyn LayerCx,
        early: &'a mut Vec<u8>,
        component: Component,
        peer: &'a SessionPeer,
    ) -> TlsIo<'a> {
        TlsIo {
            below,
            cx,
            early,
            component,
            peer,
        }
    }
}

/// Every setting a connection's TLS handshake was made with that a
/// transfer must share to reuse the connection (C's `ssl_filter_config`,
/// compared by `match_ssl_primary_config`). A route to a TLS peer holds
/// one, made from the transfer's options; the connection it sets up
/// keeps it.
#[derive(Debug)]
pub struct TlsIdentity {
    /// The peer's certificate must verify.
    pub verify_peer: bool,
    /// The certificate must name the host.
    pub verify_host: bool,
    pub options: TlsOptions,
    /// What the library trusts when the options name nothing.
    pub ca_defaults: CaDefaults,
}

impl TlsIdentity {
    /// The identity the transfer's options `tls` make, shared by its
    /// route and the connection set up for it, with the library's
    /// defaults where the options keep them.
    pub(crate) fn of(
        tls: &Tls,
        ca_defaults: CaDefaults,
    ) -> Result<TryArc<TlsIdentity>, OutOfMemory> {
        let mut options = tls.options.try_clone()?;
        // The handle's, which a connection does not keep: it is called
        // through the transfer that makes the connection.
        options.context = None;
        TryArc::try_new(TlsIdentity {
            verify_peer: tls.verify_peer,
            verify_host: tls.verify_host,
            options,
            ca_defaults,
        })
    }

    /// The file of certificates to trust: the transfer's, or the
    /// library's default if it keeps it (`Curl_ssl_filter_config_tmp_init`
    /// copies the default into the setting).
    pub fn ca_file(&self) -> Option<&[u8]> {
        resolved(&self.options.ca_file, self.ca_defaults.file)
    }

    /// The directory of certificates to trust, resolved as `ca_file`.
    pub fn ca_path(&self) -> Option<&[u8]> {
        resolved(&self.options.ca_path, self.ca_defaults.path)
    }
}

/// A CA setting as it applies: the default where it keeps it.
fn resolved<'a>(setting: &'a CaSetting, default: Option<&'static str>) -> Option<&'a [u8]> {
    match setting {
        CaSetting::Default => default.map(str::as_bytes),
        CaSetting::Unset => None,
        CaSetting::Given(given) => Some(given),
    }
}

/// A connection made with one identity serves a transfer that wants the
/// other only if every setting matches, as `match_ssl_primary_config`
/// compares them: the paths, blobs, keys and certificates exactly, the
/// lists and the formats in any case, the key's password in constant
/// time.
impl PartialEq for TlsIdentity {
    fn eq(&self, other: &TlsIdentity) -> bool {
        // Every field by name, so that one added does not compile until
        // it is compared here or said why not.
        let TlsIdentity {
            verify_peer,
            verify_host,
            options,
            // Compared as the CA file and path they resolve: a handle
            // that names the default's path matches one that keeps it,
            // as C, which copies the default in, finds them.
            ca_defaults: _,
        } = self;
        let TlsOptions {
            min_version,
            max_version,
            ssl_options,
            verify_status,
            // Compared as they resolve, below.
            ca_file: _,
            ca_path: _,
            ca_blob,
            crl_file,
            issuer_cert,
            issuer_cert_blob,
            cert,
            cert_blob,
            cert_type,
            key,
            key_blob,
            key_type,
            key_password,
            ciphers,
            tls13_ciphers,
            curves,
            signature_algorithms,
            pinned_key,
            // The handle's, not the connection's: C reads it as the
            // handshake starts and matches no connection by it.
            alpn: _,
            // The handle's too, read as the store is set up.
            ca_cache: _,
            // The handle's (`STRING_SSL_ENGINE`, `engine_default`), read
            // as the context is made.
            engine: _,
            engine_default: _,
            // The connection's, but C matches no connection by it: a
            // transfer that keeps no session may reuse one that does.
            session_cache: _,
            // The handle's, called as the context is made; the identity
            // holds none.
            context: _,
        } = options;
        let o = &other.options;
        *verify_peer == other.verify_peer
            && *verify_host == other.verify_host
            && *min_version == o.min_version
            && *max_version == o.max_version
            && *ssl_options == o.ssl_options
            && *verify_status == o.verify_status
            && self.ca_file() == other.ca_file()
            && self.ca_path() == other.ca_path()
            && *ca_blob == o.ca_blob
            && *crl_file == o.crl_file
            && *issuer_cert == o.issuer_cert
            && *issuer_cert_blob == o.issuer_cert_blob
            && *cert == o.cert
            && *cert_blob == o.cert_blob
            && same_name(cert_type, &o.cert_type)
            && *key == o.key
            && *key_blob == o.key_blob
            && same_name(key_type, &o.key_type)
            && same_secret(key_password, &o.key_password)
            && same_name(ciphers, &o.ciphers)
            && same_name(tls13_ciphers, &o.tls13_ciphers)
            && same_name(curves, &o.curves)
            && same_name(signature_algorithms, &o.signature_algorithms)
            && *pinned_key == o.pinned_key
    }
}

impl Eq for TlsIdentity {}

/// The same list or format, in any case (`curl_strequal`), or neither.
fn same_name(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (a, b) => a.is_none() && b.is_none(),
    }
}

/// The same secret, or neither, compared in a time that does not depend
/// on where they first differ (`Curl_timestrcmp`).
fn same_secret(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
        }
        (a, b) => a.is_none() && b.is_none(),
    }
}

#[cfg(test)]
mod tests;
