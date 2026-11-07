//! TLS, as the core asks it of the library bound beside it (C's
//! `vtls`): the settings a connection's handshake is made with, which
//! decide which connections a transfer may reuse, and the seam a TLS
//! library implements. The library makes a session for each connection
//! (`TlsBackend`), and the core drives it as a layer over the
//! connection's stream (`TlsSession`), handing it the layers below to
//! read and write through (`TlsIo`). A QUIC connection's session
//! (`QuicTls`) is driven by the QUIC library instead, which carries its
//! records; it reaches only the transfer (`TlsCx`). The core names no
//! library's types.

use std::any::Any;
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::ptr::NonNull;
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};

use crate::components::Component;
use crate::conn::Peer;
use crate::conn::io::{Recv, Sent};
use crate::conn::layer::LayerCalls as _;
use crate::conn::layer::{Below, LayerCx};
use crate::error::ErrorKind;
use crate::handler::DebugKind;
use crate::options::{CaSetting, SslOptions, Tls, TlsOptions};
use crate::report::CertInfo;
use crate::time::Instant;

pub use crate::conn::layer::Handshake;
pub(crate) use cache::SessionCache;
pub(crate) use cache::unpack as unpack_session;
pub use cache::{SessionExport, SessionFor, SessionPeer, TLS1_3, TlsTicket};
pub use keylog::{KeyLog, SharedKeyLog};
pub use pin::pin_peer_pubkey;
pub use store::StoreCache;

pub(crate) mod cache;
pub mod hostcheck;
mod keylog;
mod pin;
mod store;
pub mod x509;

/// A test double: a TLS library of text lines and scrambled records.
#[cfg(any(test, feature = "test-util"))]
pub mod fake;
#[cfg(any(test, feature = "test-util"))]
mod wire;
#[cfg(any(test, feature = "test-util"))]
pub use wire::Wire;

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

    /// A session for one QUIC connection to `peer`, offering HTTP/3 by
    /// ALPN (C's `Curl_vquic_tls_init`): made at once, its context and
    /// its library's session object, which `QuicTls::native` hands the
    /// QUIC library; its objects handed to `setup` where the library's
    /// QUIC setup comes (see `QuicContextSetup`); a session the cache
    /// kept for the peer is resumed. The pointer the library hands its
    /// QUIC callbacks (OpenSSL's and wolfSSL's application data, GnuTLS's
    /// session pointer) is the QUIC library's to set, never the session's
    /// own. A library that cannot carry QUIC has none.
    fn quic_session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        shared: &TlsShared,
        setup: QuicContextSetup<'_>,
        cx: &mut TlsCx<'_>,
    ) -> Result<Box<dyn QuicTls>, ErrorKind> {
        let _ = (identity, peer, shared, setup);
        Err(cx.fail(
            ErrorKind::QuicConnectError,
            format_args!("the TLS library has no QUIC"),
        ))
    }

    /// Where it finds the certificates to trust when a transfer names
    /// none, as its build found them.
    fn ca_defaults(&self) -> CaDefaults;

    /// What it can do past the handshake every library makes, which the
    /// options asking for it need (C's `supports` bits): an option asking
    /// for what it lacks is not built in.
    fn support(&self) -> TlsSupport;

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
/// none; and how it takes the system's own store.
///
/// It has no default: a library says how it takes the system's store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaDefaults {
    pub file: Option<&'static str>,
    pub path: Option<&'static str>,
    pub system: SystemStore,
}

impl CaDefaults {
    /// No file, no directory, and the system's store only where asked
    /// for.
    pub const NONE: CaDefaults = CaDefaults {
        file: None,
        path: None,
        system: SystemStore::Asked,
    };
}

/// How a TLS library takes the system's own store of certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemStore {
    /// Only where a transfer asks for it (`CURLSSLOPT_NATIVE_CA`).
    Asked,
    /// Also where a transfer names no file, directory or blob of its own
    /// (C's `CURL_CA_NATIVE` and `USE_APPLE_SECTRUST` builds), so that
    /// naming one turns it off. The tool still names those the
    /// environment gives.
    Default,
    /// It is the library's own, which verifies the peer against it by
    /// itself: no default is set for it (C sets one only where the
    /// backend is not Schannel), and the tool names no certificates from
    /// the environment (`win32_using_schannel`).
    Own,
}

/// What a TLS library can do past the handshake, each named so that a
/// library says yes or no to every one: the options asking for one it
/// lacks are not built in (C's `SSLSUPP_*` bits, `Curl_ssl_supports`,
/// and the checks C makes of the library by name). The application's
/// way in refuses them, as C's `curl_easy_setopt` does: the shim's
/// setopt and the tool's.
///
/// It has no default: a capability added is one every library has to
/// declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsSupport {
    /// A directory of certificates to trust (`SSLSUPP_CA_PATH`).
    pub ca_path: bool,
    /// The certificates to trust given in memory (`SSLSUPP_CAINFO_BLOB`).
    pub ca_blob: bool,
    /// The certificates to trust kept for the multi's next connections
    /// (`SSLSUPP_CA_CACHE`).
    pub ca_cache: bool,
    /// The peer's chain reported (`SSLSUPP_CERTINFO`).
    pub cert_info: bool,
    /// The peer's public key pinned (`SSLSUPP_PINNEDPUBKEY`).
    pub pinned_key: bool,
    /// The application told of the library's context
    /// (`SSLSUPP_SSL_CTX`).
    pub context_handler: bool,
    /// An HTTPS proxy (`SSLSUPP_HTTPS_PROXY`).
    pub https_proxy: bool,
    /// The cipher list before TLS 1.3 (`SSLSUPP_CIPHER_LIST`), and TLS
    /// 1.3's suites (`SSLSUPP_TLS13_CIPHERSUITES`).
    pub ciphers: bool,
    pub tls13_ciphers: bool,
    /// The curves (`SSLSUPP_SSL_EC_CURVES`) and signature algorithms
    /// (`SSLSUPP_SIGNATURE_ALGORITHMS`) allowed.
    pub curves: bool,
    pub signature_algorithms: bool,
    /// A revocation list (`SSLSUPP_CRLFILE`).
    pub crl_file: bool,
    /// The certificate the peer's must be issued by, in a file
    /// (`SSLSUPP_ISSUERCERT`) and in memory (`SSLSUPP_ISSUERCERT_BLOB`).
    pub issuer_cert: bool,
    pub issuer_cert_blob: bool,
    /// Encrypted Client Hello (`SSLSUPP_ECH`).
    pub ech: bool,
    /// The peer's stapled certificate status checked
    /// (`cert_status_request`).
    pub cert_status: bool,
    /// Crypto engines or providers to use (C allows `CURLOPT_SSLENGINE`
    /// with OpenSSL alone).
    pub engines: bool,
}

impl TlsSupport {
    /// Nothing: a build without a TLS library, of which C's
    /// `Curl_ssl_supports` says no to all.
    pub const NONE: TlsSupport = TlsSupport {
        ca_path: false,
        ca_blob: false,
        ca_cache: false,
        cert_info: false,
        pinned_key: false,
        context_handler: false,
        https_proxy: false,
        ciphers: false,
        tls13_ciphers: false,
        curves: false,
        signature_algorithms: false,
        crl_file: false,
        issuer_cert: false,
        issuer_cert_blob: false,
        ech: false,
        cert_status: false,
        engines: false,
    };

    /// What a transfer's options ask of its TLS library: its own TLS
    /// options `origin`, an HTTPS proxy's `proxy`, and its DoH server's
    /// status check `doh_status`. Each option C's `curl_easy_setopt`
    /// refuses where the library lacks it asks for it once set, to any
    /// value but its default, as C refuses the setopt whatever the value.
    /// What C sets for the origin alone (the curves, the signature
    /// algorithms, the handle's own settings) is read from `origin`.
    pub(crate) fn asked_by(origin: &Tls, proxy: &Tls, doh_status: bool) -> TlsSupport {
        let (o, p) = (&*origin.options, &*proxy.options);
        let either = |set: fn(&TlsOptions) -> bool| set(o) || set(p);
        TlsSupport {
            ca_path: either(|t| t.ca_path != CaSetting::Default),
            ca_blob: either(|t| t.ca_blob != CaSetting::Default),
            ca_cache: o.ca_cache != crate::options::CaCache::DEFAULT,
            cert_info: origin.certinfo,
            pinned_key: either(|t| t.pinned_key.is_some()),
            context_handler: either(|t| t.context.is_some()),
            // An HTTPS proxy is asked for by the proxy's URL, which its
            // parse refuses (`SSLSUPP_HTTPS_PROXY` in `parse_proxy`).
            https_proxy: false,
            ciphers: either(|t| t.ciphers.is_some()),
            tls13_ciphers: either(|t| t.tls13_ciphers.is_some()),
            curves: o.curves.is_some(),
            signature_algorithms: o.signature_algorithms.is_some(),
            crl_file: either(|t| t.crl_file.is_some()),
            issuer_cert: either(|t| t.issuer_cert.is_some()),
            issuer_cert_blob: either(|t| t.issuer_cert_blob.is_some()),
            // No option asks for it.
            ech: false,
            cert_status: o.verify_status || doh_status,
            engines: o.engine.is_some() || o.engine_default,
        }
    }

    /// The first of what `asked` asks for that this lacks, named as the
    /// failure says it.
    pub(crate) fn lacking(&self, asked: &TlsSupport) -> Option<&'static str> {
        // Every field by name, so one added is checked too.
        let TlsSupport {
            ca_path,
            ca_blob,
            ca_cache,
            cert_info,
            pinned_key,
            context_handler,
            https_proxy,
            ciphers,
            tls13_ciphers,
            curves,
            signature_algorithms,
            crl_file,
            issuer_cert,
            issuer_cert_blob,
            ech,
            cert_status,
            engines,
        } = *asked;
        let pairs = [
            (ca_path, self.ca_path, "a CA certificate directory"),
            (ca_blob, self.ca_blob, "CA certificates in memory"),
            (ca_cache, self.ca_cache, "a CA cache timeout"),
            (cert_info, self.cert_info, "certificate info"),
            (pinned_key, self.pinned_key, "a pinned public key"),
            (context_handler, self.context_handler, "a context callback"),
            (https_proxy, self.https_proxy, "an HTTPS proxy"),
            (ciphers, self.ciphers, "a cipher list"),
            (tls13_ciphers, self.tls13_ciphers, "TLS 1.3 cipher suites"),
            (curves, self.curves, "a curve list"),
            (
                signature_algorithms,
                self.signature_algorithms,
                "signature algorithms",
            ),
            (crl_file, self.crl_file, "a CRL file"),
            (issuer_cert, self.issuer_cert, "an issuer certificate"),
            (
                issuer_cert_blob,
                self.issuer_cert_blob,
                "an issuer certificate in memory",
            ),
            (ech, self.ech, "ECH"),
            (cert_status, self.cert_status, "certificate status checks"),
            (engines, self.engines, "a crypto engine"),
        ];
        pairs
            .into_iter()
            .find(|&(asked, has, _)| asked && !has)
            .map(|(_, _, what)| what)
    }
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

    /// Move the goodbye on: the peer's close_notify read for, and ours
    /// sent unless `goodbye` says only the peer's.
    fn shutdown(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<Handshake, ErrorKind>;

    /// What its last call that could not go on waits for on the socket
    /// (C's `io_need`): to read, or to write, which it may need while it
    /// reads.
    fn waits(&self) -> TlsWait;

    /// It holds bytes it read and has not given out, which a poll of the
    /// socket cannot see.
    fn pending(&self) -> bool;

    /// What the peer chose of the ALPN offer, once the handshake is over
    /// and if it chose (`connssl->negotiated.alpn`); while a handshake is
    /// put off, what the session it resumes chose.
    fn chosen(&self) -> Option<Chosen> {
        None
    }

    /// The handshake was put off to send early data in it, as `handshake`
    /// said it was done (`ssl_connection_deferred`): it waits for the
    /// first bytes sent, as many as it allows going early.
    fn deferred(&self) -> Option<Deferred> {
        None
    }

    /// Move a handshake put off on, `early`, at most as many as
    /// `deferred` allowed and perhaps none, sent first as early data
    /// (`ossl_send_earlydata`): as `handshake`, given the same bytes each
    /// call until it is done.
    fn handshake_early(
        &mut self,
        io: &mut TlsIo<'_>,
        early: &[u8],
    ) -> Result<Handshake, ErrorKind> {
        let _ = early;
        self.handshake(io)
    }

    /// The peer took the early data, once the handshake that sent it is
    /// done (`SSL_EARLY_DATA_ACCEPTED`).
    fn early_accepted(&self) -> bool {
        false
    }

    /// The library's own objects for the session, once it made them.
    fn native(&self) -> Option<TlsNative> {
        None
    }

    /// The channel's binding, for an authentication bound to it (RFC
    /// 5929's `tls-server-end-point`, C's `get_channel_binding`): the
    /// prefix `tls-server-end-point:` and the hash of the peer's
    /// certificate, or none where the peer showed no certificate or its
    /// signature names no digest. What it has to say goes to `notes`.
    fn channel_binding(&self, notes: &mut dyn BindingNotes) -> Result<Option<Vec<u8>>, ErrorKind>;
}

/// One QUIC connection's TLS (C's `curl_tls_ctx` under its QUIC filter):
/// the library's session, which the QUIC library drives, handing it the
/// handshake's bytes and taking its records' keys. The core's part is to
/// run each call into the QUIC library inside `drive`, so the session's
/// own callbacks reach the transfer, and to check the peer when the QUIC
/// library says the handshake is done.
pub trait QuicTls: Send {
    /// The library's own objects, its session among them, for the QUIC
    /// library to drive.
    fn native(&self) -> TlsNative;

    /// The session the cache kept that this one resumes, if early data
    /// may be sent under it: the transfer asks for early data, and the
    /// session has a protocol and allows some over TLS 1.3 (the
    /// conditions on which C calls `sess_reuse_cb`).
    fn early_data(&self) -> Option<&TlsTicket>;

    /// The QUIC connection decided on early data under the ticket
    /// `early_data` gave, once it has read the ticket's transport
    /// parameters and set HTTP/3 up for it: where it goes (`early`), the
    /// ALPN offer is only the ticket's protocol, and a library that is
    /// told the most early data the ticket allows is told it; where it
    /// does not, the offer stays whole (what `sess_reuse_cb`'s caller
    /// does with `do_early_data`). Called once, before the handshake's
    /// first bytes, for a session whose `early_data` gave a ticket, and
    /// never for one whose did not.
    fn early_data_decided(&mut self, cx: &mut TlsCx<'_>, early: bool) -> Result<(), ErrorKind>;

    /// Get ready for the peer's first bytes: the trust store set up, if
    /// it is not (`Curl_vquic_tls_before_recv`).
    fn before_recv(&mut self, cx: &mut TlsCx<'_>) -> Result<(), ErrorKind>;

    /// Run `call`, a call into the QUIC library that may move the
    /// session on, with the session's callbacks reaching `cx`. `call` is
    /// given what the QUIC library's own callbacks reach during it: the
    /// transfer, and the session's check, which the QUIC library's word
    /// that the handshake is done runs, inside its callback, so nothing
    /// of the peer's is taken before it is checked. A session the peer
    /// gives during the call is kept with the transport parameters
    /// `params` encodes, if it encodes any.
    fn drive(
        &mut self,
        cx: &mut TlsCx<'_>,
        params: &mut dyn FnMut() -> Option<Vec<u8>>,
        call: &mut dyn FnMut(&mut dyn DriveCall),
    );
}

/// What a QUIC library's callbacks reach during a call `QuicTls::drive`
/// runs. Neither method may be called from inside the other.
pub trait DriveCall {
    /// The QUIC library says the handshake is done
    /// (`cb_ngtcp2_handshake_completed`): the handshake reported, and the
    /// peer's certificate checked as a stream session's is, the peer's
    /// sessions forgotten if it fails (`Curl_vquic_tls_verify_peer`).
    fn handshake_done(&mut self) -> Result<(), ErrorKind>;

    /// Run `f` with the transfer the call reaches.
    fn with_cx(&mut self, f: &mut dyn FnMut(&mut TlsCx<'_>));
}

/// What a session says as it makes a channel binding: a line of the
/// transfer's verbose output, or why the transfer fails.
pub trait BindingNotes {
    /// A line of the transfer's verbose output (`infof`).
    fn info(&mut self, line: fmt::Arguments<'_>);

    /// The transfer fails with `kind`, for the reason `why` (`failf`):
    /// `kind` back.
    fn fail(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind;
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

/// What the QUIC library does to a QUIC session's objects (C's
/// `cb_setup`, `cf_ngtcp2_tls_ctx_setup`): handed the context once it is
/// made, before the session's own object is made from it, by a library
/// whose QUIC setup is the context's (OpenSSL, wolfSSL); the session's
/// object too, once it is made, by one whose setup is the session's
/// (GnuTLS). Why it could not, as C says it, if it could not.
pub type QuicContextSetup<'a> = &'a dyn Fn(TlsNative) -> Result<(), &'static str>;

/// Whose close_notify a session's goodbye is made of (C's
/// `send_shutdown`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Goodbye {
    /// Ours sent, and the peer's read for: a connection's end, and FTP's
    /// active CCC.
    Mutual,
    /// Only the peer's read for, ours never sent: FTP's passive CCC, as
    /// servers that say theirs without waiting for ours expect.
    Heard,
}

impl Goodbye {
    /// Ours is sent.
    pub fn sends(self) -> bool {
        self == Goodbye::Mutual
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
/// HTTP versions ask (`alpn_get_spec`): HTTP/1.0 offers HTTP/1.1 too, as
/// some HTTP/1.0 servers know only it; HTTP/2, where a library speaks it,
/// goes first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alpn {
    /// None (`CURLOPT_SSL_ENABLE_ALPN` off).
    None,
    Http11,
    Http10,
    /// HTTP/2, or else HTTP/1.1.
    H2Http11,
    /// HTTP/2 only.
    H2,
    /// HTTP/3, over QUIC, offered as C's ngtcp2 filter offers it, with
    /// its last draft's name (`ALPN_SPEC_H3`).
    H3,
}

impl Alpn {
    /// The offer as ALPN puts it on the wire: each name after its length.
    pub fn wire(self) -> &'static [u8] {
        match self {
            Alpn::None => b"",
            Alpn::Http11 => b"\x08http/1.1",
            Alpn::Http10 => b"\x08http/1.0\x08http/1.1",
            Alpn::H2Http11 => b"\x02h2\x08http/1.1",
            Alpn::H2 => b"\x02h2",
            Alpn::H3 => b"\x02h3\x05h3-29",
        }
    }

    /// The offer includes `chosen` (`Curl_alpn_contains_proto`).
    pub fn offers(self, chosen: Chosen) -> bool {
        match chosen {
            Chosen::H2 => matches!(self, Alpn::H2Http11 | Alpn::H2),
            Chosen::Http11 => matches!(self, Alpn::Http11 | Alpn::Http10 | Alpn::H2Http11),
            Chosen::Http10 => self == Alpn::Http10,
            Chosen::H3 => self == Alpn::H3,
        }
    }

    /// The names offered, in the offer's order, as a library that takes
    /// them one by one is given them.
    pub fn names(self) -> impl Iterator<Item = &'static [u8]> {
        let mut wire = self.wire();
        core::iter::from_fn(move || {
            let (&len, rest) = wire.split_first()?;
            let (name, next) = rest.split_at(usize::from(len));
            wire = next;
            Some(name)
        })
    }

    /// The offer as C traces it (`ALPN: curl offers ...`), if any.
    pub fn offer(self) -> Option<&'static str> {
        match self {
            Alpn::None => None,
            Alpn::Http11 => Some("http/1.1"),
            Alpn::Http10 => Some("http/1.0,http/1.1"),
            Alpn::H2Http11 => Some("h2,http/1.1"),
            Alpn::H2 => Some("h2"),
            Alpn::H3 => Some("h3,h3-29"),
        }
    }
}

/// A protocol a peer may choose of an ALPN offer: one this build
/// offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chosen {
    Http11,
    Http10,
    H2,
    H3,
}

impl Chosen {
    /// The protocol whose ALPN name is `name`, if one this build offers;
    /// a library checks the peer chose of the offer.
    pub fn named(name: &[u8]) -> Option<Chosen> {
        match name {
            b"http/1.1" => Some(Chosen::Http11),
            b"http/1.0" => Some(Chosen::Http10),
            b"h2" => Some(Chosen::H2),
            b"h3" => Some(Chosen::H3),
            _ => None,
        }
    }

    /// It alone, as ALPN puts an offer on the wire
    /// (`Curl_alpn_restrict_to`).
    pub fn wire(self) -> &'static [u8] {
        match self {
            Chosen::Http11 => b"\x08http/1.1",
            Chosen::Http10 => b"\x08http/1.0",
            Chosen::H2 => b"\x02h2",
            Chosen::H3 => b"\x02h3",
        }
    }

    /// Its ALPN name.
    pub fn name(self) -> &'static str {
        match self {
            Chosen::Http11 => "http/1.1",
            Chosen::Http10 => "http/1.0",
            Chosen::H2 => "h2",
            Chosen::H3 => "h3",
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
    /// The handshake may be put off to send early data, resuming a
    /// session that allows it: the transfer asked for it
    /// (`CURLSSLOPT_EARLYDATA`) and makes its requests on the connection
    /// (not `bits.connect_only`).
    pub early_data: bool,
}

/// The name a session to the peer `name` of kind `kind` sends by SNI
/// (`Curl_ssl_peer_init`'s `peer->sni`): a host name's, lower case,
/// without a trailing dot, if shorter than 64 KiB (RFC 6066 3); none for
/// an address. It has room for a zero byte after it, for a library that
/// takes a C string.
pub fn sni(name: &[u8], kind: TlsPeerKind) -> Result<Option<Vec<u8>>, OutOfMemory> {
    let Some(name) = sni_unlowered(name, kind) else {
        return Ok(None);
    };
    let mut sni = Vec::new();
    sni.try_reserve_exact(name.len() + 1)
        .map_err(|_| OutOfMemory)?;
    sni.try_extend_from_slice(name)?;
    sni.make_ascii_lowercase();
    Ok(Some(sni))
}

/// The name [`sni`] sends, before it is made lower case: for a library
/// that keeps it with other names, lowering it in place.
pub fn sni_unlowered(name: &[u8], kind: TlsPeerKind) -> Option<&[u8]> {
    if kind != TlsPeerKind::Name {
        return None;
    }
    let name = name.strip_suffix(b".").unwrap_or(name);
    (name.len() < usize::from(u16::MAX)).then_some(name)
}

/// What the peer chose of the ALPN offer, `chosen`, empty if nothing,
/// said, and refused where it may not be (`Curl_alpn_set_negotiated`):
/// a session that asked for `asked` alone, as the session it resumed
/// agreed, needs the peer to choose it again; a name with a zero byte in
/// it is no name. The library keeps what was chosen.
pub fn alpn_negotiated(
    cx: &mut TlsCx<'_>,
    asked: Option<&[u8]>,
    chosen: &[u8],
) -> Result<(), ErrorKind> {
    if let Some(asked) = asked {
        let asked = Text(asked);
        if chosen.is_empty() {
            return Err(cx.fail(
                ErrorKind::SslConnectError,
                format_args!(
                    "ALPN: asked for '{asked}' from previous session, but server did not confirm it. Refusing to continue."
                ),
            ));
        }
        if chosen != asked.0 {
            return Err(cx.fail(
                ErrorKind::SslConnectError,
                format_args!(
                    "ALPN: asked for '{asked}' from previous session, but server selected '{}'. Refusing to continue.",
                    Text(chosen)
                ),
            ));
        }
        cx.info(format_args!("ALPN: server confirmed to use '{asked}'"));
        return Ok(());
    }
    if chosen.is_empty() {
        cx.info(format_args!(
            "ALPN: server did not agree on a protocol. Uses default."
        ));
    } else if chosen.contains(&0) {
        return Err(cx.fail(
            ErrorKind::SslConnectError,
            format_args!("ALPN: server selected protocol contains NUL. Refusing to continue."),
        ));
    } else {
        cx.info(format_args!("ALPN: server accepted {}", Text(chosen)));
    }
    Ok(())
}

/// Bytes as C's `%s` shows them in a library's line: text as it is, any
/// other byte as the character of its number.
#[derive(Clone, Copy, Debug)]
pub struct Text<'a>(pub &'a [u8]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for &b in chunk.invalid() {
                fmt::Write::write_char(f, char::from(b))?;
            }
        }
        Ok(())
    }
}

/// `bytes` and a zero byte after them, for a library's call that takes a
/// C string, or a buffer counted with it; `Err` out of memory.
pub fn c_string(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut c = Vec::new();
    c.try_reserve_exact(bytes.len() + 1)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    c.try_extend_from_slice(bytes)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    c.try_push(0)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    Ok(c)
}

/// What `c_string` made, as a `CStr`: a name with a zero in it ends
/// there, as C reads it.
pub fn as_c(bytes: &[u8]) -> &std::ffi::CStr {
    std::ffi::CStr::from_bytes_until_nul(bytes).expect("made by `c_string`")
}

/// A handshake a session put off to send early data in it (TLS 1.3's
/// 0-RTT), resuming a session that allows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deferred {
    /// The most bytes that may go early.
    pub most: usize,
    /// What the resumed session's connection agreed by ALPN, which the
    /// transfer goes on in and the peer must agree to again.
    pub alpn: Chosen,
}

/// What a TLS peer's name is: an address names no server (no SNI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsPeerKind {
    Name,
    Ipv4,
    Ipv6,
}

impl<'a> TlsPeer<'a> {
    pub(crate) fn of(peer: &'a Peer, early_data: bool) -> TlsPeer<'a> {
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
            early_data,
        }
    }
}

/// What a TLS session reaches while it works, for the one call it is
/// given to: the layers below it, down to the socket, and the transfer
/// it works for (`TlsCx`, which it derefs to). The bytes the connection
/// received before the session was made, after a proxy's answer, are
/// read first.
pub struct TlsIo<'a> {
    below: Below<'a>,
    early: &'a mut Vec<u8>,
    cx: TlsCx<'a>,
}

/// What a TLS session reaches of the transfer it works for, for the one
/// call it is given to: its trace, its failure, its cache of sessions
/// and its application's hooks. A QUIC connection's TLS, whose records
/// the QUIC library carries, reaches only this.
pub struct TlsCx<'a> {
    cx: &'a mut dyn LayerCx,
    component: Component,
    /// Who the connection's sessions are kept for.
    peer: &'a SessionPeer,
    /// What the connection keeps of its sessions apart from the cache,
    /// for a session over a stream.
    own: Option<&'a mut OwnSessions>,
}

/// What a connection's TLS keeps of its sessions apart from the cache
/// (C's `connssl->session`): FTP's control connection keeps a copy of its
/// latest, for its data connections to resume, as servers may insist
/// they do (`Curl_ossl_add_session`'s duplicate); a data connection is
/// given that one (`Curl_ssl_get_cf_session`).
#[derive(Debug, Default)]
pub(crate) struct OwnSessions {
    /// A copy of each session kept is held as `latest`.
    keeps_latest: bool,
    latest: Option<TlsTicket>,
    given: Option<TlsTicket>,
}

impl OwnSessions {
    /// Keeping its latest, and given `given` to resume first.
    pub(crate) fn new(keeps_latest: bool, given: Option<TlsTicket>) -> OwnSessions {
        OwnSessions {
            keeps_latest,
            latest: None,
            given,
        }
    }

    /// The latest session kept, if it keeps a copy.
    pub(crate) fn latest(&self) -> Option<&TlsTicket> {
        self.latest.as_ref()
    }
}

impl<'a> std::ops::Deref for TlsIo<'a> {
    type Target = TlsCx<'a>;

    fn deref(&self) -> &TlsCx<'a> {
        &self.cx
    }
}

impl<'a> std::ops::DerefMut for TlsIo<'a> {
    fn deref_mut(&mut self) -> &mut TlsCx<'a> {
        &mut self.cx
    }
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
        self.below.reborrow().recv(self.cx.cx, buf)
    }

    /// Send from `bytes`, which is not empty, through the layers below,
    /// whose socket traces the send and says why it failed (`Send
    /// failure:`).
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<Sent> {
        self.below.reborrow().send(self.cx.cx, bytes)
    }

    /// The connection below seems usable: the peer has not closed it
    /// (`is_alive` of the filter below).
    pub fn peer_alive(&mut self) -> bool {
        matches!(
            self.below.reborrow().alive(self.cx.cx),
            crate::conn::layer::Alive::Alive { .. } | crate::conn::layer::Alive::Changed
        )
    }
}

impl TlsCx<'_> {
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
    pub fn debugs(&mut self) -> bool {
        self.cx.debugs()
    }

    /// Trace a line of the layer's (`CURL_TRC_CF`), if its component is
    /// traced.
    pub fn trace(&mut self, line: fmt::Arguments<'_>) {
        self.cx.of(self.component, line);
    }

    /// The early data sent was taken, if `sent` is positive, or not:
    /// reported, with the handshake's end (`Curl_pgrsEarlyData`).
    pub(crate) fn early_done(&mut self, sent: i64) {
        self.cx.early_done(sent);
    }

    /// The same of an HTTP/3 proxy's handshake, which counts the early
    /// data for the transfer but does not time its TLS.
    pub(crate) fn proxy_early_done(&mut self, sent: i64) {
        self.cx.proxy_early_done(sent);
    }

    /// Hand the transfer what the HTTP/3 library told of a stream.
    pub(crate) fn h3_event(
        &mut self,
        stream: crate::http3::StreamId,
        event: crate::http3::StreamEvent<'_>,
    ) -> crate::http3::Heard {
        self.cx.h3_event(stream, event)
    }

    /// The transfer is verbose (`Curl_trc_is_verbose`): a library with
    /// work to do for its `info` lines, work that can fail, asks first.
    pub fn verbose(&mut self) -> bool {
        self.cx.verbose()
    }

    /// A line of the transfer's verbose output (`infof`).
    pub fn info(&mut self, line: fmt::Arguments<'_>) {
        self.cx.info(line);
    }

    /// `info` with a line made of `parts`, which need not be text.
    pub fn info_with(&mut self, parts: &[&[u8]]) {
        self.cx.info_with(parts);
    }

    /// A line only C's debug build says (`DEBUGF(infof(...))`): `info`
    /// in the debug-hooks build, nothing in any other.
    pub fn debug_info(&mut self, line: fmt::Arguments<'_>) {
        if cfg!(feature = "debug-hooks") {
            self.cx.info(line);
        }
    }

    /// What the library made of the peer's certificate, its own code, 0
    /// being verified: the origin's (`CURLINFO_SSL_VERIFYRESULT`) or an
    /// HTTPS proxy's (`CURLINFO_PROXY_SSL_VERIFYRESULT`), as the session
    /// is the one or the other's.
    pub fn verified(&mut self, result: impl Into<i64>) {
        self.cx.tls_verified(self.component, result.into());
    }

    /// The session is an HTTPS proxy's, not the origin's
    /// (`Curl_ssl_cf_is_proxy`): its certificate is the proxy's.
    pub fn for_proxy(&self) -> bool {
        matches!(self.component, Component::SslProxy | Component::H3Proxy)
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
    pub fn configures_context(&mut self) -> bool {
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
    pub fn unix_time(&mut self) -> i64 {
        self.cx.unix_time()
    }

    /// The transfer has a cache of sessions and the connection keeps its
    /// own there (`Curl_ssl_scache_use`).
    pub fn caches_sessions(&mut self) -> bool {
        self.cx.has_tls_sessions() && self.peer.caches()
    }

    /// The session of the connection this one serves, FTP's control
    /// connection's, to resume before any of the cache's
    /// (`Curl_ssl_get_cf_session`): given once.
    pub fn take_given_session(&mut self) -> Option<TlsTicket> {
        self.own.as_deref_mut().and_then(|own| own.given.take())
    }

    /// A session to resume, taken from the transfer's cache
    /// (`Curl_ssl_scache_take`).
    pub fn take_session(&mut self) -> Option<TlsTicket> {
        let now = self.cx.unix_time();
        let peer = self.peer;
        let mut taken = None;
        self.cx.with_tls_sessions(&mut |cache, cx| {
            taken = cache.take(peer, now, &mut |line| cx.say_line(Component::Ssls, line));
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
        // Out of memory, the copy is not kept and the cache's is
        // (`Curl_ssl_session_dup`).
        if let Some(own) = self.own.as_deref_mut().filter(|own| own.keeps_latest)
            && let Ok(copy) = ticket.try_clone()
        {
            own.latest = Some(copy);
        }
        let now = self.cx.unix_time();
        let peer = self.peer;
        let mut ticket = Some(ticket);
        self.cx.with_tls_sessions(&mut |cache, cx| {
            let ticket = ticket.take().expect("called once");
            let kept = cache.put(peer, ticket, now, &mut |line| {
                cx.say_line(Component::Ssls, line);
            });
            if kept.is_err() {
                let key = cache::Shown(peer.key());
                cx.say_failure(
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

    /// What the library keeps for the connection's peer in place of
    /// sessions, of its own type `T`, if it keeps one there
    /// (`Curl_ssl_scache_get_obj`): a copy of it.
    pub fn session_object<T: Any + Clone>(&mut self) -> Option<T> {
        let peer = self.peer;
        let mut found = None;
        self.cx.with_tls_sessions(&mut |cache, cx| {
            found = cache.object::<T>(peer, &mut |line| cx.say_line(Component::Ssls, line));
        });
        found
    }

    /// Keep `object` for the connection's peer, in place of any the
    /// library kept there before (`Curl_ssl_scache_add_obj`).
    pub fn keep_session_object<T: Any + Send>(&mut self, object: T) -> Result<(), ErrorKind> {
        let object: Box<dyn Any + Send> = try_box(object).map_err(|_| ErrorKind::OutOfMemory)?;
        let peer = self.peer;
        let mut object = Some(object);
        let mut kept = Ok(());
        self.cx.with_tls_sessions(&mut |cache, cx| {
            let object = object.take().expect("called once");
            kept = cache.put_object(peer, object, &mut |line| cx.say_line(Component::Ssls, line));
        });
        kept.map_err(|OutOfMemory| ErrorKind::OutOfMemory)
    }

    /// Forget the sessions kept for the connection's peer, as its check
    /// failed (`Curl_ssl_scache_remove_all`).
    pub fn forget_sessions(&mut self) {
        let peer = self.peer;
        self.cx.with_tls_sessions(&mut |cache, cx| {
            cache.remove_all(peer, &mut |line| cx.say_line(Component::Ssls, line));
        });
    }
}

impl<'a> TlsIo<'a> {
    pub(crate) fn new(
        below: Below<'a>,
        cx: &'a mut dyn LayerCx,
        early: &'a mut Vec<u8>,
        component: Component,
        peer: &'a SessionPeer,
        own: &'a mut OwnSessions,
    ) -> TlsIo<'a> {
        TlsIo {
            below,
            early,
            cx: TlsCx {
                own: Some(own),
                ..TlsCx::new(cx, component, peer)
            },
        }
    }
}

/// What a test's TLS context says: each line traced, as `info: ...`,
/// `trace: ...` or `fail: <kind>: ...`.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct Notes(pub Vec<String>);

#[cfg(any(test, feature = "test-util"))]
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a test's notes, which may allocate as they like"
)]
impl LayerCx for Notes {
    fn now(&self) -> Instant {
        crate::time::Clock::now(&crate::time::ManualClock::new().expect("a clock"))
    }

    fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
        Some(self)
    }

    fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
        Some(self)
    }

    fn transfer(&mut self) -> Option<&mut dyn crate::conn::layer::ForTransfer> {
        None
    }

    fn tls_sessions(&mut self) -> Option<&mut dyn crate::conn::layer::TlsSessions> {
        None
    }

    fn early_data(&mut self) -> Option<&mut dyn crate::conn::layer::EarlyData> {
        None
    }

    fn quic_timer(&mut self) -> Option<&mut dyn crate::conn::layer::QuicTimer> {
        None
    }

    fn h3_streams(&mut self) -> Option<&mut dyn crate::conn::layer::H3Streams> {
        None
    }

    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
        None
    }
}

#[cfg(any(test, feature = "test-util"))]
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a test's notes, which may allocate as they like"
)]
impl crate::conn::layer::Trace for Notes {
    fn line(&mut self, _: Component, line: fmt::Arguments<'_>) {
        self.0.push(format!("trace: {line}"));
    }

    fn line_with(&mut self, _: Component, parts: &[&[u8]]) {
        let line = String::from_utf8(parts.concat()).expect("a test's line is text");
        self.0.push(format!("trace: {line}"));
    }

    fn info_line(&mut self, line: fmt::Arguments<'_>) {
        self.0.push(format!("info: {line}"));
    }

    fn info_line_with(&mut self, parts: &[&[u8]]) {
        let line = String::from_utf8(parts.concat()).expect("a test's line is text");
        self.0.push(format!("info: {line}"));
    }

    /// Its info lines are noted, but a library asking first is told the
    /// transfer is not verbose.
    fn says_info(&self) -> bool {
        false
    }
}

#[cfg(any(test, feature = "test-util"))]
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a test's notes, which may allocate as they like"
)]
impl crate::conn::layer::Failures for Notes {
    fn keep(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        self.0.push(format!("fail: {kind:?}: {why}"));
        kind
    }

    fn keep_with(&mut self, kind: ErrorKind, parts: &[&[u8]]) -> ErrorKind {
        let why = String::from_utf8(parts.concat()).expect("a test's reason is text");
        self.0.push(format!("fail: {kind:?}: {why}"));
        kind
    }

    fn keep_errno(&mut self, e: &std::io::Error) {
        self.0.push(format!("errno: {e}"));
    }
}

/// What a test's TLS context says, as `Notes`, and the sessions it keeps
/// from one connection to the next, as a multi keeps them.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct Kept {
    pub notes: Notes,
    sessions: SessionCache,
    /// The transfer is verbose: a library asking is told so, where
    /// `Notes` alone says it is not.
    pub verbose: bool,
    /// The transfer's TLS context handler (`CURLOPT_SSL_CTX_FUNCTION`), if
    /// it has one.
    pub context: Option<ContextHandler>,
}

#[cfg(any(test, feature = "test-util"))]
impl Kept {
    pub fn new() -> Kept {
        Kept {
            notes: Notes::default(),
            sessions: SessionCache::new(SessionCache::PEERS),
            verbose: false,
            context: None,
        }
    }
}

/// A test transfer's TLS context handler: what it answers each context it
/// is handed, and how many it was. The transfer it stands for has nothing
/// else: no debug handler, no report, and the time of day 0.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct ContextHandler {
    /// The error it answers with, if any.
    pub refuses: Option<ErrorKind>,
    pub handed: usize,
}

#[cfg(any(test, feature = "test-util"))]
impl crate::conn::layer::ForTransfer for ContextHandler {
    fn debug_bytes(&mut self, _: DebugKind, _: &[u8]) {}

    fn has_debug_handler(&self) -> bool {
        false
    }

    fn certinfo_report(&mut self) -> Option<&mut crate::report::TransferReport> {
        None
    }

    fn peer_verified(&mut self, _: Component, _: i64) {}

    fn has_tls_handler(&self) -> bool {
        true
    }

    fn hand_tls_context(&mut self, _: TlsNative) -> Result<(), ErrorKind> {
        self.handed += 1;
        self.refuses.map_or(Ok(()), Err)
    }

    fn stop_recv(&mut self) {}

    fn seconds_since_1970(&self) -> i64 {
        0
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Default for Kept {
    fn default() -> Kept {
        Kept::new()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl LayerCx for Kept {
    fn now(&self) -> Instant {
        self.notes.now()
    }

    fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
        Some(self)
    }

    fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
        Some(&mut self.notes)
    }

    fn transfer(&mut self) -> Option<&mut dyn crate::conn::layer::ForTransfer> {
        self.context
            .as_mut()
            .map(|c| c as &mut dyn crate::conn::layer::ForTransfer)
    }

    fn tls_sessions(&mut self) -> Option<&mut dyn crate::conn::layer::TlsSessions> {
        Some(self)
    }

    fn early_data(&mut self) -> Option<&mut dyn crate::conn::layer::EarlyData> {
        None
    }

    fn quic_timer(&mut self) -> Option<&mut dyn crate::conn::layer::QuicTimer> {
        None
    }

    fn h3_streams(&mut self) -> Option<&mut dyn crate::conn::layer::H3Streams> {
        None
    }

    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
        None
    }
}

/// The notes', but for whether the transfer is verbose.
#[cfg(any(test, feature = "test-util"))]
impl crate::conn::layer::Trace for Kept {
    fn line(&mut self, component: Component, line: fmt::Arguments<'_>) {
        self.notes.line(component, line);
    }

    fn line_with(&mut self, component: Component, parts: &[&[u8]]) {
        self.notes.line_with(component, parts);
    }

    fn info_line(&mut self, line: fmt::Arguments<'_>) {
        self.notes.info_line(line);
    }

    fn info_line_with(&mut self, parts: &[&[u8]]) {
        self.notes.info_line_with(parts);
    }

    fn says_info(&self) -> bool {
        self.verbose
    }
}

#[cfg(any(test, feature = "test-util"))]
impl crate::conn::layer::TlsSessions for Kept {
    fn with_cache(
        &mut self,
        f: &mut dyn FnMut(&mut SessionCache, &mut dyn crate::conn::layer::SessionSays),
    ) {
        f(&mut self.sessions, &mut self.notes);
    }
}

#[cfg(any(test, feature = "test-util"))]
impl TlsCx<'_> {
    /// Run `f` with what a multi keeps for a library and a context for
    /// a QUIC session to `host`'s port 443 made with `identity`, which
    /// keeps no sessions and notes what it is told in `notes`, for the
    /// tests of a library's sessions.
    pub fn testing<R>(
        identity: &TryArc<TlsIdentity>,
        host: &[u8],
        notes: &mut Notes,
        f: impl FnOnce(&TlsShared, &mut TlsCx<'_>) -> R,
    ) -> R {
        TlsCx::testing_over(identity, host, notes, f)
    }

    /// `testing`, the sessions kept in `kept`, which also notes what it
    /// is told.
    pub fn testing_kept<R>(
        identity: &TryArc<TlsIdentity>,
        host: &[u8],
        kept: &mut Kept,
        f: impl FnOnce(&TlsShared, &mut TlsCx<'_>) -> R,
    ) -> R {
        TlsCx::testing_over(identity, host, kept, f)
    }

    fn testing_over<R>(
        identity: &TryArc<TlsIdentity>,
        host: &[u8],
        notes: &mut dyn LayerCx,
        f: impl FnOnce(&TlsShared, &mut TlsCx<'_>) -> R,
    ) -> R {
        let mut name = Vec::new();
        name.try_extend_from_slice(host).expect("memory for a test");
        let origin = Peer::new(crate::proto::http::HTTPS, name, 443, None);
        let peer = SessionPeer::new(identity, &origin, None, &"test", crate::conn::Dial::Quic)
            .expect("memory for a test");
        let shared = TlsShared::new().expect("memory for a test");
        let mut cx = TlsCx::new(notes, Component::Ssl, &peer);
        f(&shared, &mut cx)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl TlsIo<'_> {
    /// Run `f` with the I/O of a stream connection to `host`'s port 443
    /// made with `identity`, straight over `socket`, its sessions kept in
    /// `kept`, which notes what it is told: for the tests of a library's
    /// sessions over a scripted wire.
    pub fn testing<R>(
        identity: &TryArc<TlsIdentity>,
        host: &[u8],
        kept: &mut Kept,
        socket: &dyn crate::conn::io::Socket,
        f: impl FnOnce(&mut TlsIo<'_>) -> R,
    ) -> R {
        TlsIo::testing_given(identity, host, kept, socket, None, f)
    }

    /// `testing`, the connection given `given` to resume before any of
    /// the cache's, as FTP's data connection is given its control
    /// connection's.
    pub fn testing_given<R>(
        identity: &TryArc<TlsIdentity>,
        host: &[u8],
        kept: &mut Kept,
        socket: &dyn crate::conn::io::Socket,
        given: Option<TlsTicket>,
        f: impl FnOnce(&mut TlsIo<'_>) -> R,
    ) -> R {
        let mut name = Vec::new();
        name.try_extend_from_slice(host).expect("memory for a test");
        let origin = Peer::new(crate::proto::http::HTTPS, name, 443, None);
        let peer = SessionPeer::new(identity, &origin, None, &"test", crate::conn::Dial::Stream)
            .expect("memory for a test");
        let mut early = Vec::new();
        let mut own = OwnSessions::new(false, given);
        let below = Below::bare(socket, None);
        let mut io = TlsIo::new(below, kept, &mut early, Component::Ssl, &peer, &mut own);
        f(&mut io)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl TlsShared {
    /// What a multi keeps for its libraries, for a test to hand the
    /// sessions it makes.
    pub fn testing() -> TlsShared {
        TlsShared::new().expect("memory for a test")
    }
}

impl<'a> TlsCx<'a> {
    pub(crate) fn new(
        cx: &'a mut dyn LayerCx,
        component: Component,
        peer: &'a SessionPeer,
    ) -> TlsCx<'a> {
        TlsCx {
            cx,
            component,
            peer,
            own: None,
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

    /// The identity an HTTPS proxy's TLS is made with: the proxy's
    /// options `proxy` (`set.proxy_ssl`), but for what C keeps on the
    /// handle and reads for either filter, which the origin's `origin`
    /// give (ALPN, the CA store's cache, the engine, the session cache),
    /// and for the curves and signature algorithms, which C sets for the
    /// origin alone (`Curl_ssl_filter_config_tmp_init`).
    pub(crate) fn of_proxy(
        proxy: &Tls,
        origin: &TlsOptions,
        ca_defaults: CaDefaults,
    ) -> Result<TryArc<TlsIdentity>, OutOfMemory> {
        let mut options = proxy.options.try_clone()?;
        options.context = None;
        options.curves = None;
        options.signature_algorithms = None;
        options.alpn = origin.alpn;
        options.ca_cache = origin.ca_cache;
        options.engine = match origin.engine.as_deref() {
            Some(engine) => {
                let mut copy = Vec::new();
                copy.try_extend_from_slice(engine)?;
                Some(copy)
            }
            None => None,
        };
        options.engine_default = origin.engine_default;
        options.session_cache = origin.session_cache;
        TryArc::try_new(TlsIdentity {
            verify_peer: proxy.verify_peer,
            verify_host: proxy.verify_host,
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

    /// The certificates to trust given in memory, if any: one set to
    /// nothing has none, as one never set.
    pub fn ca_blob(&self) -> Option<&[u8]> {
        resolved(&self.options.ca_blob, None)
    }

    /// The peer is to be checked against the system's own trust store
    /// (`native_ca_store`): asked for (`CURLSSLOPT_NATIVE_CA`), or, where
    /// the library makes it the default (`SystemStore::Default`), when
    /// the transfer names no file, directory or blob of certificates of
    /// its own, naming none counting as naming one
    /// (`Curl_ssl_filter_config_tmp_init`, `custom_cablob`).
    pub fn native_ca_store(&self) -> bool {
        let o = &self.options;
        o.ssl_options.contains(SslOptions::NATIVE_CA)
            || (self.ca_defaults.system == SystemStore::Default
                && matches!(o.ca_file, CaSetting::Default)
                && matches!(o.ca_path, CaSetting::Default)
                && matches!(o.ca_blob, CaSetting::Default))
    }
}

/// The SHA-256 of `bytes` (`Curl_sha256it`), by which a library tells
/// two blobs of certificates apart.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use crate::hash::Hash as _;
    let mut h = crate::hash::Sha256::default();
    h.update(bytes);
    h.finish()
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
            // as C, which copies the default in, finds them; the system's
            // store as it resolves (`native_ca_store`).
            ca_defaults: _,
        } = self;
        let TlsOptions {
            min_version,
            max_version,
            ssl_options,
            verify_status,
            // Compared as they resolve, below, and by the store they
            // make the default (`native_ca_store`).
            ca_file: _,
            ca_path: _,
            ca_blob: _,
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
            && self.ca_blob() == other.ca_blob()
            && self.native_ca_store() == other.native_ca_store()
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
