//! What the session asks of wolfSSL, one method per call of the library's
//! that `lib/vtls/wolfssl.c` makes, so that the order of the calls, and
//! what is made of each answer, is this crate's safe code (`session.rs`,
//! `trust.rs`). The library itself is `wolfssl.rs`; the tests give a
//! scripted one.
//!
//! The context (`WOLFSSL_CTX`) and the session's object (`WOLFSSL`) are
//! two values, as in C: the trust store is set up on the context from
//! inside a read of the session's handshake. A call that may read or
//! write the connection is given the `Call` of the session's call under
//! way, which the library's callbacks reach: the BIO's write, read and
//! control (C's `wssl_bio_cf_out_write`, `wssl_bio_cf_in_read`,
//! `wssl_bio_cf_ctrl`), and the callback told of each new session
//! (`wssl_vtls_new_session_cb`; over QUIC, `wssl_quic_new_session_cb`).
//! The callbacks find the call through the session's BIO, never its
//! application data, which over QUIC is ngtcp2's crypto's.

use core::ffi::CStr;
use core::fmt;

use curl_alloc::{OutOfMemory, TryArc};
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::tls::{Checked, Chosen, DriveCall, Text, TlsCx, TlsIo, TlsTicket};

/// `CURLE_AGAIN`, as the trace numbers a call that would block.
pub(crate) const AGAIN: u16 = 81;

/// A number the library answers with: `WOLFSSL_SUCCESS` (1), a count, or
/// a failure, which `Ssl::error` details.
pub(crate) type Rc = i32;

/// The library's words for an error (`wssl_strerror`): what
/// `wolfSSL_ERR_error_string_n` writes into C's 256 bytes, or C's own
/// words where it writes nothing.
#[derive(Clone, Copy)]
pub(crate) struct Words {
    buf: [u8; 256],
    len: usize,
}

impl Words {
    /// The first 255 bytes of `bytes`, as they fit C's buffer with their
    /// zero byte; for `error`, C's words where they are empty.
    pub(crate) fn new(bytes: &[u8], error: u32) -> Words {
        let bytes = if bytes.is_empty() {
            if error != 0 {
                &b"Unknown error"[..]
            } else {
                &b"No error"[..]
            }
        } else {
            bytes
        };
        let mut buf = [0; 256];
        let len = bytes.len().min(buf.len() - 1);
        buf[..len].copy_from_slice(&bytes[..len]);
        Words { buf, len }
    }
}

impl fmt::Display for Words {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Text(&self.buf[..self.len]).fmt(f)
    }
}

impl fmt::Debug for Words {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Words({self})")
    }
}

/// What a file or blob is read as (`wssl_do_file_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileType {
    /// `WOLFSSL_FILETYPE_PEM`.
    Pem,
    /// `WOLFSSL_FILETYPE_ASN1`: DER.
    Asn1,
    /// A type the library does not know: C hands it -1.
    Unknown,
}

impl FileType {
    /// The type named `kind` (`wssl_do_file_type`): PEM if none.
    pub(crate) fn of(kind: Option<&[u8]>) -> FileType {
        match kind {
            None | Some(b"") => FileType::Pem,
            Some(t) if t.eq_ignore_ascii_case(b"PEM") => FileType::Pem,
            Some(t) if t.eq_ignore_ascii_case(b"DER") => FileType::Asn1,
            Some(_) => FileType::Unknown,
        }
    }
}

/// wolfSSL: what it makes, and what it says of a number.
pub(crate) trait Wolfssl: Sync + 'static {
    type Ctx: Ctx<Store = Self::Store>;
    /// A counted reference to a store of certificates to trust
    /// (`WOLFSSL_X509_STORE`), freed as it goes.
    type Store: Store;
    /// The BIO method a session reads and writes the connection through
    /// (C's `wssl_bio_cf_method`), made by the global init; each session
    /// object holds it as long as it lives.
    type Method: Send + Sync + 'static;

    /// A context for a client (`wolfTLS_client_method`,
    /// `wolfSSL_CTX_new`), whose session objects read and write through
    /// `method`.
    fn ctx(&self, method: &TryArc<Self::Method>) -> Result<Self::Ctx, NoCtx>;

    /// A store of its own, for the multi to keep
    /// (`wolfSSL_X509_STORE_new`).
    fn new_store(&self) -> Option<Self::Store>;

    /// The library's words for `error` (`wssl_strerror`).
    fn strerror(&self, error: u32) -> Words;

    /// The suites the library has, by name, in its order
    /// (`wolfSSL_get_cipher_list` of 0, 1, ... until none).
    fn cipher(&self, index: usize) -> Option<&'static [u8]>;
}

/// What failed making a context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoCtx {
    /// No method (`wolfTLS_client_method`).
    Method,
    /// No context (`wolfSSL_CTX_new`).
    Context,
}

/// A counted reference to a store of certificates.
pub(crate) trait Store: Send + 'static {
    /// Another reference to the same store (`wolfSSL_X509_STORE_up_ref`),
    /// if the library could count it.
    fn another(&self) -> Option<Self>
    where
        Self: Sized;
}

/// A context (`WOLFSSL_CTX`), the library's calls on it.
pub(crate) trait Ctx: Send {
    type Store: Store;
    type Ssl: Ssl;

    /// `wolfSSL_CTX_set_min_proto_version` of the wire's number:
    /// whether it took it.
    fn min_version(&mut self, version: u16) -> bool;
    /// `wolfSSL_CTX_set_max_proto_version`, likewise.
    fn max_version(&mut self, version: u16) -> bool;
    /// `wolfSSL_CTX_set_cipher_list`, none being C's null.
    fn cipher_list(&mut self, list: Option<&CStr>) -> bool;
    /// `wolfSSL_CTX_set1_groups_list`.
    fn groups(&mut self, list: &CStr) -> bool;
    /// `wolfSSL_CTX_use_certificate_chain_buffer`.
    fn cert_chain_buffer(&mut self, pem: &[u8]) -> Rc;
    /// `wolfSSL_CTX_use_certificate_chain_file`.
    fn cert_chain_file(&mut self, file: &CStr) -> Rc;
    /// `wolfSSL_CTX_use_certificate_buffer`.
    fn cert_buffer(&mut self, cert: &[u8], kind: FileType) -> Rc;
    /// `wolfSSL_CTX_use_certificate_file`.
    fn cert_file(&mut self, file: &CStr, kind: FileType) -> Rc;
    /// `wolfSSL_CTX_use_PrivateKey_buffer`.
    fn key_buffer(&mut self, key: &[u8], kind: FileType) -> Rc;
    /// `wolfSSL_CTX_use_PrivateKey_file`.
    fn key_file(&mut self, file: &CStr, kind: FileType) -> Rc;
    /// `wolfSSL_CTX_set_verify`, the peer verified or not.
    fn verify(&mut self, peer: bool);
    /// `wolfSSL_CTX_UseSNI` of a host name: whether it took it.
    fn sni(&mut self, name: &[u8]) -> bool;
    /// `wolfSSL_CTX_sess_set_new_cb`: each new session reaches
    /// `Call::new_session`.
    fn tell_sessions(&mut self);

    /// `wolfSSL_CTX_load_system_CA_certs`: whether it loaded them.
    fn system_ca(&mut self) -> bool;
    /// `wolfSSL_CTX_load_verify_buffer` of PEM: whether it loaded it.
    fn ca_buffer(&mut self, pem: &[u8]) -> bool;
    /// `wolfSSL_CTX_load_verify_locations_ex`, errors ignored
    /// (`WOLFSSL_LOAD_FLAG_IGNORE_ERR`): whether it loaded them.
    fn ca_locations(&mut self, file: Option<&CStr>, path: Option<&CStr>) -> bool;
    /// The context's store is `store` (`wolfSSL_CTX_get_cert_store`).
    fn uses_store(&self, store: &Self::Store) -> bool;
    /// Another reference to the context's store, if it could count it.
    fn store(&self) -> Option<Self::Store>;
    /// Make `store` the context's (`wolfSSL_CTX_set_cert_store`), which
    /// takes this reference over.
    fn set_store(&mut self, store: Self::Store);

    /// The context, and `ssl` once made of it, for the application
    /// (`CURLOPT_SSL_CTX_FUNCTION`, `CURLINFO_TLS_SESSION`,
    /// `CURLINFO_TLS_SSL_PTR`) and the QUIC library.
    fn native(&self, ssl: Option<&Self::Ssl>) -> curl_core::tls::TlsNative;

    /// The session's object (`wolfSSL_new`); none out of memory. Its
    /// callbacks reach the call under way once it has its BIO
    /// (`Ssl::bio`).
    fn ssl(&mut self) -> Result<Self::Ssl, OutOfMemory>;
}

/// What resuming a session the cache kept came to (`wolfSSL_d2i_SSL_SESSION`,
/// `wolfSSL_set_session`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resume {
    Done,
    /// It would not decode.
    Undecoded,
    /// It decoded, and the library would not take it.
    Refused(Rc),
}

/// The peer's certificate, as the library hands it
/// (`wolfSSL_get_peer_certificate`, `wolfSSL_X509_get_der`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PeerCert {
    /// It has none.
    None,
    /// It has one and gives no DER of it.
    NoDer,
    Der(Vec<u8>),
    /// No room for a copy of it.
    NoRoom,
}

/// What `wolfSSL_ALPN_GetProtocol` came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AlpnGot {
    /// The peer chose this.
    Chose(Vec<u8>),
    /// It chose nothing (`WOLFSSL_ALPN_NOT_FOUND`).
    NotFound,
    /// Another failure, this number.
    Failed(Rc),
    /// No room for a copy of what it chose.
    NoRoom,
}

/// The secrets of a session before TLS 1.3, for the key log
/// (`wolfSSL_get_keys`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tls12Keys {
    pub(crate) master: Vec<u8>,
    pub(crate) client_random: Vec<u8>,
}

/// The session's object (`WOLFSSL`), the library's calls on it. Each
/// call that may move the connection clears the thread's errors first
/// (`wolfSSL_ERR_clear_error`), as C does before each.
pub(crate) trait Ssl: Send {
    /// Resume the session `der` saved.
    fn resume(&mut self, der: &[u8]) -> Resume;
    /// `wolfSSL_get_version`: the version's name.
    fn version_name(&self) -> &'static [u8];
    /// `wolfSSL_GetVersion` names a version before TLS 1.3.
    fn before_tls13(&self) -> bool;
    /// `wolfSSL_get_cipher_name`, none for none.
    fn cipher_name(&self) -> Option<&'static [u8]>;
    /// `wolfSSL_SESSION_get_max_early_data` of `wolfSSL_get_session`.
    fn session_max_early_data(&self) -> u32;
    /// `wolfSSL_set_max_early_data`.
    fn max_early_data(&mut self, most: u32);
    /// `wolfSSL_UseALPN` of `list`, names after commas, going on if the
    /// peer chooses none (`WOLFSSL_ALPN_CONTINUE_ON_MISMATCH`): whether
    /// it took them.
    fn alpn(&mut self, list: &[u8]) -> bool;
    /// `wolfSSL_SetEchConfigsBase64` of `b64`, an ECHConfigList in
    /// base64, which the library decodes: whether it took it.
    fn ech_configs_base64(&mut self, b64: &[u8]) -> bool;
    /// `wolfSSL_SetEchConfigs` of `list`, an ECHConfigList: whether it
    /// took it.
    fn set_ech_configs(&mut self, list: &[u8]) -> bool;
    /// `wolfSSL_GetEchConfigs` into C's 1000 bytes: the ECHConfigList the
    /// session holds, or none if it fails.
    fn ech_configs(&self) -> Option<Vec<u8>>;
    /// `wolfSSL_set_min_proto_version`: whether it is 1.
    fn min_version(&mut self, version: u16) -> bool;
    /// `wolfSSL_KeepArrays`.
    fn keep_arrays(&mut self);
    /// `wolfSSL_FreeArrays`.
    fn free_arrays(&mut self);
    /// `wolfSSL_get_keys`, if it has them.
    fn tls12_keys(&self) -> Option<Tls12Keys>;
    /// `wolfSSL_check_domain_name`: whether it took it.
    fn check_domain(&mut self, name: &CStr) -> bool;
    /// `wolfSSL_set_quic_use_legacy_codepoint` of 0: QUIC's transport
    /// parameters sent at RFC 9000's code point.
    fn quic_codepoint(&mut self);
    /// `wolfSSL_BIO_new` of the connection's method and `wolfSSL_set_bio`:
    /// the session reads and writes through the call under way, and its
    /// callbacks find that call through the BIO; none out of memory. A
    /// QUIC session never reads or writes through it.
    fn bio(&mut self) -> Result<(), OutOfMemory>;
    /// Run `op`, a call into the QUIC library that drives the session,
    /// with the session's callbacks reaching `call`, and lend `op` what
    /// the QUIC library's own callbacks reach: `call`'s transfer, and
    /// `check` run on the session and the transfer as the QUIC library
    /// says the handshake is done.
    fn drive(
        &mut self,
        call: &mut Call<'_, '_>,
        check: &mut dyn FnMut(&mut Self, &mut TlsCx<'_>) -> Result<Checked, ErrorKind>,
        op: &mut dyn FnMut(&mut dyn DriveCall),
    );

    /// `wolfSSL_connect`.
    fn connect(&mut self, call: &mut Call<'_, '_>) -> Rc;
    /// `wolfSSL_get_error` of `rc`, the last call's answer.
    fn error(&self, rc: Rc) -> i32;
    /// `wolfSSL_want_read`, `wolfSSL_want_write`.
    fn wants_read(&self) -> bool;
    fn wants_write(&self) -> bool;
    /// `wolfSSL_write_early_data`: its answer and the bytes it took.
    fn write_early(&mut self, call: &mut Call<'_, '_>, bytes: &[u8]) -> (Rc, usize);
    /// `wolfSSL_get_early_data_status` says the peer rejected it.
    fn early_rejected(&self) -> bool;
    /// `wolfSSL_read`: a count, or not positive, which `error` details.
    fn read(&mut self, call: &mut Call<'_, '_>, buf: &mut [u8]) -> Rc;
    /// `wolfSSL_write`, likewise.
    fn write(&mut self, call: &mut Call<'_, '_>, bytes: &[u8]) -> Rc;
    /// `wolfSSL_shutdown`.
    fn shutdown(&mut self, call: &mut Call<'_, '_>) -> Rc;
    /// `wolfSSL_get_shutdown` has `WOLFSSL_SENT_SHUTDOWN`.
    fn sent_shutdown(&self) -> bool;
    /// `wolfSSL_pending` is not 0.
    fn pending(&self) -> bool;

    /// The peer's certificate.
    fn peer_cert(&self) -> PeerCert;
    /// `wolfSSL_X509_check_ip_asc` of the peer's certificate and `ip`;
    /// none if it has no certificate.
    fn check_ip(&self, ip: &CStr) -> Option<Rc>;
    /// `wolfSSL_X509_check_host` of the peer's certificate and `name`,
    /// with no flags; none if it has no certificate.
    fn check_host(&self, name: &[u8]) -> Option<Rc>;
    /// `wolfSSL_ALPN_GetProtocol`.
    fn alpn_selected(&self) -> AlpnGot;
}

/// What the last read or write below came to (C's `io_result`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum IoResult {
    #[default]
    Ok,
    Again,
    Failed(ErrorKind),
}

impl IoResult {
    /// As C's `CURLcode` numbers it.
    pub(crate) fn number(self) -> u16 {
        match self {
            IoResult::Ok => 0,
            IoResult::Again => AGAIN,
            IoResult::Failed(kind) => kind.number(),
        }
    }
}

/// What a session's I/O keeps from one call to the next, which its
/// callbacks change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IoState {
    /// What the last read or write below came to (`io_result`).
    pub(crate) result: IoResult,
    /// A read below met the connection's end (`peer_closed`).
    pub(crate) peer_closed: bool,
    /// The goodbye is under way (`shutting_down`), and the length of the
    /// write of it that would have blocked (`io_send_blocked_len`).
    pub(crate) shutting_down: bool,
    pub(crate) blocked_len: usize,
    /// The handshake's first step is over (`ssl_connect_2`): its reads
    /// set the trust store up first, if it is not.
    pub(crate) handshaking: bool,
    /// The trust store is set up (`x509_store_setup`).
    pub(crate) store_ready: bool,
}

/// Sets the trust store up, from inside a read, on the context.
pub(crate) type SetupStore<'s> = &'s mut dyn FnMut(&mut TlsCx<'_>) -> Result<(), ErrorKind>;

/// A session the library made, as `wssl_vtls_new_session_cb` hands it to
/// `Curl_wssl_cache_session`.
#[derive(Clone, Debug)]
pub(crate) enum NewSession {
    /// Its DER, the version its connection speaks, the seconds it lives
    /// and the early data it allows.
    Made {
        der: Vec<u8>,
        version: u16,
        timeout: i64,
        early_max: u32,
    },
    /// Its length could not be had, or it would not be written: the
    /// number the library answered, as C's unsigned length reads it.
    Unsized(u32),
    Unwritten(u32),
    /// No room for its DER, this many bytes of it.
    NoRoom(u32),
}

/// What a call's callbacks reach of the connection: a stream session's
/// layers below and its transfer, or a QUIC session's transfer alone.
pub(crate) enum Reach<'s, 'a> {
    Stream(&'s mut TlsIo<'a>),
    Quic(&'s mut TlsCx<'a>),
}

impl<'a> Reach<'_, 'a> {
    /// The transfer.
    pub(crate) fn cx(&mut self) -> &mut TlsCx<'a> {
        match self {
            Reach::Stream(io) => io,
            Reach::Quic(cx) => cx,
        }
    }

    /// The layers below: a stream session's alone, as a QUIC session's
    /// records are the QUIC library's to carry.
    fn below(&mut self) -> &mut TlsIo<'a> {
        match self {
            Reach::Stream(io) => io,
            Reach::Quic(_) => unreachable!("a QUIC session's records are the QUIC library's"),
        }
    }
}

/// Encodes the QUIC connection's transport parameters, which a session
/// the peer gives is kept with (`ngtcp2_conn_encode_0rtt_transport_params`).
pub(crate) type QuicParams<'s> = &'s mut dyn FnMut() -> Option<Vec<u8>>;

/// What the callbacks of one call into the library reach.
pub(crate) struct Call<'s, 'a> {
    pub(crate) io: Reach<'s, 'a>,
    pub(crate) state: &'s mut IoState,
    /// Sets the trust store up at the handshake's first read, if not yet.
    pub(crate) store: Option<SetupStore<'s>>,
    /// What ALPN agreed, which a session kept is kept with
    /// (`connssl->negotiated.alpn`).
    pub(crate) alpn: Option<Chosen>,
    /// A QUIC session's: its connection's transport parameters, which a
    /// session the peer gives is kept with.
    pub(crate) quic_params: Option<QuicParams<'s>>,
}

impl Call<'_, '_> {
    /// The library writes `bytes` (`wssl_bio_cf_out_write`): what went,
    /// or none, which the library reads as a failure or, with the retry
    /// flag set (`wolfSSL_BIO_set_retry_write`), a wait.
    pub(crate) fn send(&mut self, bytes: &[u8]) -> Moved {
        let mut len = bytes.len();
        let mut skip = 0;
        let s = &mut *self.state;
        if s.shutting_down && s.blocked_len != 0 && s.blocked_len < len {
            // wolfSSL adds the close_notify again each time a blocked
            // send of it is retried (wolfSSL/wolfssl#7784): only what
            // blocked is sent, the rest counted as sent.
            self.io.cx().trace(format_args!(
                "bio_write, shutdown restrict send of {len} to {} bytes",
                s.blocked_len
            ));
            skip = len - s.blocked_len;
            len = s.blocked_len;
        }
        let (result, n) = if len == 0 {
            (IoResult::Ok, 0)
        } else {
            match self.io.below().send(&bytes[..len]) {
                Ok(Sent::Bytes(n)) => (IoResult::Ok, n.get()),
                Ok(Sent::WouldBlock) => (IoResult::Again, 0),
                Err(_) => (IoResult::Failed(ErrorKind::SendError), 0),
            }
        };
        self.state.result = result;
        self.io.cx().trace(format_args!(
            "bio_write(len={len}) -> {}, {n}",
            result.number()
        ));
        match result {
            IoResult::Ok => Moved::Bytes(n + skip),
            IoResult::Again => {
                if self.state.shutting_down && self.state.blocked_len == 0 {
                    self.state.blocked_len = len;
                }
                Moved::Again
            }
            IoResult::Failed(_) => Moved::Failed,
        }
    }

    /// The library reads into `buf` (`wssl_bio_cf_in_read`), the trust
    /// store set up first in the handshake, if it is not.
    pub(crate) fn recv(&mut self, buf: &mut [u8]) -> Moved {
        if buf.is_empty() {
            return Moved::Bytes(0);
        }
        if self.state.handshaking && !self.state.store_ready {
            // Set up before the server's answer is read, so the
            // ClientHello goes without waiting for it.
            self.state.store_ready = true;
            if let Some(setup) = self.store.as_mut()
                && let Err(kind) = setup(self.io.cx())
            {
                self.io.cx().trace(format_args!(
                    "Curl_wssl_setup_x509_store() -> {}",
                    kind.number()
                ));
                self.state.result = IoResult::Failed(kind);
                return Moved::Refused;
            }
        }
        let len = buf.len();
        let (result, n) = match self.io.below().recv(buf) {
            Ok(Recv::Data(n)) => (IoResult::Ok, n.get()),
            Ok(Recv::Eof) => (IoResult::Ok, 0),
            Ok(Recv::WouldBlock) => (IoResult::Again, 0),
            Err(_) => (IoResult::Failed(ErrorKind::RecvError), 0),
        };
        self.state.result = result;
        self.io.cx().trace(format_args!(
            "bio_read(len={len}) -> {}, {n}",
            result.number()
        ));
        match result {
            IoResult::Ok => {
                if n == 0 {
                    self.state.peer_closed = true;
                }
                Moved::Bytes(n)
            }
            IoResult::Again => Moved::Again,
            IoResult::Failed(_) => Moved::Failed,
        }
    }

    /// The library read with a length below 0 (`wssl_bio_cf_in_read`):
    /// refused, the session's I/O failed.
    pub(crate) fn recv_refused(&mut self) -> Moved {
        self.state.result = IoResult::Failed(ErrorKind::FailedInit);
        Moved::Refused
    }

    /// Whether the connection's end has been read (`WOLFSSL_BIO_CTRL_EOF`).
    pub(crate) fn at_eof(&self) -> bool {
        self.state.peer_closed
    }

    /// The library made a session (`wssl_vtls_new_session_cb`): kept in
    /// the cache, as `Curl_wssl_cache_session` keeps it, if it could be
    /// written out. Over QUIC (`wssl_quic_new_session_cb`), what ALPN
    /// agreed is HTTP/3, and it is kept with the connection's transport
    /// parameters where they encode.
    pub(crate) fn new_session(&mut self, made: NewSession) {
        match made {
            NewSession::Unsized(n) => {
                self.io
                    .cx()
                    .trace(format_args!("fail to assess session length: {n}"));
            }
            NewSession::Unwritten(n) => {
                self.io
                    .cx()
                    .trace(format_args!("fail to serialize session: {n}"));
            }
            NewSession::NoRoom(n) => {
                self.io.cx().fail(
                    ErrorKind::OutOfMemory,
                    format_args!("unable to allocate session buffer of {n} bytes"),
                );
            }
            NewSession::Made {
                der,
                version,
                timeout,
                early_max,
            } => {
                let until = self.io.cx().unix_time().saturating_add(timeout);
                let early = usize::try_from(early_max).unwrap_or(usize::MAX);
                let ticket = TlsTicket::new(der, version, self.alpn, early, until);
                let ticket = match self.quic_params.as_mut().and_then(|params| params()) {
                    Some(params) => ticket.with_quic_params(params),
                    None => ticket,
                };
                self.io.cx().keep_session(ticket);
            }
        }
    }
}

impl fmt::Debug for Call<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call")
            .field("state", &self.state)
            .field("alpn", &self.alpn)
            .finish_non_exhaustive()
    }
}

/// What a write or read below answers the library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Moved {
    /// This many bytes; 0 for a read, the connection's end.
    Bytes(usize),
    /// None, as it would have blocked: the BIO's retry flag set.
    Again,
    /// None, as it failed (-1).
    Failed,
    /// None, failed before the connection was reached (-1): the BIO's
    /// retry flags are left as they were.
    Refused,
}

pub(crate) use curl_core::tls::{as_c, c_string};
