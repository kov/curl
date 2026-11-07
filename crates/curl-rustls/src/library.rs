//! What the session asks of rustls, one method per call of rustls-ffi's
//! that `lib/vtls/rustls.c` makes, so that the order of the calls, and
//! what is made of each answer, is the session's (`session.rs`). The
//! library itself is `rustls.rs`, which makes each call as rustls-ffi
//! makes it of the rustls crate; the tests give a scripted one.
//!
//! A call that reads or writes the connection is given the `Call` of the
//! session's call under way, which its I/O reaches: C's `read_cb` and
//! `write_cb`.

use core::fmt;

use curl_alloc::OutOfMemory;
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::tls::{SharedKeyLog, TlsIo};

use crate::result::Code;

/// `CURLE_AGAIN`, as the trace numbers a call that would block.
pub(crate) const AGAIN: u16 = 81;

/// The wire's numbers of the versions the library speaks
/// (`RUSTLS_TLS_VERSION_TLSV1_2`, `..._3`).
pub(crate) const TLS1_2: u16 = 0x0303;
pub(crate) const TLS1_3: u16 = 0x0304;

/// A cipher suite the library has (`rustls_supported_ciphersuite`): its
/// number, and whether it is TLS 1.3's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Suite {
    pub(crate) id: u16,
    pub(crate) tls13: bool,
}

/// rustls, as rustls-ffi hands it to C: what it makes, each step of the
/// configuration, and the connection made from it.
pub(crate) trait Rustls: Sync + 'static {
    /// A configuration being built (`rustls_client_config_builder`).
    type Builder: Send;
    /// Certificates to trust (`rustls_root_cert_store`).
    type Roots;
    /// Revocation lists (the verifier builder's CRLs).
    type Crls;
    /// A verifier of the peer's certificate (`rustls_server_cert_verifier`).
    type Verifier;
    /// The client's certificate and key (`rustls_certified_key`).
    type Key;
    /// A configuration built (`rustls_client_config`).
    type Config;
    type Conn: Conn;

    /// The default crypto provider's suites, in its order
    /// (`rustls_default_crypto_provider_ciphersuites_get`).
    fn suites(&self) -> Result<Vec<Suite>, OutOfMemory>;

    /// A configuration offering `suites` over `versions`, from a crypto
    /// provider that is the default but for its suites
    /// (`rustls_crypto_provider_builder_new_from_default`,
    /// `..._set_cipher_suites`, `..._build`, then
    /// `rustls_client_config_builder_new_custom`): none of which fails
    /// but for want of memory.
    fn builder(&self, suites: &[Suite], versions: &[u16]) -> Result<Self::Builder, OutOfMemory>;

    /// The certificates of the PEM `pem`, every one of which must parse,
    /// and at least one (`rustls_root_cert_store_builder_add_pem` or
    /// `..._load_roots_from_file`, strict, then `..._build`).
    fn roots(&self, pem: &[u8]) -> Result<Self::Roots, Code>;

    /// The revocation lists of the PEM `pem`, at least one
    /// (`rustls_web_pki_server_cert_verifier_builder_add_crl`).
    fn crls(&self, pem: &[u8]) -> Result<Self::Crls, Code>;

    /// The verifier of the peer's chain against `roots`, and `crls` if
    /// any (`rustls_web_pki_server_cert_verifier_builder_new`, `..._build`).
    fn webpki(&self, roots: Self::Roots, crls: Option<Self::Crls>) -> Result<Self::Verifier, Code>;

    /// The verifier of the system's own (`rustls_platform_server_cert_verifier`).
    fn platform(&self) -> Result<Self::Verifier, Code>;

    /// The client's certificate chain and key from their PEM
    /// (`rustls_certified_key_build`).
    fn certified_key(&self, chain: &[u8], key: &[u8]) -> Result<Self::Key, Code>;

    /// The key is the certificate's (`rustls_certified_key_keys_match`).
    fn keys_match(&self, key: &Self::Key) -> Result<(), Code>;

    /// `rustls_client_config_builder_set_alpn_protocols`.
    fn alpn(&self, builder: &mut Self::Builder, names: &[&[u8]]) -> Result<(), OutOfMemory>;

    /// `rustls_client_config_builder_dangerous_set_certificate_verifier`
    /// with C's `cr_verify_none`: any chain passes, its signatures still
    /// checked.
    fn verify_none(&self, builder: &mut Self::Builder);

    /// `rustls_client_config_builder_set_server_verifier`.
    fn verifier(&self, builder: &mut Self::Builder, verifier: Self::Verifier);

    /// `rustls_client_config_builder_set_certified_key`.
    fn certify(&self, builder: &mut Self::Builder, key: Self::Key);

    /// `rustls_client_config_builder_set_key_log` with C's
    /// `cr_keylog_log_cb`: each secret written to `log`.
    fn key_log(&self, builder: &mut Self::Builder, log: SharedKeyLog);

    /// `rustls_client_config_builder_enable_ech_grease` with the suites
    /// of `rustls_supported_hpke`, which the provider here always has
    /// (aws-lc-rs's): GREASE for one of them at random, which needs the
    /// configuration's versions to be TLS 1.3 alone.
    fn ech_grease(&self, builder: &mut Self::Builder) -> Result<(), Code>;

    /// `rustls_client_config_builder_enable_ech` of `list`, an
    /// ECHConfigList, with the same suites: one of its configurations
    /// they can use, over TLS 1.3 alone.
    fn ech(&self, builder: &mut Self::Builder, list: &[u8]) -> Result<(), Code>;

    /// `rustls_client_config_builder_build`.
    fn build(&self, builder: Self::Builder) -> Result<Self::Config, Code>;

    /// `rustls_client_connection_new` to the server `name`, a host name or
    /// an address.
    fn connect(&self, config: Self::Config, name: &[u8]) -> Result<Self::Conn, Code>;
}

/// What a read of the plain text came to (`rustls_connection_read`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plain {
    /// This many bytes; 0 at the peer's close_notify.
    Read(usize),
    /// None yet (`RUSTLS_RESULT_PLAINTEXT_EMPTY`).
    Empty,
    /// The peer closed the connection without its close_notify
    /// (`RUSTLS_RESULT_UNEXPECTED_EOF`).
    UnexpectedEof,
    /// Any other failure (`RUSTLS_RESULT_IO`).
    Failed(Code),
}

/// The error a read or write of the connection's records failed with, as
/// rustls-ffi passes it on: the number the I/O answered, or `EIO` for a
/// failure of rustls's own (`rustls_io_result`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Errno {
    /// `EAGAIN`.
    Again,
    /// `EINVAL`, which C's I/O answers for any failure below.
    Invalid,
    /// `EIO`.
    Io,
}

impl fmt::Display for Errno {
    /// C's words for it (`curlx_strerror`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Errno::Again => "Resource temporarily unavailable",
            Errno::Invalid => "Invalid argument",
            Errno::Io => "Input/output error",
        })
    }
}

/// One connection of the library's (`rustls_connection`).
pub(crate) trait Conn: Send {
    /// `rustls_connection_read_tls`, reading through `call`.
    fn read_tls(&mut self, call: &mut Call<'_, '_>) -> Result<usize, Errno>;
    /// `rustls_connection_write_tls`, writing through `call`.
    fn write_tls(&mut self, call: &mut Call<'_, '_>) -> Result<usize, Errno>;
    /// `rustls_connection_process_new_packets`.
    fn process_new_packets(&mut self) -> Result<(), Code>;
    /// `rustls_connection_wants_read`.
    fn wants_read(&self) -> bool;
    /// `rustls_connection_wants_write`.
    fn wants_write(&self) -> bool;
    /// `rustls_connection_is_handshaking`.
    fn is_handshaking(&self) -> bool;
    /// `rustls_connection_read` into `buf`.
    fn read(&mut self, buf: &mut [u8]) -> Plain;
    /// `rustls_connection_write` of `bytes`: how many it took.
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Code>;
    /// `rustls_connection_send_close_notify`.
    fn send_close_notify(&mut self);
    /// `rustls_connection_get_alpn_protocol`: none if none.
    fn alpn(&self) -> Option<&[u8]>;
    /// `rustls_connection_get_protocol_version`: the wire's number, 0 if
    /// not yet known.
    fn version(&self) -> u16;
    /// `rustls_connection_get_negotiated_ciphersuite_name`, empty if none.
    fn suite_name(&self) -> &str;
    /// `rustls_connection_get_negotiated_key_exchange_group_name`, empty if
    /// none.
    fn group_name(&self) -> &str;
    /// The DER of the peer's certificate `i`, the leaf's first
    /// (`rustls_connection_get_peer_certificate`,
    /// `rustls_certificate_get_der`): none past the last.
    fn peer_cert(&self, i: usize) -> Option<&[u8]>;
}

/// What a read or write of the connection answers the library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Moved {
    /// This many bytes; 0 for a read, the connection's end.
    Bytes(usize),
    /// None, as it would have blocked (`EAGAIN`).
    Again,
    /// None, as it failed (`EINVAL`).
    Failed,
}

/// What the I/O of one call into the library reaches: the connection
/// below the session.
pub(crate) struct Call<'s, 'a> {
    pub(crate) io: &'s mut TlsIo<'a>,
}

impl Call<'_, '_> {
    /// The library reads into `buf` (`read_cb`).
    pub(crate) fn recv(&mut self, buf: &mut [u8]) -> Moved {
        let got = if buf.is_empty() {
            Ok(Recv::WouldBlock)
        } else {
            self.io.recv(buf)
        };
        let (moved, code, n) = match got {
            Ok(Recv::Data(n)) => (Moved::Bytes(n.get()), 0, n.get()),
            Ok(Recv::Eof) => (Moved::Bytes(0), 0, 0),
            Ok(Recv::WouldBlock) => (Moved::Again, AGAIN, 0),
            Err(_) => (Moved::Failed, ErrorKind::RecvError.number(), 0),
        };
        let len = buf.len();
        self.io
            .trace(format_args!("cf->next recv(len={len}) -> {code}, {n}"));
        moved
    }

    /// The library writes `bytes` (`write_cb`).
    pub(crate) fn send(&mut self, bytes: &[u8]) -> Moved {
        let got = if bytes.is_empty() {
            Ok(Sent::WouldBlock)
        } else {
            self.io.send(bytes)
        };
        let (moved, code, n) = match got {
            Ok(Sent::Bytes(n)) => (Moved::Bytes(n.get()), 0, n.get()),
            Ok(Sent::WouldBlock) => (Moved::Again, AGAIN, 0),
            Err(_) => (Moved::Failed, ErrorKind::SendError.number(), 0),
        };
        let len = bytes.len();
        self.io
            .trace(format_args!("cf->next send(len={len}) -> {code}, {n}"));
        moved
    }
}

impl fmt::Debug for Call<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call").finish_non_exhaustive()
    }
}
