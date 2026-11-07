//! What the session asks of GnuTLS, one method per call of the library's
//! that `lib/vtls/gtls.c` makes, so that the order of the calls, and
//! what is made of each answer, is this crate's safe code (`session.rs`,
//! `trust.rs`, `verify.rs`). The library itself is `gnutls.rs`; the tests
//! give a scripted one.
//!
//! A call that may read or write the connection is given the `Call` of
//! the session's call under way, which its callbacks reach: GnuTLS's
//! push and pull functions, its handshake hook and its key log function
//! (C's `gtls_push`, `gtls_pull`, `gtls_handshake_cb` and
//! `keylog_callback`).

use std::ffi::CStr;
use std::fmt;

use curl_alloc::TryVec as _;
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::tls::{Chosen, KeyLog, TlsCx, TlsIo, TlsTicket};

use crate::text::Text;

/// `CURLE_AGAIN`, as the trace numbers a call that would block.
pub(crate) const AGAIN: u16 = 81;

/// A number the library answers with: 0 or more, a success (for some
/// calls a count), less than 0, one of its `GNUTLS_E_*` errors.
pub(crate) type Rc = i32;

/// The formats of a certificate or key file (`gnutls_x509_crt_fmt_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Der,
    Pem,
}

/// GnuTLS: what it makes, and what it says of a number.
pub(crate) trait Gnutls: Sync + 'static {
    type Creds: Creds;
    type Session: Session<Creds = Self::Creds, Cert = Self::Cert>;
    type Cert: Cert;

    /// Certificate credentials, empty
    /// (`gnutls_certificate_allocate_credentials`).
    fn creds(&self) -> Result<Self::Creds, Rc>;

    /// A client session of `flags` (`gnutls_init`).
    fn session(&self, flags: u32) -> Result<Self::Session, Rc>;

    /// A certificate, empty (`gnutls_x509_crt_init`).
    fn cert(&self) -> Result<Self::Cert, Rc>;

    /// The text of `rc` (`gnutls_strerror`).
    fn strerror(&self, rc: Rc) -> &'static [u8];

    /// `rc` ends the session (`gnutls_error_is_fatal`).
    fn is_fatal(&self, rc: Rc) -> bool;
}

/// Certificate credentials: the anchors to trust, the lists of revoked
/// certificates, and the client's certificate and key. Each answers as
/// the library does: the count of what was added, or an error. They are
/// changed only while one session holds them (`trust::populate` asserts
/// it), through the library's pointer: never while shared.
pub(crate) trait Creds: Send + Sync + 'static {
    /// `gnutls_certificate_set_x509_system_trust`.
    fn system_trust(&self) -> Rc;
    /// `gnutls_certificate_set_x509_trust_mem`, of PEM.
    fn trust_mem(&self, pem: &[u8]) -> Rc;
    /// `gnutls_certificate_set_verify_flags`, with
    /// `GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT`.
    fn allow_v1_ca(&self);
    /// `gnutls_certificate_set_x509_trust_file`, of PEM.
    fn trust_file(&self, file: &CStr) -> Rc;
    /// `gnutls_certificate_set_x509_trust_dir`, of PEM.
    fn trust_dir(&self, dir: &CStr) -> Rc;
    /// `gnutls_certificate_set_x509_crl_file`, of PEM.
    fn crl_file(&self, file: &CStr) -> Rc;
    /// `gnutls_certificate_set_x509_simple_pkcs12_file`, of DER.
    fn pkcs12_file(&self, file: &CStr, password: &CStr) -> Rc;
    /// `gnutls_certificate_set_x509_key_file2`, with the key encryptions
    /// C allows.
    fn key_file(&self, cert: &CStr, key: &CStr, format: Format, password: Option<&CStr>) -> Rc;
}

/// One connection's session.
pub(crate) trait Session: Send {
    type Creds;
    type Cert: Cert;

    /// `gnutls_server_name_set` with a DNS name.
    fn server_name(&mut self, name: &[u8]) -> Rc;
    /// `gnutls_set_default_priority`.
    fn default_priority(&mut self) -> Rc;
    /// `gnutls_priority_set_direct`: on an error, the part of `priority`
    /// it fails at (`err_pos`), if it says.
    fn priority<'p>(&mut self, priority: &'p CStr) -> Result<(), (Rc, Option<&'p [u8]>)>;
    /// `gnutls_credentials_set` of the certificate kind. The session
    /// points at `creds`, which must outlive it or be replaced.
    fn credentials(&mut self, creds: &Self::Creds) -> Rc;
    /// `gnutls_ocsp_status_request_enable_client`, asking for no
    /// particular responder.
    fn status_request(&mut self) -> Rc;
    /// `gnutls_session_set_data`: resume the session `data` describes.
    fn set_data(&mut self, data: &[u8]) -> Rc;
    /// `gnutls_session_get_data`: the session to resume, as the library
    /// keeps it, empty if it has none; `Err` out of memory.
    fn data(&mut self) -> Result<Vec<u8>, ErrorKind>;
    /// `gnutls_record_get_max_early_data_size`.
    fn max_early_data(&mut self) -> usize;
    /// `gnutls_alpn_set_protocols`, mandatory.
    fn alpn(&mut self, protocols: &[&[u8]]) -> Rc;
    /// `gnutls_session_set_keylog_function`: the secrets told of reach
    /// `Call::keylog_secret`.
    fn log_keys(&mut self);
    /// `gnutls_handshake_set_hook_function` for every message after it
    /// is handled (`Call::handshake_message`), and the transport's push
    /// and pull functions (`Call::push`, `Call::pull`).
    fn hook(&mut self);

    /// `gnutls_handshake`.
    fn handshake(&mut self, call: &mut Call<'_, '_, Self::Creds>) -> Rc;
    /// `gnutls_record_send`: a count, or an error.
    fn send(&mut self, call: &mut Call<'_, '_, Self::Creds>, bytes: &[u8]) -> isize;
    /// `gnutls_record_recv`: a count, 0 the end, or an error.
    fn recv(&mut self, call: &mut Call<'_, '_, Self::Creds>, buf: &mut [u8]) -> isize;
    /// `gnutls_record_send_early_data`.
    fn send_early(&mut self, call: &mut Call<'_, '_, Self::Creds>, bytes: &[u8]) -> isize;
    /// `gnutls_bye`, both ways.
    fn bye(&mut self, call: &mut Call<'_, '_, Self::Creds>) -> Rc;

    /// `gnutls_record_get_direction`: the last call that would have
    /// blocked would have written.
    fn wants_write(&mut self) -> bool;
    /// `gnutls_alert_get_name` of `gnutls_alert_get`.
    fn alert_name(&mut self) -> Option<&'static [u8]>;
    /// `gnutls_record_check_pending`: decrypted bytes held.
    fn pending(&self) -> bool;
    /// `gnutls_protocol_get_version`, the library's number.
    fn version(&mut self) -> i32;
    /// `gnutls_protocol_get_name` of the version.
    fn version_name(&mut self) -> Option<&'static [u8]>;
    /// `gnutls_cipher_suite_get_name` of the agreed key exchange,
    /// cipher and MAC.
    fn suite_name(&mut self) -> Option<&'static [u8]>;
    /// `gnutls_alpn_get_selected_protocol`, empty if none.
    fn alpn_selected(&mut self) -> &[u8];
    /// `gnutls_session_get_flags` has `GNUTLS_SFLAGS_EARLY_DATA`.
    fn early_data_accepted(&mut self) -> bool;
    /// `gnutls_certificate_get_peers`: the peer's chain, DER, leaf
    /// first; none if it sent none.
    fn peers(&self) -> Option<Vec<&[u8]>>;
    /// `gnutls_certificate_verify_peers2`: the status bits, or the error.
    fn verify_peers(&self) -> Result<u32, Rc>;
    /// The stapled status checked for `cert` (`gtls_verify_ocsp_status`'s
    /// calls).
    fn stapled_status(&self, cert: &Self::Cert) -> Stapled;
    /// The session's own object, for the application
    /// (`CURLINFO_TLS_SSL_PTR`).
    fn native(&self) -> core::ptr::NonNull<core::ffi::c_void>;
}

/// What the peer's stapled status came to, at each step C says it fails
/// at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stapled {
    /// None came.
    None,
    /// One came the library would not give.
    Invalid,
    /// No room to read it.
    InitFailed,
    /// It does not parse.
    Unparsed,
    /// Its overall status is not successful.
    NotSuccessful,
    /// It says nothing of the peer's certificate.
    NotForPeer,
    /// The part for the peer's certificate does not read.
    SingleUnparsed,
    /// The certificate's status: `GNUTLS_OCSP_CERT_*`.
    Status(u32),
}

/// A certificate.
pub(crate) trait Cert {
    /// `gnutls_x509_crt_import`.
    fn import(&mut self, data: &[u8], format: Format) -> Rc;
    /// The first common name of the subject, as C reads it into 65
    /// bytes (`gnutls_x509_crt_get_dn_by_oid`): the text, or the error.
    fn common_name(&self) -> Result<Vec<u8>, Rc>;
    /// `gnutls_x509_crt_get_expiration_time`, -1 if it has none.
    fn expiration(&self) -> i64;
    /// `gnutls_x509_crt_get_activation_time`, -1 if it has none.
    fn activation(&self) -> i64;
    /// `gnutls_x509_crt_check_hostname`.
    fn matches_host(&self, name: &CStr) -> bool;
    /// `gnutls_x509_crt_check_issuer`.
    fn issued_by(&self, issuer: &Self) -> bool;
    /// `gnutls_pk_algorithm_get_name` of `gnutls_x509_crt_get_pk_algorithm`.
    fn key_algorithm(&self) -> Option<&'static [u8]>;
    /// `gnutls_x509_crt_get_version`.
    fn version(&self) -> i32;
    /// `gnutls_x509_crt_get_dn2`: the subject as text, or the error.
    fn subject(&self) -> Result<Vec<u8>, Rc>;
    /// `gnutls_x509_crt_get_issuer_dn2`.
    fn issuer(&self) -> Result<Vec<u8>, Rc>;
    /// The DER of the public key (`gnutls_pubkey_export` of
    /// `gnutls_pubkey_import_x509`), none if any step fails.
    fn public_key(&self) -> Option<Vec<u8>>;
}

/// What the last read or write below came to (`io_result`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IoResult {
    Ok,
    /// It would have blocked (`CURLE_AGAIN`).
    Again,
    /// It failed, as this kind; the reason said.
    Failed(ErrorKind),
}

impl IoResult {
    /// The failure, if it failed (a nonzero `io_result`).
    pub(crate) fn failure(self) -> Option<ErrorKind> {
        match self {
            IoResult::Failed(kind) => Some(kind),
            IoResult::Ok | IoResult::Again => None,
        }
    }

    /// As C's trace numbers it.
    fn number(self) -> u16 {
        match self {
            IoResult::Ok => 0,
            IoResult::Again => AGAIN,
            IoResult::Failed(kind) => kind.number(),
        }
    }
}

/// What a push or pull answers the library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Moved {
    /// This many bytes; 0 for a pull, the connection's end.
    Bytes(usize),
    /// None, as it would have blocked (`EAGAIN`).
    Again,
    /// None, as it failed (`EINVAL`).
    Failed,
}

/// Points the session of the call under way at other credentials
/// (`gnutls_credentials_set`, called from inside the library's call, as
/// C calls it from its pull function).
pub(crate) type SetCreds<'f, C> = &'f mut dyn FnMut(&C) -> Rc;

/// Sets the trust anchors up, as the peer's first bytes are about to be
/// read (`Curl_gtls_client_trust_setup`), given how to point the session
/// at the multi's credentials.
pub(crate) type TrustSetup<'s, C> =
    &'s mut dyn FnMut(&mut TlsCx<'_>, SetCreds<'_, C>) -> Result<(), ErrorKind>;

/// What the callbacks of one call into the library reach, for a session
/// of credentials `C`.
pub(crate) struct Call<'s, 'a, C> {
    pub(crate) io: &'s mut TlsIo<'a>,
    pub(crate) io_result: IoResult,
    /// Sets the trust anchors up, until they are.
    pub(crate) trust: Option<TrustSetup<'s, C>>,
    /// The anchors are set up.
    pub(crate) trust_ready: bool,
    /// Where secrets go, while the key log is open.
    pub(crate) keylog: Option<&'s KeyLog>,
    /// What ALPN agreed, which a session the peer gives is kept with
    /// (`connssl->negotiated.alpn`).
    pub(crate) alpn: Option<Chosen>,
}

impl<C> Call<'_, '_, C> {
    /// The library writes `bytes` (`gtls_push`).
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Moved {
        let got = if bytes.is_empty() {
            Ok(Sent::WouldBlock)
        } else {
            self.io.send(bytes)
        };
        let (moved, n) = match got {
            Ok(Sent::Bytes(n)) => {
                self.io_result = IoResult::Ok;
                (Moved::Bytes(n.get()), n.get())
            }
            Ok(Sent::WouldBlock) => {
                self.io_result = IoResult::Again;
                (Moved::Again, 0)
            }
            Err(_) => {
                self.io_result = IoResult::Failed(ErrorKind::SendError);
                (Moved::Failed, 0)
            }
        };
        let (len, code) = (bytes.len(), self.io_result.number());
        self.io
            .trace(format_args!("gtls_push(len={len}) -> {code}, {n}"));
        moved
    }

    /// The library reads into `buf` (`gtls_pull`): the trust anchors set
    /// up first, unless they are, `set` pointing the session at other
    /// credentials.
    pub(crate) fn pull(&mut self, buf: &mut [u8], set: SetCreds<'_, C>) -> Moved {
        if !self.trust_ready
            && let Some(setup) = self.trust.as_mut()
        {
            match setup(self.io, set) {
                Ok(()) => self.trust_ready = true,
                Err(kind) => {
                    self.io_result = IoResult::Failed(kind);
                    return Moved::Failed;
                }
            }
        }
        let got = if buf.is_empty() {
            Ok(Recv::WouldBlock)
        } else {
            self.io.recv(buf)
        };
        let (moved, n) = match got {
            Ok(Recv::Data(n)) => {
                self.io_result = IoResult::Ok;
                (Moved::Bytes(n.get()), n.get())
            }
            Ok(Recv::Eof) => {
                self.io_result = IoResult::Ok;
                (Moved::Bytes(0), 0)
            }
            Ok(Recv::WouldBlock) => {
                self.io_result = IoResult::Again;
                (Moved::Again, 0)
            }
            Err(_) => {
                self.io_result = IoResult::Failed(ErrorKind::RecvError);
                (Moved::Failed, 0)
            }
        };
        let (len, code) = (buf.len(), self.io_result.number());
        self.io
            .trace(format_args!("gtls_pull(len={len}) -> {code}, {n}"));
        moved
    }

    /// The library handled a handshake message of type `kind`, the
    /// peer's if `incoming` (`gtls_handshake_cb`): whether it is a session
    /// ticket the connection would keep, which the caller then hands to
    /// `keep_ticket`.
    pub(crate) fn handshake_message(&mut self, kind: u32, incoming: bool) -> bool {
        let way = if incoming { "incoming" } else { "outgoing" };
        self.io
            .trace(format_args!("handshake: {way} message type {kind}"));
        kind == crate::sys::GNUTLS_HANDSHAKE_NEW_SESSION_TICKET && self.io.caches_sessions()
    }

    /// Keep the session the library has (`cf_gtls_update_session_id`).
    pub(crate) fn keep_ticket(&mut self, data: Vec<u8>, version: i32, early_max: usize) {
        keep_ticket(self.io, data, version, early_max, self.alpn);
    }

    /// The library tells of a secret (`keylog_callback`): written with
    /// the connection's client random, which must be 32 bytes. Whether it
    /// was taken.
    pub(crate) fn keylog_secret(&mut self, label: &[u8], random: &[u8], secret: &[u8]) -> bool {
        let Ok(random) = <&[u8; 32]>::try_from(random) else {
            return false;
        };
        if let Some(log) = self.keylog {
            log.write_secret(label, random, secret);
        }
        true
    }
}

/// The version `version`, the library's number, as the wire has it
/// (`gtls_get_ietf_proto`); 0 for one it does not name.
pub(crate) fn ietf_version(version: i32) -> u16 {
    use crate::sys::{GNUTLS_SSL3, GNUTLS_TLS1_0, GNUTLS_TLS1_1, GNUTLS_TLS1_2, GNUTLS_TLS1_3};
    match version {
        GNUTLS_SSL3 => 0x300,
        GNUTLS_TLS1_0 => 0x301,
        GNUTLS_TLS1_1 => 0x302,
        GNUTLS_TLS1_2 => 0x303,
        GNUTLS_TLS1_3 => 0x304,
        _ => 0,
    }
}

/// Keep the session `data` of a connection of `version` allowing
/// `early_max` bytes of early data, agreed `alpn`, in the transfer's
/// cache (`Curl_gtls_cache_session`), unless it keeps none or the library
/// gave none.
pub(crate) fn keep_ticket(
    io: &mut TlsCx<'_>,
    data: Vec<u8>,
    version: i32,
    early_max: usize,
    alpn: Option<Chosen>,
) {
    if data.is_empty() {
        return;
    }
    let name = alpn.map_or("-", Chosen::name);
    io.trace(format_args!(
        "get session id (len={}, alpn={name}, earlymax={early_max}) and store in cache",
        data.len()
    ));
    io.keep_session(TlsTicket::new(
        data,
        ietf_version(version),
        alpn,
        early_max,
        0,
    ));
}

/// A C string of `bytes`, for a call that takes one; `Err` out of memory.
pub(crate) fn c_string(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut c = Vec::new();
    c.try_reserve_exact(bytes.len() + 1)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    c.try_extend_from_slice(bytes)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    c.try_push(0).map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(c)
}

/// `bytes` and the zero after them, as a `CStr`: what `c_string` makes.
/// A name with a zero in it ends there, as C reads it.
pub(crate) fn as_c(bytes: &[u8]) -> &CStr {
    CStr::from_bytes_until_nul(bytes).expect("made by `c_string`")
}

impl<C> fmt::Debug for Call<'_, '_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call")
            .field("io_result", &self.io_result)
            .field("trust_ready", &self.trust_ready)
            .finish_non_exhaustive()
    }
}

/// The library's text of `rc`, as C's `%s` prints it.
pub(crate) fn strerror<G: Gnutls>(lib: &G, rc: Rc) -> Text<'static> {
    Text(lib.strerror(rc))
}
