//! What the session asks of mbedTLS, one method per call of the library's
//! that `lib/vtls/mbedtls.c` makes, so that the order of the calls, and
//! what is made of each answer, is this crate's safe code (`session.rs`,
//! `verify.rs`). The library itself is `mbedtls.rs`; the tests give a
//! scripted one.
//!
//! A call that may read or write the connection is given the `Call` of
//! the session's call under way, which its callbacks reach: the BIO's
//! send and receive (C's `mbedtls_bio_cf_write`, `mbedtls_bio_cf_read`)
//! and the verify callback (`mbed_verify_cb`).

use core::ffi::CStr;
use core::fmt;

use curl_alloc::{OutOfMemory, TryArc};
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::tls::{Text, TlsIo};

use crate::sys;

/// `CURLE_AGAIN`, as the trace numbers a call that would block.
pub(crate) const AGAIN: u16 = 81;

/// A number the library answers with: 0 or more, a success (for some
/// calls a count), less than 0, one of its `MBEDTLS_ERR_*` errors.
pub(crate) type Rc = i32;

/// The library's words for a number or for a certificate's flags, as C
/// reads them into a buffer of 128 bytes (`errorbuf`).
#[derive(Clone, Copy)]
pub(crate) struct Words {
    buf: [u8; 128],
    len: usize,
}

impl Words {
    /// The first 127 bytes of `bytes`, as the library writes them into
    /// 128 with their zero byte.
    pub(crate) fn new(bytes: &[u8]) -> Words {
        let mut buf = [0; 128];
        let len = bytes.len().min(buf.len() - 1);
        buf[..len].copy_from_slice(&bytes[..len]);
        Words { buf, len }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl fmt::Display for Words {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Text(self.bytes()).fmt(f)
    }
}

impl fmt::Debug for Words {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Words({self})")
    }
}

/// A number as C's `-0x%04X` of `(unsigned int)-ret` shows it.
pub(crate) struct Hex(pub(crate) Rc);

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "-0x{:04X}", self.0.cast_unsigned().wrapping_neg())
    }
}

/// A number as C's `-0x%x` of `(unsigned int)-ret` shows it.
pub(crate) struct LowHex(pub(crate) Rc);

impl fmt::Display for LowHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "-0x{:x}", self.0.cast_unsigned().wrapping_neg())
    }
}

/// mbedTLS: what it makes, and what it says of a number.
pub(crate) trait Mbedtls: Explain + Sync + 'static {
    /// The library's random numbers, shared by every connection.
    type Rng: Send + Sync + 'static;
    type Conn: Conn;

    /// The random number generator, seeded, as `mbedtls_init` makes it:
    /// entropy, a CTR-DRBG seeded from it, and prediction resistance on.
    /// `Err` with the library's number if the seeding fails.
    fn rng(&self) -> Result<Self::Rng, Rc>;

    /// One connection's objects, each initialised and none set up: the
    /// context, the configuration, the CA chain, the client's certificate,
    /// its key and the revocation list (`mbedtls_ssl_init`,
    /// `mbedtls_ssl_config_init`, `mbedtls_x509_crt_init`, ...), drawing
    /// on `rng`.
    fn conn(&self, rng: &TryArc<Self::Rng>) -> Result<Self::Conn, OutOfMemory>;

    /// The text of `rc` (`mbedtls_strerror`).
    fn strerror(&self, rc: Rc) -> Words;

    /// The suites the library has, by number, in its order of preference
    /// (`mbedtls_ssl_list_ciphersuites`).
    fn suites(&self) -> &'static [i32];

    /// The library's name of suite `id` (`mbedtls_ssl_get_ciphersuite_name`).
    fn suite_name(&self, id: i32) -> &'static [u8];

    /// The DER of the public key of the certificate `der`, as
    /// `mbed_connect_step2` writes it, copying the certificate first.
    fn public_key(&self, der: &[u8]) -> Result<Vec<u8>, KeyCopy>;
}

/// What the verify callback asks of the library.
pub(crate) trait Explain {
    /// The library's words for a certificate's flags
    /// (`mbedtls_x509_crt_verify_info`, no prefix).
    fn verify_info(&self, flags: u32) -> Words;
}

/// Where copying the peer's public key failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyCopy {
    /// No room for the copy or the key.
    OutOfMemory,
    /// The certificate would not parse again (`mbedtls_x509_crt_parse_der`).
    Certificate,
    /// The key would not be written (`mbedtls_pk_write_pubkey_der`).
    Key,
}

/// What a resumed session came to (`mbedtls_ssl_session_load`, then
/// `mbedtls_ssl_set_session`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resume {
    Done,
    /// It would not load.
    Load(Rc),
    /// It loaded and would not be set.
    Set(Rc),
}

/// The session the connection has, saved (`mbedtls_ssl_get_session`, then
/// `mbedtls_ssl_session_save` twice: for its length, then its bytes).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Saved {
    Data(Vec<u8>),
    /// It could not be got.
    GetFailed(Rc),
    /// It saves to nothing.
    Empty,
    /// It would not be saved.
    SaveFailed(Rc),
}

/// One connection's objects, the library's calls on them. The
/// configuration points at the others, which live as long as it.
pub(crate) trait Conn: Send {
    /// `mbedtls_x509_crt_parse` into the CA chain.
    fn ca_parse(&mut self, data: &[u8]) -> Rc;
    /// `mbedtls_x509_crt_parse_file` into the CA chain.
    fn ca_parse_file(&mut self, file: &CStr) -> Rc;
    /// `mbedtls_x509_crt_parse_path` into the CA chain.
    fn ca_parse_path(&mut self, dir: &CStr) -> Rc;
    /// `mbedtls_x509_crt_parse_file` into the client's certificate.
    fn cert_parse_file(&mut self, file: &CStr) -> Rc;
    /// `mbedtls_x509_crt_parse` into the client's certificate.
    fn cert_parse(&mut self, data: &[u8]) -> Rc;
    /// `mbedtls_pk_parse_keyfile`, with the RNG.
    fn key_parse_file(&mut self, file: &CStr, password: Option<&CStr>) -> Rc;
    /// `mbedtls_pk_parse_key`, with the RNG.
    fn key_parse(&mut self, key: &[u8], password: Option<&[u8]>) -> Rc;
    /// The key signs as TLS needs (`mbedtls_pk_can_do` of RSA or EC).
    fn key_signs(&self) -> bool;
    /// `mbedtls_x509_crl_parse_file`.
    fn crl_parse_file(&mut self, file: &CStr) -> Rc;

    /// `mbedtls_ssl_config_defaults` for a client over a stream, the
    /// default preset.
    fn defaults(&mut self) -> Rc;
    /// `mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets`, where
    /// the library has it (3.6.1 and later): TLS 1.3's tickets told of.
    fn signal_tickets(&mut self);
    /// `mbedtls_ssl_conf_verify`: the peer's chain reaches
    /// `Call::verify`.
    fn verify_hook(&mut self);
    /// `mbedtls_ssl_conf_authmode`, required.
    fn verify_required(&mut self);
    /// `mbedtls_ssl_conf_cert_profile`, `mbedtls_x509_crt_profile_next`.
    fn profile_next(&mut self);
    /// `mbedtls_ssl_conf_min_tls_version` and `..._max_...`, the
    /// library's numbers.
    fn versions(&mut self, min: i32, max: i32);
    /// `mbedtls_ssl_conf_rng`, the CTR-DRBG.
    fn use_rng(&mut self);
    /// `mbedtls_ssl_setup`.
    fn setup(&mut self) -> Rc;
    /// `mbedtls_ssl_set_bio`: the connection's bytes go through
    /// `Call::send` and `Call::recv`.
    fn bio(&mut self);
    /// `mbedtls_ssl_conf_ciphersuites` of `suites`, which the connection
    /// keeps, as the library does not copy them.
    fn ciphersuites(&mut self, suites: Vec<i32>) -> Result<(), OutOfMemory>;
    /// `mbedtls_ssl_conf_ciphersuites` of the library's own list.
    fn default_ciphersuites(&mut self);
    /// `mbedtls_ssl_conf_renegotiation`, enabled.
    fn renegotiation(&mut self);
    /// `mbedtls_ssl_conf_session_tickets`, disabled.
    fn tickets_off(&mut self);
    /// Resume the session `data` saved (`mbedtls_ssl_session_load`,
    /// `mbedtls_ssl_set_session`).
    fn resume(&mut self, data: &[u8]) -> Resume;
    /// `mbedtls_ssl_conf_ca_chain`: the CA chain and the revocation list.
    fn ca_chain(&mut self);
    /// `mbedtls_ssl_conf_own_cert`: the client's certificate and key.
    fn own_cert(&mut self);
    /// `mbedtls_ssl_set_hostname`.
    fn hostname(&mut self, name: &CStr) -> Rc;
    /// `mbedtls_ssl_conf_alpn_protocols` of `names`, which the connection
    /// keeps, as the library does not copy them.
    fn alpn(&mut self, names: &[&[u8]]) -> Result<Rc, OutOfMemory>;
    /// The configuration and the context, for the application's turn
    /// at them (`CURLOPT_SSL_CTX_FUNCTION`).
    fn configured(&self) -> curl_core::tls::TlsNative;
    /// The context, as both the session and the context, for the
    /// application (`CURLINFO_TLS_SSL_PTR`).
    fn native(&self) -> curl_core::tls::TlsNative;

    /// `mbedtls_ssl_handshake`.
    fn handshake(&mut self, call: &mut Call<'_, '_>) -> Rc;
    /// `mbedtls_ssl_read`: a count, or an error.
    fn read(&mut self, call: &mut Call<'_, '_>, buf: &mut [u8]) -> Rc;
    /// `mbedtls_ssl_write`: a count, or an error.
    fn write(&mut self, call: &mut Call<'_, '_>, bytes: &[u8]) -> Rc;
    /// `mbedtls_ssl_close_notify`.
    fn close_notify(&mut self, call: &mut Call<'_, '_>) -> Rc;

    /// `mbedtls_ssl_get_ciphersuite_id_from_ssl`.
    fn suite(&self) -> i32;
    /// `mbedtls_ssl_get_version`.
    fn version_name(&self) -> &'static [u8];
    /// `mbedtls_ssl_get_version_number`: the wire's number.
    fn version(&self) -> i32;
    /// `mbedtls_ssl_get_alpn_protocol`, none if none.
    fn alpn_selected(&self) -> Option<&[u8]>;
    /// The DER of the peer's certificate (`mbedtls_ssl_get_peer_cert`'s
    /// `raw`), none if it has none or it is empty.
    fn peer_cert(&self) -> Option<&[u8]>;
    /// The session to resume, saved.
    fn saved(&mut self) -> Result<Saved, OutOfMemory>;
    /// `mbedtls_ssl_get_bytes_avail` is not 0.
    fn pending(&self) -> bool;
}

/// The chain the library hands the verify callback.
pub(crate) trait Chain {
    /// The certificate as text (`mbedtls_x509_crt_info` into 16384 bytes,
    /// each line after a space), none if that fails or there is no room.
    fn info(&self) -> Option<Vec<u8>>;
    /// The DER of this certificate and of those after it, at most `most`.
    fn ders(&self, most: usize) -> Result<Vec<&[u8]>, OutOfMemory>;
}

/// What a send or receive answers the library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Moved {
    /// This many bytes; 0 for a receive, the connection's end.
    Bytes(usize),
    /// None, as it would have blocked (`MBEDTLS_ERR_SSL_WANT_*`).
    Again,
    /// None, as it failed (-1).
    Failed,
}

impl Moved {
    /// The number C's BIO answers: a count, `want` or -1.
    pub(crate) fn rc(self, want: Rc) -> Rc {
        match self {
            Moved::Bytes(n) => Rc::try_from(n).expect("no more than the library asked"),
            Moved::Again => want,
            Moved::Failed => -1,
        }
    }
}

/// What the callbacks of one call into the library reach.
pub(crate) struct Call<'s, 'a> {
    pub(crate) io: &'s mut TlsIo<'a>,
    /// The checks of the peer that are on: what the verify callback
    /// clears the flags of the others of.
    pub(crate) verify_peer: bool,
    pub(crate) verify_host: bool,
    pub(crate) explain: &'s dyn Explain,
}

impl Call<'_, '_> {
    /// The library writes `bytes` (`mbedtls_bio_cf_write`).
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
        self.io.trace(format_args!(
            "mbedtls_bio_cf_out_write(len={len}) -> {code}, {n}"
        ));
        moved
    }

    /// The library reads into `buf` (`mbedtls_bio_cf_read`).
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
        self.io.trace(format_args!(
            "mbedtls_bio_cf_in_read(len={len}) -> {code}, {n}"
        ));
        moved
    }

    /// The library checked the certificate at `depth` of the peer's
    /// chain, `chain` from it on, and found `flags` wrong
    /// (`mbed_verify_cb`): the leaf told of, the flags of the checks that
    /// are off cleared, and what is left said. The handshake goes on to
    /// fail if any is left.
    pub(crate) fn verify(&mut self, depth: i32, chain: &dyn Chain, flags: &mut u32) {
        if depth == 0 {
            if self.io.verbose() {
                crate::verify::dump(self.io, chain);
            }
            if self.io.wants_certinfo() {
                crate::verify::certinfo(self.io, chain);
            }
        }
        // `verifypeer` and `verifyhost` are independent: the name's
        // mismatch is `verifyhost`'s alone.
        if !self.verify_peer {
            *flags &= sys::MBEDTLS_X509_BADCERT_CN_MISMATCH;
        }
        if !self.verify_host {
            *flags &= !sys::MBEDTLS_X509_BADCERT_CN_MISMATCH;
        }
        if *flags != 0 {
            let words = self.explain.verify_info(*flags);
            self.io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("mbedTLS: {words}"),
            );
        }
    }
}

impl fmt::Debug for Call<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call")
            .field("verify_peer", &self.verify_peer)
            .field("verify_host", &self.verify_host)
            .finish_non_exhaustive()
    }
}

pub(crate) use curl_core::tls::{as_c, c_string};
