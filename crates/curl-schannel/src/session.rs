//! One connection's Schannel (`lib/vtls/schannel.c`): the credential,
//! found in the transfer's cache or made (`schannel_acquire_credential_handle`),
//! the handshake in C's three steps (`schannel_connect_step1` to `_step3`),
//! the records both ways (`schannel_recv`, `schannel_send`), the
//! renegotiation a peer asks for as it sends (`schannel_recv_renegotiate`)
//! and the goodbye (`schannel_shutdown`).
//!
//! Where C blocks on the socket (a record sent whole, a renegotiation
//! waiting in the direction its caller does not), this session says what
//! it waits for and is called again: the bytes on the wire are the same.

use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::{SslOptions, TlsMaxVersion, TlsMinVersion};
use curl_core::time::Instant;
use curl_core::tls::{
    Alpn, BindingNotes, Chosen, Goodbye, Handshake, TlsCx, TlsIdentity, TlsIo, TlsKind, TlsNative,
    TlsPeer, TlsPeerKind, TlsSession, TlsShared, TlsWait,
};
use curl_os::error::ErrorText;

use crate::client;
use crate::close::{Flushed, Pending, Record};
use crate::sspi::{
    self, Context, CredKind, CredSpec, Credentials, StreamSizes, cred, protocol, req, status,
};
use crate::text::Text;
use crate::verify;

/// The room the buffers start with, and keep free at least
/// (`CURL_SCHANNEL_BUFFER_INIT_SIZE`, `CURL_SCHANNEL_BUFFER_FREE_SIZE`).
const INIT_SIZE: usize = 4096;
const FREE_SIZE: usize = 1024;
/// The longest a renegotiation may take (`MAX_RENEG_BLOCK_TIME`).
const RENEG_MOST: std::time::Duration = std::time::Duration::from_secs(60);
/// The most certificates a peer's chain is reported with
/// (`MAX_ALLOWED_CERT_AMOUNT`).
const MOST_CERTS: usize = 100;

/// A credential the transfer's cache keeps for its peer, which the
/// connections to it share (`Curl_schannel_cred`): Schannel resumes the
/// sessions it keeps for one. The last holder frees it.
pub(crate) struct Cred {
    creds: Credentials,
    /// The name the handshakes are made for (SNI), UTF-16 ended by a
    /// zero.
    sni: Vec<u16>,
}

/// What a session waits for on the socket (`io_need`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Need {
    None,
    Recv,
    Send,
}

/// How far a handshake has come (`connecting_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    One,
    Two,
    Three,
    Done,
}

/// What a receive came to so far (`result` in `schannel_recv`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Res {
    Ok,
    Again,
    Err(ErrorKind),
}

/// The goodbye's token and how much of it went.
type CloseNotify = Pending<sspi::Token>;

impl Record for sspi::Token {
    fn bytes(&self) -> &[u8] {
        sspi::Token::bytes(self)
    }
}

pub(crate) struct Session {
    identity: TryArc<TlsIdentity>,
    shared: TlsShared,
    /// The origin's name as the URL gives it, an IPv6 address without
    /// its brackets.
    host: Vec<u8>,
    port: u16,
    kind: TlsPeerKind,
    alpn: Alpn,
    step: Step,
    /// The handshake is done (`ssl_connection_complete`).
    complete: bool,
    // The context before the credential it was made with.
    ctx: Option<Context>,
    cred: Option<TryArc<Cred>>,
    req: u32,
    ret: u32,
    use_alpn: bool,
    /// The peer is checked here, not by Schannel: against a CA file or
    /// blob (`use_manual_cred_validation`).
    manual: bool,
    /// What the peer sent, not yet decrypted: `enc_off` bytes of room
    /// `enc.len()`.
    enc: Vec<u8>,
    enc_off: usize,
    enc_incomplete: bool,
    /// What was decrypted, not yet given out.
    dec: Vec<u8>,
    dec_off: usize,
    sizes: StreamSizes,
    send_buf: Vec<u8>,
    /// A record encrypted and not sent whole: its length, how much went,
    /// and the plaintext it carries, reported once it is all sent.
    sending: Option<(usize, usize, usize)>,
    need: Need,
    recv_err: Option<ErrorKind>,
    close_notify: bool,
    closed: bool,
    renegotiating: bool,
    /// A renegotiation under way: when it started and what it waits for.
    reneg: Option<(Instant, Need)>,
    /// What ALPN agreed (`negotiated.alpn`).
    negotiated: Option<Vec<u8>>,
    goodbye: Option<CloseNotify>,
    goodbye_made: bool,
    goodbye_sent: bool,
    /// The goodbye is over or failed (`cf->shutdown`).
    shut: bool,
}

impl Session {
    pub(crate) fn new(
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        shared: &TlsShared,
    ) -> Result<Session, ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(peer.name).map_err(oom)?;
        Ok(Session {
            identity: identity.clone(),
            shared: shared.clone(),
            host,
            port: peer.port,
            kind: peer.kind,
            alpn,
            step: Step::One,
            complete: false,
            ctx: None,
            cred: None,
            req: 0,
            ret: 0,
            use_alpn: false,
            manual: false,
            enc: Vec::new(),
            enc_off: 0,
            enc_incomplete: false,
            dec: Vec::new(),
            dec_off: 0,
            sizes: StreamSizes::default(),
            send_buf: Vec::new(),
            sending: None,
            need: Need::None,
            recv_err: None,
            close_notify: false,
            closed: false,
            renegotiating: false,
            reneg: None,
            negotiated: None,
            goodbye: None,
            goodbye_made: false,
            goodbye_sent: false,
            shut: false,
        })
    }
}

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}

/// `bytes` as UTF-16 ended by a zero, as `curlx_convert_UTF8_to_tchar`
/// makes a wide name: bytes that are not UTF-8 each as the character of
/// its number.
pub(crate) fn wide(bytes: &[u8]) -> Result<Vec<u16>, OutOfMemory> {
    let mut w = Vec::new();
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().encode_utf16() {
            w.try_push(c)?;
        }
        for &b in chunk.invalid() {
            w.try_push(u16::from(b))?;
        }
    }
    w.try_push(0)?;
    Ok(w)
}

/// Room for `min` bytes in `buf`, and `FREE_SIZE` past `used` at least
/// (`ensure_encoding_size`).
fn ensure_encoding(buf: &mut Vec<u8>, used: usize, min: usize) -> Result<(), OutOfMemory> {
    if buf.len() - used < FREE_SIZE || buf.len() < min {
        let len = (used + FREE_SIZE).max(min);
        buf.try_resize(len, 0)?;
    }
    Ok(())
}

/// Room for `now` bytes more past `used`, at least `FREE_SIZE`, and `len`
/// in all (`ensure_decoding_size`).
fn ensure_decoding(
    buf: &mut Vec<u8>,
    used: usize,
    now: usize,
    len: usize,
) -> Result<(), OutOfMemory> {
    let size = now.max(FREE_SIZE);
    if buf.len() - used < size || buf.len() < len {
        let length = (used + size).max(len);
        buf.try_resize(length, 0)?;
    }
    Ok(())
}

/// The protocols a credential enables for the versions the identity
/// allows (`schannel_set_ssl_version_min_max`).
fn protocols(identity: &TlsIdentity, cx: &mut TlsCx<'_>) -> Result<u32, ErrorKind> {
    let tls13 = tls13_built_in();
    // C's numbers for the versions, which it counts through.
    let min = match identity.options.min_version {
        TlsMinVersion::Tls1 => 1,
        TlsMinVersion::Tls1_0 => 4,
        TlsMinVersion::Tls1_1 => 5,
        TlsMinVersion::Tls1_2 => 6,
        TlsMinVersion::Tls1_3 => 7,
    };
    let max = match identity.options.max_version {
        TlsMaxVersion::None | TlsMaxVersion::Default => {
            if tls13 {
                7
            } else {
                6
            }
        }
        TlsMaxVersion::Tls1_0 => 4,
        TlsMaxVersion::Tls1_1 => 5,
        TlsMaxVersion::Tls1_2 => 6,
        TlsMaxVersion::Tls1_3 => 7,
    };
    let mut enabled = 0;
    for i in min..=max {
        match i {
            4 => enabled |= protocol::TLS1_0,
            5 => enabled |= protocol::TLS1_1,
            6 => enabled |= protocol::TLS1_2,
            7 if tls13 => enabled |= protocol::TLS1_3,
            7 => {
                return Err(cx.fail(
                    ErrorKind::SslConnectError,
                    format_args!("schannel: TLS 1.3 not supported on Windows 10 or older"),
                ));
            }
            _ => {}
        }
    }
    Ok(enabled)
}

/// Schannel speaks TLS 1.3: Windows Server 2022 and Windows 11, build
/// 20348 and later.
fn tls13_built_in() -> bool {
    let (major, minor, build) = sspi::windows_version();
    (major, minor, build) >= (10, 0, 20348)
}

/// The algorithms of a cipher list (`set_ssl_ciphers`): each a number
/// or a `CALG_` name, `USE_STRONG_CRYPTO` setting that flag; `None` for
/// one it does not know.
fn algorithms(list: &[u8], flags: &mut u32) -> Option<Vec<u32>> {
    let mut algs = Vec::new();
    let mut rest = Some(list);
    while let Some(cur) = rest.filter(|c| !c.is_empty() && c[0] != 0) {
        if algs.len() >= crate::algs::MOST {
            break;
        }
        let alg = crate::algs::number(cur)
            .filter(|&n| n != 0)
            .or_else(|| crate::algs::named(cur));
        match alg {
            Some(alg) => algs.try_push(alg).ok()?,
            None if cur.starts_with(b"USE_STRONG_CRYPTO")
                || cur.starts_with(b"SCH_USE_STRONG_CRYPTO") =>
            {
                *flags |= cred::USE_STRONG_CRYPTO;
            }
            None => return None,
        }
        rest = cur.iter().position(|&b| b == b':').map(|at| &cur[at + 1..]);
    }
    Some(algs)
}

impl Session {
    fn say_debug(io: &mut TlsCx<'_>, line: std::fmt::Arguments<'_>) {
        io.debug_info(line);
    }

    /// A credential made for the connection (`schannel_acquire_credential_handle`).
    fn acquire(&mut self, io: &mut TlsIo<'_>) -> Result<TryArc<Cred>, ErrorKind> {
        let identity = self.identity.clone();
        let o = &identity.options;
        let mut flags;
        if identity.verify_peer {
            flags = if self.manual {
                cred::MANUAL_CRED_VALIDATION
            } else {
                cred::AUTO_CRED_VALIDATION
            };
            if o.ssl_options.contains(SslOptions::NO_REVOKE) {
                flags |= cred::IGNORE_NO_REVOCATION_CHECK | cred::IGNORE_REVOCATION_OFFLINE;
                Self::say_debug(
                    io,
                    format_args!("schannel: disabled server certificate revocation checks"),
                );
            } else if o.ssl_options.contains(SslOptions::REVOKE_BEST_EFFORT) {
                flags |= cred::IGNORE_NO_REVOCATION_CHECK
                    | cred::IGNORE_REVOCATION_OFFLINE
                    | cred::REVOCATION_CHECK_CHAIN;
                Self::say_debug(
                    io,
                    format_args!("schannel: ignore revocation offline errors"),
                );
            } else {
                flags |= cred::REVOCATION_CHECK_CHAIN;
                Self::say_debug(
                    io,
                    format_args!("schannel: checking server certificate revocation"),
                );
            }
        } else {
            flags = cred::MANUAL_CRED_VALIDATION
                | cred::IGNORE_NO_REVOCATION_CHECK
                | cred::IGNORE_REVOCATION_OFFLINE;
            Self::say_debug(
                io,
                format_args!("schannel: disabled server cert revocation checks"),
            );
        }
        if !identity.verify_host {
            flags |= cred::NO_SERVERNAME_CHECK;
            Self::say_debug(
                io,
                format_args!(
                    "schannel: verifyhost setting prevents Schannel from comparing the supplied target name with the subject names in server certificates."
                ),
            );
        }
        if !o.ssl_options.contains(SslOptions::AUTO_CLIENT_CERT) {
            flags &= !cred::USE_DEFAULT_CREDS;
            flags |= cred::NO_DEFAULT_CREDS;
            io.info(format_args!(
                "schannel: disabled automatic use of client certificate"
            ));
        } else {
            io.info(format_args!(
                "schannel: enabled automatic use of client certificate"
            ));
        }
        let enabled = protocols(&identity, io)?;
        let (store, client) = client::certificate(&identity, io)?;
        let modern = o.ciphers.is_none() && tls13_built_in();
        let algs;
        let kind = if modern {
            flags |= cred::USE_STRONG_CRYPTO;
            CredKind::Modern
        } else {
            match &o.ciphers {
                Some(list) => {
                    if enabled & protocol::TLS1_3 != 0 {
                        if enabled & !protocol::TLS1_3 == 0 {
                            return Err(io.fail(
                                ErrorKind::SslConnectError,
                                format_args!(
                                    "schannel: TLS 1.3 is not supported with a cipher list; remove the cipher list or allow a lower TLS version"
                                ),
                            ));
                        }
                        io.info(format_args!(
                            "schannel: WARNING: This version of Schannel negotiates a less-secure TLS version than TLS 1.3 because the user set an algorithm cipher list."
                        ));
                    }
                    algs = match algorithms(list, &mut flags) {
                        Some(a) => a,
                        None => {
                            return Err(io.fail(
                                ErrorKind::SslCipher,
                                format_args!("schannel: Failed setting algorithm cipher list"),
                            ));
                        }
                    };
                    CredKind::Legacy { algs: Some(&algs) }
                }
                None => {
                    flags |= cred::USE_STRONG_CRYPTO;
                    CredKind::Legacy { algs: None }
                }
            }
        };
        let spec = CredSpec {
            flags,
            protocols: enabled,
            client: client.as_ref(),
            kind,
        };
        let creds = match Credentials::acquire(&spec, store) {
            Ok(c) => c,
            Err(st) => {
                let kind = if st == status::INSUFFICIENT_MEMORY {
                    ErrorKind::OutOfMemory
                } else {
                    ErrorKind::SslConnectError
                };
                let why = ErrorText::sspi(st);
                return Err(io.fail(
                    kind,
                    format_args!(
                        "schannel: AcquireCredentialsHandle failed: {}",
                        Text(why.as_bytes())
                    ),
                ));
            }
        };
        drop(client);
        // The name SNI sends, C's `peer.sni`, else the host as given.
        let sni_host = match self.kind {
            TlsPeerKind::Name => self.host.strip_suffix(b".").unwrap_or(&self.host),
            TlsPeerKind::Ipv4 | TlsPeerKind::Ipv6 => &self.host,
        };
        let sni = wide(sni_host).map_err(oom)?;
        TryArc::try_new(Cred { creds, sni }).map_err(oom)
    }

    /// The ALPN extension SSPI is handed (the `alpn_buffer` of
    /// `schannel_connect_step1`).
    fn alpn_extension(&self) -> Result<Vec<u8>, OutOfMemory> {
        let list = self.alpn.wire();
        let list_len = u16::try_from(list.len()).expect("a short list");
        let ext_len = u32::from(list_len) + 4 + 2;
        let mut b = Vec::new();
        b.try_extend_from_slice(&ext_len.to_le_bytes())?;
        // `SecApplicationProtocolNegotiationExt_ALPN`.
        b.try_extend_from_slice(&2u32.to_le_bytes())?;
        b.try_extend_from_slice(&list_len.to_le_bytes())?;
        b.try_extend_from_slice(list)?;
        Ok(b)
    }

    /// `schannel_connect_step1`.
    fn step1(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        let host = Text(&self.host);
        let port = self.port;
        Self::say_debug(
            io,
            format_args!("schannel: SSL/TLS connection with {host} port {port} (step 1/3)"),
        );
        self.use_alpn = !self.alpn.wire().is_empty();
        self.manual = self.identity.ca_file().is_some() || self.identity.ca_blob().is_some();
        self.cred = None;
        if io.caches_sessions()
            && let Some(old) = io.session_object::<TryArc<Cred>>()
        {
            Self::say_debug(
                io,
                format_args!("schannel: reusing existing credential handle"),
            );
            let n = TryArc::count(&old);
            Self::say_debug(
                io,
                format_args!("schannel: incremented credential handle refcount = {n}"),
            );
            self.cred = Some(old);
        }
        if self.cred.is_none() {
            self.cred = Some(self.acquire(io)?);
        }
        if self.kind != TlsPeerKind::Name {
            io.info(format_args!(
                "schannel: using IP address, SNI is not supported by OS."
            ));
        }
        let mut ext = Vec::new();
        if self.use_alpn {
            ext = self.alpn_extension().map_err(oom)?;
            if let Some(offer) = self.alpn.offer() {
                io.info(format_args!("ALPN: curl offers {offer}"));
            }
        }
        self.req = req::SEQUENCE_DETECT
            | req::REPLAY_DETECT
            | req::CONFIDENTIALITY
            | req::ALLOCATE_MEMORY
            | req::STREAM
            | if self
                .identity
                .options
                .ssl_options
                .contains(SslOptions::AUTO_CLIENT_CERT)
            {
                0
            } else {
                req::USE_SUPPLIED_CREDS
            };
        let cred = self.cred.as_ref().expect("found or made above");
        let first = sspi::start(
            &cred.creds,
            &cred.sni,
            self.req,
            self.use_alpn.then_some(&mut ext[..]),
        )
        .map_err(|OutOfMemory| {
            io.fail(
                ErrorKind::OutOfMemory,
                format_args!("schannel: unable to allocate memory"),
            )
        })?;
        self.ret = first.attrs;
        if first.status != status::CONTINUE_NEEDED {
            let why = ErrorText::sspi(first.status);
            let why = Text(why.as_bytes());
            return Err(match first.status {
                status::INSUFFICIENT_MEMORY => io.fail(
                    ErrorKind::OutOfMemory,
                    format_args!("schannel: initial InitializeSecurityContext failed: {why}"),
                ),
                status::WRONG_PRINCIPAL => io.fail(
                    ErrorKind::PeerFailedVerification,
                    format_args!("schannel: SNI or certificate check failed: {why}"),
                ),
                _ => io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("schannel: initial InitializeSecurityContext failed: {why}"),
                ),
            });
        }
        self.ctx = first.context;
        let token = first.token;
        let bytes = token.as_ref().map_or(&[][..], |t| t.bytes());
        let len = bytes.len();
        Self::say_debug(
            io,
            format_args!("schannel: sending initial handshake data: sending {len} bytes."),
        );
        let written = send_once(io, bytes);
        if written != Some(len) {
            let n = written.unwrap_or(0);
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!(
                    "schannel: failed to send initial handshake data: sent {n} of {len} bytes"
                ),
            ));
        }
        Self::say_debug(
            io,
            format_args!("schannel: sent initial handshake data: sent {len} bytes"),
        );
        self.recv_err = None;
        self.close_notify = false;
        self.closed = false;
        self.renegotiating = false;
        self.reneg = None;
        self.enc_incomplete = false;
        self.goodbye_made = false;
        self.goodbye = None;
        self.step = Step::Two;
        Ok(())
    }

    /// `schannel_error`: why a later `InitializeSecurityContext` failed.
    fn isc_error(io: &mut TlsCx<'_>, st: i32) -> ErrorKind {
        let why = ErrorText::sspi(st);
        let why = Text(why.as_bytes());
        match st {
            status::INSUFFICIENT_MEMORY => io.fail(
                ErrorKind::OutOfMemory,
                format_args!("schannel: next InitializeSecurityContext failed: {why}"),
            ),
            status::WRONG_PRINCIPAL => io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("schannel: SNI or certificate check failed: {why}"),
            ),
            status::UNTRUSTED_ROOT => io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("schannel: {why}"),
            ),
            _ => io.fail(
                ErrorKind::SslConnectError,
                format_args!("schannel: next InitializeSecurityContext failed: {why}"),
            ),
        }
    }

    /// `schannel_connect_step2`.
    fn step2(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        let mut doread = self.need != Need::Send;
        self.need = Need::None;
        let host = Text(&self.host);
        let port = self.port;
        Self::say_debug(
            io,
            format_args!("schannel: SSL/TLS connection with {host} port {port} (step 2/3)"),
        );
        if self.cred.is_none() || self.ctx.is_none() {
            return Err(ErrorKind::SslConnectError);
        }
        if self.dec.is_empty() {
            self.dec_off = 0;
            self.dec.try_resize(INIT_SIZE, 0).map_err(|OutOfMemory| {
                io.fail(
                    ErrorKind::OutOfMemory,
                    format_args!("schannel: unable to allocate memory"),
                )
            })?;
        }
        if self.enc.is_empty() {
            self.enc_incomplete = false;
            self.enc_off = 0;
            self.enc.try_resize(INIT_SIZE, 0).map_err(|OutOfMemory| {
                io.fail(
                    ErrorKind::OutOfMemory,
                    format_args!("schannel: unable to allocate memory"),
                )
            })?;
        }
        self.ensure_enc(io, 0)?;
        let mut st;
        loop {
            if doread {
                match io.recv(&mut self.enc[self.enc_off..]) {
                    Ok(Recv::WouldBlock) => {
                        if self.enc_off == 0 || self.enc_incomplete {
                            self.need = Need::Recv;
                            Self::say_debug(
                                io,
                                format_args!(
                                    "schannel: failed to receive handshake, need more data"
                                ),
                            );
                            return Ok(());
                        }
                        Self::say_debug(
                            io,
                            format_args!(
                                "schannel: no new handshake data received, continuing to process existing handshake data"
                            ),
                        );
                    }
                    Ok(Recv::Data(n)) => {
                        self.enc_off += n.get();
                        self.enc_incomplete = false;
                    }
                    Ok(Recv::Eof) | Err(_) => {
                        return Err(io.fail(
                            ErrorKind::SslConnectError,
                            format_args!(
                                "schannel: failed to receive handshake, SSL/TLS connection failed"
                            ),
                        ));
                    }
                }
            }
            let mut input = Vec::new();
            input
                .try_extend_from_slice(&self.enc[..self.enc_off])
                .map_err(|OutOfMemory| {
                    io.fail(
                        ErrorKind::OutOfMemory,
                        format_args!("schannel: unable to allocate memory"),
                    )
                })?;
            let cred = self.cred.as_ref().expect("checked above");
            let ctx = self.ctx.as_mut().expect("checked above");
            let next = ctx.next(&cred.creds, &cred.sni, self.req, &mut input);
            drop(input);
            self.ret = next.attrs;
            st = next.status;
            match st {
                status::INCOMPLETE_MESSAGE => {
                    self.enc_incomplete = true;
                    self.need = Need::Recv;
                    Self::say_debug(
                        io,
                        format_args!("schannel: received incomplete message, need more data"),
                    );
                    return Ok(());
                }
                status::CONTINUE_NEEDED | status::OK => {
                    let mut failed = false;
                    for token in next.tokens.iter().flatten() {
                        let bytes = token.bytes();
                        if bytes.is_empty() {
                            continue;
                        }
                        let len = bytes.len();
                        Self::say_debug(
                            io,
                            format_args!(
                                "schannel: sending next handshake data: sending {len} bytes."
                            ),
                        );
                        let written = send_once(io, bytes);
                        if written != Some(len) {
                            let n = written.unwrap_or(0);
                            io.fail(
                                ErrorKind::SslConnectError,
                                format_args!(
                                    "schannel: failed to send next handshake data: sent {n} of {len} bytes"
                                ),
                            );
                            failed = true;
                        }
                    }
                    drop(next.tokens);
                    if failed {
                        return Err(ErrorKind::SslConnectError);
                    }
                }
                status::INCOMPLETE_CREDENTIALS if self.req & req::USE_SUPPLIED_CREDS == 0 => {
                    // The server asked for a client certificate: go on
                    // without one, as servers that ask and do not need
                    // one allow.
                    self.req |= req::USE_SUPPLIED_CREDS;
                    self.need = Need::Send;
                    Self::say_debug(
                        io,
                        format_args!("schannel: a client certificate has been requested"),
                    );
                    return Ok(());
                }
                _ => return Err(Self::isc_error(io, st)),
            }
            if let Some(extra) = next.extra {
                if self.enc_off > extra {
                    self.enc.copy_within(self.enc_off - extra..self.enc_off, 0);
                    self.enc_off = extra;
                    if st == status::CONTINUE_NEEDED {
                        doread = false;
                        continue;
                    }
                }
            } else {
                self.enc_off = 0;
            }
            break;
        }
        if st == status::CONTINUE_NEEDED {
            self.need = Need::Recv;
            return Ok(());
        }
        if st == status::OK {
            self.step = Step::Three;
            Self::say_debug(io, format_args!("schannel: SSL/TLS handshake complete"));
        }
        if let Some(pinned) = self.identity.options.pinned_key.as_deref() {
            let ctx = self.ctx.as_ref().expect("checked above");
            if let Err(kind) = verify::pin(io, ctx, pinned) {
                io.fail(
                    kind,
                    format_args!("SSL: public key does not match pinned public key"),
                );
                return Err(kind);
            }
        }
        let ctx = self.ctx.as_ref().expect("checked above");
        if self.identity.verify_peer && self.manual {
            return verify::certificate(io, ctx, &self.identity, &self.shared, &self.host, true);
        }
        if !self.identity.verify_peer && self.identity.verify_host {
            return verify::host(io, ctx, &self.host);
        }
        Ok(())
    }

    fn ensure_enc(&mut self, io: &mut TlsCx<'_>, min: usize) -> Result<(), ErrorKind> {
        ensure_encoding(&mut self.enc, self.enc_off, min).map_err(|OutOfMemory| {
            io.fail(
                ErrorKind::OutOfMemory,
                format_args!("schannel: unable to re-allocate memory"),
            )
        })
    }

    /// `schannel_connect_step3`.
    fn step3(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        let host = Text(&self.host);
        let port = self.port;
        Self::say_debug(
            io,
            format_args!("schannel: SSL/TLS connection with {host} port {port} (step 3/3)"),
        );
        if self.cred.is_none() {
            return Err(ErrorKind::SslConnectError);
        }
        if self.ret != self.req {
            let r = self.ret;
            for (bit, what) in [
                (req::SEQUENCE_DETECT, "sequence detection"),
                (req::REPLAY_DETECT, "replay detection"),
                (req::CONFIDENTIALITY, "confidentiality"),
                (req::ALLOCATE_MEMORY, "memory allocation"),
                (req::STREAM, "stream orientation"),
            ] {
                if r & bit == 0 {
                    io.fail(
                        ErrorKind::SslConnectError,
                        format_args!("schannel: failed to setup {what}"),
                    );
                }
            }
            return Err(ErrorKind::SslConnectError);
        }
        let ctx = self.ctx.as_ref().expect("made at the first step");
        if self.use_alpn {
            let Ok(chosen) = ctx.alpn() else {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("schannel: failed to retrieve ALPN result"),
                ));
            };
            match chosen {
                Some((id, len)) => {
                    let proto = &id[..len];
                    if self.renegotiating
                        && let Some(was) = &self.negotiated
                        && !strncmp_same(was, proto)
                    {
                        return Err(io.fail(
                            ErrorKind::SslConnectError,
                            format_args!("schannel: server selected an ALPN protocol too late"),
                        ));
                    }
                    self.set_negotiated(io, proto)?;
                }
                None if !self.renegotiating => self.set_negotiated(io, &[])?,
                None => {}
            }
        }
        if io.caches_sessions() {
            let cred = self.cred.as_ref().expect("checked above").clone();
            io.keep_session_object(cred)?;
        }
        if io.wants_certinfo() {
            let ctx = self.ctx.as_ref().expect("made at the first step");
            verify::certinfo(io, ctx, MOST_CERTS)?;
        }
        self.step = Step::Done;
        Ok(())
    }

    /// `Curl_alpn_set_negotiated`: what the peer chose, said, and kept
    /// unless the session asked for one alone.
    fn set_negotiated(&mut self, io: &mut TlsCx<'_>, proto: &[u8]) -> Result<(), ErrorKind> {
        curl_core::tls::alpn_negotiated(io, self.negotiated.as_deref(), proto)?;
        if self.negotiated.is_none() && !proto.is_empty() {
            let mut copy = Vec::new();
            copy.try_extend_from_slice(proto).map_err(oom)?;
            self.negotiated = Some(copy);
        }
        Ok(())
    }

    /// `schannel_connect`: the steps it has left, then the record sizes.
    fn connect(&mut self, io: &mut TlsIo<'_>) -> Result<bool, ErrorKind> {
        if self.complete {
            return Ok(true);
        }
        if self.step == Step::One {
            self.step1(io)?;
        }
        if self.step == Step::Two {
            self.step2(io)?;
        }
        if self.step == Step::Three {
            self.step3(io)?;
        }
        if self.step == Step::Done {
            let ctx = self.ctx.as_ref().expect("made at the first step");
            match ctx.stream_sizes() {
                Ok(s) => self.sizes = s,
                Err(_) => {
                    return Err(io.fail(
                        ErrorKind::SslConnectError,
                        format_args!("schannel: failed getting stream sizes"),
                    ));
                }
            }
            self.complete = true;
            return Ok(true);
        }
        Ok(false)
    }

    /// `schannel_recv_renegotiate`: done, or waiting for the socket as
    /// `need` says; never longer than a minute.
    fn renegotiate(&mut self, io: &mut TlsIo<'_>) -> Result<bool, ErrorKind> {
        if !self.renegotiating {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("schannel: unexpected call to schannel_recv_renegotiate"),
            ));
        }
        let now = io.now();
        let (start, need) = match self.reneg {
            Some(r) => r,
            None => {
                io.info(format_args!("schannel: renegotiating SSL/TLS connection"));
                self.complete = false;
                self.step = Step::Two;
                (now, Need::Send)
            }
        };
        let result = loop {
            if now.ms_since(start) >= curl_core::time::millis(RENEG_MOST) {
                break Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("schannel: renegotiation timeout"),
                ));
            }
            self.need = need;
            match self.connect(io) {
                Ok(true) => break Ok(()),
                Ok(false) => {
                    if self.need == Need::None {
                        continue;
                    }
                    // C waits here, in the direction its caller does not;
                    // this session is called again.
                    self.reneg = Some((start, self.need));
                    return Ok(false);
                }
                Err(kind) => break Err(kind),
            }
        };
        self.reneg = None;
        self.renegotiating = false;
        self.need = Need::None;
        match result {
            Ok(()) => {
                io.info(format_args!("schannel: SSL/TLS connection renegotiated"));
                Ok(true)
            }
            Err(kind) => {
                io.fail(kind, format_args!("schannel: renegotiation failed"));
                Err(kind)
            }
        }
    }

    /// Give out what was decrypted, at most `buf`'s length.
    fn give(&mut self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        let size = buf.len().min(self.dec_off);
        let n = NonZeroUsize::new(size)?;
        buf[..size].copy_from_slice(&self.dec[..size]);
        self.dec.copy_within(size..self.dec_off, 0);
        self.dec_off -= size;
        Some(n)
    }

    /// `schannel_recv`, for a buffer of `buf.len()` bytes, which is not
    /// empty.
    fn read(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> Res {
        let len = buf.len();
        let mut result = Res::Ok;
        'cleanup: {
            if len <= self.dec_off {
                break 'cleanup;
            }
            if let Some(e) = self.recv_err {
                result = Res::Err(e);
                io.info(format_args!(
                    "schannel: an unrecoverable error occurred in a prior call"
                ));
                break 'cleanup;
            }
            if self.close_notify {
                io.info(format_args!(
                    "schannel: server indicated shutdown in a prior call"
                ));
                break 'cleanup;
            }
            if !self.closed {
                if let Err(kind) = self.ensure_enc(io, len + FREE_SIZE) {
                    result = Res::Err(kind);
                    break 'cleanup;
                }
                match io.recv(&mut self.enc[self.enc_off..]) {
                    Ok(Recv::WouldBlock) => result = Res::Again,
                    Ok(Recv::Eof) => {
                        self.closed = true;
                        Self::say_debug(io, format_args!("schannel: server closed the connection"));
                    }
                    Ok(Recv::Data(n)) => {
                        self.enc_off += n.get();
                        self.enc_incomplete = false;
                    }
                    Err(_) => {
                        let code = ErrorKind::RecvError.number();
                        io.info(format_args!("schannel: recv returned error {code}"));
                        self.recv_err = Some(ErrorKind::RecvError);
                        result = Res::Err(ErrorKind::RecvError);
                    }
                }
            }
            let mut st = status::OK;
            while self.enc_off > 0 && st == status::OK && (self.dec_off < len || self.closed) {
                let ctx = self.ctx.as_mut().expect("made at the first step");
                let d = ctx.decrypt(&mut self.enc[..self.enc_off]);
                st = d.status;
                if st == status::OK || st == status::RENEGOTIATE || st == status::CONTEXT_EXPIRED {
                    if let Some((at, n)) = d.plain {
                        if ensure_decoding(&mut self.dec, self.dec_off, n, len).is_err() {
                            io.fail(
                                ErrorKind::OutOfMemory,
                                format_args!("schannel: unable to re-allocate memory"),
                            );
                            result = Res::Err(ErrorKind::OutOfMemory);
                            break 'cleanup;
                        }
                        self.dec[self.dec_off..self.dec_off + n]
                            .copy_from_slice(&self.enc[at..at + n]);
                        self.dec_off += n;
                    }
                    match d.extra {
                        Some(extra) => {
                            if self.enc_off > extra {
                                self.enc.copy_within(self.enc_off - extra..self.enc_off, 0);
                                self.enc_off = extra;
                            }
                        }
                        None => self.enc_off = 0,
                    }
                    if st == status::RENEGOTIATE {
                        io.info(format_args!(
                            "schannel: remote party requests renegotiation"
                        ));
                        if let Res::Err(_) = result {
                            io.info(format_args!(
                                "schannel: cannot renegotiate, an error is pending"
                            ));
                            break 'cleanup;
                        }
                        self.renegotiating = true;
                        match self.renegotiate(io) {
                            Ok(true) => {}
                            Ok(false) => {
                                result = Res::Again;
                                break 'cleanup;
                            }
                            Err(kind) => {
                                result = Res::Err(kind);
                                break 'cleanup;
                            }
                        }
                        st = status::OK;
                        continue;
                    }
                    if st == status::CONTEXT_EXPIRED {
                        self.close_notify = true;
                        self.closed = true;
                        if result == Res::Err(ErrorKind::RecvError) {
                            result = Res::Ok;
                        }
                        io.info(format_args!(
                            "schannel: server close notification received (close_notify)"
                        ));
                        break 'cleanup;
                    }
                } else if st == status::INCOMPLETE_MESSAGE {
                    self.enc_incomplete = true;
                    if result == Res::Ok {
                        result = Res::Again;
                    }
                    break 'cleanup;
                } else {
                    let why = ErrorText::sspi(st);
                    io.fail(
                        ErrorKind::RecvError,
                        format_args!(
                            "schannel: failed to read data from server: {}",
                            Text(why.as_bytes())
                        ),
                    );
                    result = Res::Err(ErrorKind::RecvError);
                    break 'cleanup;
                }
            }
        }
        if self.dec_off == 0 && self.closed && !self.close_notify {
            result = Res::Err(ErrorKind::RecvError);
            io.fail(
                ErrorKind::RecvError,
                format_args!("schannel: server closed abruptly (missing close_notify)"),
            );
        }
        if let Res::Err(kind) = result {
            self.recv_err = Some(kind);
        }
        result
    }

    /// Send what is left of the record being sent: done, or not.
    fn flush_record(&mut self, io: &mut TlsIo<'_>) -> io::Result<bool> {
        let Some((len, mut sent, _)) = self.sending else {
            return Ok(true);
        };
        while sent < len {
            match io.send(&self.send_buf[sent..len]) {
                Ok(Sent::Bytes(n)) => sent += n.get(),
                Ok(Sent::WouldBlock) => {
                    self.sending = self.sending.map(|(l, _, p)| (l, sent, p));
                    self.need = Need::Send;
                    return Ok(false);
                }
                Err(e) => {
                    self.sending = None;
                    return Err(e);
                }
            }
        }
        self.sending = self.sending.map(|(l, _, p)| (l, sent, p));
        Ok(true)
    }
}

/// C's `strncmp(was, proto, proto.len())`, `was` a C string: the same
/// up to the first zero or the length.
fn strncmp_same(was: &[u8], proto: &[u8]) -> bool {
    for (i, &b) in proto.iter().enumerate() {
        let a = was.get(i).copied().unwrap_or(0);
        if a != b {
            return false;
        }
        if a == 0 {
            return true;
        }
    }
    true
}

/// One send of `bytes` through the layers below (`Curl_conn_cf_send`):
/// how many went, none if it failed.
fn send_once(io: &mut TlsIo<'_>, bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return Some(0);
    }
    match io.send(bytes) {
        Ok(Sent::Bytes(n)) => Some(n.get()),
        Ok(Sent::WouldBlock) => Some(0),
        Err(_) => None,
    }
}

impl TlsSession for Session {
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        match self.connect(io)? {
            true => Ok(Handshake::Done),
            false => Ok(Handshake::Waiting),
        }
    }

    fn recv(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        if self.renegotiating {
            match self.renegotiate(io) {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(self.give(buf).map_or(Recv::WouldBlock, Recv::Data));
                }
                Err(_) => return Err(io::ErrorKind::Other.into()),
            }
        }
        let result = self.read(io, buf);
        if let Some(n) = self.give(buf) {
            return Ok(Recv::Data(n));
        }
        match result {
            Res::Ok if !self.closed => Ok(Recv::WouldBlock),
            Res::Ok => Ok(Recv::Eof),
            Res::Again => Ok(Recv::WouldBlock),
            Res::Err(_) => Err(io::ErrorKind::Other.into()),
        }
    }

    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent> {
        self.need = Need::None;
        if self.renegotiating {
            match self.renegotiate(io) {
                Ok(true) => {}
                Ok(false) => return Ok(Sent::WouldBlock),
                Err(_) => return Err(io::ErrorKind::Other.into()),
            }
        }
        if let Some((_, _, plain)) = self.sending {
            // A record not sent whole goes first: it holds the first
            // bytes of these, which the caller gives again.
            assert!(plain <= bytes.len(), "a record's bytes are given again");
            if !self.flush_record(io)? {
                return Ok(Sent::WouldBlock);
            }
            self.sending = None;
            return Ok(Sent::Bytes(
                NonZeroUsize::new(plain).expect("a record holds bytes"),
            ));
        }
        let most = usize::try_from(self.sizes.most).expect("a u32 fits");
        let len = bytes.len().min(most);
        let header = usize::try_from(self.sizes.header).expect("a u32 fits");
        let trailer = usize::try_from(self.sizes.trailer).expect("a u32 fits");
        let total = header + len + trailer;
        if total > self.send_buf.len() {
            self.send_buf
                .try_resize(total, 0)
                .map_err(|OutOfMemory| io::Error::from(io::ErrorKind::OutOfMemory))?;
        }
        self.send_buf[header..header + len].copy_from_slice(&bytes[..len]);
        let ctx = self.ctx.as_mut().expect("made at the first step");
        let (record, plain) = match ctx.encrypt(&self.sizes, &mut self.send_buf, len) {
            Ok(r) => r,
            Err(_) => return Err(io::ErrorKind::Other.into()),
        };
        self.sending = Some((record, 0, plain));
        if !self.flush_record(io)? {
            return Ok(Sent::WouldBlock);
        }
        self.sending = None;
        match NonZeroUsize::new(plain) {
            Some(n) => Ok(Sent::Bytes(n)),
            None => Ok(Sent::WouldBlock),
        }
    }

    fn shutdown(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<Handshake, ErrorKind> {
        // C's Schannel sends its close_notify whatever it is asked.
        let _ = goodbye;
        if self.shut {
            return Ok(Handshake::Done);
        }
        let r = self.goodbye(io);
        let done = matches!(r, Ok(true));
        self.shut = r.is_err() || done;
        r.map(|done| {
            if done {
                Handshake::Done
            } else {
                Handshake::Waiting
            }
        })
    }

    fn waits(&self) -> TlsWait {
        match self.need {
            Need::None => TlsWait::Nothing,
            Need::Recv => TlsWait::Recv,
            Need::Send => TlsWait::Send,
        }
    }

    /// `schannel_data_pending`.
    fn pending(&self) -> bool {
        self.ctx.is_some()
            && (self.dec_off > 0
                || (self.enc_off > 0 && !self.enc_incomplete)
                || self.closed
                || self.close_notify
                || self.recv_err.is_some())
    }

    fn chosen(&self) -> Option<Chosen> {
        self.negotiated.as_deref().and_then(Chosen::named)
    }

    /// The context's handle, as C hands it out for either info
    /// (`schannel_get_internals`).
    fn native(&self) -> Option<TlsNative> {
        let h = self.ctx.as_ref()?.handle_ptr();
        Some(TlsNative::new(TlsKind::Schannel, h, Some(h)))
    }

    /// C's Schannel has no `get_channel_binding`.
    fn channel_binding(&self, _: &mut dyn BindingNotes) -> Result<Option<Vec<u8>>, ErrorKind> {
        Ok(None)
    }
}

impl Session {
    /// `schannel_shutdown`, once: done, or waiting as `need` says.
    fn goodbye(&mut self, io: &mut TlsIo<'_>) -> Result<bool, ErrorKind> {
        self.need = Need::None;
        if self.ctx.is_some() {
            let host = Text(&self.host);
            let port = self.port;
            io.info(format_args!(
                "schannel: shutting down SSL/TLS connection with {host} port {port}"
            ));
        }
        if self.ctx.is_none() {
            return Ok(true);
        }
        let mut done = false;
        if let Some(cred) = &self.cred
            && !self.goodbye_sent
            && !self.goodbye_made
        {
            let ctx = self.ctx.as_mut().expect("checked above");
            match ctx.goodbye(&cred.creds, &cred.sni, self.req) {
                Err(st) => {
                    let why = ErrorText::sspi(st);
                    return Err(io.fail(
                        ErrorKind::SendError,
                        format_args!(
                            "schannel: ApplyControlToken failure: {}",
                            Text(why.as_bytes())
                        ),
                    ));
                }
                Ok((st, token, attrs)) => {
                    self.ret = attrs;
                    if st == status::OK || st == status::CONTEXT_EXPIRED {
                        self.goodbye = token.map(CloseNotify::new);
                        self.goodbye_made = true;
                    } else {
                        drop(token);
                        let why = ErrorText::sspi(st);
                        return Err(io.fail(
                            ErrorKind::SendError,
                            format_args!(
                                "schannel: generating close msg failed: {}",
                                Text(why.as_bytes())
                            ),
                        ));
                    }
                }
            }
        }
        if self.goodbye_made && !self.goodbye_sent {
            let flushed = match &mut self.goodbye {
                Some(g) => g.flush(|left| match io.send(left)? {
                    Sent::Bytes(n) => Ok::<_, io::Error>(Some(n.get())),
                    Sent::WouldBlock => Ok(None),
                }),
                None => Flushed::Done,
            };
            if flushed == Flushed::Waiting {
                self.need = Need::Send;
                return Ok(false);
            }
            if flushed == Flushed::Failed {
                if self.closed {
                    return Ok(true);
                }
                let code = ErrorKind::SendError.number();
                return Err(io.fail(
                    ErrorKind::SendError,
                    format_args!("schannel: error sending close msg: {code}"),
                ));
            }
            self.goodbye = None;
            self.goodbye_sent = true;
            done = true;
        }
        if self.cred.is_some() && !self.close_notify && !self.closed {
            let mut buf = [0u8; 1024];
            let r = self.read(io, &mut buf);
            // What was read is dropped, as C's buffer is.
            let got = self.give(&mut buf).is_some();
            match r {
                _ if got => {}
                Res::Err(kind) => {
                    let code = kind.number();
                    io.trace(format_args!("SSL shutdown, error {code}"));
                    return Err(ErrorKind::RecvError);
                }
                Res::Ok if self.closed => done = true,
                Res::Ok | Res::Again => self.need = Need::Recv,
            }
        }
        Ok(done)
    }
}
