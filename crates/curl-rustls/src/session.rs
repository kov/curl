//! One connection's Rustls (`lib/vtls/rustls.c`): its configuration built
//! and its connection made at the handshake's first step
//! (`cr_init_backend`), the handshake (`cr_connect`), then the records both
//! ways (`cr_recv`, `cr_send`) and the goodbye (`cr_shutdown`). C keeps no
//! session to resume, and builds each connection's configuration anew.

use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::{EchMode, TlsMaxVersion, TlsMinVersion};
use curl_core::report::CertInfo;
use curl_core::tls::pin::{self, Pin};
use curl_core::tls::{
    Alpn, BindingNotes, Chosen, Goodbye, Handshake, SharedKeyLog, Text, TlsIdentity, TlsIo,
    TlsNative, TlsPeer, TlsSession, TlsWait,
};
use curl_core::tls::{Checked, Residuals, TlsCx};

use crate::files::{self, Read};
use crate::library::{Call, Conn as _, Errno, Plain, Rustls, TLS1_2, TLS1_3};
use crate::result::Code;

/// Where a connection's handshake is (`ssl_connection_state`), by C's
/// numbers, as `cr_connect` traces them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    None = 0,
    Negotiating = 2,
    Complete = 3,
}

/// The most certificates of the peer's chain reported
/// (`MAX_ALLOWED_CERT_AMOUNT`).
const MOST_CERTS: usize = 100;

/// The largest client certificate and key read, and revocation list
/// (`DYN_CERTFILE_SIZE`, `DYN_KEYFILE_SIZE`, `DYN_CRLFILE_SIZE`).
const CERT_MOST: usize = 100 * 1024;
const KEY_MOST: usize = 100 * 1024;
const CRL_MOST: usize = 400 * 1024 * 1024;

/// What a send came to (`cr_send`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flushed {
    Done,
    /// It would have blocked (`CURLE_AGAIN`).
    Again,
}

/// What a receive came to (`cr_recv`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Got {
    /// This many bytes, none being the peer's close_notify.
    Bytes(usize),
    /// None yet (`CURLE_AGAIN`).
    Again,
}

/// One connection's Rustls, through the library `G`.
pub(crate) struct Session<G: Rustls> {
    lib: &'static G,
    conn: Option<G::Conn>,
    identity: TryArc<TlsIdentity>,
    /// The origin's name as the URL gives it, without brackets: the name
    /// the connection is made to (`connssl->peer.origin->hostname`).
    host: Vec<u8>,
    alpn: Alpn,
    keylog: Option<SharedKeyLog>,
    state: State,
    waits: TlsWait,
    /// Plain bytes the library took for a send that then blocked, which
    /// the next send counts first (`plain_out_buffered`).
    plain_out_buffered: usize,
    /// The library may hold plain bytes not yet read (`data_in_pending`).
    data_in_pending: bool,
    /// The goodbye was sent (`sent_shutdown`), and it is over or failed
    /// (the filter's `shutdown`).
    sent_shutdown: bool,
    shut: bool,
    /// What ALPN agreed (`connssl->negotiated.alpn`).
    negotiated: Option<Chosen>,
    /// The ECHConfigList of the origin's HTTPS record, if it has one.
    ech_record: Option<Vec<u8>>,
}

/// An error the session said why it failed for: what the core reads as
/// the read's or the send's failure.
fn said() -> io::Error {
    io::ErrorKind::Other.into()
}

/// The transfer's error for a failure rustls-ffi numbered `code`
/// (`map_error`).
fn kind_of(code: Code) -> ErrorKind {
    if code.is_cert_error() {
        return ErrorKind::PeerFailedVerification;
    }
    match code {
        Code::NullParameter => ErrorKind::BadFunctionArgument,
        _ => ErrorKind::RecvError,
    }
}

/// A result's number, as C's traces show it: 0, or the error's.
fn number<T>(r: &Result<T, ErrorKind>) -> u16 {
    r.as_ref().err().map_or(0, |kind| kind.number())
}

impl<G: Rustls> Session<G> {
    /// A session for one connection to `peer`, nothing of the library's
    /// made yet, logging its secrets to `keylog` if given one.
    pub(crate) fn new(
        lib: &'static G,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        keylog: Option<SharedKeyLog>,
    ) -> Result<Session<G>, ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(peer.name)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        let ech_record = match peer.ech_configs {
            Some(list) => {
                let mut copy = Vec::new();
                copy.try_extend_from_slice(list)
                    .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
                Some(copy)
            }
            None => None,
        };
        Ok(Session {
            lib,
            conn: None,
            identity: identity.clone(),
            host,
            alpn,
            keylog,
            state: State::None,
            waits: TlsWait::Nothing,
            plain_out_buffered: 0,
            data_in_pending: false,
            sent_shutdown: false,
            shut: false,
            negotiated: None,
            ech_record,
        })
    }

    fn conn(&mut self) -> &mut G::Conn {
        self.conn
            .as_mut()
            .expect("made at the handshake's first step")
    }

    /// The configuration's versions and suites (`init_config_builder`).
    fn config_builder(&self, io: &mut TlsIo<'_>) -> Result<G::Builder, ErrorKind> {
        let o = &self.identity.options;
        let mut versions = [TLS1_2, TLS1_3];
        let mut len = 2;
        match o.min_version {
            TlsMinVersion::Tls1
            | TlsMinVersion::Tls1_0
            | TlsMinVersion::Tls1_1
            | TlsMinVersion::Tls1_2 => {}
            TlsMinVersion::Tls1_3 => {
                versions[0] = TLS1_3;
                len = 1;
            }
        }
        match o.max_version {
            TlsMaxVersion::Default | TlsMaxVersion::None | TlsMaxVersion::Tls1_3 => {}
            TlsMaxVersion::Tls1_2 if versions[0] == TLS1_2 => len = 1,
            TlsMaxVersion::Tls1_2 | TlsMaxVersion::Tls1_1 | TlsMaxVersion::Tls1_0 => {
                return Err(io.fail(
                    ErrorKind::BadFunctionArgument,
                    format_args!("rustls: unsupported maximum TLS version value"),
                ));
            }
        }
        // ECH, GREASE too, holds the handshake to TLS 1.3 whether or not
        // it is set up.
        if o.ech.enabled() {
            versions[0] = TLS1_3;
            len = 1;
            io.info(format_args!("rustls: ECH enabled, forcing TLSv1.3"));
        }
        let suites = self
            .lib
            .suites()
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        let selected = curl_core::tls::suites::select(
            io,
            "rustls",
            &suites,
            |s| s.id,
            |s| s.tls13,
            o.ciphers.as_deref(),
            o.tls13_ciphers.as_deref(),
        )?;
        self.lib
            .builder(&selected, &versions[..len])
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)
    }

    /// The certificates to trust, from the blob, else the file, and the
    /// revocation list, made into the configuration's verifier
    /// (`init_config_builder_verifier`).
    fn verifier(
        &self,
        io: &mut TlsIo<'_>,
        builder: &mut G::Builder,
        blob: Option<&[u8]>,
        file: Option<&[u8]>,
    ) -> Result<(), ErrorKind> {
        let lib = self.lib;
        let roots = if let Some(blob) = blob {
            lib.roots(blob).map_err(|code| {
                io.fail(
                    ErrorKind::SslCacertBadfile,
                    format_args!(
                        "failed to parse trusted certificates from blob: {}",
                        code.words()
                    ),
                )
            })?
        } else {
            let file = file.expect("a blob or a file");
            // rustls-ffi reads the file itself, and says any failure to
            // open or read it, its name not UTF-8 among them, as I/O's.
            let read = match files::read(file, usize::MAX) {
                Read::Data(data) if core::str::from_utf8(file).is_ok() => lib.roots(&data),
                Read::OutOfMemory => return Err(ErrorKind::OutOfMemory),
                Read::Data(_) | Read::Failed | Read::TooLarge => Err(Code::Io),
            };
            read.map_err(|code| {
                io.fail(
                    ErrorKind::SslCacertBadfile,
                    format_args!("failed to load trusted certificates: {}", code.words()),
                )
            })?
        };
        let mut crls = None;
        if let Some(crl) = self.identity.options.crl_file.as_deref() {
            let data = match files::read(crl, CRL_MOST) {
                Read::Data(data) => data,
                Read::OutOfMemory | Read::Failed | Read::TooLarge => {
                    return Err(io.fail(
                        ErrorKind::SslCrlBadfile,
                        format_args!("rustls: failed to read revocation list file"),
                    ));
                }
            };
            crls = Some(lib.crls(&data).map_err(|code| {
                io.fail(
                    ErrorKind::SslCrlBadfile,
                    format_args!("failed to parse revocation list: {}", code.words()),
                )
            })?);
        }
        let verifier = lib.webpki(roots, crls).map_err(|code| {
            io.fail(
                ErrorKind::SslCacertBadfile,
                format_args!("failed to build certificate verifier: {}", code.words()),
            )
        })?;
        lib.verifier(builder, verifier);
        Ok(())
    }

    /// The client's certificate and key, PEM only, from their blobs or
    /// files (`init_config_builder_client_auth`).
    fn client_auth(&self, io: &mut TlsIo<'_>, builder: &mut G::Builder) -> Result<(), ErrorKind> {
        let o = &self.identity.options;
        let have_cert = o.cert.is_some() || o.cert_blob.is_some();
        let have_key = o.key.is_some() || o.key_blob.is_some();
        if have_cert && !have_key {
            return Err(io.fail(
                ErrorKind::SslCertproblem,
                format_args!("rustls: must provide key with certificate"),
            ));
        }
        if !have_cert && have_key {
            return Err(io.fail(
                ErrorKind::SslCertproblem,
                format_args!("rustls: must provide certificate with key"),
            ));
        }
        if let Some(t) = o.cert_type.as_deref().filter(|t| !is_pem(t)) {
            return Err(io.fail(
                ErrorKind::SslCertproblem,
                format_args!(
                    "rustls: unsupported certificate type '{}', only 'PEM' is supported",
                    Text(t)
                ),
            ));
        }
        if let Some(t) = o.key_type.as_deref().filter(|t| !is_pem(t)) {
            return Err(io.fail(
                ErrorKind::SslCertproblem,
                format_args!(
                    "rustls: unsupported key type '{}', only 'PEM' is supported",
                    Text(t)
                ),
            ));
        }
        let cert = match (o.cert_blob.as_deref(), o.cert.as_deref()) {
            (Some(blob), _) => copy_blob(io, blob, CERT_MOST, "client certificate blob")?,
            (None, file) => {
                let file = file.expect("a certificate's blob or file");
                match files::read(file, CERT_MOST) {
                    Read::Data(data) => data,
                    Read::OutOfMemory | Read::Failed | Read::TooLarge => {
                        return Err(io.fail(
                            ErrorKind::SslCertproblem,
                            format_args!(
                                "rustls: failed to read client certificate file: '{}'",
                                Text(file)
                            ),
                        ));
                    }
                }
            }
        };
        let key = match (o.key_blob.as_deref(), o.key.as_deref()) {
            (Some(blob), _) => copy_blob(io, blob, KEY_MOST, "key blob")?,
            (None, file) => {
                let file = file.expect("a key's blob or file");
                match files::read(file, KEY_MOST) {
                    Read::Data(data) => data,
                    Read::OutOfMemory | Read::Failed | Read::TooLarge => {
                        return Err(io.fail(
                            ErrorKind::SslCertproblem,
                            format_args!("rustls: failed to read key file: '{}'", Text(file)),
                        ));
                    }
                }
            }
        };
        let lib = self.lib;
        let certified = lib.certified_key(&cert, &key).map_err(|code| {
            io.fail(
                ErrorKind::SslCertproblem,
                format_args!("rustls: failed to build certified key: {}", code.words()),
            )
        })?;
        lib.keys_match(&certified).map_err(|code| {
            io.fail(
                ErrorKind::SslCertproblem,
                format_args!(
                    "rustls: client certificate and keypair files do not match:: {}",
                    code.words()
                ),
            )
        })?;
        lib.certify(builder, certified);
        Ok(())
    }

    /// The configuration built and the connection made from it
    /// (`cr_init_backend`).
    fn init_backend(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        let lib = self.lib;
        let mut builder = self.config_builder(io)?;
        if let Some(offer) = self.alpn.offer() {
            let mut names = Vec::new();
            for name in self.alpn.names() {
                names
                    .try_push(name)
                    .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
            }
            lib.alpn(&mut builder, &names)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
            io.info(format_args!("ALPN: curl offers {offer}"));
        }
        let identity = self.identity.clone();
        // The blob in place of the file (`CURLOPT_CAINFO_BLOB` overrides
        // `CURLOPT_CAINFO`).
        let blob = identity.ca_blob();
        let file = if blob.is_some() {
            None
        } else {
            identity.ca_file()
        };
        if !identity.verify_peer {
            lib.verify_none(&mut builder);
        } else if identity.native_ca_store() {
            if identity.options.crl_file.is_some() {
                return Err(io.fail(
                    ErrorKind::NotBuiltIn,
                    format_args!(
                        "rustls: CRL file not supported with native CA store; the platform verifier has no CRL attachment API"
                    ),
                ));
            }
            let verifier = lib.platform().map_err(|code| {
                io.fail(
                    ErrorKind::SslCacertBadfile,
                    format_args!(
                        "failed to create platform certificate verifier: {}",
                        code.words()
                    ),
                )
            })?;
            lib.verifier(&mut builder, verifier);
        } else if blob.is_some() || file.is_some() {
            self.verifier(io, &mut builder, blob, file)?;
        }
        let o = &identity.options;
        if o.cert.is_some() || o.cert_blob.is_some() || o.key.is_some() || o.key_blob.is_some() {
            self.client_auth(io, &mut builder)?;
        }
        // ECH that cannot be set up fails the handshake only where it is
        // hard; else the handshake goes on without it, said.
        if o.ech.enabled()
            && let Err(kind) = self.init_ech(io, &mut builder)
            && o.ech.mode == EchMode::Hard
        {
            return Err(kind);
        }
        // The key log is opened as a connection's configuration is built
        // (`init_config_builder_keylog`), and its secrets go to it while
        // it is open.
        if let Some(log) = &self.keylog {
            log.open();
            if log.enabled() {
                lib.key_log(&mut builder, log.clone());
            }
        }
        let config = lib.build(builder).map_err(|code| {
            io.fail(
                ErrorKind::SslConnectError,
                format_args!("failed to build client config: {}", code.words()),
            )
        })?;
        let conn = lib.connect(config, &self.host).map_err(|code| {
            io.fail(
                ErrorKind::CouldntConnect,
                format_args!("rustls_client_connection_new: {}", code.words()),
            )
        })?;
        self.conn = Some(conn);
        Ok(())
    }

    /// Encrypted Client Hello set up on the configuration
    /// (`init_config_builder_ech`): GREASE; else the transfer's list,
    /// from base64, or the origin's HTTPS record's. An outer name cannot
    /// be set. What fails is said, and fails the handshake as the caller
    /// decides.
    fn init_ech(&self, io: &mut TlsIo<'_>, builder: &mut G::Builder) -> Result<(), ErrorKind> {
        let ech = &self.identity.options.ech;
        if ech.public_name.is_some() {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("rustls: ECH outername not supported"),
            ));
        }
        if ech.mode == EchMode::Grease {
            return self.lib.ech_grease(builder).map_err(|code| {
                io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("rustls: failed to configure ECH GREASE: {}", code.words()),
                )
            });
        }
        let decoded;
        let list: &[u8] = match &ech.config {
            Some(b64) => {
                if b64.is_empty() {
                    io.info(format_args!("rustls: ECHConfig from command line empty"));
                    return Err(ErrorKind::SslConnectError);
                }
                // Out of memory is a failure to decode, as C's is.
                let Ok(Some(list)) = curl_core::tls::base64_decode(b64) else {
                    io.info(format_args!(
                        "rustls: cannot base64 decode ECHConfig from command line"
                    ));
                    return Err(ErrorKind::SslConnectError);
                };
                decoded = list;
                &decoded
            }
            None => match &self.ech_record {
                Some(list) => list,
                None => {
                    return Err(io.fail(
                        ErrorKind::SslConnectError,
                        format_args!("rustls: ECH requested but no ECHConfig available"),
                    ));
                }
            },
        };
        self.lib.ech(builder, list).map_err(|code| {
            io.fail(
                ErrorKind::SslConnectError,
                format_args!("rustls: failed to configure ECH: {}", code.words()),
            )
        })
    }

    /// Read the peer's records and make what the library can of them
    /// (`tls_recv_more`): how many bytes were read, none if the peer
    /// closed the connection, or none yet.
    fn recv_more(&mut self, io: &mut TlsIo<'_>) -> Result<Option<usize>, ErrorKind> {
        let conn = self
            .conn
            .as_mut()
            .expect("made at the handshake's first step");
        let n = match conn.read_tls(&mut Call { io }) {
            Ok(n) => n,
            Err(Errno::Again) => return Ok(None),
            Err(e) => {
                return Err(io.fail(
                    ErrorKind::RecvError,
                    format_args!("reading from socket: {e}"),
                ));
            }
        };
        if let Err(code) = conn.process_new_packets() {
            return Err(io.fail(
                kind_of(code),
                format_args!("rustls_connection_process_new_packets: {}", code.words()),
            ));
        }
        self.data_in_pending = true;
        Ok(Some(n))
    }

    /// Read into `buf` what the library has of the peer's plain text, and
    /// read its records for more while it has none (`cr_recv`).
    fn recv_plain(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> Result<Got, ErrorKind> {
        let len = buf.len();
        let mut nread = 0;
        let r = self.recv_into(io, buf, &mut nread);
        io.trace(format_args!(
            "rustls_recv(len={len}) -> {}, {nread}",
            match &r {
                Ok(Got::Again) => crate::library::AGAIN,
                r => number(r),
            }
        ));
        r
    }

    fn recv_into(
        &mut self,
        io: &mut TlsIo<'_>,
        buf: &mut [u8],
        nread: &mut usize,
    ) -> Result<Got, ErrorKind> {
        let mut eof = false;
        while *nread < buf.len() {
            if !self.data_in_pending && self.recv_more(io)?.is_none() {
                break;
            }
            match self.conn().read(&mut buf[*nread..]) {
                // A record with no plain text: no more is read for now, so
                // that a server cannot keep us here for ever.
                Plain::Empty => {
                    self.data_in_pending = false;
                    break;
                }
                Plain::UnexpectedEof => {
                    return Err(io.fail(
                        ErrorKind::RecvError,
                        format_args!(
                            "rustls: peer closed TCP connection without first closing TLS connection"
                        ),
                    ));
                }
                Plain::Failed(code) => {
                    return Err(io.fail(
                        ErrorKind::RecvError,
                        format_args!("rustls_connection_read: {}", code.words()),
                    ));
                }
                // The peer's close_notify, perhaps after bytes read before
                // it, which go out first.
                Plain::Read(0) => {
                    eof = true;
                    break;
                }
                Plain::Read(n) => *nread += n,
            }
        }
        if !eof && *nread == 0 {
            return Ok(Got::Again);
        }
        Ok(Got::Bytes(*nread))
    }

    /// Write out every record the library has (`cr_flush_out`).
    fn flush_out(&mut self, io: &mut TlsIo<'_>) -> Result<Flushed, ErrorKind> {
        let conn = self
            .conn
            .as_mut()
            .expect("made at the handshake's first step");
        let mut total = 0;
        while conn.wants_write() {
            match conn.write_tls(&mut Call { io }) {
                Err(Errno::Again) => {
                    io.trace(format_args!("cf_send: EAGAIN after {total} bytes"));
                    return Ok(Flushed::Again);
                }
                Err(e) => {
                    return Err(
                        io.fail(ErrorKind::SendError, format_args!("writing to socket: {e}"))
                    );
                }
                Ok(0) => {
                    return Err(io.fail(ErrorKind::SendError, format_args!("EOF in swrite")));
                }
                Ok(n) => {
                    io.trace(format_args!("cf_send: wrote {n} TLS bytes"));
                    total += n;
                }
            }
        }
        Ok(Flushed::Done)
    }

    /// Hand `plain` to the library, after counting what it took of a send
    /// that blocked, and write out its records (`cr_send`): how many of
    /// `plain`'s bytes are sent, or none yet. `plain` may be empty, to
    /// write out the records alone.
    fn send_plain(
        &mut self,
        io: &mut TlsIo<'_>,
        plain: &[u8],
    ) -> Result<(Flushed, usize), ErrorKind> {
        let len = plain.len();
        io.trace(format_args!("cf_send(len={len})"));
        let mut written = 0;
        let mut buf = plain;
        if self.plain_out_buffered > 0 {
            let buffered = self.plain_out_buffered;
            let r = self.flush_out(io);
            let code = match &r {
                Ok(Flushed::Again) => crate::library::AGAIN,
                r => number(r),
            };
            io.trace(format_args!(
                "cf_send: flushing {buffered} previously added bytes -> {code}"
            ));
            if r? == Flushed::Again {
                return Ok((Flushed::Again, 0));
            }
            buf = buf.get(buffered..).unwrap_or_default();
            written += buffered;
            self.plain_out_buffered = 0;
        }
        let r = self.add_and_flush(io, buf, written);
        let (code, n) = match &r {
            Ok((Flushed::Again, n)) => (crate::library::AGAIN, *n),
            Ok((Flushed::Done, n)) => (0, *n),
            Err(kind) => (kind.number(), written),
        };
        io.trace(format_args!("rustls_send(len={len}) -> {code}, {n}"));
        r
    }

    fn add_and_flush(
        &mut self,
        io: &mut TlsIo<'_>,
        buf: &[u8],
        mut written: usize,
    ) -> Result<(Flushed, usize), ErrorKind> {
        let mut plainwritten = 0;
        if !buf.is_empty() {
            io.trace(format_args!(
                "cf_send: adding {} plain bytes to Rustls",
                buf.len()
            ));
            match self.conn().write(buf) {
                Err(code) => {
                    return Err(io.fail(
                        ErrorKind::WriteError,
                        format_args!("rustls_connection_write: {}", code.words()),
                    ));
                }
                Ok(0) => {
                    return Err(io.fail(
                        ErrorKind::WriteError,
                        format_args!("rustls_connection_write: EOF"),
                    ));
                }
                Ok(n) => plainwritten = n,
            }
        }
        match self.flush_out(io)? {
            // The records may be partly written, but the whole send waits,
            // remembering what the library took.
            Flushed::Again => {
                self.plain_out_buffered = plainwritten;
                if written > 0 {
                    return Ok((Flushed::Done, written));
                }
                Ok((Flushed::Again, written))
            }
            Flushed::Done => {
                written += plainwritten;
                Ok((Flushed::Done, written))
            }
        }
    }

    /// What the peer chose of the ALPN offer (`cr_set_negotiated_alpn`),
    /// said and kept. C makes nothing of what it says: a choice it
    /// refuses is said, and the handshake goes on.
    fn set_negotiated_alpn(&mut self, io: &mut TlsIo<'_>) {
        let conn = self
            .conn
            .as_ref()
            .expect("made at the handshake's first step");
        let chosen = conn.alpn().unwrap_or_default();
        let asked = self.negotiated.map(|c| c.name().as_bytes());
        // `cr_set_negotiated_alpn` is void: a choice `Curl_alpn_set_negotiated`
        // refuses is said, and the handshake goes on.
        let _refused = curl_core::tls::alpn_negotiated(io, asked, chosen).is_err();
        if self.negotiated.is_none() && !chosen.contains(&0) {
            self.negotiated = Chosen::named(chosen);
        }
    }

    /// The handshake is over: what was agreed said, and the peer's chain
    /// reported if asked for.
    fn complete(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        let conn = self
            .conn
            .as_ref()
            .expect("made at the handshake's first step");
        let ver = match conn.version() {
            TLS1_3 => "TLSv1.3",
            TLS1_2 => "TLSv1.2",
            _ => "TLS version unknown",
        };
        io.info(format_args!(
            "rustls: handshake complete, {ver}, ciphersuite: {}, key exchange group: {}",
            conn.suite_name(),
            conn.group_name()
        ));
        if io.wants_certinfo() {
            let mut count = 0;
            while conn.peer_cert(count).is_some() {
                count += 1;
                if count > MOST_CERTS {
                    return Err(io.fail(
                        ErrorKind::SslConnectError,
                        format_args!("{count} certificates is more than allowed ({MOST_CERTS})"),
                    ));
                }
            }
            let mut info = CertInfo::new(count).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
            for i in 0..count {
                let der = conn.peer_cert(i).expect("counted above");
                curl_core::tls::x509::certinfo(io, &mut info, i, der)?;
            }
            io.set_certinfo(Some(info))?;
        }
        Ok(())
    }

    /// Move the handshake on, until it is done or the socket would block
    /// (`cr_connect`).
    fn connect(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        io.trace(format_args!("cr_connect, state={}", self.state as i32));
        if self.conn.is_none() {
            let r = self.init_backend(io);
            io.trace(format_args!("cr_connect, init backend -> {}", number(&r)));
            r?;
            self.state = State::Negotiating;
        }
        loop {
            self.waits = TlsWait::Nothing;
            if !self.conn().is_handshaking() {
                // The library says it is done before it has sent its
                // Finished: it is let write once more.
                self.set_negotiated_alpn(io);
                if self.send_plain(io, &[])?.0 == Flushed::Again {
                    self.waits = TlsWait::Send;
                    return Ok(Handshake::Waiting);
                }
                self.complete(io)?;
                let _checked = checked(io)?;
                self.state = State::Complete;
                return Ok(Handshake::Done);
            }
            let conn = self.conn();
            let wants_read = conn.wants_read();
            let wants_write = conn.wants_write() || self.plain_out_buffered > 0;
            assert!(
                wants_read || wants_write,
                "a handshake under way wants to read or to write"
            );
            if wants_write {
                io.trace(format_args!("rustls_connection wants us to write_tls."));
                if self.send_plain(io, &[])?.0 == Flushed::Again {
                    io.trace(format_args!("writing would block"));
                    self.waits = TlsWait::Send;
                    return Ok(Handshake::Waiting);
                }
            }
            if wants_read {
                io.trace(format_args!("rustls_connection wants us to read_tls."));
                match self.recv_more(io) {
                    Ok(Some(0)) => {
                        return Err(io.fail(
                            ErrorKind::SslConnectError,
                            format_args!("TLS connect error: Connection closed abruptly"),
                        ));
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        io.trace(format_args!("reading would block"));
                        self.waits = TlsWait::Recv;
                        return Ok(Handshake::Waiting);
                    }
                    Err(ErrorKind::RecvError) => return Err(ErrorKind::SslConnectError),
                    Err(kind) => return Err(kind),
                }
            }
        }
    }

    /// The goodbye (`cr_shutdown`): `Ok(true)` once over.
    fn goodbye(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<bool, ErrorKind> {
        if !self.sent_shutdown {
            // Only once.
            self.sent_shutdown = true;
            if goodbye.sends() {
                self.conn().send_close_notify();
            }
        }
        match self.send_plain(io, &[]) {
            Ok((Flushed::Again, _)) => {
                self.waits = TlsWait::Send;
                return Ok(false);
            }
            Ok((Flushed::Done, _)) => {}
            Err(kind) => {
                io.trace(format_args!("shutdown send failed: {}", kind.number()));
                return Err(kind);
            }
        }
        let mut buf = [0u8; 1024];
        let mut last = Ok(Got::Bytes(0));
        for _ in 0..10 {
            last = self.recv_plain(io, &mut buf);
            if !matches!(last, Ok(Got::Bytes(_))) {
                break;
            }
        }
        match last {
            Ok(Got::Again) => {
                self.waits = TlsWait::Recv;
                Ok(false)
            }
            Err(kind) => {
                io.trace(format_args!("shutdown, error: {}", kind.number()));
                Err(kind)
            }
            // The peer's close_notify read: done.
            Ok(Got::Bytes(n)) => Ok(n == 0),
        }
    }
}

/// The type names PEM (`curl_strequal(type, "PEM")`).
fn is_pem(kind: &[u8]) -> bool {
    kind.eq_ignore_ascii_case(b"PEM")
}

/// A copy of the blob `blob`, if it fits a buffer of `most` bytes with
/// the zero byte C adds; else the transfer fails with why, said of `what`
/// (`curlx_dyn_addn`).
fn copy_blob(
    io: &mut TlsIo<'_>,
    blob: &[u8],
    most: usize,
    what: &str,
) -> Result<Vec<u8>, ErrorKind> {
    let (kind, why) = if blob.len() >= most {
        (ErrorKind::TooLarge, "too large")
    } else {
        let mut copy = Vec::new();
        if copy.try_extend_from_slice(blob).is_ok() {
            return Ok(copy);
        }
        (ErrorKind::OutOfMemory, "out of memory")
    };
    Err(io.fail(kind, format_args!("rustls: failed to copy {what} ({why})")))
}

/// The peer checked as its handshake ends: the library matched its name
/// with its chain, or, verifying neither, neither. No key is pinned, which
/// the library has no support for.
fn checked(io: &mut TlsCx<'_>) -> Result<Checked, ErrorKind> {
    let Pin::NotAsked(pin) = pin::of(io) else {
        return Err(io.fail(
            ErrorKind::NotBuiltIn,
            format_args!("rustls: no pinned public key support"),
        ));
    };
    let residuals = Residuals::NONE.host_check_follows_chain(io);
    Checked::new(io, pin, residuals)
}

impl<G: Rustls> TlsSession for Session<G> {
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        if self.state == State::Complete {
            return Ok(Handshake::Done);
        }
        self.connect(io)
    }

    fn recv(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        match self.recv_plain(io, buf) {
            Ok(Got::Again) => Ok(Recv::WouldBlock),
            Ok(Got::Bytes(n)) => Ok(NonZeroUsize::new(n).map_or(Recv::Eof, Recv::Data)),
            Err(_) => Err(said()),
        }
    }

    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent> {
        match self.send_plain(io, bytes) {
            Ok((_, n)) => Ok(NonZeroUsize::new(n).map_or(Sent::WouldBlock, Sent::Bytes)),
            Err(_) => Err(said()),
        }
    }

    fn shutdown(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<Handshake, ErrorKind> {
        if self.conn.is_none() || self.shut {
            return Ok(Handshake::Done);
        }
        self.waits = TlsWait::Nothing;
        let done = self.goodbye(io, goodbye);
        self.shut = !matches!(done, Ok(false));
        done.map(|done| {
            if done {
                Handshake::Done
            } else {
                Handshake::Waiting
            }
        })
    }

    fn waits(&self) -> TlsWait {
        self.waits
    }

    fn pending(&self) -> bool {
        self.data_in_pending
    }

    fn chosen(&self) -> Option<Chosen> {
        self.negotiated
    }

    /// None: C hands out its `rustls_connection`, rustls-ffi's, which
    /// this build has none of (`DIVERGENCE.md`).
    fn native(&self) -> Option<TlsNative> {
        None
    }

    /// None: C's Rustls build makes no channel binding
    /// (`get_channel_binding` is NULL).
    fn channel_binding(&self, _: &mut dyn BindingNotes) -> Result<Option<Vec<u8>>, ErrorKind> {
        Ok(None)
    }
}
