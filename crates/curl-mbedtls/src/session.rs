//! One connection's mbedTLS (`lib/vtls/mbedtls.c`): its objects loaded and
//! set up at the handshake's first step as C sets them up
//! (`mbed_connect_step1`, `mbed_configure_ssl`), resuming a session the
//! cache kept, the handshake (`mbed_connect_step2`), the session kept
//! (`mbed_new_session`), then the records both ways (`mbed_recv`,
//! `mbed_send`) and the goodbye (`mbedtls_shutdown`).

use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::{TlsMaxVersion, TlsMinVersion};
use curl_core::tls::{
    Alpn, BindingNotes, Chosen, Goodbye, Handshake, Text, TlsCx, TlsIdentity, TlsIo, TlsKind,
    TlsNative, TlsPeer, TlsPeerKind, TlsSession, TlsTicket, TlsWait,
};

use crate::library::{
    AGAIN, Call, Conn as _, Hex, LowHex, Mbedtls, Rc, Resume, Saved, as_c, c_string,
};
use crate::sys;

/// How far a session's handshake has come (`connecting_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Nothing made yet: the objects are set up at the first step.
    One,
    /// The handshake runs.
    Two,
    /// The handshake is done; the session is to be kept.
    Three,
    Done,
}

/// One connection's mbedTLS, through the library `G`.
pub(crate) struct Session<G: Mbedtls> {
    lib: &'static G,
    rng: TryArc<G::Rng>,
    conn: Option<G::Conn>,
    /// The context is initialised (`initialized`): a goodbye has a
    /// session to say it in.
    initialized: bool,
    identity: TryArc<TlsIdentity>,
    /// The origin's name as the URL gives it, without brackets, and its
    /// port.
    host: Vec<u8>,
    port: u16,
    kind: TlsPeerKind,
    alpn: Alpn,
    step: Step,
    waits: TlsWait,
    /// The goodbye was sent (`sent_shutdown`), and it is over or failed
    /// (the filter's `shutdown`).
    sent_shutdown: bool,
    shut: bool,
    /// A write that would have blocked, and how long it was: the library
    /// wants the same again (`send_blocked`, `send_blocked_len`).
    send_blocked: Option<usize>,
    /// What ALPN agreed (`connssl->negotiated.alpn`).
    negotiated: Option<Chosen>,
}

impl<G: Mbedtls> Session<G> {
    /// A session for one connection to `peer`, drawing on `rng`, nothing
    /// of the library's made yet.
    pub(crate) fn new(
        lib: &'static G,
        rng: TryArc<G::Rng>,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
    ) -> Result<Session<G>, ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(peer.name)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        Ok(Session {
            lib,
            rng,
            conn: None,
            initialized: false,
            identity: identity.clone(),
            host,
            port: peer.port,
            kind: peer.kind,
            alpn,
            step: Step::One,
            waits: TlsWait::Nothing,
            sent_shutdown: false,
            shut: false,
            send_blocked: None,
            negotiated: None,
        })
    }

    fn conn(&mut self) -> &mut G::Conn {
        self.conn.as_mut().expect("made at the first step")
    }

    /// Run `op`, a call into the library on the connection, with its
    /// callbacks reaching `io`.
    fn call<R>(
        &mut self,
        io: &mut TlsIo<'_>,
        op: impl FnOnce(&mut G::Conn, &mut Call<'_, '_>) -> R,
    ) -> R {
        let lib = self.lib;
        let mut call = Call {
            io,
            verify_peer: self.identity.verify_peer,
            verify_host: self.identity.verify_host,
            explain: lib,
        };
        let conn = self.conn.as_mut().expect("made at the first step");
        op(conn, &mut call)
    }

    /// The library's words for `rc`.
    fn words(&self, rc: Rc) -> crate::library::Words {
        self.lib.strerror(rc)
    }

    /// The connection's objects loaded and set up (`mbed_connect_step1`).
    fn step1(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        let conn = self
            .lib
            .conn(&self.rng)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        self.conn = Some(conn);
        self.load_cacert(io)?;
        self.load_clicert(io)?;
        self.load_privkey(io)?;
        self.load_crl(io)?;
        self.configure(io)
    }

    /// The certificates to trust, from the blob, else the file, and the
    /// directory (`mbed_load_cacert`): the blob and the file only for a
    /// peer that is verified; a directory that does not load fails only
    /// such a peer.
    fn load_cacert(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let identity = self.identity.clone();
        let verify = identity.verify_peer;
        let blob = identity.ca_blob();
        let file = if blob.is_some() {
            None
        } else {
            identity.ca_file()
        };
        if let Some(blob) = blob.filter(|_| verify) {
            let der = is_der(identity.options.cert_type.as_deref());
            let rc = self.parse_blob(blob, der, |c, b| c.ca_parse(b))?;
            if rc < 0 {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "mbedTLS: error importing CA cert blob: ({}) {}",
                        Hex(rc),
                        self.words(rc)
                    ),
                ));
            }
        }
        if let Some(file) = file.filter(|_| verify) {
            let name = c_string(file)?;
            let rc = self.conn().ca_parse_file(as_c(&name));
            if rc < 0 {
                return Err(io.fail(
                    ErrorKind::SslCacertBadfile,
                    format_args!(
                        "mbedTLS: error reading CA cert file {}: ({}) {}",
                        Text(file),
                        Hex(rc),
                        self.words(rc)
                    ),
                ));
            }
        }
        if let Some(dir) = identity.ca_path() {
            let name = c_string(dir)?;
            let rc = self.conn().ca_parse_path(as_c(&name));
            if rc < 0 {
                let kind = io.fail(
                    ErrorKind::SslCacertBadfile,
                    format_args!(
                        "mbedTLS: error reading CA cert path {}: ({}) {}",
                        Text(dir),
                        Hex(rc),
                        self.words(rc)
                    ),
                );
                if verify {
                    return Err(kind);
                }
            }
        }
        Ok(())
    }

    /// Parse `blob` with `parse`, as C hands PEM to the library: as it is
    /// if DER (`der`) or ended by a zero byte, else with one added, which
    /// the library needs to read PEM.
    fn parse_blob(
        &mut self,
        blob: &[u8],
        der: bool,
        parse: impl FnOnce(&mut G::Conn, &[u8]) -> Rc,
    ) -> Result<Rc, ErrorKind> {
        if der || blob.last() == Some(&0) {
            return Ok(parse(self.conn(), blob));
        }
        let ended = c_string(blob)?;
        Ok(parse(self.conn(), &ended))
    }

    /// The client's certificate, from its file and its blob
    /// (`mbed_load_clicert`).
    fn load_clicert(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let identity = self.identity.clone();
        let o = &identity.options;
        if let Some(file) = o.cert.as_deref() {
            let name = c_string(file)?;
            let rc = self.conn().cert_parse_file(as_c(&name));
            if rc != 0 {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "mbedTLS: error reading client cert file {}: ({}) {}",
                        Text(file),
                        Hex(rc),
                        self.words(rc)
                    ),
                ));
            }
        }
        if let Some(blob) = o.cert_blob.as_deref() {
            let rc =
                self.parse_blob(blob, is_der(o.cert_type.as_deref()), |c, b| c.cert_parse(b))?;
            if rc != 0 {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "mbedTLS: error reading client cert blob: ({}) {}",
                        Hex(rc),
                        self.words(rc)
                    ),
                ));
            }
        }
        Ok(())
    }

    /// The client's key, from its file, else its blob, which must sign as
    /// RSA or EC (`mbed_load_privkey`).
    fn load_privkey(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let identity = self.identity.clone();
        let o = &identity.options;
        let password = o.key_password.as_deref();
        if let Some(file) = o.key.as_deref() {
            let name = c_string(file)?;
            let pass = password.map(c_string).transpose()?;
            let conn = self.conn();
            let mut rc = conn.key_parse_file(as_c(&name), pass.as_deref().map(as_c));
            if rc == 0 && !conn.key_signs() {
                rc = sys::MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            if rc != 0 {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "mbedTLS: error reading private key {}: ({}) {}",
                        Text(file),
                        Hex(rc),
                        self.words(rc)
                    ),
                ));
            }
        } else if let Some(blob) = o.key_blob.as_deref() {
            // The library reads PEM only with a zero byte after it,
            // counted; DER only without.
            let ended = c_string(blob)?;
            let len = if is_der(o.key_type.as_deref()) {
                blob.len()
            } else {
                blob.len() + 1
            };
            // The password up to a zero byte in it, as C's `strlen`.
            let password = password.map(|p| p.split(|&b| b == 0).next().unwrap_or_default());
            let conn = self.conn();
            let mut rc = conn.key_parse(&ended[..len], password);
            if rc == 0 && !conn.key_signs() {
                rc = sys::MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            if rc != 0 {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "mbedTLS: error parsing private key: ({}) {}",
                        Hex(rc),
                        self.words(rc)
                    ),
                ));
            }
        }
        Ok(())
    }

    /// The revocation list, from its file (`mbed_load_crl`).
    fn load_crl(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let identity = self.identity.clone();
        if let Some(file) = identity.options.crl_file.as_deref() {
            let name = c_string(file)?;
            let rc = self.conn().crl_parse_file(as_c(&name));
            if rc != 0 {
                return Err(io.fail(
                    ErrorKind::SslCrlBadfile,
                    format_args!(
                        "mbedTLS: error reading CRL file {}: ({}) {}",
                        Text(file),
                        Hex(rc),
                        self.words(rc)
                    ),
                ));
            }
        }
        Ok(())
    }

    /// The configuration and the context set up (`mbed_configure_ssl`).
    fn configure(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        io.info(format_args!(
            "mbedTLS: Connecting to {}:{}",
            Text(&self.host),
            self.port
        ));
        if self.conn().defaults() != 0 {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("mbedTLS: ssl_config failed"),
            ));
        }
        let conn = self.conn();
        conn.signal_tickets();
        // The library always checks the peer; the callback clears the
        // flags of the checks that are off, and says what is left.
        conn.verify_hook();
        conn.verify_required();
        self.initialized = true;
        self.conn().profile_next();
        let o = &self.identity.options;
        let (min, max) = (o.min_version, o.max_version);
        let min = match min {
            TlsMinVersion::Tls1
            | TlsMinVersion::Tls1_0
            | TlsMinVersion::Tls1_1
            | TlsMinVersion::Tls1_2 => sys::MBEDTLS_SSL_VERSION_TLS1_2,
            TlsMinVersion::Tls1_3 => sys::MBEDTLS_SSL_VERSION_TLS1_3,
        };
        let max = match max {
            TlsMaxVersion::None | TlsMaxVersion::Default | TlsMaxVersion::Tls1_3 => {
                sys::MBEDTLS_SSL_VERSION_TLS1_3
            }
            TlsMaxVersion::Tls1_2 => sys::MBEDTLS_SSL_VERSION_TLS1_2,
            TlsMaxVersion::Tls1_1 | TlsMaxVersion::Tls1_0 => {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("mbedTLS: unsupported maximum TLS version value"),
                ));
            }
        };
        let conn = self.conn();
        conn.versions(min, max);
        conn.use_rng();
        let rc = conn.setup();
        if rc != 0 {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!(
                    "mbedTLS: ssl_setup failed: ({}) {}",
                    Hex(rc),
                    self.words(rc)
                ),
            ));
        }
        self.conn().bio();
        let identity = self.identity.clone();
        let o = &identity.options;
        if o.ciphers.is_some() || o.tls13_ciphers.is_some() {
            let chosen = crate::suites::select(
                self.lib,
                io,
                o.ciphers.as_deref(),
                o.tls13_ciphers.as_deref(),
            )
            .and_then(|suites| {
                self.conn()
                    .ciphersuites(suites)
                    .map_err(|OutOfMemory| ErrorKind::OutOfMemory)
            });
            if let Err(kind) = chosen {
                io.fail(kind, format_args!("mbedTLS: failed to set cipher suites"));
                return Err(kind);
            }
        } else {
            self.conn().default_ciphersuites();
        }
        let conn = self.conn();
        conn.renegotiation();
        conn.tickets_off();
        self.resume(io);
        let conn = self.conn();
        conn.ca_chain();
        if o.key.is_some() || o.key_blob.is_some() {
            conn.own_cert();
        }
        // The name the certificate is checked against and SNI sends: the
        // host's for an address too.
        let sni = curl_core::tls::sni(&self.host, self.kind)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        let name = c_string(sni.as_deref().unwrap_or(&self.host))?;
        if self.conn().hostname(as_c(&name)) != 0 {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("Failed to set SNI"),
            ));
        }
        if let Some(offer) = self.alpn.offer() {
            let mut names = Vec::new();
            for name in self.alpn.names() {
                names
                    .try_push(name)
                    .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
            }
            let rc = self
                .conn()
                .alpn(&names)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
            if rc != 0 {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("Failed setting ALPN protocols"),
                ));
            }
            io.info(format_args!("ALPN: curl offers {offer}"));
        }
        // The application's turn at the configuration (`ssl_fsslctx`).
        if io.configures_context() {
            let conn = self.conn();
            let native = TlsNative::new(TlsKind::MbedTls, conn.config(), Some(conn.native()));
            io.configure_context(native)?;
        }
        Ok(())
    }

    /// Resume FTP's control connection's session, or else one the cache
    /// kept for the peer (`mbed_configure_ssl`, `mbed_apply_session`).
    fn resume(&mut self, io: &mut TlsCx<'_>) {
        let mut applied = false;
        if let Some(given) = io.take_given_session()
            && self.apply(io, &given)
        {
            io.trace(format_args!("applied SSL session from control connection"));
            applied = true;
        }
        if !applied && io.caches_sessions() {
            let taken = io.take_session();
            if let Some(ticket) = taken.as_ref() {
                self.apply(io, ticket);
            }
            io.return_session(taken);
        }
    }

    /// Resume `ticket`, if it has a session, saying how it went: whether
    /// it was resumed.
    fn apply(&mut self, io: &mut TlsCx<'_>, ticket: &TlsTicket) -> bool {
        if ticket.data.is_empty() {
            return false;
        }
        match self.conn().resume(&ticket.data) {
            Resume::Done => {
                io.info(format_args!("SSL reusing session ID"));
                true
            }
            Resume::Load(rc) => {
                io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("SSL session error loading: {}", LowHex(rc)),
                );
                false
            }
            Resume::Set(rc) => {
                io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("SSL session error setting: {}", LowHex(rc)),
                );
                false
            }
        }
    }

    /// Move the handshake on, then check the pinned key and take what the
    /// peer chose (`mbed_connect_step2`).
    fn step2(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        let rc = self.call(io, |c, call| c.handshake(call));
        match rc {
            sys::MBEDTLS_ERR_SSL_WANT_READ => {
                self.waits = TlsWait::Recv;
                return Ok(Handshake::Waiting);
            }
            sys::MBEDTLS_ERR_SSL_WANT_WRITE => {
                self.waits = TlsWait::Send;
                return Ok(Handshake::Waiting);
            }
            sys::MBEDTLS_ERR_X509_CERT_VERIFY_FAILED => {
                return Err(io.fail(
                    ErrorKind::PeerFailedVerification,
                    format_args!("peer certificate could not be verified"),
                ));
            }
            0 => {}
            rc => {
                let version = self.conn().version();
                io.trace(format_args!("TLS version {version:04X}"));
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("ssl_handshake returned: ({}) {}", Hex(rc), self.words(rc)),
                ));
            }
        }
        let conn = self.conn();
        let id = u16::try_from(conn.suite()).unwrap_or_default();
        let version = conn.version_name();
        io.info(format_args!(
            "mbedTLS: {} Handshake complete, cipher is {}",
            Text(version),
            crate::suites::name(id, true)
        ));
        let identity = self.identity.clone();
        if let Some(pinned) = identity.options.pinned_key.as_deref() {
            let conn = self.conn.as_ref().expect("made at the first step");
            crate::verify::pinned_key(self.lib, io, conn.peer_cert(), pinned)?;
        }
        if self.alpn != Alpn::None {
            let conn = self.conn.as_ref().expect("made at the first step");
            let chosen = conn.alpn_selected().unwrap_or_default();
            curl_core::tls::alpn_negotiated(io, None, chosen)?;
            if !chosen.is_empty() {
                self.negotiated = Chosen::named(chosen);
            }
        }
        io.info(format_args!("SSL connected"));
        Ok(Handshake::Done)
    }

    /// Keep the connection's session in the transfer's cache, if it keeps
    /// them (`mbed_new_session`). Only failing to get it fails.
    fn new_session(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        if !io.caches_sessions() {
            return Ok(());
        }
        let saved = self
            .conn()
            .saved()
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        match saved {
            Saved::GetFailed(rc) => Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("mbedtls_ssl_get_session returned {}", LowHex(rc)),
            )),
            Saved::Empty => {
                io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("failed to serialize session: length is 0"),
                );
                Ok(())
            }
            Saved::SaveFailed(rc) => {
                io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("failed to serialize session: {}", LowHex(rc)),
                );
                Ok(())
            }
            Saved::Data(data) => {
                let version = u16::try_from(self.conn().version()).unwrap_or_default();
                io.keep_session(TlsTicket::new(data, version, self.negotiated, 0, 0));
                Ok(())
            }
        }
    }

    /// The steps of `mbedtls_connect`.
    fn connect(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        if self.step == Step::One {
            self.step1(io)?;
            self.step = Step::Two;
        }
        if self.step == Step::Two {
            if self.step2(io)? == Handshake::Waiting {
                return Ok(Handshake::Waiting);
            }
            self.step = Step::Three;
        }
        // TLS 1.3 tells of its sessions as they come.
        if self.conn().version() <= sys::MBEDTLS_SSL_VERSION_TLS1_2 {
            self.new_session(io)?;
        }
        self.step = Step::Done;
        Ok(Handshake::Done)
    }

    /// The goodbye (`mbedtls_shutdown`): `Ok(true)` once over.
    fn goodbye(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<bool, ErrorKind> {
        if !self.sent_shutdown {
            // Only once.
            self.sent_shutdown = true;
            if goodbye.sends() {
                match self.call(io, |c, call| c.close_notify(call)) {
                    0 => {}
                    sys::MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => return Ok(true),
                    sys::MBEDTLS_ERR_SSL_WANT_READ => {
                        self.waits = TlsWait::Recv;
                        return Ok(false);
                    }
                    sys::MBEDTLS_ERR_SSL_WANT_WRITE => {
                        self.waits = TlsWait::Send;
                        return Ok(false);
                    }
                    rc => {
                        io.trace(format_args!("mbedtls_shutdown error {}", Hex(rc)));
                        return Err(ErrorKind::RecvError);
                    }
                }
            }
        }
        let mut buf = [0u8; 1024];
        let mut rc = 0;
        for _ in 0..10 {
            rc = self.call(io, |c, call| c.read(call, &mut buf));
            // The library may say it wants to read without having been
            // told to wait (TLS 1.3): it is asked again.
            if rc == sys::MBEDTLS_ERR_SSL_WANT_READ {
                rc = self.call(io, |c, call| c.read(call, &mut buf));
            }
            if rc == sys::MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET {
                continue;
            }
            if rc <= 0 {
                break;
            }
        }
        if rc > 0 {
            io.trace(format_args!("mbedtls_shutdown, still getting data"));
            Ok(false)
        } else if rc == 0 || rc == sys::MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY {
            io.trace(format_args!("mbedtls_shutdown done"));
            Ok(true)
        } else if rc == sys::MBEDTLS_ERR_SSL_WANT_READ {
            io.trace(format_args!("mbedtls_shutdown, need RECV"));
            self.waits = TlsWait::Recv;
            Ok(false)
        } else if rc == sys::MBEDTLS_ERR_SSL_WANT_WRITE {
            io.trace(format_args!("mbedtls_shutdown, need SEND"));
            self.waits = TlsWait::Send;
            Ok(false)
        } else {
            io.trace(format_args!("mbedtls_shutdown error {}", Hex(rc)));
            Err(ErrorKind::RecvError)
        }
    }
}

/// The type names DER (`curl_strequal(type, "DER")`).
fn is_der(kind: Option<&[u8]>) -> bool {
    kind.is_some_and(|t| t.eq_ignore_ascii_case(b"DER"))
}

/// An error the session said why it failed for, or that C's says nothing
/// of: what the core reads as the read's or the send's failure.
fn said() -> io::Error {
    io::ErrorKind::Other.into()
}

impl<G: Mbedtls> TlsSession for Session<G>
where
    G::Conn: Send,
{
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        if self.step == Step::Done {
            return Ok(Handshake::Done);
        }
        self.waits = TlsWait::Nothing;
        self.connect(io)
    }

    fn recv(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        loop {
            self.waits = TlsWait::Nothing;
            let len = buf.len();
            let n = self.call(io, |c, call| c.read(call, buf));
            if n > 0 {
                let n = usize::try_from(n).expect("positive");
                return Ok(Recv::Data(NonZeroUsize::new(n).expect("positive")));
            }
            io.trace(format_args!("mbedtls_ssl_read(len={len}) -> {}", Hex(n)));
            match n {
                sys::MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => {
                    // Not a wait: read on, until a real answer comes.
                    if self.new_session(io).is_err() {
                        return Err(said());
                    }
                }
                sys::MBEDTLS_ERR_SSL_WANT_READ => {
                    self.waits = TlsWait::Recv;
                    return Ok(Recv::WouldBlock);
                }
                sys::MBEDTLS_ERR_SSL_WANT_WRITE => {
                    self.waits = TlsWait::Send;
                    return Ok(Recv::WouldBlock);
                }
                sys::MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => return Ok(Recv::Eof),
                rc => {
                    io.fail(
                        ErrorKind::RecvError,
                        format_args!("ssl_read returned: ({}) {}", Hex(rc), self.words(rc)),
                    );
                    return Err(said());
                }
            }
        }
    }

    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent> {
        loop {
            self.waits = TlsWait::Nothing;
            let mut len = bytes.len();
            // The library wants a write that would have blocked made again
            // with as many bytes, or it loses some.
            if let Some(blocked) = self.send_blocked {
                if blocked > len {
                    io.fail(
                        ErrorKind::BadFunctionArgument,
                        format_args!("re-send data shorter than previously"),
                    );
                    io.trace(format_args!(
                        "mbedtls_ssl_write(len={len}) -> {}, 0",
                        ErrorKind::BadFunctionArgument.number()
                    ));
                    return Err(said());
                }
                io.trace(format_args!(
                    "mbedtls_ssl_write(len={len}) -> previously blocked on {blocked} bytes"
                ));
                len = blocked;
            }
            let n = self.call(io, |c, call| c.write(call, &bytes[..len]));
            let (got, code, written) = if n >= 0 {
                self.send_blocked = None;
                let n = usize::try_from(n).expect("not negative");
                let got = match NonZeroUsize::new(n) {
                    Some(n) => Sent::Bytes(n),
                    None => Sent::WouldBlock,
                };
                (Ok(got), 0, n)
            } else {
                io.trace(format_args!("mbedtls_ssl_write(len={len}) -> {}", Hex(n)));
                let wait = match n {
                    sys::MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => {
                        // Not a wait: send on, until a real answer comes.
                        match self.new_session(io) {
                            Ok(()) => continue,
                            Err(kind) => {
                                io.trace(format_args!(
                                    "mbedtls_ssl_write(len={len}) -> {}, 0",
                                    kind.number()
                                ));
                                return Err(said());
                            }
                        }
                    }
                    sys::MBEDTLS_ERR_SSL_WANT_READ => Some(TlsWait::Recv),
                    sys::MBEDTLS_ERR_SSL_WANT_WRITE => Some(TlsWait::Send),
                    _ => None,
                };
                match wait {
                    Some(wait) => {
                        self.waits = wait;
                        if self.send_blocked.is_none() {
                            self.send_blocked = Some(len);
                        }
                        (Ok(Sent::WouldBlock), AGAIN, 0)
                    }
                    None => (Err(said()), ErrorKind::SendError.number(), 0),
                }
            };
            io.trace(format_args!(
                "mbedtls_ssl_write(len={len}) -> {code}, {written}"
            ));
            return got;
        }
    }

    fn shutdown(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<Handshake, ErrorKind> {
        if !self.initialized || self.shut {
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
        self.conn
            .as_ref()
            .is_some_and(crate::library::Conn::pending)
    }

    fn chosen(&self) -> Option<Chosen> {
        self.negotiated
    }

    /// The `mbedtls_ssl_context`, as C hands it out for both the session
    /// and the context (`mbedtls_get_internals`).
    fn native(&self) -> Option<TlsNative> {
        let s = self.conn.as_ref()?.native();
        Some(TlsNative::new(TlsKind::MbedTls, s, Some(s)))
    }

    /// None: C's mbedTLS build makes no channel binding
    /// (`get_channel_binding` is NULL).
    fn channel_binding(&self, _: &mut dyn BindingNotes) -> Result<Option<Vec<u8>>, ErrorKind> {
        Ok(None)
    }
}
