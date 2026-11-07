//! One connection's GnuTLS (`lib/vtls/gtls.c`): its session made at the
//! handshake's first step as C makes it (`gtls_connect_step1`,
//! `Curl_gtls_ctx_init`, `gtls_client_init`), resuming one the cache
//! kept, the handshake (`cf_gtls_handshake`), the peer checked
//! (`gtls_verifyserver`), then the records both ways (`gtls_recv`,
//! `gtls_send`) and the goodbye (`gtls_shutdown`); early data sent in a
//! handshake put off for it (`gtls_send_earlydata`).

use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::time::Instant;
use curl_core::tls::{
    Alpn, BindingNotes, Chosen, Deferred, Goodbye, Handshake, SharedKeyLog, TlsCx, TlsIdentity,
    TlsIo, TlsNative, TlsPeer, TlsPeerKind, TlsSession, TlsShared, TlsTicket, TlsWait,
};

use crate::library::{
    self, AGAIN, Call, Creds as _, Format, Gnutls, IoResult, Rc, Session as _, as_c, c_string,
    strerror,
};
use crate::sys;
use crate::trust;
use crate::verify;
use curl_core::tls::Text;

/// The most early data a handshake holds to send (`CURL_SSL_EARLY_MAX`).
const EARLY_MOST: usize = 64 * 1024;

/// What the library says of a session that allows no early data, and of
/// one it cannot tell (gnutls/gnutls#1619).
const EARLY_UNKNOWN: usize = 0xFFFF_FFFF;

/// How far a session's handshake has come (`connecting_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Nothing made yet: the session is made at the first step.
    Init,
    /// The handshake runs.
    Handshake,
    /// The handshake is done; the peer is to be checked.
    Check,
    Done,
}

/// Where a handshake put off for early data is (`earlydata_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Early {
    /// None put off, or it waits for its early data.
    None,
    /// Handing it to the library, this much handed.
    Sending(usize),
    /// Handed, the handshake going on.
    Sent,
    /// The handshake is done, the peer taking the early data or not.
    Over { accepted: bool },
}

/// One connection's GnuTLS, through the library `G`.
pub(crate) struct Session<G: Gnutls> {
    lib: &'static G,
    // Dropped in this order: the library's session, which points at its
    // credentials, before them.
    gs: Option<G::Session>,
    creds: Option<TryArc<G::Creds>>,
    /// When the credentials were made (`shared_creds->time`).
    made: Option<Instant>,
    /// The credentials' anchors are set up (`trust_setup`).
    trust_ready: bool,
    identity: TryArc<TlsIdentity>,
    /// What the library keeps for the multi, until the trust is set up.
    shared: Option<TlsShared>,
    /// The origin's name as the URL gives it, without brackets.
    host: Vec<u8>,
    kind: TlsPeerKind,
    /// The protocols offered, and the one the session resumed restricts
    /// the offer to (`Curl_alpn_restrict_to`).
    alpn: Alpn,
    restricted: Option<Chosen>,
    step: Step,
    waits: TlsWait,
    /// The goodbye was sent (`sent_shutdown`), and it is over or failed
    /// (the filter's `shutdown`).
    sent_shutdown: bool,
    shut: bool,
    keylog: Option<SharedKeyLog>,
    /// The transfer may send early data.
    early_data: bool,
    /// The handshake is put off for early data (`ssl_connection_deferred`).
    deferred: Option<Deferred>,
    early: Early,
    /// What ALPN agreed (`connssl->negotiated.alpn`).
    negotiated: Option<Chosen>,
}

impl<G: Gnutls> Session<G> {
    /// A session for one connection to `peer`, nothing of the library's
    /// made yet.
    pub(crate) fn new(
        lib: &'static G,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        shared: &TlsShared,
        keylog: Option<SharedKeyLog>,
    ) -> Result<Session<G>, ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(peer.name)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        Ok(Session {
            lib,
            gs: None,
            creds: None,
            made: None,
            trust_ready: false,
            identity: identity.clone(),
            shared: Some(shared.clone()),
            host,
            kind: peer.kind,
            alpn,
            restricted: None,
            step: Step::Init,
            waits: TlsWait::Nothing,
            sent_shutdown: false,
            shut: false,
            keylog,
            early_data: peer.early_data,
            deferred: None,
            early: Early::None,
            negotiated: None,
        })
    }

    /// The name sent by SNI (`Curl_ssl_peer_init`).
    fn sni(&self) -> Result<Option<Vec<u8>>, ErrorKind> {
        curl_core::tls::sni(&self.host, self.kind).map_err(|OutOfMemory| ErrorKind::OutOfMemory)
    }

    /// Set the trust up outside a call into the library
    /// (`Curl_gtls_client_trust_setup`).
    fn trust_setup(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let gs = self.gs.as_mut().expect("made at the first step");
        let creds = self.creds.as_mut().expect("made with the session");
        let made = self.made.expect("made with the credentials");
        let mut set = |c: &G::Creds| gs.credentials(c);
        trust::setup(
            self.lib,
            &self.identity,
            self.shared.as_ref(),
            creds,
            made,
            io,
            &mut set,
        )?;
        self.trust_ready = true;
        // Not needed past the trust: the connection does not keep the
        // multi's state alive, wherever it goes.
        self.shared = None;
        Ok(())
    }

    /// Run `op`, a call into the library on the session, with its
    /// callbacks reaching `io`: what the last read or write below came to
    /// after it.
    fn call<R>(
        &mut self,
        io: &mut TlsIo<'_>,
        op: impl FnOnce(&mut G::Session, &mut Call<'_, '_, G::Creds>) -> R,
    ) -> (R, IoResult) {
        let Session {
            lib,
            gs,
            creds,
            made,
            trust_ready,
            identity,
            shared,
            keylog,
            negotiated,
            ..
        } = self;
        let lib = *lib;
        let gs = gs.as_mut().expect("made at the first step");
        let creds = creds.as_mut().expect("made with the session");
        let made = made.expect("made with the credentials");
        let shared = shared.as_ref();
        let mut setup = |cx: &mut TlsCx<'_>, set: library::SetCreds<'_, G::Creds>| {
            trust::setup(lib, identity, shared, creds, made, cx, set)
        };
        let keylog = keylog
            .as_deref()
            .filter(|l| curl_core::tls::KeyLog::enabled(l));
        let mut call = Call {
            io,
            io_result: IoResult::Ok,
            trust: Some(&mut setup),
            trust_ready: *trust_ready,
            keylog,
            alpn: *negotiated,
        };
        let r = op(gs, &mut call);
        let (ready, result) = (call.trust_ready, call.io_result);
        *trust_ready = ready;
        if ready {
            self.shared = None;
        }
        (r, result)
    }

    /// Make the session (`gtls_connect_step1`).
    fn step1(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        let given = io.take_given_session();
        let mut setup = false;
        if let Some(ticket) = given {
            setup = self.apply_session(io, &ticket)?;
            if setup {
                io.trace(format_args!("applied SSL session from control connection"));
            }
        }
        let mut taken = None;
        let o = &self.identity.options;
        if !setup && o.session_cache && !o.verify_status {
            taken = io.take_session();
            if let Some(ticket) = taken.as_ref() {
                match self.apply_session(io, ticket) {
                    Ok(s) => setup = s,
                    Err(kind) => {
                        io.return_session(taken);
                        return Err(kind);
                    }
                }
            }
        }
        let made = if setup {
            Ok(())
        } else {
            self.client_init(io, 0)
        };
        let made = made.and_then(|()| self.finish_init(io));
        io.return_session(taken);
        made?;
        if self.deferred.is_none()
            && let Some(offer) = self.alpn.offer()
        {
            io.info(format_args!("ALPN: curl offers {offer}"));
        }
        self.gs.as_mut().expect("made above").hook();
        Ok(())
    }

    /// What follows the session's making in `Curl_gtls_ctx_init`: the key
    /// log, and the ALPN offer.
    fn finish_init(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let gs = self.gs.as_mut().expect("made by the client's init");
        // Opened unless it is, by whichever library asks first
        // (`Curl_tls_keylog_open`).
        if let Some(log) = self.keylog.as_deref() {
            log.open();
            if log.enabled() {
                gs.log_keys();
            }
        }
        let restricted;
        let protocols: Vec<&[u8]> = match self.restricted {
            Some(c) => {
                restricted = [c.name().as_bytes()];
                let mut v = Vec::new();
                v.try_extend_from_slice(&restricted)
                    .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
                v
            }
            None => {
                let mut names = Vec::new();
                for name in self.alpn.names() {
                    names
                        .try_push(name)
                        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
                }
                names
            }
        };
        if !protocols.is_empty() && gs.alpn(&protocols) != 0 {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("failed setting ALPN"),
            ));
        }
        Ok(())
    }

    /// Make the session resuming `ticket`, if the transfer offers what it
    /// agreed (`gtls_apply_session`): whether it was made.
    fn apply_session(&mut self, io: &mut TlsCx<'_>, ticket: &TlsTicket) -> Result<bool, ErrorKind> {
        let offered = match ticket.alpn_name() {
            None => true,
            Some(_) => ticket.chosen().is_some_and(|c| self.alpn.offers(c)),
        };
        if ticket.data.is_empty() || !offered {
            return Ok(false);
        }
        self.client_init(io, ticket.earlydata_max)?;
        let gs = self.gs.as_mut().expect("made above");
        if gs.set_data(&ticket.data) < 0 {
            io.info(format_args!(
                "SSL session not accepted by GnuTLS, continuing without"
            ));
            return Ok(true);
        }
        let alpn = ticket.alpn_name().unwrap_or(b"-");
        io.info_with(&[b"SSL reusing session with ALPN '", alpn, b"'"]);
        if self.early_data
            && let Some(chosen) = ticket.chosen()
        {
            // `gtls_on_session_reuse`: what the library says the session
            // allows, which it cannot tell from none.
            let most = gs.max_early_data();
            let allowed = most != 0 && most != EARLY_UNKNOWN;
            self.defer(allowed, most, chosen, io);
        }
        Ok(true)
    }

    /// Put the handshake off for early data, resuming a session that
    /// allows `most` bytes of it, if `allowed`, and agreed `chosen` by
    /// ALPN, if the transfer offers it (`Curl_on_session_reuse`).
    fn defer(&mut self, allowed: bool, most: usize, chosen: Chosen, io: &mut TlsCx<'_>) {
        if !allowed {
            io.trace(format_args!("SSL session does not allow earlydata"));
        } else if !self.alpn.offers(chosen) {
            io.trace(format_args!(
                "SSL session has different ALPN, no early data"
            ));
        } else {
            let name = chosen.name();
            io.info(format_args!(
                "SSL session allows {most} bytes of early data, reusing ALPN '{name}'"
            ));
            self.deferred = Some(Deferred {
                most: most.min(EARLY_MOST),
                alpn: chosen,
            });
            self.negotiated = Some(chosen);
            io.info(format_args!(
                "ALPN: deferred handshake for early data using '{name}'."
            ));
            self.restricted = Some(chosen);
        }
    }

    /// Make the library's credentials and session (`gtls_client_init`),
    /// for a session the cache kept allowing `early_max` bytes of early
    /// data, if any.
    fn client_init(&mut self, io: &mut TlsCx<'_>, early_max: usize) -> Result<(), ErrorKind> {
        let lib = self.lib;
        let creds = lib.creds().map_err(|rc| {
            io.fail(
                ErrorKind::SslConnectError,
                format_args!(
                    "gnutls_certificate_allocate_credentials() failed: {}",
                    strerror(lib, rc)
                ),
            )
        })?;
        let creds = TryArc::try_new(creds).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        self.creds = Some(creds);
        self.made = Some(io.now());
        io.verified(0);
        let mut flags = sys::GNUTLS_CLIENT | sys::GNUTLS_FORCE_CLIENT_CERT;
        if early_max > 0 && early_max != EARLY_UNKNOWN {
            flags |= sys::GNUTLS_ENABLE_EARLY_DATA;
        }
        io.trace(format_args!(
            "gnutls_init(flags={flags:x}), earlydata={early_max}"
        ));
        let gs = lib.session(flags).map_err(|rc| {
            io.fail(
                ErrorKind::SslConnectError,
                format_args!("gnutls_init() failed: {rc}"),
            )
        })?;
        self.gs = Some(gs);
        let sni = self.sni()?;
        let gs = self.gs.as_mut().expect("made above");
        if let Some(sni) = sni
            && gs.server_name(&sni) < 0
        {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("Failed to set SNI"),
            ));
        }
        if gs.default_priority() != 0 {
            return Err(ErrorKind::SslConnectError);
        }
        let o = &self.identity.options;
        let Some(base) = crate::priority::versions(o.min_version, o.max_version) else {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("GnuTLS: cannot set TLS protocol"),
            ));
        };
        let priority = crate::priority::string(base, o.ciphers.as_deref())?;
        let priority = as_c(&priority);
        io.info(format_args!(
            "GnuTLS priority: {}",
            Text(priority.to_bytes())
        ));
        if let Err((rc, at)) = gs.priority(priority) {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!(
                    "Error {rc} setting GnuTLS priority: {}",
                    Text(at.unwrap_or(b"(nil)"))
                ),
            ));
        }
        let identity = self.identity.clone();
        if let Some(cert) = identity.options.cert.as_deref() {
            if !self.trust_ready {
                self.trust_setup(io)?;
            }
            self.client_cert(io, cert)?;
        }
        let gs = self.gs.as_mut().expect("made above");
        let creds = self.creds.as_ref().expect("made above");
        let rc = gs.credentials(creds);
        if rc != 0 {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("gnutls_credentials_set() failed: {}", strerror(lib, rc)),
            ));
        }
        if self.identity.options.verify_status {
            let rc = gs.status_request();
            if rc != 0 {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("gnutls_ocsp_status_request_enable_client() failed: {rc}"),
                ));
            }
        }
        Ok(())
    }

    /// The client's certificate and key, from their files, into the
    /// credentials (`gtls_client_init`): PKCS #12 or, of the certificate's
    /// type, PEM or DER.
    fn client_cert(&mut self, io: &mut TlsCx<'_>, cert: &[u8]) -> Result<(), ErrorKind> {
        let lib = self.lib;
        let o = &self.identity.options;
        let creds = self.creds.as_ref().expect("made with the session");
        let name = c_string(cert)?;
        let password = o.key_password.as_deref().map(c_string).transpose()?;
        let p12 = o
            .cert_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case(b"P12"));
        if p12 {
            let pass = password.as_deref().map_or(c"", as_c);
            let rc = creds.pkcs12_file(as_c(&name), pass);
            if rc != 0 {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!(
                        "error reading X.509 potentially-encrypted key or certificate file: {}",
                        strerror(lib, rc)
                    ),
                ));
            }
            return Ok(());
        }
        let key = o.key.as_deref().map(c_string).transpose()?;
        let format = match o.cert_type.as_deref() {
            Some(t) if t.eq_ignore_ascii_case(b"DER") => Format::Der,
            _ => Format::Pem,
        };
        let rc = creds.key_file(
            as_c(&name),
            key.as_deref().map_or(as_c(&name), as_c),
            format,
            password.as_deref().map(as_c),
        );
        if rc != 0 {
            let encrypted = if password.is_some() {
                "potentially-encrypted "
            } else {
                ""
            };
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!(
                    "error reading X.509 {encrypted}key file: {}",
                    strerror(lib, rc)
                ),
            ));
        }
        Ok(())
    }

    /// Move the handshake on (`cf_gtls_handshake`).
    fn handshake_step(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        self.waits = TlsWait::Nothing;
        let (rc, result) = self.call(io, |gs, call| gs.handshake(call));
        if !self.trust_ready {
            // The ClientHello went out without a read: the trust is set
            // up for the certificate to come.
            self.trust_setup(io)?;
        }
        let lib = self.lib;
        let gs = self.gs.as_mut().expect("made at the first step");
        if rc == sys::GNUTLS_E_AGAIN || rc == sys::GNUTLS_E_INTERRUPTED {
            self.waits = if gs.wants_write() {
                TlsWait::Send
            } else {
                TlsWait::Recv
            };
            return Ok(Handshake::Waiting);
        }
        if rc < 0 && !lib.is_fatal(rc) {
            let alert = if rc == sys::GNUTLS_E_WARNING_ALERT_RECEIVED {
                gs.alert_name()
            } else {
                None
            };
            let why = alert.unwrap_or_else(|| lib.strerror(rc));
            io.info(format_args!("gnutls_handshake() warning: {}", Text(why)));
            return Ok(Handshake::Waiting);
        }
        if rc < 0
            && let Some(kind) = result.failure()
        {
            return Err(kind);
        }
        if rc < 0 {
            let alert = if rc == sys::GNUTLS_E_FATAL_ALERT_RECEIVED {
                gs.alert_name()
            } else {
                None
            };
            let why = alert.unwrap_or_else(|| lib.strerror(rc));
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("GnuTLS, handshake failed: {}", Text(why)),
            ));
        }
        Ok(Handshake::Done)
    }

    /// The handshake's outcome said (`Curl_gtls_report_handshake`).
    fn report_handshake(&mut self, io: &mut TlsCx<'_>) {
        if !io.verbose() {
            return;
        }
        let gs = self.gs.as_mut().expect("made at the first step");
        let suite = gs.suite_name();
        let version = gs.version_name();
        io.info(format_args!(
            "SSL connection using {} / {}",
            Text(version.unwrap_or(b"(nil)")),
            Text(suite.unwrap_or(b"(nil)"))
        ));
    }

    /// The peer checked, and before TLS 1.3 its session kept, which TLS
    /// 1.3 gives later (`gtls_verifyserver`).
    fn verify_server(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let sni = self.sni()?;
        let peer = verify::Peer {
            name: &self.host,
            sni: sni.as_deref(),
        };
        let gs = self.gs.as_mut().expect("made at the first step");
        let now = io.unix_time();
        verify::verify_server(self.lib, gs, &self.identity, &peer, now, io)?;
        if gs.version() < sys::GNUTLS_TLS1_3 && io.caches_sessions() {
            let data = gs.data()?;
            let (version, early) = (gs.version(), gs.max_early_data());
            library::keep_ticket(io, data, version, early, self.negotiated);
        }
        Ok(())
    }

    /// What the peer chose of the ALPN offer (`Curl_alpn_set_negotiated`).
    fn negotiate(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let gs = self.gs.as_mut().expect("made at the first step");
        let chosen = gs.alpn_selected();
        let asked = self.deferred.map(|d| d.alpn.name().as_bytes());
        curl_core::tls::alpn_negotiated(io, asked, chosen)?;
        if asked.is_none() && !chosen.is_empty() {
            self.negotiated = Chosen::named(chosen);
        }
        Ok(())
    }

    /// Hand `early` to the library as early data, from `sent` on
    /// (`gtls_send_earlydata`): done, or waiting with what went kept.
    fn send_early(
        &mut self,
        io: &mut TlsIo<'_>,
        early: &[u8],
        mut sent: usize,
    ) -> Result<Handshake, ErrorKind> {
        while sent < early.len() {
            let rest = &early[sent..];
            let (n, result) = self.call(io, |gs, call| gs.send_early(call, rest));
            io.trace(format_args!(
                "gtls_send_earlydata(len={}) -> {n}",
                rest.len()
            ));
            if n < 0 {
                self.early = Early::Sending(sent);
                if n == sys::GNUTLS_E_AGAIN as isize {
                    return Ok(Handshake::Waiting);
                }
                return Err(result.failure().unwrap_or(ErrorKind::SendError));
            }
            // GnuTLS answers 0 for all it took.
            let n = if n == 0 {
                rest.len()
            } else {
                usize::try_from(n).expect("positive")
            };
            sent += n.min(rest.len());
        }
        io.info(format_args!(
            "SSL sending {} bytes of early data",
            early.len()
        ));
        self.early = Early::Sent;
        Ok(Handshake::Done)
    }

    /// The library's direction, as what the session waits for.
    fn direction(&mut self) -> TlsWait {
        let gs = self.gs.as_mut().expect("made at the first step");
        if gs.wants_write() {
            TlsWait::Send
        } else {
            TlsWait::Recv
        }
    }

    /// The goodbye (`gtls_shutdown`): `Ok(true)` once over.
    fn goodbye(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<bool, ErrorKind> {
        let lib = self.lib;
        if !self.sent_shutdown {
            self.sent_shutdown = true;
            if goodbye.sends() {
                let (rc, _) = self.call(io, |gs, call| gs.bye(call));
                if rc == sys::GNUTLS_E_AGAIN || rc == sys::GNUTLS_E_INTERRUPTED {
                    io.trace(format_args!("SSL shutdown, gnutls_bye EAGAIN"));
                    self.waits = self.direction();
                    self.sent_shutdown = false;
                    return Ok(false);
                }
                if rc != 0 {
                    io.trace(format_args!(
                        "SSL shutdown, gnutls_bye error: '{}'({rc})",
                        strerror(lib, rc)
                    ));
                    return Err(ErrorKind::RecvError);
                }
            }
        }
        let mut buf = [0u8; 1024];
        let mut nread = 0;
        for _ in 0..10 {
            (nread, _) = self.call(io, |gs, call| gs.recv(call, &mut buf));
            if nread <= 0 {
                break;
            }
        }
        if nread > 0 {
            // Still data coming in.
            Ok(false)
        } else if nread == 0 {
            Ok(true)
        } else if nread == sys::GNUTLS_E_AGAIN as isize
            || nread == sys::GNUTLS_E_INTERRUPTED as isize
        {
            self.waits = self.direction();
            Ok(false)
        } else {
            let rc = Rc::try_from(nread).unwrap_or(Rc::MIN);
            io.trace(format_args!(
                "SSL shutdown, error: '{}'({rc})",
                strerror(lib, rc)
            ));
            Err(ErrorKind::RecvError)
        }
    }
}

/// An error the session said why it failed for: what the core reads as
/// the read's or the send's failure, its reason given already.
fn said() -> io::Error {
    io::ErrorKind::Other.into()
}

impl<G: Gnutls> TlsSession for Session<G>
where
    G::Session: Send,
{
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        if self.step == Step::Done {
            return Ok(Handshake::Done);
        }
        self.waits = TlsWait::Nothing;
        let done = self.connect(io);
        match &done {
            Ok(Handshake::Waiting) => {}
            Ok(Handshake::Done) => io.trace(format_args!("gtls_connect_common() -> 0, done=1")),
            Err(kind) => io.trace(format_args!(
                "gtls_connect_common() -> {}, done=0",
                kind.number()
            )),
        }
        if matches!(done, Ok(Handshake::Done))
            && self.step == Step::Done
            && let Some(log) = &self.keylog
        {
            log.with_name(|name| {
                io.info(format_args!(
                    "SSLKEYLOGFILE set, all TLS secrets are logged to '{}'",
                    Text(name)
                ));
            });
        }
        done
    }

    fn recv(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        let lib = self.lib;
        let len = buf.len();
        let (nread, result) = self.call(io, |gs, call| gs.recv(call, buf));
        let (got, code) = if nread > 0 {
            let n = usize::try_from(nread).expect("positive");
            (Ok(Recv::Data(NonZeroUsize::new(n).expect("positive"))), 0)
        } else if nread == 0 {
            (Ok(Recv::Eof), 0)
        } else if nread == sys::GNUTLS_E_AGAIN as isize
            || nread == sys::GNUTLS_E_INTERRUPTED as isize
        {
            (Ok(Recv::WouldBlock), AGAIN)
        } else if nread == sys::GNUTLS_E_REHANDSHAKE as isize {
            // A renegotiation before TLS 1.3, or TLS 1.3's key update.
            match self.handshake_step(io) {
                Ok(_) => (Ok(Recv::WouldBlock), AGAIN),
                Err(kind) => (Err(said()), kind.number()),
            }
        } else {
            let rc = Rc::try_from(nread).unwrap_or(Rc::MIN);
            io.fail(
                ErrorKind::RecvError,
                format_args!("GnuTLS recv error ({rc}): {}", strerror(lib, rc)),
            );
            let kind = result.failure().unwrap_or(ErrorKind::RecvError);
            (Err(said()), kind.number())
        };
        io.trace(format_args!("gtls_recv(len={len}) -> {code}, {nread}"));
        got
    }

    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent> {
        /// How the loop of sends ended.
        enum Ended {
            Sent,
            Again,
            Failed(ErrorKind),
        }
        let mut written = 0usize;
        let mut ended = Ended::Sent;
        while written < bytes.len() {
            let rest = &bytes[written..];
            let (n, result) = self.call(io, |gs, call| gs.send(call, rest));
            if n >= 0 {
                let n = usize::try_from(n).expect("not negative");
                if n > rest.len() {
                    io.fail(
                        ErrorKind::SendError,
                        format_args!("gnutls_record_send(len={}) returned {n}", rest.len()),
                    );
                    ended = Ended::Failed(ErrorKind::SendError);
                    break;
                }
                written += n;
            } else if n == sys::GNUTLS_E_AGAIN as isize {
                // What was sent is sent; else the send waits.
                if written == 0 {
                    ended = Ended::Again;
                }
                break;
            } else {
                ended = Ended::Failed(result.failure().unwrap_or(ErrorKind::SendError));
                break;
            }
        }
        let code = match ended {
            Ended::Sent => 0,
            Ended::Again => AGAIN,
            Ended::Failed(kind) => kind.number(),
        };
        io.trace(format_args!(
            "gtls_send(len={}) -> {code}, {written}",
            bytes.len()
        ));
        match ended {
            Ended::Sent => Ok(match NonZeroUsize::new(written) {
                Some(n) => Sent::Bytes(n),
                None => Sent::WouldBlock,
            }),
            Ended::Again => Ok(Sent::WouldBlock),
            Ended::Failed(_) => Err(said()),
        }
    }

    fn shutdown(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<Handshake, ErrorKind> {
        if self.gs.is_none() || self.shut || self.step != Step::Done {
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
        self.gs.as_ref().is_some_and(library::Session::pending)
    }

    /// What the peer chose, which is none before the handshake chose it,
    /// but for one put off: what the session resumed chose, which `defer`
    /// takes as agreed.
    fn chosen(&self) -> Option<Chosen> {
        self.negotiated
    }

    fn deferred(&self) -> Option<Deferred> {
        self.deferred.filter(|_| self.early == Early::None)
    }

    fn handshake_early(
        &mut self,
        io: &mut TlsIo<'_>,
        early: &[u8],
    ) -> Result<Handshake, ErrorKind> {
        assert!(self.deferred.is_some(), "a handshake put off");
        self.waits = TlsWait::Nothing;
        if self.early == Early::None {
            self.early = Early::Sending(0);
        }
        if let Early::Sending(sent) = self.early
            && self.send_early(io, early, sent)? == Handshake::Waiting
        {
            return Ok(Handshake::Waiting);
        }
        self.handshake(io)
    }

    fn early_accepted(&self) -> bool {
        self.early == (Early::Over { accepted: true })
    }

    /// The `gnutls_session_t`, as C hands it out for both the session
    /// and the context (`gtls_get_internals`).
    fn native(&self) -> Option<TlsNative> {
        let s = self.gs.as_ref()?.native();
        Some(TlsNative::new(s, Some(s)))
    }

    /// None: C's GnuTLS build makes no channel binding
    /// (`get_channel_binding` is NULL).
    fn channel_binding(&self, _: &mut dyn BindingNotes) -> Result<Option<Vec<u8>>, ErrorKind> {
        Ok(None)
    }
}

impl<G: Gnutls> Session<G> {
    /// The steps of `gtls_connect_common`.
    fn connect(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        if self.step == Step::Init {
            self.step1(io)?;
            self.step = Step::Handshake;
        }
        if self.step == Step::Handshake {
            // Put off, it waits for its early data.
            if self.deferred.is_some() && self.early == Early::None {
                return Ok(Handshake::Done);
            }
            match self.handshake_step(io)? {
                Handshake::Waiting => return Ok(Handshake::Waiting),
                Handshake::Done => self.step = Step::Check,
            }
        }
        self.report_handshake(io);
        self.verify_server(io)?;
        self.step = Step::Done;
        self.negotiate(io)?;
        if self.early == Early::Sent {
            let gs = self.gs.as_mut().expect("made at the first step");
            self.early = Early::Over {
                accepted: gs.early_data_accepted(),
            };
        }
        Ok(Handshake::Done)
    }
}
