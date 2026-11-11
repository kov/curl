//! One connection's wolfSSL (`lib/vtls/wolfssl.c`): its context and
//! session object made at the handshake's first step as C makes them
//! (`wssl_connect_step1`, `Curl_wssl_ctx_init`, `wssl_init_ssl_handle`),
//! resuming a session the cache kept (`wssl_apply_session`), the
//! handshake (`wssl_handshake`), the pinned key and ALPN after it
//! (`wssl_connect`), then the records both ways (`wssl_recv`,
//! `wssl_send`) and the goodbye (`wssl_shutdown`); early data sent in a
//! handshake put off for it (`wssl_send_earlydata`). A QUIC connection's
//! is made at once, by the same steps as for QUIC's transport (`quic.rs`).

use std::io;
use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};
use curl_core::conn::io::{Recv, Sent};
use curl_core::error::ErrorKind;
use curl_core::options::{EchMode, TlsMaxVersion, TlsMinVersion};
use curl_core::tls::{
    Alpn, BindingNotes, Chosen, Deferred, Goodbye, Handshake, QuicContextSetup, SharedKeyLog, Text,
    TlsCx, TlsIdentity, TlsIo, TlsNative, TlsPeer, TlsPeerKind, TlsSession, TlsShared, TlsTicket,
    TlsWait,
};

use crate::library::{
    AGAIN, AlpnGot, Call, Ctx as _, FileType, IoResult, IoState, NoCtx, PeerCert, Reach, Resume,
    Ssl, Wolfssl, as_c, c_string,
};
use crate::sys;

/// The most early data a handshake holds to send (`CURL_SSL_EARLY_MAX`).
const EARLY_MOST: usize = 64 * 1024;

/// The longest cipher list C builds (`MAX_CIPHER_LEN`): its buffer holds
/// one byte less, with room for the zero.
const CIPHER_LIST_MOST: usize = 4096;

/// The wire's numbers of the versions (`TLS1_VERSION` ...).
const TLS1_0: u16 = 0x0301;
const TLS1_1: u16 = 0x0302;
const TLS1_2: u16 = 0x0303;
const TLS1_3: u16 = 0x0304;

/// How far a session's handshake has come (`connecting_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Nothing made yet: the context and session are made at the first
    /// step.
    One,
    /// The handshake runs.
    Two,
    /// The handshake is over, this its outcome: the peer's key and ALPN
    /// are to be checked (`hs_result`).
    Three(Result<(), ErrorKind>),
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

/// The session's object of a library's context.
pub(crate) type SslOf<W> = <<W as Wolfssl>::Ctx as crate::library::Ctx>::Ssl;

/// One connection's wolfSSL, through the library `W`.
pub(crate) struct Session<W: Wolfssl> {
    pub(crate) lib: &'static W,
    method: TryArc<W::Method>,
    // The session's object holds its context's reference too: either may
    // go first.
    pub(crate) ssl: Option<SslOf<W>>,
    ctx: Option<W::Ctx>,
    pub(crate) identity: TryArc<TlsIdentity>,
    /// What the library keeps for the multi, until the trust store is set
    /// up.
    shared: Option<TlsShared>,
    /// The origin's name as the URL gives it, without brackets.
    pub(crate) host: Vec<u8>,
    pub(crate) kind: TlsPeerKind,
    /// The protocols offered, and the one the session resumed restricts
    /// the offer to (`Curl_alpn_restrict_to`).
    alpn: Alpn,
    restricted: Option<Chosen>,
    step: Step,
    waits: TlsWait,
    pub(crate) state: IoState,
    /// The goodbye is over or failed (the filter's `shutdown`).
    shut: bool,
    keylog: Option<SharedKeyLog>,
    /// The transfer may send early data.
    early_data: bool,
    /// The ECHConfigList of the origin's HTTPS record, if it has one.
    ech_record: Option<Vec<u8>>,
    /// The handshake is put off for early data (`ssl_connection_deferred`).
    deferred: Option<Deferred>,
    early: Early,
    /// What ALPN agreed (`connssl->negotiated.alpn`).
    negotiated: Option<Chosen>,
    /// A QUIC connection's: the QUIC library carries its records
    /// (`TRNSPRT_QUIC`).
    quic: bool,
    /// A QUIC connection's session the cache kept, which it resumed over
    /// TLS 1.3 for a transfer that may send early data: the QUIC library
    /// decides on it (`cf_ngtcp2_on_session_reuse`), and the ALPN offer
    /// waits for its word.
    pub(crate) quic_early: Option<TlsTicket>,
    /// The QUIC library said whether early data goes under `quic_early`,
    /// and the offer is made.
    pub(crate) quic_decided: bool,
}

impl<W: Wolfssl> Session<W> {
    /// A session for one connection to `peer`, nothing of the library's
    /// made yet.
    pub(crate) fn new(
        lib: &'static W,
        method: TryArc<W::Method>,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        shared: &TlsShared,
        keylog: Option<SharedKeyLog>,
    ) -> Result<Session<W>, ErrorKind> {
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
            method,
            ssl: None,
            ctx: None,
            identity: identity.clone(),
            shared: Some(shared.clone()),
            host,
            kind: peer.kind,
            alpn,
            restricted: None,
            step: Step::One,
            waits: TlsWait::Nothing,
            state: IoState::default(),
            shut: false,
            keylog,
            early_data: peer.early_data,
            ech_record,
            deferred: None,
            early: Early::None,
            negotiated: None,
            quic: false,
            quic_early: None,
            quic_decided: false,
        })
    }

    /// The same, for a QUIC connection, offering HTTP/3.
    pub(crate) fn new_quic(
        lib: &'static W,
        method: TryArc<W::Method>,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        shared: &TlsShared,
        keylog: Option<SharedKeyLog>,
    ) -> Result<Session<W>, ErrorKind> {
        let mut s = Session::new(lib, method, identity, peer, Alpn::H3, shared, keylog)?;
        s.quic = true;
        Ok(s)
    }

    fn ctx(&mut self) -> &mut W::Ctx {
        self.ctx.as_mut().expect("made at the first step")
    }

    fn ssl(&mut self) -> &mut SslOf<W> {
        self.ssl.as_mut().expect("made at the first step")
    }

    /// The key log, if it is open (`Curl_tls_keylog_enabled`).
    fn keylog(&self) -> Option<&curl_core::tls::KeyLog> {
        self.keylog
            .as_deref()
            .filter(|l| curl_core::tls::KeyLog::enabled(l))
    }

    /// The name sent by SNI (`Curl_ssl_peer_init`'s `peer->sni`).
    fn sni(&self) -> Result<Option<Vec<u8>>, ErrorKind> {
        curl_core::tls::sni(&self.host, self.kind).map_err(|OutOfMemory| ErrorKind::OutOfMemory)
    }

    /// Set the trust store up outside a call into the library
    /// (`Curl_wssl_setup_x509_store`).
    pub(crate) fn setup_store(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        self.state.store_ready = true;
        let ctx = self.ctx.as_mut().expect("made at the first step");
        let set_up = crate::trust::setup(self.lib, ctx, &self.identity, self.shared.as_ref(), io);
        // Not needed past the store: the connection does not keep the
        // multi's state alive, wherever it goes.
        self.shared = None;
        set_up
    }

    /// Run `op`, a call into the library on the session's object, with
    /// its callbacks reaching `io`; in the handshake, the trust store set
    /// up at its first read if it is not.
    fn call<R>(
        &mut self,
        io: &mut TlsIo<'_>,
        op: impl FnOnce(&mut SslOf<W>, &mut Call<'_, '_>) -> R,
    ) -> R {
        let Session {
            lib,
            ssl,
            ctx,
            identity,
            shared,
            state,
            negotiated,
            ..
        } = self;
        let lib = *lib;
        let ssl = ssl.as_mut().expect("made at the first step");
        let ctx = ctx.as_mut().expect("made at the first step");
        let kept = shared.as_ref();
        let mut setup =
            |cx: &mut TlsCx<'_>| crate::trust::setup(lib, &mut *ctx, identity, kept, cx);
        let mut call = Call {
            io: Reach::Stream(io),
            state,
            store: Some(&mut setup),
            alpn: *negotiated,
            quic_params: None,
        };
        let r = op(ssl, &mut call);
        if self.state.store_ready {
            self.shared = None;
        }
        r
    }

    /// Make the context and the session's object, and set them up
    /// (`wssl_connect_step1`).
    fn step1(&mut self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        let made = self.ctx_init(io, None);
        if made.is_err() {
            // C frees what it made of them.
            self.ssl = None;
            self.ctx = None;
        }
        made?;
        if self.deferred.is_none()
            && let Some(offer) = self.alpn.offer()
        {
            io.info(format_args!("ALPN: curl offers {offer}"));
        }
        // RFC 2818's checks of the name, which cannot check an address:
        // that is done after the handshake.
        if self.identity.verify_host
            && let Some(sni) = self.sni()?
        {
            let name = c_string(&sni)?;
            if !self.ssl().check_domain(as_c(&name)) {
                return Err(ErrorKind::SslConnectError);
            }
        }
        self.ssl()
            .bio()
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)
    }

    /// Make a QUIC connection's context and session's object at once
    /// (`Curl_wssl_ctx_init` for QUIC's transport), the context handed to
    /// the QUIC library's `setup`; and the BIO its callbacks find the
    /// call under way through, which it never reads or writes.
    pub(crate) fn quic_init(
        &mut self,
        cx: &mut TlsCx<'_>,
        setup: QuicContextSetup<'_>,
    ) -> Result<(), ErrorKind> {
        let made = self.ctx_init(cx, Some(setup)).and_then(|()| {
            self.ssl()
                .bio()
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory)
        });
        if made.is_err() {
            // C frees what it made of them.
            self.ssl = None;
            self.ctx = None;
        }
        made
    }

    /// The context and the session's object made (`Curl_wssl_ctx_init`):
    /// for QUIC, the context handed to the QUIC library's `setup` where
    /// C calls it (`cb_setup`, `cf_ngtcp2_tls_ctx_setup`), which tells
    /// the context of new sessions in its place.
    fn ctx_init(
        &mut self,
        io: &mut TlsCx<'_>,
        setup: Option<QuicContextSetup<'_>>,
    ) -> Result<(), ErrorKind> {
        let ctx = self.lib.ctx(&self.method).map_err(|no| {
            let what = match no {
                NoCtx::Method => "could not create a client method",
                NoCtx::Context => "could not create a context",
            };
            io.fail(ErrorKind::OutOfMemory, format_args!("wolfSSL: {what}"))
        })?;
        self.ctx = Some(ctx);
        let (min, max) = self.versions(io)?;
        self.ciphers(io, min, max)?;
        self.curves(io)?;
        self.client_cert(io)?;
        // The library always verifies the peer; this says whether a peer
        // that does not verify fails the handshake.
        let verify = self.identity.verify_peer;
        self.ctx().verify(verify);
        if let Some(sni) = self.sni()? {
            if !self.ctx().sni(&sni) {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("Failed to set SNI"),
                ));
            }
            io.trace(format_args!("set SNI '{}'", Text(&sni)));
        }
        if !self.quic && io.caches_sessions() {
            self.ctx().tell_sessions();
        }
        if let Some(setup) = setup {
            let native = self.ctx().native(None);
            if let Err(why) = setup(native) {
                return Err(io.fail(ErrorKind::FailedInit, format_args!("{why}")));
            }
            // Over QUIC, the sessions are kept with the connection's
            // transport parameters (`wssl_quic_new_session_cb`).
            if io.caches_sessions() {
                self.ctx().tell_sessions();
            }
        }
        // The application's turn at the context (`ssl_fsslctx`), its
        // trust store set up first.
        if io.configures_context() {
            if !self.state.store_ready {
                self.setup_store(io)?;
            }
            let native = self.ctx().native(None);
            io.configure_context(native)?;
        }
        self.init_ssl_handle(io)?;
        if self.identity.options.ech.enabled() {
            self.init_ech(io)?;
        }
        Ok(())
    }

    /// Encrypted Client Hello set up on the session's object
    /// (`wssl_init_ech`): GREASE is the library's own; else the
    /// transfer's list, in base64, or the origin's HTTPS record's, and the
    /// handshake held to TLS 1.3 once one is taken. A list the library
    /// refuses, or none, fails it only where ECH is hard; an outer name it
    /// cannot set fails it whatever the mode.
    fn init_ech(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let identity = self.identity.clone();
        let ech = &identity.options.ech;
        let hard = ech.mode == EchMode::Hard;
        if ech.public_name.is_some() {
            io.info(format_args!("ECH: outername not supported with wolfSSL"));
            return Err(ErrorKind::SslConnectError);
        }
        let mut trying = false;
        if ech.mode == EchMode::Grease {
            io.info(format_args!(
                "ECH: GREASE is done by default by wolfSSL: no need to ask"
            ));
        } else if let Some(b64) = &ech.config {
            if !b64.is_empty() && !self.ssl().ech_configs_base64(b64) {
                if hard {
                    return Err(ErrorKind::SslConnectError);
                }
            } else {
                trying = true;
                io.info(format_args!("ECH: ECHConfig from command line"));
            }
        } else if let Some(list) = self.ech_record.take() {
            io.info(format_args!("ECH: ECHConfig from HTTPS RR"));
            if self.ssl().set_ech_configs(&list) {
                trying = true;
                io.info(format_args!(
                    "ECH: imported ECHConfigList of length {}",
                    list.len()
                ));
            } else {
                io.info(format_args!("ECH: wolfSSL_SetEchConfigs failed"));
                if hard {
                    return Err(ErrorKind::SslConnectError);
                }
            }
        } else {
            io.info(format_args!("ECH: requested but no ECHConfig available"));
            if hard {
                return Err(ErrorKind::SslConnectError);
            }
        }
        if trying && !self.ssl().min_version(TLS1_3) {
            io.info(format_args!("ECH: cannot force TLSv1.3 [ERROR]"));
            return Err(ErrorKind::SslConnectError);
        }
        Ok(())
    }

    /// The versions allowed, set on the context (`ssl_version`): the
    /// least and the most, 0 for none.
    fn versions(&mut self, io: &mut TlsCx<'_>) -> Result<(u16, u16), ErrorKind> {
        let o = &self.identity.options;
        let min = match o.min_version {
            TlsMinVersion::Tls1 | TlsMinVersion::Tls1_0 => TLS1_0,
            TlsMinVersion::Tls1_1 => TLS1_1,
            TlsMinVersion::Tls1_2 => TLS1_2,
            TlsMinVersion::Tls1_3 => TLS1_3,
        };
        let max = match o.max_version {
            TlsMaxVersion::Tls1_3 => TLS1_3,
            TlsMaxVersion::Tls1_2 => TLS1_2,
            TlsMaxVersion::Tls1_1 => TLS1_1,
            TlsMaxVersion::Tls1_0 => TLS1_0,
            TlsMaxVersion::Default | TlsMaxVersion::None => 0,
        };
        if !self.ctx().min_version(min) {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("wolfSSL: failed set the minimum TLS version"),
            ));
        }
        if max != 0 && !self.ctx().max_version(max) {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("wolfSSL: failed set the maximum TLS version"),
            ));
        }
        Ok((min, max))
    }

    /// The cipher list, if the transfer names one for either kind of
    /// suite (`wssl_init_ciphers`): TLS 1.3's first, where the most
    /// allowed is 1.3, then the others', where the least is below it,
    /// each the transfer's or else the library's own of that kind.
    fn ciphers(&mut self, io: &mut TlsCx<'_>, min: u16, max: u16) -> Result<(), ErrorKind> {
        let identity = self.identity.clone();
        let o = &identity.options;
        if o.ciphers.is_none() && o.tls13_ciphers.is_none() {
            return Ok(());
        }
        let mut list = CipherList::default();
        if max == 0 || max >= TLS1_3 {
            match o.tls13_ciphers.as_deref() {
                Some(given) => list.add(given)?,
                None => self.add_default(&mut list, true)?,
            }
        }
        if min < TLS1_3 {
            match o.ciphers.as_deref() {
                Some(given) => {
                    if !list.0.is_empty() {
                        list.add(b":")?;
                    }
                    list.add(given)?;
                }
                None => self.add_default(&mut list, false)?,
            }
        }
        let c = if list.0.is_empty() {
            None
        } else {
            Some(c_string(&list.0)?)
        };
        // An empty list is C's null, which C prints so.
        let shown = Text(c.as_deref().map_or(b"(nil)", |c| as_c(c).to_bytes()));
        if !self.ctx().cipher_list(c.as_deref().map(as_c)) {
            return Err(io.fail(
                ErrorKind::SslCipher,
                format_args!("failed setting cipher list: {shown}"),
            ));
        }
        io.info(format_args!("Cipher selection: {shown}"));
        Ok(())
    }

    /// The library's own suites of TLS 1.3, or of the versions before it,
    /// after a colon (`wssl_add_default_ciphers`).
    fn add_default(&self, list: &mut CipherList, tls13: bool) -> Result<(), ErrorKind> {
        let mut i = 0;
        while let Some(name) = self.lib.cipher(i) {
            i += 1;
            if name.starts_with(b"TLS13") != tls13 {
                continue;
            }
            if !list.0.is_empty() {
                list.add(b":")?;
            }
            // C says any failure to add the name is out of memory.
            list.add(name).map_err(|_| ErrorKind::OutOfMemory)?;
        }
        Ok(())
    }

    /// The curves, if the transfer names them (`wssl_init_curves`);
    /// else the library's own choice of key share groups.
    fn curves(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let identity = self.identity.clone();
        let Some(curves) = identity.options.curves.as_deref() else {
            return Ok(());
        };
        let c = c_string(curves)?;
        if !self.ctx().groups(as_c(&c)) {
            return Err(io.fail(
                ErrorKind::SslCipher,
                format_args!(
                    "failed setting curves list: '{}'",
                    Text(as_c(&c).to_bytes())
                ),
            ));
        }
        Ok(())
    }

    /// The client's certificate and key (`wssl_client_cert`), from a blob
    /// or else a file, the key from the certificate's own where the
    /// transfer names none. Its password is never read.
    fn client_cert(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let identity = self.identity.clone();
        let o = &identity.options;
        let (cert_blob, cert_file) = (o.cert_blob.as_deref(), o.cert.as_deref());
        if cert_blob.is_none() && cert_file.is_none() {
            return Ok(());
        }
        let mut kind = FileType::of(o.cert_type.as_deref());
        let file = cert_file.map(c_string).transpose()?;
        let ctx = self.ctx.as_mut().expect("made at the first step");
        let rc = match (kind, cert_blob) {
            (FileType::Pem, Some(blob)) => ctx.cert_chain_buffer(blob),
            (FileType::Pem, None) => ctx.cert_chain_file(as_c(file.as_deref().unwrap_or(b"\0"))),
            (FileType::Asn1, Some(blob)) => ctx.cert_buffer(blob, kind),
            (FileType::Asn1, None) => ctx.cert_file(as_c(file.as_deref().unwrap_or(b"\0")), kind),
            (FileType::Unknown, _) => {
                return Err(io.fail(
                    ErrorKind::BadFunctionArgument,
                    format_args!("unknown cert type"),
                ));
            }
        };
        if rc != 1 {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("unable to use client certificate"),
            ));
        }
        let (mut key_blob, mut key_file) = (o.key_blob.as_deref(), o.key.as_deref());
        if key_blob.is_none() && key_file.is_none() {
            key_blob = cert_blob;
            key_file = cert_file;
        } else {
            kind = FileType::of(o.key_type.as_deref());
        }
        let key_file = key_file.map(c_string).transpose()?;
        let ctx = self.ctx.as_mut().expect("made at the first step");
        let rc = match key_blob {
            Some(blob) => ctx.key_buffer(blob, kind),
            None => ctx.key_file(as_c(key_file.as_deref().unwrap_or(b"\0")), kind),
        };
        if rc != 1 {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("unable to set private key"),
            ));
        }
        Ok(())
    }

    /// The session's object made and set up (`wssl_init_ssl_handle`):
    /// FTP's control connection's session resumed, else one the cache
    /// kept; the ALPN offer; the key log's arrays kept. A QUIC session's
    /// sends its transport parameters at QUIC's own code point.
    fn init_ssl_handle(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let ssl = self.ctx().ssl().map_err(|OutOfMemory| {
            io.fail(
                ErrorKind::OutOfMemory,
                format_args!("SSL: could not create a handle"),
            )
        })?;
        self.ssl = Some(ssl);
        if self.quic {
            self.ssl().quic_codepoint();
        }
        let mut applied = false;
        if let Some(given) = io.take_given_session() {
            applied = self.apply_session(io, &given);
            if applied {
                io.trace(format_args!("applied SSL session from control connection"));
            }
        }
        if !applied && io.caches_sessions() {
            // One not applied is dropped: it is not to be tried again.
            if let Some(ticket) = io.take_session()
                && self.apply_session(io, &ticket)
            {
                if self.quic && self.reuses_early() {
                    // A TLS 1.3 session, which the cache would not take
                    // back: the QUIC library's to decide on.
                    self.quic_early = Some(ticket);
                } else {
                    io.return_session(Some(ticket));
                }
            }
        }
        // Under a QUIC ticket for early data, the offer waits for the QUIC
        // library's word on it (`quic_early_decided`).
        if self.quic_early.is_none() {
            self.offer_alpn(io)?;
        }
        if self.keylog().is_some() {
            // The client's random kept for the log.
            self.ssl().keep_arrays();
        }
        Ok(())
    }

    /// The ALPN offer: what the transfer offers, or the protocol the
    /// session resumed restricts it to (`wolfSSL_UseALPN`, which adds to
    /// an offer made before: made once).
    fn offer_alpn(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        if self.alpn == Alpn::None {
            return Ok(());
        }
        let list = match self.restricted {
            Some(c) => c.name(),
            None => self.alpn.offer().unwrap_or_default(),
        };
        if !self.ssl().alpn(list.as_bytes()) {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("SSL: failed setting ALPN protocols"),
            ));
        }
        io.trace(format_args!("set ALPN: {list}"));
        Ok(())
    }

    /// The QUIC library said whether early data goes under the ticket it
    /// was handed (`quic_early`), once it took the ticket's transport
    /// parameters: where it does, the offer is restricted to the
    /// ticket's protocol and the library told the most the ticket allows
    /// (`wssl_apply_session` after `sess_reuse_cb`); then the offer is
    /// made, as `Curl_wssl_ctx_init` makes it after the session applied.
    pub(crate) fn quic_early_decided(
        &mut self,
        io: &mut TlsCx<'_>,
        early: bool,
    ) -> Result<(), ErrorKind> {
        assert!(!self.quic_decided, "told once");
        let ticket = self
            .quic_early
            .as_ref()
            .expect("told only under a ticket resumed for early data");
        self.quic_decided = true;
        if early {
            let chosen = ticket
                .chosen()
                .expect("early data goes under a ticket made for h3");
            let edmax = u32::try_from(ticket.earlydata_max).unwrap_or(u32::MAX);
            self.restricted = Some(chosen);
            self.ssl().max_early_data(edmax);
        }
        self.offer_alpn(io)
    }

    /// Resume `ticket`, if it has a session and the transfer offers what
    /// it agreed by ALPN (`wssl_apply_session`): whether it did. A TLS 1.3
    /// session the transfer may send early data under puts the handshake
    /// off for it (`wssl_on_session_reuse`).
    fn apply_session(&mut self, io: &mut TlsCx<'_>, ticket: &TlsTicket) -> bool {
        let offered = match ticket.alpn_name() {
            None => true,
            Some(_) => ticket.chosen().is_some_and(|c| self.alpn.offers(c)),
        };
        if ticket.data.is_empty() || !offered {
            return false;
        }
        match self.ssl().resume(&ticket.data) {
            Resume::Undecoded => {
                io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("could not decode previous session"),
                );
                false
            }
            Resume::Refused(rc) => {
                io.info(format_args!(
                    "cached session not accepted ({rc}), removing from cache"
                ));
                false
            }
            Resume::Done => {
                let alpn = ticket.alpn_name().unwrap_or(b"-");
                io.info_with(&[b"SSL reusing session with ALPN '", alpn, b"'"]);
                // A QUIC session's is the QUIC library's to decide on.
                if self.reuses_early() && !self.quic {
                    let most = self.ssl().session_max_early_data();
                    self.defer(io, ticket, most);
                }
                true
            }
        }
    }

    /// The session resumed is one the transfer may send early data under:
    /// it asks for it, and the session speaks TLS 1.3 (where C calls
    /// `sess_reuse_cb`).
    fn reuses_early(&self) -> bool {
        self.early_data
            && self
                .ssl
                .as_ref()
                .is_some_and(|ssl| ssl.version_name() == b"TLSv1.3")
    }

    /// Put the handshake off for early data, resuming `ticket`, whose
    /// session the library says allows `most` bytes of it, if it allows
    /// any and the transfer offers what it agreed (`Curl_on_session_reuse`):
    /// the offer restricted to that, and the library told the most the
    /// ticket allows.
    fn defer(&mut self, io: &mut TlsCx<'_>, ticket: &TlsTicket, most: u32) {
        let chosen = ticket.chosen().filter(|&c| self.alpn.offers(c));
        let most = usize::try_from(most).unwrap_or(usize::MAX);
        if most == 0 {
            io.trace(format_args!("SSL session does not allow earlydata"));
            return;
        }
        let Some(chosen) = chosen else {
            io.trace(format_args!(
                "SSL session has different ALPN, no early data"
            ));
            return;
        };
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
        let edmax = u32::try_from(ticket.earlydata_max).unwrap_or(u32::MAX);
        self.ssl().max_early_data(edmax);
    }

    /// Hand `early` to the library as early data, from `sent` on
    /// (`wssl_send_earlydata`): done, or waiting with what went kept.
    fn send_early(
        &mut self,
        io: &mut TlsIo<'_>,
        early: &[u8],
        mut sent: usize,
    ) -> Result<Handshake, ErrorKind> {
        self.state.result = IoResult::Ok;
        while sent < early.len() {
            let rest = &early[sent..];
            let len = rest.len().min(i32::MAX as usize);
            let (rc, n) = self.call(io, |ssl, call| ssl.write_early(call, &rest[..len]));
            io.trace(format_args!(
                "wolfSSL_write_early_data(len={}) -> {rc}, {n}",
                rest.len()
            ));
            if rc < 0 {
                self.early = Early::Sending(sent);
                let err = self.ssl().error(rc);
                if matches!(
                    err,
                    sys::WOLFSSL_ERROR_NONE
                        | sys::WOLFSSL_ERROR_WANT_READ
                        | sys::WOLFSSL_ERROR_WANT_WRITE
                ) {
                    return Ok(Handshake::Waiting);
                }
                let words = self.lib.strerror(err.cast_unsigned());
                io.trace(format_args!("SSL send early data, error: '{words}'({err})"));
                return Err(ErrorKind::SendError);
            }
            sent += n.min(rest.len());
        }
        self.early = Early::Sent;
        io.info(format_args!(
            "SSL sending {} bytes of early data",
            early.len()
        ));
        Ok(Handshake::Done)
    }

    /// Move the handshake on (`wssl_handshake`): done, waiting, or failed
    /// as the library's detail of its answer says.
    fn handshake_step(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        self.waits = TlsWait::Nothing;
        let mut ret = self.call(io, |ssl, call| ssl.connect(call));
        if !self.state.store_ready {
            // The ClientHello went without a read: the store is set up for
            // the certificate to come.
            if let Err(kind) = self.setup_store(io) {
                io.trace(format_args!(
                    "Curl_wssl_setup_x509_store() -> {}",
                    kind.number()
                ));
                return Err(kind);
            }
        }
        if self.keylog().is_some() {
            let ssl = self.ssl.as_ref().expect("made at the first step");
            // Over, well or not, when it waits for nothing: the secret
            // is there to log, and the arrays are let go.
            if ret == sys::WOLFSSL_SUCCESS || (!ssl.wants_read() && !ssl.wants_write()) {
                self.log_tls12_secret();
                self.ssl().free_arrays();
            }
        }
        let mut detail = self.ssl().error(ret);
        io.trace(format_args!("wolfSSL_connect() -> {ret}, detail={detail}"));
        if ret == sys::WOLFSSL_SUCCESS && self.identity.verify_host && self.sni()?.is_none() {
            // An address, which the library's name check could not check.
            let ip = c_string(&self.host)?;
            let Some(rc) = self.ssl().check_ip(as_c(&ip)) else {
                return Err(io.fail(
                    ErrorKind::PeerFailedVerification,
                    format_args!("unable to get peer certificate"),
                ));
            };
            io.trace(format_args!(
                "check peer certificate for IP match on {} -> {rc}",
                Text(&self.host)
            ));
            ret = rc;
            if rc != sys::WOLFSSL_SUCCESS {
                detail = sys::DOMAIN_NAME_MISMATCH;
            }
        }
        if ret == sys::WOLFSSL_SUCCESS {
            return Ok(Handshake::Done);
        }
        match detail {
            sys::WOLFSSL_ERROR_WANT_READ => {
                self.waits = TlsWait::Recv;
                Ok(Handshake::Waiting)
            }
            sys::WOLFSSL_ERROR_WANT_WRITE => {
                self.waits = TlsWait::Send;
                Ok(Handshake::Waiting)
            }
            sys::DOMAIN_NAME_MISMATCH => {
                // Neither the names nor the common name can be let off
                // alone.
                Err(io.fail(
                    ErrorKind::PeerFailedVerification,
                    format_args!(
                        " subject alt name(s) or common name do not match \"{}\"",
                        Text(&self.host)
                    ),
                ))
            }
            sys::ASN_NO_SIGNER_E => {
                if self.identity.verify_peer {
                    return Err(io.fail(
                        ErrorKind::SslCacertBadfile,
                        format_args!(" CA signer not available for verification"),
                    ));
                }
                io.info(format_args!(
                    "CA signer not available for verification, continuing anyway"
                ));
                Ok(Handshake::Done)
            }
            sys::ASN_AFTER_DATE_E => Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("server verification failed: certificate has expired."),
            )),
            sys::ASN_BEFORE_DATE_E => Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("server verification failed: certificate not valid yet."),
            )),
            _ => match self.state.result {
                IoResult::Failed(ErrorKind::SendError | ErrorKind::RecvError) => {
                    Err(ErrorKind::SslConnectError)
                }
                IoResult::Failed(kind) => Err(kind),
                IoResult::Again => Ok(Handshake::Waiting),
                // What ECH's failure comes to: the session's list traced,
                // as C traces it in the hope of the retry configurations,
                // which the library does not give.
                IoResult::Ok if detail == -1 => {
                    match self.ssl().ech_configs() {
                        None => io.info(format_args!("Failed to get ECHConfigs")),
                        // Untraced out of memory, as C goes on past it.
                        Some(list) => {
                            if let Ok(b64) = curl_core::tls::base64_encode(&list) {
                                io.info_with(&[b"ECH: (not yet) retry_configs ", &b64]);
                            }
                        }
                    }
                    Err(ErrorKind::SslConnectError)
                }
                IoResult::Ok => {
                    let words = self.lib.strerror(detail.cast_unsigned());
                    Err(io.fail(
                        ErrorKind::SslConnectError,
                        format_args!("SSL_connect failed with error {detail}: {words}"),
                    ))
                }
            },
        }
    }

    /// Log the secret of a session before TLS 1.3 (`wssl_log_tls12_secret`):
    /// none for TLS 1.3, whose master secret is not one to log, nor for a
    /// handshake that ended before it had one.
    fn log_tls12_secret(&self) {
        let (Some(log), Some(ssl)) = (self.keylog(), self.ssl.as_ref()) else {
            return;
        };
        if !ssl.before_tls13() {
            return;
        }
        let Some(keys) = ssl.tls12_keys() else {
            return;
        };
        if keys.master.iter().all(|&b| b == 0) {
            return;
        }
        let Some(random) = keys.client_random.first_chunk::<32>() else {
            return;
        };
        log.write_secret(b"CLIENT_RANDOM", random, &keys.master);
    }

    /// The peer's public key is the pinned one, if one is
    /// (`Curl_wssl_verify_pinned`).
    fn verify_pinned(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        let ssl = self.ssl.as_ref().expect("made at the first step");
        verify_pinned(ssl, &self.identity, io)
    }

    /// What the peer chose of the ALPN offer, if one was made
    /// (`wssl_connect`'s third step).
    fn negotiate(&mut self, io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        if self.alpn == Alpn::None {
            return Ok(());
        }
        let chosen = match self.ssl().alpn_selected() {
            AlpnGot::Chose(name) => name,
            AlpnGot::NotFound => Vec::new(),
            AlpnGot::NoRoom => return Err(ErrorKind::OutOfMemory),
            AlpnGot::Failed(rc) => {
                return Err(io.fail(
                    ErrorKind::SslConnectError,
                    format_args!("ALPN, failure getting protocol, error {rc}"),
                ));
            }
        };
        let asked = self.deferred.map(|d| d.alpn.name().as_bytes());
        // C goes on whatever the peer chose: a choice it refuses is said,
        // and the connection is made all the same (`wssl_connect` drops
        // what `Curl_alpn_set_negotiated` answers).
        match curl_core::tls::alpn_negotiated(io, asked, &chosen) {
            Ok(()) if asked.is_none() && !chosen.is_empty() => {
                self.negotiated = Chosen::named(&chosen);
            }
            Ok(()) | Err(_) => {}
        }
        Ok(())
    }

    /// The handshake's outcome said (`Curl_wssl_report_handshake`).
    fn report_handshake(&mut self, io: &mut TlsCx<'_>) {
        report_handshake(self.ssl(), io);
    }

    /// The steps of `wssl_connect`.
    fn connect(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        if self.step == Step::One {
            self.step1(io)?;
            self.step = Step::Two;
            self.state.handshaking = true;
        }
        if self.step == Step::Two {
            // Put off, it waits for its early data.
            if self.deferred.is_some() && self.early == Early::None {
                return Ok(Handshake::Done);
            }
            let outcome = match self.handshake_step(io) {
                Ok(Handshake::Waiting) => return Ok(Handshake::Waiting),
                Ok(Handshake::Done) => Ok(()),
                Err(kind) => Err(kind),
            };
            self.step = Step::Three(outcome);
            self.state.handshaking = false;
        }
        if let Step::Three(outcome) = self.step {
            // Once failed, the handshake fails the same on every call.
            outcome?;
            let checked = self.verify_pinned(io).and_then(|()| self.negotiate(io));
            if let Err(kind) = checked {
                self.step = Step::Three(Err(kind));
                return Err(kind);
            }
            self.step = Step::Done;
            self.report_handshake(io);
            if self.early == Early::Sent {
                let rejected = self.ssl().early_rejected();
                self.early = Early::Over {
                    accepted: !rejected,
                };
            }
        }
        Ok(Handshake::Done)
    }

    /// The goodbye (`wssl_shutdown`): `Ok(true)` once over.
    fn goodbye(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<bool, ErrorKind> {
        self.state.shutting_down = true;
        let mut buf = [0u8; 1024];
        if !self.ssl().sent_shutdown() {
            // Ours not begun: did the peer say its own already?
            let nread = self.call(io, |ssl, call| ssl.read(call, &mut buf));
            let err = self.ssl().error(nread);
            io.trace(format_args!("wolfSSL_read, nread={nread}, err={err}"));
            if nread == 0 && err == sys::WOLFSSL_ERROR_ZERO_RETURN {
                if !goodbye.sends() {
                    io.trace(format_args!("SSL shutdown received, not sending"));
                    return Ok(true);
                }
                if !io.peer_alive() {
                    // It closed after its own: it does not wait for ours.
                    io.trace(format_args!("peer closed connection"));
                    self.state.peer_closed = true;
                    return Ok(true);
                }
            }
        }
        if goodbye.sends() {
            let rc = self.call(io, |ssl, call| ssl.shutdown(call));
            if rc == 1 {
                io.trace(format_args!("SSL shutdown finished"));
                return Ok(true);
            }
            if self.ssl().error(rc) == sys::WOLFSSL_ERROR_WANT_WRITE {
                io.trace(format_args!("SSL shutdown still wants to send"));
                self.waits = TlsWait::Send;
                return Ok(false);
            }
            // Ours sent, the peer's is read for.
        }
        let mut nread = -1;
        for _ in 0..10 {
            nread = self.call(io, |ssl, call| ssl.read(call, &mut buf));
            if nread <= 0 {
                break;
            }
        }
        let err = self.ssl().error(nread);
        match err {
            sys::WOLFSSL_ERROR_ZERO_RETURN => {
                io.trace(format_args!("SSL shutdown received"));
                Ok(true)
            }
            sys::WOLFSSL_ERROR_NONE | sys::WOLFSSL_ERROR_WANT_READ => {
                io.trace(format_args!("SSL shutdown sent, want receive"));
                self.waits = TlsWait::Recv;
                Ok(false)
            }
            sys::WOLFSSL_ERROR_WANT_WRITE => {
                io.trace(format_args!("SSL shutdown send blocked"));
                self.waits = TlsWait::Send;
                Ok(false)
            }
            _ => {
                let words = self.lib.strerror(err.cast_unsigned());
                io.trace(format_args!("SSL shutdown, error: '{words}'({err})"));
                Err(ErrorKind::RecvError)
            }
        }
    }
}

/// The peer's public key is the pinned one, if `identity` pins one
/// (`Curl_wssl_verify_pinned`).
pub(crate) fn verify_pinned<S: Ssl>(
    ssl: &S,
    identity: &TlsIdentity,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let Some(pinned) = identity.options.pinned_key.as_deref() else {
        return Ok(());
    };
    let der = match ssl.peer_cert() {
        PeerCert::None => {
            return Err(io.fail(
                ErrorKind::SslPinnedpubkeynotmatch,
                format_args!("SSL: failed retrieving server certificate"),
            ));
        }
        PeerCert::NoDer => {
            return Err(io.fail(
                ErrorKind::SslPinnedpubkeynotmatch,
                format_args!("SSL: failed retrieving ASN.1 server certificate"),
            ));
        }
        PeerCert::Der(der) => der,
        PeerCert::NoRoom => return Err(ErrorKind::OutOfMemory),
    };
    let Some(cert) = curl_core::tls::x509::parse(&der) else {
        return Err(ErrorKind::SslPinnedpubkeynotmatch);
    };
    let spki = cert.public_key_info.whole;
    if spki.is_empty() {
        return Err(io.fail(
            ErrorKind::SslPinnedpubkeynotmatch,
            format_args!("SSL: failed retrieving public key from server certificate"),
        ));
    }
    curl_core::tls::pin_peer_pubkey(io, pinned, spki).map_err(|kind| {
        io.fail(
            kind,
            format_args!("SSL: public key does not match pinned public key"),
        )
    })
}

/// The handshake's outcome said (`Curl_wssl_report_handshake`).
pub(crate) fn report_handshake<S: Ssl>(ssl: &S, io: &mut TlsCx<'_>) {
    let version = ssl.version_name();
    let cipher = ssl.cipher_name();
    io.info(format_args!(
        "SSL connection using {} / {}",
        Text(version),
        Text(cipher.unwrap_or(b"(nil)"))
    ));
}

/// The cipher list C builds, in a buffer of `CIPHER_LIST_MOST` bytes.
#[derive(Default)]
pub(crate) struct CipherList(Vec<u8>);

impl CipherList {
    /// Add `bytes` to it (`curlx_dyn_addn`): too large for the buffer, the
    /// list is dropped and the connection fails (`CURLE_TOO_LARGE`).
    pub(crate) fn add(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        if self.0.len() + bytes.len() + 1 > CIPHER_LIST_MOST {
            self.0 = Vec::new();
            return Err(ErrorKind::TooLarge);
        }
        self.0
            .try_extend_from_slice(bytes)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)
    }
}

/// An error the session said why it failed for, or that C's says nothing
/// of: what the core reads as the read's or the send's failure.
fn said() -> io::Error {
    io::ErrorKind::Other.into()
}

/// The thread's last system error, as C's `SOCKERRNO` reads it.
fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

impl<W: Wolfssl> TlsSession for Session<W> {
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind> {
        if self.step == Step::Done {
            return Ok(Handshake::Done);
        }
        self.waits = TlsWait::Nothing;
        let done = self.connect(io);
        if matches!(done, Ok(Handshake::Done))
            && let Some(log) = self.keylog()
        {
            // `cf_connect`'s, said by each library here.
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
        let len = buf.len();
        let room = len.min(i32::MAX as usize);
        let nread = self.call(io, |ssl, call| ssl.read(call, &mut buf[..room]));
        if nread > 0 {
            let n = usize::try_from(nread).expect("positive");
            io.trace(format_args!("wssl_recv(len={len}) -> 0, {n}"));
            return Ok(Recv::Data(NonZeroUsize::new(n).expect("positive")));
        }
        let err = self.ssl().error(nread);
        let pending = matches!(
            err,
            sys::WOLFSSL_ERROR_NONE | sys::WOLFSSL_ERROR_WANT_READ | sys::WOLFSSL_ERROR_WANT_WRITE
        );
        if err == sys::WOLFSSL_ERROR_ZERO_RETURN {
            io.trace(format_args!("wssl_recv(len={len}) -> CLOSED"));
            return Ok(Recv::Eof);
        }
        if pending && self.state.result == IoResult::Ok && !self.state.peer_closed {
            // More to come: read again.
            io.trace(format_args!("wssl_recv(len={len}) -> AGAIN"));
            return Ok(Recv::WouldBlock);
        }
        if self.state.result == IoResult::Again {
            io.trace(format_args!("wssl_recv(len={len}) -> AGAIN"));
            return Ok(Recv::WouldBlock);
        }
        if self.state.result == IoResult::Ok && self.state.peer_closed {
            io.trace(format_args!("wssl_recv(len={len}) -> CLOSED"));
            io.fail(
                ErrorKind::RecvError,
                format_args!("Connection closed abruptly"),
            );
        } else {
            let words = self.lib.strerror(err.cast_unsigned());
            let errno = errno();
            io.fail(
                ErrorKind::RecvError,
                format_args!("SSL read: {words}, errno {errno}"),
            );
        }
        Err(said())
    }

    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent> {
        let len = bytes.len();
        let memlen = len.min(i32::MAX as usize);
        let n = self.call(io, |ssl, call| ssl.write(call, &bytes[..memlen]));
        let (got, code, written) = if n > 0 {
            let n = usize::try_from(n).expect("positive");
            (
                Ok(Sent::Bytes(NonZeroUsize::new(n).expect("positive"))),
                0,
                n,
            )
        } else {
            let err = self.ssl().error(n);
            if matches!(
                err,
                sys::WOLFSSL_ERROR_WANT_READ | sys::WOLFSSL_ERROR_WANT_WRITE
            ) || self.state.result == IoResult::Again
            {
                (Ok(Sent::WouldBlock), AGAIN, 0)
            } else {
                let words = self.lib.strerror(err.cast_unsigned());
                let errno = errno();
                io.fail(
                    ErrorKind::SendError,
                    format_args!("SSL write: {words}, errno {errno}"),
                );
                (Err(said()), ErrorKind::SendError.number(), 0)
            }
        };
        io.trace(format_args!("wssl_send(len={len}) -> {code}, {written}"));
        got
    }

    fn shutdown(&mut self, io: &mut TlsIo<'_>, goodbye: Goodbye) -> Result<Handshake, ErrorKind> {
        if self.ssl.is_none() || self.shut {
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
        self.ssl.as_ref().is_some_and(crate::library::Ssl::pending)
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

    /// The context and the session's object, as C hands them out for
    /// `CURLINFO_TLS_SESSION` and `CURLINFO_TLS_SSL_PTR`
    /// (`wssl_get_internals`).
    fn native(&self) -> Option<TlsNative> {
        Some(self.ctx.as_ref()?.native(self.ssl.as_ref()))
    }

    /// None: C's wolfSSL build makes no channel binding
    /// (`get_channel_binding` is NULL).
    fn channel_binding(&self, _: &mut dyn BindingNotes) -> Result<Option<Vec<u8>>, ErrorKind> {
        Ok(None)
    }
}
