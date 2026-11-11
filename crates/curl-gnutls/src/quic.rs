//! One QUIC connection's GnuTLS (`lib/vquic/vquic-tls.c` over
//! `Curl_gtls_ctx_init`): its session made at once, as for QUIC's
//! transport, resuming one the cache kept, handed to the QUIC library's
//! setup as soon as it is made; its trust set up before the peer's first
//! bytes; its handshake driven by the QUIC library, whose calls this
//! session's callbacks run inside (`drive`); the peer reported and
//! checked as the QUIC library says the handshake is done
//! (`Curl_vquic_report_handshake`, `Curl_vquic_tls_verify_peer`).

use curl_alloc::TryArc;
use curl_core::error::ErrorKind;
use curl_core::tls::{
    Chosen, DriveCall, KeyLog, QuicContextSetup, QuicTls, SharedKeyLog, TlsCx, TlsIdentity,
    TlsNative, TlsPeer, TlsShared, TlsTicket,
};

use crate::library::{Call, Gnutls, IoResult, Reach, Session as _};
use crate::session::{self, Session};

/// One QUIC connection's session, through the library `G`.
pub(crate) struct QuicSession<G: Gnutls>(Session<G>);

impl<G: Gnutls> QuicSession<G> {
    /// The session for one QUIC connection to `peer`, made as
    /// `Curl_gtls_ctx_init` makes it, `setup` handed it once it is.
    pub(crate) fn new(
        lib: &'static G,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        shared: &TlsShared,
        keylog: Option<SharedKeyLog>,
        setup: QuicContextSetup<'_>,
        cx: &mut TlsCx<'_>,
    ) -> Result<QuicSession<G>, ErrorKind> {
        let mut s = Session::new_quic(lib, identity, peer, shared, keylog)?;
        let mut applied = false;
        let mut taken = None;
        let o = &identity.options;
        if o.session_cache {
            taken = cx.take_session();
            if let Some(ticket) = taken.as_ref() {
                match s.apply_session(cx, ticket) {
                    Ok(made) => applied = made,
                    Err(kind) => {
                        cx.return_session(taken);
                        return Err(kind);
                    }
                }
            }
        }
        let made = if applied {
            Ok(())
        } else {
            s.client_init(cx, 0)
        };
        let made = made.and_then(|()| {
            let native = s.native_objects().expect("made by the client's init");
            if let Err(why) = setup(native) {
                return Err(cx.fail(ErrorKind::FailedInit, format_args!("{why}")));
            }
            // Where the sessions are kept, the peer's tickets are kept with
            // the connection's transport parameters (`quic_gtls_handshake_cb`).
            let tickets = cx.caches_sessions();
            s.gs.as_mut().expect("made above").quic_hook(tickets);
            s.finish_init(cx)
        });
        cx.return_session(taken);
        made?;
        Ok(QuicSession(s))
    }
}

impl<G: Gnutls> QuicTls for QuicSession<G>
where
    G::Session: Send,
{
    /// The `gnutls_session_t`, as both the session and the context.
    fn native(&self) -> TlsNative {
        self.0.native_objects().expect("made as the session is")
    }

    fn early_data(&self) -> Option<&TlsTicket> {
        self.0.quic_early.as_ref()
    }

    fn early_data_decided(&mut self, cx: &mut TlsCx<'_>, early: bool) -> Result<(), ErrorKind> {
        self.0.quic_early_decided(cx, early)
    }

    fn before_recv(&mut self, cx: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        if !self.0.trust_ready {
            self.0.trust_setup(cx)?;
        }
        Ok(())
    }

    fn drive(
        &mut self,
        cx: &mut TlsCx<'_>,
        params: &mut dyn FnMut() -> Option<Vec<u8>>,
        call: &mut dyn FnMut(&mut dyn DriveCall),
    ) {
        let s = &mut self.0;
        assert!(
            s.quic_early.is_none() || s.quic_decided,
            "the ALPN offer is made before the handshake's first bytes"
        );
        let lib = s.lib;
        let keylog = s.keylog.as_deref().filter(|l| KeyLog::enabled(l));
        let mut gcall = Call {
            io: Reach::Quic(cx),
            io_result: IoResult::Ok,
            trust: None,
            trust_ready: s.trust_ready,
            keylog,
            alpn: Some(Chosen::H3),
            quic_params: Some(params),
        };
        let (identity, names) = (&s.identity, &s.names);
        let mut check = |gs: &mut G::Session, cx: &mut TlsCx<'_>| {
            session::report_handshake(gs, cx);
            let checked = session::check_peer(lib, gs, identity, names, cx);
            if checked.is_err() {
                // No session of a peer that fails its check is resumed.
                cx.forget_sessions();
            }
            checked
        };
        let gs = s.gs.as_mut().expect("made as the session is");
        gs.drive(&mut gcall, &mut check, call);
    }
}
