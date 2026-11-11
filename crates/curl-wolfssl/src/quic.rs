//! One QUIC connection's wolfSSL (`lib/vquic/vquic-tls.c` over
//! `Curl_wssl_ctx_init`): its context and session's object made at once,
//! as for QUIC's transport, resuming one the cache kept, the context
//! handed to the QUIC library's setup where C calls it; its trust store
//! set up before the peer's first bytes; its handshake driven by the QUIC
//! library, whose calls this session's callbacks run inside (`drive`);
//! the peer reported and checked as the QUIC library says the handshake
//! is done (`Curl_vquic_report_handshake`, `Curl_vquic_tls_verify_peer`).

use curl_core::error::ErrorKind;
use curl_core::tls::{Checked, Residuals};
use curl_core::tls::{
    Chosen, DriveCall, QuicContextSetup, QuicTls, TlsCx, TlsIdentity, TlsNative, TlsPeerKind,
    TlsTicket,
};

use crate::library::{Call, Reach, Ssl, Wolfssl, as_c, c_string};
use crate::session::{self, Session};
use crate::sys;

/// One QUIC connection's session, through the library `W`.
pub(crate) struct QuicSession<W: Wolfssl>(Session<W>);

impl<W: Wolfssl> QuicSession<W> {
    /// The session `s` (`Session::new_quic`) for one QUIC connection,
    /// its library's objects made as `Curl_wssl_ctx_init` makes them for
    /// QUIC, its context handed to `setup`.
    pub(crate) fn new(
        mut s: Session<W>,
        setup: QuicContextSetup<'_>,
        cx: &mut TlsCx<'_>,
    ) -> Result<QuicSession<W>, ErrorKind> {
        s.quic_init(cx, setup)?;
        Ok(QuicSession(s))
    }
}

/// The peer checked as C checks a QUIC session's
/// (`Curl_vquic_tls_verify_peer`): its name, or its address where it has
/// no name sent by SNI, in the certificate where the host is verified,
/// failing only where the library says it does not match; then the
/// pinned key. No words are said of a failed match.
fn check_peer<S: Ssl>(
    ssl: &S,
    identity: &TlsIdentity,
    host: &[u8],
    kind: TlsPeerKind,
    cx: &mut TlsCx<'_>,
) -> Result<Checked, ErrorKind> {
    if identity.verify_host {
        let rc = match curl_core::tls::sni_unlowered(host, kind) {
            Some(name) => ssl.check_host(name),
            None => {
                let ip = c_string(host)?;
                ssl.check_ip(as_c(&ip))
            }
        };
        match rc {
            // No certificate of the peer's, which C reads as no memory.
            None => return Err(ErrorKind::OutOfMemory),
            Some(sys::WOLFSSL_FAILURE) => return Err(ErrorKind::PeerFailedVerification),
            Some(_) => {}
        }
    }
    let pin = session::verify_pinned(ssl, cx)?;
    Checked::new(cx, pin, Residuals::NONE)
}

impl<W: Wolfssl> QuicTls for QuicSession<W> {
    /// The context and the session's object, as for a stream session.
    fn native(&self) -> TlsNative {
        use curl_core::tls::TlsSession as _;
        self.0.native().expect("made as the session is")
    }

    fn early_data(&self) -> Option<&TlsTicket> {
        self.0.quic_early.as_ref()
    }

    fn early_data_decided(&mut self, cx: &mut TlsCx<'_>, early: bool) -> Result<(), ErrorKind> {
        self.0.quic_early_decided(cx, early)
    }

    fn before_recv(&mut self, cx: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        if !self.0.state.store_ready {
            self.0.setup_store(cx)?;
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
        let mut wcall = Call {
            io: Reach::Quic(cx),
            state: &mut s.state,
            store: None,
            // A QUIC session's are kept for HTTP/3 (`"h3"`).
            alpn: Some(Chosen::H3),
            quic_params: Some(params),
        };
        let (identity, host, kind) = (&s.identity, &s.host, s.kind);
        let mut check = |ssl: &mut _, cx: &mut TlsCx<'_>| {
            session::report_handshake(ssl, cx);
            let checked = check_peer(ssl, identity, host, kind, cx);
            if checked.is_err() {
                // No session of a peer that fails its check is resumed.
                cx.forget_sessions();
            }
            checked.map(|_| ())
        };
        let ssl = s.ssl.as_mut().expect("made as the session is");
        ssl.drive(&mut wcall, &mut check, call);
    }
}
