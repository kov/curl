//! A connection's TLS handshakes (`cf_setup_connect`'s SSL stages): an
//! HTTPS proxy's, before its tunnel or as the last stage of a connection
//! requests go whole over, and the origin's, the last of a connection's
//! setup. The handle's TLS library makes a session for the peer, whose
//! layer goes on top of the connection's stream and is connected there;
//! the bytes after go through it, the origin's through the proxy's.

use curl_alloc::{OutOfMemory, try_box};

use super::{Connecting, Handshake, StepCx, TransferState, Wake};
use crate::components::Component;
use crate::conn::Made;
use crate::conn::tls::TlsLayer;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::options::HttpVersion;
use crate::options::{SslOptions, TlsMaxVersion, TlsMinVersion, TlsOptions};
use crate::tls::{Alpn, Handshake as Shake, SessionPeer, TlsPeer, TlsShared};
use crate::trace;

/// Whose TLS a handshake makes: the origin's (C's `SSL` filter) or an
/// HTTPS proxy's (`SSL-PROXY`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsSide {
    Origin,
    Proxy,
}

impl TlsSide {
    /// The filter C's chain holds for it.
    pub(super) fn filter(self) -> Component {
        match self {
            TlsSide::Origin => Component::Ssl,
            TlsSide::Proxy => Component::SslProxy,
        }
    }

    /// What the connection's `made` records once it is made.
    fn made(self) -> Made {
        match self {
            TlsSide::Origin => Made::TLS,
            TlsSide::Proxy => Made::PROXY_TLS,
        }
    }
}

/// The handshakes before it are made: the session is made and its layer
/// put on the stream, taking the bytes the stream received and did not
/// use, which follow a proxy's answer. An HTTPS proxy's is offered
/// HTTP/1.1 by ALPN unless ALPN is off, whatever the transfer's version
/// (`cf_ssl_proxy_create`), and is the proxy's peer, its sessions kept
/// for the proxy.
pub(super) fn start<H: Host>(
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
    side: TlsSide,
) -> (TransferState, Wake) {
    // Held apart from the handle, as the multi's state is borrowed too.
    let libraries = cx.easy().shared_libraries();
    let backend = libraries
        .tls
        .as_deref()
        .expect("a route has TLS only with a TLS library");
    let options = cx.easy().options();
    let (identity, peer, via) = match side {
        TlsSide::Origin => (
            c.route.tls.as_ref().expect("a TLS route"),
            &*c.route.origin,
            c.route.via.as_deref(),
        ),
        TlsSide::Proxy => {
            let proxy = c.route.proxy.as_ref().expect("an HTTPS proxy");
            (
                proxy.tls().expect("an HTTPS proxy's TLS"),
                &*proxy.peer,
                None,
            )
        }
    };
    // HTTP/2 is offered only where a library speaks it, and the request
    // may.
    let version = options.http.version;
    let versions = c.proto.http_versions(options);
    let h2 = versions.h2 && cx.easy().libraries().h2.is_some();
    let alpn = match (options.tls.options.alpn, side, version) {
        (false, ..) => Alpn::None,
        (true, TlsSide::Proxy, _) => Alpn::Http11,
        (true, TlsSide::Origin, HttpVersion::Http10) => Alpn::Http10,
        (true, TlsSide::Origin, _) if h2 && !versions.h1 => Alpn::H2,
        (true, TlsSide::Origin, _) if h2 => Alpn::H2Http11,
        (true, TlsSide::Origin, _) => Alpn::Http11,
    };
    // Early data, where the transfer asks for it and makes requests
    // (`conn_cfg->earlydata`, `bits.connect_only`).
    let early_data = identity.options.ssl_options.contains(SslOptions::EARLYDATA)
        && !options.connect_only.reserves();
    let peer_of = |early| TlsPeer::of(peer, early);
    // What the library keeps across the multi's connections, made with
    // its first session.
    let shared = match &mut *cx.rest.tls {
        Some(shared) => shared,
        none => match TlsShared::new() {
            Ok(made) => none.insert(made),
            Err(OutOfMemory) => {
                return (
                    TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
                    Wake::Again,
                );
            }
        },
    };
    let session = match backend.session(identity, &peer_of(early_data), alpn, shared) {
        Ok(session) => session,
        Err(kind) => return (TransferState::Connecting(c).fail(kind), Wake::Again),
    };
    // Who its sessions are kept for: the peer, through a connect-to's
    // peer if any (`cf_ssl_peer_init`).
    let kept_for = match SessionPeer::new(identity, peer, via, backend.id()) {
        Ok(p) => p,
        Err(OutOfMemory) => {
            return (
                TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
                Wake::Again,
            );
        }
    };
    let filter = side.filter();
    let stream = c.lease.dialed().stream();
    let pushed = stream
        .push_over_received(|early| TlsLayer::boxed(session, early, kept_for, filter))
        .and_then(|()| try_box(Handshake::Tls(side)));
    match pushed {
        Ok(h) => {
            c.handshake = Some(h);
            (TransferState::Connecting(c), Wake::Again)
        }
        Err(OutOfMemory) => (
            TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
            Wake::Again,
        ),
    }
}

/// Move the handshake on, as far as the socket lets it, each call traced
/// as the TLS filter traces its connect (`ssl_cf_connect`); the versions
/// allowed are checked first (`ssl_prefs_check`).
pub(super) fn step<H: Host>(
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
    side: TlsSide,
) -> (TransferState, Wake) {
    let ssl = side.filter();
    trace::of(cx, ssl, format_args!("cf_connect()"));
    let traced = Some(c.route.socket_component());
    let identity = match side {
        TlsSide::Origin => c.route.tls.as_ref(),
        TlsSide::Proxy => c.route.proxy_tls(),
    };
    let checked = prefs_check(cx, &identity.expect("a TLS stage's settings").options);
    let shaken = match checked {
        Ok(()) => c.lease.dialed().stream().connect(cx, traced),
        Err(kind) => Err(kind),
    };
    let (code, done) = match shaken {
        Ok(Shake::Done) => (trace::Code(Ok(())), 1),
        Ok(Shake::Waiting) => (trace::Code(Ok(())), 0),
        Err(kind) => (trace::Code(Err(kind)), 0),
    };
    trace::of(cx, ssl, format_args!("cf_connect() -> {code}, done={done}"));
    // The session may have made its objects.
    cx.lend(super::tls_native(&c.lease));
    match shaken {
        Ok(Shake::Done) => {
            c.lease.dialed().mark_made(side.made());
            c.handshake = None;
            (TransferState::Connecting(c), Wake::Again)
        }
        Ok(Shake::Waiting) => (TransferState::Connecting(c), Wake::Idle),
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}

/// The newest version the filter's `options` allow is not older than
/// the oldest (`ssl_prefs_check`), each as C numbers them: any TLS 1.x is
/// below TLS 1.0; no newest set, or the library's, allows any.
fn prefs_check<H: Host>(cx: &mut StepCx<'_, H>, options: &TlsOptions) -> Result<(), ErrorKind> {
    let min = match options.min_version {
        TlsMinVersion::Tls1 => 1,
        TlsMinVersion::Tls1_0 => 4,
        TlsMinVersion::Tls1_1 => 5,
        TlsMinVersion::Tls1_2 => 6,
        TlsMinVersion::Tls1_3 => 7,
    };
    let max = match options.max_version {
        TlsMaxVersion::None | TlsMaxVersion::Default => return Ok(()),
        TlsMaxVersion::Tls1_0 => 4,
        TlsMaxVersion::Tls1_1 => 5,
        TlsMaxVersion::Tls1_2 => 6,
        TlsMaxVersion::Tls1_3 => 7,
    };
    if max < min {
        let why = format_args!("CURL_SSLVERSION_MAX incompatible with CURL_SSLVERSION");
        return Err(trace::fail(cx, ErrorKind::SslConnectError, why));
    }
    Ok(())
}
