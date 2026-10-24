//! The origin's TLS handshake, the last of a connection's setup
//! (`cf_setup_connect`'s SSL stage): the handle's TLS library makes a
//! session for the origin, whose layer goes on top of the connection's
//! stream and is connected there; the request's bytes go through it
//! after.

use curl_alloc::{OutOfMemory, try_box};

use super::{Connecting, Handshake, StepCx, TransferState, Wake};
use crate::components::Component;
use crate::conn::Made;
use crate::conn::tls::TlsLayer;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::options::HttpVersion;
use crate::options::{TlsMaxVersion, TlsMinVersion};
use crate::tls::{Alpn, Handshake as Shake, TlsPeer, TlsShared};
use crate::trace;

/// The handshakes before it are made: the session is made and its layer
/// put on the stream, taking the bytes the stream received and did not
/// use, which follow a proxy's answer.
pub(super) fn start<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let backend = cx
        .easy()
        .libraries()
        .tls
        .expect("a route has TLS only with a TLS library");
    let identity = c.route.tls.as_ref().expect("a TLS route");
    let options = cx.easy().options();
    let alpn = match (options.tls.options.alpn, options.http.version) {
        (false, _) => Alpn::None,
        (true, HttpVersion::Http10) => Alpn::Http10,
        (true, HttpVersion::Http11) => Alpn::Http11,
    };
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
    let peer = TlsPeer::of(&c.route.origin);
    let session = match backend.session(identity, &peer, alpn, shared) {
        Ok(session) => session,
        Err(kind) => return (TransferState::Connecting(c).fail(kind), Wake::Again),
    };
    let stream = c.lease.dialed().stream();
    let pushed = stream
        .push_over_received(|early| TlsLayer::boxed(session, early))
        .and_then(|()| try_box(Handshake::Tls));
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
pub(super) fn step<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let ssl = Component::Ssl;
    trace::of(cx, ssl, format_args!("cf_connect()"));
    let traced = Some(c.route.socket_component());
    let shaken = match prefs_check(cx) {
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
            c.lease.dialed().mark_made(Made::TLS);
            c.handshake = None;
            (TransferState::Connecting(c), Wake::Again)
        }
        Ok(Shake::Waiting) => (TransferState::Connecting(c), Wake::Idle),
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}

/// The newest version allowed is not older than the oldest
/// (`ssl_prefs_check`), each as C numbers them: any TLS 1.x is below
/// TLS 1.0; no newest set, or the library's, allows any.
fn prefs_check<H: Host>(cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    let options = &cx.easy().options().tls.options;
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
