//! A transfer's tunnel through an HTTPS proxy that agreed to HTTP/2, set
//! up over its connection to the proxy (`cf-h2-proxy.c`'s `H2_CONNECT`):
//! the `CONNECT` sent as a stream of a session with the proxy, the
//! proxy's answer read and traced, and the session, once the proxy
//! agrees, the layer the tunnel's bytes pass through.

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use super::{Connecting, Handshake, StepCx, TransferState, Wake};
use crate::components::Component;
use crate::conn::Made;
use crate::conn::h2proxy::{H2Proxy, TunnelState};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::proto::http::negotiate;
use crate::proto::http1::auth::{self, Challenges, HeardNote, Side};
use crate::proto::http1::framing::Note as HeadNote;
use crate::proto::http2::fields_of;
use crate::trace;

/// The session made with the proxy and its `CONNECT` sent on it
/// (`cf_h2_proxy_ctx_init`, `submit_CONNECT`), what the connection
/// received and did not use going to it first.
pub(super) fn start<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
) -> Result<Box<Handshake>, ErrorKind> {
    let library = cx
        .easy()
        .libraries()
        .h2
        .expect("HTTP/2 is offered to a proxy with a library to speak it");
    let mut proxy = H2Proxy::open(library, cx.max_streams())?;
    proxy.received(c.lease.dialed().stream().rx_mut().take());
    connect(&mut proxy, c, cx)?;
    let proxy = try_box(proxy).map_err(oom)?;
    try_box(Handshake::H2Connect(proxy)).map_err(oom)
}

/// A `CONNECT` sent on a new stream (`submit_CONNECT`).
fn connect<H: Host>(
    proxy: &mut H2Proxy,
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    let (head, _) = super::tunnel::connect_head(c, cx, true)?;
    let fields = fields_of(&head, None, b"https")?;
    let pairs = fields.pairs().map_err(oom)?;
    if proxy.submit(&pairs).is_err() {
        return Err(trace::fail(
            cx,
            ErrorKind::SendError,
            format_args!("Failed sending CONNECT to proxy"),
        ));
    }
    let stream = proxy.stream().map_or(-1, |s| s.0);
    trace::of(
        cx,
        Component::H2Proxy,
        format_args!("[{stream}] new tunnel state 'connect'"),
    );
    Ok(())
}

/// The session under way in a handshake.
fn proxy(handshake: &mut Option<Box<Handshake>>) -> &mut H2Proxy {
    match handshake.as_deref_mut() {
        Some(Handshake::H2Connect(p)) => p,
        _ => unreachable!("an HTTP/2 tunnel is set up"),
    }
}

/// Move the handshake on as far as its socket lets it.
pub(super) fn step<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    match run(&mut c, cx) {
        Ok(Ran::Idle) => (TransferState::Connecting(c), Wake::Idle),
        Ok(Ran::Again) => (TransferState::Connecting(c), Wake::Again),
        Ok(Ran::Through) => (TransferState::Connecting(c), Wake::Again),
        Err(kind) => {
            if let Some(Handshake::H2Connect(p)) = c.handshake.as_deref_mut() {
                p.set_state(TunnelState::Failed);
            }
            (TransferState::Connecting(c).fail(kind), Wake::Again)
        }
    }
}

enum Ran {
    /// Nothing more until the socket is ready.
    Idle,
    /// Another `CONNECT` goes at once.
    Again,
    /// The tunnel is through: the next handshake follows.
    Through,
}

fn run<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<Ran, ErrorKind> {
    // Through the proxy's TLS, the socket's sends and receives are the
    // TLS session's records, traced as C's socket filter traces them.
    let traced = c.route.proxy_tls().map(|_| c.route.socket_component());
    let p = proxy(&mut c.handshake);
    if p.conn_closed() {
        return Err(trace::fail(
            cx,
            ErrorKind::CouldntConnect,
            format_args!("proxy closed connection"),
        ));
    }
    let stream = c.lease.dialed().stream();
    p.ingress(cx, stream.below(traced))
        .and_then(|()| p.egress(cx, stream.below(traced)))
        .map_err(|e| e.kind())?;
    if p.answer().is_none() {
        // A stream closed before its answer leaves the tunnel failed.
        if p.tunnel_closed() {
            return Err(ErrorKind::RecvError);
        }
        return Ok(Ran::Idle);
    }
    inspect(c, cx)
}

/// The proxy's final answer, traced and acted on
/// (`Curl_http_proxy_inspect_tunnel_response`): the tunnel is up, or a
/// `CONNECT` goes again for a Negotiate challenge taken, or it failed.
fn inspect<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<Ran, ErrorKind> {
    let p = proxy(&mut c.handshake);
    let answer = p.answer().expect("the answer is whole");
    let status = answer.status;
    trace::info(cx, format_args!("CONNECT Response Status {status}"));
    let total = answer.fields.len();
    trace::info(cx, format_args!("Response Headers ({total} total):"));
    for (name, value) in &answer.fields {
        trace::info_with(cx, &[b"  ", name, b": ", value]);
    }
    if status == 407 && challenged(c, cx)? {
        let mut p = take(c);
        connect(&mut p, c, cx)?;
        c.handshake = Some(try_box(Handshake::H2Connect(p)).map_err(oom)?);
        return Ok(Ran::Again);
    }
    if status / 100 != 2 {
        proxy(&mut c.handshake).set_state(TunnelState::Failed);
        return Err(ErrorKind::CouldntConnect);
    }
    trace::info(
        cx,
        format_args!("CONNECT tunnel established, response {status}"),
    );
    let mut p = take(c);
    p.set_state(TunnelState::Established);
    let stream = p.stream().map_or(-1, |s| s.0);
    trace::of(
        cx,
        Component::H2Proxy,
        format_args!("[{stream}] new tunnel state 'established'"),
    );
    trace::info(cx, format_args!("CONNECT phase completed for HTTP/2 proxy"));
    cx.easy_mut().auth.side(Side::Proxy).finish();
    c.lease
        .dialed()
        .stream()
        .push_over_received(|received| {
            assert!(received.is_empty(), "the session read what came");
            Ok(p as Box<dyn crate::conn::layer::Layer>)
        })
        .map_err(oom)?;
    c.lease.proxied(Made::TUNNEL | Made::H2_TUNNEL, || {
        cx.easy().options().proxy.haproxy
    });
    Ok(Ran::Through)
}

/// The session, out of the handshake.
fn take(c: &mut Connecting) -> Box<H2Proxy> {
    match c.handshake.take().map(|h| *h) {
        Some(Handshake::H2Connect(p)) => p,
        _ => unreachable!("an HTTP/2 tunnel is set up"),
    }
}

/// A 407's `Proxy-Authenticate`, if it has one, taken in
/// (`Curl_http_input_auth`): whether a Negotiate challenge was taken, so
/// that the `CONNECT` goes again with its answer. No other challenge
/// makes it go again, as none sets C's `newurl`.
fn challenged<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<bool, ErrorKind> {
    let p = proxy(&mut c.handshake);
    let answer = p.answer().expect("the answer is whole");
    let Some((_, value)) = answer
        .fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(b"Proxy-Authenticate"))
    else {
        return Ok(false);
    };
    let mut copied = Vec::new();
    copied.try_extend_from_slice(value).map_err(oom)?;
    let value = copied;
    trace::of_with(
        cx,
        Component::H2Proxy,
        &[b"[0] CONNECT: fwd auth header '", &value, b"'"],
    );
    let asked = super::tunnel::proxy_asked(c, cx);
    let mut challenges = Challenges::default();
    let heard = challenges.read(&value, &asked).map_err(oom)?;
    for note in heard.notes() {
        let note = match note {
            HeardNote::Problem(method) => HeadNote::AuthProblem(method),
            HeardNote::DuplicateDigest => HeadNote::DuplicateDigest,
        };
        trace::info(cx, format_args!("{note}"));
    }
    cx.report_mut().add_proxy_auth_offered(challenges.offered);
    // Negotiate in use with the proxy takes each challenge into its
    // context (`auth_spnego`).
    let Some(gss) = cx.easy().libraries().gss else {
        return Ok(false);
    };
    if !cx.easy().auth.proxy_picks_negotiate() {
        return Ok(false);
    }
    let (peer, credentials, _) = super::tunnel::proxy(&c.route);
    let request = negotiate::Request {
        gss,
        side: Side::Proxy,
        credentials,
        peer,
        delegation: cx.easy().options().login.delegation,
        // The origin's TLS has no peer yet while the tunnel is set up.
        tls: None,
    };
    let mut taken = false;
    for challenge in auth::negotiate_challenges(&value) {
        taken |= negotiate::challenged(cx, &mut c.negotiate, &request, challenge);
    }
    Ok(taken)
}

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}
