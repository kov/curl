//! A transfer's tunnel through an HTTPS proxy that speaks HTTP/3, set up
//! over the QUIC connection the setup's race made to it
//! (`cf_h3_proxy_tunnel`): the `CONNECT` sent on a request stream of the
//! connection, the proxy's answer read and traced, and the connection,
//! once the proxy agrees, the layer the tunnel's bytes pass through.

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use super::{Connecting, Handshake, StepCx, TransferState, Wake};
use crate::components::Component;
use crate::conn::Made;
use crate::conn::h3proxy::{H3Proxy, TunnelState};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::proto::http1::auth::Side;
use crate::proto::http2::fields_of;
use crate::trace;

const H3P: Component = Component::H3Proxy;

/// The tunnel over the connection the race made, and its `CONNECT` sent
/// (`H3_TUNNEL_INIT`).
pub(super) fn start<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
) -> Result<Box<Handshake>, ErrorKind> {
    let quic = c
        .lease
        .dialed()
        .take_quic()
        .expect("an HTTP/3 proxy's tunnel goes over its QUIC connection");
    let mut proxy = H3Proxy::new(quic);
    connect(&mut proxy, c, cx)?;
    let proxy = try_box(proxy).map_err(oom)?;
    try_box(Handshake::H3Connect(proxy)).map_err(oom)
}

/// A `CONNECT` sent on a new stream (`cf_h3_proxy_submit_CONNECT`), and
/// what the connection has to send sent.
fn connect<H: Host>(
    proxy: &mut H3Proxy,
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    let target = c.route.target();
    let (host, port) = (
        String::from_utf8_lossy(target.request_host()),
        target.port(),
    );
    trace::of(cx, H3P, format_args!("[0] CONNECT start for {host}:{port}"));
    let (head, _) = super::tunnel::connect_head(c, cx, b"HTTP/3")?;
    let fields = fields_of(&head, None, b"https")?;
    let pairs = fields.pairs().map_err(oom)?;
    let url = cx.easy().report().url().map(copied).transpose()?;
    let url = url.as_deref().unwrap_or_default();
    let socket = c.lease.dialed().stream().socket();
    if let Err(kind) = proxy.submit(cx, socket, &pairs, url) {
        let kind = match kind {
            ErrorKind::OutOfMemory => kind,
            _ => ErrorKind::SendError,
        };
        return Err(trace::fail(
            cx,
            kind,
            format_args!("Failed sending CONNECT to proxy"),
        ));
    }
    proxy.go_state(cx, TunnelState::Connect);
    let socket = c.lease.dialed().stream().socket();
    proxy.egress(cx, socket)
}

fn copied(url: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut v = Vec::new();
    v.try_extend_from_slice(url).map_err(oom)?;
    Ok(v)
}

/// The tunnel under way in a handshake.
fn proxy(handshake: &mut Option<Box<Handshake>>) -> &mut H3Proxy {
    match handshake.as_deref_mut() {
        Some(Handshake::H3Connect(p)) => p,
        _ => unreachable!("an HTTP/3 tunnel is set up"),
    }
}

/// Move the handshake on as far as its socket lets it.
pub(super) fn step<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    match run(&mut c, cx) {
        Ok(Ran::Idle) => (TransferState::Connecting(c), Wake::Idle),
        Ok(Ran::Again | Ran::Through) => (TransferState::Connecting(c), Wake::Again),
        Err(ErrorKind::OutOfMemory) => (
            TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
            Wake::Again,
        ),
        Err(kind) => {
            if let Some(Handshake::H3Connect(p)) = c.handshake.as_deref_mut() {
                p.go_state(cx, TunnelState::Failed);
            }
            // The tunnel is the race's attempt in C, whose failure is the
            // last attempt's (`cf_ip_happy_connect`): the proxy's
            // connection goes, and the setup fails as the race does.
            if c.handshake.take().is_some() {
                trace::of(cx, H3P, format_args!("cf_h3_proxy_destroy()"));
            }
            let failed = crate::conn::ConnectError::Failed(None, kind);
            let kind = super::connect_failed(cx, &c.route, failed);
            super::attempt_failed(c, cx, kind)
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

/// `H3_TUNNEL_CONNECT`: read what came and send what waits, once; then,
/// with the answer whole, `H3_TUNNEL_RESPONSE`.
fn run<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<Ran, ErrorKind> {
    let socket = c.lease.dialed().stream().socket();
    let p = proxy(&mut c.handshake);
    p.progress(cx, socket)?;
    if p.answer().is_none() {
        // A stream closed before its answer leaves the tunnel failed.
        if p.tunnel_closed() {
            return Err(ErrorKind::RecvError);
        }
        return Ok(Ran::Idle);
    }
    p.go_state(cx, TunnelState::Response);
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
    if status == 407 {
        let value = answer
            .fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(b"Proxy-Authenticate"))
            .map(|(_, v)| copied(v))
            .transpose()?;
        if let Some(value) = value
            && super::h2tunnel::challenged(c, cx, H3P, value)?
        {
            let p = proxy(&mut c.handshake);
            p.go_state(cx, TunnelState::Init);
            let mut p = take(c);
            connect(&mut p, c, cx)?;
            c.handshake = Some(try_box(Handshake::H3Connect(p)).map_err(oom)?);
            return Ok(Ran::Again);
        }
    }
    if status / 100 != 2 {
        return Err(ErrorKind::CouldntConnect);
    }
    trace::info(
        cx,
        format_args!("CONNECT tunnel established, response {status}"),
    );
    let mut p = take(c);
    p.go_state(cx, TunnelState::Established);
    // The request follows the `CONNECT`: what reads it starts over
    // (`Curl_client_reset`).
    crate::upload::trace_reset(cx, false);
    cx.easy_mut().auth.side(Side::Proxy).finish();
    c.lease
        .dialed()
        .stream()
        .push_over_received(|received| {
            assert!(
                received.is_empty(),
                "nothing is read over QUIC's socket but by it"
            );
            Ok(p as Box<dyn crate::conn::layer::Layer>)
        })
        .map_err(oom)?;
    c.lease.proxied(Made::TUNNEL | Made::H3_TUNNEL, || {
        cx.easy().options().proxy.haproxy
    });
    Ok(Ran::Through)
}

/// The tunnel, out of the handshake.
fn take(c: &mut Connecting) -> Box<H3Proxy> {
    match c.handshake.take().map(|h| *h) {
        Some(Handshake::H3Connect(p)) => p,
        _ => unreachable!("an HTTP/3 tunnel is set up"),
    }
}

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}
