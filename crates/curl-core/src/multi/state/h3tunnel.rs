//! A transfer's tunnel through an HTTPS proxy that speaks HTTP/3, made
//! by a race's attempt over the QUIC connection it made to the proxy
//! (`cf_h3_proxy_tunnel`): the `CONNECT` sent on a request stream of the
//! connection, the proxy's answer read and traced, and the connection,
//! once the proxy agrees, the attempt that won the race. C's attempt is
//! the H3-PROXY filter, connected as the tunnel is (`cf_h3_proxy_connect`).

use curl_alloc::{OutOfMemory, TryVec as _};

use super::{Lent, StepCx};
use crate::auth::http::Side;
use crate::components::Component;
use crate::conn::ConnectMachine;
use crate::conn::h3proxy::{H3Proxy, TunnelState};
use crate::conn::io::Socket;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::proto::http2::{connect_udp_fields, fields_of};
use crate::text::Text;
use crate::trace;

const H3P: Component = Component::H3Proxy;

/// What a drive of the race's tunnels came to.
pub(super) enum Tunnels {
    /// None is decided.
    Idle,
    /// Attempt `.0`'s tunnel is through.
    Through(usize),
    /// Attempt `.0`'s tunnel failed with `.1`, traced.
    Failed(usize, ErrorKind),
}

/// Each tunnel the race's attempts make moved on as far as its socket
/// lets it, its `CONNECT` sent first if it is new, oldest first as C's
/// race checks its attempts (`cf_ip_ballers_run`): the first decided ends
/// the drive. Running out of memory fails the transfer.
pub(super) fn drive<H: Host>(
    machine: &mut ConnectMachine,
    lent: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
) -> Result<Tunnels, OutOfMemory> {
    let udp = machine.dialing().asks_udp();
    for (i, p, socket) in machine.tunnels() {
        // Up as the pass before found it, the attempt is connected now
        // (`H3_TUNNEL_ESTABLISHED`): the request follows the `CONNECT`,
        // and what reads it starts over (`Curl_client_reset`).
        if p.established() {
            crate::upload::trace_reset(cx, false);
            return Ok(Tunnels::Through(i));
        }
        let ran = if p.unasked() {
            connect(p, socket, udp, lent, cx).and_then(|()| run(p, socket, udp, lent, cx))
        } else {
            run(p, socket, udp, lent, cx)
        };
        match ran {
            // Up, the attempt is connected at the next pass, which comes
            // at once as the answer marked the transfer to run
            // (`Curl_multi_mark_dirty`).
            Ok(true) => {
                cx.rest.dirty.insert(cx.me.index());
            }
            Ok(false) => {}
            Err(ErrorKind::OutOfMemory) => return Err(OutOfMemory),
            Err(kind) => {
                p.go_state(cx, TunnelState::Failed);
                return Ok(Tunnels::Failed(i, kind));
            }
        }
    }
    Ok(Tunnels::Idle)
}

/// A `CONNECT` sent on a new stream (`cf_h3_proxy_submit_CONNECT`), and
/// what the connection has to send sent.
fn connect<H: Host>(
    proxy: &mut H3Proxy,
    socket: &dyn Socket,
    udp: bool,
    lent: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    let target = lent.route.target();
    let port = Text::<8>::clipped(format_args!(":{}", target.port())).0;
    let parts = [
        &b"[0] CONNECT start for "[..],
        target.request_host(),
        port.bytes(),
    ];
    trace::of_with(cx, H3P, &parts);
    let head = super::tunnel::connect_head(lent, cx, b"HTTP/3", udp)?;
    let fields = match &head.udp {
        Some(udp) => connect_udp_fields(
            &head.head,
            head.authorized,
            udp.scheme,
            &udp.authority,
            &udp.path,
        )?,
        None => fields_of(&head.head, None, b"https")?,
    };
    let pairs = fields.pairs().map_err(oom)?;
    let url = cx.easy().report().url().map(copied).transpose()?;
    let url = url.as_deref().unwrap_or_default();
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
    proxy.egress(cx, socket)
}

fn copied(url: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut v = Vec::new();
    v.try_extend_from_slice(url).map_err(oom)?;
    Ok(v)
}

/// `H3_TUNNEL_CONNECT`: read what came and send what waits, once; then,
/// with the answer whole, `H3_TUNNEL_RESPONSE`. True once the proxy
/// agreed; a `CONNECT` that goes again for a Negotiate challenge is moved
/// on at once.
fn run<H: Host>(
    p: &mut H3Proxy,
    socket: &dyn Socket,
    udp: bool,
    lent: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
) -> Result<bool, ErrorKind> {
    loop {
        p.progress(cx, socket)?;
        if p.answer().is_none() {
            // A stream closed before its answer leaves the tunnel failed.
            if p.tunnel_closed() {
                return Err(ErrorKind::RecvError);
            }
            return Ok(false);
        }
        p.go_state(cx, TunnelState::Response);
        if inspect(p, socket, udp, lent, cx)? {
            return Ok(true);
        }
    }
}

/// The proxy's final answer, traced and acted on
/// (`Curl_http_proxy_inspect_tunnel_response`): the tunnel is up (true),
/// or a `CONNECT` goes again for a Negotiate challenge taken (false), or
/// it failed.
fn inspect<H: Host>(
    p: &mut H3Proxy,
    socket: &dyn Socket,
    udp: bool,
    lent: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
) -> Result<bool, ErrorKind> {
    let answer = p.answer().expect("the answer is whole");
    let status = answer.status;
    let what = super::tunnel::method_name(udp);
    trace::info(cx, format_args!("{what} Response Status {status}"));
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
            && super::h2tunnel::challenged(lent, cx, H3P, value)?
        {
            p.go_state(cx, TunnelState::Init);
            connect(p, socket, udp, lent, cx)?;
            return Ok(false);
        }
    }
    if udp {
        let answer = p.answer().expect("the answer is whole");
        super::tunnel::udp_answer(cx, status, answer.field(b"capsule-protocol"))?;
    } else if status / 100 != 2 {
        return Err(ErrorKind::CouldntConnect);
    } else {
        trace::info(
            cx,
            format_args!("CONNECT tunnel established, response {status}"),
        );
    }
    p.go_state(cx, TunnelState::Established);
    cx.easy_mut().auth.side(Side::Proxy).finish();
    Ok(true)
}

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}
