//! A transfer's way through a SOCKS proxy, made over its connection to
//! the proxy (`lib/socks.c`'s filter): the handshake's requests sent and
//! its replies read, then the connection is the destination's, or the
//! transfer fails with what the proxy refused.

use curl_alloc::try_box;

use super::{Bytes, Connecting, Handshake, Ip, StepCx, TransferState, Wake, report_resolved};
use crate::conn::io::{Events, Recv, Sent};
use crate::conn::socks::{
    Creds, Dest, Failed, GssError, GssLine, GssMethod, Handshake as Exchange, Resolved, SocksError,
    Took, Version,
};
use crate::conn::{Came, Made, RecvFailed};
use crate::error::ErrorKind;
use crate::gss::Style;
use crate::multi::Host;
use crate::trace;

/// The most one read takes.
const READ_SIZE: usize = 512;

/// A SOCKS handshake under way.
#[derive(Debug)]
pub(crate) struct Socks(Exchange);

impl Socks {
    /// What the handshake waits for on its socket.
    pub(super) fn interest(&self) -> Events {
        if self.0.to_send().is_empty() {
            Events::IN
        } else {
            Events::OUT
        }
    }
}

/// The handshake under way.
fn socks(handshake: &mut Option<Box<Handshake>>) -> &mut Exchange {
    match handshake.as_deref_mut() {
        Some(Handshake::Socks(s)) => &mut s.0,
        _ => unreachable!("a SOCKS handshake is under way"),
    }
}

/// Connected to the proxy: the handshake's first request is made, for
/// the destination, its name resolved here if `version` has it so.
pub(super) fn dialed<H: Host>(
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
    version: Version,
) -> (TransferState, Wake) {
    match start(&mut c, cx, version) {
        Ok(handshake) => {
            c.handshake = Some(handshake);
            (TransferState::Connecting(c), Wake::Again)
        }
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}

fn start<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
    version: Version,
) -> Result<Box<Handshake>, ErrorKind> {
    let ip = cx.easy().options().ip_version;
    let found = match c.lease.dialed().target() {
        None => None,
        Some(Ok((answer, found))) => Some(Ok((answer.clone(), *found))),
        Some(Err(_)) => Some(Err(())),
    };
    let leg = c.route.socks().expect("through a SOCKS proxy");
    let target = leg.to;
    let resolved = match found {
        None => Resolved::Remote,
        Some(Ok((answer, found))) => {
            match found {
                Came::Cached => {
                    let name = Bytes(answer.name());
                    trace::info(cx, format_args!("Hostname {name} was found in DNS cache"));
                }
                Came::Stale => {
                    trace::info(cx, format_args!("Hostname in DNS cache was stale, zapped"));
                }
                Came::Resolved => {}
            }
            report_resolved(cx, &answer, target.port());
            Resolved::pick(version, answer.addrs(), ip)
        }
        Some(Err(())) => Resolved::Failed,
    };
    let creds = leg.creds.map(|c| Creds {
        user: &c.user,
        password: &c.password,
        service: &c.service,
    });
    let dest = Dest {
        name: target.name(),
        port: target.port(),
        resolved,
    };
    let options = cx.easy().options();
    let auth = options.proxy.socks5_auth;
    let gss = cx.easy().libraries().gss.map(|library| GssMethod {
        library,
        nec: options.proxy.socks5_gssapi_nec,
        delegation: options.login.delegation,
    });
    let exchange = Exchange::new(version, dest, creds, auth, gss).map_err(|e| refused(cx, &e))?;
    try_box(Handshake::Socks(Socks(exchange))).map_err(|_| ErrorKind::OutOfMemory)
}

/// Move the handshake on as far as its socket lets it.
pub(super) fn step<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    match run(&mut c, cx) {
        Ok(false) => (TransferState::Connecting(c), Wake::Idle),
        Ok(true) => opened(c, cx),
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}

/// Send and read until the socket blocks, or the proxy connected to the
/// destination (`socks_flush`, `socks_recv`).
fn run<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<bool, ErrorKind> {
    loop {
        let h = socks(&mut c.handshake);
        let dialed = c.lease.dialed().stream();
        if !h.to_send().is_empty() {
            match dialed.send(cx, h.to_send(), None) {
                Ok(Sent::Bytes(n)) => h.sent(n.get()),
                Ok(Sent::WouldBlock) => return Ok(false),
                Err(_) if let Some(e) = h.gss_send_failed() => return Err(refused(cx, &e)),
                Err(_) => {
                    return Err(failed(
                        cx,
                        crate::conn::ProxyError::SendConnect,
                        format_args!("Failed to send SOCKS request: {}", ErrorKind::SendError),
                    ));
                }
            }
            continue;
        }
        if h.done() {
            return Ok(true);
        }
        let took = h.take_saying(dialed.received(), &mut |line| say(cx, line));
        match took {
            Ok(Took::Read(n)) => {
                dialed.consume(n);
                if h.gss_starts() {
                    let leg = c.route.socks().expect("through a SOCKS proxy");
                    h.start_gss(leg.at.name(), &mut |line| say(cx, line))
                        .map_err(|e| refused(cx, &e))?;
                }
                continue;
            }
            Ok(Took::Need(_)) => {}
            Err(e) => return Err(refused(cx, &e)),
        }
        let received = dialed.received().len();
        match dialed.recv(cx, READ_SIZE, None) {
            Ok(Recv::Data(_)) => {}
            Ok(Recv::WouldBlock) => return Ok(false),
            Ok(Recv::Eof) | Err(RecvFailed::Os(_)) if let Some(e) = h.gss_recv_failed(received) => {
                return Err(refused(cx, &e));
            }
            Ok(Recv::Eof) => {
                return Err(failed(
                    cx,
                    crate::conn::ProxyError::RecvConnect,
                    format_args!("Failed to receive SOCKS response, proxy closed connection"),
                ));
            }
            Err(RecvFailed::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
            Err(RecvFailed::Os(_)) => {
                return Err(failed(
                    cx,
                    crate::conn::ProxyError::RecvConnect,
                    format_args!("Failed to receive SOCKS response: {}", ErrorKind::RecvError),
                ));
            }
        }
    }
}

/// The time to connect ran out: if a GSS-API message was awaited, the
/// read of it failed, as C's blocking read fails it once no time is left
/// (`Curl_blockread_all`), and the method with it.
pub(super) fn timed_out<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Option<ErrorKind> {
    let received = c.lease.dialed().stream().received().len();
    let e = socks(&mut c.handshake).gss_recv_failed(received)?;
    Some(refused(cx, &e))
}

/// The proxy connected where it was asked, traced as C traces it
/// (`socks_proxy_cf_connect`), and the connection kept for transfers
/// that insist on the user being authenticated if it was: the next
/// handshake follows.
fn opened<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let authenticated = socks(&mut c.handshake).authenticated();
    if authenticated {
        c.lease.dialed().socks5_authenticated();
    }
    c.lease
        .proxied(Made::SOCKS, || cx.easy().options().proxy.haproxy);
    let (remote, local) = c.lease.dialed().ends();
    let (lip, lport) = local.map_or((None, 0), |l| (Some(l.ip()), l.port()));
    let proxy = c.route.proxy.as_ref().expect("dialed through a proxy");
    let to = proxy
        .socks(c.route.target())
        .expect("through a SOCKS proxy")
        .to;
    let (name, port) = (Bytes(to.name()), to.port());
    trace::info(
        cx,
        format_args!(
            "Opened SOCKS connection from {} port {lport} to {name} port {port} (via {} port {})",
            Ip(lip),
            remote.shown_ip(),
            remote.port()
        ),
    );
    c.handshake = None;
    (TransferState::Connecting(c), Wake::Again)
}

/// The handshake failed, as the proxy's error (`CURLE_PROXY`).
fn failed<H: Host>(
    cx: &mut StepCx<'_, H>,
    code: crate::conn::ProxyError,
    said: std::fmt::Arguments<'_>,
) -> ErrorKind {
    cx.report_mut().set_proxy_error(code);
    trace::fail(cx, ErrorKind::Proxy, said)
}

/// A line of the GSS-API method's, traced.
fn say<H: Host>(cx: &mut StepCx<'_, H>, line: GssLine<'_>) {
    trace::info(cx, format_args!("{line}"));
}

/// A handshake refused, said as C says it.
fn refused<H: Host>(cx: &mut StepCx<'_, H>, e: &SocksError) -> ErrorKind {
    let Some(code) = e.code() else {
        return ErrorKind::OutOfMemory;
    };
    cx.report_mut().set_proxy_error(code);
    if let SocksError::Gss(gss) = e {
        return gss_refused(cx, gss);
    }
    match e.said() {
        Some(said) => trace::fail(cx, ErrorKind::Proxy, format_args!("{said}")),
        None => ErrorKind::Proxy,
    }
}

/// The GSS-API method failed: what the library said of the call that
/// failed (`check_gss_err`, which says nothing of a text too long for its
/// buffer), what C says of the step, and that the method failed, each a
/// reason of its own (`Curl_SOCKS5_gssapi_negotiate`'s caller).
fn gss_refused<H: Host>(cx: &mut StepCx<'_, H>, e: &GssError) -> ErrorKind {
    if let Some((call, status)) = e.status {
        let gss = cx
            .easy()
            .libraries()
            .gss
            .expect("a GSS-API status is the library's");
        // At most C's 1024 bytes, on the stack.
        let mut text = crate::text::Text::<1024>::new();
        if gss
            .describe(&status, Style::Socks, &mut |part| text.push_clipped(part))
            .is_ok()
        {
            trace::fail_with(
                cx,
                ErrorKind::Proxy,
                &[
                    b"GSS-API error: ",
                    GssError::call_name(call).as_bytes(),
                    b" failed: ",
                    text.bytes(),
                ],
            );
        }
    }
    if e.step != Failed::Silently {
        trace::fail(cx, ErrorKind::Proxy, format_args!("{}", e.step));
    }
    trace::fail(
        cx,
        ErrorKind::Proxy,
        format_args!("Unable to negotiate SOCKS5 GSS-API context."),
    )
}
