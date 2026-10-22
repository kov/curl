//! A transfer's way through a SOCKS proxy, made over its connection to
//! the proxy (`lib/socks.c`'s filter): the handshake's requests sent and
//! its replies read, then the connection is the destination's, or the
//! transfer fails with what the proxy refused.

use curl_alloc::try_box;

use super::{
    Bytes, Connecting, Handshake, Ip, StepCx, TransferState, Wake, established, report_resolved,
};
use crate::conn::io::{Events, Recv, Sent};
use crate::conn::socks::{Creds, Dest, Handshake as Exchange, Resolved, SocksError, Took, Version};
use crate::conn::{Connected, Found, RecvFailed};
use crate::error::ErrorKind;
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
    let proxy = c.proxy.as_ref().expect("dialed through a proxy");
    let leg = proxy.socks(c.target()).expect("through a SOCKS proxy");
    let target = leg.to;
    let resolved = match found {
        None => Resolved::Remote,
        Some(Ok((answer, found))) => {
            match found {
                Found::Cached => {
                    let name = Bytes(answer.name());
                    trace::info(cx, format_args!("Hostname {name} was found in DNS cache"));
                }
                Found::Stale => {
                    trace::info(cx, format_args!("Hostname in DNS cache was stale, zapped"));
                }
                Found::Resolved => {}
            }
            report_resolved(cx, &answer, target.port());
            Resolved::pick(version, answer.addrs(), ip)
        }
        Some(Err(())) => Resolved::Failed,
    };
    let creds = leg.creds.map(|c| Creds {
        user: &c.user,
        password: &c.password,
    });
    let dest = Dest {
        name: target.name(),
        port: target.port(),
        resolved,
    };
    let auth = cx.easy().options().proxy.socks5_auth;
    let exchange = Exchange::new(version, dest, creds, auth).map_err(|e| refused(cx, &e))?;
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
        let dialed = c.lease.dialed();
        if !h.to_send().is_empty() {
            match dialed.send(h.to_send()) {
                Ok(Sent::Bytes(n)) => h.sent(n.get()),
                Ok(Sent::WouldBlock) => return Ok(false),
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
        match h.take(dialed.received()) {
            Ok(Took::Read(n)) => {
                dialed.consume(n);
                continue;
            }
            Ok(Took::Need(_)) => {}
            Err(e) => return Err(refused(cx, &e)),
        }
        match dialed.recv(READ_SIZE) {
            Ok(Recv::Data(_)) => {}
            Ok(Recv::WouldBlock) => return Ok(false),
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

/// The proxy connected where it was asked, traced as C traces it
/// (`socks_proxy_cf_connect`), and the connection kept for transfers
/// that insist on the user being authenticated if it was: the HTTP
/// proxy behind it tunnels next, or the connection is up.
fn opened<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let authenticated = socks(&mut c.handshake).authenticated();
    let dialed = c.lease.dialed();
    if authenticated {
        dialed.socks5_authenticated();
    }
    let (remote, local) = dialed.ends();
    let (lip, lport) = local.map_or((None, 0), |l| (Some(l.ip()), l.port()));
    let proxy = c.proxy.as_ref().expect("dialed through a proxy");
    let to = proxy.socks(c.target()).expect("through a SOCKS proxy").to;
    let (name, port) = (Bytes(to.name()), to.port());
    trace::info(
        cx,
        format_args!(
            "Opened SOCKS connection from {} port {lport} to {name} port {port} (via {} port {})",
            Ip(lip),
            remote.ip(),
            remote.port()
        ),
    );
    if proxy.tunnels() {
        return super::tunnel::dialed(c, cx);
    }
    match c.lease.tunneled() {
        Connected::Established { remote, local, at } => established(c, cx, remote, local, at),
        _ => unreachable!("the handshake makes the connection"),
    }
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

/// A handshake refused, said as C says it.
fn refused<H: Host>(cx: &mut StepCx<'_, H>, e: &SocksError) -> ErrorKind {
    let Some(code) = e.code() else {
        return ErrorKind::OutOfMemory;
    };
    cx.report_mut().set_proxy_error(code);
    match e.said() {
        Some(said) => trace::fail(cx, ErrorKind::Proxy, format_args!("{said}")),
        None => ErrorKind::Proxy,
    }
}
