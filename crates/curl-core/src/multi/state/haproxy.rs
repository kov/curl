//! The PROXY protocol's line a new connection sends before anything else
//! (`lib/cf-haproxy.c`): the addresses and ports it comes from and goes
//! to, as the server behind a load balancer would be told them.

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};

use curl_alloc::{OutOfMemory, TryVec as _};

use super::{Connecting, Handshake, OsError, StepCx, TransferState, Wake, up};
use crate::conn::io::{Events, Sent};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::proto::http1::request::decimal;
use crate::time::Instant;
use crate::trace;

/// The line being sent, and the connection it is sent over.
#[derive(Debug)]
pub(crate) struct Preface {
    line: Vec<u8>,
    sent: usize,
    remote: SocketAddr,
    local: Option<SocketAddr>,
    at: Instant,
}

impl Preface {
    /// It only sends (`cf_haproxy_adjust_pollset`).
    pub(super) fn interest(&self) -> Events {
        Events::OUT
    }
}

/// The line for a connection from `local` to `remote`, the first hop's
/// socket, saying `client` in place of both addresses if given
/// (`cf_haproxy_date_out_set`). A connection over a Unix socket would
/// say `PROXY UNKNOWN`; there are none yet.
fn line(
    remote: SocketAddr,
    local: Option<SocketAddr>,
    client: Option<&[u8]>,
) -> Result<Vec<u8>, OutOfMemory> {
    // The longest address an IPv6 socket gives, 45 bytes, and more.
    let mut src = [0u8; 64];
    let mut dst = [0u8; 64];
    let text = |buf: &mut [u8; 64], ip: Option<std::net::IpAddr>| -> usize {
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        if let Some(ip) = ip {
            write!(cursor, "{ip}").expect("an address fits");
        }
        usize::try_from(cursor.position()).expect("within the buffer")
    };
    let (src, dst, v6) = match client {
        // The family is IPv4's only if the address is one (`Curl_is_ipv4addr`).
        Some(ip) => {
            let v4 = std::str::from_utf8(ip).is_ok_and(|s| s.parse::<Ipv4Addr>().is_ok());
            (ip, ip, !v4)
        }
        None => {
            let s = text(&mut src, local.map(|l| l.ip()));
            let d = text(&mut dst, Some(remote.ip()));
            (&src[..s], &dst[..d], remote.is_ipv6())
        }
    };
    let mut lport = [0; 20];
    let mut rport = [0; 20];
    let lport = decimal(u64::from(local.map_or(0, |l| l.port())), &mut lport);
    let rport = decimal(u64::from(remote.port()), &mut rport);
    let family: &[u8] = if v6 { b"TCP6" } else { b"TCP4" };
    let mut out = Vec::new();
    for part in [
        &b"PROXY "[..],
        family,
        b" ",
        src,
        b" ",
        dst,
        b" ",
        lport,
        b" ",
        rport,
        b"\r\n",
    ] {
        out.try_extend_from_slice(part)?;
    }
    Ok(out)
}

/// The connection is up: its line is sent next, if the transfer asks
/// for one; otherwise none is made.
pub(super) fn wanted<H: Host>(
    cx: &StepCx<'_, H>,
    remote: SocketAddr,
    local: Option<SocketAddr>,
    at: Instant,
) -> Result<Option<Preface>, ErrorKind> {
    let proxy = &cx.easy().options().proxy;
    if !proxy.haproxy {
        return Ok(None);
    }
    let line = line(remote, local, proxy.haproxy_client_ip.as_deref())
        .map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(Some(Preface {
        line,
        sent: 0,
        remote,
        local,
        at,
    }))
}

/// Send the line as far as the socket takes it, then the connection is
/// up (`cf_haproxy_connect`).
pub(super) fn step<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let p = match c.handshake.as_deref_mut() {
        Some(Handshake::Haproxy(p)) => p,
        _ => unreachable!("the PROXY line is being sent"),
    };
    while p.sent < p.line.len() {
        match cx
            .rest
            .pool_net(cx.me)
            .0
            .get(&c.lease)
            .send(&p.line[p.sent..])
        {
            Ok(Sent::Bytes(n)) => p.sent += n.get(),
            Ok(Sent::WouldBlock) => return (TransferState::Connecting(c), Wake::Idle),
            Err(e) => {
                let why = OsError(&e);
                let kind = trace::fail(
                    cx,
                    ErrorKind::SendError,
                    format_args!("Send failure: {why}"),
                );
                return (TransferState::Connecting(c).fail(kind), Wake::Again);
            }
        }
    }
    let (remote, local, at) = (p.remote, p.local, p.at);
    up(c, cx, remote, local, at)
}
