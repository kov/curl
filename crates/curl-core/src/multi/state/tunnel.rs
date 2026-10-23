//! A transfer's tunnel through an HTTP proxy, set up over its connection
//! to the proxy (`cf-h1-proxy.c`'s `H1_CONNECT`): the `CONNECT` made and
//! sent, the proxy's answer traced, delivered and read for its
//! challenges, and what it leads to: the tunnel, another `CONNECT` over
//! the same connection or a new one, or the transfer's failure.

use std::net::SocketAddr;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use super::{Connecting, Handshake, StepCx, TransferState, Wake, established};
use crate::conn::Connected;
use crate::conn::io::{Events, Recv, Sent};
use crate::conn::{Peer, RecvFailed};
use crate::error::ErrorKind;
use crate::handler::{DebugKind, HeaderOrigin};
use crate::multi::Host;
use crate::options::ProxyType;
use crate::progress;
use crate::proto::ProtoState;
use crate::proto::http::auth::{
    AuthAct, AuthRequest, Challenges, HeardNote, Offered, OutputError, PeerAsked, Secret, Side,
};
use crate::proto::http1::fields::{self, MAX_HEADERS};
use crate::proto::http1::framing::Note as HeadNote;
use crate::proto::http1::request::{CredentialGate, decimal};
use crate::proto::http1::tunnel::{Answer, AnswerError, Applied, ConnectRequest, Read};
use crate::time::Instant;
use crate::trace;

/// The most one read takes.
const READ_SIZE: usize = 16384;

/// A `CONNECT` under way.
#[derive(Debug)]
pub(crate) struct Tunnel {
    request: Vec<u8>,
    sent: usize,
    answer: Answer,
    /// The proxy's challenges, from its answer.
    challenges: Challenges,
    /// `Proxy-Authorization` went with it, and the handshake has not
    /// waited on its socket since: C holds the header (`hd_proxy_auth`)
    /// only until `cf_h1_proxy_connect` returns.
    authorized: bool,
    /// The proxy closed the connection on an answer it may be asked
    /// again: the next `CONNECT` goes over a new one
    /// (`close_connection`).
    closed: bool,
    /// The answer's head bytes, against C's limit (`allheadercount`).
    head_bytes: usize,
    /// Bytes at the front of the connection's input that progress was
    /// taken for already: the byte a line's end was checked against.
    counted: usize,
}

/// The tunnel under way in a handshake.
fn tunnel(handshake: &mut Option<Box<Handshake>>) -> &mut Tunnel {
    match handshake.as_deref_mut() {
        Some(Handshake::Connect(t)) => t,
        _ => unreachable!("a tunnel is set up"),
    }
}

impl Tunnel {
    /// What the handshake waits for on its socket.
    pub(super) fn interest(&self) -> Events {
        if self.sent < self.request.len() {
            Events::OUT
        } else {
            Events::IN
        }
    }
}

/// Connected to the proxy: the tunnel's first `CONNECT` is made
/// (`http_proxy_cf_connect`).
pub(super) fn dialed<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    trace::info(cx, format_args!("CONNECT: no ALPN negotiated"));
    match start(&c, cx) {
        Ok(tunnel) => {
            c.handshake = Some(tunnel);
            (TransferState::Connecting(c), Wake::Again)
        }
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}

/// The proxy and what it is given, as the route has them.
fn proxy(c: &Connecting) -> (&Peer, Option<Secret<'_>>, bool) {
    let proxy = c
        .route
        .proxy
        .as_ref()
        .expect("a tunnel goes through a proxy");
    let secret = proxy
        .creds
        .as_deref()
        .map(|c| Secret::new(&c.user, &c.password));
    (&proxy.peer, secret, proxy.kind == ProxyType::Http10)
}

/// A `CONNECT` made (`start_CONNECT`), with the proxy's credentials as
/// far as they go.
fn start<H: Host>(c: &Connecting, cx: &mut StepCx<'_, H>) -> Result<Box<Handshake>, ErrorKind> {
    // Each `CONNECT` reads the application's header lists as they are
    // now.
    let options = cx.easy_mut().options_mut();
    options
        .reread_headers()
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    let target = c.route.target();
    let mut digits = [0; 20];
    let port = decimal(u64::from(target.port()), &mut digits);
    let mut authority = Vec::new();
    let made = (|| -> Result<(), OutOfMemory> {
        authority.try_extend_from_slice(target.shown())?;
        authority.try_push(b':')?;
        authority.try_extend_from_slice(port)
    })();
    made.map_err(oom)?;
    let (peer, secret, http10) = proxy(c);
    let request = AuthRequest {
        origin: peer,
        method: b"CONNECT",
        uri: &authority,
        get_or_head: true,
        // Nothing the application set for an origin goes to a proxy.
        trusted: None,
    };
    let random = |bytes: &mut [u8; 12]| curl_os::random::fill(bytes).map_err(|_| ());
    let options = cx.easy().options();
    let custom = options
        .proxy
        .own_headers(&options.http)
        .replaces(b"Proxy-Authorization");
    let output = cx
        .easy_mut()
        .auth
        .side(Side::Proxy)
        .output(secret, custom, &request, random);
    let output = output.map_err(|e| match e {
        OutputError::OutOfMemory => ErrorKind::OutOfMemory,
        OutputError::Random => ErrorKind::FailedInit,
    })?;
    cx.report_mut().set_proxy_auth_used(output.used);
    // Named once in use, though Digest sends nothing before its first
    // challenge (`output_auth_headers`).
    if !output.used.is_empty() {
        let user = secret.map_or(&b""[..], |s| s.user());
        let name = output.used.name().as_bytes();
        trace::info_with(
            cx,
            &[b"Proxy auth using ", name, b" with user '", user, b"'"],
        );
    }
    trace::info_with(cx, &[b"Establishing HTTP proxy tunnel to ", &authority]);
    let mut out = Vec::new();
    let options = cx.easy().options();
    let trusted = match &c.proto {
        ProtoState::Http(request) => request.trusted(),
        _ => CredentialGate::FIRST.trusted(),
    };
    let connect = ConnectRequest {
        authority: &authority,
        http10,
        proxy_authorization: output.header.as_ref().map(|(m, v)| (m.name(), &v[..])),
        user_agent: options.http.user_agent.as_deref(),
        headers: options.proxy.own_headers(&options.http),
        trusted,
    };
    connect.render(&mut out).map_err(oom)?;
    let tunnel = Tunnel {
        request: out,
        sent: 0,
        answer: Answer::new(),
        challenges: Challenges::default(),
        authorized: output.header.is_some(),
        closed: false,
        head_bytes: 0,
        counted: 0,
    };
    try_box(Handshake::Connect(tunnel)).map_err(oom)
}

/// Move the handshake on as far as its socket lets it.
pub(super) fn step<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    match run(&mut c, cx) {
        Ok(Ran::Idle) => {
            tunnel(&mut c.handshake).authorized = false;
            (TransferState::Connecting(c), Wake::Idle)
        }
        Ok(Ran::Again) => (TransferState::Connecting(c), Wake::Again),
        Ok(Ran::Up(remote, local, at)) => established(c, cx, remote, local, at),
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}

enum Ran {
    /// Nothing more until the socket is ready.
    Idle,
    /// The setup goes on at once: another `CONNECT`, or a new connection.
    Again,
    Up(SocketAddr, Option<SocketAddr>, Instant),
}

fn run<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<Ran, ErrorKind> {
    loop {
        let t = tunnel(&mut c.handshake);
        if t.sent < t.request.len() {
            let sent = c.lease.dialed().stream().send(&t.request[t.sent..]);
            let n = match sent {
                Ok(Sent::Bytes(n)) => n.get(),
                Ok(Sent::WouldBlock) => return Ok(Ran::Idle),
                Err(_) => {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::SendError,
                        format_args!("Failed sending CONNECT to proxy"),
                    ));
                }
            };
            let t = tunnel(&mut c.handshake);
            let from = t.sent;
            t.sent += n;
            trace::bytes(cx, DebugKind::HeaderOut, &t.request[from..from + n]);
            continue;
        }
        if t.answer.done() {
            progress::update(cx, false)?;
            return finish(c, cx);
        }
        // C reads the answer a byte at a time, taking stock of the
        // transfer after each read, the end of the connection's too, and
        // once more as it returns for more or with the answer whole
        // (`recv_CONNECT_resp`, `H1_CONNECT`).
        let dialed = c.lease.dialed().stream();
        if dialed.received().is_empty() {
            match dialed.recv(READ_SIZE) {
                Ok(Recv::Data(_)) => {}
                Ok(Recv::WouldBlock) => {
                    progress::update(cx, false)?;
                    return Ok(Ran::Idle);
                }
                Ok(Recv::Eof) => {
                    progress::update(cx, false)?;
                    return closed(c, cx);
                }
                Err(RecvFailed::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                Err(RecvFailed::Os(_)) => return Err(ErrorKind::RecvError),
            }
        }
        let read = t.answer.read(dialed.received());
        let (used, read) = match read {
            Ok(read) => read,
            Err(e) => return Err(refused(cx, e)),
        };
        dialed.consume(used);
        let looked = used + usize::from(t.answer.looked_ahead());
        let owed = looked
            .checked_sub(t.counted)
            .expect("a byte looked at ahead is read next");
        t.counted = looked - used;
        for _ in 0..owed {
            progress::update(cx, false)?;
        }
        match read {
            Read::Line => line(c, cx)?,
            Read::More => {}
            Read::Done => {
                progress::update(cx, false)?;
                return finish(c, cx);
            }
        }
    }
}

/// The proxy closed the connection: the answer ends where it is, after
/// the line it was reading; the end of a 407 is no failure where
/// credentials were sent and methods are left to try, but the connection
/// is not used again (`recv_CONNECT_resp`).
fn closed<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<Ran, ErrorKind> {
    let t = tunnel(&mut c.handshake);
    if t.answer.closed() == Read::Line {
        line(c, cx)?;
    }
    let t = tunnel(&mut c.handshake);
    let wanted = !cx.easy().options().proxy.auth.0.is_empty();
    if wanted && t.authorized && cx.easy().auth.proxy_offers(&t.challenges) {
        trace::info(cx, format_args!("Proxy CONNECT connection closed"));
        tunnel(&mut c.handshake).closed = true;
        progress::update(cx, false)?;
        return finish(c, cx);
    }
    Err(trace::fail(
        cx,
        ErrorKind::RecvError,
        format_args!("Proxy CONNECT aborted"),
    ))
}

/// A line of the answer is traced, checked, delivered and taken in
/// (`single_header`).
fn line<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    let t = tunnel(&mut c.handshake);
    let line = t.answer.line();
    trace::bytes(cx, DebugKind::HeaderIn, line);
    if let Err(e) = t.answer.verify() {
        return Err(refused(cx, e));
    }
    let first = t.answer.code().is_none();
    let pipeline = c.proto.pipeline_mut().expect("HTTP delivers");
    if first {
        pipeline.connect_status(cx, line)?;
    } else {
        pipeline.header(cx, line, HeaderOrigin::Connect)?;
    }
    let len = line.len();
    cx.report_mut().sizes_mut().header += len as u64;
    t.head_bytes += len;
    if t.head_bytes > MAX_HEADERS {
        let (bytes, max) = (t.head_bytes, MAX_HEADERS);
        return Err(trace::fail(
            cx,
            ErrorKind::RecvError,
            format_args!("Too large response headers: {bytes} > {max}"),
        ));
    }
    let applied = match t.answer.apply() {
        Ok(applied) => applied,
        Err(e) => return Err(refused(cx, e)),
    };
    if first && let Some(code) = t.answer.code() {
        cx.report_mut().set_connect_code(code);
    }
    match applied {
        Applied::Nothing => {}
        Applied::Note(note) => trace::info(cx, format_args!("{note}")),
        Applied::Challenge => {
            let asked = proxy_asked(c, cx);
            let t = tunnel(&mut c.handshake);
            let value = fields::header_value(t.answer.line()).unwrap_or(&[]);
            let heard = t.challenges.read(value, &asked).map_err(oom)?;
            for note in heard.notes() {
                let note = match note {
                    HeardNote::Problem(method) => HeadNote::AuthProblem(method),
                    HeardNote::DuplicateDigest => HeadNote::DuplicateDigest,
                };
                trace::info(cx, format_args!("{note}"));
            }
        }
        Applied::End => {
            let problem = cx.easy().auth.problem() || t.challenges.refused();
            if let Some(note) = t.answer.end_head(problem) {
                trace::info(cx, format_args!("{note}"));
            }
        }
    }
    Ok(())
}

/// What the proxy is asked, for its challenges.
fn proxy_asked<H: Host>(c: &Connecting, cx: &StepCx<'_, H>) -> PeerAsked {
    let (peer, secret, _) = proxy(c);
    cx.easy()
        .auth
        .asked((None, peer), (secret, peer), false, true)
        .proxy
}

/// The answer ended: the tunnel is up, or another `CONNECT` is made for
/// the proxy's challenge, or it failed (`H1_CONNECT`'s response).
fn finish<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<Ran, ErrorKind> {
    let t = tunnel(&mut c.handshake);
    if t.answer.chunks_read() {
        trace::info(cx, format_args!("chunk reading DONE"));
    }
    let code = t.answer.code().unwrap_or(0);
    if code / 100 == 2 {
        trace::info(cx, format_args!("CONNECT phase completed for HTTP proxy"));
        cx.easy_mut().auth.side(Side::Proxy).finish();
        trace::info(
            cx,
            format_args!("CONNECT tunnel established, response {code}"),
        );
        return match c.lease.tunneled() {
            Connected::Established {
                remote, local, at, ..
            } => Ok(Ran::Up(remote, local, at)),
            _ => unreachable!("a tunnel makes the connection"),
        };
    }
    // What the challenges lead to (`Curl_http_auth_act`).
    let asked = {
        let (peer, secret, _) = proxy(c);
        cx.easy()
            .auth
            .asked((None, peer), (secret, peer), false, true)
    };
    let t = tunnel(&mut c.handshake);
    let closes = t.answer.closes() || t.closed;
    let offered = Offered {
        host: Challenges::default(),
        proxy: std::mem::take(&mut t.challenges),
    };
    let act = AuthAct::of(code, &offered, &asked);
    let report = cx.report_mut();
    report.add_proxy_auth_offered(offered.proxy.offered);
    if let Some(picked) = act.proxy_picked.filter(|p| !p.is_empty()) {
        report.set_proxy_auth_used(picked);
    }
    let route = &c.route;
    let proxy = &route
        .proxy
        .as_ref()
        .expect("a tunnel goes through a proxy")
        .peer;
    cx.easy_mut()
        .auth
        .apply(&act, offered, &route.origin, proxy)
        .map_err(oom)?;
    if !act.reload {
        return Err(trace::fail(
            cx,
            ErrorKind::CouldntConnect,
            format_args!("CONNECT tunnel failed, response {code}"),
        ));
    }
    if closes {
        trace::info(cx, format_args!("Connect me again please"));
        c.handshake = None;
        if !c.lease.redial(&mut cx.rest.net(cx.me)) {
            return Err(ErrorKind::CouldntConnect);
        }
        return Ok(Ran::Again);
    }
    // Over the same connection.
    let tunnel = start(c, cx)?;
    c.handshake = Some(tunnel);
    Ok(Ran::Again)
}

/// An answer refused, said as C says it.
fn refused<H: Host>(cx: &mut StepCx<'_, H>, e: AnswerError) -> ErrorKind {
    let kind = match &e {
        AnswerError::OutOfMemory => return ErrorKind::OutOfMemory,
        AnswerError::TooLarge => ErrorKind::RecvError,
        AnswerError::BadChunks(bad) => bad.kind(),
        _ => ErrorKind::WeirdServerReply,
    };
    match e.said() {
        Some(said) => trace::fail(cx, kind, format_args!("{said}")),
        None => kind,
    }
}

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}
