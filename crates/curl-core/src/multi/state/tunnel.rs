//! A transfer's tunnel through an HTTP proxy, set up over its connection
//! to the proxy (`cf-h1-proxy.c`'s `H1_CONNECT`): the `CONNECT` made and
//! sent, the proxy's answer traced, delivered and read for its
//! challenges, and what it leads to: the tunnel, another `CONNECT` over
//! the same connection or a new one, or the transfer's failure.

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use super::{Connecting, Handshake, StepCx, TransferState, Wake};
use crate::components::Component;
use crate::conn::io::{Events, Recv, Sent};
use crate::conn::{Made, Peer, RecvFailed, Tcp};
use crate::error::ErrorKind;
use crate::handler::{DebugKind, HeaderOrigin};
use crate::multi::Host;
use crate::multi::cx::DriveCx;
use crate::options::ProxyType;
use crate::progress;
use crate::proto::ProtoState;
use crate::proto::http::negotiate;
use crate::proto::http1::auth::{
    self, AuthAct, AuthRequest, Challenges, HeardNote, Offered, Output, OutputError, PeerAsked,
    Secret, Side,
};
use crate::proto::http1::fields::{self, MAX_HEADERS};
use crate::proto::http1::framing::Note as HeadNote;
use crate::proto::http1::request::{CredentialGate, decimal};
use crate::proto::http1::tunnel::{Answer, AnswerError, Applied, ConnectRequest, Read, UdpTarget};
use crate::tls::Chosen;
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
    // An HTTP/3 proxy's tunnel is its QUIC connection's own: the setup
    // skips the HTTP proxy's filter (`CF_SETUP_CNNCT_HTTP_PROXY`).
    if c.route.proxy_over_quic() {
        return match super::h3tunnel::start(&mut c, cx) {
            Ok(tunnel) => {
                c.handshake = Some(tunnel);
                (TransferState::Connecting(c), Wake::Again)
            }
            Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
        };
    }
    // The filter below the tunnel's is asked (`http_proxy_cf_connect`):
    // an HTTPS proxy's TLS, the SOCKS proxy's, or the one that dialed the
    // proxy.
    let below = if c.route.proxy_tls().is_some() {
        Component::SslProxy
    } else if c.route.socks().is_some() {
        Component::Socks
    } else {
        Component::HappyEyeballs
    };
    // What the proxy's TLS negotiated names the tunnel's protocol; with
    // none, the proxy type does: HTTP/2 for an HTTPS proxy asked for in
    // it.
    let what = method_name(&c.route);
    let h2 = match super::query_alpn(cx, &c.lease, below) {
        Some(chosen) => {
            let name = chosen.name();
            trace::info(cx, format_args!("{what}: '{name}' negotiated"));
            chosen == Chosen::H2
        }
        None => {
            trace::info(cx, format_args!("{what}: no ALPN negotiated"));
            c.route
                .proxy
                .as_ref()
                .is_some_and(|p| p.kind == ProxyType::Https2)
        }
    };
    if h2 && cx.easy().libraries().h2.is_none() {
        let failed = trace::fail(
            cx,
            ErrorKind::CouldntConnect,
            format_args!("CONNECT: negotiated ALPN 'h2' not supported"),
        );
        return (TransferState::Connecting(c).fail(failed), Wake::Again);
    }
    let started = if h2 {
        super::h2tunnel::start(&mut c, cx)
    } else {
        start(&mut c, cx)
    };
    match started {
        Ok(tunnel) => {
            c.handshake = Some(tunnel);
            (TransferState::Connecting(c), Wake::Again)
        }
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}

/// What the tunnel's request is called in C's lines: `CONNECT`, or
/// `CONNECT-UDP` for a tunnel QUIC's datagrams go through.
pub(super) fn method_name(route: &Tcp) -> &'static str {
    if route.tunnels_udp() {
        "CONNECT-UDP"
    } else {
        "CONNECT"
    }
}

/// A CONNECT-UDP's final answer, `status` with its `capsule-protocol`
/// field's value if it has one, acted on
/// (`Curl_http_proxy_inspect_tunnel_response`): the datagrams go as
/// capsules (RFC 9297), which a proxy may leave unsaid but not ask for
/// another protocol in place of. Traced; the tunnel fails but on a 2xx.
pub(super) fn udp_answer<H: Host>(
    cx: &mut StepCx<'_, H>,
    status: u16,
    capsules: Option<&[u8]>,
) -> Result<(), ErrorKind> {
    if status / 100 != 2 {
        return Err(trace::fail(
            cx,
            ErrorKind::CouldntConnect,
            format_args!("Failed to establish CONNECT-UDP tunnel, response {status}"),
        ));
    }
    match capsules {
        Some(b"?1") => trace::info(
            cx,
            format_args!("CONNECT-UDP tunnel established, response {status}"),
        ),
        Some(v) => {
            let v = String::from_utf8_lossy(v);
            return Err(trace::fail(
                cx,
                ErrorKind::CouldntConnect,
                format_args!(
                    "Failed to establish CONNECT-UDP tunnel, response {status}, \
                     unsupported capsule-protocol value '{v}'"
                ),
            ));
        }
        None => trace::info(
            cx,
            format_args!(
                "CONNECT-UDP tunnel established, response {status} \
                 but no capsule-protocol header found"
            ),
        ),
    }
    Ok(())
}

/// The proxy and what it is given, as the route has them.
pub(super) fn proxy(route: &Tcp) -> (&Peer, Option<Secret<'_>>, bool) {
    let proxy = route.proxy.as_ref().expect("a tunnel goes through a proxy");
    let secret = proxy.creds.as_deref().map(crate::conn::ProxyCreds::secret);
    (&proxy.peer, secret, proxy.kind == ProxyType::Http10)
}

/// A `CONNECT` made (`start_CONNECT`), with the proxy's credentials as
/// far as they go.
fn start<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<Box<Handshake>, ErrorKind> {
    let ConnectHead {
        head: request,
        authorized,
        ..
    } = connect_head(c, cx, b"HTTP")?;
    let tunnel = Tunnel {
        request,
        sent: 0,
        answer: Answer::new(),
        challenges: Challenges::default(),
        authorized,
        closed: false,
        head_bytes: 0,
        counted: 0,
    };
    try_box(Handshake::Connect(tunnel)).map_err(oom)
}

/// The `CONNECT`'s head, as HTTP/1 writes it, and whether it carries
/// `Proxy-Authorization` (`Curl_http_proxy_create_tunnel_request`). For a
/// proxy that speaks HTTP/2, `h2`, the head is what its stream's fields
/// are made of, which leave out the `Host` and `Proxy-Connection` C adds
/// for HTTP/1 alone.
pub(super) fn connect_head<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
    version: &[u8],
) -> Result<ConnectHead, ErrorKind> {
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
        authority.try_extend_from_slice(target.request_host())?;
        authority.try_push(b':')?;
        authority.try_extend_from_slice(port)
    })();
    made.map_err(oom)?;
    let (peer, secret, http10) = proxy(&c.route);
    // A CONNECT-UDP asks the proxy itself, at the path naming the target
    // (`http_proxy_create_CONNECTUDP`); over HTTP/1, with `GET`.
    let udp = c.route.tunnels_udp();
    let h1 = version == b"HTTP";
    let mut proxy_authority = Vec::new();
    let mut path = Vec::new();
    if udp {
        udp_target(peer, target, &mut proxy_authority, &mut path).map_err(oom)?;
    }
    let uri = if udp { &proxy_authority } else { &authority };
    let method: &[u8] = if udp && h1 { b"GET" } else { b"CONNECT" };
    let request = AuthRequest {
        side: Side::Proxy,
        origin: peer,
        method,
        uri,
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
    // Negotiate's token is the context's to make, the connection's to
    // be (`Curl_output_negotiate`).
    let output = if output.negotiate {
        negotiate(cx, &mut c.negotiate, peer, secret)?
    } else {
        output
    };
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
    let kind: &[u8] = if udp { b"UDP " } else { b"" };
    trace::info_with(
        cx,
        &[
            b"Establishing ",
            version,
            b" proxy ",
            kind,
            b"tunnel to ",
            &authority,
        ],
    );
    let mut out = Vec::new();
    let options = cx.easy().options();
    let trusted = match &c.proto {
        ProtoState::Http(request) => request.trusted(),
        _ => CredentialGate::FIRST.trusted(),
    };
    let scheme: &'static [u8] = if c.route.proxy_tls().is_some() {
        b"https"
    } else {
        b"http"
    };
    let connect = ConnectRequest {
        authority: uri,
        udp: udp.then_some(UdpTarget {
            scheme,
            path: &path,
            h2: !h1,
        }),
        http10,
        proxy_authorization: output.header.as_ref().map(|(m, v)| (m.name(), &v[..])),
        user_agent: options.http.user_agent.as_deref(),
        headers: options.proxy.own_headers(&options.http),
        trusted,
    };
    connect.render(&mut out).map_err(oom)?;
    Ok(ConnectHead {
        head: out,
        authorized: output.header.is_some(),
        udp: udp.then_some(UdpAsk {
            scheme,
            authority: proxy_authority,
            path,
        }),
    })
}

/// A tunnel's request, as [`connect_head`] makes it.
pub(super) struct ConnectHead {
    /// The head, as HTTP/1 writes it.
    pub(super) head: Vec<u8>,
    /// It carries `Proxy-Authorization`.
    pub(super) authorized: bool,
    /// A CONNECT-UDP's target, which a proxy that speaks HTTP/2 is given
    /// as the stream's fields.
    pub(super) udp: Option<UdpAsk>,
}

/// Where a CONNECT-UDP asks: the proxy's scheme and authority, and the
/// path naming the target.
pub(super) struct UdpAsk {
    pub(super) scheme: &'static [u8],
    pub(super) authority: Vec<u8>,
    pub(super) path: Vec<u8>,
}

/// A CONNECT-UDP's authority, the proxy's, and its path naming the
/// target, an IPv6 address's colons escaped (RFC 9298's template:
/// `/.well-known/masque/udp/{host}/{port}/`).
fn udp_target(
    proxy: &Peer,
    target: &Peer,
    authority: &mut Vec<u8>,
    path: &mut Vec<u8>,
) -> Result<(), OutOfMemory> {
    let mut digits = [0; 20];
    authority.try_extend_from_slice(proxy.request_host())?;
    authority.try_push(b':')?;
    authority.try_extend_from_slice(decimal(u64::from(proxy.port()), &mut digits))?;
    path.try_extend_from_slice(b"/.well-known/masque/udp/")?;
    for &b in target.name() {
        match b {
            b':' => path.try_extend_from_slice(b"%3A")?,
            b => path.try_push(b)?,
        }
    }
    path.try_push(b'/')?;
    path.try_extend_from_slice(decimal(u64::from(target.port()), &mut digits))?;
    path.try_push(b'/')
}

/// Move the handshake on as far as its socket lets it.
pub(super) fn step<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    match run(&mut c, cx) {
        Ok(Ran::Idle) => {
            tunnel(&mut c.handshake).authorized = false;
            (TransferState::Connecting(c), Wake::Idle)
        }
        Ok(Ran::Again) => (TransferState::Connecting(c), Wake::Again),
        Ok(Ran::Through) => {
            c.handshake = None;
            (TransferState::Connecting(c), Wake::Again)
        }
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}

enum Ran {
    /// Nothing more until the socket is ready.
    Idle,
    /// The setup goes on at once: another `CONNECT`, or a new connection.
    Again,
    /// The tunnel is through: the next handshake follows.
    Through,
}

fn run<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) -> Result<Ran, ErrorKind> {
    // Through an HTTPS proxy's TLS, the socket's sends and receives are
    // the TLS session's records, traced as C's socket filter traces them.
    let traced = c.route.proxy_tls().map(|_| c.route.socket_component());
    loop {
        let t = tunnel(&mut c.handshake);
        if t.sent < t.request.len() {
            let sent = c
                .lease
                .dialed()
                .stream()
                .send(cx, &t.request[t.sent..], traced);
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
        // (`recv_CONNECT_resp`, `H1_CONNECT`). Through an HTTPS proxy's
        // TLS, each of those reads is one of the TLS filter's, which says
        // so: they are made a byte at a time too, and what follows the
        // answer stays in the TLS session.
        let size = if c.route.proxy_tls().is_some() {
            1
        } else {
            READ_SIZE
        };
        let dialed = c.lease.dialed().stream();
        if dialed.received().is_empty() {
            match dialed.recv(cx, size, traced) {
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
            challenged(c, cx);
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

/// The `Proxy-Authenticate` line just read, Negotiate in use with the
/// proxy: each Negotiate challenge it offers is taken into the context
/// with the proxy (`auth_spnego`), and the request made again if one was.
fn challenged<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) {
    let Some(gss) = cx.easy().libraries().gss else {
        return;
    };
    if !cx.easy().auth.proxy_picks_negotiate() {
        return;
    }
    let (peer, credentials, _) = proxy(&c.route);
    let request = negotiate::Request {
        gss,
        side: Side::Proxy,
        credentials,
        peer,
        delegation: cx.easy().options().login.delegation,
        // The origin's TLS has no peer yet while the tunnel is set up.
        tls: None,
    };
    let Some(Handshake::Connect(t)) = c.handshake.as_deref_mut() else {
        unreachable!("a tunnel is set up");
    };
    let value = fields::header_value(t.answer.line()).unwrap_or(&[]);
    let mut answered = None;
    for challenge in auth::negotiate_challenges(value) {
        let taken = negotiate::challenged(cx, &mut c.negotiate, &request, challenge);
        let (any, _) = answered.unwrap_or((false, true));
        answered = Some((any || taken, taken));
    }
    if let Some((any, last)) = answered {
        t.challenges.negotiate_line_answered(any, last);
    }
}

/// The token Negotiate with the proxy sends with the `CONNECT`, made by
/// the context in `kept` (`Curl_output_negotiate`); without a GSS-API
/// library, none, as in a build without one.
fn negotiate<H: Host>(
    cx: &mut StepCx<'_, H>,
    kept: &mut Option<Box<negotiate::Negotiate>>,
    peer: &Peer,
    credentials: Option<Secret<'_>>,
) -> Result<Output, ErrorKind> {
    let Some(gss) = cx.easy().libraries().gss else {
        cx.easy_mut().auth.side(Side::Proxy).finish();
        return Ok(Output {
            header: None,
            used: crate::options::AuthMethods::NONE,
            probe: false,
            negotiate: false,
        });
    };
    let request = negotiate::Request {
        gss,
        side: Side::Proxy,
        credentials,
        peer,
        delegation: cx.easy().options().login.delegation,
        // The origin's TLS has no peer yet while the tunnel is set up.
        tls: None,
    };
    let (header, done) = negotiate::output(cx, kept, &request)?;
    Ok(cx
        .easy_mut()
        .auth
        .side(Side::Proxy)
        .negotiated(header, done, true))
}

/// What the proxy is asked, for its challenges.
pub(super) fn proxy_asked<H: Host>(c: &Connecting, cx: &StepCx<'_, H>) -> PeerAsked {
    let (peer, secret, _) = proxy(&c.route);
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
    // A CONNECT-UDP is answered by switching protocols (RFC 9298).
    let udp = c.route.tunnels_udp();
    let what = method_name(&c.route);
    if code / 100 == 2 || (udp && code == 101) {
        trace::info(cx, format_args!("{what} phase completed for HTTP proxy"));
        cx.easy_mut().auth.side(Side::Proxy).finish();
        trace::info(
            cx,
            format_args!("{what} tunnel established, response {code}"),
        );
        // The request follows the `CONNECT`: what reads it starts over
        // (`cf_h1_proxy_connect`'s `Curl_client_reset`).
        crate::upload::trace_reset(cx, false);
        c.lease
            .proxied(Made::TUNNEL, || cx.easy().options().proxy.haproxy);
        return Ok(Ran::Through);
    }
    // What the challenges lead to (`Curl_http_auth_act`).
    let asked = {
        let (peer, secret, _) = proxy(&c.route);
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
    if !act.again() {
        return Err(trace::fail(
            cx,
            ErrorKind::CouldntConnect,
            format_args!("{what} tunnel failed, response {code}"),
        ));
    }
    if closes {
        trace::info(cx, format_args!("Connect me again please"));
        c.handshake = None;
        let redialed = c.lease.redial(&mut DriveCx {
            step: cx,
            kept: None,
            deadlines: None,
        });
        if !redialed {
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

#[cfg(test)]
mod tests {
    use super::udp_target;
    use crate::conn::Peer;

    fn target(proxy: &[u8], origin: &[u8]) -> (String, String) {
        let http = crate::conn::Scheme {
            name: "http",
            reuse: true,
        };
        let peer = |host: &[u8], port| Peer::new(http, host.to_vec(), port, None);
        let (mut authority, mut path) = (Vec::new(), Vec::new());
        udp_target(
            &peer(proxy, 3128),
            &peer(origin, 443),
            &mut authority,
            &mut path,
        )
        .unwrap();
        (
            String::from_utf8(authority).unwrap(),
            String::from_utf8(path).unwrap(),
        )
    }

    /// A CONNECT-UDP asks the proxy, by its authority, at the path naming
    /// the target, an IPv6 address unbracketed and its colons escaped
    /// (RFC 9298's template; `http_proxy_create_CONNECTUDP`).
    #[test]
    fn a_connect_udp_names_its_target_in_its_path() {
        assert_eq!(
            target(b"proxy.example", b"origin.example"),
            (
                "proxy.example:3128".to_owned(),
                "/.well-known/masque/udp/origin.example/443/".to_owned()
            )
        );
        assert_eq!(
            target(b"[::1]", b"[2001:db8::1]"),
            (
                "[::1]:3128".to_owned(),
                "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/".to_owned()
            )
        );
    }
}
