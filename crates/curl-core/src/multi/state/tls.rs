//! A connection's TLS handshakes (`cf_setup_connect`'s SSL stages): an
//! HTTPS proxy's, before its tunnel or as the last stage of a connection
//! requests go whole over, and the origin's, the last of a connection's
//! setup. The handle's TLS library makes a session for the peer, whose
//! layer goes on top of the connection's stream and is connected there;
//! the bytes after go through it, the origin's through the proxy's.

use curl_alloc::{OutOfMemory, TryArc, try_box};

use super::{Failure, Handshake, Lent, SetupMut, StepCx, Wake};
use crate::components::Component;
use crate::conn::chain::Chain;
use crate::conn::layer::LayerQuery;
use crate::conn::tls::TlsLayer;
use crate::conn::{Conn, Dial, Handshook, Peer, Stream};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::options::{ProxyType, SslOptions, TlsMaxVersion, TlsMinVersion, TlsOptions};
use crate::report::Timer;
use crate::tls::{
    Alpn, Handshake as Shake, OwnSessions, SessionPeer, TlsIdentity, TlsPeer, TlsShared, TlsTicket,
};
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
    fn made(self) -> Handshook {
        match self {
            TlsSide::Origin => Handshook::Tls,
            TlsSide::Proxy => Handshook::ProxyTls,
        }
    }
}

/// The handshakes before it are made: the session is made and its layer
/// put on the stream (`put_on`). An HTTPS proxy's is offered HTTP/1.1 by
/// ALPN unless ALPN is off, whatever the transfer's version
/// (`cf_ssl_proxy_create`), and is the proxy's peer, its sessions kept
/// for the proxy.
pub(super) fn start<H: Host>(
    s: &mut SetupMut<'_>,
    lent: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
    side: TlsSide,
) -> Result<Wake, Failure> {
    let (identity, peer, via) = match side {
        TlsSide::Origin => (
            lent.route.tls.as_ref().expect("a TLS route"),
            &*lent.route.origin,
            lent.route.via.as_deref(),
        ),
        TlsSide::Proxy => {
            let proxy = lent.route.proxy.as_ref().expect("an HTTPS proxy");
            (
                proxy.tls().expect("an HTTPS proxy's TLS"),
                &*proxy.peer,
                None,
            )
        }
    };
    // HTTP/2 is offered only where a library speaks it, and the request
    // may.
    let neg = lent.request.negotiation();
    let only_10 = neg.is_some_and(|n| n.only_10);
    // Any, for a protocol that is not HTTP (`http_neg.wanted`).
    let versions = neg.map_or(crate::proto::http::Versions::ALL, |n| n.versions());
    let h2 = versions.h2 && cx.easy().libraries().h2.is_some();
    // An HTTPS proxy asked for in HTTP/2 is offered it, by ALPN whatever
    // the transfer says of ALPN (`cf_ssl_proxy_create`).
    let proxy_h2 = side == TlsSide::Proxy
        && cx.easy().libraries().h2.is_some()
        && lent
            .route
            .proxy
            .as_ref()
            .is_some_and(|p| p.kind == ProxyType::Https2);
    // HTTP/1.0 alone is offered as `http/1.0` and `http/1.1`
    // (`alpn_get_spec`).
    // A scheme that is not HTTP's offers none (`PROTOPT_ALPN`).
    let offers = side == TlsSide::Proxy || peer.scheme().offers_alpn();
    let alpn = match (cx.easy().options().tls.options.alpn || proxy_h2, side) {
        (false, _) => Alpn::None,
        (true, TlsSide::Origin) if !offers => Alpn::None,
        (true, TlsSide::Proxy) if proxy_h2 => Alpn::H2Http11,
        (true, TlsSide::Proxy) => Alpn::Http11,
        (true, TlsSide::Origin) if only_10 && versions.h1 => Alpn::Http10,
        (true, TlsSide::Origin) if h2 && !versions.h1 => Alpn::H2,
        (true, TlsSide::Origin) if h2 => Alpn::H2Http11,
        (true, TlsSide::Origin) => Alpn::Http11,
    };
    let to = TlsFor {
        side,
        identity,
        peer,
        via,
        alpn,
    };
    put_on(s.machine.dialed().stream(), &to, None, cx)?;
    match try_box(Handshake::Tls(side)) {
        Ok(h) => {
            *s.handshake = Some(h);
            Ok(Wake::Again)
        }
        Err(OutOfMemory) => Err(Failure::Transfer(ErrorKind::OutOfMemory)),
    }
}

/// Whom a TLS session is made for: its side, the settings it is made
/// with, its peer (through a connect-to's, `via`) and what ALPN offers.
pub(super) struct TlsFor<'a> {
    pub(super) side: TlsSide,
    pub(super) identity: &'a TryArc<TlsIdentity>,
    pub(super) peer: &'a Peer,
    pub(super) via: Option<&'a Peer>,
    pub(super) alpn: Alpn,
}

/// A session for `to` is made and its layer put on `stream`, taking the
/// bytes the stream received and did not use, which follow a proxy's
/// answer: over a connection being set up, or one open, upgraded. It
/// resumes `given` before any session of the cache's.
pub(super) fn put_on<H: Host>(
    stream: &mut Stream,
    to: &TlsFor<'_>,
    given: Option<TlsTicket>,
    cx: &mut StepCx<'_, H>,
) -> Result<(), Failure> {
    // Held apart from the handle, as the multi's state is borrowed too.
    let libraries = cx.easy().shared_libraries();
    let backend = libraries
        .tls
        .as_deref()
        .expect("a route has TLS only with a TLS library");
    let options = cx.easy().options();
    // Early data, where the transfer asks for it and makes requests
    // (`conn_cfg->earlydata`, `bits.connect_only`).
    let early_data = to
        .identity
        .options
        .ssl_options
        .contains(SslOptions::EARLYDATA)
        && !options.connect_only.reserves();
    let peer_of = |early| TlsPeer::of(to.peer, early);
    // What the library keeps across the multi's connections, made with
    // its first session.
    let shared = match &mut *cx.rest.tls {
        Some(shared) => shared,
        none => match TlsShared::new() {
            Ok(made) => none.insert(made),
            Err(OutOfMemory) => {
                return Err(Failure::Transfer(ErrorKind::OutOfMemory));
            }
        },
    };
    let session = match backend.session(to.identity, &peer_of(early_data), to.alpn, shared) {
        Ok(session) => session,
        Err(kind) => return Err(Failure::Attempt(kind)),
    };
    // Who its sessions are kept for: the peer, through a connect-to's
    // peer if any (`cf_ssl_peer_init`), over TCP.
    let kept_for = match SessionPeer::new(to.identity, to.peer, to.via, backend.id(), Dial::Stream)
    {
        Ok(p) => p,
        Err(OutOfMemory) => {
            return Err(Failure::Transfer(ErrorKind::OutOfMemory));
        }
    };
    // FTP's origin keeps a copy of its latest session, for its data
    // connections (`Curl_ossl_add_session`, `CURLPROTO_FTP`).
    let keeps_latest = to.side == TlsSide::Origin && to.peer.scheme().ftp_family();
    let own = OwnSessions::new(keeps_latest, given);
    let filter = to.side.filter();
    stream
        .push_over_received(|early| TlsLayer::boxed(session, early, kept_for, own, filter))
        .map_err(|OutOfMemory| Failure::Transfer(ErrorKind::OutOfMemory))
}

/// What a connection upgraded to TLS in place (STARTTLS, FTP's `AUTH`)
/// is made with and said as, read from its route as each run of its
/// protocol starts: the peer a connect-to entry names in the origin's
/// place, which the TLS is made with; the host the connection is said to
/// be to (`CURL_CONN_HOST_DISPNAME`); and the chain the TLS goes on top
/// of.
#[derive(Debug, Default)]
pub(crate) struct InPlace {
    via: Option<TryArc<Peer>>,
    shown: Option<TryArc<Peer>>,
    below: Option<Chain>,
}

impl InPlace {
    pub(crate) fn of(conn: &Conn) -> InPlace {
        let route = conn.net_route();
        InPlace {
            via: route.and_then(|r| r.via.clone()),
            shown: route.map(|r| r.destination_shared().clone()),
            below: conn.chain(),
        }
    }
}

/// Whether the connect of an upgrade waits for its end, as C's says
/// (`Curl_conn_connect`'s `blocking`). Here neither waits: the handshake
/// moves on as the socket lets it, as a connection's own does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Blocks {
    /// STARTTLS's (`imap_perform_upgrade_tls` and the others).
    No,
    /// FTP's after `AUTH` (`ftp_state_auth_resp`).
    Yes,
}

/// Upgrade an open connection to TLS in place (STARTTLS,
/// `Curl_ssl_cfilter_add` then `Curl_conn_connect`): the session for
/// `peer`, through `in_place`'s connect-to peer if one is named, made
/// with `identity` and offering no ALPN, goes on its stream the first
/// time, taking what was received after the server's go-ahead, its filter
/// said added; each call moves the handshake on as far as the socket lets
/// it, said as C's connect of the whole chain says it. Once made, the
/// chain is connected again: its TLS timed, and the connection said
/// established, then its chain, as C's connect does
/// (`conn_report_stats`, `conn_connect_trace`, `Curl_conn_trc_filters`).
/// A failure is said as C's connect says its filter's.
pub(crate) fn upgrade<H: Host>(
    carrier: &mut crate::conn::mux::Carrier<'_>,
    identity: &TryArc<TlsIdentity>,
    peer: &Peer,
    in_place: &InPlace,
    blocks: Blocks,
    cx: &mut StepCx<'_, H>,
) -> Result<Shake, ErrorKind> {
    let ssl = Component::Ssl;
    // Its filter goes on top of the chain first (`Curl_conn_cf_add`).
    let adds = !carrier.over_tls();
    if adds {
        trace::of(cx, ssl, format_args!("added"));
    }
    let shaken = upgrade_resuming(carrier, identity, peer, in_place.via.as_deref(), None, cx);
    let code = trace::Code(shaken.map(|_| ()));
    let done = u8::from(shaken == Ok(Shake::Done));
    let block = u8::from(blocks == Blocks::Yes);
    trace::of(
        cx,
        ssl,
        format_args!("Curl_conn_connect(block={block}) -> {code}, done={done}"),
    );
    let chain = |connected| in_place.below.map(|below| below.under(ssl, connected));
    match shaken {
        Ok(Shake::Waiting) => {}
        Ok(Shake::Done) => {
            let now = cx.now();
            let marked = cx.report_mut().timings_mut().mark(Timer::AppConnect, now);
            crate::multi::mstate::marked(cx, Timer::AppConnect, marked);
            if let (Some(shown), Some(ends)) = (
                in_place.shown.as_deref(),
                cx.report_mut().primary().cloned(),
            ) {
                super::say_established(cx, shown.shown(), &ends.remote, ends.local);
            }
            if let Some(chain) = chain(true) {
                crate::multi::mstate::trace(cx, format_args!("connected {chain}"));
                crate::multi::mstate::trace(cx, format_args!("reduced to {chain}"));
            }
        }
        Err(_) => {
            trace::of(
                cx,
                ssl,
                format_args!("Curl_conn_connect(), filter returned {code}"),
            );
            if let Some(chain) = chain(false) {
                crate::multi::mstate::trace(cx, format_args!("failed to connect {chain}"));
            }
        }
    }
    shaken
}

/// The same, the session made resuming `given`, its control connection's
/// session, before any of the cache's: FTP's data connection's.
pub(crate) fn upgrade_resuming<H: Host>(
    carrier: &mut crate::conn::mux::Carrier<'_>,
    identity: &TryArc<TlsIdentity>,
    peer: &Peer,
    via: Option<&Peer>,
    given: Option<TlsTicket>,
    cx: &mut StepCx<'_, H>,
) -> Result<Shake, ErrorKind> {
    let traced = Some(carrier.socket_component());
    if !carrier.over_tls() {
        let to = TlsFor {
            side: TlsSide::Origin,
            identity,
            peer,
            via,
            alpn: Alpn::None,
        };
        put_on(carrier.stream_mut(), &to, given, cx).map_err(|f| match f {
            Failure::Attempt(kind) | Failure::Transfer(kind) => kind,
        })?;
    }
    shake(
        carrier.stream_mut(),
        TlsSide::Origin,
        &identity.options,
        traced,
        cx,
    )
}

/// Move the handshake on, as far as the socket lets it (`shake`).
pub(super) fn step<H: Host>(
    s: &mut SetupMut<'_>,
    lent: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
    side: TlsSide,
) -> Result<Wake, Failure> {
    let traced = Some(s.machine.dialing().socket_component());
    let identity = match side {
        TlsSide::Origin => lent.route.tls.as_ref(),
        TlsSide::Proxy => lent.route.proxy_tls(),
    };
    let options = &identity.expect("a TLS stage's settings").options;
    match shake(s.machine.dialed().stream(), side, options, traced, cx) {
        Ok(Shake::Done) => {
            s.machine.dialed().mark_made(side.made());
            *s.handshake = None;
            Ok(Wake::Again)
        }
        Ok(Shake::Waiting) => Ok(Wake::Idle),
        Err(kind) => Err(Failure::Attempt(kind)),
    }
}

/// Move the TLS handshake of `side` on over `stream`, as far as the
/// socket lets it, each call traced as the TLS filter traces its connect
/// (`ssl_cf_connect`); the versions `options` allow are checked first
/// (`ssl_prefs_check`). The session's objects are lent to the transfer
/// as they are made. The socket's bytes are traced as `traced`'s.
pub(super) fn shake<H: Host>(
    stream: &mut Stream,
    side: TlsSide,
    options: &TlsOptions,
    traced: Option<Component>,
    cx: &mut StepCx<'_, H>,
) -> Result<Shake, ErrorKind> {
    let ssl = side.filter();
    trace::of(cx, ssl, format_args!("cf_connect()"));
    let shaken = match prefs_check(cx, options) {
        Ok(()) => stream.connect(cx, traced),
        Err(kind) => Err(kind),
    };
    let (code, done) = match shaken {
        Ok(Shake::Done) => (trace::Code(Ok(())), 1),
        Ok(Shake::Waiting) => (trace::Code(Ok(())), 0),
        Err(kind) => (trace::Code(Err(kind)), 0),
    };
    trace::of(cx, ssl, format_args!("cf_connect() -> {code}, done={done}"));
    // The session may have made its objects.
    cx.lend(super::native_of(stream.query(LayerQuery::TlsNative)));
    shaken
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

/// Assert that `said`, a transfer's trace with its `multi` and `ssl`
/// components on, says a connection upgraded to TLS in place as C's
/// connect of the whole chain says it, before `next`, the first line
/// after the upgrade: the filter added before its first handshake call;
/// each call's end, `block` given as C's connect is, a first that
/// waited if any; once done, the
/// handshake timed, the connection said established again, then its
/// chain connected and reduced, all of it TLS over TCP.
#[cfg(test)]
pub(crate) fn assert_upgraded_in_place(said: &str, block: u8, next: &str) {
    let at = |line: &str| {
        said.find(line)
            .unwrap_or_else(|| panic!("{line:?} in {said}"))
    };
    let added = at("[SSL] added\n");
    let shaking = at("[SSL] cf_connect()\n");
    let waiting = said
        .find(&format!(
            "[SSL] Curl_conn_connect(block={block}) -> 0, done=0\n"
        ))
        .unwrap_or(shaking + 1);
    let shaken = at(&format!(
        "[SSL] Curl_conn_connect(block={block}) -> 0, done=1\n"
    ));
    let timed = at("[PGRS-APPCONNECT]");
    let connected = at("connected [0][SSL][TCP]\n");
    let reduced = at("reduced to [0][SSL][TCP]\n");
    let next = at(next);
    let established: Vec<usize> = said
        .match_indices("Established connection to 127.0.0.1")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(established.len(), 2, "{said}");
    assert!(established[0] < added && added < shaking, "{said}");
    assert!(shaking < waiting && waiting < shaken, "{said}");
    assert!(shaken < timed && timed < established[1], "{said}");
    assert!(established[1] < connected && connected < reduced, "{said}");
    assert!(reduced < next, "{said}");
}
