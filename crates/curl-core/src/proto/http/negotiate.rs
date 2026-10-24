//! HTTP Negotiate (SPNEGO) with the origin and with an HTTP proxy
//! (`lib/http_negotiate.c` and `lib/vauth/spnego_gssapi.c`): a security
//! context with each the connection keeps, stepped by the library a
//! handle names, its tokens in base64 in `Authorization: Negotiate` and
//! `Proxy-Authorization: Negotiate`. Once a context with the origin
//! starts, the connection is bound to the credentials and the origin it
//! started with, and serves no transfer with others; once one with the
//! proxy starts, it serves only a transfer negotiating with the proxy.

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use crate::conn::{Conn, Peer};
use crate::error::ErrorKind;
use crate::gss::{
    Flags, Gss, GssCall, GssContext, GssFailure, GssFailureKind, GssNote, GssStatus, Mech,
    Progress, StepSink, Style, Target,
};
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::Delegation;
use crate::proto::http1::auth::{Answered, Secret, Side, base64};
use crate::trace;

/// What a connection keeps of Negotiate (C's `conn->http_negotiate_state`,
/// `conn->proxy_negotiate_state`, a `negotiatedata` for each, and
/// `conn->creds`, `conn->creds_origin`): made the first time a request
/// negotiates with either peer, dropped with the connection, its contexts
/// deleted then (`nego_conn_dtor`). While a tunnel is set up, before the
/// connection is, the transfer setting it up holds it, and hands it to the
/// connection once that is up.
#[derive(Debug, Default)]
pub(crate) struct Negotiate {
    host: Peering,
    proxy: Peering,
    /// The credentials and the origin the context with the origin started
    /// with: the connection's from then on.
    bound: Option<Bound>,
}

/// Where Negotiate with one peer is (`CURL_NEGO_AUTH_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum State {
    /// Not started.
    #[default]
    None,
    /// The peer's challenge was taken into the context: the request goes
    /// again, on this connection.
    Recv,
    /// A token went, its context not yet complete nor wanting more.
    Sent,
    /// A token went: nothing more is sent unless the peer asks.
    Done,
    /// A response other than the peer's refusal (a 401, or a 407)
    /// followed: the connection is authenticated.
    Succ,
}

/// The context with one peer, and what is known of how it goes.
#[derive(Debug, Default)]
struct Peering {
    state: State,
    /// The context, once a step made a token.
    context: Option<Box<dyn GssContext>>,
    /// How far the last step took it (`status`).
    progress: Option<Progress>,
    /// The last token made, to send (`output_token`).
    token: Vec<u8>,
    /// Each request authenticates again (`noauthpersist`): the server said
    /// so in `Persistent-Auth: false`, or, unless it said, the context
    /// took only one round.
    no_persist: bool,
    /// The server said whether it persists (`havenoauthpersist`).
    persist_said: bool,
    /// The last challenge taken had a token (`havenegdata`).
    challenged: bool,
    /// A request went with a token after a challenge that had one
    /// (`havemultiplerequests`).
    rounds: bool,
}

/// What a context with the origin was bound to.
#[derive(Debug)]
struct Bound {
    origin: Peer,
    /// None for a request with no credentials.
    credentials: Option<Answered>,
}

impl Peering {
    /// The context deleted, and everything said of it forgotten
    /// (`Curl_auth_cleanup_spnego`).
    fn clean(&mut self) {
        self.context = None;
        self.progress = None;
        self.token = Vec::new();
        self.no_persist = false;
        self.persist_said = false;
        self.challenged = false;
        self.rounds = false;
    }
}

impl Negotiate {
    /// The context with one peer.
    fn with(&mut self, side: Side) -> &mut Peering {
        match side {
            Side::Host => &mut self.host,
            Side::Proxy => &mut self.proxy,
        }
    }

    /// Started over with one peer: not negotiating, and with the origin
    /// bound to nothing (`http_auth_nego_reset`).
    fn reset(&mut self, side: Side) {
        if side == Side::Host {
            self.bound = None;
        }
        let peering = self.with(side);
        peering.state = State::None;
        peering.clean();
    }

    /// Where Negotiate with one peer is.
    pub(crate) fn state(&self, side: Side) -> State {
        match side {
            Side::Host => self.host.state,
            Side::Proxy => self.proxy.state,
        }
    }

    /// Whether a transfer looking for a connection may have this one, as
    /// far as Negotiate goes (`url_match_auth`'s credentials,
    /// `url_match_auth_nego`).
    pub(crate) fn serves(&self, wants: &Wants<'_>) -> bool {
        let bound = self.bound.as_ref();
        let credentials = bound.and_then(|b| b.credentials.as_ref());
        let same = same_credentials(credentials, wants.credentials);
        // Bound to credentials, it serves only a transfer with the same,
        // negotiating or not (`url_match_auth`).
        if credentials.is_some() && !same {
            return false;
        }
        // Negotiating with the proxy, it serves only a transfer
        // negotiating with it, as the same credentials: the route's are
        // the proxy's, compared already.
        if self.proxy.state != State::None && !wants.proxy {
            return false;
        }
        let same_origin = bound.is_some_and(|b| wants.origin == Some(&b.origin));
        if self.host.state != State::None {
            // Negotiating, it serves only a transfer negotiating as it
            // does.
            wants.negotiate && same && same_origin
        } else {
            // A transfer negotiating is not served by one bound to others.
            !(wants.negotiate && bound.is_some() && !(same && same_origin))
        }
    }
}

/// `Curl_creds_same`, for those a connection is bound to.
fn same_credentials(bound: Option<&Answered>, credentials: Option<Secret<'_>>) -> bool {
    match (bound, credentials) {
        (None, None) => true,
        (Some(a), Some(s)) => s.answers_as(a),
        _ => false,
    }
}

/// What a transfer looking for a connection brings to the matching of
/// what Negotiate bound it to: whether it negotiates with the origin,
/// with which credentials, and the origin (`want_nego_http`,
/// `state.creds`, `state.origin`), and whether it negotiates with the
/// HTTP proxy, with credentials for it (`want_proxy_nego_http`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Wants<'w> {
    pub(crate) negotiate: bool,
    pub(crate) credentials: Option<Secret<'w>>,
    /// None for a transfer with no origin to authenticate with.
    pub(crate) origin: Option<&'w Peer>,
    pub(crate) proxy: bool,
}

impl Wants<'static> {
    /// A transfer with no origin to authenticate with.
    pub(crate) const NONE: Wants<'static> = Wants {
        negotiate: false,
        credentials: None,
        origin: None,
        proxy: false,
    };
}

/// What a request negotiates with: the library, the peer, the
/// credentials it has for that peer, and how far the credentials are
/// delegated.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Request<'r> {
    pub(crate) gss: &'static dyn Gss,
    /// The origin, or the HTTP proxy.
    pub(crate) side: Side,
    pub(crate) credentials: Option<Secret<'r>>,
    /// The peer the context is with: the origin, or the proxy.
    pub(crate) peer: &'r Peer,
    pub(crate) delegation: Delegation,
}

/// The connection's Negotiate, kept in `kept` and made the first time it
/// is needed (`Curl_auth_nego_get`).
fn of(kept: &mut Option<Box<Negotiate>>) -> Result<&mut Negotiate, ErrorKind> {
    if kept.is_none() {
        *kept = Some(try_box(Negotiate::default()).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?);
    }
    Ok(kept.as_deref_mut().expect("made above"))
}

/// What a request sends to negotiate with the peer `request` names
/// (`Curl_output_negotiate`), over the connection whose Negotiate is
/// `kept`: the value of its `Authorization: Negotiate`, or of its
/// `Proxy-Authorization: Negotiate`, if one goes, and whether
/// authenticating is done.
pub(crate) fn output<H: Host>(
    cx: &mut StepCx<'_, H>,
    kept: &mut Option<Box<Negotiate>>,
    request: &Request<'_>,
) -> Result<(Option<Vec<u8>>, bool), ErrorKind> {
    let nego = of(kept)?;
    let side = nego.with(request.side);
    match side.state {
        State::Recv if side.challenged => side.rounds = true,
        State::Succ if !side.persist_said => side.no_persist = !side.rounds,
        _ => {}
    }
    let mut header = None;
    if side.no_persist || !matches!(side.state, State::Done | State::Succ) {
        if side.no_persist && side.state == State::Succ {
            trace::info(
                cx,
                format_args!(
                    "Curl_output_negotiate, no persistent authentication: cleanup existing context"
                ),
            );
            nego.reset(request.side);
        }
        if nego.with(request.side).context.is_none() {
            match input(cx, nego, request, b"") {
                // Without a context, the request goes unauthenticated, as
                // before curl 7.64.1.
                Err(ErrorKind::AuthError) => return Ok((None, true)),
                Err(e) => return Err(e),
                Ok(()) => {}
            }
        }
        let side = nego.with(request.side);
        // `Curl_auth_create_spnego_message`.
        if side.token.is_empty() {
            return Err(ErrorKind::RemoteAccessDenied);
        }
        let mut value = Vec::new();
        let made = value
            .try_reserve_exact(side.token.len().div_ceil(3) * 4)
            .map_err(|_| OutOfMemory)
            .and_then(|()| base64(side.token.iter().copied(), side.token.len(), &mut value));
        if made.is_err() {
            side.token = Vec::new();
            return Err(ErrorKind::OutOfMemory);
        }
        header = Some(value);
        side.state = match side.progress {
            Some(Progress::Complete | Progress::Continue) => State::Done,
            _ => State::Sent,
        };
    }
    let side = nego.with(request.side);
    let done = matches!(side.state, State::Done | State::Succ);
    side.challenged = false;
    Ok((header, done))
}

/// A 401's or a 407's `Negotiate` challenge, `challenge` what follows its
/// name, taken into the context with the peer `request` names
/// (`auth_spnego`): whether it was, the connection then waiting for the
/// request to go again.
pub(crate) fn challenged<H: Host>(
    cx: &mut StepCx<'_, H>,
    kept: &mut Option<Box<Negotiate>>,
    request: &Request<'_>,
    challenge: &[u8],
) -> bool {
    let Ok(nego) = of(kept) else {
        return false;
    };
    let taken = input(cx, nego, request, challenge).is_ok();
    if taken {
        nego.with(request.side).state = State::Recv;
    }
    taken
}

/// `Persistent-Auth: <value>` from the origin, Negotiate in use: whether
/// each request authenticates again, as the server says.
pub(crate) fn persistence<H: Host>(
    cx: &mut StepCx<'_, H>,
    conn: &mut Conn,
    value: &[u8],
) -> Result<(), ErrorKind> {
    let side = &mut of(conn.negotiate_mut())?.host;
    side.no_persist = value.len() >= 5 && value[..5].eq_ignore_ascii_case(b"false");
    side.persist_said = true;
    let said: &[u8] = if side.no_persist { b"1" } else { b"0" };
    trace::info_with(
        cx,
        &[
            b"Negotiate: noauthpersist -> ",
            said,
            b", header part: ",
            value,
        ],
    );
    Ok(())
}

/// A final response came after a token went: other than a 401, the
/// connection is authenticated with the origin, and other than a 407,
/// with the proxy (`http_check_auth_closure`).
pub(crate) fn responded(conn: &mut Conn, code: u16) {
    if let Some(nego) = conn.negotiate_mut().as_deref_mut() {
        for (peering, refused) in [(&mut nego.host, 401), (&mut nego.proxy, 407)] {
            if peering.state == State::Done && code != refused {
                peering.state = State::Succ;
            }
        }
    }
}

/// `Curl_input_negotiate`: a challenge, or none (`b""`) for the first
/// token, taken into the context with the peer `request` names, which is
/// made if there is none; a connection negotiating with the origin bound
/// to the request's credentials and origin. Any failure starts Negotiate
/// with that peer over.
fn input<H: Host>(
    cx: &mut StepCx<'_, H>,
    nego: &mut Negotiate,
    request: &Request<'_>,
    challenge: &[u8],
) -> Result<(), ErrorKind> {
    let side = request.side;
    let peering = nego.with(side);
    let state = peering.state;
    peering.challenged = !challenge.is_empty();
    if challenge.is_empty() {
        if state == State::Succ {
            trace::info(cx, format_args!("Negotiate auth restarted"));
            nego.reset(side);
        } else if state != State::None {
            // The server refused the token and offers nothing more.
            nego.reset(side);
            return Err(ErrorKind::LoginDenied);
        }
    }
    if let Err(e) = step(cx, nego.with(side), request, challenge) {
        nego.reset(side);
        return Err(e);
    }
    // Only the origin's binds the connection.
    if side == Side::Proxy {
        return Ok(());
    }
    match &nego.bound {
        Some(bound) => {
            let same = same_credentials(bound.credentials.as_ref(), request.credentials);
            assert!(
                bound.origin == *request.peer && same,
                "a connection negotiating for one origin and credentials serves only them"
            );
        }
        None => {
            let oom = |OutOfMemory| ErrorKind::OutOfMemory;
            nego.bound = Some(Bound {
                origin: request.peer.try_clone().map_err(oom)?,
                credentials: request
                    .credentials
                    .map(|c| c.answered())
                    .transpose()
                    .map_err(oom)?,
            });
        }
    }
    Ok(())
}

/// The context made if there is none, and stepped with the challenge
/// decoded (`Curl_auth_decode_spnego_message`).
fn step<H: Host>(
    cx: &mut StepCx<'_, H>,
    side: &mut Peering,
    request: &Request<'_>,
    challenge: &[u8],
) -> Result<(), ErrorKind> {
    if side.context.is_some() && side.progress == Some(Progress::Complete) {
        // Done on our side, and refused all the same: nothing better to
        // offer.
        side.clean();
        return Err(ErrorKind::LoginDenied);
    }
    let gss = request.gss;
    if side.context.is_none() {
        let service = request
            .credentials
            .and_then(|c| c.service())
            .unwrap_or(b"HTTP");
        let target = Target::Service {
            service,
            host: request.peer.name(),
        };
        let flags = Flags {
            mutual: true,
            delegate_by_policy: request.delegation.by_policy,
            delegate: request.delegation.always,
        };
        match gss.context(target, Mech::Spnego, flags) {
            Ok(context) => side.context = Some(context),
            Err(failure) => return Err(failed(cx, gss, failure)),
        }
    }
    let input = if challenge.is_empty() {
        None
    } else {
        let decoded = if challenge[0] == b'=' {
            Vec::new()
        } else {
            crate::base64::decode(challenge)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?
                .ok_or(ErrorKind::BadContentEncoding)?
        };
        if decoded.is_empty() {
            trace::info(
                cx,
                format_args!("SPNEGO handshake failure (empty challenge message)"),
            );
            return Err(ErrorKind::BadContentEncoding);
        }
        Some(decoded)
    };
    let context = side.context.as_mut().expect("made above");
    let mut sink = Sink {
        cx,
        gss,
        token: Vec::new(),
    };
    match context.step(input.as_deref(), None, &mut sink) {
        Ok(step) => {
            side.progress = Some(step.progress);
            side.token = sink.token;
            Ok(())
        }
        Err(failure) => {
            if failure.kind == GssFailureKind::NtlmChosen {
                side.clean();
            }
            Err(failed(sink.cx, gss, failure))
        }
    }
}

/// What a step makes, its notes traced as they come.
struct Sink<'s, 'c, H: Host> {
    cx: &'s mut StepCx<'c, H>,
    gss: &'static dyn Gss,
    token: Vec<u8>,
}

impl<H: Host> StepSink for Sink<'_, '_, H> {
    fn token(&mut self, token: &[u8]) -> Result<(), OutOfMemory> {
        self.token.try_extend_from_slice(token)
    }

    fn note(&mut self, note: GssNote) {
        match note {
            GssNote::SetNegMechs(status) => {
                logged(self.cx, self.gss, "gss_set_neg_mechs() failed: ", &status);
            }
        }
    }
}

/// The error a library failure is, said as C says it.
fn failed<H: Host>(
    cx: &mut StepCx<'_, H>,
    gss: &'static dyn Gss,
    failure: GssFailure,
) -> ErrorKind {
    match failure.kind {
        GssFailureKind::OutOfMemory => ErrorKind::OutOfMemory,
        // No token made: nothing said of it.
        GssFailureKind::EmptyToken => ErrorKind::AuthError,
        GssFailureKind::NtlmChosen => {
            trace::info(
                cx,
                format_args!("SPNEGO chose NTLM, but NTLM is not allowed"),
            );
            ErrorKind::AuthError
        }
        GssFailureKind::Status(status) => {
            let prefix = match failure.call {
                GssCall::ImportName => "gss_import_name() failed: ",
                GssCall::AcquireCred => "gss_acquire_cred() failed: ",
                GssCall::InitSecContext => "gss_init_sec_context() failed: ",
                GssCall::InquireContext => "gss_inquire_context() failed: ",
                GssCall::DisplayName => "gss_display_name() failed: ",
                GssCall::Wrap => "gss_wrap() failed: ",
                GssCall::Unwrap => "gss_unwrap() failed: ",
            };
            logged(cx, gss, prefix, &status);
            ErrorKind::AuthError
        }
    }
}

/// `prefix` and what the library says of `status` (`Curl_gss_log_error`).
fn logged<H: Host>(
    cx: &mut StepCx<'_, H>,
    gss: &'static dyn Gss,
    prefix: &str,
    status: &GssStatus,
) {
    if !cx.easy().options().output.verbose {
        return;
    }
    // At most C's 1024 bytes, on the stack.
    let mut text = crate::text::Text::<1024>::new();
    let fits = gss.describe(status, Style::Log, &mut |part| text.push_clipped(part));
    assert!(fits.is_ok(), "the log's layout is never too long");
    trace::info_with(cx, &[prefix.as_bytes(), text.bytes()]);
}
