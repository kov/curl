//! What the mail protocols, POP3, IMAP and SMTP, share of their login and
//! their connect phase.

use curl_alloc::TryArc;

use super::Connect;
use crate::auth::creds::Credentials;
use crate::auth::sasl::{self, Sasl, SaslError};
use crate::conn::{ConnLease, Peer, RouteCold};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::trace;

/// The credentials the connection logs in with.
pub(super) fn login_of(cold: &Option<TryArc<RouteCold>>) -> Option<&Credentials> {
    cold.as_deref().and_then(|c| c.login.as_ref())
}

/// The SASL context of a step over `cold`'s credentials, for `peer`.
pub(super) fn sasl_step<H: Host, R>(
    cx: &mut StepCx<'_, H>,
    peer: &Peer,
    cold: &Option<TryArc<RouteCold>>,
    state: &mut Sasl,
    f: impl FnOnce(&mut Sasl, &mut sasl::Ctx<'_>) -> R,
) -> R {
    let sasl_ir = cx.easy().options().line.sasl_ir;
    let libraries = cx.easy().shared_libraries();
    let mut random = |out: &mut [u8]| libraries.random(out).map_err(|_| ());
    let mut say = |to: sasl::Say, args: core::fmt::Arguments<'_>| match to {
        sasl::Say::Debug => trace::debug_info(cx, args),
        sasl::Say::Info => trace::info(cx, args),
    };
    let mut sx = sasl::Ctx {
        creds: login_of(cold).map(Credentials::secret),
        sasl_ir,
        host: peer.name(),
        port: peer.port(),
        random: &mut random,
        sspi: libraries
            .security
            .and_then(crate::libraries::Security::sspi),
        said: &mut say,
    };
    f(state, &mut sx)
}

/// What SASL's failure `e` fails the transfer with.
pub(super) fn sasl_failed<H: Host>(cx: &mut StepCx<'_, H>, e: SaslError) -> ErrorKind {
    match e {
        SaslError::Denied => ErrorKind::LoginDenied,
        SaslError::OutOfMemory => ErrorKind::OutOfMemory,
        SaslError::Random => {
            trace::fail(cx, ErrorKind::FailedInit, format_args!("no random bytes"))
        }
        SaslError::NoAuthInfo => trace::fail(
            cx,
            ErrorKind::AuthError,
            format_args!("SSPI: could not get auth info"),
        ),
        SaslError::AuthError => ErrorKind::AuthError,
    }
}

/// The connect phase of `request`: the connection's state set up the first
/// time (`conn_state`), then the back and forth as far as it goes now
/// (`run`).
pub(super) fn connect<'c, H: Host, R>(
    request: &mut R,
    cx: &mut StepCx<'c, H>,
    lease: &mut ConnLease,
    conn_state: fn(&mut R, &mut StepCx<'c, H>, &mut ConnLease) -> Result<(), ErrorKind>,
    run: fn(&mut R, &mut StepCx<'c, H>, &mut ConnLease) -> Result<bool, ErrorKind>,
) -> Result<Connect, ErrorKind> {
    if !lease.conn().keeps_line() {
        conn_state(request, cx, lease)?;
    }
    Ok(if run(request, cx, lease)? {
        Connect::Done
    } else {
        Connect::Waiting
    })
}
