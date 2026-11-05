//! SASL's GSSAPI mechanism (RFC 4752), Kerberos 5 by SSPI's `Kerberos`
//! package, as C's Windows build makes its messages
//! (`lib/vauth/krb5_sspi.c`): the user's tokens for `service/host`, then
//! the answer to the server's security layer, which offers none and
//! asks no receive buffer. C never asks for mutual authentication here
//! (`sasl->mutual_auth` stays false), so the user's token is answered by
//! the security layer at once.

use curl_alloc::TryVec as _;

use super::{Ctx, SaslError, Say, join};
use crate::auth::creds::Secret;
use crate::sspi::{
    Identity, Initialize, Output, Package, Req, SecStatus, Sizes, Sspi, SspiContext, SspiFailure,
};

/// What is kept of Kerberos for the connection (`struct kerberos5data`):
/// the target's name, the room a token takes, and the credentials with
/// the context made with them.
#[derive(Debug)]
pub(super) struct Krb5 {
    spn: Vec<u8>,
    room: usize,
    context: Box<dyn SspiContext>,
}

/// SSPI has Kerberos (`Curl_auth_is_gssapi_supported`).
pub(super) fn supported(sspi: &dyn Sspi) -> bool {
    sspi.max_token(Package::Kerberos).is_ok()
}

/// The user names a domain, or names none and is the process's
/// (`Curl_auth_user_contains_domain`): its first `\`, `/` or `@` is
/// neither its first byte nor its last.
pub(super) fn user_contains_domain(user: &[u8]) -> bool {
    if user.is_empty() {
        return true;
    }
    user.iter()
        .position(|b| matches!(b, b'\\' | b'/' | b'@'))
        .is_some_and(|at| at > 0 && at < user.len() - 1)
}

/// The user's token (`Curl_auth_create_gssapi_user_message`, with no
/// challenge): a new context's first, for `service/host`, made with the
/// credentials kept in `krb5`, or acquired there the first time; none
/// where SSPI makes no bytes.
pub(super) fn user_message(
    krb5: &mut Option<Krb5>,
    cx: &Ctx<'_>,
    sspi: &dyn Sspi,
    service: &str,
) -> Result<Option<Vec<u8>>, SaslError> {
    let krb5 = match krb5 {
        Some(k) => k,
        None => {
            let spn = join(&[cx.service(service), b"/", cx.host])?;
            let room = sspi
                .max_token(Package::Kerberos)
                .map_err(|_| SaslError::NoAuthInfo)?;
            let identity = if cx.user().is_empty() {
                Identity::Current
            } else {
                Identity::of(cx.user(), cx.password())
            };
            let context = match sspi.credentials(Package::Kerberos, &identity) {
                Ok(context) => context,
                Err(SspiFailure::OutOfMemory) => return Err(SaslError::OutOfMemory),
                Err(SspiFailure::Status(_)) => return Err(SaslError::Denied),
            };
            krb5.insert(Krb5 { spn, room, context })
        }
    };
    let call = Initialize {
        target: &krb5.spn,
        flags: Req::default(),
        native: true,
        fresh: true,
        input: &[],
        output: Output::Room(krb5.room),
    };
    let mut out = Vec::new();
    let status = match krb5.context.initialize(&call, &mut out) {
        Ok(done) => done.status,
        Err(SspiFailure::OutOfMemory) => return Err(SaslError::OutOfMemory),
        Err(SspiFailure::Status(status)) => status,
    };
    if status == SecStatus::INSUFFICIENT_MEMORY {
        return Err(SaslError::OutOfMemory);
    }
    if status != SecStatus::OK && status != SecStatus::CONTINUE_NEEDED {
        return Err(SaslError::AuthError);
    }
    Ok((!out.is_empty()).then_some(out))
}

/// The answer to the server's security layer `chlg`
/// (`Curl_auth_create_gssapi_security_message`): no layer and no
/// receive buffer, then the identity acted for, protected by the
/// context; `None` for a message that cannot be read, said, which
/// cancels the exchange.
pub(super) fn security_message(
    krb5: &mut Krb5,
    cx: &mut Ctx<'_>,
    chlg: &[u8],
) -> Result<Option<Vec<u8>>, SaslError> {
    let cancel = |cx: &mut Ctx<'_>, why: &str| {
        (cx.said)(Say::Info, format_args!("GSSAPI handshake failure ({why})"));
        Ok(None)
    };
    if chlg.is_empty() {
        return cancel(cx, "empty security message");
    }
    let sizes: Sizes = match krb5.context.sizes() {
        Ok(sizes) => sizes,
        Err(SecStatus::INSUFFICIENT_MEMORY) => return Err(SaslError::OutOfMemory),
        Err(_) => return Err(SaslError::AuthError),
    };
    let mut layer = Vec::new();
    match krb5.context.unwrap(chlg, &mut layer) {
        Ok(()) => {}
        Err(SspiFailure::OutOfMemory) => return Err(SaslError::OutOfMemory),
        Err(SspiFailure::Status(_)) => return cancel(cx, "decryption failed"),
    }
    // The layers offered and the largest message, 4 bytes (RFC 4752 3.1).
    let [offered, _, _, _] = layer[..] else {
        return cancel(cx, "invalid security data");
    };
    // No layer (`KERB_WRAP_NO_ENCRYPT`'s low bit) must be among them.
    if offered & 1 == 0 {
        return cancel(cx, "invalid security layer");
    }
    let authzid = cx.creds.as_ref().map_or(&[][..], Secret::authzid);
    let mut message = Vec::new();
    // No layer, and no receive buffer.
    message.try_extend_from_slice(&[1, 0, 0, 0])?;
    message.try_extend_from_slice(authzid)?;
    let mut out = Vec::new();
    match krb5.context.wrap(sizes, &message, &mut out) {
        Ok(()) => Ok(Some(out)),
        Err(SspiFailure::OutOfMemory | SspiFailure::Status(SecStatus::INSUFFICIENT_MEMORY)) => {
            Err(SaslError::OutOfMemory)
        }
        Err(SspiFailure::Status(_)) => Err(SaslError::AuthError),
    }
}
