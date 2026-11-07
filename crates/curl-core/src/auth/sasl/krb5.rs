//! SASL's GSSAPI mechanism (RFC 4752), Kerberos 5 by GSS-API as C's
//! builds with a GSS-API library make its messages
//! (`lib/vauth/krb5_gssapi.c`), or by SSPI's `Kerberos` package as C's
//! Windows build makes them (`lib/vauth/krb5_sspi.c`): the user's token
//! for the service on the host, then the answer to the server's security
//! layer, which offers none and asks no receive buffer. C never asks for
//! mutual authentication here (`sasl->mutual_auth` stays false), so the
//! user's token is answered by the security layer at once.

use curl_alloc::{OutOfMemory, TryVec as _};

use super::{Ctx, Lossy, SaslError, Say, join};
use crate::auth::creds::Secret;
use crate::gss::{
    Flags, Gss, GssCall, GssContext, GssFailure, GssFailureKind, GssNote, GssStatus, Mech,
    StepSink, Style, Target,
};
use crate::libraries::Security;
use crate::sspi::{
    Identity, Initialize, Output, Package, Req, SecStatus, Sizes, Sspi, SspiContext, SspiFailure,
};

/// What is kept of Kerberos for the connection (`struct kerberos5data`),
/// by the library that made it.
#[derive(Debug)]
pub(super) enum Krb5 {
    /// The target's name, the room a token takes, and the credentials
    /// with the context made with them.
    Sspi {
        spn: Vec<u8>,
        room: usize,
        context: Box<dyn SspiContext>,
    },
    /// The context, its target's name imported.
    Gss {
        gss: &'static dyn Gss,
        context: Box<dyn GssContext>,
    },
}

/// The library has Kerberos (`Curl_auth_is_gssapi_supported`): a GSS-API
/// library always, SSPI when it knows the package.
pub(super) fn supported(security: Security) -> bool {
    match security {
        Security::Gss(_) => true,
        Security::Sspi(sspi) => sspi.max_token(Package::Kerberos).is_ok(),
    }
}

/// The user names a domain, or names none and is the one the library
/// has credentials for (`Curl_auth_user_contains_domain`): its first
/// `\`, `/` or `@` is neither its first byte nor its last.
pub(super) fn user_contains_domain(user: &[u8]) -> bool {
    if user.is_empty() {
        return true;
    }
    user.iter()
        .position(|b| matches!(b, b'\\' | b'/' | b'@'))
        .is_some_and(|at| at > 0 && at < user.len() - 1)
}

/// The user's token (`Curl_auth_create_gssapi_user_message`, with no
/// challenge): the next step of the context kept in `krb5`, or of one
/// made there with `security` the first time; none where the library
/// makes no bytes.
pub(super) fn user_message(
    krb5: &mut Option<Krb5>,
    cx: &mut Ctx<'_>,
    security: Security,
    service: &str,
) -> Result<Option<Vec<u8>>, SaslError> {
    let krb5 = match krb5 {
        Some(k) => k,
        None => {
            let made = match security {
                Security::Sspi(sspi) => sspi_context(cx, sspi, service)?,
                Security::Gss(gss) => gss_context(cx, gss, service)?,
            };
            krb5.insert(made)
        }
    };
    match krb5 {
        Krb5::Sspi { spn, room, context } => sspi_user_message(spn, *room, context.as_mut()),
        Krb5::Gss { gss, context } => {
            let gss = *gss;
            let mut sink = Sink {
                token: Vec::new(),
                neg_mechs: None,
                no_policy: false,
            };
            // A context already made is stepped again with no token, as C
            // steps the one it keeps.
            let stepped = context.step(None, None, &mut sink);
            // In the order C says them: the credentials' narrowing, then
            // the step's flags.
            if let Some(status) = sink.neg_mechs {
                logged(cx, gss, "gss_set_neg_mechs() failed: ", &status);
            }
            if sink.no_policy {
                (cx.said)(Say::Info, format_args!("{}", GssNote::NO_DELEGATION_POLICY));
            }
            if let Err(failure) = stepped {
                return Err(gss_failed(cx, gss, failure));
            }
            Ok((!sink.token.is_empty()).then_some(sink.token))
        }
    }
}

/// SSPI's credentials for `service/host`, as the user given or the
/// process's, and the room its tokens take.
fn sspi_context(cx: &Ctx<'_>, sspi: &dyn Sspi, service: &str) -> Result<Krb5, SaslError> {
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
    Ok(Krb5::Sspi { spn, room, context })
}

/// A GSS-API context with `service@host` by Kerberos, its name imported,
/// asking the delegation the transfer asks and no mutual authentication.
/// The library's own credentials are used: the user and password given
/// are not.
fn gss_context(cx: &mut Ctx<'_>, gss: &'static dyn Gss, service: &str) -> Result<Krb5, SaslError> {
    let target = Target::Service {
        service: cx.service(service),
        host: cx.host,
    };
    let flags = Flags {
        mutual: false,
        delegate_by_policy: cx.delegation.by_policy,
        delegate: cx.delegation.always,
    };
    match gss.context(target, Mech::Kerberos, flags) {
        Ok(context) => Ok(Krb5::Gss { gss, context }),
        Err(failure) => Err(gss_failed(cx, gss, failure)),
    }
}

/// SSPI's first token of a new context for `spn`.
fn sspi_user_message(
    spn: &[u8],
    room: usize,
    context: &mut dyn SspiContext,
) -> Result<Option<Vec<u8>>, SaslError> {
    let call = Initialize {
        target: spn,
        flags: Req::default(),
        native: true,
        fresh: true,
        input: &[],
        output: Output::Room(room),
    };
    let mut out = Vec::new();
    let status = match context.initialize(&call, &mut out) {
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
    if chlg.is_empty() {
        return cancel(cx, "empty security message");
    }
    match krb5 {
        Krb5::Sspi { context, .. } => {
            let sizes: Sizes = match context.sizes() {
                Ok(sizes) => sizes,
                Err(SecStatus::INSUFFICIENT_MEMORY) => return Err(SaslError::OutOfMemory),
                Err(_) => return Err(SaslError::AuthError),
            };
            let mut layer = Vec::new();
            match context.unwrap(chlg, &mut layer) {
                Ok(()) => {}
                Err(SspiFailure::OutOfMemory) => return Err(SaslError::OutOfMemory),
                Err(SspiFailure::Status(_)) => return cancel(cx, "decryption failed"),
            }
            let Some(message) = layer_answer(cx, &layer)? else {
                return Ok(None);
            };
            let mut out = Vec::new();
            match context.wrap(sizes, &message, &mut out) {
                Ok(()) => Ok(Some(out)),
                Err(
                    SspiFailure::OutOfMemory | SspiFailure::Status(SecStatus::INSUFFICIENT_MEMORY),
                ) => Err(SaslError::OutOfMemory),
                Err(SspiFailure::Status(_)) => Err(SaslError::AuthError),
            }
        }
        Krb5::Gss { gss, context } => {
            let gss = *gss;
            let mut layer = Vec::new();
            match context.unwrap(chlg, &mut |b| layer.try_extend_from_slice(b)) {
                Ok(()) => {}
                Err(GssFailure {
                    kind: GssFailureKind::Status(status),
                    ..
                }) => {
                    // Said as the library says it, then cancelled.
                    logged(cx, gss, "gss_unwrap() failed: ", &status);
                    return Ok(None);
                }
                Err(failure) => return Err(gss_failed(cx, gss, failure)),
            }
            let Some(message) = layer_answer(cx, &layer)? else {
                return Ok(None);
            };
            let mut out = Vec::new();
            match context.wrap(&message, &mut |b| out.try_extend_from_slice(b)) {
                Ok(()) => Ok(Some(out)),
                Err(failure) => Err(gss_failed(cx, gss, failure)),
            }
        }
    }
}

/// The message answering the security layer the server sent, `layer`
/// unwrapped: no layer, no receive buffer and the identity acted for;
/// `None` if the server's cannot be answered, said.
fn layer_answer(cx: &mut Ctx<'_>, layer: &[u8]) -> Result<Option<Vec<u8>>, SaslError> {
    // The layers offered and the largest message, 4 bytes (RFC 4752 3.1).
    let [offered, _, _, _] = layer[..] else {
        return cancel(cx, "invalid security data");
    };
    // No layer (`GSSAUTH_P_NONE`) must be among them.
    if offered & 1 == 0 {
        return cancel(cx, "invalid security layer");
    }
    let authzid = cx.creds.as_ref().map_or(&[][..], Secret::authzid);
    let mut message = Vec::new();
    // No layer, and no receive buffer.
    message.try_extend_from_slice(&[1, 0, 0, 0])?;
    message.try_extend_from_slice(authzid)?;
    Ok(Some(message))
}

/// The handshake given up, said why (`CURLE_BAD_CONTENT_ENCODING`).
fn cancel(cx: &mut Ctx<'_>, why: &str) -> Result<Option<Vec<u8>>, SaslError> {
    (cx.said)(Say::Info, format_args!("GSSAPI handshake failure ({why})"));
    Ok(None)
}

/// What a step makes: its token, and what the library noted on the way.
struct Sink {
    token: Vec<u8>,
    neg_mechs: Option<GssStatus>,
    no_policy: bool,
}

impl StepSink for Sink {
    fn token(&mut self, token: &[u8]) -> Result<(), OutOfMemory> {
        self.token.try_extend_from_slice(token)
    }

    fn note(&mut self, note: GssNote) {
        match note {
            GssNote::SetNegMechs(status) => self.neg_mechs = Some(status),
            GssNote::NoDelegationPolicy => self.no_policy = true,
        }
    }
}

/// The error a library failure is, said as C says it: the call's name
/// and what the library says of its status, `CURLE_AUTH_ERROR`.
fn gss_failed(cx: &mut Ctx<'_>, gss: &'static dyn Gss, failure: GssFailure) -> SaslError {
    match failure.kind {
        GssFailureKind::OutOfMemory => SaslError::OutOfMemory,
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
            SaslError::AuthError
        }
        GssFailureKind::NtlmChosen | GssFailureKind::EmptyToken => {
            unreachable!("only SPNEGO's contexts fail so, and Kerberos is asked")
        }
    }
}

/// `prefix` and what the library says of `status` (`Curl_gss_log_error`).
fn logged(cx: &mut Ctx<'_>, gss: &'static dyn Gss, prefix: &str, status: &GssStatus) {
    // At most C's 1024 bytes, on the stack.
    let mut text = crate::text::Text::<1024>::new();
    let fits = gss.describe(status, Style::Log, &mut |part| text.push_clipped(part));
    assert!(fits.is_ok(), "the log's layout is never too long");
    (cx.said)(Say::Info, format_args!("{prefix}{}", Lossy(text.bytes())));
}
