//! SOCKS5's GSS-API method (RFC 1961, `lib/socks_gssapi.c`): a Kerberos
//! context with the proxy's service, its tokens sent and read in
//! messages of a version byte, a type byte and a 16-bit length, then the
//! protection the rest of the connection would have agreed on, wrapped by
//! the context unless NEC's reference implementation is followed.
//!
//! C runs the exchange with the socket made blocking; here its messages
//! are states of the handshake, sent and read as the socket lets them.

use std::fmt;

use curl_alloc::TryVec as _;

use super::{Awaiting, Handshake, SocksError, Took, head};
use crate::gss::{
    Flags, Gss, GssCall, GssFailure, GssFailureKind, GssNote, GssStatus, Mech, Progress, StepSink,
    Target,
};
use crate::options::Delegation;

/// SOCKS5's GSS-API method, built in with `library`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GssMethod {
    pub(crate) library: &'static dyn Gss,
    /// The protection level goes unwrapped (`CURLOPT_SOCKS5_GSSAPI_NEC`).
    pub(crate) nec: bool,
    /// What the credentials may be delegated (`CURLOPT_GSSAPI_DELEGATION`).
    pub(crate) delegation: Delegation,
}

/// The service a proxy is authenticated as where none is named.
const DEFAULT_SERVICE: &[u8] = b"rcmd";

/// The subnegotiation's version (RFC 1961, 3).
const VERSION: u8 = 1;
/// The message types: authentication, protection level, and the
/// proxy's refusal.
const AUTHENTICATION: u8 = 1;
const PROTECTION: u8 = 2;
const REFUSED: u8 = 255;

/// The protection a context can give, and the level byte that asks for
/// it (`gss_enc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    None = 0,
    Integrity = 1,
    Confidentiality = 2,
}

/// What the bytes to send hold, for the words C fails a send with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    /// No GSS-API message.
    None,
    /// An authentication message; the protection level's after it, from
    /// this offset, if the context completed with this token.
    Token { level_at: Option<usize> },
    /// The protection level's message alone.
    Level,
}

/// What C says along the way (`infof`).
#[derive(Clone, Copy, Debug)]
pub(crate) enum GssLine<'a> {
    /// The context is complete, as this user.
    Authenticated(&'a [u8]),
    /// The protection asked for.
    Supports(Level),
    /// The protection the proxy granted.
    Granted(u8),
}

impl fmt::Display for GssLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            GssLine::Authenticated(user) => write!(
                f,
                "SOCKS5 server authenticated user {} with GSS-API.",
                super::Text(user)
            ),
            GssLine::Supports(level) => write!(
                f,
                "SOCKS5 server supports GSS-API {} data protection.",
                match level {
                    Level::None => "no",
                    Level::Integrity => "integrity",
                    Level::Confidentiality => "confidentiality",
                }
            ),
            GssLine::Granted(level) => write!(
                f,
                "SOCKS5 access {} protection granted.",
                match level {
                    0 => "without GSS-API data",
                    1 => "with GSS-API integrity",
                    _ => "with GSS-API confidentiality",
                }
            ),
        }
    }
}

/// How the GSS-API method failed: the library call that said no, with
/// its status, then what C says of the step, each a `failf` of its own,
/// before "Unable to negotiate SOCKS5 GSS-API context.".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GssError {
    pub(crate) status: Option<(GssCall, GssStatus)>,
    pub(crate) step: Failed,
}

impl GssError {
    fn of(failure: GssFailure, step: Failed) -> GssError {
        match failure.kind {
            GssFailureKind::Status(status) => GssError {
                status: Some((failure.call, status)),
                step,
            },
            // Out of memory, C says no more than that it was unable to
            // negotiate; SPNEGO's own failures are not Kerberos's.
            GssFailureKind::OutOfMemory
            | GssFailureKind::NtlmChosen
            | GssFailureKind::EmptyToken => GssError::silent(),
        }
    }

    fn at(step: Failed) -> GssError {
        GssError { status: None, step }
    }

    fn silent() -> GssError {
        GssError::at(Failed::Silently)
    }

    /// The name C gives the call (`check_gss_err`'s `function`).
    pub(crate) fn call_name(call: GssCall) -> &'static str {
        match call {
            GssCall::ImportName => "gss_import_name()",
            GssCall::AcquireCred => "gss_acquire_cred",
            GssCall::InitSecContext => "gss_init_sec_context",
            GssCall::InquireContext => "gss_inquire_context",
            GssCall::DisplayName => "gss_display_name",
            GssCall::Wrap => "gss_wrap",
            GssCall::Unwrap => "gss_unwrap",
        }
    }
}

impl From<GssError> for SocksError {
    fn from(e: GssError) -> SocksError {
        SocksError::Gss(e)
    }
}

/// The step that failed, as C says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failed {
    /// Nothing is said of it.
    Silently,
    CreateName,
    InitToken,
    SendAuthRequest,
    SendAuthToken,
    RecvAuthResponse,
    Rejected(u8, u8),
    AuthType(u8, u8),
    ZeroAuthToken,
    RecvAuthToken,
    Username,
    Wrap,
    SendLevelRequest,
    SendLevel,
    RecvLevelResponse,
    LevelType(u8, u8),
    ZeroLevelToken,
    RecvLevel,
    Unwrap,
    LevelLength(usize),
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match *self {
            Failed::Silently => "",
            Failed::CreateName => "Failed to create service name.",
            Failed::InitToken => "Failed to initialize GSS-API token.",
            Failed::SendAuthRequest => "Failed to send GSS-API authentication request.",
            Failed::SendAuthToken => "Failed to send GSS-API authentication token.",
            Failed::RecvAuthResponse => "Failed to receive GSS-API authentication response.",
            Failed::Rejected(v, t) => {
                return write!(f, "User was rejected by the SOCKS5 server ({v} {t}).");
            }
            Failed::AuthType(v, t) => {
                return write!(f, "Invalid GSS-API authentication response type ({v} {t}).");
            }
            Failed::ZeroAuthToken => "Invalid zero-length GSS-API authentication token.",
            Failed::RecvAuthToken => "Failed to receive GSS-API authentication token.",
            Failed::Username => "Failed to determine username.",
            Failed::Wrap => "Failed to wrap GSS-API encryption value into token.",
            Failed::SendLevelRequest => "Failed to send GSS-API encryption request.",
            Failed::SendLevel => "Failed to send GSS-API encryption type.",
            Failed::RecvLevelResponse => "Failed to receive GSS-API encryption response.",
            Failed::LevelType(v, t) => {
                return write!(f, "Invalid GSS-API encryption response type ({v} {t}).");
            }
            Failed::ZeroLevelToken => "Invalid zero-length GSS-API encryption token.",
            Failed::RecvLevel => "Failed to receive GSS-API encryption type.",
            Failed::Unwrap => "Failed to unwrap GSS-API encryption value into token.",
            Failed::LevelLength(n) => {
                return write!(f, "Invalid GSS-API encryption response length ({n}).");
            }
        };
        f.write_str(text)
    }
}

/// The length a message's 4 bytes say it has, with them.
fn framed_len(r: &[u8; 4]) -> usize {
    4 + usize::from(u16::from_be_bytes([r[2], r[3]]))
}

/// Where a step's token goes: framed after what is to be sent.
struct Framer<'a> {
    out: &'a mut Vec<u8>,
    /// The token does not fit its 16-bit length.
    too_long: bool,
}

impl StepSink for Framer<'_> {
    fn token(&mut self, token: &[u8]) -> Result<(), curl_alloc::OutOfMemory> {
        let Ok(len) = u16::try_from(token.len()) else {
            self.too_long = true;
            return Ok(());
        };
        if !token.is_empty() {
            let [hi, lo] = len.to_be_bytes();
            self.out
                .try_extend_from_slice(&[VERSION, AUTHENTICATION, hi, lo])?;
            self.out.try_extend_from_slice(token)?;
        }
        Ok(())
    }

    /// SPNEGO's alone.
    fn note(&mut self, _: GssNote) {}
}

impl Handshake {
    /// GSS-API was picked: its context is to be made, with `start_gss`.
    pub(crate) fn gss_starts(&self) -> bool {
        self.awaiting == Awaiting::GssStart
    }

    /// Make the context with the proxy called `proxy`, as the service the
    /// credentials name or `rcmd`, and take its first step
    /// (`socks5_gss_create_service_name`).
    pub(crate) fn start_gss(
        &mut self,
        proxy: &[u8],
        say: &mut dyn FnMut(GssLine<'_>),
    ) -> Result<(), SocksError> {
        let method = self.gss.expect("GSS-API is built in when picked");
        let service = match &self.creds {
            Some(c) if !c.service.is_empty() => &c.service[..],
            _ => DEFAULT_SERVICE,
        };
        let target = if service.contains(&b'/') {
            Target::Name(service)
        } else {
            Target::Service {
                service,
                host: proxy,
            }
        };
        let flags = Flags {
            mutual: true,
            delegate_by_policy: method.delegation.by_policy,
            delegate: method.delegation.always,
        };
        let context = method
            .library
            .context(target, Mech::Kerberos, flags)
            .map_err(|f| GssError::of(f, Failed::CreateName))?;
        self.context = Some(context);
        self.gss_step(None, say)
    }

    /// The next step of the context, with the proxy's token if it sent
    /// one, and its token framed to be sent; once the context needs no
    /// more, who it is, and the protection asked for
    /// (`socks5_gss_auth_loop`).
    fn gss_step(
        &mut self,
        input: Option<&[u8]>,
        say: &mut dyn FnMut(GssLine<'_>),
    ) -> Result<(), SocksError> {
        let context = self.context.as_mut().expect("a context is made");
        self.out.clear();
        self.sent = 0;
        let mut framer = Framer {
            out: &mut self.out,
            too_long: false,
        };
        let step = context
            .step(input, None, &mut framer)
            .map_err(|f| GssError::of(f, Failed::InitToken))?;
        if framer.too_long {
            return Err(GssError::at(Failed::InitToken).into());
        }
        // Each step says it anew (`gss_ret_flags`).
        self.can = if step.confidentiality {
            Level::Confidentiality
        } else if step.integrity {
            Level::Integrity
        } else {
            Level::None
        };
        if step.progress == Progress::Continue {
            self.framing = Framing::Token { level_at: None };
            self.awaiting = Awaiting::GssToken;
            return Ok(());
        }
        let level_at = self.out.len();
        self.framing = Framing::Token {
            level_at: Some(level_at),
        };
        self.verify(say)?;
        self.ask_level(say)?;
        if level_at == 0 {
            self.framing = Framing::Level;
        }
        Ok(())
    }

    /// The proxy's authentication message: refused, or its token for the
    /// next step, if all of it is there.
    pub(super) fn gss_token(
        &mut self,
        input: &[u8],
        say: &mut dyn FnMut(GssLine<'_>),
    ) -> Result<Took, SocksError> {
        let r = match head::<4>(input) {
            Ok(r) => r,
            Err(need) => return Ok(need),
        };
        // The version is not looked at.
        match r[1] {
            REFUSED => return Err(GssError::at(Failed::Rejected(r[0], r[1])).into()),
            AUTHENTICATION => {}
            _ => return Err(GssError::at(Failed::AuthType(r[0], r[1])).into()),
        }
        let len = framed_len(r);
        if len == 4 {
            return Err(GssError::at(Failed::ZeroAuthToken).into());
        }
        let Some(token) = input.get(4..len) else {
            return Ok(Took::Need(len));
        };
        self.gss_step(Some(token), say)?;
        Ok(Took::Read(len))
    }

    /// Who the context says it authenticated (`socks5_gss_auth_verify`).
    fn verify(&mut self, say: &mut dyn FnMut(GssLine<'_>)) -> Result<(), SocksError> {
        let context = self.context.as_mut().expect("a context is made");
        context
            .initiator(&mut |user| {
                say(GssLine::Authenticated(user));
                Ok(())
            })
            .map_err(|f| GssError::of(f, Failed::Username).into())
    }

    /// The protection level asked for, after what is to be sent: wrapped
    /// by the context, or alone in NEC's way (`socks5_gss_negotiate_enc`).
    fn ask_level(&mut self, say: &mut dyn FnMut(GssLine<'_>)) -> Result<(), SocksError> {
        let level = self.can;
        say(GssLine::Supports(level));
        let method = self.gss.expect("GSS-API is built in when picked");
        if method.nec {
            self.out
                .try_extend_from_slice(&[VERSION, PROTECTION, 0, 1, level as u8])
                .map_err(|_| GssError::silent())?;
        } else {
            let context = self.context.as_mut().expect("a context is made");
            let out = &mut self.out;
            context
                .wrap(&[level as u8], &mut |token| {
                    // C keeps the low 16 bits of a length that cannot need
                    // more.
                    let [hi, lo] = (token.len() as u16).to_be_bytes();
                    out.try_extend_from_slice(&[VERSION, PROTECTION, hi, lo])?;
                    out.try_extend_from_slice(token)
                })
                .map_err(|f| GssError::of(f, Failed::Wrap))?;
        }
        self.awaiting = Awaiting::GssLevel;
        Ok(())
    }

    /// The proxy's protection-level message, if all of it is there: the
    /// level granted, then the request for the destination.
    pub(super) fn gss_level(
        &mut self,
        input: &[u8],
        say: &mut dyn FnMut(GssLine<'_>),
    ) -> Result<Took, SocksError> {
        let r = match head::<4>(input) {
            Ok(r) => r,
            Err(need) => return Ok(need),
        };
        match r[1] {
            REFUSED => return Err(GssError::at(Failed::Rejected(r[0], r[1])).into()),
            PROTECTION => {}
            _ => return Err(GssError::at(Failed::LevelType(r[0], r[1])).into()),
        }
        let len = framed_len(r);
        if len == 4 {
            return Err(GssError::at(Failed::ZeroLevelToken).into());
        }
        let Some(token) = input.get(4..len) else {
            return Ok(Took::Need(len));
        };
        let method = self.gss.expect("GSS-API is built in when picked");
        let granted = if method.nec {
            match token {
                &[level] => level,
                _ => return Err(GssError::at(Failed::LevelLength(token.len())).into()),
            }
        } else {
            let context = self.context.as_mut().expect("a context is made");
            let mut unwrapped = Err(0);
            context
                .unwrap(token, &mut |message| {
                    unwrapped = match message {
                        &[level] => Ok(level),
                        _ => Err(message.len()),
                    };
                    Ok(())
                })
                .map_err(|f| GssError::of(f, Failed::Unwrap))?;
            unwrapped.map_err(|n| GssError::at(Failed::LevelLength(n)))?
        };
        say(GssLine::Granted(granted));
        self.granted = granted;
        if granted == 0 {
            self.context = None;
        }
        self.request5()?;
        Ok(Took::Read(len))
    }

    /// What C says of a send of the GSS-API messages that failed, if they
    /// are what was being sent.
    pub(crate) fn gss_send_failed(&self) -> Option<SocksError> {
        let at = |base: usize, request, rest| {
            if self.sent < base + 4 { request } else { rest }
        };
        let step = match self.framing {
            Framing::None => return None,
            Framing::Token {
                level_at: Some(level_at),
            } if self.sent >= level_at => at(level_at, Failed::SendLevelRequest, Failed::SendLevel),
            Framing::Token { .. } => at(0, Failed::SendAuthRequest, Failed::SendAuthToken),
            Framing::Level => at(0, Failed::SendLevelRequest, Failed::SendLevel),
        };
        Some(GssError::at(step).into())
    }

    /// What C says of the proxy closing, or a read failing, while one of
    /// its GSS-API messages is awaited, of which `received` bytes came.
    pub(crate) fn gss_recv_failed(&self, received: usize) -> Option<SocksError> {
        let step = match (self.awaiting, received < 4) {
            (Awaiting::GssToken, true) => Failed::RecvAuthResponse,
            (Awaiting::GssToken, false) => Failed::RecvAuthToken,
            (Awaiting::GssLevel, true) => Failed::RecvLevelResponse,
            (Awaiting::GssLevel, false) => Failed::RecvLevel,
            _ => return None,
        };
        Some(GssError::at(step).into())
    }
}
