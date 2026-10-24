//! What a GSS-API library does for the core (C's `lib/curl_gssapi.c`
//! and the library under it): security contexts with a named service,
//! by Kerberos or by SPNEGO, stepped one token at a time, for HTTP's
//! Negotiate and SOCKS5's GSS-API method. The core links no library;
//! whoever builds a handle names one in its `Libraries`, and without
//! one these methods are not built in, as in a C build without GSS-API.
//!
//! The library's statuses pass through the core opaque: only the
//! library says what they mean, in the text it gives for them.

use std::fmt;

use curl_alloc::OutOfMemory;

/// A GSS-API library.
pub trait Gss: Send + Sync {
    /// A security context with `target`, by `mech`, which `flags` ask of
    /// the peer: the name imported (`gss_import_name`), nothing sent yet.
    fn context(
        &self,
        target: Target<'_>,
        mech: Mech,
        flags: Flags,
    ) -> Result<Box<dyn GssContext>, GssFailure>;

    /// What the library says of `status`, laid out as `style` asks, in
    /// the pieces `out` is given: its bytes as the library has them.
    /// `Err` when the text is longer than the layout's buffer holds,
    /// which in `Style::Socks` C answers by saying nothing.
    fn describe(
        &self,
        status: &GssStatus,
        style: Style,
        out: &mut dyn FnMut(&[u8]),
    ) -> Result<(), TooLong>;
}

impl fmt::Debug for dyn Gss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gss")
    }
}

/// One security context, from its first token to its last; the library
/// releases what it holds of it when it is dropped
/// (`gss_delete_sec_context`, `gss_release_name`, `gss_release_cred`).
pub trait GssContext: Send {
    /// The next step of the exchange (`gss_init_sec_context`): `input` is
    /// the peer's last token, none for the first step; `binding` is the
    /// TLS channel's binding data, if the exchange goes over TLS. The
    /// token to send goes to `sink`, which may be called with an empty
    /// one; what the library notes on the way, without failing, goes
    /// there too.
    fn step(
        &mut self,
        input: Option<&[u8]>,
        binding: Option<&[u8]>,
        sink: &mut dyn StepSink,
    ) -> Result<Step, GssFailure>;

    /// `message` protected for the peer, integrity only (`gss_wrap` with
    /// no confidentiality), handed to `out`.
    fn wrap(
        &mut self,
        message: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
    ) -> Result<(), GssFailure>;

    /// The message `token` protects (`gss_unwrap`), handed to `out`.
    fn unwrap(
        &mut self,
        token: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
    ) -> Result<(), GssFailure>;

    /// The name the context authenticated as, as the library displays
    /// it (`gss_inquire_context`, `gss_display_name`), handed to `out`.
    fn initiator(
        &mut self,
        out: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
    ) -> Result<(), GssFailure>;
}

impl fmt::Debug for dyn GssContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GssContext")
    }
}

/// Where a step puts what it makes.
pub trait StepSink {
    /// The token to send to the peer: called once, though possibly with
    /// no bytes. The library's buffer is released when this returns.
    fn token(&mut self, token: &[u8]) -> Result<(), OutOfMemory>;

    /// Something the library failed at on the way, without failing the
    /// step.
    fn note(&mut self, note: GssNote);
}

/// What a context is with: a host-based service (`service@host`, as
/// `GSS_C_NT_HOSTBASED_SERVICE`), or a name the library parses as it
/// is (SOCKS5's service names holding a `/`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    Service { service: &'a [u8], host: &'a [u8] },
    Name(&'a [u8]),
}

/// The mechanism a context uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mech {
    /// Kerberos 5 itself (SOCKS5).
    Kerberos,
    /// SPNEGO (HTTP's Negotiate), never settling on NTLM: the library
    /// is told to leave it out where it can be, and a context that
    /// chose it anyway fails.
    Spnego,
}

/// What a context asks of the peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// The peer is to prove who it is too (`GSS_C_MUTUAL_FLAG`).
    pub mutual: bool,
    /// The credentials are delegated to the peer where policy allows
    /// (`CURLGSSAPI_DELEGATION_POLICY_FLAG`).
    pub delegate_by_policy: bool,
    /// The credentials are delegated to the peer
    /// (`CURLGSSAPI_DELEGATION_FLAG`).
    pub delegate: bool,
}

/// Where a step left the context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub progress: Progress,
    /// The context can keep messages secret (`GSS_C_CONF_FLAG`).
    pub confidentiality: bool,
    /// The context can keep messages whole (`GSS_C_INTEG_FLAG`).
    pub integrity: bool,
}

/// How far a step that did not fail took the exchange, as the library's
/// major status says it, which C compares exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Complete on our side (`GSS_S_COMPLETE`).
    Complete,
    /// The peer's next token is needed (`GSS_S_CONTINUE_NEEDED`).
    Continue,
    /// Neither, though not an error: a status with supplementary bits.
    Other,
}

/// What the library failed at, without failing the step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GssNote {
    /// SPNEGO's mechanisms could not be narrowed to leave NTLM out
    /// (`gss_set_neg_mechs`).
    SetNegMechs(GssStatus),
}

/// A library call that failed, and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GssFailure {
    pub call: GssCall,
    pub kind: GssFailureKind,
}

impl GssFailure {
    pub fn status(call: GssCall, status: GssStatus) -> GssFailure {
        GssFailure {
            call,
            kind: GssFailureKind::Status(status),
        }
    }

    pub fn out_of_memory(call: GssCall) -> GssFailure {
        GssFailure {
            call,
            kind: GssFailureKind::OutOfMemory,
        }
    }
}

/// The library call a failure is of, which C's messages name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GssCall {
    ImportName,
    AcquireCred,
    InitSecContext,
    InquireContext,
    DisplayName,
    Wrap,
    Unwrap,
}

/// How a call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GssFailureKind {
    /// The library said no, with this status.
    Status(GssStatus),
    /// SPNEGO settled on NTLM, which is not allowed.
    NtlmChosen,
    /// SPNEGO made no token to send.
    EmptyToken,
    OutOfMemory,
}

/// A status the library answered with: its own codes, which only it
/// can say anything of (`Gss::describe`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GssStatus {
    major: u32,
    minor: u32,
}

impl GssStatus {
    /// For the library: its major and minor codes.
    pub fn new(major: u32, minor: u32) -> GssStatus {
        GssStatus { major, minor }
    }

    /// For the library: the codes it made the status with.
    pub fn codes(&self) -> (u32, u32) {
        (self.major, self.minor)
    }
}

/// A status's text did not fit its layout's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong;

/// How a status's text is laid out, as C's two layouts have it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// `Curl_gss_log_error`'s: every message of the major code, unless
    /// it is the bare `GSS_S_FAILURE`, then every message of the minor
    /// code, each followed by `". "`, as many as 1024 bytes hold; never
    /// too long.
    Log,
    /// `check_gss_err`'s: the major code's first message, `".\n"`, the
    /// minor code's first message, in at most 1023 bytes.
    Socks,
}
