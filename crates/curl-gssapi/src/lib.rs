//! GSS-API by MIT krb5 (`lib/curl_gssapi.c`, `lib/vauth/spnego_gssapi.c`
//! and the library calls of `lib/socks_gssapi.c`): security contexts by
//! SPNEGO, which never settles on NTLM, or by Kerberos, behind
//! `curl_core::gss::Gss`.
//!
//! With the `debug-hooks` feature, the debug test build's stub stands in
//! for the credentials and the steps whenever `CURL_STUB_GSS_CREDS` is
//! set, as in C's debug build.

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod describe;
#[cfg(feature = "debug-hooks")]
mod stub;
mod sys;
#[cfg(test)]
mod tests;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};
use curl_core::gss::{
    Flags, Gss, GssCall, GssContext, GssFailure, GssFailureKind, GssNote, GssStatus, Mech,
    Progress, Step, StepSink, Style, Target, TooLong,
};

use sys::{Name, NameKind};

/// SPNEGO, 1.3.6.1.5.5.2.
const SPNEGO_OID: &[u8] = b"\x2b\x06\x01\x05\x05\x02";
/// Kerberos 5, 1.2.840.113554.1.2.2.
const KRB5_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
/// NTLMSSP, 1.3.6.1.4.1.311.2.2.10.
const NTLMSSP_OID: &[u8] = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";

/// The library, for a handle's `Libraries`.
pub static GSSAPI: GssApi = GssApi;

/// The library's version, as `curl -V` names it after `mit-krb5/`
/// (`CURL_KRB5_VERSION`, found as the crate was built).
pub fn version() -> &'static str {
    env!("CURL_KRB5_VERSION")
}

/// MIT krb5's GSS-API.
pub struct GssApi;

impl Gss for GssApi {
    fn context(
        &self,
        target: Target<'_>,
        mech: Mech,
        flags: Flags,
    ) -> Result<Box<dyn GssContext>, GssFailure> {
        let oom = |OutOfMemory| GssFailure::out_of_memory(GssCall::ImportName);
        // The name in memory of its own, as C's `curl_maprintf` and
        // `curlx_memdup` make it.
        let mut text = Vec::new();
        let kind = match target {
            Target::Service { service, host } => {
                for part in [service, b"@", host] {
                    text.try_extend_from_slice(part).map_err(oom)?;
                }
                NameKind::HostBased
            }
            Target::Name(name) => {
                text.try_extend_from_slice(name).map_err(oom)?;
                NameKind::Native
            }
        };
        let name = Name::import(&text, kind)
            .map_err(|s| GssFailure::status(GssCall::ImportName, status(s)))?;
        drop(text);
        let mut req = sys::GSS_C_REPLAY_FLAG;
        if flags.mutual {
            req |= sys::GSS_C_MUTUAL_FLAG;
        }
        if flags.delegate_by_policy {
            req |= sys::GSS_C_DELEG_POLICY_FLAG;
        }
        if flags.delegate {
            req |= sys::GSS_C_DELEG_FLAG;
        }
        let context = Context {
            name,
            mech,
            flags: req,
            backend: None,
        };
        Ok(try_box(context).map_err(oom)?)
    }

    fn describe(
        &self,
        status: &GssStatus,
        style: Style,
        out: &mut dyn FnMut(&[u8]),
    ) -> Result<(), TooLong> {
        describe::describe(status, style, out)
    }
}

fn status((major, minor): sys::Status) -> GssStatus {
    GssStatus::new(major, minor)
}

/// One context: its name, and once it is first stepped, whose it is.
struct Context {
    name: Name,
    mech: Mech,
    /// The flags asked of the peer (`req_flags`).
    flags: u32,
    backend: Option<Backend>,
}

/// The library's context, or the stub's: decided as the context is
/// first stepped, as C decides each call, and kept, since a context of
/// one is nothing to the other.
enum Backend {
    Library {
        cred: Option<sys::Cred>,
        ctx: sys::Ctx,
    },
    #[cfg(feature = "debug-hooks")]
    Stub {
        cred: Option<Box<stub::Cred>>,
        ctx: Option<Box<stub::Ctx>>,
    },
}

impl Backend {
    fn chosen() -> Backend {
        #[cfg(feature = "debug-hooks")]
        if stub::chosen() {
            return Backend::Stub {
                cred: None,
                ctx: None,
            };
        }
        Backend::Library {
            cred: None,
            ctx: sys::Ctx::new(),
        }
    }

    fn has_cred(&self) -> bool {
        match self {
            Backend::Library { cred, .. } => cred.is_some(),
            #[cfg(feature = "debug-hooks")]
            Backend::Stub { cred, .. } => cred.is_some(),
        }
    }

    /// SPNEGO's credentials, without NTLM among the mechanisms it may
    /// negotiate where the library lets them be narrowed (C's
    /// `HAVE_GSS_SET_NEG_MECHS` block).
    fn spnego_cred(&mut self, sink: &mut dyn StepSink) -> Result<(), GssFailure> {
        let acquired = |s| GssFailure::status(GssCall::AcquireCred, status(s));
        match self {
            Backend::Library { cred, .. } => {
                let new = sys::Cred::acquire().map_err(acquired)?;
                if let Ok(all) = sys::OidSet::mechanisms()
                    && let Ok(narrowed) = all.without(NTLMSSP_OID)
                    && let Err(s) = new.set_neg_mechs(&narrowed)
                {
                    sink.note(GssNote::SetNegMechs(status(s)));
                }
                *cred = Some(new);
            }
            #[cfg(feature = "debug-hooks")]
            Backend::Stub { cred, .. } => {
                let mut new = stub::Cred::acquire().map_err(acquired)?;
                if let Ok((all, n)) = stub::mechanisms() {
                    let mut narrowed = [&[][..]; 2];
                    let mut kept = 0;
                    for oid in &all[..n] {
                        if *oid != NTLMSSP_OID {
                            narrowed[kept] = oid;
                            kept += 1;
                        }
                    }
                    new.set_neg_mechs(&narrowed[..kept]);
                }
                *cred = Some(new);
            }
        }
        Ok(())
    }
}

impl GssContext for Context {
    fn step(
        &mut self,
        input: Option<&[u8]>,
        binding: Option<&[u8]>,
        sink: &mut dyn StepSink,
    ) -> Result<Step, GssFailure> {
        let backend = self.backend.get_or_insert_with(Backend::chosen);
        if self.mech == Mech::Spnego && !backend.has_cred() {
            backend.spnego_cred(sink)?;
        }
        let init = |s| GssFailure::status(GssCall::InitSecContext, status(s));
        let mech = match self.mech {
            Mech::Spnego => SPNEGO_OID,
            Mech::Kerberos => KRB5_OID,
        };
        let binding = binding.filter(|b| !b.is_empty());
        let (major, flags, ntlm, token) = match backend {
            Backend::Library { cred, ctx } => {
                let out = ctx.init(cred.as_ref(), &self.name, mech, self.flags, binding, input);
                if sys::is_error(out.major) {
                    return Err(init((out.major, out.minor)));
                }
                let ntlm = |ctx: &sys::Ctx| ctx.is_made() && ctx.mech_is(NTLMSSP_OID) == Ok(true);
                (out.major, out.flags, ntlm(ctx), Token::Library(out.token))
            }
            #[cfg(feature = "debug-hooks")]
            Backend::Stub { cred, ctx } => {
                let out = stub::init(ctx, cred.as_deref(), &self.name, self.flags, input)
                    .map_err(init)?;
                let ntlm = ctx.as_ref().is_some_and(|c| c.is_ntlm());
                (out.major, out.flags, ntlm, Token::Stub(out.token))
            }
        };
        if self.mech == Mech::Spnego {
            // C's checks after `Curl_gss_init_sec_context`, in its order.
            if token.bytes().is_empty() {
                return Err(GssFailure {
                    call: GssCall::InitSecContext,
                    kind: GssFailureKind::EmptyToken,
                });
            }
            if ntlm {
                return Err(GssFailure {
                    call: GssCall::InquireContext,
                    kind: GssFailureKind::NtlmChosen,
                });
            }
        }
        sink.token(token.bytes())
            .map_err(|OutOfMemory| GssFailure::out_of_memory(GssCall::InitSecContext))?;
        let progress = match major {
            sys::GSS_S_COMPLETE => Progress::Complete,
            sys::GSS_S_CONTINUE_NEEDED => Progress::Continue,
            _ => Progress::Other,
        };
        Ok(Step {
            progress,
            confidentiality: flags & sys::GSS_C_CONF_FLAG != 0,
            integrity: flags & sys::GSS_C_INTEG_FLAG != 0,
        })
    }

    fn wrap(
        &mut self,
        message: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
    ) -> Result<(), GssFailure> {
        let ctx = self.library_ctx(GssCall::Wrap)?;
        let wrapped = ctx
            .wrap(message)
            .map_err(|s| GssFailure::status(GssCall::Wrap, status(s)))?;
        out(wrapped.bytes()).map_err(|OutOfMemory| GssFailure::out_of_memory(GssCall::Wrap))
    }

    fn unwrap(
        &mut self,
        token: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
    ) -> Result<(), GssFailure> {
        let ctx = self.library_ctx(GssCall::Unwrap)?;
        let message = ctx
            .unwrap(token)
            .map_err(|s| GssFailure::status(GssCall::Unwrap, status(s)))?;
        out(message.bytes()).map_err(|OutOfMemory| GssFailure::out_of_memory(GssCall::Unwrap))
    }

    fn initiator(
        &mut self,
        out: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
    ) -> Result<(), GssFailure> {
        let ctx = self.library_ctx(GssCall::InquireContext)?;
        let name = ctx
            .initiator()
            .map_err(|s| GssFailure::status(GssCall::InquireContext, status(s)))?;
        let shown = name
            .display()
            .map_err(|s| GssFailure::status(GssCall::DisplayName, status(s)))?;
        out(shown.bytes()).map_err(|OutOfMemory| GssFailure::out_of_memory(GssCall::DisplayName))
    }
}

impl Context {
    /// The library's context, for the calls the stub has no stand-in
    /// for: a stub's context fails them as one the library does not
    /// know.
    fn library_ctx(&self, call: GssCall) -> Result<&sys::Ctx, GssFailure> {
        match &self.backend {
            Some(Backend::Library { ctx, .. }) if ctx.is_made() => Ok(ctx),
            #[cfg(feature = "debug-hooks")]
            Some(Backend::Stub { .. }) => Err(GssFailure::status(
                call,
                GssStatus::new(sys::GSS_S_FAILURE, stub::INVALID_CTX),
            )),
            // No context yet: the library's answer to one it was never
            // given (`GSS_S_NO_CONTEXT`).
            _ => Err(GssFailure::status(call, GssStatus::new(NO_CONTEXT, 0))),
        }
    }
}

/// `GSS_S_NO_CONTEXT`.
const NO_CONTEXT: u32 = 8 << 16;

/// A step's token: the library's buffer, released after it is handed
/// on, or the stub's.
enum Token {
    Library(sys::Buffer),
    #[cfg(feature = "debug-hooks")]
    Stub(stub::Token),
}

impl Token {
    fn bytes(&self) -> &[u8] {
        match self {
            Token::Library(b) => b.bytes(),
            #[cfg(feature = "debug-hooks")]
            Token::Stub(t) => t.bytes(),
        }
    }
}
