//! The debug test build's stand-in for a KDC (C's `CURL_GSS_STUB` in
//! `lib/curl_gssapi.c`): with `CURL_STUB_GSS_CREDS` set, a context's
//! credentials and steps are this stub's, which makes tokens that say
//! what they were asked (`creds:target:type:`, padded with `A`) and
//! answers a peer's `D` (done) and `C` (continue). The name is still the
//! library's, imported and displayed by it, as in C.
//!
//! As C's, the stub does not wrap or unwrap: SOCKS5's GSS-API cannot run
//! on it.

use curl_alloc::{OutOfMemory, try_box};

use crate::sys::{self, Name};
use crate::{KRB5_OID, NTLMSSP_OID};

const VARIABLE: &[u8] = b"CURL_STUB_GSS_CREDS";

/// The room C keeps for the credentials, their NUL included.
const CREDS: usize = 250;

/// The token's length: base64 of it fills the credentials' room.
const TOKEN: usize = CREDS * 3 / 4;

/// The stub's minor codes (`enum min_err_code`).
pub(crate) const NO_MEMORY: u32 = 1;
pub(crate) const INVALID_CREDS: u32 = 3;
pub(crate) const INVALID_CTX: u32 = 4;
pub(crate) const SERVER_ERR: u32 = 5;
pub(crate) const NO_MECH: u32 = 6;

/// Whether contexts are the stub's: the variable is set.
pub(crate) fn chosen() -> bool {
    curl_os::env::is_set(VARIABLE)
}

/// A failure with the stub's minor code.
fn failure(minor: u32) -> sys::Status {
    (sys::GSS_S_FAILURE, minor)
}

/// The credentials the variable names, if it is set, in `buf`.
fn creds(buf: &mut [u8; CREDS]) -> Option<&[u8]> {
    curl_os::env::var_into(VARIABLE, buf)
}

/// Which mechanisms the credentials allow (`stub_gss_cred_id_t_desc`).
pub(crate) struct Cred {
    allow_krb5: bool,
    allow_ntlm: bool,
}

impl Cred {
    /// The default credentials, allowing every mechanism
    /// (`stub_gss_acquire_cred`).
    pub(crate) fn acquire() -> Result<Box<Cred>, sys::Status> {
        try_box(Cred {
            allow_krb5: true,
            allow_ntlm: true,
        })
        .map_err(|OutOfMemory| failure(NO_MEMORY))
    }

    /// Narrows the mechanisms to `set`'s (`stub_gss_set_neg_mechs`).
    pub(crate) fn set_neg_mechs(&mut self, set: &[&[u8]]) {
        self.allow_krb5 = set.contains(&KRB5_OID);
        self.allow_ntlm = set.contains(&NTLMSSP_OID);
    }
}

/// The mechanisms the stub has: Kerberos, and NTLM if the credentials
/// name it (`stub_gss_indicate_mechs`).
pub(crate) fn mechanisms() -> Result<([&'static [u8]; 2], usize), sys::Status> {
    let mut buf = [0; CREDS];
    let creds = creds(&mut buf).ok_or(failure(INVALID_CREDS))?;
    if contains(creds, b"NTLM") {
        Ok(([KRB5_OID, NTLMSSP_OID], 2))
    } else {
        Ok(([KRB5_OID, KRB5_OID], 1))
    }
}

/// The token last sent, by mechanism.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sent {
    Krb5 = 1,
    Ntlm1 = 2,
    Ntlm3 = 3,
}

/// A context (`stub_gss_ctx_id_t_desc`).
pub(crate) struct Ctx {
    sent: Sent,
    have_ntlm: bool,
    flags: u32,
    creds: [u8; CREDS],
    creds_len: usize,
}

impl Ctx {
    fn creds(&self) -> &[u8] {
        &self.creds[..self.creds_len]
    }

    /// Whether the mechanism is NTLM (`stub_gss_inquire_context`).
    pub(crate) fn is_ntlm(&self) -> bool {
        matches!(self.sent, Sent::Ntlm1 | Sent::Ntlm3)
    }
}

/// A token the stub made.
pub(crate) struct Token {
    bytes: [u8; TOKEN],
    len: usize,
}

impl Token {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// What a step gave back, as `sys::Init` has it.
pub(crate) struct Init {
    pub(crate) major: u32,
    pub(crate) token: Token,
    pub(crate) flags: u32,
}

/// One step (`stub_gss_init_sec_context`): `ctx` is the context so far,
/// none before the first; `cred` restricts the mechanisms, if given.
pub(crate) fn init(
    ctx: &mut Option<Box<Ctx>>,
    cred: Option<&Cred>,
    name: &Name,
    flags: u32,
    input: Option<&[u8]>,
) -> Result<Init, sys::Status> {
    let mut buf = [0; CREDS];
    let creds = match creds(&mut buf) {
        Some(creds) if creds.len() < CREDS => creds,
        _ => return Err(failure(INVALID_CREDS)),
    };
    if ctx.as_ref().is_some_and(|c| c.creds() != creds) {
        return Err(failure(INVALID_CREDS));
    }
    let empty = Token {
        bytes: [0; TOKEN],
        len: 0,
    };
    let mut made = None;
    match input.filter(|i| !i.is_empty()) {
        Some(input) => {
            let Some(ctx) = ctx.as_mut() else {
                return Err(failure(INVALID_CTX));
            };
            match input[0] {
                // Done.
                b'D' => {
                    return match ctx.sent {
                        Sent::Krb5 | Sent::Ntlm3 => Ok(Init {
                            major: sys::GSS_S_COMPLETE,
                            token: empty,
                            flags: ctx.flags,
                        }),
                        Sent::Ntlm1 => Err(failure(SERVER_ERR)),
                    };
                }
                // Continue: Kerberos failed, NTLM goes on.
                b'C' => match ctx.sent {
                    Sent::Krb5 if ctx.have_ntlm => ctx.sent = Sent::Ntlm1,
                    Sent::Ntlm1 => ctx.sent = Sent::Ntlm3,
                    _ => return Err(failure(SERVER_ERR)),
                },
                _ => return Err(failure(SERVER_ERR)),
            }
        }
        None => {
            if ctx.is_some() {
                return Err(failure(INVALID_CTX));
            }
            let mut have_krb5 = contains(creds, b"KRB5");
            let mut have_ntlm = contains(creds, b"NTLM");
            if let Some(cred) = cred {
                have_krb5 &= cred.allow_krb5;
                have_ntlm &= cred.allow_ntlm;
            }
            let sent = if have_krb5 {
                Sent::Krb5
            } else if have_ntlm {
                Sent::Ntlm1
            } else {
                return Err(failure(NO_MECH));
            };
            let mut new = try_box(Ctx {
                sent,
                have_ntlm,
                flags,
                creds: [0; CREDS],
                creds_len: creds.len(),
            })
            .map_err(|OutOfMemory| failure(NO_MEMORY))?;
            new.creds[..creds.len()].copy_from_slice(creds);
            made = Some(new);
        }
    }
    let sent = made.as_ref().or(ctx.as_ref()).map(|c| c.sent);
    let sent = sent.expect("a context made or kept");
    let token = token(creds, name, sent)?;
    if let Some(made) = made {
        *ctx = Some(made);
    }
    Ok(Init {
        major: sys::GSS_S_CONTINUE_NEEDED,
        token,
        flags: 0,
    })
}

/// `creds:target:type:`, the name displayed by the library, cut where
/// C's `curl_msnprintf` cuts it and padded with `A` to `TOKEN` bytes.
fn token(creds: &[u8], name: &Name, sent: Sent) -> Result<Token, sys::Status> {
    let target = name.display().map_err(|_| failure(NO_MEMORY))?;
    let target = target.bytes();
    if creds.len() + target.len() + 5 >= CREDS {
        return Err(failure(NO_MEMORY));
    }
    let mut token = Token {
        bytes: [b'A'; TOKEN],
        len: TOKEN,
    };
    // The text, as much of it as fits before the NUL C writes last.
    let number = [b'0' + sent as u8];
    let parts: [&[u8]; 6] = [creds, b":", target, b":", &number, b":"];
    let mut at = 0;
    for part in parts {
        // `%.*s` and `%s` stop at a NUL.
        let part = part.split(|&b| b == 0).next().unwrap_or_default();
        let n = part.len().min(TOKEN - 1 - at);
        token.bytes[at..at + n].copy_from_slice(&part[..n]);
        at += n;
    }
    Ok(token)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
