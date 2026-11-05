//! Windows' SSPI for the curl rewrite's authentication, behind
//! `curl_core::sspi::Sspi`: the credentials and contexts of the
//! `Negotiate`, `Kerberos` and `WDigest` packages, as C's
//! `USE_WINDOWS_SSPI` build makes them, in the build's text (the ANSI
//! code page, or UTF-8 converted to UTF-16 in the Unicode build); and
//! what Schannel shares of SSPI with them (`handle`). On any other system
//! the crate is empty.

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

#[cfg(windows)]
pub mod handle;
#[cfg(windows)]
mod sys;

#[cfg(windows)]
pub use imp::{SSPI, WindowsSspi};

#[cfg(windows)]
mod imp {
    use curl_alloc::{OutOfMemory, TryVec as _, try_box};
    use curl_core::sspi::{
        Identity, Initialize, Initialized, Input, Output, Package, SecStatus, Sizes, Sspi,
        SspiContext, SspiFailure,
    };

    use crate::sys::{self, Text};

    /// SSPI, as the core's.
    #[derive(Debug)]
    pub struct WindowsSspi;

    /// SSPI.
    pub static SSPI: WindowsSspi = WindowsSspi;

    /// `text` in the build's form, ended by a zero: as it is, or
    /// converted from UTF-8 to UTF-16 in the Unicode build, where text
    /// that is not UTF-8 does not convert, as C's
    /// `curlx_convert_UTF8_to_tchar` fails on it.
    pub(crate) fn tchar(text: &[u8]) -> Result<Text, OutOfMemory> {
        if curl_os::UNICODE {
            let s = core::str::from_utf8(text).map_err(|_| OutOfMemory)?;
            let mut w = Vec::new();
            w.try_reserve_exact(s.encode_utf16().count() + 1)
                .map_err(|_| OutOfMemory)?;
            for unit in s.encode_utf16() {
                w.try_push(unit)?;
            }
            w.try_push(0)?;
            Ok(Text::Wide(w))
        } else {
            let mut a = Vec::new();
            a.try_reserve_exact(text.len() + 1)
                .map_err(|_| OutOfMemory)?;
            a.try_extend_from_slice(text)?;
            a.try_push(0)?;
            Ok(Text::Ansi(a))
        }
    }

    /// The name C gives `package` (`SP_NAME_*`).
    fn package_name(package: Package) -> &'static [u8] {
        match package {
            Package::Negotiate => b"Negotiate",
            Package::Kerberos => b"Kerberos",
            Package::Digest => b"WDigest",
        }
    }

    fn status(code: i32) -> SecStatus {
        SecStatus::new(code)
    }

    impl Sspi for WindowsSspi {
        fn max_token(&self, package: Package) -> Result<usize, SecStatus> {
            let name = tchar(package_name(package))
                .map_err(|OutOfMemory| SecStatus::INSUFFICIENT_MEMORY)?;
            sys::max_token(&name)
                .map(|n| usize::try_from(n).expect("a u32 fits"))
                .map_err(status)
        }

        fn credentials(
            &self,
            package: Package,
            identity: &Identity<'_>,
        ) -> Result<Box<dyn SspiContext>, SspiFailure> {
            let name = tchar(package_name(package))?;
            let identity = match *identity {
                Identity::Current => None,
                Identity::Packages(list) => Some(sys::IdentityText {
                    given: None,
                    packages: Some(tchar(list)?),
                }),
                Identity::Given {
                    user,
                    domain,
                    password,
                    packages,
                } => Some(sys::IdentityText {
                    given: Some([tchar(user)?, tchar(domain)?, tchar(password)?]),
                    packages: if packages.is_empty() {
                        None
                    } else {
                        Some(tchar(packages)?)
                    },
                }),
            };
            let cred = sys::acquire(&name, identity.as_ref())
                .map_err(|s| SspiFailure::Status(status(s)))?;
            Ok(try_box(Context {
                cred,
                context: None,
            })?)
        }

        fn describe(&self, status: SecStatus, out: &mut dyn FnMut(&[u8])) {
            out(curl_os::error::ErrorText::sspi(status.code()).as_bytes());
        }
    }

    /// Credentials and the context made with them.
    struct Context {
        cred: sys::CredHandle,
        /// Dropped first: a context before its credentials.
        context: Option<sys::CtxtHandle>,
    }

    impl Drop for Context {
        fn drop(&mut self) {
            self.context = None;
        }
    }

    /// `ISC_REQ_*` for what the core asks.
    fn req(r: curl_core::sspi::Req) -> u32 {
        use windows_sys::Win32::Security::Authentication::Identity as id;
        let mut bits = 0;
        for (on, bit) in [
            (r.delegate, id::ISC_REQ_DELEGATE),
            (r.mutual_auth, id::ISC_REQ_MUTUAL_AUTH),
            (r.replay_detect, id::ISC_REQ_REPLAY_DETECT),
            (r.confidentiality, id::ISC_REQ_CONFIDENTIALITY),
            (r.allocate_memory, id::ISC_REQ_ALLOCATE_MEMORY),
            (r.use_http_style, id::ISC_REQ_USE_HTTP_STYLE),
        ] {
            if on {
                bits |= bit;
            }
        }
        bits
    }

    impl SspiContext for Context {
        fn initialize(
            &mut self,
            call: &Initialize<'_>,
            out: &mut Vec<u8>,
        ) -> Result<Initialized, SspiFailure> {
            use windows_sys::Win32::Security::Authentication::Identity as id;
            let target = tchar(call.target)?;
            let none = || sys::In {
                kind: 0,
                bytes: b"",
            };
            let mut input = [none(), none(), none()];
            assert!(call.input.len() <= input.len(), "at most three inputs");
            for (slot, i) in input.iter_mut().zip(call.input) {
                *slot = match *i {
                    Input::Token(b) => sys::In {
                        kind: sys::kind::TOKEN,
                        bytes: b,
                    },
                    Input::Params(b) => sys::In {
                        kind: sys::kind::PKG_PARAMS,
                        bytes: b,
                    },
                };
            }
            let room = match call.output {
                Output::Room(n) => Some(n),
                Output::Allocated => {
                    assert!(call.flags.allocate_memory, "SSPI allocates when asked to");
                    None
                }
            };
            let sys_call = sys::Call {
                fresh: call.fresh,
                target: &target,
                req: req(call.flags),
                native: call.native,
                input: &input[..call.input.len()],
                room,
            };
            let done = sys::initialize(&self.cred, &mut self.context, &sys_call, out)?;
            Ok(Initialized {
                status: status(done.status),
                confidentiality: done.attrs & id::ISC_RET_CONFIDENTIALITY != 0,
                integrity: done.attrs & id::ISC_RET_INTEGRITY != 0,
            })
        }

        fn complete(&mut self, token: &mut Vec<u8>) -> SecStatus {
            status(sys::complete(self.context.as_ref(), token))
        }

        fn make_signature(
            &mut self,
            method: &[u8],
            uri: &[u8],
            room: usize,
            out: &mut Vec<u8>,
        ) -> Result<(), SecStatus> {
            let context = self.context.as_ref().expect("a context is made");
            sys::make_signature(context, method, uri, room, out).map_err(status)
        }

        fn sizes(&mut self) -> Result<Sizes, SecStatus> {
            let context = self.context.as_ref().expect("a context is made");
            let (trailer, block) = sys::sizes(context).map_err(status)?;
            Ok(Sizes {
                trailer: usize::try_from(trailer).expect("a u32 fits"),
                block: usize::try_from(block).expect("a u32 fits"),
            })
        }

        fn wrap(
            &mut self,
            sizes: Sizes,
            message: &[u8],
            out: &mut Vec<u8>,
        ) -> Result<(), SspiFailure> {
            let context = self.context.as_ref().expect("a context is made");
            let n = |v: usize| u32::try_from(v).expect("sizes SSPI gave");
            sys::wrap(context, n(sizes.trailer), n(sizes.block), message, out).map_err(failed)
        }

        fn unwrap(&mut self, token: &[u8], out: &mut Vec<u8>) -> Result<(), SspiFailure> {
            let context = self.context.as_ref().expect("a context is made");
            sys::unwrap(context, token, out).map_err(failed)
        }

        /// In UTF-8 in the Unicode build, units that are no character
        /// read as U+FFFD, as `WideCharToMultiByte` reads them.
        fn user_name(&mut self, out: &mut Vec<u8>) -> Result<(), SspiFailure> {
            out.clear();
            match sys::user_name(&self.cred, curl_os::UNICODE).map_err(failed)? {
                sys::UserName::Ansi(bytes) => *out = bytes,
                sys::UserName::Wide(units) => {
                    let mut buf = [0; 4];
                    for c in char::decode_utf16(units) {
                        let c = c.unwrap_or(char::REPLACEMENT_CHARACTER);
                        out.try_extend_from_slice(c.encode_utf8(&mut buf).as_bytes())?;
                    }
                }
            }
            Ok(())
        }
    }

    fn failed(f: sys::Failed) -> SspiFailure {
        match f {
            sys::Failed::Status(s) => SspiFailure::Status(status(s)),
            sys::Failed::OutOfMemory => SspiFailure::OutOfMemory,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Text goes in the build's form, ended by a zero; in the Unicode
        /// build, text that is not UTF-8 does not convert.
        #[test]
        fn text_is_the_builds() {
            match (curl_os::UNICODE, tchar(b"HTTP/h\xc3\xa9").unwrap()) {
                (true, Text::Wide(w)) => {
                    assert_eq!(w, [72, 84, 84, 80, 47, 104, 0xe9, 0]);
                    assert!(tchar(b"\xe9").is_err());
                }
                (false, Text::Ansi(a)) => assert_eq!(a, b"HTTP/h\xc3\xa9\0"),
                (unicode, _) => panic!("not the text of a build with UNICODE {unicode}"),
            }
        }

        /// The packages are there, with the sizes their tokens take.
        #[test]
        fn packages_are_known() {
            for p in [Package::Negotiate, Package::Kerberos, Package::Digest] {
                assert!(SSPI.max_token(p).unwrap() > 0, "{p:?}");
            }
        }

        /// Digest makes a response to a challenge with the given user, as
        /// HTTP's Digest asks it, and signs the next request with the
        /// context, where the system's WDigest takes credentials given at
        /// all: Windows 11's refuses them (`SEC_E_UNKNOWN_CREDENTIALS`),
        /// for which C's build and Microsoft's curl.exe fail with 67 too,
        /// and the process's user's alike.
        #[test]
        fn digest_answers_a_challenge() {
            let room = SSPI.max_token(Package::Digest).unwrap();
            // The realm as the domain, as C sets it where the user names none.
            let identity = Identity::of(b"testrealm\\testuser", b"testpass");
            let mut ctx = match SSPI.credentials(Package::Digest, &identity) {
                Ok(ctx) => ctx,
                Err(SspiFailure::Status(s)) if s.code() == 0x8009_030d_u32 as i32 => return,
                Err(e) => panic!("{e:?}"),
            };
            let challenge = b"realm=\"testrealm\", nonce=\"1053604145\"";
            let input = [Input::Token(challenge), Input::Params(b"GET")];
            let call = Initialize {
                target: b"/1",
                flags: curl_core::sspi::Req {
                    use_http_style: true,
                    ..Default::default()
                },
                native: false,
                fresh: true,
                input: &input,
                output: Output::Room(room),
            };
            let mut out = Vec::new();
            let done = ctx.initialize(&call, &mut out).unwrap();
            assert!(!done.status.is_error(), "{:?}", done.status);
            let text = String::from_utf8(out).unwrap();
            assert!(text.contains("username=\"testuser\""), "{text}");
            assert!(text.contains("uri=\"/1\""), "{text}");
            let mut signed = Vec::new();
            ctx.make_signature(b"GET", b"/2", room, &mut signed)
                .unwrap();
            let text = String::from_utf8(signed).unwrap();
            assert!(text.contains("uri=\"/2\""), "{text}");
        }

        /// SPNEGO with NTLM allowed, for the process's user, makes a first
        /// token where no domain is (NTLM's own, as Microsoft's curl.exe
        /// 8.21.0 sends it); the same without NTLM is refused, below.
        #[test]
        fn negotiate_with_ntlm_makes_a_token() {
            let room = SSPI.max_token(Package::Negotiate).unwrap();
            let mut ctx = SSPI
                .credentials(Package::Negotiate, &Identity::Current)
                .unwrap();
            let call = Initialize {
                target: b"HTTP/127.0.0.1",
                flags: curl_core::sspi::Req {
                    confidentiality: true,
                    ..Default::default()
                },
                native: true,
                fresh: true,
                input: &[],
                output: Output::Room(room),
            };
            let mut out = Vec::new();
            let done = ctx.initialize(&call, &mut out).unwrap();
            assert_eq!(done.status, SecStatus::CONTINUE_NEEDED);
            assert!(out.len() <= room && !out.is_empty());
            assert!(out.starts_with(b"NTLMSSP\0\x01\0\0\0"), "{out:?}");
            // A peer's answer goes in as the token it is, and the context
            // answers it: NTLM's challenge, then its authentication.
            let mut challenge = Vec::new();
            challenge.extend_from_slice(b"NTLMSSP\0\x02\0\0\0");
            // No target name, at the payload's start.
            challenge.extend_from_slice(&[0, 0, 0, 0, 56, 0, 0, 0]);
            // Unicode, target, sign, seal, NTLM, always sign, a domain,
            // extended session security, target info, version, 128-bit,
            // key exchange, 56-bit.
            challenge.extend_from_slice(&0xe289_8235_u32.to_le_bytes());
            challenge.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            challenge.extend_from_slice(&[0; 8]);
            // The domain and the server by NetBIOS name, a time, the end.
            let info: &[u8] = b"\x02\0\x06\0D\0O\0M\0\x01\0\x02\0S\0\
                \x07\0\x08\0\0\x80\x3e\xd5\xde\xb1\x9d\x01\0\0\0\0";
            let len = info.len() as u8;
            challenge.extend_from_slice(&[len, 0, len, 0, 56, 0, 0, 0]);
            challenge.extend_from_slice(&[10, 0, 0x61, 0x4a, 0, 0, 0, 15]);
            challenge.extend_from_slice(info);
            let input = [Input::Token(&challenge)];
            let call = Initialize {
                fresh: false,
                input: &input,
                ..call
            };
            let done = ctx.initialize(&call, &mut out).unwrap();
            assert!(!done.status.is_error(), "{:#x}", done.status.code());
            assert!(out.starts_with(b"NTLMSSP\0\x03\0\0\0"), "{out:?}");
        }

        /// SPNEGO without NTLM, for the process's user, refuses a target
        /// no domain knows, and the refusal has C's words.
        #[test]
        fn negotiate_without_a_domain_is_refused() {
            let room = SSPI.max_token(Package::Negotiate).unwrap();
            let identity = Identity::Current.with_packages(b"!ntlm");
            let mut ctx = SSPI.credentials(Package::Negotiate, &identity).unwrap();
            let call = Initialize {
                target: b"HTTP/nowhere.invalid",
                flags: curl_core::sspi::Req {
                    confidentiality: true,
                    ..Default::default()
                },
                native: true,
                fresh: true,
                input: &[],
                output: Output::Room(room),
            };
            let mut out = Vec::new();
            let done = ctx.initialize(&call, &mut out).unwrap();
            let mut said = Vec::new();
            SSPI.describe(done.status, &mut |b| said.extend_from_slice(b));
            let said = String::from_utf8_lossy(&said);
            assert!(done.status.is_error(), "{said}");
            // C's words for it, on the same machine.
            assert_eq!(
                said,
                "SEC_E_NO_CREDENTIALS (0x8009030e) - No credentials are available in the security \
                 package"
            );
        }
    }
}
