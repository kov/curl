//! What Windows' SSPI does for the core (C's `Curl_pSecFn` and
//! `lib/curl_sspi.c`): credentials of a security package, for the
//! process's user or for one named, and security contexts made with
//! them, for HTTP's Negotiate and Digest, SASL's DIGEST-MD5 and SOCKS5's
//! GSS-API method, as a C build with `USE_WINDOWS_SSPI` routes them. The
//! core links no library; whoever builds a handle names this one in its
//! `Libraries` in place of a GSS-API library.
//!
//! What C decides with the library's answers (which call comes next,
//! what is said, which error a status is) the core decides; the calls
//! and their buffers are the library's. A status passes through the core
//! as the number SSPI gave, which only the library has words for.

use std::fmt;

use curl_alloc::OutOfMemory;

/// SSPI.
pub trait Sspi: Send + Sync {
    /// The largest token `package` makes (`QuerySecurityPackageInfo`'s
    /// `cbMaxToken`), or the status it was refused with.
    fn max_token(&self, package: Package) -> Result<usize, SecStatus>;

    /// Outbound credentials of `package` (`AcquireCredentialsHandle`), as
    /// `identity` says, with no context yet.
    fn credentials(
        &self,
        package: Package,
        identity: &Identity<'_>,
    ) -> Result<Box<dyn SspiContext>, SspiFailure>;

    /// What C says of `status` (`Curl_sspi_strerror`): its name, its code
    /// and the system's words for it, handed to `out`.
    fn describe(&self, status: SecStatus, out: &mut dyn FnMut(&[u8]));
}

impl fmt::Debug for dyn Sspi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sspi")
    }
}

/// A credential handle and the security context made with it, if one
/// is; both released when it is dropped (`DeleteSecurityContext`,
/// `FreeCredentialsHandle`).
pub trait SspiContext: Send {
    /// `InitializeSecurityContext` as `call` says, the token made put
    /// in `out` (emptied first).
    fn initialize(
        &mut self,
        call: &Initialize<'_>,
        out: &mut Vec<u8>,
    ) -> Result<Initialized, SspiFailure>;

    /// `CompleteAuthToken` over `token`, the token the last `initialize`
    /// made, which it may change; handed the handle `with` names.
    fn complete(&mut self, with: Completing, token: &mut Vec<u8>) -> SecStatus;

    /// `MakeSignature` on the context with Digest's parameters (the
    /// method and the URI), in a room of `room` bytes: the response it
    /// signs into `out` (emptied first), or the status.
    fn make_signature(
        &mut self,
        method: &[u8],
        uri: &[u8],
        room: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), SecStatus>;

    /// The context's sizes (`SECPKG_ATTR_SIZES`).
    fn sizes(&mut self) -> Result<Sizes, SecStatus>;

    /// `message` protected for the peer without encryption
    /// (`EncryptMessage` with `KERB_WRAP_NO_ENCRYPT`), the token, the
    /// message and the padding laid end to end in `out` (emptied first);
    /// `sizes` are the context's.
    fn wrap(&mut self, sizes: Sizes, message: &[u8], out: &mut Vec<u8>) -> Result<(), SspiFailure>;

    /// The message `token` protects (`DecryptMessage` of a stream),
    /// into `out` (emptied first).
    fn unwrap(&mut self, token: &[u8], out: &mut Vec<u8>) -> Result<(), SspiFailure>;

    /// The name of the credentials' user (`QueryCredentialsAttributes`,
    /// `SECPKG_CRED_ATTR_NAMES`), in the build's text, into `out`
    /// (emptied first).
    fn user_name(&mut self, out: &mut Vec<u8>) -> Result<(), SspiFailure>;
}

impl fmt::Debug for dyn SspiContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SspiContext")
    }
}

/// The handle `CompleteAuthToken` is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completing {
    /// The context's, as SPNEGO hands it (`spnego_sspi.c`).
    Context,
    /// The credentials', where the context's belongs, as Digest hands
    /// it (`digest_sspi.c`).
    Credentials,
}

/// A security package, as C names it (`SP_NAME_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Package {
    /// `Negotiate`: SPNEGO.
    Negotiate,
    /// `Kerberos`.
    Kerberos,
    /// `WDigest`.
    Digest,
}

/// Whose credentials (`SEC_WINNT_AUTH_IDENTITY_EX`, or none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity<'a> {
    /// The process's user, with no identity given.
    Current,
    /// The process's user, with an identity naming nothing but the
    /// packages it may use (`PackageList`).
    Packages(&'a [u8]),
    /// The given user, in the domain given, with the packages `packages`
    /// names, if it names any.
    Given {
        user: &'a [u8],
        domain: &'a [u8],
        password: &'a [u8],
        packages: &'a [u8],
    },
}

impl<'a> Identity<'a> {
    /// The identity for `user` and `password` (`Curl_create_sspi_identity`):
    /// the domain is what comes before the user's first `\`, or else its
    /// first `/`, and the user what follows.
    pub fn of(user: &'a [u8], password: &'a [u8]) -> Identity<'a> {
        let at = user
            .iter()
            .position(|&b| b == b'\\')
            .or_else(|| user.iter().position(|&b| b == b'/'));
        let (domain, user) = match at {
            Some(at) => (&user[..at], &user[at + 1..]),
            None => (&b""[..], user),
        };
        Identity::Given {
            user,
            domain,
            password,
            packages: b"",
        }
    }

    /// The identity, limited to the packages `list` names.
    pub fn with_packages(self, list: &'a [u8]) -> Identity<'a> {
        match self {
            Identity::Current | Identity::Packages(_) => Identity::Packages(list),
            Identity::Given {
                user,
                domain,
                password,
                ..
            } => Identity::Given {
                user,
                domain,
                password,
                packages: list,
            },
        }
    }
}

/// One `InitializeSecurityContext` call.
#[derive(Clone, Copy, Debug)]
pub struct Initialize<'a> {
    /// The target's name (UTF-8, or the ANSI code page's bytes in a
    /// build without Unicode, as C's `TCHAR` text has it).
    pub target: &'a [u8],
    /// The context requirements (`fContextReq`).
    pub flags: Req,
    /// The data is in the machine's representation
    /// (`SECURITY_NATIVE_DREP`), as Negotiate and SOCKS5 say; Digest
    /// says nothing.
    pub native: bool,
    /// The call goes on with the context the last made, or makes a new
    /// one in its place.
    pub fresh: bool,
    /// The input buffers, in order; none passes no input at all. C would
    /// add the TLS channel's bindings (`SECBUFFER_CHANNEL_BINDINGS`) to
    /// SPNEGO's from `conn->sslContext`, which nothing in C sets: none
    /// are passed, as C passes none.
    pub input: &'a [Input<'a>],
    /// Where the output token goes.
    pub output: Output,
}

/// An input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input<'a> {
    /// `SECBUFFER_TOKEN`.
    Token(&'a [u8]),
    /// `SECBUFFER_PKG_PARAMS`.
    Params(&'a [u8]),
}

/// Where a call's output token goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    /// A buffer of this many bytes, the caller's.
    Room(usize),
    /// A buffer the library allocates (`ISC_REQ_ALLOCATE_MEMORY`).
    Allocated,
}

/// Context requirements (`ISC_REQ_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Req {
    pub delegate: bool,
    pub mutual_auth: bool,
    pub replay_detect: bool,
    pub confidentiality: bool,
    pub allocate_memory: bool,
    pub use_http_style: bool,
}

/// What a call that was not refused outright gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Initialized {
    /// The call's status, a success or not.
    pub status: SecStatus,
    /// The context can keep messages secret (`ISC_RET_CONFIDENTIALITY`).
    pub confidentiality: bool,
    /// The context can keep messages whole (`ISC_RET_INTEGRITY`).
    pub integrity: bool,
}

/// A context's sizes (`SecPkgContext_Sizes`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizes {
    /// `cbSecurityTrailer`.
    pub trailer: usize,
    /// `cbBlockSize`.
    pub block: usize,
}

/// Why a call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SspiFailure {
    /// SSPI said no.
    Status(SecStatus),
    /// No memory, or text that does not convert to the build's (C's
    /// `curlx_convert_UTF8_to_tchar` failing).
    OutOfMemory,
}

impl From<OutOfMemory> for SspiFailure {
    fn from(_: OutOfMemory) -> Self {
        SspiFailure::OutOfMemory
    }
}

/// A status SSPI answered with (`SECURITY_STATUS`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecStatus(i32);

impl SecStatus {
    /// `SEC_E_OK`.
    pub const OK: SecStatus = SecStatus(0);
    /// `SEC_I_CONTINUE_NEEDED`.
    pub const CONTINUE_NEEDED: SecStatus = SecStatus(0x0009_0312);
    /// `SEC_I_COMPLETE_NEEDED`.
    pub const COMPLETE_NEEDED: SecStatus = SecStatus(0x0009_0313);
    /// `SEC_I_COMPLETE_AND_CONTINUE`.
    pub const COMPLETE_AND_CONTINUE: SecStatus = SecStatus(0x0009_0314);
    /// `SEC_E_INSUFFICIENT_MEMORY`.
    pub const INSUFFICIENT_MEMORY: SecStatus = SecStatus(0x8009_0300_u32 as i32);

    /// For the library: the status it returned.
    pub const fn new(code: i32) -> SecStatus {
        SecStatus(code)
    }

    /// The status's number.
    pub fn code(self) -> i32 {
        self.0
    }

    /// An error, not a success nor a note (C's `GSS_ERROR`, the top bit).
    pub fn is_error(self) -> bool {
        self.0 < 0
    }

    /// `CompleteAuthToken` is to be called (`SEC_I_COMPLETE_NEEDED`,
    /// `SEC_I_COMPLETE_AND_CONTINUE`).
    pub fn wants_completion(self) -> bool {
        self == SecStatus::COMPLETE_NEEDED || self == SecStatus::COMPLETE_AND_CONTINUE
    }
}

impl fmt::Debug for SecStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecStatus({:#010x})", self.0)
    }
}

/// An SSPI whose calls are scripted, for the core's tests: each call
/// answers with the next answer given it, and what was asked of it is
/// kept to be read back.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// What a scripted call answers.
    #[derive(Clone, Debug)]
    pub(crate) enum Answer {
        /// `max_token` gives this.
        MaxToken(Result<usize, SecStatus>),
        /// `credentials` succeeds, or fails.
        Credentials(Result<(), SspiFailure>),
        /// `initialize` makes `token` and gives this, or fails.
        Initialized(Result<(Initialized, Vec<u8>), SspiFailure>),
        /// `complete` gives this.
        Completed(SecStatus),
        /// `make_signature` makes this, or fails.
        Signed(Result<Vec<u8>, SecStatus>),
        /// `sizes` gives this.
        Sizes(Result<Sizes, SecStatus>),
        /// `wrap` makes this, or fails.
        Wrapped(Result<Vec<u8>, SspiFailure>),
        /// `unwrap` finds this, or fails.
        Unwrapped(Result<Vec<u8>, SspiFailure>),
        /// `user_name` names this, or fails.
        User(Result<Vec<u8>, SspiFailure>),
    }

    /// Something asked of the library, in order.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum Asked {
        MaxToken(Package),
        /// Credentials, for this identity: user, domain, password and
        /// packages, or none for the process's user.
        Credentials(Package, Option<[Vec<u8>; 4]>),
        /// Credentials for the process's user, limited to these packages.
        CredentialsLimited(Package, Vec<u8>),
        Initialize {
            target: Vec<u8>,
            flags: Req,
            native: bool,
            fresh: bool,
            input: Vec<(u8, Vec<u8>)>,
            output: Output,
        },
        Complete(Completing, Vec<u8>),
        MakeSignature {
            method: Vec<u8>,
            uri: Vec<u8>,
            room: usize,
        },
        Sizes,
        Wrap(Vec<u8>),
        Unwrap(Vec<u8>),
        UserName,
        Dropped,
    }

    #[derive(Debug, Default)]
    struct Script {
        answers: VecDeque<Answer>,
        asked: Vec<Asked>,
    }

    /// The library.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct Scripted(Arc<Mutex<Script>>);

    impl Scripted {
        /// A library made for a test, and kept to its end.
        pub(crate) fn leaked() -> &'static Scripted {
            Box::leak(Box::new(Scripted::default()))
        }

        /// The next call answers `answer`.
        pub(crate) fn then(&self, answer: Answer) -> &Self {
            self.0.lock().unwrap().answers.push_back(answer);
            self
        }

        /// What was asked of it so far, taken.
        pub(crate) fn asked(&self) -> Vec<Asked> {
            std::mem::take(&mut self.0.lock().unwrap().asked)
        }

        /// The answers given and not yet used.
        pub(crate) fn unused(&self) -> usize {
            self.0.lock().unwrap().answers.len()
        }

        fn next(&self, asked: Asked) -> Answer {
            let mut script = self.0.lock().unwrap();
            script.asked.push(asked.clone());
            script
                .answers
                .pop_front()
                .unwrap_or_else(|| panic!("an answer scripted for {asked:?}"))
        }
    }

    impl Sspi for Scripted {
        fn max_token(&self, package: Package) -> Result<usize, SecStatus> {
            match self.next(Asked::MaxToken(package)) {
                Answer::MaxToken(answer) => answer,
                other => panic!("a max token scripted, not {other:?}"),
            }
        }

        fn credentials(
            &self,
            package: Package,
            identity: &Identity<'_>,
        ) -> Result<Box<dyn SspiContext>, SspiFailure> {
            let asked = match *identity {
                Identity::Current => Asked::Credentials(package, None),
                Identity::Packages(list) => Asked::CredentialsLimited(package, list.to_vec()),
                Identity::Given {
                    user,
                    domain,
                    password,
                    packages,
                } => Asked::Credentials(
                    package,
                    Some([
                        user.to_vec(),
                        domain.to_vec(),
                        password.to_vec(),
                        packages.to_vec(),
                    ]),
                ),
            };
            match self.next(asked) {
                Answer::Credentials(answer) => {
                    answer.map(|()| Box::new(Context(self.clone())) as Box<dyn SspiContext>)
                }
                other => panic!("credentials scripted, not {other:?}"),
            }
        }

        /// `status 0x...` for any status.
        fn describe(&self, status: SecStatus, out: &mut dyn FnMut(&[u8])) {
            out(format!("status {:#010x}", status.code()).as_bytes());
        }
    }

    struct Context(Scripted);

    impl Drop for Context {
        fn drop(&mut self) {
            self.0.0.lock().unwrap().asked.push(Asked::Dropped);
        }
    }

    fn put(out: &mut Vec<u8>, bytes: &[u8]) {
        out.clear();
        out.extend_from_slice(bytes);
    }

    impl SspiContext for Context {
        fn initialize(
            &mut self,
            call: &Initialize<'_>,
            out: &mut Vec<u8>,
        ) -> Result<Initialized, SspiFailure> {
            let input = call
                .input
                .iter()
                .map(|i| match *i {
                    Input::Token(b) => (b'T', b.to_vec()),
                    Input::Params(b) => (b'P', b.to_vec()),
                })
                .collect();
            let asked = Asked::Initialize {
                target: call.target.to_vec(),
                flags: call.flags,
                native: call.native,
                fresh: call.fresh,
                input,
                output: call.output,
            };
            match self.0.next(asked) {
                Answer::Initialized(answer) => answer.map(|(initialized, token)| {
                    put(out, &token);
                    initialized
                }),
                other => panic!("an initialize scripted, not {other:?}"),
            }
        }

        fn complete(&mut self, with: Completing, token: &mut Vec<u8>) -> SecStatus {
            match self.0.next(Asked::Complete(with, token.clone())) {
                Answer::Completed(status) => status,
                other => panic!("a completion scripted, not {other:?}"),
            }
        }

        fn make_signature(
            &mut self,
            method: &[u8],
            uri: &[u8],
            room: usize,
            out: &mut Vec<u8>,
        ) -> Result<(), SecStatus> {
            let asked = Asked::MakeSignature {
                method: method.to_vec(),
                uri: uri.to_vec(),
                room,
            };
            match self.0.next(asked) {
                Answer::Signed(answer) => answer.map(|token| put(out, &token)),
                other => panic!("a signature scripted, not {other:?}"),
            }
        }

        fn sizes(&mut self) -> Result<Sizes, SecStatus> {
            match self.0.next(Asked::Sizes) {
                Answer::Sizes(answer) => answer,
                other => panic!("sizes scripted, not {other:?}"),
            }
        }

        fn wrap(&mut self, _: Sizes, message: &[u8], out: &mut Vec<u8>) -> Result<(), SspiFailure> {
            match self.0.next(Asked::Wrap(message.to_vec())) {
                Answer::Wrapped(answer) => answer.map(|token| put(out, &token)),
                other => panic!("a wrap scripted, not {other:?}"),
            }
        }

        fn unwrap(&mut self, token: &[u8], out: &mut Vec<u8>) -> Result<(), SspiFailure> {
            match self.0.next(Asked::Unwrap(token.to_vec())) {
                Answer::Unwrapped(answer) => answer.map(|message| put(out, &message)),
                other => panic!("an unwrap scripted, not {other:?}"),
            }
        }

        fn user_name(&mut self, out: &mut Vec<u8>) -> Result<(), SspiFailure> {
            match self.0.next(Asked::UserName) {
                Answer::User(answer) => answer.map(|user| put(out, &user)),
                other => panic!("a user name scripted, not {other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The domain is what comes before the user's first `\`, else its
    /// first `/`, as C splits it.
    #[test]
    fn identity_splits_the_domain_as_c_does() {
        let given = |user: &'static [u8], domain: &'static [u8]| Identity::Given {
            user,
            domain,
            password: b"pw",
            packages: b"",
        };
        assert_eq!(Identity::of(b"user", b"pw"), given(b"user", b""));
        assert_eq!(Identity::of(b"dom\\user", b"pw"), given(b"user", b"dom"));
        assert_eq!(Identity::of(b"dom/user", b"pw"), given(b"user", b"dom"));
        assert_eq!(Identity::of(b"a/b\\c", b"pw"), given(b"c", b"a/b"));
        assert_eq!(Identity::of(b"a\\b/c", b"pw"), given(b"b/c", b"a"));
        assert_eq!(Identity::of(b"\\user", b"pw"), given(b"user", b""));
        assert_eq!(
            Identity::of(b"", b""),
            Identity::Given {
                user: b"",
                domain: b"",
                password: b"",
                packages: b"",
            }
        );
    }

    #[test]
    fn statuses_say_what_c_tells_apart() {
        assert!(SecStatus::INSUFFICIENT_MEMORY.is_error());
        assert!(!SecStatus::CONTINUE_NEEDED.is_error());
        assert!(!SecStatus::OK.is_error());
        assert!(SecStatus::COMPLETE_NEEDED.wants_completion());
        assert!(SecStatus::COMPLETE_AND_CONTINUE.wants_completion());
        assert!(!SecStatus::CONTINUE_NEEDED.wants_completion());
        assert_eq!(SecStatus::new(-1).code(), -1);
    }
}
