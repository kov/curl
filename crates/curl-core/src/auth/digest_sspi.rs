//! HTTP Digest by SSPI's `WDigest` (`lib/vauth/digest_sspi.c`), which
//! a Windows build of C uses in place of its own: the challenge is kept
//! as the server sent it, and the package makes the response from it,
//! then signs each later request with the context it made.

use curl_alloc::{OutOfMemory, TryVec as _};

use super::creds::Secret;
use super::digest::{pair, skip_blanks};
use crate::sspi::{
    Completing, Identity, Initialize, Input, Output, Package, Req, SecStatus, Sspi, SspiContext,
    SspiFailure,
};

/// What is kept of Digest by SSPI (`struct digestdata`'s `input_token`
/// and `http_context`), with the SSPI it was read for.
#[derive(Debug)]
pub(crate) struct SspiDigest {
    pub(crate) sspi: &'static dyn Sspi,
    /// The challenge after `Digest` and its blanks, the rest of the line
    /// as it came; none after a challenge that could not be read.
    pub(crate) challenge: Option<Vec<u8>>,
    /// The context the first response was made with, which signs the
    /// next.
    context: Option<Box<dyn SspiContext>>,
}

impl SspiDigest {
    /// `challenge` read, for `sspi`, no context made yet.
    pub(crate) fn new(sspi: &'static dyn Sspi, challenge: Option<Vec<u8>>) -> SspiDigest {
        SspiDigest {
            sspi,
            challenge,
            context: None,
        }
    }

    /// A challenge to answer.
    pub(crate) fn has_challenge(&self) -> bool {
        self.challenge.is_some()
    }
}

/// A challenge, after `Digest` and its blanks, read where one was kept
/// before if `had` (`Curl_auth_decode_digest_http_message`): another
/// after one means the credentials were refused, unless the server calls
/// the nonce stale. `None` for a refusal, which leaves what was kept as
/// it was.
pub(crate) fn decode(challenge: &[u8], had: bool) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if had && !stale(challenge)? {
        return Ok(None);
    }
    let mut kept = Vec::new();
    kept.try_extend_from_slice(challenge)?;
    Ok(Some(kept))
}

/// The challenge says `stale=true`, in any case.
fn stale(mut s: &[u8]) -> Result<bool, OutOfMemory> {
    loop {
        s = skip_blanks(s);
        let Some((name, content, rest)) = pair(s)? else {
            return Ok(false);
        };
        if name.eq_ignore_ascii_case(b"stale") && content.eq_ignore_ascii_case(b"true") {
            return Ok(true);
        }
        s = skip_blanks(rest);
        if s.first() == Some(&b',') {
            s = &s[1..];
        }
    }
}

/// The last `realm` the challenge names (`Curl_override_sspi_http_realm`),
/// the domain the credentials go in where the user names none.
fn realm(mut s: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    let mut realm = None;
    loop {
        s = skip_blanks(s);
        let Some((name, content, rest)) = pair(s)? else {
            return Ok(realm);
        };
        if name.eq_ignore_ascii_case(b"realm") {
            realm = Some(content);
        }
        s = skip_blanks(rest);
        if s.first() == Some(&b',') {
            s = &s[1..];
        }
    }
}

/// Why no response was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    OutOfMemory,
    /// The package's credentials were refused (`CURLE_LOGIN_DENIED`).
    LoginDenied,
    /// The package failed otherwise (`CURLE_AUTH_ERROR`).
    AuthError,
}

impl From<OutOfMemory> for Refused {
    fn from(_: OutOfMemory) -> Self {
        Refused::OutOfMemory
    }
}

/// What C says along the way: an `infof`, or a `failf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SspiDigestNote {
    /// "SSPI: could not get auth info" (`failf`).
    NoAuthInfo,
    /// "digest_sspi: MakeSignature failed, error 0x%08lx".
    MakeSignature(SecStatus),
    /// "schannel: InitializeSecurityContext failed: <text>".
    Initialize(SecStatus),
}

/// The `Authorization: Digest` value answering what `state` keeps, for a
/// request with `method` to `uri`, as `credentials` (the process's user
/// where they name none) (`Curl_auth_create_digest_http_message`): the
/// context kept signs it, or one is made, the challenge's realm the
/// domain where the user names none. Notes go to `note` as they come.
pub(crate) fn respond(
    state: &mut SspiDigest,
    credentials: Secret<'_>,
    method: &[u8],
    uri: &[u8],
    note: &mut dyn FnMut(SspiDigestNote),
) -> Result<Vec<u8>, Refused> {
    let sspi = state.sspi;
    let Ok(room) = sspi.max_token(Package::Digest) else {
        note(SspiDigestNote::NoAuthInfo);
        return Err(Refused::AuthError);
    };
    let mut out = Vec::new();
    if let Some(context) = state.context.as_mut() {
        match context.make_signature(method, uri, room, &mut out) {
            Ok(()) => return Ok(out),
            Err(status) => {
                // A new context is made in its place.
                note(SspiDigestNote::MakeSignature(status));
                state.context = None;
            }
        }
    }
    let challenge = state.challenge.as_deref().unwrap_or_default();
    let realm = realm(challenge)?;
    let identity = if credentials.user().is_empty() {
        Identity::Current
    } else {
        match Identity::of(credentials.user(), credentials.password()) {
            Identity::Given {
                user,
                domain: b"",
                password,
                packages,
            } if realm.is_some() => Identity::Given {
                user,
                domain: realm.as_deref().unwrap_or_default(),
                password,
                packages,
            },
            identity => identity,
        }
    };
    let mut context = match sspi.credentials(Package::Digest, &identity) {
        Ok(context) => context,
        Err(SspiFailure::OutOfMemory) => return Err(Refused::OutOfMemory),
        Err(SspiFailure::Status(_)) => return Err(Refused::LoginDenied),
    };
    let input = [
        Input::Token(challenge),
        Input::Params(method),
        Input::Params(b""),
    ];
    let call = Initialize {
        // The URI is the target (`spn`).
        target: uri,
        flags: Req {
            use_http_style: true,
            ..Req::default()
        },
        native: false,
        fresh: true,
        input: &input,
        output: Output::Room(room),
    };
    let status = match context.initialize(&call, &mut out) {
        Ok(initialized) => initialized.status,
        Err(SspiFailure::OutOfMemory) => return Err(Refused::OutOfMemory),
        Err(SspiFailure::Status(status)) => status,
    };
    if status.wants_completion() {
        // C hands the credentials' handle where the context's belongs, and
        // reads nothing of the answer: the token goes as SSPI leaves it.
        let _unread: SecStatus = context.complete(Completing::Credentials, &mut out);
    } else if status != SecStatus::OK && status != SecStatus::CONTINUE_NEEDED {
        if status == SecStatus::INSUFFICIENT_MEMORY {
            return Err(Refused::OutOfMemory);
        }
        note(SspiDigestNote::Initialize(status));
        return Err(Refused::AuthError);
    }
    state.context = Some(context);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sspi::Initialized;
    use crate::sspi::testing::{Answer, Asked, Scripted};

    #[test]
    fn a_challenge_after_one_is_a_refusal_unless_stale() {
        assert_eq!(
            decode(b"realm=\"r\", nonce=\"1\"", false).unwrap(),
            Some(b"realm=\"r\", nonce=\"1\"".to_vec())
        );
        assert_eq!(decode(b"realm=\"r\", nonce=\"2\"", true).unwrap(), None);
        for stale in [
            &b"nonce=\"2\", stale=true"[..],
            b"stale=\"TRUE\"",
            b"  stale=True,nonce=3",
        ] {
            assert!(decode(stale, true).unwrap().is_some(), "{stale:?}");
        }
        assert_eq!(decode(b"stale=false", true).unwrap(), None);
        // A pair that does not read ends the search.
        assert_eq!(decode(b"x, stale=true", true).unwrap(), None);
    }

    #[test]
    fn the_last_realm_is_the_domain() {
        assert_eq!(realm(b"realm=\"a\", nonce=1").unwrap(), Some(b"a".to_vec()));
        assert_eq!(realm(b"realm=a, realm=\"b\"").unwrap(), Some(b"b".to_vec()));
        assert_eq!(realm(b"nonce=1").unwrap(), None);
    }

    fn made(status: SecStatus, token: &[u8]) -> Answer {
        Answer::Initialized(Ok((
            Initialized {
                status,
                confidentiality: false,
                integrity: false,
            },
            token.to_vec(),
        )))
    }

    /// The first response is the package's to a context made with the
    /// challenge, the realm the domain; the next is signed with that
    /// context, and one it cannot sign makes a new context.
    #[test]
    fn a_context_is_made_then_signs() {
        let sspi = Scripted::leaked();
        let mut state = SspiDigest {
            sspi,
            challenge: Some(b"realm=\"r\", nonce=\"1\"".to_vec()),
            context: None,
        };
        let creds = Secret::new(b"user", b"pw", b"");
        let mut notes = Vec::new();
        sspi.then(Answer::MaxToken(Ok(64)))
            .then(Answer::Credentials(Ok(())))
            .then(made(SecStatus::OK, b"first"));
        let first = respond(&mut state, creds, b"GET", b"/1", &mut |n| notes.push(n));
        assert_eq!(first, Ok(b"first".to_vec()));
        assert_eq!(
            sspi.asked(),
            [
                Asked::MaxToken(Package::Digest),
                Asked::Credentials(
                    Package::Digest,
                    Some([b"user".to_vec(), b"r".to_vec(), b"pw".to_vec(), Vec::new()])
                ),
                Asked::Initialize {
                    target: b"/1".to_vec(),
                    flags: Req {
                        use_http_style: true,
                        ..Req::default()
                    },
                    native: false,
                    fresh: true,
                    input: vec![
                        (b'T', b"realm=\"r\", nonce=\"1\"".to_vec()),
                        (b'P', b"GET".to_vec()),
                        (b'P', Vec::new())
                    ],
                    output: Output::Room(64),
                },
            ]
        );
        sspi.then(Answer::MaxToken(Ok(64)))
            .then(Answer::Signed(Ok(b"second".to_vec())));
        let second = respond(&mut state, creds, b"POST", b"/2", &mut |n| notes.push(n));
        assert_eq!(second, Ok(b"second".to_vec()));
        assert_eq!(
            sspi.asked()[1],
            Asked::MakeSignature {
                method: b"POST".to_vec(),
                uri: b"/2".to_vec(),
                room: 64
            }
        );
        let refused = SecStatus::new(0x8009_0301_u32 as i32);
        sspi.then(Answer::MaxToken(Ok(64)))
            .then(Answer::Signed(Err(refused)))
            .then(Answer::Credentials(Ok(())))
            .then(made(SecStatus::CONTINUE_NEEDED, b"third"));
        let third = respond(&mut state, creds, b"GET", b"/3", &mut |n| notes.push(n));
        assert_eq!(third, Ok(b"third".to_vec()));
        assert_eq!(notes, [SspiDigestNote::MakeSignature(refused)]);
        assert_eq!(sspi.asked()[2], Asked::Dropped, "the old context deleted");
        assert_eq!(sspi.unused(), 0);
    }

    /// A token SSPI says wants completing is completed as C completes it,
    /// with the credentials' handle, whatever that answers.
    #[test]
    fn a_token_wanting_completion_is_completed_with_the_credentials() {
        let sspi = Scripted::leaked();
        let creds = Secret::new(b"u", b"p", b"");
        for status in [SecStatus::COMPLETE_NEEDED, SecStatus::COMPLETE_AND_CONTINUE] {
            let mut state = SspiDigest {
                sspi,
                challenge: Some(b"realm=\"r\"".to_vec()),
                context: None,
            };
            let invalid_handle = SecStatus::new(0x8009_0301_u32 as i32);
            sspi.then(Answer::MaxToken(Ok(8)))
                .then(Answer::Credentials(Ok(())))
                .then(made(status, b"made"))
                .then(Answer::Completed(invalid_handle));
            let r = respond(&mut state, creds, b"GET", b"/", &mut |_| {});
            assert_eq!(r, Ok(b"made".to_vec()));
            assert_eq!(
                sspi.asked()[3],
                Asked::Complete(Completing::Credentials, b"made".to_vec())
            );
            assert!(state.context.is_some());
            drop(state);
            assert_eq!(sspi.asked(), [Asked::Dropped]);
        }
        assert_eq!(sspi.unused(), 0);
    }

    /// A user naming its domain keeps it; no user is the process's.
    #[test]
    fn the_identity_is_the_user_s_or_the_process_s() {
        let sspi = Scripted::leaked();
        for (user, want) in [
            (
                &b"dom\\u"[..],
                Asked::Credentials(
                    Package::Digest,
                    Some([b"u".to_vec(), b"dom".to_vec(), b"pw".to_vec(), Vec::new()]),
                ),
            ),
            (b"", Asked::Credentials(Package::Digest, None)),
        ] {
            let mut state = SspiDigest {
                sspi,
                challenge: Some(b"realm=\"r\"".to_vec()),
                context: None,
            };
            sspi.then(Answer::MaxToken(Ok(8)))
                .then(Answer::Credentials(Ok(())))
                .then(made(SecStatus::OK, b"t"));
            let creds = Secret::new(user, b"pw", b"");
            respond(&mut state, creds, b"GET", b"/", &mut |_| {}).unwrap();
            drop(state);
            assert_eq!(sspi.asked()[1], want);
        }
    }

    /// Credentials refused are a login denied, unsaid; the package
    /// unknown or a context refused are an error, said.
    #[test]
    fn refusals_are_c_s() {
        let sspi = Scripted::leaked();
        let creds = Secret::new(b"u", b"p", b"");
        let mut state = SspiDigest {
            sspi,
            challenge: Some(Vec::new()),
            context: None,
        };
        let mut notes = Vec::new();
        let refused = SecStatus::new(0x8009_030d_u32 as i32);
        sspi.then(Answer::MaxToken(Ok(8)))
            .then(Answer::Credentials(Err(SspiFailure::Status(refused))));
        let r = respond(&mut state, creds, b"GET", b"/", &mut |n| notes.push(n));
        assert_eq!(r, Err(Refused::LoginDenied));
        assert!(notes.is_empty());
        sspi.then(Answer::MaxToken(Err(refused)));
        let r = respond(&mut state, creds, b"GET", b"/", &mut |n| notes.push(n));
        assert_eq!(r, Err(Refused::AuthError));
        assert_eq!(notes, [SspiDigestNote::NoAuthInfo]);
        notes.clear();
        sspi.then(Answer::MaxToken(Ok(8)))
            .then(Answer::Credentials(Ok(())))
            .then(made(refused, b""));
        let r = respond(&mut state, creds, b"GET", b"/", &mut |n| notes.push(n));
        assert_eq!(r, Err(Refused::AuthError));
        assert_eq!(notes, [SspiDigestNote::Initialize(refused)]);
        assert!(state.context.is_none());
        sspi.then(Answer::MaxToken(Ok(8)))
            .then(Answer::Credentials(Ok(())))
            .then(made(SecStatus::INSUFFICIENT_MEMORY, b""));
        let r = respond(&mut state, creds, b"GET", b"/", &mut |n| notes.push(n));
        assert_eq!(r, Err(Refused::OutOfMemory));
    }
}
