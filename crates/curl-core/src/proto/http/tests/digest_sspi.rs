//! HTTP Digest over a scripted SSPI, as C's Windows build makes it
//! (`lib/vauth/digest_sspi.c` under `lib/http_digest.c`): the challenge
//! handed to the package as it came, the response the package's, the
//! next request signed with the context, and the refusals said as C says
//! them.

use super::*;
use crate::libraries::{Libraries, Security, SharedLibraries};
use crate::options::HttpAuth;
use crate::sspi::testing::{Answer, Asked, Scripted};
use crate::sspi::{Initialized, Package, SecStatus, SspiFailure};

fn scripted() -> (&'static Scripted, SharedLibraries) {
    let sspi = Scripted::leaked();
    let libraries = SharedLibraries::new(Libraries {
        security: Some(Security::Sspi(sspi)),
        ..Libraries::NONE
    })
    .unwrap();
    (sspi, libraries)
}

fn digesting(libraries: &SharedLibraries) -> Easy {
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    e
}

fn as_user(o: &mut Options) {
    *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
    o.http.auth = HttpAuth(AuthMethods::DIGEST);
}

fn made(token: &[u8]) -> Answer {
    Answer::Initialized(Ok((
        Initialized {
            status: SecStatus::OK,
            confidentiality: false,
            integrity: false,
        },
        token.to_vec(),
    )))
}

const CHALLENGE: &[u8] = b"HTTP/1.1 401 Who\r\n\
    WWW-Authenticate: Digest realm=\"r\", nonce=\"n\", Basic\r\nContent-Length: 0\r\n\r\n";

fn answered(path: &str, token: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nAuthorization: Digest {token}\r\n\
         User-Agent: curl/test\r\nAccept: */*\r\n\r\n"
    )
}

/// The challenge goes to the package as it came, the rest of the line
/// with it, and the response is the package's, made with the realm as
/// the domain; the next transfer is signed with the context.
#[test]
fn the_response_is_the_package_s() {
    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(32)))
        .then(Answer::Credentials(Ok(())))
        .then(made(b"made"));
    let (mut m, talk, _) = server(&[CHALLENGE, OK], false);
    let mut e = digesting(&libraries);
    as_user(e.options_mut());
    let ran = get_with(&mut m, e, "/a", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(text.ends_with(&answered("/a", "made")), "{text}");
    let asked = sspi.asked();
    assert_eq!(
        asked[1],
        Asked::Credentials(
            Package::Digest,
            Some([b"u".to_vec(), b"r".to_vec(), b"p".to_vec(), Vec::new()])
        )
    );
    let Asked::Initialize { target, input, .. } = &asked[2] else {
        panic!("{asked:?}");
    };
    assert_eq!(target, b"/a");
    assert_eq!(
        input[0],
        (b'T', b"realm=\"r\", nonce=\"n\", Basic".to_vec())
    );
    assert_eq!(input[1], (b'P', b"GET".to_vec()));
}

/// A second challenge not called stale is a refusal, said, which leaves
/// the 401; credentials the package refuses fail the transfer with
/// `CURLE_LOGIN_DENIED`, unsaid, as Windows 11's WDigest has C's build
/// fail.
#[test]
fn refusals_end_as_c_s() {
    let again = b"HTTP/1.1 401 No\r\nWWW-Authenticate: Digest realm=\"r\", nonce=\"m\"\r\n\
        Content-Length: 3\r\n\r\nno\n";
    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(32)))
        .then(Answer::Credentials(Ok(())))
        .then(made(b"made"));
    let (mut m, talk, _) = server(&[CHALLENGE, again], false);
    let mut e = digesting(&libraries);
    as_user(e.options_mut());
    let ran = get_with(&mut m, e, "/a", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"no\n");
    assert!(
        ran.seen
            .text()
            .contains(&"Digest authentication problem, ignoring.\n".to_string())
    );

    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(32)))
        .then(Answer::Credentials(Err(SspiFailure::Status(
            SecStatus::new(0x8009_030d_u32 as i32),
        ))));
    let (mut m, talk, _) = server(&[CHALLENGE], false);
    let mut e = digesting(&libraries);
    as_user(e.options_mut());
    let ran = get_with(&mut m, e, "/a", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::LoginDenied));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert_eq!(text.matches("GET /a ").count(), 1, "{text}");
}

/// The package unknown is a `failf`, the context refused an `infof`, as
/// C says them, each failing the transfer with `CURLE_AUTH_ERROR`.
#[test]
fn the_package_s_failures_are_said() {
    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Err(SecStatus::new(-1))));
    let (mut m, talk, _) = server(&[CHALLENGE], false);
    let mut e = digesting(&libraries);
    as_user(e.options_mut());
    let ran = get_with(&mut m, e, "/a", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::AuthError));
    assert!(
        ran.seen
            .text()
            .contains(&"SSPI: could not get auth info\n".to_string())
    );

    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(32)))
        .then(Answer::Credentials(Ok(())))
        .then(Answer::Initialized(Ok((
            Initialized {
                status: SecStatus::new(0x8009_0304_u32 as i32),
                confidentiality: false,
                integrity: false,
            },
            Vec::new(),
        ))));
    let (mut m, talk, _) = server(&[CHALLENGE], false);
    let mut e = digesting(&libraries);
    as_user(e.options_mut());
    let ran = get_with(&mut m, e, "/a", talk, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::AuthError));
    assert!(
        ran.seen.text().contains(
            &"schannel: InitializeSecurityContext failed: status 0x80090304\n".to_string()
        )
    );
}
