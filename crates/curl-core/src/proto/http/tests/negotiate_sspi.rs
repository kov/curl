//! HTTP Negotiate with the origin over a scripted SSPI, as C's Windows
//! build routes it (`lib/vauth/spnego_sspi.c` under
//! `lib/http_negotiate.c`): the package's room, the credentials given or
//! the process's user's without NTLM, the target `service/host`, and what
//! is said when SSPI refuses.

use super::*;
use crate::libraries::{Libraries, Security, SharedLibraries};
use crate::options::{Delegation, HttpAuth};
use crate::sspi::testing::{Answer, Asked, Scripted};
use crate::sspi::{Initialized, Output, Package, Req, SecStatus, SspiFailure};

const ROOM: usize = 48;

/// A scripted SSPI, and the libraries naming it.
fn scripted() -> (&'static Scripted, SharedLibraries) {
    let sspi = Scripted::leaked();
    let libraries = SharedLibraries::new(Libraries {
        security: Some(Security::Sspi(sspi)),
        ..Libraries::NONE
    })
    .unwrap();
    (sspi, libraries)
}

fn b64(bytes: &[u8]) -> String {
    let mut out = Vec::new();
    crate::base64::encode(bytes.iter().copied(), bytes.len(), &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

fn negotiated_get(path: &str, token: &[u8]) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nAuthorization: Negotiate {}\r\n\
         User-Agent: curl/test\r\nAccept: */*\r\n\r\n",
        b64(token)
    )
}

fn negotiating(libraries: &SharedLibraries) -> Easy {
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    e.options_mut().http.auth = HttpAuth(AuthMethods::NEGOTIATE);
    e
}

const OK_200: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";

fn text_has(ran: &Ran, line: &str) -> bool {
    ran.seen.text().iter().any(|l| l == line)
}

/// The step answers `status` with `token`.
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

/// The call C makes: `HTTP/host`, confidentiality asked, the machine's
/// representation, in a room of the package's size.
fn initialize(fresh: bool, input: &[(u8, &[u8])], flags: Req) -> Asked {
    Asked::Initialize {
        target: b"HTTP/127.0.0.1".to_vec(),
        flags,
        native: true,
        fresh,
        input: input.iter().map(|(k, b)| (*k, b.to_vec())).collect(),
        output: Output::Room(ROOM),
    }
}

fn confidential() -> Req {
    Req {
        confidentiality: true,
        ..Req::default()
    }
}

/// Without credentials, the first token goes at once, made for the
/// process's user without NTLM (`!ntlm`), the target `HTTP/host`, as
/// `spnego_sspi.c` makes it.
#[test]
fn the_first_token_is_the_process_user_s_without_ntlm() {
    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(ROOM)))
        .then(Answer::Credentials(Ok(())))
        .then(made(SecStatus::CONTINUE_NEEDED, b"first"));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(&libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_get("/", b"first")
    );
    assert_eq!(
        sspi.asked(),
        [
            Asked::MaxToken(Package::Negotiate),
            Asked::CredentialsLimited(Package::Negotiate, b"!ntlm".to_vec()),
            initialize(true, &[], confidential()),
        ]
    );
}

/// Credentials naming a user are the identity's, the domain before its
/// `\`; full delegation asks to delegate and for mutual authentication,
/// delegation by policy for nothing more (`CURLGSSAPI_DELEGATION_FLAG`
/// alone counts).
#[test]
fn credentials_and_delegation_are_the_identity_s_and_the_flags() {
    for (delegation, flags) in [
        (
            Delegation {
                by_policy: false,
                always: true,
            },
            Req {
                confidentiality: true,
                delegate: true,
                mutual_auth: true,
                ..Req::default()
            },
        ),
        (
            Delegation {
                by_policy: true,
                always: false,
            },
            confidential(),
        ),
    ] {
        let (sspi, libraries) = scripted();
        sspi.then(Answer::MaxToken(Ok(ROOM)))
            .then(Answer::Credentials(Ok(())))
            .then(made(SecStatus::CONTINUE_NEEDED, b"t"));
        let (mut m, talk, _) = server(&[OK_200], false);
        let ran = get_with(&mut m, negotiating(&libraries), "/", talk, |o| {
            o.login.make_mut().unwrap().user = Some(b"dom\\user".to_vec());
            o.login.make_mut().unwrap().password = Some(b"pw".to_vec());
            o.login.make_mut().unwrap().delegation = delegation;
        });
        assert_eq!(ran.result, Ok(()));
        assert_eq!(
            sspi.asked(),
            [
                Asked::MaxToken(Package::Negotiate),
                Asked::Credentials(
                    Package::Negotiate,
                    Some([
                        b"user".to_vec(),
                        b"dom".to_vec(),
                        b"pw".to_vec(),
                        b"!ntlm".to_vec()
                    ])
                ),
                initialize(true, &[], flags),
            ]
        );
    }
}

/// A challenge goes on with the context made, the token decoded; the
/// context then complete, a second 401 is a refusal (`SEC_E_OK` and a
/// context, `CURLE_LOGIN_DENIED`).
#[test]
fn a_challenge_goes_on_with_the_context() {
    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(ROOM)))
        .then(Answer::Credentials(Ok(())))
        .then(made(SecStatus::CONTINUE_NEEDED, b"first"))
        .then(made(SecStatus::OK, b"second"));
    let unauthorized = format!(
        "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate {}\r\nContent-Length: 4\r\n\r\nno!\n",
        b64(b"challenge")
    );
    let (mut m, talk, _) = server(&[unauthorized.as_bytes(), OK_200], false);
    let ran = get_with(&mut m, negotiating(&libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_get("/", b"first") + &negotiated_get("/", b"second")
    );
    assert_eq!(
        sspi.asked(),
        [
            Asked::MaxToken(Package::Negotiate),
            Asked::CredentialsLimited(Package::Negotiate, b"!ntlm".to_vec()),
            initialize(true, &[], confidential()),
            initialize(false, &[(b'T', b"challenge")], confidential()),
        ]
    );
}

/// A refusal is the transfer's error, said with SSPI's words for it; the
/// first token not made, the request goes without one. A package SSPI
/// does not know is said as C says it, and credentials it refuses are
/// not said at all.
#[test]
fn refusals_are_said_as_c_says_them() {
    let refused = SecStatus::new(0x8009_030e_u32 as i32);
    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(ROOM)))
        .then(Answer::Credentials(Ok(())))
        .then(Answer::Initialized(Ok((
            Initialized {
                status: refused,
                confidentiality: false,
                integrity: false,
            },
            Vec::new(),
        ))));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(&libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(text_has(
        &ran,
        "InitializeSecurityContext failed: status 0x8009030e\n"
    ));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        String::from_utf8(request_of("/")).unwrap()
    );
    assert_eq!(sspi.asked().last(), Some(&Asked::Dropped));

    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Err(SecStatus::new(-1))));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(&libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(text_has(&ran, "SSPI: could not get auth info\n"));

    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(ROOM)))
        .then(Answer::Credentials(Err(SspiFailure::Status(refused))));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(&libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(!ran.seen.text().iter().any(|l| l.contains("failed")));
}

/// A step SSPI says needs completing is completed over its token, which
/// goes as completion leaves it; a completion refused is said.
#[test]
fn a_token_needing_completion_is_completed() {
    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(ROOM)))
        .then(Answer::Credentials(Ok(())))
        .then(made(SecStatus::COMPLETE_AND_CONTINUE, b"raw"))
        .then(Answer::Completed(SecStatus::CONTINUE_NEEDED));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(&libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        String::from_utf8(ran.request.clone()).unwrap(),
        negotiated_get("/", b"raw")
    );
    assert_eq!(sspi.asked()[3], Asked::Complete(b"raw".to_vec()));

    let (sspi, libraries) = scripted();
    sspi.then(Answer::MaxToken(Ok(ROOM)))
        .then(Answer::Credentials(Ok(())))
        .then(made(SecStatus::COMPLETE_NEEDED, b"raw"))
        .then(Answer::Completed(SecStatus::new(0x8009_0304_u32 as i32)));
    let (mut m, talk, _) = server(&[OK_200], false);
    let ran = get_with(&mut m, negotiating(&libraries), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(text_has(
        &ran,
        "CompleteAuthToken failed: status 0x80090304\n"
    ));
}
