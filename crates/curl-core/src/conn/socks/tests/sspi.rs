//! SOCKS5's GSS-API method over a scripted SSPI, as C's Windows build
//! runs it (`lib/socks_sspi.c`): the Kerberos package's tokens in the
//! same messages, the user the credentials', the level wrapped as
//! token, data and padding, and SSPI's words for each way it fails.

use super::*;
use crate::libraries::Security;
use crate::sspi::testing::{Answer, Asked, Scripted};
use crate::sspi::{Initialized, Output, Package, Req, SecStatus, Sizes, SspiFailure};

const PROXY: &[u8] = b"proxy.example";

fn offered(sspi: &'static Scripted, service: Option<&[u8]>, nec: bool) -> Handshake {
    let d = dest(b"host.example", Resolved::Remote);
    let c = service.map(|service| Creds {
        user: b"u",
        password: b"p",
        service,
    });
    let method = GssMethod {
        library: Security::Sspi(sspi),
        nec,
        delegation: crate::options::Delegation::default(),
    };
    let mut h = Handshake::new(
        Version::V5Hostname,
        d,
        c,
        Socks5Auth::default(),
        Some(method),
    )
    .unwrap();
    send(&mut h);
    h
}

fn lines_of<T>(
    h: &mut Handshake,
    f: impl FnOnce(&mut Handshake, &mut dyn FnMut(GssLine<'_>)) -> T,
) -> (T, Vec<String>) {
    let mut lines = Vec::new();
    let got = f(h, &mut |line| lines.push(line.to_string()));
    (got, lines)
}

fn picked(h: &mut Handshake) -> (Result<(), SocksError>, Vec<String>) {
    assert_eq!(h.take(b"\x05\x01"), Ok(Took::Read(2)));
    assert!(h.gss_starts());
    lines_of(h, |h, say| h.start_gss(PROXY, say))
}

fn step(status: SecStatus, token: &[u8]) -> Answer {
    Answer::Initialized(Ok((
        Initialized {
            status,
            confidentiality: true,
            integrity: true,
        },
        token.to_vec(),
    )))
}

fn kerberos_flags() -> Req {
    Req {
        mutual_auth: true,
        confidentiality: true,
        replay_detect: true,
        ..Req::default()
    }
}

fn initialize(target: &[u8], fresh: bool, input: &[u8]) -> Asked {
    Asked::Initialize {
        target: target.to_vec(),
        flags: kerberos_flags(),
        native: true,
        fresh,
        input: vec![(b'T', input.to_vec())],
        output: Output::Allocated,
    }
}

fn gss_error(e: SocksError) -> GssError {
    match e {
        SocksError::Gss(g) => g,
        other => panic!("{other:?}"),
    }
}

/// The process's Kerberos credentials make a context with `rcmd/proxy`,
/// whose tokens go framed as GSS-API's do; once complete, the user is
/// the credentials', and the protection level goes wrapped as token,
/// data and padding, its answer unwrapped and granted "BUT NOT USED".
#[test]
fn the_exchange_is_c_s() {
    let sspi = Scripted::leaked();
    let mut h = offered(sspi, None, false);
    sspi.then(Answer::Credentials(Ok(())))
        .then(step(SecStatus::CONTINUE_NEEDED, b"first"));
    let (r, lines) = picked(&mut h);
    assert_eq!(r, Ok(()));
    assert!(lines.is_empty());
    assert_eq!(send(&mut h), b"\x01\x01\x00\x05first");
    sspi.then(step(SecStatus::OK, b"last"))
        .then(Answer::User(Ok(b"me@REALM".to_vec())))
        .then(Answer::Sizes(Ok(Sizes {
            trailer: 12,
            block: 0,
        })))
        .then(Answer::Wrapped(Ok(b"W\x02".to_vec())));
    let (r, lines) = lines_of(&mut h, |h, say| h.take_saying(b"\x01\x01\x00\x02ok", say));
    assert_eq!(r, Ok(Took::Read(6)));
    assert_eq!(
        lines,
        [
            "SOCKS5 server authenticated user me@REALM with GSS-API.",
            "SOCKS5 server supports GSS-API confidentiality data protection.",
        ]
    );
    assert_eq!(send(&mut h), b"\x01\x01\x00\x04last\x01\x02\x00\x02W\x02");
    sspi.then(Answer::Unwrapped(Ok(vec![0])));
    let (r, lines) = lines_of(&mut h, |h, say| h.take_saying(b"\x01\x02\x00\x01u", say));
    assert_eq!(r, Ok(Took::Read(5)));
    assert_eq!(
        lines,
        ["SOCKS5 access without GSS-API data protection granted BUT NOT USED."]
    );
    assert_eq!(
        sspi.asked(),
        [
            Asked::Credentials(Package::Kerberos, None),
            initialize(b"rcmd/proxy.example", true, b""),
            initialize(b"rcmd/proxy.example", false, b"ok"),
            Asked::UserName,
            Asked::Sizes,
            Asked::Wrap(vec![2]),
            Asked::Unwrap(b"u".to_vec()),
            Asked::Dropped,
        ]
    );
}

/// A service naming its host is the target as it is; NEC's way sends
/// the level bare.
#[test]
fn a_service_with_a_host_is_the_name() {
    let sspi = Scripted::leaked();
    let mut h = offered(sspi, Some(b"socks/other"), true);
    sspi.then(Answer::Credentials(Ok(())))
        .then(step(SecStatus::OK, b""))
        .then(Answer::User(Ok(b"u".to_vec())));
    assert_eq!(picked(&mut h).0, Ok(()));
    assert_eq!(send(&mut h), b"\x01\x02\x00\x01\x02");
    assert_eq!(sspi.asked()[1], initialize(b"socks/other", true, b""));
}

/// Each failure: the call SSPI refused, with its status, and what C's
/// SSPI build says of the step.
#[test]
fn failures_are_said_in_sspi_s_words() {
    let refused = SecStatus::new(0x8009_030e_u32 as i32);
    let sspi = Scripted::leaked();
    let mut h = offered(sspi, None, false);
    sspi.then(Answer::Credentials(Err(SspiFailure::Status(refused))));
    let e = gss_error(picked(&mut h).0.unwrap_err());
    assert_eq!(
        e.status,
        Some(Status::Sspi(SspiCall::AcquireCredentialsHandle, refused))
    );
    assert_eq!(e.step.sspi().to_string(), "Failed to acquire credentials.");

    // A status that is no error but not one C passes still fails.
    let incomplete = SecStatus::new(0x0009_0320);
    for status in [refused, incomplete] {
        let mut h = offered(sspi, None, false);
        sspi.then(Answer::Credentials(Ok(())))
            .then(step(status, b""));
        let e = gss_error(picked(&mut h).0.unwrap_err());
        assert_eq!(
            e.status,
            Some(Status::Sspi(SspiCall::InitializeSecurityContext, status))
        );
        assert_eq!(
            e.step.sspi().to_string(),
            "Failed to initialize security context."
        );
    }

    let mut h = offered(sspi, None, false);
    sspi.then(Answer::Credentials(Ok(())))
        .then(step(SecStatus::OK, b"t"))
        .then(Answer::User(Err(SspiFailure::Status(refused))));
    let e = gss_error(picked(&mut h).0.unwrap_err());
    assert_eq!(
        e.status,
        Some(Status::Sspi(SspiCall::QueryCredentialsAttributes, refused))
    );
    assert_eq!(e.step.sspi().to_string(), "Failed to determine username.");

    let mut h = offered(sspi, None, false);
    sspi.then(Answer::Credentials(Ok(())))
        .then(step(SecStatus::OK, b"t"))
        .then(Answer::User(Ok(b"u".to_vec())))
        .then(Answer::Sizes(Err(refused)));
    let e = gss_error(picked(&mut h).0.unwrap_err());
    assert_eq!(
        e.status,
        Some(Status::Sspi(SspiCall::QueryContextAttributes, refused))
    );
    assert_eq!(
        e.step.sspi().to_string(),
        "Failed to query security context attributes."
    );

    let mut h = offered(sspi, None, false);
    sspi.then(Answer::Credentials(Ok(())))
        .then(step(SecStatus::OK, b"t"))
        .then(Answer::User(Ok(b"u".to_vec())))
        .then(Answer::Sizes(Ok(Sizes::default())))
        .then(Answer::Wrapped(Err(SspiFailure::Status(refused))));
    let e = gss_error(picked(&mut h).0.unwrap_err());
    assert_eq!(
        (e.status, e.step),
        (
            Some(Status::Sspi(SspiCall::EncryptMessage, refused)),
            Failed::Silently
        )
    );

    let mut h = offered(sspi, None, false);
    sspi.then(Answer::Credentials(Ok(())))
        .then(step(SecStatus::OK, b"t"))
        .then(Answer::User(Ok(b"u".to_vec())))
        .then(Answer::Sizes(Ok(Sizes::default())))
        .then(Answer::Wrapped(Ok(b"w".to_vec())));
    assert_eq!(picked(&mut h).0, Ok(()));
    send(&mut h);
    sspi.then(Answer::Unwrapped(Err(SspiFailure::Status(refused))));
    let e = gss_error(h.take(b"\x01\x02\x00\x01x").unwrap_err());
    assert_eq!(
        (e.status, e.step),
        (
            Some(Status::Sspi(SspiCall::DecryptMessage, refused)),
            Failed::Silently
        )
    );

    let mut h = offered(sspi, None, false);
    sspi.then(Answer::Credentials(Ok(())))
        .then(step(SecStatus::OK, b"t"))
        .then(Answer::User(Ok(b"u".to_vec())))
        .then(Answer::Sizes(Ok(Sizes::default())))
        .then(Answer::Wrapped(Ok(b"w".to_vec())));
    assert_eq!(picked(&mut h).0, Ok(()));
    send(&mut h);
    sspi.then(Answer::Unwrapped(Ok(b"12".to_vec())));
    let e = gss_error(h.take(b"\x01\x02\x00\x01x").unwrap_err());
    assert_eq!(
        e.step.sspi().to_string(),
        "Invalid SSPI encryption response length (2)."
    );
    sspi.asked();
}

/// The words of every step C's SSPI build says.
#[test]
fn sspi_words_are_c_s() {
    for (step, text) in [
        (Failed::Silently, ""),
        (Failed::Unwrap, ""),
        (
            Failed::Rejected(1, 255),
            "User was rejected by the SOCKS5 server (1 255).",
        ),
        (Failed::Username, "Failed to determine username."),
        (
            Failed::SendAuthRequest,
            "Failed to send SSPI authentication request.",
        ),
        (
            Failed::SendAuthToken,
            "Failed to send SSPI authentication token.",
        ),
        (
            Failed::RecvAuthResponse,
            "Failed to receive SSPI authentication response.",
        ),
        (
            Failed::AuthType(1, 3),
            "Invalid SSPI authentication response type (1 3).",
        ),
        (
            Failed::ZeroAuthToken,
            "Invalid zero-length SSPI authentication token.",
        ),
        (
            Failed::RecvAuthToken,
            "Failed to receive SSPI authentication token.",
        ),
        (
            Failed::SendLevelRequest,
            "Failed to send SSPI encryption request.",
        ),
        (Failed::SendLevel, "Failed to send SSPI encryption type."),
        (
            Failed::RecvLevelResponse,
            "Failed to receive SSPI encryption response.",
        ),
        (
            Failed::LevelType(1, 3),
            "Invalid SSPI encryption response type (1 3).",
        ),
        (
            Failed::ZeroLevelToken,
            "Invalid zero-length SSPI encryption token.",
        ),
        (Failed::RecvLevel, "Failed to receive SSPI encryption type."),
    ] {
        assert_eq!(step.sspi().to_string(), text);
    }
}
