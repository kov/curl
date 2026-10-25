//! SOCKS5's GSS-API method through the core with this library, over the
//! core's fake network: with the debug build's stub, the bytes and the
//! lines C's build sends and says (C's captures with
//! `CURL_STUB_GSS_CREDS` against a hand-rolled RFC 1961 proxy); with the
//! library itself and a made-up ticket, its first token framed and its
//! failure on the proxy's answer said as C lays it out. Each case runs
//! in a child process of this binary, its environment set.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use curl_core::conn::io::{Conversation, FakeNet, Peer};
use curl_core::easy::Easy;
use curl_core::error::ErrorKind;
use curl_core::handler::{DebugHandler, DebugKind, Handler, Write, WriteHandler};
use curl_core::id::ArenaPolicy;
use curl_core::libraries::{Libraries, SharedLibraries};
use curl_core::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
use curl_core::options::Options;
use curl_core::time::{ManualClock, TimeLimit};

#[path = "../src/tests/ccache.rs"]
#[allow(dead_code)]
mod ccache;

static LIBRARIES: Libraries = Libraries {
    gss: Some(&curl_gssapi::GSSAPI),
    ..Libraries::NONE
};

const PORT: u16 = 8991;

/// The Kerberos OID, as a token's framing holds it.
const KRB5_OID: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";

/// The text lines a transfer traced.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<String>>>);

impl DebugHandler for Seen {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text {
            let text = String::from_utf8_lossy(data);
            self.0
                .lock()
                .unwrap()
                .push(text.strip_suffix('\n').unwrap_or(&text).to_owned());
        }
    }
}

impl WriteHandler for Seen {
    fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
        Write::Accepted
    }
}

impl Seen {
    /// The lines of the method, from its first to the transfer's end.
    fn gss_lines(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|l| {
                ["GSS", "SOCKS5", "Failed", "Unable", "User", "Invalid"]
                    .iter()
                    .any(|p| l.contains(p))
            })
            .cloned()
            .collect()
    }
}

struct Ran {
    result: Result<(), ErrorKind>,
    /// What the proxy was sent.
    sent: Vec<u8>,
    seen: Seen,
    failure: Option<Vec<u8>>,
}

/// A GET through the SOCKS5 proxy at `PORT`, which answers each send
/// with the next of `replies`, with the options `set` makes.
fn through_proxy(replies: &[&[u8]], set: impl FnOnce(&mut Options)) -> Ran {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::replies(replies, true).per_send();
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let mut e = Easy::new();
    e.set_libraries(SharedLibraries::of_static(&LIBRARIES));
    let seen = Seen::default();
    let o = e.options_mut();
    o.set_url(Some(b"http://origin.example/a")).unwrap();
    o.proxy.make_mut().unwrap().url = Some(format!("socks5h://127.0.0.1:{PORT}").into_bytes());
    o.output.verbose = true;
    o.limits.total = TimeLimit::from_millis(10_000);
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    set(o);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let easy = m.remove(id, &mut NoEvents).unwrap().easy;
    Ran {
        result,
        sent: talk.received(),
        seen,
        failure: easy.report().failure().map(<[u8]>::to_vec),
    }
}

/// Runs the test `name` of this binary in a child with `env` set, and
/// asserts it passed.
fn in_child(name: &str, env: &[(String, String)]) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", name, "--test-threads=1"])
        .env("CURL_GSSAPI_CHILD", name);
    for (k, v) in env {
        child.env(k, v);
    }
    let out = child.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn is_child(name: &str) -> bool {
    std::env::var("CURL_GSSAPI_CHILD").is_ok_and(|n| n == name)
}

#[cfg(feature = "debug-hooks")]
fn stub(creds: &str) -> Vec<(String, String)> {
    vec![("CURL_STUB_GSS_CREDS".into(), creds.into())]
}

/// The stub's first token for `target`, framed: C's capture's bytes.
#[cfg(feature = "debug-hooks")]
fn stub_frame(target: &str) -> Vec<u8> {
    let mut token = format!("KRB5_Alice:{target}:1:").into_bytes();
    token.resize(187, b'A');
    let mut frame = b"\x01\x01\x00\xbb".to_vec();
    frame.extend_from_slice(&token);
    frame
}

/// C's capture: the offer with GSS-API, the stub's token for
/// `rcmd@127.0.0.1` framed, the proxy's rejection the transfer's reason,
/// the method's end said after it.
#[cfg(feature = "debug-hooks")]
#[test]
fn the_stub_s_token_is_framed_as_c_s() {
    in_child("framed_in_a_child", &stub("KRB5_Alice"));
}

#[cfg(feature = "debug-hooks")]
#[test]
fn framed_in_a_child() {
    if !is_child("framed_in_a_child") {
        return;
    }
    let ran = through_proxy(&[b"\x05\x01", b"\x01\xff\x00\x00"], |_| {});
    assert_eq!(ran.result, Err(ErrorKind::Proxy));
    let mut want = b"\x05\x02\x00\x01".to_vec();
    want.extend_from_slice(&stub_frame("rcmd@127.0.0.1"));
    assert_eq!(ran.sent, want);
    assert_eq!(
        ran.failure.as_deref(),
        Some(&b"User was rejected by the SOCKS5 server (1 255)."[..])
    );
    assert_eq!(
        ran.seen.gss_lines(),
        [
            "User was rejected by the SOCKS5 server (1 255).",
            "Unable to negotiate SOCKS5 GSS-API context.",
        ]
    );
}

/// C's captures: a service with a `/` is a name as it is, which the
/// stub's token names; one without is a service at the proxy. Either
/// makes the proxy's credentials, so the user and password method is
/// offered too.
#[cfg(feature = "debug-hooks")]
#[test]
fn the_service_names_the_target() {
    in_child("service_in_a_child", &stub("KRB5_Alice"));
}

#[cfg(feature = "debug-hooks")]
#[test]
fn service_in_a_child() {
    if !is_child("service_in_a_child") {
        return;
    }
    for (service, target) in [("foo/bar", "foo/bar"), ("svc", "svc@127.0.0.1")] {
        let ran = through_proxy(&[b"\x05\x01", b"\x01\xff\x00\x00"], |o| {
            o.proxy.make_mut().unwrap().service = Some(service.as_bytes().to_vec());
        });
        let mut want = b"\x05\x03\x00\x01\x02".to_vec();
        want.extend_from_slice(&stub_frame(target));
        assert_eq!(ran.sent, want, "{service}");
    }
    // GSS-API alone: the credentials, and their service, let go.
    let ran = through_proxy(&[b"\x05\x01", b"\x01\xff\x00\x00"], |o| {
        let proxy = o.proxy.make_mut().unwrap();
        proxy.service = Some(b"foo/bar".to_vec());
        proxy.socks5_auth.basic = false;
    });
    let mut want = b"\x05\x02\x00\x01".to_vec();
    want.extend_from_slice(&stub_frame("rcmd@127.0.0.1"));
    assert_eq!(ran.sent, want);
}

/// The stub's context complete, the library is asked who it is, which
/// it fails, the stub's context being nothing to it. C asks the library
/// about the stub's context too and crashes (`DIVERGENCE.md`).
#[cfg(feature = "debug-hooks")]
#[test]
fn the_stub_s_context_names_no_user() {
    in_child("no_user_in_a_child", &stub("KRB5_Alice"));
}

#[cfg(feature = "debug-hooks")]
#[test]
fn no_user_in_a_child() {
    if !is_child("no_user_in_a_child") {
        return;
    }
    let ran = through_proxy(&[b"\x05\x01", b"\x01\x01\x00\x01D"], |_| {});
    assert_eq!(ran.result, Err(ErrorKind::Proxy));
    let lines = ran.seen.gss_lines();
    assert!(
        lines[0].starts_with("GSS-API error: gss_inquire_context failed: ")
            && lines[0].contains(".\n"),
        "{lines:?}"
    );
    assert_eq!(
        lines[1..],
        [
            "Failed to determine username.",
            "Unable to negotiate SOCKS5 GSS-API context.",
        ]
    );
}

/// The stub refuses a `C` answer to its Kerberos context with a minor
/// code the library has no words for: said with none. C asks the library
/// for them for ever (`DIVERGENCE.md`).
#[cfg(feature = "debug-hooks")]
#[test]
fn a_status_without_words_is_said_without_them() {
    in_child("wordless_in_a_child", &stub("KRB5_Alice"));
}

#[cfg(feature = "debug-hooks")]
#[test]
fn wordless_in_a_child() {
    if !is_child("wordless_in_a_child") {
        return;
    }
    let ran = through_proxy(&[b"\x05\x01", b"\x01\x01\x00\x01C"], |_| {});
    assert_eq!(ran.result, Err(ErrorKind::Proxy));
    let lines = ran.seen.gss_lines();
    assert!(
        lines[0].starts_with("GSS-API error: gss_init_sec_context failed: ")
            && lines[0].ends_with(".\n"),
        "{lines:?}"
    );
    assert_eq!(
        lines[1..],
        [
            "Failed to initialize GSS-API token.",
            "Unable to negotiate SOCKS5 GSS-API context.",
        ]
    );
}

/// The library itself, with a ticket for `HTTP/127.0.0.1` in its cache:
/// its first token, Kerberos's in the mechanism's framing, goes framed;
/// mutual authentication then wants the proxy's, and fails on one that
/// is no token, said as C lays the library's words out.
#[test]
fn the_library_s_token_is_framed() {
    let kdcless = ccache::Kdcless::new("socks", ccache::Key::Aes256);
    in_child("library_in_a_child", &kdcless.env());
}

#[test]
fn library_in_a_child() {
    if !is_child("library_in_a_child") {
        return;
    }
    let ran = through_proxy(&[b"\x05\x01", b"\x01\x01\x00\x0bnot a token"], |o| {
        o.proxy.make_mut().unwrap().service = Some(b"HTTP".to_vec());
    });
    assert_eq!(ran.result, Err(ErrorKind::Proxy));
    let sent = &ran.sent;
    assert_eq!(&sent[..5], b"\x05\x03\x00\x01\x02");
    assert_eq!(&sent[5..7], b"\x01\x01");
    let len = usize::from(u16::from_be_bytes([sent[7], sent[8]]));
    let token = &sent[9..];
    assert_eq!(token.len(), len);
    assert!(
        token[0] == 0x60 && token.windows(KRB5_OID.len()).any(|w| w == KRB5_OID),
        "{token:x?}"
    );
    // C's capture for the same exchange: the library's words for a
    // token it cannot read, laid out as `check_gss_err` lays them.
    let said = "GSS-API error: gss_init_sec_context failed: Invalid token was supplied.\nSuccess";
    assert_eq!(ran.failure.as_deref(), Some(said.as_bytes()));
    assert_eq!(
        ran.seen.gss_lines(),
        [
            said,
            "Failed to initialize GSS-API token.",
            "Unable to negotiate SOCKS5 GSS-API context.",
        ]
    );
}
