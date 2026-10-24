//! HTTP Negotiate through the core with the debug build's stub standing in
//! for a KDC, over the core's fake network: the bytes and the lines C's
//! build sends and says for the same exchanges (C's captures with
//! `CURL_STUB_GSS_CREDS`, tests 2056, 2057 and 2096 to 2099). The stub
//! reads `CURL_STUB_GSS_CREDS` each time it is asked, so each case runs in
//! a child process of this binary with the variable set.

#![cfg(feature = "debug-hooks")]
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use curl_core::conn::io::{Conversation, FakeNet, Peer};
use curl_core::easy::Easy;
use curl_core::error::ErrorKind;
use curl_core::handler::{DebugHandler, DebugKind, Handler, Write, WriteHandler};
use curl_core::id::ArenaPolicy;
use curl_core::libraries::Libraries;
use curl_core::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
use curl_core::options::{AuthMethods, HttpAuth, Login, Options};
use curl_core::time::ManualClock;

static LIBRARIES: Libraries = Libraries {
    gss: Some(&curl_gssapi::GSSAPI),
    ..Libraries::NONE
};

const PORT: u16 = 8990;

/// The stub's first token for `creds`, from `HTTP@127.0.0.1`, in base64:
/// what test 2056 expects for `KRB5_Alice`.
fn token(creds: &str) -> String {
    let mut raw = format!("{creds}:HTTP@127.0.0.1:1:").into_bytes();
    raw.resize(187, b'A');
    base64(&raw)
}

fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for group in bytes.chunks(3) {
        let n = group
            .iter()
            .chain(std::iter::repeat(&0))
            .take(3)
            .fold(0u32, |n, &b| n << 8 | u32::from(b));
        for i in 0..4 {
            if i <= group.len() {
                out.push(ABC[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// What a transfer saw: its text lines and the header lines in and out,
/// in order, each tagged as C's `--trace-ascii` tags them.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<String>>>);

impl DebugHandler for Seen {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        let tag = match kind {
            DebugKind::Text => "*",
            DebugKind::HeaderIn => "<=",
            DebugKind::HeaderOut => "=>",
            _ => return,
        };
        let text = String::from_utf8_lossy(data);
        let line = match kind {
            // A request's head is one piece; its lines are what matters.
            DebugKind::HeaderOut => format!("{tag} {}", text.lines().next().unwrap_or("")),
            _ => format!("{tag} {}", text.trim_end()),
        };
        self.0.lock().unwrap().push(line.trim_end().to_owned());
    }
}

impl WriteHandler for Seen {
    fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
        Write::Accepted
    }
}

impl Seen {
    /// The lines, without those of the transport and the debug build
    /// that C's capture leaves out or words otherwise.
    fn lines(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|l| {
                ![
                    "* !!!",
                    "* This is a debug build",
                    "*   Trying",
                    "* Established",
                    "* Connected to",
                    "* Request completely sent off",
                    "* sending last upload chunk",
                    "* Curl_xfer_send",
                ]
                .iter()
                .any(|p| l.starts_with(p))
            })
            .cloned()
            .collect()
    }
}

/// A multi whose server at `PORT` answers `replies` in turn on one
/// connection.
fn server(replies: &[&[u8]]) -> (Multi, Conversation) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::replies(replies, false);
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), talk)
}

/// A verbose GET of `path` on `m`, with the options `set` makes.
fn get(m: &mut Multi, path: &str, set: impl FnOnce(&mut Options)) -> (Result<(), ErrorKind>, Seen) {
    let mut e = Easy::new();
    e.set_libraries(&LIBRARIES);
    let seen = Seen::default();
    let o = e.options_mut();
    let url = format!("http://127.0.0.1:{PORT}{path}");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.output.verbose = true;
    o.http.user_agent = Some(b"curl/test".to_vec());
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    set(o);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(m, id, &mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    (result, seen)
}

fn negotiate(o: &mut Options) {
    o.http.auth = HttpAuth(AuthMethods::NEGOTIATE);
}

fn request(path: &str, token: Option<&str>) -> String {
    let auth = token.map_or(String::new(), |t| {
        format!("Authorization: Negotiate {t}\r\n")
    });
    format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n{auth}User-Agent: curl/test\r\n\
         Accept: */*\r\n\r\n"
    )
}

/// Runs the test `name` of this binary in a child with the stub's
/// credentials `creds`, and asserts it passed.
fn in_child(name: &str, creds: &str) {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1"])
        .env("CURL_GSSAPI_CHILD", name)
        .env("CURL_STUB_GSS_CREDS", creds)
        .output()
        .unwrap();
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

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";

/// Test 2056: one request, its token the stub's, said as C says it.
#[test]
fn the_stub_s_token_goes_at_once() {
    in_child("first_token_in_a_child", "KRB5_Alice");
}

#[test]
fn first_token_in_a_child() {
    if !is_child("first_token_in_a_child") {
        return;
    }
    let (mut m, talk) = server(&[OK]);
    let (result, seen) = get(&mut m, "/2056", negotiate);
    assert_eq!(result, Ok(()));
    assert_eq!(
        String::from_utf8(talk.received()).unwrap(),
        request("/2056", Some(&token("KRB5_Alice")))
    );
    assert_eq!(
        seen.lines(),
        [
            "* using HTTP/1.x",
            "* Server auth using Negotiate with user ''",
            "=> GET /2056 HTTP/1.1",
            "<= HTTP/1.1 200 OK",
            "<= Content-Length: 3",
            "<=",
            "* Connection #0 to host 127.0.0.1:8990 left intact",
        ]
    );
}

/// Test 2057: NTLM credentials alone leave SPNEGO nothing: the failure
/// is said with the stub's empty text, and the request goes without.
#[test]
fn ntlm_alone_goes_without() {
    in_child("ntlm_alone_in_a_child", "NTLM_Alice");
}

#[test]
fn ntlm_alone_in_a_child() {
    if !is_child("ntlm_alone_in_a_child") {
        return;
    }
    let (mut m, talk) = server(&[OK]);
    let (result, seen) = get(&mut m, "/2057", negotiate);
    assert_eq!(result, Ok(()));
    assert_eq!(
        String::from_utf8(talk.received()).unwrap(),
        request("/2057", None)
    );
    assert_eq!(
        seen.lines()[..3],
        [
            "* using HTTP/1.x",
            "* gss_init_sec_context() failed:",
            "* Server auth using Negotiate with user ''",
        ]
    );
}

/// Test 2096, C's capture with `--anyauth -u :`: a 401 offering
/// Negotiate has it picked and the request made again with the stub's
/// token, and the 200's `Persistent-Auth` read.
#[test]
fn a_401_round_trip() {
    in_child("round_trip_in_a_child", "KRB5_Alice");
}

#[test]
fn round_trip_in_a_child() {
    if !is_child("round_trip_in_a_child") {
        return;
    }
    let unauthorized =
        b"HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 4\r\n\r\nno!\n";
    let ok = b"HTTP/1.1 200 OK\r\nPersistent-Auth: true\r\nContent-Length: 3\r\n\r\nok\n";
    let (mut m, talk) = server(&[unauthorized, ok]);
    let (result, seen) = get(&mut m, "/a", |o| {
        o.http.auth = HttpAuth(AuthMethods::ANY);
        *o.login.make_mut().unwrap() = Login::from_pair(b":").unwrap();
    });
    assert_eq!(result, Ok(()));
    assert_eq!(
        String::from_utf8(talk.received()).unwrap(),
        request("/a", None) + &request("/a", Some(&token("KRB5_Alice")))
    );
    // C's lines for the same exchange, but its debug build's own.
    assert_eq!(
        seen.lines(),
        [
            "* using HTTP/1.x",
            "=> GET /a HTTP/1.1",
            "<= HTTP/1.1 401 Who",
            "<= WWW-Authenticate: Negotiate",
            "<= Content-Length: 4",
            "* Ignoring the response-body",
            "* setting size while ignoring",
            "<=",
            "* Connection #0 to host 127.0.0.1:8990 left intact",
            "* Issue another request to this URL: 'http://127.0.0.1:8990/a'",
            "* Reusing existing http: connection with host 127.0.0.1",
            "* Server auth using Negotiate with user ''",
            "=> GET /a HTTP/1.1",
            "<= HTTP/1.1 200 OK",
            "* Negotiate: noauthpersist -> 0, header part: true",
            "<= Persistent-Auth: true",
            "<= Content-Length: 3",
            "<=",
            "* Connection #0 to host 127.0.0.1:8990 left intact",
        ]
    );
}

/// Test 2097, C's capture: the stub fails a `C` (continue) challenge to
/// a Kerberos context, said as the line is handled; the 401 stays the
/// response. A `D` (done) one completes it with no token, which fails
/// it unsaid.
#[test]
fn a_challenge_the_stub_refuses() {
    in_child("refused_in_a_child", "KRB5_Alice");
}

#[test]
fn refused_in_a_child() {
    if !is_child("refused_in_a_child") {
        return;
    }
    for (challenge, said) in [("Qw==", true), ("RA==", false)] {
        let unauthorized = format!(
            "HTTP/1.1 401 Who\r\nWWW-Authenticate: Negotiate {challenge}\r\n\
             Content-Length: 4\r\n\r\nno!\n"
        );
        let (mut m, talk) = server(&[unauthorized.as_bytes()]);
        let (result, seen) = get(&mut m, "/a", negotiate);
        assert_eq!(result, Ok(()));
        assert_eq!(
            String::from_utf8(talk.received()).unwrap(),
            request("/a", Some(&token("KRB5_Alice")))
        );
        let mut want = vec![
            "* using HTTP/1.x".to_owned(),
            "* Server auth using Negotiate with user ''".to_owned(),
            "=> GET /a HTTP/1.1".to_owned(),
            "<= HTTP/1.1 401 Who".to_owned(),
        ];
        if said {
            want.push("* gss_init_sec_context() failed:".to_owned());
        }
        want.extend([
            format!("<= WWW-Authenticate: Negotiate {challenge}"),
            "<= Content-Length: 4".to_owned(),
            "<=".to_owned(),
            "* Connection #0 to host 127.0.0.1:8990 left intact".to_owned(),
        ]);
        assert_eq!(seen.lines(), want, "{challenge}");
    }
}

/// Tests 2098 and 2099, C's captures: a second request over the
/// connection makes a new token, the old context cleaned up, unless the
/// server said its authentication persists.
#[test]
fn a_second_request() {
    in_child("second_request_in_a_child", "KRB5_Alice");
}

#[test]
fn second_request_in_a_child() {
    if !is_child("second_request_in_a_child") {
        return;
    }
    for persists in [false, true] {
        let first: &[u8] = if persists {
            b"HTTP/1.1 200 OK\r\nPersistent-Auth: true\r\nContent-Length: 3\r\n\r\nok\n"
        } else {
            OK
        };
        let (mut m, talk) = server(&[first, OK]);
        let (result, _) = get(&mut m, "/b", negotiate);
        assert_eq!(result, Ok(()));
        let (result, seen) = get(&mut m, "/a", negotiate);
        assert_eq!(result, Ok(()));
        let t = token("KRB5_Alice");
        let second = if persists {
            request("/a", None)
        } else {
            request("/a", Some(&t))
        };
        assert_eq!(
            String::from_utf8(talk.received()).unwrap(),
            request("/b", Some(&t)) + &second
        );
        let cleaned =
            "* Curl_output_negotiate, no persistent authentication: cleanup existing context";
        let mut want = vec!["* Reusing existing http: connection with host 127.0.0.1"];
        if !persists {
            want.push(cleaned);
        }
        want.extend([
            "* Server auth using Negotiate with user ''",
            "=> GET /a HTTP/1.1",
        ]);
        assert_eq!(seen.lines()[..want.len()], want, "{persists}");
    }
}
