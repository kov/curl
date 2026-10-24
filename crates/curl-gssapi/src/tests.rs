use curl_alloc::OutOfMemory;
use curl_core::gss::{
    Flags, Gss, GssCall, GssFailureKind, GssNote, GssStatus, Mech, StepSink, Style, Target,
};

use crate::GSSAPI;

/// What a step put out.
#[derive(Default)]
struct Collected {
    token: Option<Vec<u8>>,
    notes: Vec<GssNote>,
}

impl StepSink for Collected {
    fn token(&mut self, token: &[u8]) -> Result<(), OutOfMemory> {
        assert!(self.token.is_none(), "one token a step");
        self.token = Some(token.to_vec());
        Ok(())
    }

    fn note(&mut self, note: GssNote) {
        self.notes.push(note);
    }
}

const HTTP_AT_LOCALHOST: Target<'static> = Target::Service {
    service: b"HTTP",
    host: b"127.0.0.1",
};

const MUTUAL: Flags = Flags {
    mutual: true,
    delegate_by_policy: false,
    delegate: false,
};

fn described(status: &GssStatus, style: Style) -> Vec<u8> {
    let mut text = Vec::new();
    GSSAPI
        .describe(status, style, &mut |part| text.extend_from_slice(part))
        .unwrap();
    text
}

/// Runs the test `name` of this binary in a child with `env` set, the
/// environment being the whole process's, and asserts it passed.
fn in_child(name: &str, env: &[(&str, &str)]) {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--test-threads=1"])
        .env("CURL_GSSAPI_CHILD", name)
        .env_remove("CURL_STUB_GSS_CREDS");
    for (k, v) in env {
        command.env(k, v);
    }
    let out = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Whether this process is the child running `name`.
fn is_child(name: &str) -> bool {
    std::env::var("CURL_GSSAPI_CHILD").is_ok_and(|n| n == name)
}

/// Without credentials, SPNEGO fails at acquiring them, and the library
/// says why in both of C's layouts.
#[test]
fn without_credentials_spnego_fails_to_acquire_them() {
    let dir = std::env::temp_dir().join(format!("curl-gssapi-{}", std::process::id()));
    let cache = format!("FILE:{}/none", dir.display());
    in_child(
        "tests::without_credentials_in_a_child",
        &[
            ("KRB5CCNAME", &cache),
            ("KRB5_CONFIG", "/dev/null"),
            // The library's messages in English, as asserted.
            ("LC_ALL", "C"),
        ],
    );
}

#[test]
fn without_credentials_in_a_child() {
    if !is_child("tests::without_credentials_in_a_child") {
        return;
    }
    let mut context = GSSAPI
        .context(HTTP_AT_LOCALHOST, Mech::Spnego, MUTUAL)
        .unwrap();
    let mut sink = Collected::default();
    let failure = context.step(None, None, &mut sink).unwrap_err();
    assert_eq!(failure.call, GssCall::AcquireCred);
    let GssFailureKind::Status(status) = failure.kind else {
        panic!("{failure:?}");
    };
    assert!(sink.token.is_none());
    // The major code's message is the library's own, the same on any
    // machine; the minor code's, after it, speaks of the configuration.
    // C's trace (test 2077): "gss_acquire_cred() failed: No credentials
    // were supplied, ... inaccessible. No Kerberos credentials available
    // (default cache: KCM:). ".
    const MAJOR: &[u8] = b"No credentials were supplied, or the credentials were \
        unavailable or inaccessible";
    let log = described(&status, Style::Log);
    let minor = log.strip_prefix(MAJOR).and_then(|l| l.strip_prefix(b". "));
    let minor = minor.unwrap_or_else(|| panic!("{}", String::from_utf8_lossy(&log)));
    assert!(
        minor.len() > 2 && minor.ends_with(b". "),
        "{}",
        String::from_utf8_lossy(&log)
    );
    // SOCKS5's layout: the major code's first message, ".\n", the minor
    // code's first message, without its period.
    let socks = described(&status, Style::Socks);
    let mut expected = MAJOR.to_vec();
    expected.extend_from_slice(b".\n");
    expected.extend_from_slice(&minor[..minor.len() - 2]);
    assert_eq!(
        String::from_utf8_lossy(&socks),
        String::from_utf8_lossy(&expected)
    );
}

/// The stub's own minor codes mean nothing to the library: a failed
/// stub step says nothing after its prefix, as test 2057's C trace has
/// it ("gss_init_sec_context() failed: ").
#[test]
fn a_stub_status_has_no_text() {
    let status = GssStatus::new(crate::sys::GSS_S_FAILURE, 6);
    assert_eq!(described(&status, Style::Log), b"");
}

#[cfg(feature = "debug-hooks")]
mod stub {
    use super::*;

    /// Test 2056's expected token, decoded: what C's stub sends for
    /// `"KRB5_Alice"` (quotes and all, as runtests sets it) and
    /// `HTTP@127.0.0.1`.
    fn expected_2056() -> Vec<u8> {
        let test = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/data/test2056"
        ))
        .unwrap();
        let start = test.find("%b64[").unwrap() + 5;
        let end = test[start..].find("]b64%").unwrap() + start;
        test.as_bytes()[start..end].to_vec()
    }

    use curl_core::gss::Progress;

    fn step(
        context: &mut dyn curl_core::gss::GssContext,
        input: Option<&[u8]>,
    ) -> Result<(Progress, Vec<u8>), curl_core::gss::GssFailure> {
        let mut sink = Collected::default();
        let step = context.step(input, None, &mut sink)?;
        assert!(sink.notes.is_empty());
        // The stub claims neither protection, as C's gives back only the
        // flags asked for, and those only when done.
        assert!(!step.confidentiality && !step.integrity, "{step:?}");
        Ok((step.progress, sink.token.unwrap()))
    }

    fn stub_failure(minor: u32) -> GssFailureKind {
        GssFailureKind::Status(GssStatus::new(crate::sys::GSS_S_FAILURE, minor))
    }

    #[test]
    fn the_stub_s_first_token_is_c_s() {
        in_child(
            "tests::stub::first_token_in_a_child",
            &[("CURL_STUB_GSS_CREDS", "\"KRB5_Alice\"")],
        );
    }

    #[test]
    fn first_token_in_a_child() {
        if !is_child("tests::stub::first_token_in_a_child") {
            return;
        }
        let expected = expected_2056();
        assert_eq!(expected.len(), 187);
        let mut context = GSSAPI
            .context(HTTP_AT_LOCALHOST, Mech::Spnego, MUTUAL)
            .unwrap();
        let (progress, token) = step(&mut *context, None).unwrap();
        assert_eq!(progress, Progress::Continue);
        assert_eq!(
            String::from_utf8_lossy(&token),
            String::from_utf8_lossy(&expected)
        );
        // A second first step is refused; the peer's "done" completes it,
        // with nothing more to send, which SPNEGO refuses.
        let failure = step(&mut *context, None).unwrap_err();
        assert_eq!(failure.kind, stub_failure(crate::stub::INVALID_CTX));
        let failure = step(&mut *context, Some(b"D")).unwrap_err();
        assert_eq!(failure.kind, GssFailureKind::EmptyToken);
    }

    /// NTLM alone: SPNEGO narrows it away, and no mechanism is left
    /// (test 2057's path).
    #[test]
    fn the_stub_leaves_ntlm_out_of_spnego() {
        in_child(
            "tests::stub::ntlm_in_a_child",
            &[("CURL_STUB_GSS_CREDS", "\"NTLM_Alice\"")],
        );
    }

    #[test]
    fn ntlm_in_a_child() {
        if !is_child("tests::stub::ntlm_in_a_child") {
            return;
        }
        let mut context = GSSAPI
            .context(HTTP_AT_LOCALHOST, Mech::Spnego, MUTUAL)
            .unwrap();
        let failure = step(&mut *context, None).unwrap_err();
        assert_eq!(failure.call, GssCall::InitSecContext);
        assert_eq!(failure.kind, stub_failure(crate::stub::NO_MECH));
        // By Kerberos, with no credentials narrowing it, NTLM goes, and
        // continues to its third message, then is done.
        let mut context = GSSAPI
            .context(HTTP_AT_LOCALHOST, Mech::Kerberos, MUTUAL)
            .unwrap();
        let (_, token) = step(&mut *context, None).unwrap();
        assert!(token.starts_with(b"\"NTLM_Alice\":HTTP@127.0.0.1:2:"));
        let (_, token) = step(&mut *context, Some(b"C")).unwrap();
        assert!(token.starts_with(b"\"NTLM_Alice\":HTTP@127.0.0.1:3:"));
        let (progress, token) = step(&mut *context, Some(b"D")).unwrap();
        assert_eq!((progress, &token[..]), (Progress::Complete, &b""[..]));
    }

    /// Kerberos refused, NTLM next; Kerberos alone has nothing next.
    #[test]
    fn the_stub_continues_from_kerberos_to_ntlm() {
        in_child(
            "tests::stub::continue_in_a_child",
            &[("CURL_STUB_GSS_CREDS", "KRB5_NTLM")],
        );
    }

    #[test]
    fn continue_in_a_child() {
        if !is_child("tests::stub::continue_in_a_child") {
            return;
        }
        let mut context = GSSAPI
            .context(HTTP_AT_LOCALHOST, Mech::Kerberos, MUTUAL)
            .unwrap();
        let (progress, token) = step(&mut *context, None).unwrap();
        assert_eq!(progress, Progress::Continue);
        assert!(token.starts_with(b"KRB5_NTLM:HTTP@127.0.0.1:1:AAA"));
        let (_, token) = step(&mut *context, Some(b"C")).unwrap();
        assert!(token.starts_with(b"KRB5_NTLM:HTTP@127.0.0.1:2:AAA"));
        // Only 'D' and 'C' are answers.
        let failure = step(&mut *context, Some(b"X")).unwrap_err();
        assert_eq!(failure.kind, stub_failure(crate::stub::SERVER_ERR));
        // Done after NTLM's first message is an error.
        let failure = step(&mut *context, Some(b"D")).unwrap_err();
        assert_eq!(failure.kind, stub_failure(crate::stub::SERVER_ERR));
        // Under SPNEGO, NTLM is left out: Kerberos refused ends it.
        let mut context = GSSAPI
            .context(HTTP_AT_LOCALHOST, Mech::Spnego, MUTUAL)
            .unwrap();
        step(&mut *context, None).unwrap();
        let failure = step(&mut *context, Some(b"C")).unwrap_err();
        assert_eq!(failure.kind, stub_failure(crate::stub::SERVER_ERR));
    }

    /// Credentials of C's whole room, or naming a target too long for
    /// the token, fail; the token is cut where C's is.
    #[test]
    fn the_stub_s_bounds_are_c_s() {
        let long = "K".repeat(250);
        in_child(
            "tests::stub::too_long_in_a_child",
            &[("CURL_STUB_GSS_CREDS", &long)],
        );
        // 190 bytes of credentials and a 9-byte target fit the room (190 +
        // 14 + 5 < 250), but not the 187-byte token: it is cut at 186, and
        // its last byte is the padding.
        let cut = format!("KRB5{}", "x".repeat(186));
        in_child(
            "tests::stub::cut_in_a_child",
            &[("CURL_STUB_GSS_CREDS", &cut)],
        );
    }

    #[test]
    fn too_long_in_a_child() {
        if !is_child("tests::stub::too_long_in_a_child") {
            return;
        }
        let mut context = GSSAPI
            .context(HTTP_AT_LOCALHOST, Mech::Kerberos, MUTUAL)
            .unwrap();
        let failure = step(&mut *context, None).unwrap_err();
        assert_eq!(failure.kind, stub_failure(crate::stub::INVALID_CREDS));
    }

    #[test]
    fn cut_in_a_child() {
        if !is_child("tests::stub::cut_in_a_child") {
            return;
        }
        let mut context = GSSAPI
            .context(HTTP_AT_LOCALHOST, Mech::Kerberos, MUTUAL)
            .unwrap();
        let (_, token) = step(&mut *context, None).unwrap();
        assert_eq!(token.len(), 187);
        assert_eq!(&token[..186], format!("KRB5{}", "x".repeat(182)).as_bytes());
        assert_eq!(token[186], b'A');
        // The credentials, the target and 5 bytes must leave room for the
        // NUL: 190 + 54 + 5 does, 190 + 55 + 5 does not.
        for (host, fits) in [(49, true), (50, false)] {
            let host = vec![b'h'; host];
            let target = Target::Service {
                service: b"HTTP",
                host: &host,
            };
            let mut context = GSSAPI.context(target, Mech::Kerberos, MUTUAL).unwrap();
            let stepped = step(&mut *context, None);
            if fits {
                assert_eq!(stepped.unwrap().1.len(), 187);
            } else {
                let failure = stepped.unwrap_err();
                assert_eq!(failure.kind, stub_failure(crate::stub::NO_MEMORY));
            }
        }
    }

    /// A stub's context wraps nothing, as C's stub has no `gss_wrap`.
    #[test]
    fn the_stub_wraps_nothing() {
        in_child(
            "tests::stub::wrap_in_a_child",
            &[("CURL_STUB_GSS_CREDS", "KRB5")],
        );
    }

    #[test]
    fn wrap_in_a_child() {
        if !is_child("tests::stub::wrap_in_a_child") {
            return;
        }
        let mut context = GSSAPI
            .context(HTTP_AT_LOCALHOST, Mech::Kerberos, MUTUAL)
            .unwrap();
        step(&mut *context, None).unwrap();
        let failure = context.wrap(b"\x00", &mut |_| Ok(())).unwrap_err();
        assert_eq!(failure.call, GssCall::Wrap);
        assert_eq!(failure.kind, stub_failure(crate::stub::INVALID_CTX));
    }
}
