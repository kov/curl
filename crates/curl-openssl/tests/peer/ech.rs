//! Encrypted Client Hello over the forks (`ossl_init_ech`): what the
//! client offers, the TLS 1.3 it holds itself to, and what it makes of a
//! server that has no ECH and answers the outer hello.

#[cfg(boringssl_like)]
pub(crate) use forks::TESTS;

/// None but over the forks: OpenSSL and LibreSSL as built here have no ECH.
#[cfg(not(boringssl_like))]
pub(crate) const TESTS: &[(&str, fn())] = &[];

#[cfg(boringssl_like)]
mod forks {
    use curl_core::options::{Ech, EchMode};
    use openssl::ssl::SslVersion;

    use super::super::*;

    pub(crate) const TESTS: &[(&str, fn())] = &[
        (
            "ech_grease_reaches_a_server_without_ech",
            ech_grease_reaches_a_server_without_ech,
        ),
        (
            "a_server_without_ech_refuses_the_list",
            a_server_without_ech_refuses_the_list,
        ),
        (
            "a_list_that_does_not_decode_is_tried_as_none",
            a_list_that_does_not_decode_is_tried_as_none,
        ),
        (
            "a_list_tried_holds_the_handshake_to_tls_1_3",
            a_list_tried_holds_the_handshake_to_tls_1_3,
        ),
        (
            "an_outer_name_is_refused_once_a_list_is_tried",
            an_outer_name_is_refused_once_a_list_is_tried,
        ),
    ];

    /// Test 4001's ECHConfigList: X25519 with HKDF-SHA256 and AES-128-GCM,
    /// for the outer name `PUBLIC`.
    const ECH_4001: &[u8] = b"AEv+DQBHdAAgACCCU49qdxKOUXJPs3wlsM06v/t42sMH5xQOL37MAd3HaAAEAAEAAQAYb3RoZXJwdWJsaWMudGVzdC5kZWZvLmllAAA=";
    const PUBLIC: &str = "otherpublic.test.defo.ie";

    fn ech(mode: EchMode, config: Option<&[u8]>, public_name: Option<&[u8]>) -> Ech {
        Ech {
            mode,
            config: config.map(<[u8]>::to_vec),
            public_name: public_name.map(<[u8]>::to_vec),
        }
    }

    /// Trust `certs`, and set ECH as `ech` says.
    fn with_ech(certs: &Certs, ech: Ech) -> impl FnOnce(&mut Options) + '_ {
        move |o| {
            trusting(certs)(o);
            o.tls.options.make_mut().unwrap().ech = ech;
        }
    }

    fn ech_lines(got: &Got) -> Vec<&str> {
        got.seen
            .lines
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("ECH: "))
            .collect()
    }

    /// GREASE is asked of the fork and said; a server without ECH takes no
    /// notice of it.
    fn ech_grease_reaches_a_server_without_ech() {
        let certs = certs("ech-grease", "localhost", &["localhost"]);
        let (at, server) = serve(&certs);
        let got = get_traced(
            "localhost",
            at,
            with_ech(&certs, ech(EchMode::Grease, None, None)),
            true,
        );
        server.join().unwrap();
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
        assert_eq!(ech_lines(&got), ["ECH: will GREASE ClientHello"]);
    }

    /// A server without ECH answers the outer hello, as the outer name,
    /// whose certificate is checked; the client then fails the handshake
    /// for ECH refused, with no retry configurations to trace, as
    /// `CURLE_ECH_REQUIRED`, whether ECH is tried or hard.
    fn a_server_without_ech_refuses_the_list() {
        for mode in [EchMode::Try, EchMode::Hard] {
            let certs = certs("ech-refused", "localhost", &["localhost", PUBLIC]);
            let (at, server) = serve(&certs);
            let got = get_traced(
                "localhost",
                at,
                with_ech(&certs, ech(mode, Some(ECH_4001), None)),
                true,
            );
            server.join().unwrap();
            assert_eq!(
                got.result,
                Err(ErrorKind::EchRequired),
                "{:#?}",
                got.seen.lines
            );
            let rejected =
                "ECH: rejected, error:1000013f:SSL routines:OPENSSL_internal:ECH_REJECTED";
            assert_eq!(
                ech_lines(&got),
                [
                    "ECH: ECHConfig from command line",
                    "ECH: no retry_configs (rv = 0)",
                    rejected
                ],
                "{mode:?}"
            );
            assert_eq!(got.failure, rejected.as_bytes());
        }
    }

    /// A list that does not decode is said, and then tried as no list, as
    /// C hands the fork what it decoded: the fork refuses it, which is
    /// said too, and the handshake goes on, held to TLS 1.3. Hard, the
    /// decoding fails the transfer as C's does.
    fn a_list_that_does_not_decode_is_tried_as_none() {
        let certs = certs("ech-undecoded", "localhost", &["localhost"]);
        let (at, server) = serve(&certs);
        let got = get_traced(
            "localhost",
            at,
            with_ech(&certs, ech(EchMode::Try, Some(b"not base64"), None)),
            true,
        );
        server.join().unwrap();
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
        assert_eq!(
            ech_lines(&got),
            [
                "ECH: cannot base64 decode ECHConfig from command line",
                "ECH: SSL_ECH_set1_ech_config_list failed",
                "ECH: ECHConfig from command line"
            ]
        );
        let (at, server) = serve(&certs);
        let got = get_traced(
            "localhost",
            at,
            with_ech(&certs, ech(EchMode::Hard, Some(b"not base64"), None)),
            true,
        );
        server.join().unwrap();
        assert_eq!(got.result, Err(ErrorKind::BadContentEncoding));
        assert_eq!(
            ech_lines(&got),
            ["ECH: cannot base64 decode ECHConfig from command line"]
        );
    }

    /// A list tried holds the handshake to TLS 1.3, which a server of TLS
    /// 1.2 alone does not speak; without ECH it is spoken to.
    fn a_list_tried_holds_the_handshake_to_tls_1_3() {
        let certs = certs("ech-tls12", "localhost", &["localhost"]);
        let tls12 = |a: &mut SslAcceptorBuilder| {
            a.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
        };
        let (at, server) = serve_configured(&certs, false, tls12);
        let got = get("localhost", at, trusting(&certs));
        server.join().unwrap();
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
        let (at, server) = serve_configured(&certs, false, tls12);
        let got = get(
            "localhost",
            at,
            with_ech(&certs, ech(EchMode::Try, Some(b"QUJD"), None)),
        );
        server.join().unwrap();
        assert_eq!(
            got.result,
            Err(ErrorKind::SslConnectError),
            "{:#?}",
            got.seen.lines
        );
    }

    /// The forks cannot set an outer name: one fails the handshake once a
    /// list is tried, and not with GREASE, which tries none.
    fn an_outer_name_is_refused_once_a_list_is_tried() {
        let certs = certs("ech-outer", "localhost", &["localhost"]);
        let (at, server) = serve(&certs);
        let got = get_traced(
            "localhost",
            at,
            with_ech(
                &certs,
                ech(EchMode::Try, Some(ECH_4001), Some(b"p.example")),
            ),
            true,
        );
        server.join().unwrap();
        assert_eq!(got.result, Err(ErrorKind::SslConnectError));
        assert!(
            said(
                &got,
                "ECH: setting public_name not supported with BoringSSL"
            ),
            "{:#?}",
            got.seen.lines
        );
        let (at, server) = serve(&certs);
        let got = get_traced(
            "localhost",
            at,
            with_ech(&certs, ech(EchMode::Grease, None, Some(b"p.example"))),
            true,
        );
        server.join().unwrap();
        assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    }
}
