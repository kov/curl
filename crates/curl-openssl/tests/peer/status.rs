//! The peer's stapled certificate status (`CURLOPT_SSL_VERIFYSTATUS`,
//! `verifystatus`), and the issuer the peer's certificate must have
//! (`CURLOPT_ISSUERCERT`, `ossl_check_issuer`).

#[cfg(not(no_ocsp))]
use std::process::Command;

#[cfg(not(no_ocsp))]
use openssl::ocsp::{OcspResponse, OcspResponseStatus};

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    // BoringSSL has no OCSP, nor C's build over it.
    #[cfg(not(no_ocsp))]
    (
        "a_status_that_is_missing_or_unusable_fails_as_c_says",
        a_status_that_is_missing_or_unusable_fails_as_c_says,
    ),
    #[cfg(not(no_ocsp))]
    (
        "a_good_status_passes_and_a_revoked_one_fails",
        a_good_status_passes_and_a_revoked_one_fails,
    ),
    #[cfg(not(any(no_ocsp, boringssl_like)))]
    (
        "a_transfer_checking_the_status_resumes_no_session",
        a_transfer_checking_the_status_resumes_no_session,
    ),
    (
        "the_issuer_named_must_have_issued_the_peer_s_certificate",
        the_issuer_named_must_have_issued_the_peer_s_certificate,
    ),
];

/// A server for `certs` that staples `status`, if any.
#[cfg(not(boringssl_like))]
fn serve_stapling(certs: &Certs, status: Option<Vec<u8>>) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    serve_configured(certs, false, move |a| {
        if let Some(status) = status {
            a.set_status_callback(move |ssl| {
                ssl.set_ocsp_status(&status).unwrap();
                Ok(true)
            })
            .unwrap();
        }
    })
}

/// Over AWS-LC, whose `openssl` crate staples nothing, the `openssl`
/// command's server for `certs`, stapling `status` if any (`-status_file`),
/// answering each GET with its page. It sends its CA after its
/// certificate, as C's build over a fork finds the issuer only in the
/// chain the peer sent (`SSL_get_peer_cert_chain`).
#[cfg(all(awslc, not(no_ocsp)))]
fn serve_stapling(certs: &Certs, status: Option<Vec<u8>>) -> (SocketAddr, StaplingServer) {
    serve_stapling_chain(certs, status, true)
}

/// As `serve_stapling`, its CA sent or not.
#[cfg(all(awslc, not(no_ocsp)))]
fn serve_stapling_chain(
    certs: &Certs,
    status: Option<Vec<u8>>,
    chain: bool,
) -> (SocketAddr, StaplingServer) {
    track::untracked(|| {
        let dir = certs_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let at = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let path = |what: &str| dir.join(format!("stapling-{}-{what}", at.port()));
        let (cert, key) = (path("cert.pem"), path("key.pem"));
        std::fs::write(&cert, certs.cert.to_pem().unwrap()).unwrap();
        std::fs::write(&key, certs.key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        let mut cmd = Command::new("openssl");
        cmd.env("OPENSSL_CONF", "/dev/null")
            .args(["s_server", "-www", "-quiet", "-accept"])
            .arg(at.port().to_string())
            .arg("-cert")
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if chain {
            let ca = path("ca.pem");
            std::fs::write(&ca, certs.ca.to_pem().unwrap()).unwrap();
            cmd.arg("-cert_chain").arg(&ca);
        }
        if let Some(status) = status {
            let file = path("status.der");
            std::fs::write(&file, status).unwrap();
            cmd.arg("-status_file").arg(&file);
        }
        let child = cmd.spawn().unwrap();
        // Listening once a connection is taken: that one is closed unused.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::net::TcpStream::connect(at).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "openssl s_server never listened"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        (at, StaplingServer(child))
    })
}

/// The `openssl` command's server, ended when the test is done with it.
#[cfg(all(awslc, not(no_ocsp)))]
struct StaplingServer(std::process::Child);

#[cfg(all(awslc, not(no_ocsp)))]
impl StaplingServer {
    fn join(mut self) -> Result<(), ()> {
        track::untracked(|| {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        });
        Ok(())
    }
}

/// A GET checking the status the server staples.
#[cfg(not(no_ocsp))]
fn checking_status(certs: &Certs, status: Option<Vec<u8>>) -> Got {
    let (at, server) = serve_stapling(certs, status);
    let got = get("localhost", at, |o| {
        trusting(certs)(o);
        o.tls.options.make_mut().unwrap().verify_status = true;
    });
    server.join().unwrap();
    got
}

/// No status, bytes that are none, and a responder that would not say:
/// each 91, said as C says it.
#[cfg(not(no_ocsp))]
fn a_status_that_is_missing_or_unusable_fails_as_c_says() {
    let certs = certs("status-bad", "localhost", &["localhost"]);
    let later = OcspResponse::create(OcspResponseStatus::TRY_LATER, None)
        .unwrap()
        .to_der()
        .unwrap();
    // OpenSSL 3.6 and later parse what a server is given to staple, and
    // send nothing that is not a response: the client then has none.
    #[cfg(not(awslc))]
    let not_der = if !cfg!(libressl) && openssl::version::number() >= 0x3060_0000 {
        &b"No OCSP response received"[..]
    } else {
        b"Invalid OCSP response"
    };
    for (status, failure) in [
        (None, &b"No OCSP response received"[..]),
        // The `openssl` command serving AWS-LC's client takes no status
        // that is not DER.
        #[cfg(not(awslc))]
        (Some(b"not DER".to_vec()), not_der),
        (Some(later), b"Invalid OCSP response status: trylater (3)"),
    ] {
        let got = checking_status(&certs, status);
        assert_eq!(got.result, Err(ErrorKind::SslInvalidcertstatus));
        assert_eq!(
            String::from_utf8_lossy(&got.failure),
            String::from_utf8_lossy(failure)
        );
    }
    // Not asked for, none is needed.
    let (at, server) = serve_stapling(&certs, None);
    let got = get("localhost", at, trusting(&certs));
    server.join().unwrap();
    assert_eq!(got.result, Ok(()));
}

/// A response the `openssl ocsp` responder makes for `certs`' server
/// certificate, signed by `signer` (its certificate and key), the
/// certificate said `revoked` or valid.
#[cfg(not(no_ocsp))]
fn response(certs: &Certs, tag: &str, signer: (&X509, &PKey<Private>), revoked: bool) -> Vec<u8> {
    let dir = certs_dir();
    let file = |name: &str, bytes: &[u8]| {
        let path = dir.join(format!("{tag}-{name}"));
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let ca = file("ca.pem", &certs.ca.to_pem().unwrap());
    let cert = file("cert.pem", &certs.cert.to_pem().unwrap());
    let rsigner = file("signer.pem", &signer.0.to_pem().unwrap());
    let rkey = file("signer.key", &signer.1.private_key_to_pem_pkcs8().unwrap());
    let line = if revoked {
        "R\t300101000000Z\t240101000000Z,keyCompromise\t02\tunknown\t/CN=localhost\n"
    } else {
        "V\t300101000000Z\t\t02\tunknown\t/CN=localhost\n"
    };
    let index = file("index.txt", line.as_bytes());
    let req = dir.join(format!("{tag}-req.der"));
    let resp = dir.join(format!("{tag}-resp.der"));
    let run = |args: &[&std::ffi::OsStr]| {
        let out = Command::new("openssl")
            .arg("ocsp")
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    };
    run(&[
        "-issuer".as_ref(),
        ca.as_os_str(),
        "-cert".as_ref(),
        cert.as_os_str(),
        "-no_nonce".as_ref(),
        "-reqout".as_ref(),
        req.as_os_str(),
    ]);
    run(&[
        "-index".as_ref(),
        index.as_os_str(),
        "-rsigner".as_ref(),
        rsigner.as_os_str(),
        "-rkey".as_ref(),
        rkey.as_os_str(),
        "-CA".as_ref(),
        ca.as_os_str(),
        "-reqin".as_ref(),
        req.as_os_str(),
        "-respout".as_ref(),
        resp.as_os_str(),
        "-ndays".as_ref(),
        "1".as_ref(),
    ]);
    std::fs::read(resp).unwrap()
}

/// A status the CA signed: good passes, saying so, whenever it was
/// issued; revoked fails with its reason; one signed by a stranger fails
/// its verification.
#[cfg(not(no_ocsp))]
fn a_good_status_passes_and_a_revoked_one_fails() {
    let certs = certs("status", "localhost", &["localhost"]);
    let good = response(&certs, "status-good", (&certs.ca, &certs.ca_key), false);
    // However old the response's issue, it is taken while it is valid
    // (`OCSP_check_validity`'s `-1`): this one is two seconds old.
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let got = checking_status(&certs, Some(good));
    assert_eq!(got.result, Ok(()), "{:#?}", got.seen.lines);
    assert!(
        said(&got, "SSL certificate status: good (0)"),
        "{:#?}",
        got.seen.lines
    );

    let revoked = response(&certs, "status-revoked", (&certs.ca, &certs.ca_key), true);
    let got = checking_status(&certs, Some(revoked));
    assert_eq!(got.result, Err(ErrorKind::SslInvalidcertstatus));
    assert!(
        said(&got, "SSL certificate status: revoked (1)"),
        "{:#?}",
        got.seen.lines
    );
    assert_eq!(
        got.failure,
        b"SSL certificate revocation reason: keyCompromise (1)"
    );

    let stranger = super::certs("status-stranger", "stranger", &[]);
    let forged = response(
        &certs,
        "status-forged",
        (&stranger.ca, &stranger.ca_key),
        false,
    );
    let got = checking_status(&certs, Some(forged));
    assert_eq!(got.result, Err(ErrorKind::SslInvalidcertstatus));
    assert_eq!(got.failure, b"OCSP response verification failed");

    // Over AWS-LC the issuer is looked for in the chain the peer sent
    // alone, not the one verified: a good status from a server sending
    // its certificate alone fails, as C's build over it fails it.
    #[cfg(awslc)]
    {
        let good = response(&certs, "status-alone", (&certs.ca, &certs.ca_key), false);
        let (at, server) = serve_stapling_chain(&certs, Some(good), false);
        let got = get("localhost", at, |o| {
            trusting(&certs)(o);
            o.tls.options.make_mut().unwrap().verify_status = true;
        });
        server.join().unwrap();
        assert_eq!(got.result, Err(ErrorKind::SslInvalidcertstatus));
        assert_eq!(got.failure, b"Error computing OCSP ID");
    }
}

/// A transfer checking the peer's status resumes no session, as a resumed
/// one carries no status to check: its second connection, to a server
/// that would resume the first's session and staples nothing this time,
/// makes a new handshake and fails for want of a status.
#[cfg(not(any(no_ocsp, boringssl_like)))]
fn a_transfer_checking_the_status_resumes_no_session() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let certs = certs("status-resume", "localhost", &["localhost"]);
    let good = response(&certs, "status-resume", (&certs.ca, &certs.ca_key), false);
    let stapled = Arc::new(AtomicBool::new(false));
    let once = stapled.clone();
    let a = super::resume::acceptor(&certs, move |a| {
        a.set_status_callback(move |ssl| {
            if once.swap(true, Ordering::SeqCst) {
                return Ok(false);
            }
            ssl.set_ocsp_status(&good).unwrap();
            Ok(true)
        })
        .unwrap();
    });
    let (at, server) = super::resume::serve_each(vec![a.clone(), a]);
    let mut m = multi(try_box(SystemClock::new()).unwrap());
    let set = |o: &mut Options| {
        trusting(&certs)(o);
        o.tls.options.make_mut().unwrap().verify_status = true;
    };
    let one = get_in(&mut m, "https", "localhost", at, set, false);
    let two = get_in(&mut m, "https", "localhost", at, set, false);
    server.join().unwrap();
    assert_eq!(one.result, Ok(()), "{:#?}", one.seen.lines);
    assert!(stapled.load(Ordering::SeqCst));
    assert!(!super::resume::resumed(&two), "{:#?}", two.seen.lines);
    assert_eq!(
        two.result,
        Err(ErrorKind::SslInvalidcertstatus),
        "{:#?}",
        two.seen.lines
    );
    assert_eq!(two.failure, b"No OCSP response received");
}

/// `CURLOPT_ISSUERCERT` and its blob: the CA that issued the peer's
/// certificate passes, said; another fails with 83, said only when the
/// peer or its name is verified; a file that cannot be read fails alike.
fn the_issuer_named_must_have_issued_the_peer_s_certificate() {
    let certs = certs("issuer", "localhost", &["localhost"]);
    let other = super::certs("issuer-other", "localhost", &["localhost"]);
    let ca = certs.ca_file.to_str().unwrap().as_bytes().to_vec();
    let not = other.ca_file.to_str().unwrap().as_bytes().to_vec();
    let with_checks =
        |set: &dyn Fn(&mut curl_core::options::TlsOptions), peer: bool, host: bool| {
            let (at, server) = serve(&certs);
            let got = get("localhost", at, |o| {
                trusting(&certs)(o);
                o.tls.verify_peer = peer;
                o.tls.verify_host = host;
                set(o.tls.options.make_mut().unwrap());
            });
            server.join().unwrap();
            got
        };
    let with = |set: &dyn Fn(&mut curl_core::options::TlsOptions), verify: bool| {
        with_checks(set, verify, verify)
    };
    let shown = |p: &[u8]| String::from_utf8(p.to_vec()).unwrap();
    let got = with(&|t| t.issuer_cert = Some(ca.clone()), true);
    assert_eq!(got.result, Ok(()));
    assert!(said(
        &got,
        &format!(" SSL certificate issuer check ok ({})", shown(&ca))
    ));
    let got = with(&|t| t.issuer_cert = Some(not.clone()), true);
    assert_eq!(got.result, Err(ErrorKind::SslIssuerError));
    assert_eq!(
        String::from_utf8(got.failure).unwrap(),
        format!("SSL: Certificate issuer check failed ({})", shown(&not))
    );
    let got = with(&|t| t.issuer_cert = Some(not.clone()), false);
    assert_eq!(got.result, Err(ErrorKind::SslIssuerError));
    assert_eq!(got.failure, b"");
    // The name checked alone is the peer verified enough to say it.
    let got = with_checks(&|t| t.issuer_cert = Some(not.clone()), false, true);
    assert_eq!(got.result, Err(ErrorKind::SslIssuerError));
    assert_eq!(
        String::from_utf8(got.failure).unwrap(),
        format!("SSL: Certificate issuer check failed ({})", shown(&not))
    );
    let got = with(
        &|t| t.issuer_cert = Some(b"/nonexistent/ca.pem".to_vec()),
        true,
    );
    assert_eq!(got.result, Err(ErrorKind::SslIssuerError));
    assert_eq!(
        got.failure,
        b"SSL: Unable to open issuer cert (/nonexistent/ca.pem)"
    );
    let pem = std::fs::read(&certs.ca_file).unwrap();
    let got = with(&|t| t.issuer_cert_blob = Some(pem.clone()), true);
    assert_eq!(got.result, Ok(()));
    assert!(said(&got, " SSL certificate issuer check ok ((null))"));
    let got = with(&|t| t.issuer_cert_blob = Some(b"not PEM".to_vec()), true);
    assert_eq!(got.result, Err(ErrorKind::SslIssuerError));
    assert_eq!(got.failure, b"SSL: Unable to read issuer cert ((null))");
}
