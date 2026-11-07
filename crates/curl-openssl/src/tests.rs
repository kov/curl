use curl_core::libraries::Ed25519;

use crate::ED25519;

fn hex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(DIGITS[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// RFC 8032's test vectors 1 and 2 (section 7.1).
#[test]
fn signs_rfc_8032_s_vectors() {
    for (key, message, signature) in [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
             fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ] {
        let key: [u8; 32] = hex(key).try_into().unwrap();
        let made = ED25519.sign(&key, &hex(message)).unwrap();
        assert_eq!(made.as_slice(), hex(signature));
    }
}

/// Test 5001's signature base, signed with the key of tests/data, is the
/// signature the test expects.
#[test]
fn signs_test_5001_s_base_with_the_test_key() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/data/data-httpsig-ed25519.key"
    );
    let key: [u8; 32] = hex(&std::fs::read_to_string(path).unwrap())
        .try_into()
        .unwrap();
    let base = "\"@method\": GET\n\
                \"@authority\": example.com:8000\n\
                \"@path\": /5001/resource\n\
                \"@query\": ?action=read\n\
                \"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\");\
                created=0;keyid=\"my-key-1\";alg=\"ed25519\"";
    let made = ED25519.sign(&key, base.as_bytes()).unwrap();
    assert_eq!(
        base64(&made),
        "RQniOeqmwdRzGvoDIMJ8XJha75evJWgqo5/66EeuJeEGczZtnP2U/F52Lzd/y7Vd1DCb8oUcCKHrKi2VJI7lBA=="
    );
}

/// What a session makes of OpenSSL's, it frees: its context, its SSL and
/// BIO method, the certificates and BIOs it reads the peer's chain and
/// the issuer named with, the store its multi keeps, the engine or the
/// provider it selects, and a client certificate's CAs. The library's
/// allocations are counted, in a process of their own, against an
/// `openssl s_server` of another, whose allocations are its own.
/// LibreSSL takes no allocator of ours (`CRYPTO_set_mem_functions`
/// refuses), so its allocations are not counted, nor BoringSSL's, which
/// has no such function; AWS-LC's are.
#[cfg(any(ossl3, awslc))]
#[test]
fn a_transfer_frees_what_it_made_of_openssl_s() {
    crate::sys::tests::in_a_child("tests::counted_transfers", "/dev/null".as_ref());
}

#[cfg(any(ossl3, awslc))]
#[test]
#[ignore = "run by a_transfer_frees_what_it_made_of_openssl_s"]
fn counted_transfers() {
    crate::sys::tests::count_allocations();
    let server = leaks::Server::start();
    let kinds = leaks::kinds(&server);
    for (name, set) in &kinds {
        let result = leaks::transfer(server.port, set);
        assert_eq!(result, Ok(()), "{name}");
    }
    assert!(
        crate::sys::tests::live_allocations() > 0,
        "the library's allocations are counted"
    );
    // The library fills caches of its own over the first transfers
    // through a provider, a few allocations at a time, depending on what
    // ran before, then keeps no more: C's build does the same (measured
    // on macOS with OpenSSL 3.6). So each kind runs three transfers at a
    // time until three leave the count where they found it, which a
    // transfer leaving anything behind never does.
    //
    // OpenSSL 3.6 also keeps state of its own for each thread until the
    // thread stops, among it a table indexed by the address of each
    // library context the thread used (`threads_common.c`): a provider's
    // context made at an address not used before grows it. On Windows
    // that left the provider's count unsettled in about half the runs,
    // the table's nodes all that was left (measured with OpenSSL 3.6.5).
    // So the thread's state is ended before each count is read.
    for (name, set) in &kinds {
        let mut left = Vec::new();
        for _ in 0..10 {
            crate::sys::tests::stop_thread();
            let at = crate::sys::tests::live_allocations();
            for _ in 0..3 {
                leaks::transfer(server.port, set).unwrap();
            }
            crate::sys::tests::stop_thread();
            left.push(crate::sys::tests::live_allocations() - at);
            if left.last() == Some(&0) {
                break;
            }
        }
        assert_eq!(
            left.last(),
            Some(&0),
            "{name}: OpenSSL's allocations left by each 3 transfers: {left:?}"
        );
    }
}

/// The server and the transfers `counted_transfers` makes.
#[cfg(any(ossl3, awslc))]
mod leaks {
    use std::io::BufRead as _;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    use curl_core::easy::Easy;
    use curl_core::error::ErrorKind;
    use curl_core::handler::{Handler, Write, WriteHandler};
    use curl_core::libraries::{Libraries, Library, SharedLibraries};
    use curl_core::multi::TransferCx;
    use curl_core::options::{CaSetting, IpVersion, Options};
    use openssl::asn1::{Asn1Time, Asn1Type};
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkcs12::Pkcs12;
    use openssl::pkey::{PKey, Private};
    use openssl::stack::Stack;
    use openssl::x509::extension::BasicConstraints;
    use openssl::x509::{X509, X509Name};

    static LIBRARIES: Libraries = Libraries {
        tls: Some(Library::Static(&crate::OPENSSL)),
        ..Libraries::NONE
    };

    fn key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    /// A certificate for `subject`'s key, signed by `issuer` (itself if
    /// none), a CA if `ca`.
    fn cert(
        subject: &X509Name,
        key: &PKey<Private>,
        issuer: Option<(&X509, &PKey<Private>)>,
        ca: bool,
    ) -> X509 {
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(if ca { 1 } else { 2 }).unwrap();
        b.set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(subject).unwrap();
        b.set_issuer_name(issuer.map_or(subject, |(c, _)| c.subject_name()))
            .unwrap();
        b.set_pubkey(key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        if ca {
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
        }
        b.sign(issuer.map_or(key, |(_, k)| k), MessageDigest::sha256())
            .unwrap();
        b.build()
    }

    fn name(cn: &str, kind: Asn1Type) -> X509Name {
        let mut n = X509Name::builder().unwrap();
        n.append_entry_by_nid_with_type(Nid::COMMONNAME, cn, kind)
            .unwrap();
        n.build()
    }

    /// `openssl s_server`, answering each connection with its status page
    /// (`-www`), asking for a client certificate the client CA signed.
    pub(super) struct Server {
        child: Child,
        pub(super) port: u16,
        dir: PathBuf,
        ca_file: Vec<u8>,
        p12: Vec<u8>,
    }

    impl Server {
        /// Its certificate names `localhost` by a common name in a
        /// BMPString, and has no alternative names, so the host check
        /// converts the name to UTF-8.
        pub(super) fn start() -> Server {
            let dir =
                std::env::temp_dir().join(format!("curl-openssl-leaks-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let write = |name: &str, bytes: &[u8]| {
                let path = dir.join(name);
                std::fs::write(&path, bytes).unwrap();
                path
            };
            let ca_key = key();
            let ca = cert(&name("leaks CA", Asn1Type::UTF8STRING), &ca_key, None, true);
            let server_key = key();
            // A BMPString is given as its bytes, UTF-16BE.
            let bmp: String = "localhost".chars().flat_map(|c| ['\0', c]).collect();
            let server = cert(
                &name(&bmp, Asn1Type::BMPSTRING),
                &server_key,
                Some((&ca, &ca_key)),
                false,
            );
            let client_ca_key = key();
            let client_ca = cert(
                &name("leaks client CA", Asn1Type::UTF8STRING),
                &client_ca_key,
                None,
                true,
            );
            let client_key = key();
            let client = cert(
                &name("client", Asn1Type::UTF8STRING),
                &client_key,
                Some((&client_ca, &client_ca_key)),
                false,
            );
            let mut cas = Stack::new().unwrap();
            cas.push(client_ca.clone()).unwrap();
            let p12 = Pkcs12::builder()
                .name("client")
                .pkey(&client_key)
                .cert(&client)
                .ca(cas)
                .build2("secret")
                .unwrap();
            let ca_file = write("ca.pem", &ca.to_pem().unwrap());
            let cert_file = write("server.pem", &server.to_pem().unwrap());
            let key_file = write(
                "server.key",
                &server_key.private_key_to_pem_pkcs8().unwrap(),
            );
            let client_ca_file = write("client-ca.pem", &client_ca.to_pem().unwrap());
            let p12 = write("client.p12", &p12.to_der().unwrap());
            let mut child = Command::new("openssl")
                .arg("s_server")
                .args(["-accept", "127.0.0.1:0", "-www", "-verify", "1"])
                .arg("-cert")
                .arg(&cert_file)
                .arg("-key")
                .arg(&key_file)
                .arg("-CAfile")
                .arg(&client_ca_file)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            let port = loop {
                line.clear();
                assert!(out.read_line(&mut line).unwrap() > 0, "s_server ended");
                if let Some(at) = line.trim().strip_prefix("ACCEPT 127.0.0.1:") {
                    break at.parse().unwrap();
                }
            };
            // What it says of each connection is read, and dropped.
            std::thread::spawn(move || std::io::copy(&mut out, &mut std::io::sink()));
            let bytes = |p: PathBuf| p.to_str().unwrap().as_bytes().to_vec();
            Server {
                child,
                port,
                dir,
                ca_file: bytes(ca_file),
                p12: bytes(p12),
            }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    pub(super) type Set = Box<dyn Fn(&mut Options)>;

    /// The transfers counted, each trusting the server's CA.
    pub(super) fn kinds(server: &Server) -> Vec<(&'static str, Set)> {
        let ca = server.ca_file.clone();
        let trusting = move |o: &mut Options| {
            o.tls.options.make_mut().unwrap().ca_file = CaSetting::Given(ca.clone());
        };
        let issuer = server.ca_file.clone();
        let p12 = server.p12.clone();
        vec![
            ("verified", Box::new(trusting.clone())),
            (
                "certinfo and issuer",
                Box::new({
                    let trusting = trusting.clone();
                    move |o| {
                        trusting(o);
                        o.tls.certinfo = true;
                        o.tls.options.make_mut().unwrap().issuer_cert = Some(issuer.clone());
                    }
                }),
            ),
            // Neither engines nor providers over AWS-LC.
            #[cfg(ossl3)]
            (
                "provider",
                Box::new({
                    let trusting = trusting.clone();
                    move |o| {
                        trusting(o);
                        o.tls.options.make_mut().unwrap().engine = Some(b"default".to_vec());
                    }
                }),
            ),
            #[cfg(ossl3)]
            (
                "engine",
                Box::new({
                    let trusting = trusting.clone();
                    // `loader_attic`, which OpenSSL 3 builds where it can
                    // load engines; on Windows the built-in `rdrand`, as
                    // vcpkg's OpenSSL has no engine of its own to load.
                    let engine = if cfg!(windows) {
                        &b"rdrand"[..]
                    } else {
                        b"loader_attic"
                    };
                    move |o| {
                        trusting(o);
                        o.tls.options.make_mut().unwrap().engine = Some(engine.to_vec());
                    }
                }),
            ),
            (
                "PKCS#12 with its CA",
                Box::new(move |o| {
                    trusting(o);
                    let t = o.tls.options.make_mut().unwrap();
                    t.cert = Some(p12.clone());
                    t.cert_type = Some(b"P12".to_vec());
                    t.key_password = Some(b"secret".to_vec());
                }),
            ),
        ]
    }

    struct Sink;

    impl WriteHandler for Sink {
        fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
            Write::Took(body.len())
        }
    }

    /// A GET of the server's page, in a handle of its own, freed after.
    pub(super) fn transfer(port: u16, set: &Set) -> Result<(), ErrorKind> {
        let mut easy = Easy::new();
        easy.set_libraries(SharedLibraries::of_static(&LIBRARIES));
        let o = easy.options_mut();
        let url = format!("https://localhost:{port}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.ip_version = IpVersion::V4;
        o.callbacks.write = Some(Handler::write(Sink).unwrap());
        set(o);
        easy.perform().map_err(|e| e.kind())
    }
}

/// `ERR_GET_LIB` and `ERR_GET_REASON` (`err.h`): a library's error packs
/// its library in the 8 bits above the 23 of its reason; a system
/// error, its top bit set, is the system library's, its reason the rest.
#[cfg(ossl3)]
#[test]
fn an_error_s_library_and_reason_are_as_err_h_unpacks_them() {
    use crate::ssl::{error_lib, error_reason};
    // `SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED`, `ERR_LIB_SSL`.
    assert_eq!(error_lib(0x0A00_045C), 20);
    assert_eq!(error_reason(0x0A00_045C), 1116);
    // `ERR_LIB_X509`, a reason of the most bits.
    assert_eq!(error_lib(0x05FF_FFFF), 11);
    assert_eq!(error_reason(0x05FF_FFFF), 0x7F_FFFF);
    // `ERR_LIB_SYS` and its `errno`, beyond the 23 bits.
    assert_eq!(error_lib(0x8000_0068), 2);
    assert_eq!(error_reason(0x8000_0068), 104);
    assert_eq!(error_lib(0x8123_4567), 2);
    assert_eq!(error_reason(0x8123_4567), 0x0123_4567);
}

/// LibreSSL's and the forks' `ERR_GET_LIB` and `ERR_GET_REASON`: its library in the top 8
/// bits, its reason in the low 12, its function between them; no system
/// flag.
#[cfg(not(ossl3))]
#[test]
fn an_error_s_library_and_reason_are_as_libressl_s_err_h_unpacks_them() {
    use crate::ssl::{error_lib, error_reason};
    // `SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED`, `ERR_LIB_SSL`.
    assert_eq!(error_lib(0x1400_045C), 20);
    assert_eq!(error_reason(0x1400_045C), 1116);
    // A function's bits are neither.
    assert_eq!(error_lib(0x0BFF_F088), 11);
    assert_eq!(error_reason(0x0BFF_F088), 0x088);
    // `ERR_LIB_SYS` and its `errno`.
    assert_eq!(error_lib(0x0200_0068), 2);
    assert_eq!(error_reason(0x0200_0068), 104);
}

/// The engines a transfer can name are the library's: `dynamic`, which
/// loads the rest, among them.
#[cfg(ossl3)]
#[test]
fn the_engines_are_the_library_s() {
    use curl_core::tls::TlsBackend as _;
    let engines = crate::OPENSSL.engines().unwrap();
    assert!(engines.iter().any(|e| e == b"dynamic"), "{engines:?}");
    assert_eq!(engines, crate::engine::ids().unwrap());
}

/// What the library declares it can do is what C's build over it has
/// (`Curl_ssl_openssl.supports`): over LibreSSL no signature algorithms
/// (`HAVE_SSL_CTX_SET1_SIGALGS` unset), the rest as over OpenSSL, the
/// engine option and the stapled status included; never Encrypted Client
/// Hello.
#[test]
fn the_library_declares_what_c_s_build_over_it_has() {
    use curl_core::tls::TlsBackend as _;
    let all = curl_core::tls::TlsSupport {
        ca_path: true,
        ca_blob: true,
        ca_cache: true,
        cert_info: true,
        pinned_key: true,
        context_handler: true,
        https_proxy: true,
        ciphers: true,
        tls13_ciphers: true,
        curves: true,
        signature_algorithms: true,
        crl_file: true,
        issuer_cert: true,
        issuer_cert_blob: true,
        ech: false,
        cert_status: true,
        engines: true,
    };
    let want = curl_core::tls::TlsSupport {
        signature_algorithms: !cfg!(libressl),
        tls13_ciphers: !cfg!(boringssl),
        cert_status: !cfg!(no_ocsp),
        ech: cfg!(boringssl_like),
        ..all
    };
    assert_eq!(crate::OPENSSL.support(), want);
}

/// The system's store is the default where C's build makes it so
/// (`CURL_CA_NATIVE`, `USE_APPLE_SECTRUST`), and only asked for in any
/// other: never OpenSSL's own.
#[test]
fn the_system_s_store_is_the_default_where_the_build_says() {
    use curl_core::tls::{SystemStore, TlsBackend as _};
    let native = cfg!(any(
        feature = "native-ca",
        all(target_os = "macos", feature = "apple-sectrust")
    ));
    let want = if native {
        SystemStore::Default
    } else {
        SystemStore::Asked
    };
    assert_eq!(crate::OPENSSL.ca_defaults().system, want);
}

/// `ossl_strerror`'s buffer of 256 bytes: the version and `: ` first if
/// they fit, with at least the text's zero byte after them; the text in
/// what is left.
#[test]
fn an_error_s_text_has_what_c_s_buffer_leaves_it() {
    use crate::x509::{after_version, no_text};
    for (version, room) in [
        (0, Some(254)),
        (13, Some(241)),
        (200, Some(54)),
        (253, Some(1)),
        (254, None),
        (300, None),
    ] {
        assert_eq!(after_version(version), room, "{version}");
    }
    assert_eq!(no_text(0), b"No error");
    assert_eq!(no_text(0x0A00_045C), b"Unknown error");
}
