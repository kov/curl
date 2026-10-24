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
#[test]
fn a_transfer_frees_what_it_made_of_openssl_s() {
    crate::sys::tests::in_a_child("tests::counted_transfers", "/dev/null".as_ref());
}

#[test]
#[ignore = "run by a_transfer_frees_what_it_made_of_openssl_s"]
fn counted_transfers() {
    crate::sys::tests::count_allocations();
    let server = leaks::Server::start();
    let kinds = leaks::kinds(&server);
    let round = || {
        for (name, set) in &kinds {
            let result = leaks::transfer(server.port, set);
            assert_eq!(result, Ok(()), "{name}");
        }
    };
    round();
    round();
    let before = crate::sys::tests::live_allocations();
    assert!(before > 0, "the library's allocations are counted");
    for (name, set) in &kinds {
        let at = crate::sys::tests::live_allocations();
        for _ in 0..3 {
            leaks::transfer(server.port, set).unwrap();
        }
        let left = crate::sys::tests::live_allocations() - at;
        assert_eq!(
            left, 0,
            "{name}: {left} of OpenSSL's allocations left by 3 transfers"
        );
    }
    assert_eq!(crate::sys::tests::live_allocations(), before);
}

/// The server and the transfers `counted_transfers` makes.
mod leaks {
    use std::io::BufRead as _;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    use curl_core::easy::Easy;
    use curl_core::error::ErrorKind;
    use curl_core::handler::{Handler, Write, WriteHandler};
    use curl_core::libraries::Libraries;
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
        tls: Some(&crate::OPENSSL),
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
            (
                "engine",
                Box::new({
                    let trusting = trusting.clone();
                    move |o| {
                        trusting(o);
                        o.tls.options.make_mut().unwrap().engine = Some(b"loader_attic".to_vec());
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
        easy.set_libraries(&LIBRARIES);
        let o = easy.options_mut();
        let url = format!("https://localhost:{port}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.ip_version = IpVersion::V4;
        o.callbacks.write = Some(Handler::write(Sink).unwrap());
        set(o);
        easy.perform().map_err(|e| e.kind())
    }
}
