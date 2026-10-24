//! What the client's first flight says (`ossl_connect_step1`,
//! `Curl_ossl_ctx_init`): the ClientHello a peer reads, before any TLS of
//! its own, as the bytes on the wire. The name it asks for (SNI), the
//! protocols it offers (ALPN), the options and lists the context is set
//! with.

use super::*;

pub(crate) const TESTS: &[(&str, fn())] = &[
    (
        "a_name_is_asked_for_in_lower_case_and_an_address_is_not",
        a_name_is_asked_for_in_lower_case_and_an_address_is_not,
    ),
    (
        "the_hello_offers_http_1_1_and_asks_for_no_ticket",
        the_hello_offers_http_1_1_and_asks_for_no_ticket,
    ),
    (
        "the_cipher_and_group_lists_are_the_ones_given",
        the_cipher_and_group_lists_are_the_ones_given,
    ),
    (
        "a_list_the_library_refuses_fails_as_c_says",
        a_list_the_library_refuses_fails_as_c_says,
    ),
];

/// A ClientHello, as far as these tests read it.
#[derive(Debug, Default)]
struct Hello {
    suites: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

/// `0x1301`..: the TLS 1.3 suites, which `CURLOPT_SSL_CIPHER_LIST` does
/// not name.
fn tls13(suite: u16) -> bool {
    suite >> 8 == 0x13
}

impl Hello {
    fn extension(&self, kind: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, data)| data.as_slice())
    }

    /// The host name asked for (`server_name`, 0).
    fn sni(&self) -> Option<Vec<u8>> {
        let data = self.extension(0)?;
        // The list's length, the name's type (0, a host name) and length.
        assert_eq!(data[2], 0, "a host name");
        let len = usize::from(u16::from_be_bytes([data[3], data[4]]));
        Some(data[5..5 + len].to_vec())
    }

    /// The protocols offered (`application_layer_protocol_negotiation`,
    /// 16).
    fn alpn(&self) -> Vec<Vec<u8>> {
        let Some(data) = self.extension(16) else {
            return Vec::new();
        };
        let mut protocols = Vec::new();
        let mut rest = &data[2..];
        while let [len, tail @ ..] = rest {
            let len = usize::from(*len);
            protocols.push(tail[..len].to_vec());
            rest = &tail[len..];
        }
        protocols
    }

    /// The two-byte entries of a list extension: `supported_groups` (10)
    /// or `signature_algorithms` (13).
    fn list(&self, kind: u16) -> Vec<u16> {
        let data = self.extension(kind).expect("the extension is sent");
        data[2..]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }
}

/// A peer that reads the client's first record, its ClientHello, and
/// closes the connection.
fn hello_reader() -> (SocketAddr, JoinHandle<Hello>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let reader = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let mut header = [0u8; 5];
        tcp.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 22, "a handshake record");
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut record = vec![0u8; len];
        tcp.read_exact(&mut record).unwrap();
        parse(&record)
    });
    (at, reader)
}

fn parse(record: &[u8]) -> Hello {
    assert_eq!(record[0], 1, "a ClientHello");
    let take = |at: &mut usize, n: usize| {
        let bytes = &record[*at..*at + n];
        *at += n;
        bytes
    };
    let len16 = |b: &[u8]| usize::from(u16::from_be_bytes([b[0], b[1]]));
    // The message's type and length, the version and the random.
    let mut at = 4 + 2 + 32;
    let session = usize::from(take(&mut at, 1)[0]);
    take(&mut at, session);
    let n = len16(take(&mut at, 2));
    let suites = take(&mut at, n)
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let n = usize::from(take(&mut at, 1)[0]);
    take(&mut at, n);
    let end = at + 2 + len16(take(&mut at, 2));
    let mut extensions = Vec::new();
    while at < end {
        let kind = u16::from_be_bytes(take(&mut at, 2).try_into().unwrap());
        let n = len16(take(&mut at, 2));
        extensions.push((kind, take(&mut at, n).to_vec()));
    }
    Hello { suites, extensions }
}

/// The hello of a transfer to `host` with the options `set` makes, and
/// what the transfer came to once the peer closed.
fn hello_to(host: &str, set: impl FnOnce(&mut Options)) -> (Hello, Got) {
    let (at, reader) = hello_reader();
    let got = get(host, at, |o| {
        // The name resolves to the reader, whatever it is.
        let entry = format!("{host}:{}:127.0.0.1", at.port());
        o.resolve.set([entry.as_bytes()]).unwrap();
        set(o);
    });
    (reader.join().unwrap(), got)
}

/// SNI (RFC 6066 3): the URL's name without its trailing dot, in lower
/// case; nothing for an address (`Curl_ssl_peer_init`).
fn a_name_is_asked_for_in_lower_case_and_an_address_is_not() {
    let (hello, got) = hello_to("localhost", |_| {});
    assert_eq!(hello.sni().as_deref(), Some(&b"localhost"[..]));
    assert_eq!(got.result, Err(ErrorKind::SslConnectError));
    let (hello, _) = hello_to("Curl.Example.", |_| {});
    assert_eq!(hello.sni().as_deref(), Some(&b"curl.example"[..]));
    let (hello, _) = hello_to("127.0.0.1", |_| {});
    assert_eq!(hello.sni(), None);
}

/// The protocol HTTP/1.1 offers by ALPN; and no session ticket asked for,
/// as C's context options say (`SSL_OP_NO_TICKET`, with `SSL_OP_ALL`).
fn the_hello_offers_http_1_1_and_asks_for_no_ticket() {
    let (hello, _) = hello_to("localhost", |_| {});
    assert_eq!(hello.alpn(), [b"http/1.1".to_vec()]);
    // `session_ticket` (35).
    assert_eq!(hello.extension(35), None, "{hello:?}");
    // Asked for in a hello without the option, as the library's default.
    assert!(hello.extension(43).is_some(), "supported_versions sent");
}

/// `--ciphers`, `--tls13-ciphers`, `--curves` and `--sigalgs`: the hello
/// offers what each names and nothing else of its kind, each choice said;
/// with TLS 1.3 as the floor, the TLS 1.2 list is not set.
fn the_cipher_and_group_lists_are_the_ones_given() {
    let (hello, got) = hello_to("localhost", |o| {
        let t = o.tls.options.make_mut().unwrap();
        t.ciphers = Some(b"ECDHE-ECDSA-AES128-GCM-SHA256".to_vec());
        t.tls13_ciphers = Some(b"TLS_CHACHA20_POLY1305_SHA256".to_vec());
        t.curves = Some(b"X25519:P-384".to_vec());
        t.signature_algorithms = Some(b"ECDSA+SHA384:ed25519".to_vec());
    });
    // TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
    assert_eq!(hello.suites, [0x1303, 0xc02b], "{hello:?}");
    // x25519, secp384r1.
    assert_eq!(hello.list(10), [0x001d, 0x0018]);
    // ecdsa_secp384r1_sha384, ed25519.
    assert_eq!(hello.list(13), [0x0503, 0x0807]);
    for line in [
        "Cipher selection: ECDHE-ECDSA-AES128-GCM-SHA256",
        "TLS 1.3 cipher selection: TLS_CHACHA20_POLY1305_SHA256",
    ] {
        assert!(said(&got, line), "no {line:?} in {:#?}", got.seen.lines);
    }
    let (hello, got) = hello_to("localhost", |o| {
        let t = o.tls.options.make_mut().unwrap();
        t.min_version = curl_core::options::TlsMinVersion::Tls1_3;
        t.ciphers = Some(b"ECDHE-ECDSA-AES128-GCM-SHA256".to_vec());
    });
    assert!(hello.suites.iter().all(|&s| tls13(s)), "{hello:?}");
    assert!(hello.suites.len() > 1, "the library's own TLS 1.3 list");
    assert!(!starts(&got, "Cipher selection:"), "{:#?}", got.seen.lines);
    // With TLS 1.2 as the ceiling, the TLS 1.3 list is not set.
    let (hello, got) = hello_to("localhost", |o| {
        let t = o.tls.options.make_mut().unwrap();
        t.max_version = curl_core::options::TlsMaxVersion::Tls1_2;
        t.tls13_ciphers = Some(b"TLS_CHACHA20_POLY1305_SHA256".to_vec());
    });
    assert!(!hello.suites.iter().any(|&s| tls13(s)), "{hello:?}");
    assert!(!starts(&got, "TLS 1.3 cipher selection:"));
}

/// A list naming nothing the library knows fails the transfer with 59,
/// before anything is sent, said as C says it.
fn a_list_the_library_refuses_fails_as_c_says() {
    type Set = Box<dyn Fn(&mut curl_core::options::TlsOptions)>;
    let cases: [(Set, &str); 4] = [
        (
            Box::new(|t| t.ciphers = Some(b"NOSUCH".to_vec())),
            "failed setting cipher list: NOSUCH",
        ),
        (
            Box::new(|t| t.tls13_ciphers = Some(b"NOSUCH".to_vec())),
            "failed setting TLS 1.3 cipher suite: NOSUCH",
        ),
        (
            Box::new(|t| t.curves = Some(b"NOSUCH".to_vec())),
            "failed setting curves list: 'NOSUCH'",
        ),
        (
            Box::new(|t| t.signature_algorithms = Some(b"NOSUCH".to_vec())),
            "failed setting signature algorithms: 'NOSUCH'",
        ),
    ];
    for (set, failure) in cases {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap();
        let got = get("localhost", at, |o| set(o.tls.options.make_mut().unwrap()));
        assert_eq!(got.result, Err(ErrorKind::SslCipher), "{failure}");
        assert_eq!(String::from_utf8(got.failure).unwrap(), failure);
        // Nothing was sent: the connection is there, unread.
        listener.set_nonblocking(true).unwrap();
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_nonblocking(false).unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(tcp.read(&mut buf).unwrap(), 0, "{failure}");
    }
}
