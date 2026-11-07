use super::*;
use crate::options::{
    CaSetting, ColdGroup as _, Ech, EchMode, EchWord, SslOptions, TlsMaxVersion, TlsMinVersion,
};

pub(super) fn identity(change: impl FnOnce(&mut TlsIdentity)) -> TlsIdentity {
    let mut id = TlsIdentity {
        verify_peer: true,
        verify_host: true,
        options: TlsOptions::NONE,
        ca_defaults: CaDefaults {
            file: Some("/default/ca.pem"),
            path: None,
            system: SystemStore::Asked,
        },
    };
    change(&mut id);
    id
}

fn text(t: &str) -> Option<Vec<u8>> {
    Some(t.as_bytes().to_vec())
}

/// unit3303: a client's certificate, key, password and types; the same
/// again matches, and another password, key, key type or certificate
/// type each does not, until it is put back.
#[test]
fn unit3303_client_identity() {
    let client = |i: &mut TlsIdentity| {
        i.options.cert = text("client.pem");
        i.options.key = text("client.key");
        i.options.key_password = text("secret");
        i.options.cert_type = text("PEM");
        i.options.key_type = text("PEM");
    };
    let base = identity(client);
    assert_eq!(base, identity(client), "identical");
    type Change = fn(&mut TlsIdentity);
    let changes: [(&str, Change); 4] = [
        ("key_password", |i| i.options.key_password = text("wrong")),
        ("key", |i| i.options.key = text("other.key")),
        ("key_type", |i| i.options.key_type = text("DER")),
        ("cert_type", |i| i.options.cert_type = text("P12")),
    ];
    for (name, change) in changes {
        let mut changed = identity(client);
        change(&mut changed);
        assert_ne!(base, changed, "{name}");
        client(&mut changed);
        assert_eq!(base, changed, "{name} put back");
    }
}

/// Two identities match only if every setting does, as
/// `match_ssl_primary_config` compares them: a change to any one makes
/// a connection serve no transfer that has the other.
#[test]
fn every_setting_tells_two_identities_apart() {
    type Change = fn(&mut TlsIdentity);
    let changes: &[(&str, Change)] = &[
        ("verify_peer", |i| i.verify_peer = false),
        ("verify_host", |i| i.verify_host = false),
        ("min_version", |i| {
            i.options.min_version = TlsMinVersion::Tls1_3
        }),
        ("max_version", |i| {
            i.options.max_version = TlsMaxVersion::Default
        }),
        ("ssl_options", |i| {
            i.options.ssl_options = SslOptions::NO_REVOKE
        }),
        ("verify_status", |i| i.options.verify_status = true),
        ("ca_file", |i| i.options.ca_file = CaSetting::Unset),
        ("ca_path", |i| {
            i.options.ca_path = CaSetting::Given(b"/etc/ssl/certs".to_vec());
        }),
        ("ca_blob", |i| {
            i.options.ca_blob = CaSetting::Given(b"pem".to_vec())
        }),
        ("crl_file", |i| i.options.crl_file = text("crl")),
        ("issuer_cert", |i| i.options.issuer_cert = text("issuer")),
        ("issuer_cert_blob", |i| {
            i.options.issuer_cert_blob = text("i")
        }),
        ("cert", |i| i.options.cert = text("client.crt")),
        ("cert_blob", |i| i.options.cert_blob = text("c")),
        ("cert_type", |i| i.options.cert_type = text("DER")),
        ("key", |i| i.options.key = text("client.key")),
        ("key_blob", |i| i.options.key_blob = text("k")),
        ("key_type", |i| i.options.key_type = text("PEM")),
        ("key_password", |i| i.options.key_password = text("secret")),
        ("ciphers", |i| i.options.ciphers = text("AES128-SHA")),
        ("tls13_ciphers", |i| {
            i.options.tls13_ciphers = text("TLS_AES_128_GCM_SHA256")
        }),
        ("curves", |i| i.options.curves = text("X25519")),
        ("signature_algorithms", |i| {
            i.options.signature_algorithms = text("ed25519");
        }),
        ("pinned_key", |i| {
            i.options.pinned_key = text("sha256//AAAA")
        }),
        ("ech mode", |i| i.options.ech.mode = EchMode::Grease),
        ("ech config", |i| i.options.ech.config = text("AEv+DQ==")),
        ("ech public name", |i| {
            i.options.ech.public_name = text("public.example")
        }),
    ];
    let plain = identity(|_| {});
    assert_eq!(plain, identity(|_| {}));
    for (name, change) in changes {
        let changed = identity(change);
        assert_ne!(plain, changed, "{name}");
        assert_ne!(changed, plain, "{name}");
        assert_eq!(changed, identity(change), "{name}");
    }
}

/// The lists and the formats match in any case (`curl_strequal`); the
/// paths, the keys and the password only exactly (`Curl_safecmp`,
/// `Curl_timestrcmp`).
#[test]
fn lists_match_in_any_case_and_paths_exactly() {
    let lists = identity(|i| {
        i.options.ciphers = text("aes128-sha");
        i.options.tls13_ciphers = text("tls_aes_128_gcm_sha256");
        i.options.curves = text("x25519");
        i.options.signature_algorithms = text("ED25519");
        i.options.cert_type = text("der");
        i.options.key_type = text("pem");
    });
    let shouted = identity(|i| {
        i.options.ciphers = text("AES128-SHA");
        i.options.tls13_ciphers = text("TLS_AES_128_GCM_SHA256");
        i.options.curves = text("X25519");
        i.options.signature_algorithms = text("ed25519");
        i.options.cert_type = text("DER");
        i.options.key_type = text("PEM");
    });
    assert_eq!(lists, shouted);
    let paths = |t: &str| {
        identity(|i| {
            i.options.ca_file = CaSetting::Given(t.as_bytes().to_vec());
            i.options.key = text(t);
        })
    };
    assert_ne!(paths("/certs/ca.pem"), paths("/certs/CA.pem"));
    let password = |t: &str| identity(|i| i.options.key_password = text(t));
    assert_ne!(password("secret"), password("SECRET"));
    assert_ne!(password("secret"), password("secre"));
    assert_eq!(password("secret"), password("secret"));
}

/// The CA file and path compare as they apply: a transfer that names
/// the library's default file matches one that keeps the default, as in
/// C, which copies the default into the setting; one that sets none
/// matches neither. Defaults the library does not have resolve to none.
/// Where the library makes the system's store the default, naming a file
/// turns it off, and the two do not match (`native_ca_store`).
#[test]
fn the_ca_default_compares_as_the_file_it_names() {
    for system in [SystemStore::Asked, SystemStore::Default, SystemStore::Own] {
        let with = |change: Change| {
            identity(|i| {
                i.ca_defaults.system = system;
                change(i);
            })
        };
        let by_default = system == SystemStore::Default;
        let kept = with(|_| {});
        let named = with(|i| i.options.ca_file = CaSetting::Given(b"/default/ca.pem".to_vec()));
        let none = with(|i| i.options.ca_file = CaSetting::Unset);
        assert_eq!(kept == named, !by_default, "{system:?}");
        assert_ne!(kept, none);
        assert_ne!(named, none);
        assert_eq!(kept.ca_file(), Some(&b"/default/ca.pem"[..]));
        assert_eq!(none.ca_file(), None);
        // No default path: keeping it is having none.
        let no_path = with(|i| i.options.ca_path = CaSetting::Unset);
        assert_eq!(kept == no_path, !by_default, "{system:?}");
        assert_eq!(kept.ca_path(), None);
        let other_default = with(|i| i.ca_defaults.file = Some("/other/ca.pem"));
        assert_ne!(kept, other_default);
    }
}

/// The system's store is used where asked for, or, by a library that
/// makes it the default, where the transfer names no file, directory or
/// blob of its own, naming none counting as naming one (`custom_cafile`,
/// `custom_cablob`). A library whose own store it is sets no default
/// (C's `!= CURLSSLBACKEND_SCHANNEL`).
#[test]
fn the_native_store_is_the_default_only_where_no_ca_is_named() {
    let of = |system| identity(|i| i.ca_defaults.system = system);
    assert!(of(SystemStore::Default).native_ca_store());
    assert!(!of(SystemStore::Asked).native_ca_store());
    assert!(!of(SystemStore::Own).native_ca_store());
    for system in [SystemStore::Asked, SystemStore::Default, SystemStore::Own] {
        let asked = identity(|i| {
            i.ca_defaults.system = system;
            i.options.ssl_options = SslOptions::NATIVE_CA;
        });
        assert!(asked.native_ca_store(), "{system:?}");
    }
    let named: [Change; 5] = [
        |i| i.options.ca_file = CaSetting::Given(b"/certs/ca.pem".to_vec()),
        |i| i.options.ca_file = CaSetting::Unset,
        |i| i.options.ca_path = CaSetting::Given(b"/certs".to_vec()),
        |i| i.options.ca_blob = CaSetting::Given(b"PEM".to_vec()),
        |i| i.options.ca_blob = CaSetting::Unset,
    ];
    for change in named {
        let id = identity(|i| {
            i.ca_defaults.system = SystemStore::Default;
            change(i);
        });
        assert!(!id.native_ca_store());
    }
}

/// A blob set to nothing holds no certificates, as one never set, so the
/// two match where that is all they differ by; but where the library
/// makes the system's store the default, one uses it and the other does
/// not, and they do not match (`match_ssl_primary_config`'s
/// `native_ca_store`).
#[test]
fn a_blob_set_to_nothing_matches_one_never_set_unless_the_store_differs() {
    for system in [SystemStore::Asked, SystemStore::Default, SystemStore::Own] {
        let never = identity(|i| i.ca_defaults.system = system);
        let nothing = identity(|i| {
            i.ca_defaults.system = system;
            i.options.ca_blob = CaSetting::Unset;
        });
        assert_eq!(nothing.ca_blob(), None);
        assert_eq!(
            never == nothing,
            system != SystemStore::Default,
            "{system:?}"
        );
    }
}

type Change = fn(&mut TlsIdentity);

/// Whether ALPN is offered is the handle's, not the connection's: C
/// matches no connection by it.
#[test]
fn alpn_does_not_tell_identities_apart() {
    assert_eq!(identity(|i| i.options.alpn = false), identity(|_| {}));
}

/// A transfer's identity is its options', copied, so a change to the
/// options after does not change a connection made with it.
#[test]
fn an_identity_copies_the_options() {
    let mut tls = Tls::default();
    tls.options.make_mut().unwrap().ca_blob = CaSetting::Given(b"pem".to_vec());
    let id = TlsIdentity::of(&tls, CaDefaults::NONE).unwrap();
    tls.options.make_mut().unwrap().ca_blob = CaSetting::Given(b"other".to_vec());
    tls.verify_peer = false;
    assert_eq!(id.options.ca_blob, CaSetting::Given(b"pem".to_vec()));
    assert!(id.verify_peer);
}

/// A copy of a handle's options (`curl_easy_duphandle`) keeps its TLS
/// settings: the verify bits, the options few transfers set, and each CA
/// setting as it was, named, none or the default.
#[test]
fn a_copy_of_the_options_keeps_the_tls_settings() {
    let mut o = crate::options::Options::default();
    o.tls.verify_peer = false;
    o.tls.verify_host = false;
    let tls = o.tls.options.make_mut().unwrap();
    tls.ca_file = CaSetting::Given(b"/certs/ca.pem".to_vec());
    tls.ca_path = CaSetting::Unset;
    tls.ssl_options = SslOptions::NO_REVOKE;
    tls.key_password = text("secret");
    let copy = o.try_clone().unwrap();
    assert!(!copy.tls.verify_peer);
    assert!(!copy.tls.verify_host);
    assert_eq!(*copy.tls.options, *o.tls.options);
    assert_eq!(
        copy.tls.options.ca_file,
        CaSetting::Given(b"/certs/ca.pem".to_vec())
    );
    assert_eq!(copy.tls.options.ca_path, CaSetting::Unset);
    // One left at the default stays the default.
    let kept = crate::options::Options::default().try_clone().unwrap();
    assert_eq!(kept.tls.options.ca_file, CaSetting::Default);
    assert!(kept.tls.verify_peer && kept.tls.verify_host);
}

/// The bits of `CURLOPT_SSL_OPTIONS` are a set: each one apart from the
/// others and from none, and a set holds what was put in it.
#[test]
fn ssl_options_are_sets() {
    use SslOptions as S;
    let bits = [
        S::ALLOW_BEAST,
        S::NO_REVOKE,
        S::NO_PARTIALCHAIN,
        S::REVOKE_BEST_EFFORT,
        S::NATIVE_CA,
        S::AUTO_CLIENT_CERT,
        S::EARLYDATA,
    ];
    assert!(S::NONE.contains(S::NONE));
    for (i, &a) in bits.iter().enumerate() {
        assert!(a.contains(a), "{i}");
        assert!(a.contains(S::NONE), "{i}");
        assert!(!S::NONE.contains(a), "{i}");
        assert_eq!(a | a, a, "{i}");
        assert_eq!(a | S::NONE, a, "{i}");
        for (j, &b) in bits.iter().enumerate().filter(|&(j, _)| j != i) {
            assert!(!a.contains(b), "{i} {j}");
            let both = a | b;
            assert!(both.contains(a) && both.contains(b), "{i} {j}");
            assert!(!a.contains(both), "{i} {j}");
        }
    }
}

/// The ALPN offer as the handshake puts it on the wire, each name after
/// its length (`Curl_alpn_to_proto_buf`), and as C traces it, the names
/// between commas (`Curl_alpn_to_proto_str`); with ALPN off, none.
#[test]
fn an_alpn_offer_is_put_as_c_puts_it() {
    assert_eq!(Alpn::None.wire(), b"");
    assert_eq!(Alpn::None.offer(), None);
    assert_eq!(Alpn::Http11.wire(), b"\x08http/1.1");
    assert_eq!(Alpn::Http11.offer(), Some("http/1.1"));
    assert_eq!(Alpn::Http10.wire(), b"\x08http/1.0\x08http/1.1");
    assert_eq!(Alpn::Http10.offer(), Some("http/1.0,http/1.1"));
    // QUIC's, as C's ngtcp2 filter offers it: HTTP/3 alone, by both
    // names, and only `h3` taken as its choice.
    assert_eq!(Alpn::H3.wire(), b"\x02h3\x05h3-29");
    assert!(Alpn::H3.offers(Chosen::H3));
    assert!(!Alpn::H3.offers(Chosen::H2));
    assert!(!Alpn::H2Http11.offers(Chosen::H3));
    assert_eq!(Chosen::named(b"h3"), Some(Chosen::H3));
    assert_eq!(Chosen::H3.wire(), b"\x02h3");
}

/// A session is an HTTPS proxy's when its layer is the TLS to an HTTPS
/// proxy or the QUIC to an HTTP/3 one (`Curl_ssl_cf_is_proxy`), and the
/// origin's otherwise: what OpenSSL's verbose lines call its certificate.
#[test]
fn a_session_is_a_proxy_s_as_its_layer_is() {
    let identity = TryArc::try_new(identity(|_| {})).unwrap();
    let origin = Peer::new(
        crate::proto::http::HTTPS,
        b"example.com".to_vec(),
        443,
        None,
    );
    let peer =
        SessionPeer::new(&identity, &origin, None, &"test", crate::conn::Dial::Stream).unwrap();
    let mut notes = Notes::default();
    for component in Component::ALL {
        let cx = TlsCx::new(&mut notes, component, &peer);
        let proxy = matches!(component, Component::SslProxy | Component::H3Proxy);
        assert_eq!(cx.for_proxy(), proxy, "{component:?}");
    }
}

/// The names an offer holds come out one by one, in its order, for the
/// libraries that take them so.
#[test]
fn an_offer_s_names_come_in_its_order() {
    let names = |a: Alpn| a.names().map(<[u8]>::to_vec).collect::<Vec<_>>();
    assert!(names(Alpn::None).is_empty());
    assert_eq!(
        names(Alpn::H2Http11),
        [b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert_eq!(
        names(Alpn::Http10),
        [b"http/1.0".to_vec(), b"http/1.1".to_vec()]
    );
    assert_eq!(names(Alpn::H3), [b"h3".to_vec(), b"h3-29".to_vec()]);
}

/// SNI names a host in lower case without its trailing dot, and no
/// address, nor a name of 64 KiB or more (`Curl_ssl_peer_init`).
#[test]
fn sni_names_a_host_in_lower_case_without_its_dot() {
    assert_eq!(
        sni(b"WWW.Example.COM.", TlsPeerKind::Name).unwrap(),
        Some(b"www.example.com".to_vec())
    );
    assert_eq!(sni(b"127.0.0.1", TlsPeerKind::Ipv4).unwrap(), None);
    assert_eq!(sni(b"::1", TlsPeerKind::Ipv6).unwrap(), None);
    let long = vec![b'a'; usize::from(u16::MAX)];
    assert_eq!(sni(&long, TlsPeerKind::Name).unwrap(), None);
    let fits = vec![b'a'; usize::from(u16::MAX) - 1];
    assert_eq!(sni(&fits, TlsPeerKind::Name).unwrap(), Some(fits.clone()));
}

/// What the peer chose is said as C says it, and refused where it may
/// not be: a protocol asked for alone must be chosen again, and a name
/// with a zero byte is none.
#[test]
fn the_protocol_chosen_is_said_and_refused_as_c_does() {
    let id = TryArc::try_new(identity(|_| {})).unwrap();
    let run = |asked: Option<&[u8]>, chosen: &[u8]| {
        let mut notes = Notes::default();
        let r = TlsCx::testing(&id, b"example.com", &mut notes, |_, cx| {
            alpn_negotiated(cx, asked, chosen)
        });
        (r, notes.0)
    };
    let (r, notes) = run(None, b"h2");
    assert_eq!(r, Ok(()));
    assert_eq!(notes, ["info: ALPN: server accepted h2"]);
    let (r, notes) = run(None, b"");
    assert_eq!(r, Ok(()));
    assert_eq!(
        notes,
        ["info: ALPN: server did not agree on a protocol. Uses default."]
    );
    let (r, notes) = run(None, b"h\0");
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert_eq!(
        notes,
        [
            "fail: SslConnectError: ALPN: server selected protocol contains NUL. Refusing to continue."
        ]
    );
    let (r, notes) = run(Some(b"h2"), b"h2");
    assert_eq!(r, Ok(()));
    assert_eq!(notes, ["info: ALPN: server confirmed to use 'h2'"]);
    let (r, notes) = run(Some(b"h2"), b"http/1.1");
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert_eq!(
        notes,
        [
            "fail: SslConnectError: ALPN: asked for 'h2' from previous session, but server selected 'http/1.1'. Refusing to continue."
        ]
    );
    let (r, notes) = run(Some(b"h2"), b"");
    assert_eq!(r, Err(ErrorKind::SslConnectError));
    assert_eq!(
        notes,
        [
            "fail: SslConnectError: ALPN: asked for 'h2' from previous session, but server did not confirm it. Refusing to continue."
        ]
    );
}

/// A C string is the bytes and one zero after them, read back up to the
/// first zero, as C reads it.
#[test]
fn a_c_string_ends_in_one_zero() {
    assert_eq!(c_string(b"name"), Ok(b"name\0".to_vec()));
    assert_eq!(c_string(b""), Ok(b"\0".to_vec()));
    let made = c_string(b"na\0me").unwrap();
    assert_eq!(made, b"na\0me\0");
    assert_eq!(as_c(&made).to_bytes(), b"na");
}

/// ECH's configuration and outer name are kept apart from its mode, as
/// `setopt_ech` keeps them: each replaces its own; one given while ECH
/// is off makes it hard, and a mode given after says what it is; `false`
/// turns it off and keeps both, so a connection made with them still
/// serves only a transfer that has them.
#[test]
fn ech_words_change_their_own_setting() {
    let words = |said: &[&str]| {
        let mut ech = Ech::NONE;
        for word in said {
            let word = EchWord::parse(word.as_bytes()).expect("a word");
            ech.apply(word).expect("memory");
        }
        ech
    };
    let ech = |mode, config: Option<&str>, public_name: Option<&str>| Ech {
        mode,
        config: config.and_then(text),
        public_name: public_name.and_then(text),
    };
    assert_eq!(words(&["grease"]), ech(EchMode::Grease, None, None));
    assert_eq!(words(&["true"]), ech(EchMode::Try, None, None));
    assert_eq!(words(&["hard"]), ech(EchMode::Hard, None, None));
    assert_eq!(words(&["ecl:QUJD"]), ech(EchMode::Hard, Some("QUJD"), None));
    assert_eq!(
        words(&["pn:p.example"]),
        ech(EchMode::Hard, None, Some("p.example"))
    );
    // The tool's order: the name, the list, then the mode.
    assert_eq!(
        words(&["pn:p.example", "ecl:QUJD", "true"]),
        ech(EchMode::Try, Some("QUJD"), Some("p.example"))
    );
    // A list after a mode leaves the mode.
    assert_eq!(
        words(&["grease", "ecl:QUJD"]),
        ech(EchMode::Grease, Some("QUJD"), None)
    );
    assert_eq!(
        words(&["ecl:QUJD", "false"]),
        ech(EchMode::Off, Some("QUJD"), None)
    );
    assert_eq!(
        words(&["ecl:QUJD", "ecl:REVG"]),
        ech(EchMode::Hard, Some("REVG"), None)
    );
    assert_eq!(words(&["true", "false"]), Ech::NONE);
}

/// The words are C's, in lower case, a prefix with something after it.
#[test]
fn ech_words_are_c_s() {
    for word in [
        "", "TRUE", "True", "yes", "ecl:", "pn:", "ECL:QUJD", "PN:x", "grease ",
    ] {
        assert_eq!(EchWord::parse(word.as_bytes()), None, "{word:?}");
    }
    assert_eq!(EchWord::parse(b"false"), Some(EchWord::Mode(EchMode::Off)));
    assert_eq!(EchWord::parse(b"ecl:A"), Some(EchWord::Config(b"A")));
    assert_eq!(EchWord::parse(b"pn:a"), Some(EchWord::PublicName(b"a")));
}

/// ECH is the origin's alone: an HTTPS proxy's TLS never tries it,
/// whatever its own options hold (`Curl_ssl_conn_config_init`).
#[test]
fn an_https_proxy_tries_no_ech() {
    let mut proxy = crate::options::Tls::NONE;
    proxy.options.make_mut().expect("memory").ech = Ech {
        mode: EchMode::Hard,
        config: text("QUJD"),
        public_name: text("p.example"),
    };
    let origin = TlsOptions::NONE;
    let id = TlsIdentity::of_proxy(&proxy, &origin, CaDefaults::NONE).expect("memory");
    assert_eq!(id.options.ech, Ech::NONE);
}

/// ECH asks for the library's support once anything of it is set, as C
/// refuses `CURLOPT_ECH` whatever its value where it is not built in.
#[test]
fn ech_asks_for_the_library_s_support() {
    let mut origin = crate::options::Tls::NONE;
    let proxy = crate::options::Tls::NONE;
    assert!(!TlsSupport::asked_by(&origin, &proxy, false).ech);
    origin.options.make_mut().expect("memory").ech.config = text("QUJD");
    let asked = TlsSupport::asked_by(&origin, &proxy, false);
    assert!(asked.ech);
    assert_eq!(TlsSupport::NONE.lacking(&asked), Some("ECH"));
}
