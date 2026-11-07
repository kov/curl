//! The rustls crate, called as rustls-ffi 0.15.5 calls it for each of the
//! calls `lib/vtls/rustls.c` makes of rustls-ffi (`library.rs`), with the
//! crypto provider it builds with, aws-lc-rs's default. C's process-wide
//! default provider, which rustls-ffi installs at its first use, is a
//! value here, made where each call needs it: the provider holds nothing
//! but its lists.
//!
//! rustls takes its objects in std's `Arc` and allocates as it likes,
//! failing no allocation; its allocations are the library's, as C's
//! rustls-ffi's are, which C's memory debugging never sees, and the debug
//! build's tracker does not count them either (`quiet`).

// rustls's own objects are std's `Arc`s, made only as rustls takes them.
#![allow(
    clippy::disallowed_methods,
    reason = "rustls takes its objects in std's `Arc`, which cannot be made fallibly"
)]

use std::io;
use std::sync::Arc;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::tls::SharedKeyLog;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{
    EchConfig, EchGreaseConfig, EchMode, ResolvesClientCert, WebPkiServerVerifier,
};
use rustls::crypto::{CryptoProvider, aws_lc_rs, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, EchConfigListBytes, PrivateKeyDer, ServerName,
    UnixTime,
};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, KeyLog, ProtocolVersion, RootCertStore,
    SignatureScheme, SupportedCipherSuite, SupportedProtocolVersion,
};

use crate::library::{Call, Errno, Moved, Plain, Suite};
use crate::result::{Code, map_error, map_verifier_builder_error};

/// The library itself.
pub(crate) static RUSTLS: Real = Real;

/// rustls, as rustls-ffi calls it.
#[derive(Debug)]
pub(crate) struct Real;

/// Run `f`, a call into rustls, its allocations kept from the debug
/// build's tracker.
fn quiet<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(feature = "debug-hooks")]
    return curl_alloc::track::untracked(f);
    #[cfg(not(feature = "debug-hooks"))]
    f()
}

/// Run `f`, a call rustls makes back into the connection below, tracked
/// again: those allocations are curl's, which C's tracker counts.
fn loud<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(feature = "debug-hooks")]
    return curl_alloc::track::tracked(f);
    #[cfg(not(feature = "debug-hooks"))]
    f()
}

/// A suite of the library's, as the session takes it.
fn suite(s: SupportedCipherSuite) -> Suite {
    Suite {
        id: u16::from(s.suite()),
        tls13: s.version() == &rustls::version::TLS13,
    }
}

/// The provider rustls-ffi takes for its default
/// (`get_default_or_install_from_crate_features`).
fn provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

/// A configuration being built: what rustls-ffi's builder holds.
#[derive(Debug)]
pub(crate) struct Builder {
    provider: Arc<CryptoProvider>,
    versions: Vec<&'static SupportedProtocolVersion>,
    verifier: Option<Arc<dyn ServerCertVerifier>>,
    alpn: Vec<Vec<u8>>,
    key: Option<Arc<CertifiedKey>>,
    key_log: Option<Arc<dyn KeyLog>>,
    /// Encrypted Client Hello, in place of the versions.
    ech: Option<EchMode>,
}

/// The builder's versions are other than TLS 1.3 alone, which ECH needs
/// (rustls-ffi's check, none being the default's).
fn not_tls13_only(builder: &Builder) -> bool {
    !builder.versions.is_empty() && builder.versions[..] != [&rustls::version::TLS13]
}

/// A configuration built.
#[derive(Debug)]
pub(crate) struct Config(Arc<ClientConfig>);

/// The verifier C sets where the peer is not checked
/// (`cr_verify_none` through rustls-ffi's `Verifier`): any chain is
/// verified, and the handshake's signatures checked with the provider's
/// algorithms.
#[derive(Debug)]
struct VerifyNone(Arc<CryptoProvider>);

impl ServerCertVerifier for VerifyNone {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The client's certificate, offered where the server's signature schemes
/// allow its key (rustls-ffi's `ResolvesClientCertFromChoices`, of one).
#[derive(Debug)]
struct OneKey(Arc<CertifiedKey>);

impl ResolvesClientCert for OneKey {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sig_schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.0
            .key
            .choose_scheme(sig_schemes)
            .is_some()
            .then(|| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Each secret written to the key log (`cr_keylog_log_cb`).
#[derive(Debug)]
struct Keys(SharedKeyLog);

impl KeyLog for Keys {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        // The client's random is 32 bytes (`CLIENT_RANDOM_SIZE`), as C
        // asserts.
        let random = <&[u8; 32]>::try_from(client_random).expect("a client random of 32 bytes");
        // A secret the log does not take goes unsaid, as C's
        // `Curl_tls_keylog_write` says nothing of it.
        self.0.write_secret(label.as_bytes(), random, secret);
    }
}

/// The certificates of `pem`, each of which must parse, in a store of
/// their own (rustls-ffi's strict `add_pem`).
fn strict_roots(pem: &[u8]) -> Result<RootCertStore, Code> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Code::CertificateParseError)?;
    let mut roots = RootCertStore::empty();
    let (parsed, rejected) = roots.add_parsable_certificates(certs);
    if rejected > 0 || parsed == 0 {
        return Err(Code::CertificateParseError);
    }
    Ok(roots)
}

impl crate::library::Rustls for Real {
    type Builder = Builder;
    type Roots = RootCertStore;
    type Crls = Vec<CertificateRevocationListDer<'static>>;
    type Verifier = Arc<dyn ServerCertVerifier>;
    type Key = Arc<CertifiedKey>;
    type Config = Config;
    type Conn = Conn;

    fn suites(&self) -> Result<Vec<Suite>, OutOfMemory> {
        let all = aws_lc_rs::DEFAULT_CIPHER_SUITES;
        let mut suites = Vec::new();
        suites
            .try_reserve_exact(all.len())
            .map_err(|_| OutOfMemory)?;
        for &s in all {
            suites.try_push(suite(s))?;
        }
        Ok(suites)
    }

    fn builder(&self, suites: &[Suite], versions: &[u16]) -> Result<Builder, OutOfMemory> {
        let mut chosen = Vec::new();
        chosen
            .try_reserve_exact(suites.len())
            .map_err(|_| OutOfMemory)?;
        for s in suites {
            let found = aws_lc_rs::DEFAULT_CIPHER_SUITES
                .iter()
                .find(|d| suite(**d) == *s)
                .expect("a suite of the provider's");
            chosen.try_push(*found)?;
        }
        let mut wanted = Vec::new();
        wanted
            .try_reserve_exact(versions.len())
            .map_err(|_| OutOfMemory)?;
        for &v in versions {
            // Those rustls speaks, as `rustls_client_config_builder_new_custom`
            // takes them.
            let proto = ProtocolVersion::from(v);
            if proto == rustls::version::TLS12.version {
                wanted.try_push(&rustls::version::TLS12)?;
            } else if proto == rustls::version::TLS13.version {
                wanted.try_push(&rustls::version::TLS13)?;
            }
        }
        Ok(quiet(|| {
            let mut provider = aws_lc_rs::default_provider();
            // An empty list keeps the base's (`build_provider`).
            if !chosen.is_empty() {
                provider.cipher_suites = chosen;
            }
            Builder {
                provider: Arc::new(provider),
                versions: wanted,
                verifier: None,
                alpn: Vec::new(),
                key: None,
                key_log: None,
                ech: None,
            }
        }))
    }

    fn roots(&self, pem: &[u8]) -> Result<RootCertStore, Code> {
        quiet(|| strict_roots(pem))
    }

    fn crls(&self, pem: &[u8]) -> Result<Self::Crls, Code> {
        quiet(|| {
            let crls = CertificateRevocationListDer::pem_slice_iter(pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Code::CertificateRevocationListParseError)?;
            if crls.is_empty() {
                return Err(Code::CertificateRevocationListParseError);
            }
            Ok(crls)
        })
    }

    fn webpki(
        &self,
        roots: RootCertStore,
        crls: Option<Self::Crls>,
    ) -> Result<Arc<dyn ServerCertVerifier>, Code> {
        quiet(|| {
            let built = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
                .with_crls(crls.unwrap_or_default())
                .build()
                .map_err(map_verifier_builder_error)?;
            Ok(built as Arc<dyn ServerCertVerifier>)
        })
    }

    fn platform(&self) -> Result<Arc<dyn ServerCertVerifier>, Code> {
        quiet(|| {
            let verifier =
                rustls_platform_verifier::Verifier::new(provider()).map_err(map_error)?;
            Ok(Arc::new(verifier) as Arc<dyn ServerCertVerifier>)
        })
    }

    fn certified_key(&self, chain: &[u8], key: &[u8]) -> Result<Arc<CertifiedKey>, Code> {
        quiet(|| {
            let der = PrivateKeyDer::from_pem_slice(key).map_err(|_| Code::PrivateKeyParseError)?;
            let key = provider()
                .key_provider
                .load_private_key(der)
                .map_err(map_error)?;
            let chain = CertificateDer::pem_slice_iter(chain)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Code::CertificateParseError)?;
            Ok(Arc::new(CertifiedKey::new(chain, key)))
        })
    }

    fn keys_match(&self, key: &Arc<CertifiedKey>) -> Result<(), Code> {
        quiet(|| key.keys_match().map_err(map_error))
    }

    fn alpn(&self, builder: &mut Builder, names: &[&[u8]]) -> Result<(), OutOfMemory> {
        let mut alpn = Vec::new();
        alpn.try_reserve_exact(names.len())
            .map_err(|_| OutOfMemory)?;
        for name in names {
            let mut copy = Vec::new();
            copy.try_extend_from_slice(name)?;
            alpn.try_push(copy)?;
        }
        builder.alpn = alpn;
        Ok(())
    }

    fn verify_none(&self, builder: &mut Builder) {
        let provider = builder.provider.clone();
        builder.verifier = Some(quiet(|| Arc::new(VerifyNone(provider))));
    }

    fn verifier(&self, builder: &mut Builder, verifier: Arc<dyn ServerCertVerifier>) {
        builder.verifier = Some(verifier);
    }

    fn certify(&self, builder: &mut Builder, key: Arc<CertifiedKey>) {
        builder.key = Some(key);
    }

    fn key_log(&self, builder: &mut Builder, log: SharedKeyLog) {
        builder.key_log = Some(quiet(|| Arc::new(Keys(log))));
    }

    fn ech_grease(&self, builder: &mut Builder) -> Result<(), Code> {
        quiet(|| {
            // A suite at random, without bias, and a key made for it
            // (rustls-ffi's `Hpke::grease_public_key`).
            let suites = aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
            let n = u32::try_from(suites.len()).expect("a handful of suites");
            let threshold = u32::MAX - (u32::MAX % n);
            let suite = loop {
                let mut buf = [0u8; 4];
                builder
                    .provider
                    .secure_random
                    .fill(&mut buf)
                    .map_err(|_| Code::HpkeError)?;
                let value = u32::from_ne_bytes(buf);
                if value < threshold {
                    let at = usize::try_from(value / (threshold / n)).expect("below the count");
                    break suites[at];
                }
            };
            let (key, _) = suite.generate_key_pair().map_err(|_| Code::HpkeError)?;
            if not_tls13_only(builder) {
                return Err(Code::BuilderIncompatibleTlsVersions);
            }
            builder.ech = Some(EchMode::Grease(EchGreaseConfig::new(suite, key)));
            Ok(())
        })
    }

    fn ech(&self, builder: &mut Builder, list: &[u8]) -> Result<(), Code> {
        quiet(|| {
            if not_tls13_only(builder) {
                return Err(Code::BuilderIncompatibleTlsVersions);
            }
            let config = EchConfig::new(
                EchConfigListBytes::from(list),
                aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
            )
            .map_err(map_error)?;
            builder.ech = Some(config.into());
            Ok(())
        })
    }

    fn build(&self, builder: Builder) -> Result<Config, Code> {
        quiet(|| {
            let Some(verifier) = builder.verifier else {
                return Err(Code::NoServerCertVerifier);
            };
            let config = ClientConfig::builder_with_provider(builder.provider);
            // ECH picks the versions itself: TLS 1.3 alone.
            let config = match builder.ech {
                Some(mode) => config.with_ech(mode),
                None => config.with_protocol_versions(&builder.versions),
            };
            let config = config
                .map_err(map_error)?
                .dangerous()
                .with_custom_certificate_verifier(verifier);
            let mut config = match builder.key {
                Some(key) => config.with_client_cert_resolver(Arc::new(OneKey(key))),
                None => config.with_no_client_auth(),
            };
            config.alpn_protocols = builder.alpn;
            config.check_selected_alpn = true;
            config.enable_sni = true;
            config.send_ticket_request = None;
            if let Some(key_log) = builder.key_log {
                config.key_log = key_log;
            }
            Ok(Config(Arc::new(config)))
        })
    }

    fn connect(&self, config: Config, name: &[u8]) -> Result<Conn, Code> {
        let name = core::str::from_utf8(name).map_err(|_| Code::InvalidDnsNameError)?;
        quiet(|| {
            let name = ServerName::try_from(name)
                .map_err(|_| Code::InvalidDnsNameError)?
                .to_owned();
            ClientConnection::new(config.0, name)
                .map(Conn)
                .map_err(map_error)
        })
    }
}

/// One connection.
#[derive(Debug)]
pub(crate) struct Conn(ClientConnection);

/// The number an I/O error came with (`rustls_io_result`): its own, as
/// C's I/O answered it, else `EIO`.
fn errno(e: &io::Error) -> Errno {
    match e.raw_os_error() {
        Some(libc::EAGAIN) => Errno::Again,
        Some(libc::EINVAL) => Errno::Invalid,
        _ => Errno::Io,
    }
}

/// The connection below, as rustls reads it (rustls-ffi's
/// `CallbackReader` over C's `read_cb`).
struct Reader<'c, 's, 'a>(&'c mut Call<'s, 'a>);

impl io::Read for Reader<'_, '_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match loud(|| self.0.recv(buf)) {
            Moved::Bytes(n) => Ok(n),
            Moved::Again => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
            Moved::Failed => Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }
}

/// The connection below, as rustls writes it (rustls-ffi's
/// `CallbackWriter` over C's `write_cb`), a buffer at a time.
struct Writer<'c, 's, 'a>(&'c mut Call<'s, 'a>);

impl io::Write for Writer<'_, '_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match loud(|| self.0.send(buf)) {
            Moved::Bytes(n) => Ok(n),
            Moved::Again => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
            Moved::Failed => Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl crate::library::Conn for Conn {
    fn read_tls(&mut self, call: &mut Call<'_, '_>) -> Result<usize, Errno> {
        quiet(|| self.0.read_tls(&mut Reader(call)).map_err(|e| errno(&e)))
    }

    fn write_tls(&mut self, call: &mut Call<'_, '_>) -> Result<usize, Errno> {
        quiet(|| self.0.write_tls(&mut Writer(call)).map_err(|e| errno(&e)))
    }

    fn process_new_packets(&mut self) -> Result<(), Code> {
        quiet(|| self.0.process_new_packets().map(drop).map_err(map_error))
    }

    fn wants_read(&self) -> bool {
        self.0.wants_read()
    }

    fn wants_write(&self) -> bool {
        self.0.wants_write()
    }

    fn is_handshaking(&self) -> bool {
        self.0.is_handshaking()
    }

    fn read(&mut self, buf: &mut [u8]) -> Plain {
        quiet(|| match io::Read::read(&mut self.0.reader(), buf) {
            Ok(n) => Plain::Read(n),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Plain::UnexpectedEof,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Plain::Empty,
            Err(_) => Plain::Failed(Code::Io),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, Code> {
        quiet(|| io::Write::write(&mut self.0.writer(), bytes).map_err(|_| Code::Io))
    }

    fn send_close_notify(&mut self) {
        quiet(|| self.0.send_close_notify());
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.0.alpn_protocol()
    }

    fn version(&self) -> u16 {
        self.0.protocol_version().map(u16::from).unwrap_or_default()
    }

    fn suite_name(&self) -> &str {
        self.0
            .negotiated_cipher_suite()
            .and_then(|cs| cs.suite().as_str())
            .unwrap_or_default()
    }

    fn group_name(&self) -> &str {
        self.0
            .negotiated_key_exchange_group()
            .and_then(|g| g.name().as_str())
            .unwrap_or_default()
    }

    fn peer_cert(&self, i: usize) -> Option<&[u8]> {
        self.0
            .peer_certificates()
            .and_then(|c| c.get(i))
            .map(|c| c.as_ref())
    }
}
