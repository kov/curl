//! The peer's checks Schannel leaves to the caller
//! (`lib/vtls/schannel_verify.c`): its chain against the transfer's CA
//! file or blob, with the system's chain engine trusting those roots
//! alone (`Curl_verify_certificate`); its name, where Schannel does not
//! check it (`Curl_verify_host`); its public key against a pinned one;
//! and its chain reported (`CURLOPT_CERTINFO`).
//!
//! The store made from a CA file or blob is kept for the multi's next
//! connections (`Curl_schannel_get_cached_cert_store`).

use std::io::{Read as _, Seek as _, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};
use curl_core::error::ErrorKind;
use curl_core::options::{CaCache, SslOptions};
use curl_core::report::CertInfo;
use curl_core::time::Instant;
use curl_core::tls::{TlsCx, TlsIdentity, TlsShared, hostcheck, x509};
use curl_os::error::ErrorText;

use crate::crypt::{self, AltNames, CertStore, ChainEngine, NameList, PemStage, trust};
use crate::sspi::Context;
use crate::text::Text;

/// The largest CA file read (`MAX_CAFILE_SIZE`).
const MOST_CAFILE: u64 = 1024 * 1024;
const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const END: &[u8] = b"\n-----END CERTIFICATE-----";

/// The store a multi keeps (`schannel_cert_share`): made from the CA file
/// or blob named, at `made`.
#[derive(Default)]
pub(crate) struct KeptStore {
    store: Option<TryArc<CertStore>>,
    ca_file: Option<Vec<u8>>,
    /// A blob's SHA-256 and length.
    blob: Option<([u8; 32], usize)>,
    made: Option<Instant>,
}

impl KeptStore {
    /// The kept store, if it serves `identity` at `now`
    /// (`Curl_schannel_get_cached_cert_store`).
    fn get(&self, identity: &TlsIdentity, now: Instant) -> Option<TryArc<CertStore>> {
        let store = self.store.as_ref()?;
        match identity.options.ca_cache {
            CaCache::Off => return None,
            CaCache::Forever => {}
            CaCache::For(most) => {
                if now.ms_since(self.made?) >= curl_core::time::millis(most) {
                    return None;
                }
            }
        }
        if let Some(blob) = identity.ca_blob() {
            let (digest, len) = self.blob.unwrap_or(([0; 32], 0));
            if len != blob.len() || digest != curl_core::tls::sha256(blob) {
                return None;
            }
        } else {
            let wanted = identity.ca_file()?;
            if self.ca_file.as_deref()? != wanted {
                return None;
            }
        }
        Some(store.clone())
    }

    /// Keep `store`, made for `identity` at `now`, in place of any kept
    /// (`Curl_schannel_set_cached_cert_store`).
    fn set(
        &mut self,
        identity: &TlsIdentity,
        now: Instant,
        store: TryArc<CertStore>,
    ) -> Result<(), OutOfMemory> {
        let (blob, ca_file) = match identity.ca_blob() {
            Some(b) => (Some((curl_core::tls::sha256(b), b.len())), None),
            None => match identity.ca_file() {
                Some(f) => {
                    let mut copy = Vec::new();
                    copy.try_extend_from_slice(f)?;
                    (None, Some(copy))
                }
                None => (None, None),
            },
        };
        *self = KeptStore {
            store: Some(store),
            ca_file,
            blob,
            made: Some(now),
        };
        Ok(())
    }
}

/// The peer's certificate, or the failure C says (`Failed to read remote
/// certificate context`).
fn peer_cert(io: &mut TlsCx<'_>, ctx: &Context) -> Result<crypt::CertContext, ErrorKind> {
    ctx.peer_cert().map_err(|st| {
        let why = ErrorText::sspi(st);
        io.fail(
            ErrorKind::PeerFailedVerification,
            format_args!(
                "schannel: Failed to read remote certificate context: {}",
                Text(why.as_bytes())
            ),
        )
    })
}

/// The peer's public key is the one `pinned` names
/// (`schannel_pkp_pin_peer_pubkey`).
pub(crate) fn pin(io: &mut TlsCx<'_>, ctx: &Context, pinned: &[u8]) -> Result<(), ErrorKind> {
    let cert = match ctx.peer_cert() {
        Ok(c) => c,
        Err(st) => {
            let why = ErrorText::sspi(st);
            io.fail(
                ErrorKind::SslPinnedpubkeynotmatch,
                format_args!(
                    "schannel: Failed to read remote certificate context: {}",
                    Text(why.as_bytes())
                ),
            );
            return Err(ErrorKind::SslPinnedpubkeynotmatch);
        }
    };
    let Some(der) = cert.der() else {
        return Err(ErrorKind::SslPinnedpubkeynotmatch);
    };
    let Some(parsed) = x509::parse(der) else {
        return Err(ErrorKind::SslPinnedpubkeynotmatch);
    };
    let spki = parsed.public_key_info.whole;
    curl_core::tls::pin_peer_pubkey(io, pinned, spki).inspect_err(|_| {
        io.fail(
            ErrorKind::SslPinnedpubkeynotmatch,
            format_args!("SSL: public key does not match pinned public key"),
        );
    })
}

/// The address `host` names, as its bytes, if it is one
/// (`get_num_host_info`).
fn address(host: &[u8]) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(host).ok()?;
    let mut bytes = Vec::new();
    if let Ok(v4) = text.parse::<Ipv4Addr>() {
        bytes.try_extend_from_slice(&v4.octets()).ok()?;
    } else {
        let v6 = text.parse::<Ipv6Addr>().ok()?;
        bytes.try_extend_from_slice(&v6.octets()).ok()?;
    }
    Some(bytes)
}

/// The peer's certificate names `host` (`Curl_verify_host`).
pub(crate) fn host(io: &mut TlsCx<'_>, ctx: &Context, host: &[u8]) -> Result<(), ErrorKind> {
    let fail = ErrorKind::PeerFailedVerification;
    let cert = peer_cert(io, ctx)?;
    let shown = Text(host);
    if let Some(ip) = address(host) {
        let addrs = match cert.ip_addresses() {
            Ok(a) => a,
            Err(AltNames::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
            Err(why) => {
                let text = match why {
                    AltNames::NoInfo => "schannel: Null certificate info.",
                    AltNames::NoExtension => "schannel: CertFindExtension() returned no extension.",
                    AltNames::NoDecode | AltNames::OutOfMemory => {
                        "schannel: CryptDecodeObjectEx() returned no alternate name information."
                    }
                };
                return Err(io.fail(fail, format_args!("{text}")));
            }
        };
        if addrs.contains(&ip) {
            io.info(format_args!(
                "schannel: connection hostname ({shown}) matched cert's IP address!"
            ));
            return Ok(());
        }
        // C says nothing more of an address no name matched.
        return Err(fail);
    }
    let names = match cert.dns_names() {
        Ok(names) => names,
        Err(NameList::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(NameList::None) => {
            return Err(io.fail(
                fail,
                format_args!(
                    "schannel: CertGetNameString() returned no certificate name information"
                ),
            ));
        }
        Err(NameList::Size) => {
            return Err(io.fail(
                fail,
                format_args!(
                    "schannel: CertGetNameString() returned certificate name information of unexpected size"
                ),
            ));
        }
    };
    // The system lists names apart at their zero bytes: a name holding
    // one is never matched in part, and the certificate is refused.
    if cert
        .der()
        .and_then(curl_core::tls::x509::host_name_holds_zero)
        .unwrap_or(false)
    {
        return Err(io.fail(
            fail,
            format_args!("schannel: a certificate name holds a zero byte"),
        ));
    }
    for name in &names {
        if hostcheck::names(name, host) {
            io.info(format_args!(
                "schannel: connection hostname ({shown}) validated against certificate name ({})",
                Text(name)
            ));
            return Ok(());
        }
        io.info(format_args!(
            "schannel: connection hostname ({shown}) did not match against certificate name ({})",
            Text(name)
        ));
    }
    Err(io.fail(
        fail,
        format_args!(
            "schannel: CertGetNameString() failed to match connection hostname ({shown}) against server certificate names"
        ),
    ))
}

/// `c_memmem`: where `needle` first is in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Add the certificates of the PEM text `pem` to `store`
/// (`add_certs_data_to_store`), named `name` in what is said.
fn add_pem_certs(
    io: &mut TlsCx<'_>,
    store: &CertStore,
    pem: &[u8],
    name: &[u8],
) -> Result<(), ErrorKind> {
    let shown = Text(name);
    let mut at = 0;
    let mut count = 0usize;
    while at < pem.len() {
        // C looks for the start in all but the last byte, so that the
        // byte after it can be read.
        let Some(begin) = find(&pem[at..pem.len() - 1], BEGIN).map(|b| at + b) else {
            break;
        };
        if !matches!(pem.get(begin + BEGIN.len()), Some(b'\r' | b'\n')) {
            break;
        }
        let Some(end) = find(&pem[begin..], END).map(|e| begin + e) else {
            return Err(io.fail(
                ErrorKind::SslCacertBadfile,
                format_args!("schannel: CA file '{shown}' is not correctly formatted"),
            ));
        };
        let block = &pem[begin..end + END.len()];
        match store.add_pem(block) {
            Ok(()) => count += 1,
            Err((PemStage::Extract, code)) => {
                let why = ErrorText::winapi(code);
                return Err(io.fail(
                    ErrorKind::SslCacertBadfile,
                    format_args!(
                        "schannel: failed to extract certificate from CA file '{shown}': {}",
                        Text(why.as_bytes())
                    ),
                ));
            }
            Err((PemStage::Add, code)) => {
                let why = ErrorText::winapi(code);
                return Err(io.fail(
                    ErrorKind::SslCacertBadfile,
                    format_args!(
                        "schannel: failed to add certificate from CA file '{shown}' to certificate store: {}",
                        Text(why.as_bytes())
                    ),
                ));
            }
        }
        at = begin + block.len();
    }
    if count == 0 {
        io.info(format_args!(
            "schannel: did not add any certificates from CA file '{shown}'"
        ));
    } else {
        io.info(format_args!(
            "schannel: added {count} certificate(s) from CA file '{shown}'"
        ));
    }
    Ok(())
}

/// Add the certificates of the CA file `name` to `store`
/// (`add_certs_file_to_store`).
fn add_file_certs(io: &mut TlsCx<'_>, store: &CertStore, name: &[u8]) -> Result<(), ErrorKind> {
    let shown = Text(name);
    let bad = ErrorKind::SslCacertBadfile;
    let Ok(mut file) = curl_os::fs::with_c_name(name, curl_os::fs::open_read) else {
        return Err(io.fail(
            bad,
            format_args!("schannel: failed to open CA file '{shown}'"),
        ));
    };
    let Ok(len) = file.seek(SeekFrom::End(0)) else {
        return Err(io.fail(
            bad,
            format_args!("schannel: failed seeking to end of CA file '{shown}'"),
        ));
    };
    if file.seek(SeekFrom::Start(0)).is_err() {
        return Err(io.fail(
            bad,
            format_args!("schannel: failed seeking to beginning of CA file '{shown}'"),
        ));
    }
    if len > MOST_CAFILE {
        return Err(io.fail(
            bad,
            format_args!("schannel: CA file exceeds max size of {MOST_CAFILE} bytes"),
        ));
    }
    let mut data = Vec::new();
    // The text, then the zero C ends it with, which the search reads.
    data.try_resize(usize::try_from(len).expect("under a mebibyte"), 0)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    let mut got = 0;
    while got < data.len() {
        match file.read(&mut data[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => {
                return Err(io.fail(
                    bad,
                    format_args!("schannel: failed to read from CA file '{shown}'"),
                ));
            }
        }
    }
    data.truncate(got);
    data.try_push(0)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    add_pem_certs(io, store, &data[..got + 1], name)
}

/// The trust store for a CA file or blob: the multi's, if it keeps one
/// that serves, else one made and kept.
fn trust_store(
    io: &mut TlsCx<'_>,
    identity: &TlsIdentity,
    shared: &TlsShared,
) -> Result<TryArc<CertStore>, ErrorKind> {
    let now = io.now();
    if let Ok(Some(Some(kept))) = shared.with(KeptStore::default, |k| k.get(identity, now)) {
        io.info(format_args!(
            "schannel: reusing certificate store from cache"
        ));
        return Ok(kept);
    }
    let store = CertStore::memory().map_err(|code| {
        let why = ErrorText::winapi(code);
        io.fail(
            ErrorKind::SslCacertBadfile,
            format_args!(
                "schannel: failed to create certificate store: {}",
                Text(why.as_bytes())
            ),
        )
    })?;
    match identity.ca_blob() {
        Some(blob) => add_pem_certs(io, &store, blob, b"(memory blob)")?,
        None => {
            let file = identity.ca_file().expect("a CA file where no blob");
            add_file_certs(io, &store, file)?;
        }
    }
    let store = TryArc::try_new(store).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    // Not kept, it is used for this connection alone.
    let _ = shared.with(KeptStore::default, |k| k.set(identity, now, store.clone()));
    Ok(store)
}

/// The peer's chain and name checked (`Curl_verify_certificate`): against
/// the CA file or blob if `manual`.
pub(crate) fn certificate(
    io: &mut TlsCx<'_>,
    ctx: &Context,
    identity: &TlsIdentity,
    shared: &TlsShared,
    host_name: &[u8],
    manual: bool,
) -> Result<(), ErrorKind> {
    let fail = ErrorKind::PeerFailedVerification;
    let cert = peer_cert(io, ctx)?;
    let o = &identity.options;
    let mut engine = None;
    let mut _store = None;
    if manual && (identity.ca_file().is_some() || identity.ca_blob().is_some()) {
        let store = trust_store(io, identity, shared)?;
        let partial = !o.ssl_options.contains(SslOptions::NO_PARTIALCHAIN);
        engine = Some(ChainEngine::exclusive(&store, partial).map_err(|code| {
            let why = ErrorText::winapi(code);
            io.fail(
                ErrorKind::SslCacertBadfile,
                format_args!(
                    "schannel: failed to create certificate chain engine: {}",
                    Text(why.as_bytes())
                ),
            )
        })?);
        _store = Some(store);
    }
    let revocation = !o.ssl_options.contains(SslOptions::NO_REVOKE);
    let errors = crypt::chain_errors(engine.as_ref(), &cert, revocation).map_err(|code| {
        let why = ErrorText::winapi(code);
        io.fail(
            fail,
            format_args!(
                "schannel: failed to get the certificate chain: {}",
                Text(why.as_bytes())
            ),
        )
    })?;
    let mut mask = errors & !trust::NOT_TIME_NESTED;
    if o.ssl_options.contains(SslOptions::REVOKE_BEST_EFFORT) {
        mask &= !(trust::REVOCATION_STATUS_UNKNOWN | trust::OFFLINE_REVOCATION);
    }
    if mask != 0 {
        let why = if mask & trust::REVOKED != 0 {
            "schannel: trust for this certificate or one of the certificates in the certificate chain has been revoked"
        } else if mask & trust::PARTIAL_CHAIN != 0 {
            "schannel: the certificate chain is incomplete"
        } else if mask & trust::UNTRUSTED_ROOT != 0 {
            "schannel: the certificate or certificate chain is based on an untrusted root"
        } else if mask & trust::NOT_TIME_VALID != 0 {
            "schannel: this certificate or one of the certificates in the certificate chain is not time valid"
        } else if mask & trust::REVOCATION_STATUS_UNKNOWN != 0 {
            "schannel: the revocation status is unknown"
        } else {
            return Err(io.fail(fail, format_args!("schannel: error 0x{mask:08x}")));
        };
        return Err(io.fail(fail, format_args!("{why}")));
    }
    drop(engine);
    if identity.verify_host {
        return host(io, ctx, host_name);
    }
    Ok(())
}

/// The peer's chain, reported (`schannel_connect_step3`'s certinfo):
/// at most `most` certificates, leaf first.
pub(crate) fn certinfo(io: &mut TlsCx<'_>, ctx: &Context, most: usize) -> Result<(), ErrorKind> {
    let Ok(cert) = ctx.peer_cert() else {
        return Err(io.fail(
            ErrorKind::PeerFailedVerification,
            format_args!("schannel: failed to retrieve remote cert context"),
        ));
    };
    let (mut chain, reverse) = cert
        .store_chain(most)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    if chain.len() > most {
        let n = chain.len();
        return Err(io.fail(
            ErrorKind::SslConnectError,
            format_args!("{n} certificates is more than allowed ({most})"),
        ));
    }
    if reverse {
        chain.reverse();
    }
    let mut info = CertInfo::new(chain.len()).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    for (i, der) in chain.iter().enumerate() {
        x509::certinfo(io, &mut info, i, der)?;
    }
    io.set_certinfo(Some(info))
}
