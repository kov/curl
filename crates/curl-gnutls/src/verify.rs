//! The peer's certificate checked once the handshake is done
//! (`Curl_gtls_verifyserver`): its chain reported, verified by GnuTLS
//! against the trust set up, its dates, its stapled status, its issuer,
//! its name and its pinned key, then described.

use std::io::Read as _;

use curl_alloc::OutOfMemory;
use curl_core::date::HttpDate;
use curl_core::error::ErrorKind;
use curl_core::report::CertInfo;
use curl_core::tls::{TlsCx, TlsIdentity, x509};

use crate::library::{Cert as _, Format, Gnutls, Session as _, Stapled, as_c, c_string, strerror};
use crate::sys;
use crate::text::Text;

/// The most certificates a chain reported may have
/// (`MAX_ALLOWED_CERT_AMOUNT`).
const MOST_CERTS: usize = 100;

/// The bits of `GNUTLS_CERT_EXPIRED` and `GNUTLS_CERT_NOT_ACTIVATED`, and
/// the errors, as the verify result C reports holds them.
const EXPIRED: i64 = sys::GNUTLS_CERT_EXPIRED as i64;
const NOT_ACTIVATED: i64 = sys::GNUTLS_CERT_NOT_ACTIVATED as i64;
const NO_CERTIFICATE: i64 = sys::GNUTLS_E_NO_CERTIFICATE_FOUND as i64;

/// Who the session talks to, as the check names it.
pub(crate) struct Peer<'a> {
    /// The name as the URL gives it (`origin->user_hostname`).
    pub(crate) name: &'a [u8],
    /// The name sent by SNI, if any: the certificate is matched against
    /// it, else against `name` (`peer->sni ? peer->sni : hostname`).
    pub(crate) sni: Option<&'a [u8]>,
}

/// Check the peer of `session`, its handshake done, as `identity` asks
/// (`Curl_gtls_verifyserver`), at `now` in seconds since 1970.
pub(crate) fn verify_server<G: Gnutls>(
    lib: &G,
    session: &G::Session,
    identity: &TlsIdentity,
    peer: &Peer<'_>,
    now: i64,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let o = &identity.options;
    let chain = session.peers();
    let leaf = chain.as_ref().and_then(|c| c.first().copied());
    if chain.is_none() {
        if identity.verify_peer || identity.verify_host || o.issuer_cert.is_some() {
            io.verified(NO_CERTIFICATE);
            return Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("failed to get server cert"),
            ));
        }
        io.info(format_args!(" common name: WARNING could not obtain"));
    }
    if let Some(chain) = chain.as_ref().filter(|_| io.wants_certinfo()) {
        if chain.len() > MOST_CERTS {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!(
                    "{} certificates is more than allowed ({MOST_CERTS})",
                    chain.len()
                ),
            ));
        }
        let mut info = CertInfo::new(chain.len()).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        for (i, der) in chain.iter().enumerate() {
            x509::certinfo(io, &mut info, i, der)?;
        }
        io.set_certinfo(Some(info))?;
    }
    if identity.verify_peer {
        verify_cert(lib, session, identity, io)?;
    } else {
        io.info(format_args!("  SSL certificate verification SKIPPED"));
    }
    let Ok(mut cert) = lib.cert() else {
        io.verified(NO_CERTIFICATE);
        return Err(io.fail(
            ErrorKind::SslConnectError,
            format_args!("failed to init GnuTLS x509_crt"),
        ));
    };
    if let Some(leaf) = leaf
        && cert.import(leaf, Format::Der) != 0
    {
        io.verified(NO_CERTIFICATE);
        return Err(io.fail(
            ErrorKind::SslConnectError,
            format_args!("error parsing server's certificate chain"),
        ));
    }
    dates(&cert, identity, now, io)?;
    if o.verify_status {
        stapled(session, &cert, io)?;
    } else {
        io.info(format_args!(
            "  SSL certificate status verification SKIPPED"
        ));
    }
    if let Some(issuer) = o.issuer_cert.as_deref() {
        check_issuer(lib, &cert, issuer, io)?;
    }
    // The name sent, which has no trailing dot, else the host's.
    let name = c_string(peer.sni.unwrap_or(peer.name))?;
    let matched = cert.matches_host(as_c(&name));
    verify_result(&cert, peer, matched, identity.verify_host, lib, io);
    if !matched && identity.verify_host {
        return Err(ErrorKind::PeerFailedVerification);
    }
    if let Some(pinned) = o.pinned_key.as_deref() {
        pin(&cert, pinned, io).inspect_err(|_| {
            io.fail(
                ErrorKind::SslPinnedpubkeynotmatch,
                format_args!("SSL: public key does not match pinned public key"),
            );
        })?;
    }
    describe(lib, &cert, io);
    Ok(())
}

/// GnuTLS's verdict on the chain (`gtls_verify_cert`), its status bits
/// the verify result.
fn verify_cert<G: Gnutls>(
    _lib: &G,
    session: &G::Session,
    identity: &TlsIdentity,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let status = match session.verify_peers() {
        Ok(status) => status,
        Err(rc) => {
            io.verified(rc);
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("server cert verify failed: {rc}"),
            ));
        }
    };
    io.verified(status);
    if status & sys::GNUTLS_CERT_INVALID == 0 {
        io.info(format_args!("  SSL certificate verified by GnuTLS"));
        return Ok(());
    }
    let mut kind = ErrorKind::PeerFailedVerification;
    let cause = if status & sys::GNUTLS_CERT_EXPIRED != 0 {
        "certificate has expired"
    } else if status & sys::GNUTLS_CERT_SIGNER_NOT_FOUND != 0 {
        "certificate signer not trusted"
    } else if status & sys::GNUTLS_CERT_INSECURE_ALGORITHM != 0 {
        "certificate uses insecure algorithm"
    } else if status & sys::GNUTLS_CERT_INVALID_OCSP_STATUS != 0 {
        kind = ErrorKind::SslInvalidcertstatus;
        "OCSP status response is invalid"
    } else {
        "certificate error, no details available"
    };
    let ca = identity.ca_file().unwrap_or(b"none");
    let crl = identity.options.crl_file.as_deref().unwrap_or(b"none");
    Err(io.fail(
        kind,
        format_args!(
            "SSL certificate verification failed: {cause}. (CAfile: {} CRLfile: {})",
            Text(ca),
            Text(crl)
        ),
    ))
}

/// The certificate's dates against `now`: past its end or before its
/// start fails a verified peer, and is said for another.
fn dates<C: crate::library::Cert>(
    cert: &C,
    identity: &TlsIdentity,
    now: i64,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let verify = identity.verify_peer;
    let expires = cert.expiration();
    if expires == -1 {
        if verify {
            io.verified(EXPIRED);
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("server cert expiration date verify failed"),
            ));
        }
        io.info(format_args!(
            "  SSL certificate expiration date verify FAILED"
        ));
    } else if expires < now {
        if verify {
            io.verified(EXPIRED);
            return Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("server certificate expiration date has passed."),
            ));
        }
        io.info(format_args!("  SSL certificate expiration date FAILED"));
    } else {
        io.info(format_args!("  SSL certificate expiration date OK"));
    }
    let starts = cert.activation();
    if starts == -1 {
        if verify {
            io.verified(NOT_ACTIVATED);
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("server cert activation date verify failed"),
            ));
        }
        io.info(format_args!(
            "  SSL certificate activation date verify FAILED"
        ));
    } else if starts > now {
        if verify {
            io.verified(NOT_ACTIVATED);
            return Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("server certificate not activated yet."),
            ));
        }
        io.info(format_args!("  SSL certificate activation date FAILED"));
    } else {
        io.info(format_args!("  SSL certificate activation date OK"));
    }
    Ok(())
}

/// The stapled status must say the certificate is good
/// (`gtls_verify_ocsp_status`).
fn stapled<S: crate::library::Session>(
    session: &S,
    cert: &S::Cert,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let why = match session.stapled_status(cert) {
        Stapled::Status(s) if s == sys::GNUTLS_OCSP_CERT_GOOD as u32 => return Ok(()),
        Stapled::Status(s) if s == sys::GNUTLS_OCSP_CERT_REVOKED as u32 => {
            "peer certificate is revoked"
        }
        Stapled::Status(s) => {
            return Err(io.fail(
                ErrorKind::SslInvalidcertstatus,
                format_args!("peer certificate OCSP status is not good: {s}"),
            ));
        }
        Stapled::None => "No OCSP response received",
        Stapled::Invalid => "Invalid OCSP response received",
        Stapled::InitFailed => "failed to init OCSP response parsing",
        Stapled::Unparsed => "failed to parse OCSP response",
        Stapled::NotSuccessful => "OCSP response basic part is not successful",
        Stapled::NotForPeer => "OCSP does not carry status for peer cert",
        Stapled::SingleUnparsed => "failed to parse OCSP response for peer cert",
    };
    Err(io.fail(ErrorKind::SslInvalidcertstatus, format_args!("{why}")))
}

/// The certificate must have been issued by the one in `file`, PEM
/// (`CURLOPT_ISSUERCERT`).
fn check_issuer<G: Gnutls>(
    lib: &G,
    cert: &G::Cert,
    file: &[u8],
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let Ok(mut issuer) = lib.cert() else {
        return Err(io.fail(
            ErrorKind::SslIssuerError,
            format_args!("failed to init GnuTLS x509_crt for issuer"),
        ));
    };
    // A file that cannot be read is read as nothing (`load_file`).
    let pem = load_file(file)?;
    let rc = issuer.import(&pem, Format::Pem);
    if rc != 0 {
        return Err(io.fail(
            ErrorKind::SslIssuerError,
            format_args!(
                "failed to import issuer certificate ({}) (Issuer Cert: {})",
                strerror(lib, rc),
                Text(file)
            ),
        ));
    }
    if !cert.issued_by(&issuer) {
        return Err(io.fail(
            ErrorKind::SslIssuerError,
            format_args!(
                "server certificate issuer check failed (Issuer Cert: {})",
                Text(file)
            ),
        ));
    }
    io.info(format_args!(
        "  SSL certificate issuer check OK (Issuer Cert: {})",
        Text(file)
    ));
    Ok(())
}

/// The largest file C reads whole (`CURL_MAX_INPUT_LENGTH`).
const MAX_INPUT: u64 = 8_000_000;

/// The bytes of the file `name`, or none if it cannot be read, is empty
/// or larger than C reads (`load_file`); `Err` out of memory.
fn load_file(name: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut out = Vec::new();
    let Ok(mut file) = curl_os::fs::with_c_name(name, curl_os::fs::open_read) else {
        return Ok(out);
    };
    let len = match file.metadata() {
        Ok(m) if m.len() <= MAX_INPUT => m.len(),
        _ => return Ok(out),
    };
    let len = usize::try_from(len).map_err(|_| ErrorKind::OutOfMemory)?;
    out.try_reserve_exact(len)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    // `take` keeps the read within the room reserved.
    if (&mut file).take(len as u64).read_to_end(&mut out).is_err() || out.len() < len {
        out.clear();
    }
    Ok(out)
}

/// Say whether the certificate names the host (`gtls_msg_verify_result`),
/// failing a transfer that needs it to.
fn verify_result<G: Gnutls>(
    cert: &G::Cert,
    peer: &Peer<'_>,
    matched: bool,
    needed: bool,
    lib: &G,
    io: &mut TlsCx<'_>,
) {
    let cn = match cert.common_name() {
        Ok(cn) => cn,
        Err(rc) => {
            io.info(format_args!(
                "error fetching CN from cert:{}",
                strerror(lib, rc)
            ));
            Vec::new()
        }
    };
    let host = Text(peer.name);
    if !matched {
        if needed {
            io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!(
                    "SSL: certificate subject name ({}) does not match target hostname '{host}'",
                    Text(&cn)
                ),
            );
        } else {
            io.info(format_args!(
                "  common name: {} (does not match '{host}')",
                Text(&cn)
            ));
        }
    } else {
        io.info(format_args!("  common name: {} (matched)", Text(&cn)));
    }
}

/// The certificate's key is the pinned one (`pkp_pin_peer_pubkey`).
fn pin<C: crate::library::Cert>(
    cert: &C,
    pinned: &[u8],
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let Some(spki) = cert.public_key() else {
        return Err(ErrorKind::SslPinnedpubkeynotmatch);
    };
    curl_core::tls::pin_peer_pubkey(io, pinned, &spki)
}

/// The certificate described, for a verbose transfer (`gtls_infof_cert`).
fn describe<G: Gnutls>(lib: &G, cert: &G::Cert, io: &mut TlsCx<'_>) {
    let _ = lib;
    if !io.verbose() {
        return;
    }
    let algo = cert.key_algorithm().unwrap_or(b"(null)");
    io.info(format_args!("  certificate public key: {}", Text(algo)));
    io.info(format_args!("  certificate version: #{}", cert.version()));
    match cert.subject() {
        Err(_) => io.info(format_args!("Failed to get certificate name")),
        Ok(subject) => {
            io.info(format_args!("  subject: {}", Text(&subject)));
            showtime(io, "start date", cert.activation());
            showtime(io, "expire date", cert.expiration());
        }
    }
    match cert.issuer() {
        Err(_) => io.info(format_args!("Failed to get certificate issuer")),
        Ok(issuer) => io.info(format_args!("  issuer: {}", Text(&issuer))),
    }
}

/// A date of the certificate's, as C's `showtime` says it; nothing for
/// one `gmtime` cannot hold.
fn showtime(io: &mut TlsCx<'_>, what: &str, t: i64) {
    if let Ok(date) = HttpDate::of(t) {
        io.info(format_args!("  {what}: {date}"));
    }
}
