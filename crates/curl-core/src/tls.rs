//! TLS, as the core asks it of the library bound beside it: the settings
//! a connection's handshake is made with, which decide which connections
//! a transfer may reuse.

use curl_alloc::{OutOfMemory, TryArc};

use crate::options::{Tls, TlsOptions};

/// Every setting a connection's TLS handshake was made with that a
/// transfer must share to reuse the connection (C's `ssl_filter_config`,
/// compared by `match_ssl_primary_config`). A route to a TLS peer holds
/// one, made from the transfer's options; the connection it sets up
/// keeps it.
#[derive(Debug)]
pub struct TlsIdentity {
    /// The peer's certificate must verify.
    pub verify_peer: bool,
    /// The certificate must name the host.
    pub verify_host: bool,
    pub options: TlsOptions,
}

impl TlsIdentity {
    /// The identity the transfer's options `tls` make, shared by its
    /// route and the connection set up for it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the https scheme makes one, next")
    )]
    pub(crate) fn of(tls: &Tls) -> Result<TryArc<TlsIdentity>, OutOfMemory> {
        TryArc::try_new(TlsIdentity {
            verify_peer: tls.verify_peer,
            verify_host: tls.verify_host,
            options: tls.options.try_clone()?,
        })
    }
}

/// A connection made with one identity serves a transfer that wants the
/// other only if every setting matches, as `match_ssl_primary_config`
/// compares them: the paths, blobs, keys and certificates exactly, the
/// lists and the formats in any case, the key's password in constant
/// time.
impl PartialEq for TlsIdentity {
    fn eq(&self, other: &TlsIdentity) -> bool {
        // Every field by name, so that one added does not compile until
        // it is compared here or said why not.
        let TlsIdentity {
            verify_peer,
            verify_host,
            options,
        } = self;
        let TlsOptions {
            min_version,
            max_version,
            ssl_options,
            verify_status,
            ca_file,
            ca_path,
            ca_blob,
            crl_file,
            issuer_cert,
            issuer_cert_blob,
            cert,
            cert_blob,
            cert_type,
            key,
            key_blob,
            key_type,
            key_password,
            ciphers,
            tls13_ciphers,
            curves,
            signature_algorithms,
            pinned_key,
            // The handle's, not the connection's: C reads it as the
            // handshake starts and matches no connection by it.
            alpn: _,
        } = options;
        let o = &other.options;
        *verify_peer == other.verify_peer
            && *verify_host == other.verify_host
            && *min_version == o.min_version
            && *max_version == o.max_version
            && *ssl_options == o.ssl_options
            && *verify_status == o.verify_status
            && *ca_file == o.ca_file
            && *ca_path == o.ca_path
            && *ca_blob == o.ca_blob
            && *crl_file == o.crl_file
            && *issuer_cert == o.issuer_cert
            && *issuer_cert_blob == o.issuer_cert_blob
            && *cert == o.cert
            && *cert_blob == o.cert_blob
            && same_name(cert_type, &o.cert_type)
            && *key == o.key
            && *key_blob == o.key_blob
            && same_name(key_type, &o.key_type)
            && same_secret(key_password, &o.key_password)
            && same_name(ciphers, &o.ciphers)
            && same_name(tls13_ciphers, &o.tls13_ciphers)
            && same_name(curves, &o.curves)
            && same_name(signature_algorithms, &o.signature_algorithms)
            && *pinned_key == o.pinned_key
    }
}

impl Eq for TlsIdentity {}

/// The same list or format, in any case (`curl_strequal`), or neither.
fn same_name(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (a, b) => a.is_none() && b.is_none(),
    }
}

/// The same secret, or neither, compared in a time that does not depend
/// on where they first differ (`Curl_timestrcmp`).
fn same_secret(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
        }
        (a, b) => a.is_none() && b.is_none(),
    }
}

#[cfg(test)]
mod tests;
