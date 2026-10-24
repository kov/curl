//! The peer's certificate chain as a transfer that asked for it reports
//! it (`CURLOPT_CERTINFO`, `CURLINFO_CERTINFO`): per certificate, from
//! the peer's own to the last it sent, its fields as `label:value`
//! lines, in the order the backend gives them.

use curl_alloc::{OutOfMemory, TryVec as _};

/// The most certificates a chain may hold (`MAX_ALLOWED_CERT_AMOUNT`).
pub const MAX_CERTS: usize = 100;

/// The room for a field's line and the zero byte after it
/// (`CURL_X509_STR_MAX`); a longer one cannot be kept, as C's buffer
/// cannot hold it.
const MAX_LINE: usize = 100_000;

/// The chain's certificates, each its lines.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CertInfo {
    certs: Vec<Vec<Vec<u8>>>,
}

impl CertInfo {
    /// A chain of `count` certificates, none of their fields yet
    /// (`Curl_ssl_init_certinfo`).
    pub fn new(count: usize) -> Result<CertInfo, OutOfMemory> {
        let mut certs = Vec::new();
        certs.try_reserve_exact(count).map_err(|_| OutOfMemory)?;
        for _ in 0..count {
            certs.try_push(Vec::new())?;
        }
        Ok(CertInfo { certs })
    }

    /// Add `label:value` to certificate `cert`'s lines
    /// (`Curl_ssl_push_certinfo_len`).
    pub fn push(&mut self, cert: usize, label: &[u8], value: &[u8]) -> Result<(), OutOfMemory> {
        let lines = self
            .certs
            .get_mut(cert)
            .expect("a certificate of the chain made");
        let len = label.len() + 1 + value.len();
        if len >= MAX_LINE {
            return Err(OutOfMemory);
        }
        let mut line = Vec::new();
        line.try_reserve_exact(len).map_err(|_| OutOfMemory)?;
        line.try_extend_from_slice(label)?;
        line.try_push(b':')?;
        line.try_extend_from_slice(value)?;
        lines.try_push(line)
    }

    /// Each certificate's lines, the peer's first.
    pub fn certs(&self) -> &[Vec<Vec<u8>>] {
        &self.certs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_kept_as_label_colon_value_per_certificate() {
        let mut info = CertInfo::new(2).unwrap();
        info.push(1, b"Subject", b"CN = ca").unwrap();
        info.push(0, b"Subject", b"CN = localhost").unwrap();
        info.push(0, b"Cert", b"-----BEGIN").unwrap();
        assert_eq!(
            info.certs(),
            [
                vec![
                    b"Subject:CN = localhost".to_vec(),
                    b"Cert:-----BEGIN".to_vec()
                ],
                vec![b"Subject:CN = ca".to_vec()],
            ]
        );
        let long = vec![b'x'; MAX_LINE - 3];
        assert_eq!(info.push(0, b"A", &long), Ok(()));
        assert_eq!(info.push(0, b"AB", &long), Err(OutOfMemory));
    }
}
