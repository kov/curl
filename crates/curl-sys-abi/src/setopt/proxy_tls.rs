//! The TLS options of `curl_easy_setopt` for an HTTPS proxy
//! (`CURLOPT_PROXY_SSL_VERIFYPEER`, `CURLOPT_PROXY_CAINFO` and the rest,
//! `lib/setopt.c`'s `set.proxy_ssl`), each taken as C takes it. The ones
//! C keeps on the handle for either filter (ALPN, the session cache, the
//! engine) are the origin's options, which the proxy's identity takes.

use curl_core::options::{Options, SslOptions, TlsOptions};

use super::{Arg, Refused, blob, ca_setting, owned, ssl_version};
use crate::ffi::{self, CURLoption};

/// `option` is one this module sets.
pub(super) fn takes(option: CURLoption) -> bool {
    [
        ffi::CURLOPT_PROXY_SSL_VERIFYPEER,
        ffi::CURLOPT_PROXY_SSL_VERIFYHOST,
        ffi::CURLOPT_PROXY_SSLVERSION,
        ffi::CURLOPT_PROXY_SSL_OPTIONS,
        ffi::CURLOPT_PROXY_CAINFO,
        ffi::CURLOPT_PROXY_CAPATH,
        ffi::CURLOPT_PROXY_CAINFO_BLOB,
        ffi::CURLOPT_PROXY_CRLFILE,
        ffi::CURLOPT_PROXY_ISSUERCERT,
        ffi::CURLOPT_PROXY_ISSUERCERT_BLOB,
        ffi::CURLOPT_PROXY_PINNEDPUBLICKEY,
        ffi::CURLOPT_PROXY_SSLCERT,
        ffi::CURLOPT_PROXY_SSLCERT_BLOB,
        ffi::CURLOPT_PROXY_SSLCERTTYPE,
        ffi::CURLOPT_PROXY_SSLKEY,
        ffi::CURLOPT_PROXY_SSLKEY_BLOB,
        ffi::CURLOPT_PROXY_SSLKEYTYPE,
        ffi::CURLOPT_PROXY_KEYPASSWD,
        ffi::CURLOPT_PROXY_SSL_CIPHER_LIST,
        ffi::CURLOPT_PROXY_TLS13_CIPHERS,
    ]
    .contains(&option)
}

/// Set `option`, one `takes` names, to `arg`.
pub(super) fn apply(options: &mut Options, option: CURLoption, arg: Arg) -> Result<(), Refused> {
    match (option, arg) {
        // Neither group is made only to keep a default.
        (ffi::CURLOPT_PROXY_SSL_VERIFYPEER, Arg::Long(n)) => {
            if n == 0 || options.proxy.made_mut().is_some() {
                options.proxy.make_mut()?.tls.verify_peer = n != 0;
            }
        }
        // 1 is taken as 2, as C takes it.
        (ffi::CURLOPT_PROXY_SSL_VERIFYHOST, Arg::Long(n)) => {
            if n == 0 || options.proxy.made_mut().is_some() {
                options.proxy.make_mut()?.tls.verify_host = n != 0;
            }
        }
        (ffi::CURLOPT_PROXY_SSLVERSION, Arg::Long(n)) => {
            let (min, max) = ssl_version(n)?;
            let t = group(options)?;
            t.min_version = min;
            t.max_version = max;
        }
        // The low eight bits, as C keeps them.
        (ffi::CURLOPT_PROXY_SSL_OPTIONS, Arg::Long(n)) => {
            group(options)?.ssl_options = SslOptions::from_bits(n as u8);
        }
        (ffi::CURLOPT_PROXY_CAINFO, Arg::Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let file = ca_setting(unsafe { owned(p) }?);
            group(options)?.ca_file = file;
        }
        (ffi::CURLOPT_PROXY_CAPATH, Arg::Ptr(p)) => {
            // SAFETY: as above.
            let path = ca_setting(unsafe { owned(p) }?);
            group(options)?.ca_path = path;
        }
        (
            ffi::CURLOPT_PROXY_CAINFO_BLOB
            | ffi::CURLOPT_PROXY_ISSUERCERT_BLOB
            | ffi::CURLOPT_PROXY_SSLCERT_BLOB
            | ffi::CURLOPT_PROXY_SSLKEY_BLOB,
            Arg::Ptr(p),
        ) => {
            // SAFETY: the application passes a blob or NULL.
            let value = unsafe { blob(p) }?;
            set(options, field(option), value)?;
        }
        (_, Arg::Ptr(p)) => {
            // SAFETY: the application passes a C string or NULL.
            let value = unsafe { owned(p) }?;
            set(options, field(option), value)?;
        }
        _ => unreachable!("an option `takes` names, of its type"),
    }
    Ok(())
}

/// The proxy's TLS options, to change: made, the proxy's group with
/// them, the first time.
fn group(options: &mut Options) -> Result<&mut TlsOptions, Refused> {
    Ok(options.proxy.make_mut()?.tls.options.make_mut()?)
}

/// Set the proxy's TLS option `field` to `value`: clearing one makes
/// neither group, as `Cold::set` does for one.
fn set(
    options: &mut Options,
    field: fn(&mut TlsOptions) -> &mut Option<Vec<u8>>,
    value: Option<Vec<u8>>,
) -> Result<(), Refused> {
    if value.is_none() && options.proxy.made_mut().is_none() {
        return Ok(());
    }
    Ok(options.proxy.make_mut()?.tls.options.set(field, value)?)
}

/// The field a string or blob option sets.
fn field(option: CURLoption) -> fn(&mut TlsOptions) -> &mut Option<Vec<u8>> {
    match option {
        ffi::CURLOPT_PROXY_CAINFO_BLOB => |t| &mut t.ca_blob,
        ffi::CURLOPT_PROXY_CRLFILE => |t| &mut t.crl_file,
        ffi::CURLOPT_PROXY_ISSUERCERT => |t| &mut t.issuer_cert,
        ffi::CURLOPT_PROXY_ISSUERCERT_BLOB => |t| &mut t.issuer_cert_blob,
        ffi::CURLOPT_PROXY_PINNEDPUBLICKEY => |t| &mut t.pinned_key,
        ffi::CURLOPT_PROXY_SSLCERT => |t| &mut t.cert,
        ffi::CURLOPT_PROXY_SSLCERT_BLOB => |t| &mut t.cert_blob,
        ffi::CURLOPT_PROXY_SSLCERTTYPE => |t| &mut t.cert_type,
        ffi::CURLOPT_PROXY_SSLKEY => |t| &mut t.key,
        ffi::CURLOPT_PROXY_SSLKEY_BLOB => |t| &mut t.key_blob,
        ffi::CURLOPT_PROXY_SSLKEYTYPE => |t| &mut t.key_type,
        ffi::CURLOPT_PROXY_KEYPASSWD => |t| &mut t.key_password,
        ffi::CURLOPT_PROXY_SSL_CIPHER_LIST => |t| &mut t.ciphers,
        ffi::CURLOPT_PROXY_TLS13_CIPHERS => |t| &mut t.tls13_ciphers,
        _ => unreachable!("a proxy's TLS text option"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curl_core::options::CaSetting;
    use std::ffi::{CString, c_void};

    fn text(s: &CString) -> Arg {
        Arg::Ptr(s.as_ptr().cast_mut().cast::<c_void>())
    }

    fn applied(options: &mut Options, option: CURLoption, arg: Arg) {
        assert!(takes(option));
        assert!(apply(options, option, arg).is_ok());
    }

    /// Each option sets the proxy's TLS, never the origin's; one that
    /// keeps a default or clears a setting makes no group, as C
    /// allocates nothing for it.
    #[test]
    fn sets_the_proxy_s_tls_alone() {
        let mut o = Options::default();
        applied(&mut o, ffi::CURLOPT_PROXY_SSL_VERIFYPEER, Arg::Long(1));
        applied(&mut o, ffi::CURLOPT_PROXY_SSL_VERIFYHOST, Arg::Long(2));
        applied(
            &mut o,
            ffi::CURLOPT_PROXY_KEYPASSWD,
            Arg::Ptr(std::ptr::null_mut()),
        );
        assert!(o.proxy.made_mut().is_none());
        applied(&mut o, ffi::CURLOPT_PROXY_SSL_VERIFYPEER, Arg::Long(0));
        assert!(!o.proxy.tls.verify_peer && o.proxy.tls.verify_host);
        applied(&mut o, ffi::CURLOPT_PROXY_SSL_VERIFYHOST, Arg::Long(0));
        assert!(!o.proxy.tls.verify_host);
        assert!(o.proxy.made_mut().unwrap().tls.options.made_mut().is_none());
        let ca = CString::new("/ca/proxy.pem").unwrap();
        applied(&mut o, ffi::CURLOPT_PROXY_CAINFO, text(&ca));
        assert!(
            matches!(&o.proxy.tls.options.ca_file, CaSetting::Given(f) if f == b"/ca/proxy.pem")
        );
        applied(
            &mut o,
            ffi::CURLOPT_PROXY_CAPATH,
            Arg::Ptr(std::ptr::null_mut()),
        );
        assert!(matches!(o.proxy.tls.options.ca_path, CaSetting::Unset));
        let pass = CString::new("secret").unwrap();
        applied(&mut o, ffi::CURLOPT_PROXY_KEYPASSWD, text(&pass));
        assert_eq!(
            o.proxy.tls.options.key_password.as_deref(),
            Some(&b"secret"[..])
        );
        let ciphers = CString::new("TLS_AES_128_GCM_SHA256").unwrap();
        applied(&mut o, ffi::CURLOPT_PROXY_TLS13_CIPHERS, text(&ciphers));
        assert_eq!(
            o.proxy.tls.options.tls13_ciphers.as_deref(),
            Some(&b"TLS_AES_128_GCM_SHA256"[..])
        );
        // The origin's are as they were.
        assert!(o.tls.verify_peer && o.tls.verify_host);
        assert!(o.tls.options.made_mut().is_none());
    }
}
