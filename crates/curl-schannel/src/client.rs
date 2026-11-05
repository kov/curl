//! The client's certificate (`get_client_cert`): a PKCS #12 file or
//! blob, or one in a system store, named as `<location>\<store>\<SHA-1
//! thumbprint>`.

use std::io::{Read as _, Seek as _, SeekFrom};

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::error::ErrorKind;
use curl_core::tls::{TlsCx, TlsIdentity};

use crate::crypt::{self, CertContext, CertStore, StoreLocation};
use crate::session::wide;
use crate::text::{Text, Wide};

/// The digits of a thumbprint (`CERT_THUMBPRINT_STR_LEN`).
const THUMBPRINT_LEN: usize = 40;
/// The most a certificate file may hold (`CURL_MAX_INPUT_LENGTH`).
const MOST_INPUT: u64 = 8_000_000;
/// `ERROR_INVALID_PASSWORD`.
const ERROR_INVALID_PASSWORD: u32 = 86;

/// The locations a path may name, in the order C tries them.
const LOCATIONS: &[&[u8]] = &[
    b"CurrentUser",
    b"LocalMachine",
    b"CurrentService",
    b"Services",
    b"Users",
    b"CurrentUserGroupPolicy",
    b"LocalMachineGroupPolicy",
    b"LocalMachineEnterprise",
];

/// Why a path names no store (`get_cert_location`'s failure).
enum NoLocation {
    Problem,
    OutOfMemory,
}

/// The store and thumbprint `path` names (`get_cert_location`): its
/// location, the store's name and the thumbprint, both UTF-16, the
/// store's ended by a zero. C compares a location's name only as far as
/// the path gives it, so a path's part that begins one names it.
fn location(path: &[u8]) -> Result<(StoreLocation, Vec<u16>, Vec<u16>), NoLocation> {
    let w = wide(path).map_err(|OutOfMemory| NoLocation::OutOfMemory)?;
    let w = &w[..w.len() - 1];
    let sep = w
        .iter()
        .position(|&c| c == u16::from(b'\\'))
        .ok_or(NoLocation::Problem)?;
    let part = &w[..sep];
    let name = LOCATIONS
        .iter()
        .find(|n| n.len() >= part.len() && n.iter().zip(part).all(|(&a, &b)| u16::from(a) == b))
        .ok_or(NoLocation::Problem)?;
    let location = StoreLocation::named(name).expect("a name of the list");
    let rest = &w[sep + 1..];
    let sep = rest
        .iter()
        .position(|&c| c == u16::from(b'\\'))
        .ok_or(NoLocation::Problem)?;
    let thumb = &rest[sep + 1..];
    if thumb.len() != THUMBPRINT_LEN {
        return Err(NoLocation::Problem);
    }
    let mut store = Vec::new();
    let mut thumbprint = Vec::new();
    (|| {
        store.try_extend_from_slice(&rest[..sep])?;
        store.try_push(0)?;
        thumbprint.try_extend_from_slice(thumb)
    })()
    .map_err(|OutOfMemory| NoLocation::OutOfMemory)?;
    Ok((location, store, thumbprint))
}

/// The whole of an open file, no longer than C reads one: empty if it
/// does not read.
fn read_open(file: &mut std::fs::File) -> Result<Vec<u8>, OutOfMemory> {
    let fail = Vec::new;
    let Ok(len) = file.seek(SeekFrom::End(0)) else {
        return Ok(fail());
    };
    if file.seek(SeekFrom::Start(0)).is_err() || len >= MOST_INPUT {
        return Ok(fail());
    }
    let mut data = Vec::new();
    data.try_resize(usize::try_from(len).expect("under the limit"), 0)?;
    if file.read_exact(&mut data).is_err() {
        return Ok(fail());
    }
    Ok(data)
}

/// The client certificate the identity names, and the store it lives in,
/// which must outlast the credential made with it; none if it names
/// none.
pub(crate) fn certificate(
    identity: &TlsIdentity,
    io: &mut TlsCx<'_>,
) -> Result<(Option<CertStore>, Option<CertContext>), ErrorKind> {
    let o = &identity.options;
    let (cert, blob) = match (&o.cert, &o.cert_blob) {
        (Some(c), _) => (Some(c.as_slice()), None),
        (None, Some(b)) => (None, Some(b.as_slice())),
        (None, None) => return Ok((None, None)),
    };
    let mut located = None;
    let mut file = None;
    if let Some(name) = cert {
        match location(name) {
            Ok(l) => located = Some(l),
            Err(why) => {
                let opened = (!name.is_empty())
                    .then(|| curl_os::fs::with_c_name(name, curl_os::fs::open_read).ok())
                    .flatten();
                match opened {
                    Some(f) => file = Some(f),
                    None => {
                        let kind = match why {
                            NoLocation::Problem => ErrorKind::SslCertproblem,
                            NoLocation::OutOfMemory => ErrorKind::OutOfMemory,
                        };
                        return Err(io.fail(
                            kind,
                            format_args!(
                                "schannel: Failed to get certificate location or file for {}",
                                Text(name)
                            ),
                        ));
                    }
                }
            }
        }
    }
    let shown = || -> Text<'_> {
        match cert {
            Some(name) if blob.is_none() => Text(name),
            _ => Text(b"(memory blob)"),
        }
    };
    if file.is_some() || blob.is_some() {
        if let Some(t) = &o.cert_type
            && !t.eq_ignore_ascii_case(b"P12")
        {
            return Err(io.fail(
                ErrorKind::SslCertproblem,
                format_args!(
                    "schannel: certificate format compatibility error for {}",
                    shown()
                ),
            ));
        }
        let read = match file.as_mut() {
            Some(f) => read_open(f).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?,
            None => Vec::new(),
        };
        drop(file);
        let data = match blob {
            Some(b) => b,
            None if read.is_empty() => {
                // C reads none of an empty file, nor of one it cannot read.
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!("schannel: Failed to read cert file {}", shown()),
                ));
            }
            None => &read[..],
        };
        let mut password =
            password(o.key_password.as_deref()).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        let imported = CertStore::pkcs12(data, &password);
        // The password goes as it came, wiped (`curlx_memzero`).
        password.iter_mut().for_each(|c| *c = 0);
        drop(password);
        let store = match imported {
            Ok(s) => s,
            Err(code) if code == ERROR_INVALID_PASSWORD => {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "schannel: Failed to import cert file {}, password is bad",
                        shown()
                    ),
                ));
            }
            Err(code) => {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "schannel: Failed to import cert file {}, last error is 0x{code:08x}",
                        shown()
                    ),
                ));
            }
        };
        let client = match store.first_with_key() {
            Ok(c) => c,
            Err(code) => {
                return Err(io.fail(
                    ErrorKind::SslCertproblem,
                    format_args!(
                        "schannel: Failed to get certificate from file {}, last error is 0x{code:08x}",
                        shown()
                    ),
                ));
            }
        };
        return Ok((Some(store), Some(client)));
    }
    let (location, name, thumb) = located.expect("a location when no file");
    let store = match CertStore::system(location, &name) {
        Ok(s) => s,
        Err(code) => {
            let loc = location.0;
            return Err(io.fail(
                ErrorKind::SslCertproblem,
                format_args!(
                    "schannel: Failed to open cert store {loc:x} {}, last error is 0x{code:08x}",
                    Wide(&name[..name.len() - 1])
                ),
            ));
        }
    };
    let Some(thumbprint) = crypt::thumbprint(&thumb) else {
        return Err(ErrorKind::SslCertproblem);
    };
    let Some(client) = store.find_by_hash(&thumbprint) else {
        return Err(io.fail(
            ErrorKind::SslCertproblem,
            format_args!("schannel: client cert not found in cert store"),
        ));
    };
    Ok((Some(store), Some(client)))
}

/// The key's password as UTF-16 ended by a zero: empty if it is not
/// UTF-8, as `MultiByteToWideChar` with `MB_ERR_INVALID_CHARS` gives
/// none.
fn password(given: Option<&[u8]>) -> Result<Vec<u16>, OutOfMemory> {
    let mut w = Vec::new();
    if let Some(p) = given
        && let Ok(text) = core::str::from_utf8(p)
    {
        for c in text.encode_utf16() {
            w.try_push(c)?;
        }
    }
    w.try_push(0)?;
    Ok(w)
}
