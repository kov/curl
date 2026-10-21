//! Authenticating HTTP requests (`lib/http.c`'s `Curl_http_output_auth`):
//! Basic, with the credentials the URL carries (`url_set_data_creds`).

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::error::UrlErrorKind;
use crate::url::{GetOptions, Part, Url, decode_but_zero};

/// The user and password a transfer authenticates with, decoded (C's
/// `struct Curl_creds`, from the URL alone so far).
#[derive(Debug)]
pub(crate) struct Credentials {
    user: Vec<u8>,
    password: Vec<u8>,
}

/// Why a URL's credentials could not be taken.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CredentialsError {
    OutOfMemory,
    /// One decodes to a zero byte: "error extracting credentials from URL".
    Malformed,
}

impl From<OutOfMemory> for CredentialsError {
    fn from(_: OutOfMemory) -> Self {
        CredentialsError::OutOfMemory
    }
}

impl Credentials {
    /// What `url` carries, if it has a user or a password: decoded,
    /// rejecting a zero byte (HTTP allows other control bytes,
    /// `PROTOPT_USERPWDCTRL`).
    pub(crate) fn of_url(url: &Url) -> Result<Option<Credentials>, CredentialsError> {
        let part = |what, missing| match url.get(what, GetOptions::NONE) {
            Ok(raw) => match decode_but_zero(&raw) {
                Ok(Some(decoded)) => Ok(Some(decoded)),
                Ok(None) => Err(CredentialsError::Malformed),
                Err(_) => Err(CredentialsError::OutOfMemory),
            },
            Err(e) if e == missing => Ok(None),
            Err(UrlErrorKind::OutOfMemory) => Err(CredentialsError::OutOfMemory),
            Err(_) => Err(CredentialsError::Malformed),
        };
        let user = part(Part::User, UrlErrorKind::NoUser)?;
        let password = part(Part::Password, UrlErrorKind::NoPassword)?;
        if user.is_none() && password.is_none() {
            return Ok(None);
        }
        Ok(Some(Credentials {
            user: user.unwrap_or_default(),
            password: password.unwrap_or_default(),
        }))
    }

    pub(crate) fn user(&self) -> &[u8] {
        &self.user
    }

    /// `user:password` in base64, what `Authorization: Basic` carries;
    /// nothing when both are empty (`Curl_creds_has_user_or_pass`).
    pub(crate) fn basic(&self) -> Result<Option<Vec<u8>>, OutOfMemory> {
        if self.user.is_empty() && self.password.is_empty() {
            return Ok(None);
        }
        let len = self.user.len() + 1 + self.password.len();
        let mut out = Vec::new();
        out.try_reserve_exact(len.div_ceil(3) * 4)
            .map_err(|_| OutOfMemory)?;
        let bytes = self.user.iter().chain(b":").chain(&self.password).copied();
        base64(bytes, len, &mut out)?;
        Ok(Some(out))
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `len` bytes from `bytes` in base64 with padding, into `out`.
fn base64(
    mut bytes: impl Iterator<Item = u8>,
    len: usize,
    out: &mut Vec<u8>,
) -> Result<(), OutOfMemory> {
    for _ in 0..len.div_ceil(3) {
        let group = [bytes.next(), bytes.next(), bytes.next()];
        let n = group
            .iter()
            .fold(0u32, |n, b| n << 8 | u32::from(b.unwrap_or(0)));
        let have = group.iter().filter(|b| b.is_some()).count();
        for i in 0..4 {
            let c = if i <= have {
                ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize]
            } else {
                b'='
            };
            out.try_push(c)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::ParseOptions;

    /// A user and a password.
    type Pair = (Vec<u8>, Vec<u8>);

    fn creds(url: &str) -> Result<Option<Pair>, CredentialsError> {
        let url = Url::parse(url.as_bytes(), ParseOptions::NONE).unwrap();
        Ok(Credentials::of_url(&url)?.map(|c| (c.user, c.password)))
    }

    /// As the C tool takes them from `http://USERINFO@host/`.
    #[test]
    fn takes_the_url_s_credentials_as_c() {
        let some = |u: &[u8], p: &[u8]| Ok(Some((u.to_vec(), p.to_vec())));
        assert_eq!(creds("http://h/"), Ok(None));
        assert_eq!(creds("http://:example@h/"), some(b"", b"example"));
        assert_eq!(creds("http://u@h/"), some(b"u", b""));
        assert_eq!(creds("http://u:@h/"), some(b"u", b""));
        assert_eq!(creds("http://@h/"), some(b"", b""));
        assert_eq!(creds("http://a%01b:x%3a@h/"), some(b"a\x01b", b"x:"));
        assert_eq!(creds("http://a%00b:x@h/"), Err(CredentialsError::Malformed));
        assert_eq!(creds("http://a:%00@h/"), Err(CredentialsError::Malformed));
    }

    /// The values the C tool sends, and RFC 4648's vectors.
    #[test]
    fn encodes_basic_as_c() {
        let basic = |u: &[u8], p: &[u8]| {
            let c = Credentials {
                user: u.to_vec(),
                password: p.to_vec(),
            };
            c.basic().unwrap().map(|b| String::from_utf8(b).unwrap())
        };
        assert_eq!(basic(b"", b"example").as_deref(), Some("OmV4YW1wbGU="));
        assert_eq!(basic(b"u", b"").as_deref(), Some("dTo="));
        assert_eq!(basic(b"a\x01b", b"x").as_deref(), Some("YQFiOng="));
        assert_eq!(basic(b"fo", b"").as_deref(), Some("Zm86"));
        assert_eq!(basic(b"foob", b"r").as_deref(), Some("Zm9vYjpy"));
        // `http://@host/` and `http://:@host/` send none.
        assert_eq!(basic(b"", b""), None);
    }
}
