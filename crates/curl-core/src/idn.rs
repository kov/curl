//! Internationalized host names (`lib/idn.c`): a name not in ASCII is
//! looked up by its punycode form, which an IDN library makes, and shown
//! back from it on request. The core links none; a handle's `Libraries`
//! name the one its build has.

use std::fmt;

use curl_alloc::OutOfMemory;
#[cfg(any(test, feature = "test-util"))]
use curl_alloc::TryVec as _;

/// What converts host names, as libidn2 does for C.
pub trait Idn: fmt::Debug + Send + Sync {
    /// The ASCII form a name is looked up by (`Curl_idn_decode`): its
    /// labels in punycode, normalised as IDNA 2008 asks, or as IDNA 2003
    /// did where 2008 refuses the name.
    fn to_ascii(&self, name: &[u8]) -> Result<Vec<u8>, IdnFailure>;

    /// A name's labels in punycode shown in Unicode (`Curl_idn_encode`).
    fn to_unicode(&self, ascii: &[u8]) -> Result<Vec<u8>, IdnFailure>;
}

/// Why a name could not be converted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdnFailure {
    /// The name is no host name the library can convert.
    Malformed,
    OutOfMemory,
}

impl IdnFailure {
    /// The transfer's error: a name that does not convert is a malformed
    /// URL's (`peer_parse_host`).
    pub(crate) fn kind(self) -> crate::error::ErrorKind {
        match self {
            IdnFailure::Malformed => crate::error::ErrorKind::UrlMalformat,
            IdnFailure::OutOfMemory => crate::error::ErrorKind::OutOfMemory,
        }
    }
}

impl From<OutOfMemory> for IdnFailure {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        IdnFailure::OutOfMemory
    }
}

/// Why a name in Unicode is not looked up.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NameRefused {
    /// The library did not convert it, or converted it to nothing.
    Convert(IdnFailure),
    /// It converted to this, which holds a byte no host name may hold or
    /// ends as none may (`Curl_hostname_check`): a character that IDNA
    /// maps to `@`, `/` or another of a URL's delimiters.
    Illegal(Vec<u8>),
}

impl From<IdnFailure> for NameRefused {
    fn from(e: IdnFailure) -> Self {
        NameRefused::Convert(e)
    }
}

impl NameRefused {
    /// The transfer's error, said as `peer_parse_host` says it.
    pub(crate) fn fail<H: crate::multi::Host>(
        self,
        cx: &mut crate::multi::state::StepCx<'_, H>,
    ) -> crate::error::ErrorKind {
        match self {
            NameRefused::Convert(e) => e.kind(),
            NameRefused::Illegal(name) => crate::trace::fail_with(
                cx,
                crate::error::ErrorKind::UrlMalformat,
                &[b"Illegal hostname: ", &name],
            ),
        }
    }
}

/// The ASCII form `idn` makes of `name`, which is neither empty nor a
/// name a host may not have (`Curl_idn_decode`, then
/// `Curl_hostname_check`). The one caller of [`Idn::to_ascii`]: a
/// library's output is never used unchecked.
pub(crate) fn ascii_form(idn: &dyn Idn, name: &[u8]) -> Result<Vec<u8>, NameRefused> {
    let ascii = idn.to_ascii(name)?;
    if ascii.is_empty() {
        return Err(IdnFailure::Malformed.into());
    }
    if !crate::url::is_host_name(&ascii) {
        return Err(NameRefused::Illegal(ascii));
    }
    Ok(ascii)
}

/// The name `name` is looked up by: itself if in ASCII, else its ASCII
/// form, as [`ascii_form`] makes it. `None` for one in ASCII, or without
/// an IDN library, which sends it as it is, as C's build without one
/// does.
pub(crate) fn lookup_name(
    idn: Option<&dyn Idn>,
    name: &[u8],
) -> Result<Option<Vec<u8>>, NameRefused> {
    let Some(idn) = idn.filter(|_| !name.is_ascii()) else {
        return Ok(None);
    };
    ascii_form(idn, name).map(Some)
}

/// A test library that knows a few names, as libidn2 converts them.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct FakeIdn;

#[cfg(any(test, feature = "test-util"))]
impl FakeIdn {
    /// Each name it knows, in Unicode and in ASCII.
    const NAMES: &[(&'static str, &'static str)] = &[
        ("www.åäö.se", "www.xn--4cab6c.se"),
        ("www.große.de", "www.xn--groe-xna.de"),
        ("åäö.test", "xn--4cab6c.test"),
        // Zero-width characters, which IDNA maps to nothing.
        ("\u{200b}\u{200c}", ""),
        // Fullwidth forms, which IDNA maps to their ASCII: a commercial
        // at, a solidus and a full stop (lib1560's `set_idn_url`).
        (
            "trusted.example\u{ff20}evil.example",
            "trusted.example@evil.example",
        ),
        ("bad\u{ff0f}host.example", "bad/host.example"),
        ("a\u{ff0f}host.example", "a/host.example"),
        ("bad\u{ff0e}host.example", "bad.host.example"),
    ];
}

#[cfg(any(test, feature = "test-util"))]
impl Idn for FakeIdn {
    fn to_ascii(&self, name: &[u8]) -> Result<Vec<u8>, IdnFailure> {
        let found = Self::NAMES.iter().find(|(u, _)| u.as_bytes() == name);
        let (_, ascii) = found.ok_or(IdnFailure::Malformed)?;
        let mut out = Vec::new();
        out.try_extend_from_slice(ascii.as_bytes())?;
        Ok(out)
    }

    fn to_unicode(&self, ascii: &[u8]) -> Result<Vec<u8>, IdnFailure> {
        let found = Self::NAMES
            .iter()
            .find(|(_, a)| !a.is_empty() && a.as_bytes() == ascii);
        let mut out = Vec::new();
        match found {
            Some((unicode, _)) => out.try_extend_from_slice(unicode.as_bytes())?,
            // A name without punycode is itself.
            None => out.try_extend_from_slice(ascii)?,
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name in ASCII, or any name without a library, is looked up as
    /// it is; another by its ASCII form, which an empty one is not.
    #[test]
    fn a_name_is_looked_up_by_its_ascii_form() {
        let idn: Option<&dyn Idn> = Some(&FakeIdn);
        assert_eq!(lookup_name(idn, b"example.com"), Ok(None));
        assert_eq!(lookup_name(None, "www.åäö.se".as_bytes()), Ok(None));
        assert_eq!(
            lookup_name(idn, "www.åäö.se".as_bytes()),
            Ok(Some(b"www.xn--4cab6c.se".to_vec()))
        );
        assert_eq!(
            lookup_name(idn, "\u{200b}\u{200c}".as_bytes()),
            Err(IdnFailure::Malformed.into())
        );
        assert_eq!(
            lookup_name(idn, b"bad-\xe2\x90.local"),
            Err(IdnFailure::Malformed.into())
        );
    }

    /// A name whose ASCII form holds a delimiter of a URL is refused,
    /// with what it converted to; a fullwidth stop is an ordinary dot.
    #[test]
    fn a_name_converted_to_a_delimiter_is_refused() {
        let idn: Option<&dyn Idn> = Some(&FakeIdn);
        assert_eq!(
            lookup_name(idn, "trusted.example\u{ff20}evil.example".as_bytes()),
            Err(NameRefused::Illegal(
                b"trusted.example@evil.example".to_vec()
            ))
        );
        assert_eq!(
            lookup_name(idn, "bad\u{ff0f}host.example".as_bytes()),
            Err(NameRefused::Illegal(b"bad/host.example".to_vec()))
        );
        assert_eq!(
            lookup_name(idn, "bad\u{ff0e}host.example".as_bytes()),
            Ok(Some(b"bad.host.example".to_vec()))
        );
    }
}
