//! `ipfs://` and `ipns://` URLs, rewritten to an HTTP gateway's
//! (`src/tool_ipfs.c`).

use core::ffi::CStr;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::error::{ErrorKind, UrlErrorKind};
use curl_core::url::{GetOptions, ParseOptions, Part, SetOptions, Url};

use crate::msgs::Messages;

/// The longest first line of a gateway file taken, less one
/// (`MAX_GATEWAY_URL_LEN`).
const MAX_GATEWAY_LEN: usize = 10_000;

/// Which of the two a URL is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Ipfs,
    Ipns,
}

impl Kind {
    /// The kind `scheme` names, in any case.
    pub(crate) fn of_scheme(scheme: &[u8]) -> Option<Kind> {
        if scheme.eq_ignore_ascii_case(b"ipfs") {
            Some(Kind::Ipfs)
        } else if scheme.eq_ignore_ascii_case(b"ipns") {
            Some(Kind::Ipns)
        } else {
            None
        }
    }

    fn name(self) -> &'static [u8] {
        match self {
            Kind::Ipfs => b"ipfs",
            Kind::Ipns => b"ipns",
        }
    }
}

/// Why a URL was not rewritten.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failed {
    /// The URL, or the gateway found, does not make one.
    Malformed,
    /// No gateway was given or found.
    NoGateway,
    /// `--ipfs-gateway` does not parse.
    BadGateway,
    OutOfMemory,
}

impl Failed {
    /// The transfer's result, said as C's `ipfs_url_rewrite` says it.
    pub(crate) fn said(self, msgs: &Messages) -> ErrorKind {
        let (kind, why): (_, &[u8]) = match self {
            Failed::Malformed => (ErrorKind::UrlMalformat, b"malformed target URL"),
            Failed::NoGateway => (
                ErrorKind::FileCouldntReadFile,
                b"IPFS automatic gateway detection failed",
            ),
            Failed::BadGateway => (
                ErrorKind::BadFunctionArgument,
                b"--ipfs-gateway was given a malformed URL",
            ),
            Failed::OutOfMemory => return ErrorKind::OutOfMemory,
        };
        msgs.help(&[why]);
        kind
    }
}

impl From<OutOfMemory> for Failed {
    fn from(_: OutOfMemory) -> Self {
        Failed::OutOfMemory
    }
}

/// Any URL failure but memory's is a malformed one.
fn malformed(e: UrlErrorKind) -> Failed {
    match e {
        UrlErrorKind::OutOfMemory => Failed::OutOfMemory,
        _ => Failed::Malformed,
    }
}

/// `url`, an `ipfs://` or `ipns://` URL of `kind` as the tool parsed it,
/// rewritten to the gateway `given` (`--ipfs-gateway`) or found: its
/// scheme, host and port, if it sets one, and its path, then `/ipfs/` or
/// `/ipns/`, the URL's host and its path, kept encoded so that no `..`
/// leaves that place (`ipfs_url_rewrite`).
pub(crate) fn rewrite(url: &mut Url, kind: Kind, given: Option<&[u8]>) -> Result<Vec<u8>, Failed> {
    let cid = url.get(Part::Host, GetOptions::NONE).map_err(malformed)?;
    let gateway = match given {
        Some(given) => {
            let guess = ParseOptions {
                guess_scheme: true,
                ..ParseOptions::NONE
            };
            Url::parse(given, guess).map_err(|e| match e {
                UrlErrorKind::OutOfMemory => Failed::OutOfMemory,
                _ => Failed::BadGateway,
            })?
        }
        None => {
            let found = found_gateway()?.ok_or(Failed::NoGateway)?;
            Url::parse(&found, ParseOptions::NONE).map_err(malformed)?
        }
    };
    // A gateway with a query is not taken.
    match gateway.get(Part::Query, GetOptions::NONE) {
        Err(UrlErrorKind::NoQuery) => {}
        Err(UrlErrorKind::OutOfMemory) => return Err(Failed::OutOfMemory),
        _ => return Err(Failed::Malformed),
    }
    let decode = GetOptions {
        url_decode: true,
        ..GetOptions::NONE
    };
    let host = gateway.get(Part::Host, decode).map_err(malformed)?;
    let scheme = gateway.get(Part::Scheme, decode).map_err(malformed)?;
    let gw_path = gateway
        .get(Part::Path, GetOptions::NONE)
        .map_err(malformed)?;
    // Only a port the gateway sets is kept: one its scheme implies
    // changes with the scheme.
    let port = match gateway.get(Part::Port, GetOptions::NONE) {
        Ok(port) => Some(port),
        Err(UrlErrorKind::NoPort) => None,
        Err(e) => return Err(malformed(e)),
    };
    let path = url.get(Part::Path, GetOptions::NONE).map_err(malformed)?;
    let encode = SetOptions {
        parse: ParseOptions {
            url_encode: true,
            ..ParseOptions::NONE
        },
        ..SetOptions::NONE
    };
    url.set(Part::Scheme, Some(&scheme), encode)
        .and_then(|()| url.set(Part::Host, Some(&host), encode))
        .and_then(|()| url.set(Part::Port, port.as_deref(), encode))
        .map_err(malformed)?;
    let path = if path == b"/" { &path[..0] } else { &path[..] };
    let mut new_path = Vec::new();
    new_path.try_extend_from_slice(&gw_path)?;
    if gw_path.last() != Some(&b'/') {
        new_path.try_push(b'/')?;
    }
    new_path.try_extend_from_slice(kind.name())?;
    new_path.try_push(b'/')?;
    new_path.try_extend_from_slice(&cid)?;
    new_path.try_extend_from_slice(path)?;
    url.set(Part::Path, Some(&new_path), SetOptions::NONE)
        .map_err(malformed)?;
    let shown = GetOptions {
        url_encode: true,
        ..GetOptions::NONE
    };
    url.get(Part::Url, shown).map_err(malformed)
}

/// The gateway the environment names (`ipfs_gateway`): `IPFS_GATEWAY`
/// as it is, or the first line of the file `gateway` in `IPFS_PATH`, or
/// else in `~/.ipfs`; none if that line is empty, too long or the file
/// is not there.
fn found_gateway() -> Result<Option<Vec<u8>>, OutOfMemory> {
    if let Some(gateway) = curl_os::env::var(b"IPFS_GATEWAY")? {
        return Ok(Some(gateway));
    }
    // An empty one is as none (`curl_getenv`).
    let set = |name| Ok::<_, OutOfMemory>(curl_os::env::var(name)?.filter(|v| !v.is_empty()));
    let mut file = match set(b"IPFS_PATH")? {
        Some(path) => path,
        None => match set(b"HOME")? {
            Some(mut home) => {
                home.try_extend_from_slice(b"/.ipfs/")?;
                home
            }
            None => return Ok(None),
        },
    };
    if file.last() != Some(&b'/') {
        file.try_push(b'/')?;
    }
    file.try_extend_from_slice(b"gateway\0")?;
    let Ok(path) = CStr::from_bytes_with_nul(&file) else {
        return Ok(None);
    };
    let Ok(opened) = curl_os::fs::open_read(path) else {
        return Ok(None);
    };
    first_line(opened)
}

/// The first line `from` reads, to a line feed, a carriage return or
/// the end; none if empty, or longer than C's buffer holds. It is read
/// through a buffer on the stack, as C's `getc` reads through stdio's:
/// the line is the one allocation.
fn first_line(mut from: impl std::io::Read) -> Result<Option<Vec<u8>>, OutOfMemory> {
    let mut line = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let read = match from.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // A read that fails ends the line, as C's `getc` does.
            Err(_) => break,
        };
        let got = &chunk[..read];
        let end = got.iter().position(|&b| b == b'\n' || b == b'\r');
        let part = &got[..end.unwrap_or(read)];
        if line.len() + part.len() >= MAX_GATEWAY_LEN {
            return Ok(None);
        }
        line.try_extend_from_slice(part)?;
        if end.is_some() {
            break;
        }
    }
    Ok((!line.is_empty()).then_some(line))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewritten(url: &str, gateway: &str) -> Result<String, Failed> {
        let parse = ParseOptions {
            guess_scheme: true,
            non_support_scheme: true,
            ..ParseOptions::NONE
        };
        let mut parsed = Url::parse(url.as_bytes(), parse).unwrap();
        let scheme = parsed.get(Part::Scheme, GetOptions::NONE).unwrap();
        let kind = Kind::of_scheme(&scheme).unwrap();
        rewrite(&mut parsed, kind, Some(gateway.as_bytes())).map(|u| String::from_utf8(u).unwrap())
    }

    /// The URLs C's tool makes (tests 727, 730-735, 739, 1691, 1851), and
    /// what it does with the rest of the URL.
    #[test]
    fn rewrites_as_c_does() {
        let ok = |s: &str| Ok(s.to_string());
        assert_eq!(
            rewritten("ipfs://r4nd0m", "http://gw.test"),
            ok("http://gw.test/ipfs/r4nd0m")
        );
        assert_eq!(
            rewritten("ipfs://cid", "gw.test"),
            ok("http://gw.test/ipfs/cid"),
            "guessed"
        );
        assert_eq!(
            rewritten("IPNS://cid/a/b?q=1&r=2#f", "http://gw.test:8/some/path/"),
            ok("http://gw.test:8/some/path/ipns/cid/a/b?q=1&r=2#f")
        );
        assert_eq!(
            rewritten("ipfs://u:p@cid:99/x", "http://gw.test/g"),
            ok("http://u:p@gw.test/g/ipfs/cid/x"),
            "the URL's port goes with its host"
        );
        assert_eq!(
            rewritten(
                "ipfs://cid/%2f..%2f..%2fadmin/config",
                "http://gw.test/private/gateway"
            ),
            ok("http://gw.test/private/gateway/ipfs/cid/%2F..%2F..%2Fadmin/config"),
            "an encoded slash stays one"
        );
        assert_eq!(
            rewritten("ipfs://cid", "http://gw.test/?a=b"),
            Err(Failed::Malformed)
        );
        assert_eq!(
            rewritten("ipfs://cid", "http://bad,host:8080"),
            Err(Failed::BadGateway)
        );
    }

    /// The gateway file's first line, to its end, if short enough.
    #[test]
    fn reads_the_first_line_of_the_gateway_file() {
        let line = |text: &[u8]| first_line(text).unwrap();
        assert_eq!(line(b"http://a\nhttp://b\n"), Some(b"http://a".to_vec()));
        assert_eq!(line(b"http://a\r\n"), Some(b"http://a".to_vec()));
        assert_eq!(line(b"http://a"), Some(b"http://a".to_vec()));
        assert_eq!(line(b"\nhttp://b"), None);
        assert_eq!(line(&[b'a'; 9_999]).map(|l| l.len()), Some(9_999));
        assert_eq!(line(&[b'a'; 10_000]), None);
    }

    /// Reading the gateway file allocates the line and nothing else, as
    /// C's `getc` loop allocates only its dynbuf: an allocation the tool
    /// could not refuse would abort the torture run (test 724).
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn reads_the_gateway_file_allocating_only_the_line() {
        let (line, cost) = curl_alloc::track::measure(|| first_line(&b"http://a\nrest"[..]));
        assert_eq!(line.unwrap(), Some(b"http://a".to_vec()));
        assert_eq!(cost.allocations, 1, "more than the line allocated");
    }
}
