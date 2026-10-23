//! `--xattr`: where a download came from, stored with its file as
//! extended attributes (`src/tool_xattr.c`).

use std::ffi::CStr;
use std::io;
use std::os::fd::BorrowedFd;

use curl_core::report::TransferReport;
use curl_core::url::{GetOptions, ParseOptions, Part, SetOptions, Url};

use crate::stdout::Stdout;

/// `url` without its user and password (`stripcredentials`); `None` if
/// it cannot be read as a URL.
fn strip_credentials(url: &[u8]) -> Option<Vec<u8>> {
    let parse = ParseOptions {
        guess_scheme: true,
        ..ParseOptions::NONE
    };
    let mut url = Url::parse(url, parse).ok()?;
    url.set(Part::User, None, SetOptions::NONE).ok()?;
    url.set(Part::Password, None, SetOptions::NONE).ok()?;
    url.get(Part::Url, GetOptions::NONE).ok()
}

/// Where the attributes go: the file, or, in the debug test build with
/// `CURL_FAKE_XATTR` set, standard output, a line each.
enum Target<'a> {
    File(BorrowedFd<'a>),
    Shown(&'a Stdout),
}

impl Target<'_> {
    /// Set attribute `name` to `value` (`xattr`).
    fn set(&self, name: &CStr, value: &[u8]) -> io::Result<()> {
        match self {
            Target::File(fd) => curl_os::xattr::set(*fd, name, value),
            Target::Shown(stdout) => {
                for part in [name.to_bytes(), b" => ", value, b"\n"] {
                    // A failed write shows when standard output is flushed.
                    stdout.fwrite(part);
                }
                Ok(())
            }
        }
    }
}

/// Store the transfer's metadata with the file `fd` (`fwrite_xattr`):
/// who made it, the referer sent, the type of what came, and `url`
/// without its credentials. The first that fails stops the rest.
pub(crate) fn write(
    fd: BorrowedFd<'_>,
    url: &[u8],
    report: &TransferReport,
    stdout: &Stdout,
) -> io::Result<()> {
    let target = if cfg!(feature = "debug-hooks") && curl_os::env::is_set(b"CURL_FAKE_XATTR") {
        Target::Shown(stdout)
    } else {
        Target::File(fd)
    };
    target.set(c"user.creator", b"curl")?;
    if let Some(referer) = report.referer() {
        target.set(c"user.xdg.referrer.url", referer)?;
    }
    if let Some(mime) = report.content_type() {
        target.set(c"user.mime_type", mime)?;
    }
    // A URL that cannot be read fails with whatever the system said
    // last, as C's does; nothing was.
    let origin = strip_credentials(url).ok_or_else(|| io::Error::from_raw_os_error(0))?;
    target.set(c"user.xdg.origin.url", &origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The URL is stored without user and password, its scheme guessed
    /// as C's `stripcredentials` guesses it.
    #[test]
    fn strips_credentials_as_c_does() {
        let strip =
            |u: &str| strip_credentials(u.as_bytes()).map(|s| String::from_utf8(s).unwrap());
        assert_eq!(strip("http://u:p@h/a?b").as_deref(), Some("http://h/a?b"));
        assert_eq!(strip("http://u@h:8/").as_deref(), Some("http://h:8/"));
        assert_eq!(strip("h/a").as_deref(), Some("http://h/a"));
        assert_eq!(strip("ftp.h/a").as_deref(), Some("ftp://ftp.h/a"));
        assert_eq!(strip("http://[::1"), None);
    }
}
