//! `--write-out`: text after each transfer, with `%{variable}`s replaced
//! by what the transfer reports (`src/tool_writeout.c`).
//!
//! Every variable C knows is named here, so an unknown one is told apart
//! from one not implemented yet; a format using the latter is refused
//! when the option is read, never written without it.

use std::io::Write;

use curl_alloc::TryVec;

use crate::stdout::Stdout;

/// C's limit on a variable's name, its terminating zero included: a longer
/// one ends the output there.
const MAX_NAME: usize = 24;

/// A variable C knows, and whether its value can be written yet.
struct Variable {
    name: &'static str,
    var: Option<Var>,
}

/// The variables written so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Var {
    /// The rest is written only after a failed transfer.
    OnError,
    /// What follows goes to standard output, or to standard error.
    Stdout,
    Stderr,
    ExitCode,
    /// The URL as the transfer was given it.
    Url,
    /// The output file, if any.
    FilenameEffective,
    SizeDownload,
    SizeUpload,
}

const fn known(name: &'static str) -> Variable {
    Variable { name, var: None }
}

const fn written(name: &'static str, var: Var) -> Variable {
    Variable {
        name,
        var: Some(var),
    }
}

/// C's `variables`, in its order.
const VARIABLES: &[Variable] = &[
    known("certs"),
    known("conn_id"),
    known("content_type"),
    known("errormsg"),
    written("exitcode", Var::ExitCode),
    written("filename_effective", Var::FilenameEffective),
    known("ftp_entry_path"),
    known("header_json"),
    known("http_code"),
    known("http_connect"),
    known("http_version"),
    known("json"),
    known("local_ip"),
    known("local_port"),
    known("method"),
    known("num_certs"),
    known("num_connects"),
    known("num_headers"),
    known("num_redirects"),
    known("num_retries"),
    written("onerror", Var::OnError),
    known("proxy_ssl_verify_result"),
    known("proxy_used"),
    known("redirect_url"),
    known("referer"),
    known("remote_ip"),
    known("remote_port"),
    known("response_code"),
    known("scheme"),
    known("size_delivered"),
    written("size_download", Var::SizeDownload),
    known("size_header"),
    known("size_request"),
    written("size_upload", Var::SizeUpload),
    known("speed_download"),
    known("speed_upload"),
    known("ssl_verify_result"),
    written("stderr", Var::Stderr),
    written("stdout", Var::Stdout),
    known("time_appconnect"),
    known("time_connect"),
    known("time_namelookup"),
    known("time_posttransfer"),
    known("time_pretransfer"),
    known("time_queue"),
    known("time_redirect"),
    known("time_starttransfer"),
    known("time_total"),
    known("tls_earlydata"),
    written("url", Var::Url),
    known("url.fragment"),
    known("url.host"),
    known("url.options"),
    known("url.password"),
    known("url.path"),
    known("url.port"),
    known("url.query"),
    known("url.scheme"),
    known("url.user"),
    known("url.zoneid"),
    known("url_effective"),
    known("urle.fragment"),
    known("urle.host"),
    known("urle.options"),
    known("urle.password"),
    known("urle.path"),
    known("urle.port"),
    known("urle.query"),
    known("urle.scheme"),
    known("urle.user"),
    known("urle.zoneid"),
    known("urlnum"),
    known("xfer_id"),
];

fn lookup(name: &[u8]) -> Option<&'static Variable> {
    VARIABLES.iter().find(|v| v.name.as_bytes() == name)
}

/// What a transfer reports, for the variables.
pub(crate) struct Facts<'a> {
    /// The transfer's CURLcode: 0 for success.
    pub(crate) exit_code: u8,
    pub(crate) url: &'a [u8],
    pub(crate) filename: Option<&'a [u8]>,
    pub(crate) size_download: u64,
    pub(crate) size_upload: u64,
}

/// One piece of a format.
enum Piece<'f> {
    /// Bytes written as they are.
    Text(&'f [u8]),
    /// A byte of an escape.
    Byte(u8),
    Variable(&'static Variable),
    /// A name C does not know, reported when met.
    Unknown(&'f [u8]),
    /// `%header{`, `%time{` or `%output{`, not implemented yet.
    Function(&'static str),
    /// A name too long for C's buffer: nothing more is written.
    End,
}

/// Read `format` as `ourWriteOut` does, giving each piece in turn.
fn pieces<'f>(format: &'f [u8], mut each: impl FnMut(Piece<'f>) -> bool) {
    let mut at = 0;
    while at < format.len() {
        let rest = &format[at..];
        let next = rest.get(1).copied();
        let (piece, used) = match (rest[0], next) {
            (b'%', Some(b'%')) => (Piece::Byte(b'%'), 2),
            (b'%', Some(b'{')) => match rest.iter().position(|&b| b == b'}') {
                // An unclosed `%{` is written as it is, and reading goes
                // on after it.
                None => (Piece::Text(&rest[..2]), 2),
                Some(end) => {
                    let name = &rest[2..end];
                    let piece = if name.len() + 1 > MAX_NAME {
                        Piece::End
                    } else {
                        lookup(name).map_or(Piece::Unknown(name), Piece::Variable)
                    };
                    (piece, end + 1)
                }
            },
            (b'%', Some(_)) if rest[1..].starts_with(b"header{") => {
                (Piece::Function("--write-out %header{}"), rest.len())
            }
            (b'%', Some(_)) if rest[1..].starts_with(b"time{") => {
                (Piece::Function("--write-out %time{}"), rest.len())
            }
            (b'%', Some(_)) if rest[1..].starts_with(b"output{") => {
                (Piece::Function("--write-out %output{}"), rest.len())
            }
            (b'\\', Some(escape @ (b'r' | b'n' | b't'))) => (
                Piece::Byte(match escape {
                    b'r' => b'\r',
                    b'n' => b'\n',
                    _ => b'\t',
                }),
                2,
            ),
            // Any other `%` or `\` is written with what follows it, which
            // is not read for itself.
            (b'%' | b'\\', Some(_)) => (Piece::Text(&rest[..2]), 2),
            _ => (Piece::Text(&rest[..1]), 1),
        };
        at += used;
        if !each(piece) {
            return;
        }
    }
}

/// What `format` uses that is not implemented yet, if anything: the
/// option is refused for it.
pub(crate) fn unimplemented(format: &[u8]) -> Option<&'static str> {
    let mut missing = None;
    pieces(format, |piece| {
        match piece {
            Piece::Variable(v) if v.var.is_none() => missing = Some(v.name),
            Piece::Function(f) => missing = Some(f),
            Piece::End => return false,
            _ => {}
        }
        missing.is_none()
    });
    missing
}

/// Write `format` for a transfer that reports `facts`, to standard output
/// unless it says otherwise. A failed write has nowhere to be reported,
/// as in C.
pub(crate) fn write(format: &[u8], facts: &Facts<'_>, stdout: &Stdout) {
    let mut stdout = Buffered(stdout);
    let mut stderr = std::io::stderr();
    let mut to_stderr = false;
    pieces(format, |piece| {
        let out: &mut dyn Write = if to_stderr { &mut stderr } else { &mut stdout };
        match piece {
            Piece::Text(text) => {
                let _ = out.write_all(text);
            }
            Piece::Byte(b) => {
                let _ = out.write_all(&[b]);
            }
            Piece::Variable(v) => match v.var.expect("refused when the option was read") {
                Var::OnError if facts.exit_code == 0 => return false,
                Var::OnError => {}
                Var::Stdout => to_stderr = false,
                Var::Stderr => to_stderr = true,
                Var::ExitCode => {
                    let _ = write!(out, "{}", facts.exit_code);
                }
                Var::Url => {
                    let _ = out.write_all(facts.url);
                }
                Var::FilenameEffective => {
                    if let Some(name) = facts.filename {
                        let _ = out.write_all(name);
                    }
                }
                Var::SizeDownload => {
                    let _ = write!(out, "{}", facts.size_download);
                }
                Var::SizeUpload => {
                    let _ = write!(out, "{}", facts.size_upload);
                }
            },
            Piece::Unknown(name) => {
                let mut line = Vec::new();
                for part in [&b"curl: unknown --write-out variable: '"[..], name, b"'\n"] {
                    if line.try_extend_from_slice(part).is_err() {
                        return true;
                    }
                }
                let _ = stderr.write_all(&line);
            }
            Piece::Function(_) => unreachable!("refused when the option was read"),
            Piece::End => return false,
        }
        true
    });
}

/// Standard output as a `Write`.
struct Buffered<'a>(&'a Stdout);

impl Write for Buffered<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pieces of `format`, as text, the way C writes them for a
    /// transfer that succeeded.
    fn render(format: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        pieces(format, |piece| {
            match piece {
                Piece::Text(t) => out.extend_from_slice(t),
                Piece::Byte(b) => out.push(b),
                Piece::Variable(v) => out.extend_from_slice(format!("<{}>", v.name).as_bytes()),
                Piece::Unknown(n) => {
                    out.extend_from_slice(b"<?");
                    out.extend_from_slice(n);
                    out.push(b'>');
                }
                Piece::Function(f) => out.extend_from_slice(f.as_bytes()),
                Piece::End => return false,
            }
            true
        });
        out
    }

    /// Tests 1440, 1441 and 1442, and the rest of C's reading.
    #[test]
    fn reads_formats_as_c() {
        assert_eq!(render(b"%{"), b"%{");
        assert_eq!(render(b"%"), b"%");
        assert_eq!(render(b"\\"), b"\\");
        assert_eq!(render(b"a%%b"), b"a%b");
        assert_eq!(render(b"%x\\x"), b"%x\\x");
        // What follows a `%` or a `\` is not read for itself.
        assert_eq!(render(b"%\\n\\%{url}%\\\\n"), b"%\\n\\%{url}%\\\n");
        assert_eq!(render(b"\\r\\n\\t"), b"\r\n\t");
        assert_eq!(render(b"%{url}!"), b"<url>!");
        assert_eq!(render(b"%{nope}%{"), b"<?nope>%{");
        // A name runs to the first `}`, whatever comes before it.
        assert_eq!(render(b"%{ %{url}"), b"<? %{url>");
        // The case matters, as `strcmp` decides.
        assert_eq!(render(b"%{URL}"), b"<?URL>");
        // 23 bytes fit C's buffer; 24 end the output.
        let fits = format!("%{{{}}}x", "a".repeat(23));
        assert_eq!(
            render(fits.as_bytes()),
            format!("<?{}>x", "a".repeat(23)).as_bytes()
        );
        let too_long = format!("a%{{{}}}x", "a".repeat(24));
        assert_eq!(render(too_long.as_bytes()), b"a");
    }

    #[test]
    fn refuses_what_is_not_implemented() {
        assert_eq!(unimplemented(b"%{url} %{exitcode}\\n"), None);
        assert_eq!(unimplemented(b"%{nosuch}"), None);
        assert_eq!(unimplemented(b"x %{http_code}"), Some("http_code"));
        assert_eq!(unimplemented(b"%header{a}"), Some("--write-out %header{}"));
        assert_eq!(unimplemented(b"%time{%H}"), Some("--write-out %time{}"));
        assert_eq!(unimplemented(b"%output{f}"), Some("--write-out %output{}"));
        let after_end = format!("%{{{}}}%{{http_code}}", "a".repeat(24));
        assert_eq!(unimplemented(after_end.as_bytes()), None);
        // The table is C's, sorted for its binary search.
        assert!(VARIABLES.windows(2).all(|w| w[0].name < w[1].name));
    }
}
