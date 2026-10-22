//! `--write-out`: text after each transfer, with `%{variable}`s replaced
//! by what the transfer reports (`src/tool_writeout.c`).
//!
//! Every variable C knows is written here. A function not implemented
//! yet (`%time{}`) is refused when the option is read, never written
//! without it.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt as _;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec, try_format};
use curl_core::error::ErrorKind;
use curl_core::report::{HeaderStore, Origins, Request, ResponseVersion, TransferReport};
use curl_core::url::{GetOptions, ParseOptions, Part, Url};

use crate::options::exit_code;
use crate::slurp::{self, ReadFailed};
use crate::stdout::Stdout;

/// C's limit on a variable's name, its terminating zero included: a longer
/// one ends the output there.
const MAX_NAME: usize = 24;

/// A variable C knows, and what it writes.
struct Variable {
    name: &'static str,
    var: Var,
}

/// The variables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Var {
    /// The rest is written only after a failed transfer.
    OnError,
    /// What follows goes to standard output, or to standard error.
    Stdout,
    Stderr,
    ExitCode,
    /// Why the transfer failed; nothing if it did not.
    ErrorMsg,
    /// The URL as the transfer was given it.
    Url,
    /// A part of the URL as given, or of the URL the transfer used
    /// (`effective`).
    UrlPart {
        part: Part,
        effective: bool,
    },
    /// The URL the transfer used.
    UrlEffective,
    /// Where the last response's `Location:` would have led.
    RedirectUrl,
    /// The number of the URL on the command line, from 0.
    UrlNum,
    /// The output file, if any.
    FilenameEffective,
    /// The last response's status code, in three digits.
    HttpCode,
    /// The status a proxy last answered `CONNECT` with, likewise.
    HttpConnect,
    HttpVersion,
    /// The scheme of the connection used, lowercase.
    Scheme,
    ContentType,
    /// The ends of the connection last used: an address, or a port, -1
    /// before any connection.
    LocalIp,
    LocalPort,
    RemoteIp,
    RemotePort,
    NumConnects,
    NumRedirects,
    Method,
    Referer,
    NumHeaders,
    NumRetries,
    SizeRequest,
    SizeDelivered,
    SizeDownload,
    SizeHeader,
    SizeUpload,
    SpeedDownload,
    SpeedUpload,
    Time(Time),
    /// The last response's headers, as a JSON object of lists.
    HeaderJson,
    /// Every variable but these five, as a JSON object.
    Json,
    /// The servers' certificates, which no transfer without TLS has.
    Certs,
    NumCerts,
    /// The number of the connection last used, -1 if none.
    ConnId,
    /// The number the transfer was given as it joined the pool.
    XferId,
    /// The path an FTP server started in: never, without FTP.
    FtpEntryPath,
    /// What checking the certificates of a TLS proxy and of the server
    /// gave: nothing to check, without TLS.
    ProxySslVerifyResult,
    SslVerifyResult,
    /// The transfer's last connection went through a proxy, as 1.
    ProxyUsed,
    /// Bytes sent as TLS early data: none, without TLS.
    TlsEarlydata,
}

/// A moment of the transfer, as seconds since its start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Time {
    Appconnect,
    Connect,
    Namelookup,
    Posttransfer,
    Pretransfer,
    Queue,
    Redirect,
    Starttransfer,
    Total,
}

const fn written(name: &'static str, var: Var) -> Variable {
    Variable { name, var }
}

const fn part(part: Part, effective: bool) -> Var {
    Var::UrlPart { part, effective }
}

/// C's `variables`, in its order.
const VARIABLES: &[Variable] = &[
    written("certs", Var::Certs),
    written("conn_id", Var::ConnId),
    written("content_type", Var::ContentType),
    written("errormsg", Var::ErrorMsg),
    written("exitcode", Var::ExitCode),
    written("filename_effective", Var::FilenameEffective),
    written("ftp_entry_path", Var::FtpEntryPath),
    written("header_json", Var::HeaderJson),
    written("http_code", Var::HttpCode),
    written("http_connect", Var::HttpConnect),
    written("http_version", Var::HttpVersion),
    written("json", Var::Json),
    written("local_ip", Var::LocalIp),
    written("local_port", Var::LocalPort),
    written("method", Var::Method),
    written("num_certs", Var::NumCerts),
    written("num_connects", Var::NumConnects),
    written("num_headers", Var::NumHeaders),
    written("num_redirects", Var::NumRedirects),
    written("num_retries", Var::NumRetries),
    written("onerror", Var::OnError),
    written("proxy_ssl_verify_result", Var::ProxySslVerifyResult),
    written("proxy_used", Var::ProxyUsed),
    written("redirect_url", Var::RedirectUrl),
    written("referer", Var::Referer),
    written("remote_ip", Var::RemoteIp),
    written("remote_port", Var::RemotePort),
    written("response_code", Var::HttpCode),
    written("scheme", Var::Scheme),
    written("size_delivered", Var::SizeDelivered),
    written("size_download", Var::SizeDownload),
    written("size_header", Var::SizeHeader),
    written("size_request", Var::SizeRequest),
    written("size_upload", Var::SizeUpload),
    written("speed_download", Var::SpeedDownload),
    written("speed_upload", Var::SpeedUpload),
    written("ssl_verify_result", Var::SslVerifyResult),
    written("stderr", Var::Stderr),
    written("stdout", Var::Stdout),
    written("time_appconnect", Var::Time(Time::Appconnect)),
    written("time_connect", Var::Time(Time::Connect)),
    written("time_namelookup", Var::Time(Time::Namelookup)),
    written("time_posttransfer", Var::Time(Time::Posttransfer)),
    written("time_pretransfer", Var::Time(Time::Pretransfer)),
    written("time_queue", Var::Time(Time::Queue)),
    written("time_redirect", Var::Time(Time::Redirect)),
    written("time_starttransfer", Var::Time(Time::Starttransfer)),
    written("time_total", Var::Time(Time::Total)),
    written("tls_earlydata", Var::TlsEarlydata),
    written("url", Var::Url),
    written("url.fragment", part(Part::Fragment, false)),
    written("url.host", part(Part::Host, false)),
    written("url.options", part(Part::Options, false)),
    written("url.password", part(Part::Password, false)),
    written("url.path", part(Part::Path, false)),
    written("url.port", part(Part::Port, false)),
    written("url.query", part(Part::Query, false)),
    written("url.scheme", part(Part::Scheme, false)),
    written("url.user", part(Part::User, false)),
    written("url.zoneid", part(Part::ZoneId, false)),
    written("url_effective", Var::UrlEffective),
    written("urle.fragment", part(Part::Fragment, true)),
    written("urle.host", part(Part::Host, true)),
    written("urle.options", part(Part::Options, true)),
    written("urle.password", part(Part::Password, true)),
    written("urle.path", part(Part::Path, true)),
    written("urle.port", part(Part::Port, true)),
    written("urle.query", part(Part::Query, true)),
    written("urle.scheme", part(Part::Scheme, true)),
    written("urle.user", part(Part::User, true)),
    written("urle.zoneid", part(Part::ZoneId, true)),
    written("urlnum", Var::UrlNum),
    written("xfer_id", Var::XferId),
];

fn lookup(name: &[u8]) -> Option<&'static Variable> {
    VARIABLES.iter().find(|v| v.name.as_bytes() == name)
}

/// What the variables are read from: the transfer's report, and what only
/// the tool knows of it.
pub(crate) struct Facts<'a> {
    pub(crate) result: Result<(), ErrorKind>,
    /// The URL as given.
    pub(crate) url: &'a [u8],
    /// Its number on the command line, from 0.
    pub(crate) urlnum: u64,
    /// Header lines with a colon in the last response's head.
    pub(crate) num_headers: u64,
    /// Times the transfer was tried again.
    pub(crate) num_retries: u64,
    pub(crate) filename: Option<&'a [u8]>,
    /// `CURLINFO_EFFECTIVE_METHOD`.
    pub(crate) method: &'a [u8],
    pub(crate) report: &'a TransferReport,
}

/// A format, as given or as read from a file.
#[derive(Debug)]
pub(crate) enum Format<'a> {
    Given(&'a [u8]),
    Read(Vec<u8>),
}

impl Format<'_> {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Format::Given(text) => text,
            Format::Read(text) => text,
        }
    }

    /// The text of file `name`, or of standard input for `-`, its
    /// carriage returns and line feeds left out (`file2string`).
    pub(crate) fn read(name: &[u8]) -> Result<Format<'static>, ReadFailed> {
        slurp::read(name, slurp::As::Text).map(Format::Read)
    }
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
    /// `%output{name}`, or `%output{>>name}` to `append`: what follows is
    /// written to that file, if it opens.
    Output {
        name: &'f [u8],
        append: bool,
    },
    /// `%header{name}`, the last response's first header of that name,
    /// or `%header{name:all:sep}`, every request's, `sep` between them.
    Header {
        name: &'f [u8],
        all: Option<&'f [u8]>,
    },
    /// `%time{`, not implemented yet.
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
            (b'%', Some(_)) if rest[1..].starts_with(b"header{") => header(&rest[8..]),
            (b'%', Some(_)) if rest[1..].starts_with(b"time{") => {
                (Piece::Function("--write-out %time{}"), rest.len())
            }
            (b'%', Some(_)) if rest[1..].starts_with(b"output{") => {
                let after = &rest[8..];
                let (append, name_at) = match after.strip_prefix(b">>") {
                    Some(_) => (true, 10),
                    None => (false, 8),
                };
                match rest[name_at..].iter().position(|&b| b == b'}') {
                    // C's buffer holds 511 bytes of name: a longer one is
                    // passed over.
                    Some(len) if len < 512 => (
                        Piece::Output {
                            name: &rest[name_at..name_at + len],
                            append,
                        },
                        name_at + len + 1,
                    ),
                    Some(len) => (Piece::Text(b""), name_at + len + 1),
                    // Unclosed: written, the `>>` lost, and reading goes on
                    // after it.
                    None => (Piece::Text(b"%output{"), name_at),
                }
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

/// `%header{`'s piece, from what follows it, and how much of the format
/// it took (`output_header`): it ends at the first `}` not after a `\`;
/// unended, `%header{` is written as it is.
fn header(after: &[u8]) -> (Piece<'_>, usize) {
    let end = (0..after.len()).find(|&i| after[i] == b'}' && (i == 0 || after[i - 1] != b'\\'));
    let Some(end) = end else {
        return (Piece::Text(b"%header{"), 8);
    };
    let inside = &after[..end];
    let (name, all) = match inside.iter().position(|&b| b == b':') {
        Some(colon) if inside[colon + 1..].starts_with(b"all:") => {
            (&inside[..colon], Some(&inside[colon + 5..]))
        }
        _ => (inside, None),
    };
    // C's buffer holds 255 bytes of name: a longer one writes nothing.
    let piece = if name.len() < 256 {
        Piece::Header { name, all }
    } else {
        Piece::Text(b"")
    };
    (piece, 8 + end + 1)
}

/// What `format` uses that is not implemented yet, if anything: the
/// option is refused for it.
pub(crate) fn unimplemented(format: &[u8]) -> Option<&'static str> {
    let mut missing = None;
    pieces(format, |piece| {
        match piece {
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
    write_to(format, facts, &mut Buffered(stdout), &mut std::io::stderr());
}

/// Where the format's text goes now.
enum To {
    Stdout,
    Stderr,
    /// The file `%output{}` named, closed when another is chosen.
    File(File),
}

fn write_to(format: &[u8], facts: &Facts<'_>, stdout: &mut dyn Write, stderr: &mut dyn Write) {
    let mut to = To::Stdout;
    pieces(format, |piece| {
        let out: &mut dyn Write = match &mut to {
            To::Stdout => &mut *stdout,
            To::Stderr => &mut *stderr,
            To::File(file) => file,
        };
        match piece {
            Piece::Text(text) => {
                let _ = out.write_all(text);
            }
            Piece::Byte(b) => {
                let _ = out.write_all(&[b]);
            }
            Piece::Variable(v) => match v.var {
                Var::OnError if facts.result.is_ok() => return false,
                Var::OnError => {}
                Var::Stdout => to = To::Stdout,
                Var::Stderr => to = To::Stderr,
                Var::HeaderJson => {
                    let _ = header_json(facts.report.headers(), out);
                }
                Var::Json => {
                    let _ = json(facts, out);
                }
                var => {
                    let _ = value(var, facts).write(out, Shape::Text);
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
            Piece::Output { name, append } => {
                let mut open = OpenOptions::new();
                open.create(true);
                if append {
                    open.append(true);
                } else {
                    open.write(true).truncate(true);
                }
                // C's name ends at a zero byte; only a file that opens is
                // written to.
                let name = name.split(|&b| b == 0).next().unwrap_or_default();
                if let Ok(file) = open.open(OsStr::from_bytes(name)) {
                    to = To::File(file);
                }
            }
            Piece::Header { name, all } => {
                let _ = header_value(facts.report.headers(), name, all, out);
            }
            Piece::Function(_) => unreachable!("refused when the option was read"),
            Piece::End => return false,
        }
        true
    });
}

/// `%header{}`'s value: the last response's first `name`, or with a
/// separator every request's, in order, until a request lacks it.
fn header_value(
    headers: &HeaderStore,
    name: &[u8],
    all: Option<&[u8]>,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let Some(sep) = all else {
        if let Ok(h) = headers.get(name, 0, ORIGIN, Request::Last) {
            out.write_all(h.value)?;
        }
        return Ok(());
    };
    let (mut request, mut index) = (0u16, 0);
    let mut written = false;
    while let Ok(h) = headers.get(name, index, ORIGIN, Request::Nth(request)) {
        if written {
            separator(sep, out)?;
        }
        out.write_all(h.value)?;
        written = true;
        if h.index + 1 < h.amount {
            index += 1;
        } else {
            let Some(next) = request.checked_add(1) else {
                break;
            };
            (request, index) = (next, 0);
        }
    }
    Ok(())
}

/// The headers `%header{}` and `%{header_json}` read: the responses',
/// not trailers, interim heads nor a proxy's (`CURLH_HEADER`).
const ORIGIN: Origins = Origins::HEADER;

/// A separator, its `\r`, `\n`, `\t` and `\}` read (`separator`); any
/// other `\` is written with what follows it.
fn separator(sep: &[u8], out: &mut dyn Write) -> std::io::Result<()> {
    let mut i = 0;
    while i < sep.len() {
        if sep[i] == b'\\'
            && let Some(&next) = sep.get(i + 1)
        {
            match next {
                b'r' => out.write_all(b"\r")?,
                b'n' => out.write_all(b"\n")?,
                b't' => out.write_all(b"\t")?,
                b'}' => out.write_all(b"}")?,
                0 => {}
                _ => out.write_all(&[b'\\', next])?,
            }
            i += 2;
        } else {
            out.write_all(&sep[i..=i])?;
            i += 1;
        }
    }
    Ok(())
}

/// The last response's headers as a JSON object, each name lowercase
/// with a list of its values, in the order the names first came
/// (`headerJSON`).
fn header_json(headers: &HeaderStore, out: &mut dyn Write) -> std::io::Result<()> {
    out.write_all(b"{")?;
    let mut prev = None;
    let mut first = true;
    while let Some(h) = headers.next(ORIGIN, Request::Last, prev) {
        prev = Some(h.cursor);
        if h.index > 0 {
            // Written with the first of its name.
            continue;
        }
        if !first {
            out.write_all(b",\n")?;
        }
        first = false;
        json_string(out, h.name, true)?;
        out.write_all(b":[")?;
        for i in 0..h.amount {
            let Ok(each) = headers.get(h.name, i, ORIGIN, Request::Last) else {
                break;
            };
            if i > 0 {
                out.write_all(b",")?;
            }
            json_string(out, each.value, false)?;
        }
        out.write_all(b"]")?;
    }
    out.write_all(b"\n}")
}

/// The longest JSON string C writes, its quotes not counted
/// (`MAX_JSON_STRING`, with room for its terminating zero).
const MAX_JSON_STRING: usize = 100_000 - 1;

/// `s` as a quoted JSON string, its ASCII letters lowercase if asked; one
/// longer quoted than C's buffer is not written at all
/// (`jsonWriteString`).
fn json_string(out: &mut dyn Write, s: &[u8], lowercase: bool) -> std::io::Result<()> {
    let escaped = |b: u8| -> usize {
        match b {
            b'\\' | b'"' | 0x08 | 0x0c | b'\n' | b'\r' | b'\t' => 2,
            0..0x20 => 6,
            _ => 1,
        }
    };
    if s.iter().map(|&b| escaped(b)).sum::<usize>() > MAX_JSON_STRING {
        return Ok(());
    }
    out.write_all(b"\"")?;
    for &b in s {
        match b {
            b'\\' => out.write_all(b"\\\\")?,
            b'"' => out.write_all(b"\\\"")?,
            0x08 => out.write_all(b"\\b")?,
            0x0c => out.write_all(b"\\f")?,
            b'\n' => out.write_all(b"\\n")?,
            b'\r' => out.write_all(b"\\r")?,
            b'\t' => out.write_all(b"\\t")?,
            0..0x20 => write!(out, "\\u{b:04x}")?,
            b'A'..=b'Z' if lowercase => out.write_all(&[b.to_ascii_lowercase()])?,
            _ => out.write_all(&[b])?,
        }
    }
    out.write_all(b"\"")
}

/// A variable's value, as C's write functions find it.
#[derive(Debug, PartialEq)]
enum Value<'a> {
    /// None to be had: nothing is written, or `null` in JSON (C's
    /// `valid` left false).
    Missing,
    Bytes(&'a [u8]),
    Owned(Vec<u8>),
    Ip(IpAddr),
    /// The text of a failure the transfer gave no reason for.
    Failure(ErrorKind),
    Number(i64),
    /// A status code: three digits as text (`%03ld`).
    Status(u16),
    /// Seconds, and six digits of microseconds.
    Time(Duration),
}

/// How a value is written: as text, or in JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Text,
    Json,
}

impl Value<'_> {
    fn write(&self, out: &mut dyn Write, shape: Shape) -> std::io::Result<()> {
        let json = shape == Shape::Json;
        match self {
            Value::Missing if json => out.write_all(b"null"),
            Value::Missing => Ok(()),
            Value::Bytes(text) if json => json_string(out, text, false),
            Value::Bytes(text) => out.write_all(text),
            Value::Owned(text) if json => json_string(out, text, false),
            Value::Owned(text) => out.write_all(text),
            // Made into text to be quoted; with no memory for it, the
            // string is not written, as one too long for C's buffer.
            Value::Ip(ip) if json => match try_format(format_args!("{ip}")) {
                Ok(text) => json_string(out, text.as_bytes(), false),
                Err(OutOfMemory) => Ok(()),
            },
            Value::Ip(ip) => write!(out, "{ip}"),
            Value::Failure(e) if json => match try_format(format_args!("{e}")) {
                Ok(text) => json_string(out, text.as_bytes(), false),
                Err(OutOfMemory) => Ok(()),
            },
            Value::Failure(e) => write!(out, "{e}"),
            Value::Number(n) => write!(out, "{n}"),
            Value::Status(code) if json => write!(out, "{code}"),
            Value::Status(code) => write!(out, "{code:03}"),
            Value::Time(d) => write_seconds(out, *d),
        }
    }
}

/// `n` as C's `long` or `curl_off_t` holds it.
fn number(n: u64) -> Value<'static> {
    Value::Number(i64::try_from(n).unwrap_or(i64::MAX))
}

/// What the debug test build gives for every time, both speeds and the
/// local port, if anything, as C's library does (`CURL_TIME`).
fn debug_time() -> Option<u64> {
    #[cfg(feature = "debug-hooks")]
    return curl_core::report::debug_info::time();
    #[cfg(not(feature = "debug-hooks"))]
    None
}

/// What the debug test build gives for the sizes of the headers and the
/// request, if anything (`CURL_DEBUG_SIZE`).
fn debug_size() -> Option<u64> {
    #[cfg(feature = "debug-hooks")]
    return curl_core::report::debug_info::size();
    #[cfg(not(feature = "debug-hooks"))]
    None
}

/// `var`'s value for `facts` (`writeString`, `writeLong`, `writeOffset`,
/// `writeTime`).
fn value<'a>(var: Var, facts: &Facts<'a>) -> Value<'a> {
    let r = facts.report;
    let bytes = |text: Option<&'a [u8]>| text.map_or(Value::Missing, Value::Bytes);
    match var {
        Var::OnError | Var::Stdout | Var::Stderr | Var::HeaderJson | Var::Json => {
            unreachable!("not a value")
        }
        Var::ExitCode => Value::Number(facts.result.err().map_or(0, |e| exit_code(e).into())),
        Var::ErrorMsg => match facts.result {
            Ok(()) => Value::Missing,
            Err(e) => r.failure().map_or(Value::Failure(e), Value::Bytes),
        },
        Var::Url => Value::Bytes(facts.url),
        Var::UrlPart { part, effective } => {
            let url = if effective {
                r.url().unwrap_or_default()
            } else {
                facts.url
            };
            url_part(url, part).map_or(Value::Missing, Value::Owned)
        }
        Var::UrlEffective => Value::Bytes(r.url().unwrap_or_default()),
        Var::UrlNum => number(facts.urlnum),
        Var::FilenameEffective => bytes(facts.filename),
        Var::HttpCode => Value::Status(r.response_code().unwrap_or(0)),
        Var::HttpConnect => Value::Status(r.connect_code().unwrap_or(0)),
        Var::HttpVersion => Value::Bytes(match r.response_version() {
            None => b"0",
            Some(ResponseVersion::Http10) => b"1",
            Some(ResponseVersion::Http11) => b"1.1",
            Some(ResponseVersion::Http2) => b"2",
            Some(ResponseVersion::Http3) => b"3",
        }),
        Var::Scheme => bytes(r.protocol().map(|p| p.name().as_bytes())),
        Var::ContentType => bytes(r.content_type()),
        Var::RedirectUrl => bytes(r.redirect_url()),
        // An address is empty, a port -1, before any connection.
        Var::LocalIp => match r.primary().and_then(|ends| ends.local) {
            Some(local) => Value::Ip(local.ip()),
            None => Value::Bytes(b""),
        },
        Var::LocalPort => match (debug_time(), r.primary()) {
            (Some(n), _) => number(n),
            (None, Some(ends)) => Value::Number(ends.local.map_or(0, |l| l.port().into())),
            (None, None) => Value::Number(-1),
        },
        Var::RemoteIp => match r.primary() {
            Some(ends) => Value::Ip(ends.remote.ip()),
            None => Value::Bytes(b""),
        },
        Var::RemotePort => Value::Number(r.primary().map_or(-1, |ends| ends.remote.port().into())),
        Var::NumConnects => Value::Number(r.connects().into()),
        Var::NumRedirects => Value::Number(r.redirects().into()),
        Var::Method => Value::Bytes(facts.method),
        Var::Referer => bytes(r.referer()),
        Var::NumHeaders => number(facts.num_headers),
        Var::NumRetries => number(facts.num_retries),
        Var::SizeRequest => number(debug_size().unwrap_or(r.sizes().request())),
        Var::SizeDelivered => number(r.sizes().delivered()),
        Var::SizeDownload => number(r.sizes().download()),
        Var::SizeHeader => number(debug_size().unwrap_or(r.sizes().header())),
        Var::SizeUpload => number(r.sizes().upload()),
        Var::SpeedDownload => number(debug_time().unwrap_or(r.speeds().download())),
        Var::SpeedUpload => number(debug_time().unwrap_or(r.speeds().upload())),
        Var::Time(time) => {
            if let Some(us) = debug_time() {
                return Value::Time(Duration::from_micros(us));
            }
            let t = r.timings();
            Value::Time(match time {
                Time::Appconnect => t.appconnect(),
                Time::Connect => t.connect(),
                Time::Namelookup => t.namelookup(),
                Time::Posttransfer => t.posttransfer(),
                Time::Pretransfer => t.pretransfer(),
                Time::Queue => t.queue(),
                Time::Redirect => t.redirect(),
                Time::Starttransfer => t.starttransfer(),
                Time::Total => t.total(),
            })
        }
        // The library answers for the certificates even without TLS:
        // none (`CURLINFO_CERTINFO`).
        Var::Certs => Value::Bytes(b""),
        Var::NumCerts => Value::Number(0),
        Var::ConnId => r.conn_number().map_or(Value::Number(-1), number),
        Var::XferId => r.transfer_number().map_or(Value::Number(-1), number),
        Var::FtpEntryPath => Value::Missing,
        Var::ProxySslVerifyResult | Var::SslVerifyResult | Var::TlsEarlydata => Value::Number(0),
        Var::ProxyUsed => Value::Number(r.used_proxy().into()),
    }
}

/// `%{json}`: every variable C has a write function for, in its order,
/// as `"name":value`, and the library's version last
/// (`ourWriteOutJSON`).
fn json(facts: &Facts<'_>, out: &mut dyn Write) -> std::io::Result<()> {
    out.write_all(b"{")?;
    for v in VARIABLES {
        if matches!(
            v.var,
            Var::OnError | Var::Stdout | Var::Stderr | Var::HeaderJson | Var::Json
        ) {
            continue;
        }
        write!(out, "\"{}\":", v.name)?;
        value(v.var, facts).write(out, Shape::Json)?;
        out.write_all(b",")?;
    }
    out.write_all(b"\"curl_version\":")?;
    let version = curl_core::version::version().components();
    if let Ok(version) = try_format(format_args!("{version}")) {
        json_string(out, version.as_bytes(), false)?;
    }
    out.write_all(b"}")
}

/// `d` as C writes a time: seconds, and six digits of microseconds.
fn write_seconds(out: &mut dyn Write, d: Duration) -> std::io::Result<()> {
    write!(out, "{}.{:06}", d.as_secs(), d.subsec_micros())
}

/// `part` of `url`, read as `urlpart` reads it: a scheme guessed if none
/// is given, any scheme allowed, the scheme's port if none is given.
fn url_part(url: &[u8], part: Part) -> Option<Vec<u8>> {
    let parse = ParseOptions {
        guess_scheme: true,
        non_support_scheme: true,
        ..ParseOptions::NONE
    };
    let get = GetOptions {
        default_port: true,
        ..GetOptions::NONE
    };
    Url::parse(url, parse).ok()?.get(part, get).ok()
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
                Piece::Output { name, append } => {
                    out.extend_from_slice(if append { b"<>>" } else { b"<>" });
                    out.extend_from_slice(name);
                    out.push(b'>');
                }
                Piece::Header { name, all } => {
                    out.extend_from_slice(b"<h:");
                    out.extend_from_slice(name);
                    if let Some(sep) = all {
                        out.extend_from_slice(b"|");
                        out.extend_from_slice(sep);
                    }
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

    /// What `name` writes for a transfer of `url` that never ran and
    /// ended with `result`.
    fn written_for(name: &str, url: &[u8], result: Result<(), ErrorKind>) -> Vec<u8> {
        let report = TransferReport::default();
        let facts = Facts {
            result,
            url,
            urlnum: 7,
            num_headers: 3,
            num_retries: 0,
            filename: None,
            method: b"GET",
            report: &report,
        };
        let mut out = Vec::new();
        value(lookup(name.as_bytes()).unwrap().var, &facts)
            .write(&mut out, Shape::Text)
            .unwrap();
        out
    }

    /// `%{json}` for a transfer of `url` that never ran and ended with
    /// `result`.
    fn json_for(url: &[u8], result: Result<(), ErrorKind>) -> String {
        let report = TransferReport::default();
        let facts = Facts {
            result,
            url,
            urlnum: 7,
            num_headers: 3,
            num_retries: 0,
            filename: None,
            method: b"GET",
            report: &report,
        };
        let mut out = Vec::new();
        json(&facts, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// `%{json}`: every variable with a write function, in C's order;
    /// numbers bare, codes without their leading zeroes, strings quoted,
    /// and `null` for what has no value (tests 970, 972).
    #[test]
    fn writes_json_as_c() {
        let json = json_for(b"http://u:p@example.com/a?q#f", Ok(()));
        let version = curl_core::version::version().components().to_string();
        let times: String = [
            "appconnect",
            "connect",
            "namelookup",
            "posttransfer",
            "pretransfer",
            "queue",
            "redirect",
            "starttransfer",
            "total",
        ]
        .map(|t| format!("\"time_{t}\":0.000000,"))
        .concat();
        let expected = format!(
            "{{\"certs\":\"\",\"conn_id\":-1,\"content_type\":null,\"errormsg\":null,\
             \"exitcode\":0,\"filename_effective\":null,\"ftp_entry_path\":null,\
             \"http_code\":0,\"http_connect\":0,\"http_version\":\"0\",\"local_ip\":\"\",\
             \"local_port\":-1,\"method\":\"GET\",\"num_certs\":0,\"num_connects\":0,\
             \"num_headers\":3,\"num_redirects\":0,\"num_retries\":0,\
             \"proxy_ssl_verify_result\":0,\"proxy_used\":0,\"redirect_url\":null,\
             \"referer\":null,\"remote_ip\":\"\",\"remote_port\":-1,\"response_code\":0,\
             \"scheme\":null,\"size_delivered\":0,\"size_download\":0,\"size_header\":0,\
             \"size_request\":0,\"size_upload\":0,\"speed_download\":0,\"speed_upload\":0,\
             \"ssl_verify_result\":0,{times}\"tls_earlydata\":0,\
             \"url\":\"http://u:p@example.com/a?q#f\",\"url.fragment\":\"f\",\
             \"url.host\":\"example.com\",\"url.options\":null,\"url.password\":\"p\",\
             \"url.path\":\"/a\",\"url.port\":\"80\",\"url.query\":\"q\",\
             \"url.scheme\":\"http\",\"url.user\":\"u\",\"url.zoneid\":null,\
             \"url_effective\":\"\",\"urle.fragment\":null,\"urle.host\":null,\
             \"urle.options\":null,\"urle.password\":null,\"urle.path\":null,\
             \"urle.port\":null,\"urle.query\":null,\"urle.scheme\":null,\"urle.user\":null,\
             \"urle.zoneid\":null,\"urlnum\":7,\"xfer_id\":-1,\"curl_version\":\"{version}\"}}"
        );
        assert_eq!(json, expected);
        let failed = json_for(b"x", Err(ErrorKind::CouldntResolveHost));
        let why = ErrorKind::CouldntResolveHost.to_string();
        assert!(
            failed.contains(&format!("\"errormsg\":\"{why}\",\"exitcode\":6,")),
            "{failed}"
        );
    }

    /// Values are written as C writes them, nothing for what is unknown.
    #[test]
    fn writes_values_as_c() {
        let url = b"http://u:p@example.com/a?q#f";
        let ok = |name| written_for(name, url, Ok(()));
        assert_eq!(ok("http_code"), b"000");
        assert_eq!(ok("response_code"), b"000");
        assert_eq!(ok("http_version"), b"0");
        assert_eq!(ok("scheme"), b"");
        assert_eq!(ok("url_effective"), b"");
        assert_eq!(ok("time_total"), b"0.000000");
        assert_eq!(ok("urlnum"), b"7");
        assert_eq!(ok("num_headers"), b"3");
        assert_eq!(ok("num_connects"), b"0");
        assert_eq!(ok("content_type"), b"");
        assert_eq!(ok("remote_ip"), b"");
        assert_eq!(ok("remote_port"), b"-1");
        assert_eq!(ok("local_port"), b"-1");
        assert_eq!(ok("errormsg"), b"");
        assert_eq!(ok("exitcode"), b"0");
        assert_eq!(ok("url.host"), b"example.com");
        assert_eq!(ok("url.port"), b"80", "the scheme's");
        assert_eq!(ok("url.user"), b"u");
        assert_eq!(ok("url.query"), b"q");
        assert_eq!(ok("url.fragment"), b"f");
        assert_eq!(ok("url.zoneid"), b"");
        assert_eq!(ok("urle.host"), b"", "no URL used");
        assert_eq!(
            written_for("url.scheme", b"example.com", Ok(())),
            b"http",
            "guessed"
        );
        assert_eq!(
            written_for("url.scheme", b"foo://h/", Ok(())),
            b"foo",
            "any scheme"
        );
        let failed = Err(ErrorKind::CouldntResolveHost);
        assert_eq!(written_for("exitcode", url, failed), b"6");
        assert_eq!(
            written_for("errormsg", url, failed),
            ErrorKind::CouldntResolveHost.to_string().as_bytes()
        );
        let mut out = Vec::new();
        write_seconds(&mut out, Duration::from_micros(3_000_042)).unwrap();
        assert_eq!(out, b"3.000042");
    }

    /// `%output{}` sends what follows to a file, emptied or added to;
    /// `%{stdout}` sends it back. A file that does not open changes
    /// nothing, and an unclosed one is written as it is.
    #[test]
    fn writes_to_the_file_output_names() {
        let dir = std::env::temp_dir().join(format!("curl-wo-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("out");
        std::fs::write(&file, b"old").unwrap();
        let name = file.to_str().unwrap();
        let format = format!(
            "a%output{{{name}}}b%{{stdout}}c%output{{>>{name}}}d%output{{/nonexistent/x}}e"
        );
        let report = TransferReport::default();
        let facts = Facts {
            result: Ok(()),
            url: b"",
            urlnum: 0,
            num_headers: 0,
            num_retries: 0,
            filename: None,
            method: b"GET",
            report: &report,
        };
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        write_to(format.as_bytes(), &facts, &mut stdout, &mut stderr);
        assert_eq!((&stdout[..], &stderr[..]), (&b"ac"[..], &b""[..]));
        assert_eq!(std::fs::read(&file).unwrap(), b"bde");
        let mut stdout = Vec::new();
        write_to(b"%output{>>x", &facts, &mut stdout, &mut stderr);
        assert_eq!(stdout, b"%output{x");
        // C's buffer holds a name of 511 bytes; a longer one is passed
        // over.
        let name = "a".repeat(511);
        let fits = format!("%output{{{name}}}x");
        assert_eq!(render(fits.as_bytes()), format!("<>{name}>x").as_bytes());
        let too_long = format!("%output{{>>{name}a}}x");
        assert_eq!(render(too_long.as_bytes()), b"x");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A format's file is read without its line ends.
    #[test]
    fn reads_a_format_file_without_line_ends() {
        let dir = std::env::temp_dir().join(format!("curl-wo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("format");
        std::fs::write(&file, b"a\r\n%{url}\nb\n").unwrap();
        let name = std::os::unix::ffi::OsStrExt::as_bytes(file.as_os_str());
        assert_eq!(Format::read(name).unwrap().bytes(), b"a%{url}b");
        assert_eq!(
            Format::read(b"/nonexistent/x").unwrap_err(),
            ReadFailed::Open
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn written(f: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> String {
        let mut out = Vec::new();
        f(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// `%header{}`: the last response's first of a name, or every
    /// request's in turn with a separator, until a request lacks it
    /// (tests 764, 765, 1670).
    #[test]
    fn writes_headers_as_c() {
        let store = HeaderStore::of_requests(&[
            &[b"This: one\r\n", b"This: two\r\n"],
            &[b"this: three\r\n", b"Other: x\r\n"],
            &[b"Other: y\r\n"],
            &[b"This: four\r\n"],
        ]);
        let value =
            |name: &[u8], all: Option<&[u8]>| written(|out| header_value(&store, name, all, out));
        assert_eq!(value(b"this", Some(b"***")), "one***two***three");
        assert_eq!(
            value(b"this", Some(b"-{\\}-\\n\\q")),
            "one-{}-\n\\qtwo-{}-\n\\qthree"
        );
        assert_eq!(value(b"this", Some(b"\\r|\\t")), "one\r|\ttwo\r|\tthree");
        assert_eq!(value(b"this", None), "four");
        assert_eq!(value(b"other", None), "");
        let piece = |format: &[u8]| render(format);
        assert_eq!(piece(b"%header{a:all:-\\}-}!"), b"<h:a|-\\}->!");
        assert_eq!(piece(b"%header{a:b}"), b"<h:a:b>");
        assert_eq!(piece(b"%header{a:b:all:,}"), b"<h:a:b:all:,>");
        assert_eq!(piece(b"%header{a"), b"%header{a");
        assert_eq!(piece(b"%header{}x"), b"<h:>x");
        // C's buffer holds a name of 255 bytes; a longer one writes
        // nothing.
        let name = "a".repeat(255);
        let fits = format!("%header{{{name}}}x");
        assert_eq!(piece(fits.as_bytes()), format!("<h:{name}>x").as_bytes());
        let too_long = format!("%header{{{name}a}}x");
        assert_eq!(piece(too_long.as_bytes()), b"x");
    }

    /// `%{header_json}`: each name once, lowercase, its values in a list
    /// (tests 421, 1671).
    #[test]
    fn writes_header_json_as_c() {
        let store = HeaderStore::of_requests(&[
            &[b"Gone: before\r\n"],
            &[
                b"Set-Cookie: a=1\r\n",
                b"Funny-Head: \"q\"\\\x01\r\n",
                b"set-cookie: b=2\r\n",
            ],
        ]);
        assert_eq!(
            written(|out| header_json(&store, out)),
            "{\"set-cookie\":[\"a=1\",\"b=2\"],\n\"funny-head\":[\"\\\"q\\\"\\\\\\u0001\"]\n}"
        );
        assert_eq!(
            written(|out| header_json(&HeaderStore::default(), out)),
            "{\n}"
        );
    }

    /// `jsonWriteString`: C's escapes, letters lowercased only when
    /// asked, and nothing at all for a string longer quoted than C's
    /// buffer holds.
    #[test]
    fn writes_json_strings_as_c() {
        let json = |s: &[u8], lowercase| written(|out| json_string(out, s, lowercase));
        assert_eq!(
            json(b"Ab\x08\x0c\n\r\t\x1f\"\\", false),
            "\"Ab\\b\\f\\n\\r\\t\\u001f\\\"\\\\\""
        );
        assert_eq!(json(b"AbZ-", true), "\"abz-\"");
        let fits = |s: Vec<u8>| json(&s, false).len() == s.len() + 2;
        let a = |n| vec![b'a'; n];
        assert!(fits(a(99_999)));
        assert_eq!(json(&a(100_000), false), "");
        // Two bytes for a quote, six for a control byte.
        let mut quotes = vec![b'"'; 49_999];
        quotes.push(b'a');
        assert_eq!(json(&quotes, false).len(), 2 + 99_999);
        assert_eq!(json(&[b'"'; 50_000], false), "");
        assert_eq!(json(&[1; 16_667], false), "");
    }

    #[test]
    fn refuses_what_is_not_implemented() {
        assert_eq!(unimplemented(b"%{url} %{exitcode}\\n"), None);
        assert_eq!(unimplemented(b"%{nosuch}"), None);
        assert_eq!(unimplemented(b"x %{json} %{certs} %{xfer_id}"), None);
        assert_eq!(unimplemented(b"%header{a} %{header_json}"), None);
        assert_eq!(unimplemented(b"%time{%H}"), Some("--write-out %time{}"));
        assert_eq!(unimplemented(b"%output{f}"), None);
        let after_end = format!("%{{{}}}%{{http_code}}", "a".repeat(24));
        assert_eq!(unimplemented(after_end.as_bytes()), None);
        // The table is C's, sorted for its binary search.
        assert!(VARIABLES.windows(2).all(|w| w[0].name < w[1].name));
    }

    const WORDS: &[&[u8]] = &[
        b"%",
        b"{",
        b"}",
        b"%{",
        b"url",
        b"http_code",
        b"header_json",
        b"onerror",
        b"stdout",
        b"stderr",
        b"url.host",
        b"url.port",
        b"urle.query",
        b"time_total",
        b"num_headers",
        b"json",
        b"%header{",
        b"name",
        b":all:",
        b", ",
        b"\\",
        b"\\n",
        b"\\}",
        b"%output{",
        b">>",
        b"%time{",
        b"%%",
        b"x",
        b"aaaaaaaaaaaaaaaaaaaaaaaaa",
        b"\0",
    ];
    const FORMATS: &[&[u8]] = &[
        b"%{http_code}\\n%{url_effective}",
        b"%header{name:all:, \\}}%header{name}",
        b"%{url.host}%{ %{url}%{url.fragment}",
        b"%output{>>file}x%{onerror}%{stderr}e",
    ];
    const URLS: &[&[u8]] = &[b"http://u:p@example.com:8/a?q#f", b"[::1]", b"%zz", b""];

    proptest::proptest! {
        #![proptest_config(crate::untrusted::config(512))]

        /// Any format is read, and what it asks for written, as
        /// `write_to` writes it but for the files it would open, for any
        /// URL and headers; or it is refused as not implemented.
        #[test]
        fn any_format_is_written(
            format in crate::untrusted::input(WORDS, FORMATS, 16),
            url in crate::untrusted::input(WORDS, URLS, 4),
            failed in proptest::prelude::any::<bool>(),
        ) {
            unimplemented(&format);
            let report = TransferReport::default();
            let facts = Facts {
                result: if failed { Err(ErrorKind::CouldntConnect) } else { Ok(()) },
                url: &url,
                urlnum: 0,
                num_headers: 0,
                num_retries: 0,
                filename: None,
                method: b"GET",
                report: &report,
            };
            let store = HeaderStore::of_requests(&[
                &[b"Name: one\r\n", b"name: two\r\n"],
                &[b"NAME: three\r\n"],
            ]);
            let mut out = Vec::new();
            pieces(&format, |piece| {
                match piece {
                    Piece::Variable(v) => match v.var {
                        Var::OnError | Var::Stdout | Var::Stderr => {}
                        Var::HeaderJson => header_json(&store, &mut out).unwrap(),
                        Var::Json => json(&facts, &mut out).unwrap(),
                        var => value(var, &facts).write(&mut out, Shape::Text).unwrap(),
                    },
                    Piece::Header { name, all } => {
                        header_value(&store, name, all, &mut out).unwrap();
                    }
                    Piece::End => return false,
                    _ => {}
                }
                true
            });
        }
    }
}
