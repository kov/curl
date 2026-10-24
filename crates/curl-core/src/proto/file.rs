//! `file:`, the local file system (`lib/file.c`). The request is the
//! whole transfer, done in DO: a download reads a file, or lists a
//! directory, into the pipeline; an upload writes the body to a file. C
//! does it in one call; here each piece of a file read or written is a
//! step of DO, so that the drive reads the clock between pieces as C's
//! `Curl_pgrsCheck` does after each.

use core::ffi::CStr;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::MetadataExt as _;

use curl_alloc::TryVec;
use curl_os::fs::{self, Dir, Keep};

use crate::date::HttpDate;
use crate::deliver::{Expect, Pipeline, Reach};
use crate::error::ErrorKind;
use crate::error::url_error;
use crate::handler::HeaderOrigin;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::{Method, Ranged, Resume};
use crate::progress;
use crate::proto::DoStep;
use crate::text::Text;
use crate::trace;
use crate::upload::{self, Upload};
use crate::url::{self, GetOptions, Part, Url};

/// The failures a test has a transfer meet, where the file system will
/// not fail on demand.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Faults {
    /// Reading the file, or the directory, fails once this much of the
    /// body is delivered.
    pub(crate) read_fails_at: Option<u64>,
    /// The opened file cannot be stat'ed.
    pub(crate) stat_fails: bool,
}

/// A request for one path.
#[derive(Debug)]
pub(crate) struct Request {
    /// The path, decoded, with a zero byte after it.
    path: Vec<u8>,
    /// Open to read, for anything but an upload; for an upload, open to
    /// write once DO starts.
    file: Option<File>,
    /// What a piece is read into, once DO starts.
    buf: Vec<u8>,
    pipeline: Pipeline,
    doing: Doing,
}

/// How far DO is. The look at the progress C takes after each piece
/// (`Curl_pgrsCheck`) starts the next step, so that it is timed after the
/// piece, as C reads the clock for it.
#[derive(Debug)]
enum Doing {
    /// Not started.
    Start,
    /// Reading the file into the pipeline, a piece delivered and not
    /// looked at yet; this many bytes more of it if known, else to its
    /// end.
    Reading(Option<u64>),
    /// Writing the body to the file, a piece written and not looked at
    /// yet; the first `skip` bytes of the body stored already, and
    /// skipped.
    Writing { upload: Upload, skip: u64 },
    /// The body is over: the last progress pass is left, after a look at
    /// the last piece if `check`.
    Ending { check: bool },
}

impl Request {
    /// The path `url` names, opened to read unless the request is an
    /// upload (`file_connect`). The host is not looked at: the URL's
    /// parser allows only this one.
    pub(crate) fn open<H: Host>(url: &Url, cx: &mut StepCx<'_, H>) -> Result<Request, ErrorKind> {
        // C asks for the path URL-encoded, which the parser has made it
        // already.
        let encoded = url.get(Part::Path, GetOptions::NONE).map_err(url_error)?;
        // A zero byte in a path is foul play.
        let mut path = url::decode_but_zero(&encoded)
            .map_err(url_error)?
            .ok_or(ErrorKind::UrlMalformat)?;
        path.try_push(0).map_err(|_| ErrorKind::OutOfMemory)?;
        let mut request = Request {
            path,
            file: None,
            buf: Vec::new(),
            pipeline: Pipeline::new(Reach::Local),
            doing: Doing::Start,
        };
        if cx.easy().options().method != Method::Upload {
            match fs::open_read(request.c_path()) {
                Ok(file) => request.file = Some(file),
                Err(_) => {
                    let kind = ErrorKind::FileCouldntReadFile;
                    return Err(trace::fail_with(
                        cx,
                        kind,
                        &[b"Could not open file ", &encoded],
                    ));
                }
            }
        }
        Ok(request)
    }

    fn c_path(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.path).expect("a path without zero bytes, ended by one")
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    /// A step of the whole transfer (`file_do`): its start and first
    /// piece, a piece, or its end.
    pub(crate) fn do_it<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<DoStep, ErrorKind> {
        match std::mem::replace(&mut self.doing, Doing::Start) {
            Doing::Start => match cx.easy().options().method {
                Method::Upload => self.upload(cx),
                Method::Get | Method::Head | Method::Post => self.download(cx),
            },
            Doing::Reading(left) => {
                progress::check(cx, false)?;
                self.read_piece(cx, left)
            }
            Doing::Writing { upload, skip } => {
                progress::check(cx, false)?;
                self.write_piece(cx, upload, skip)
            }
            Doing::Ending { check } => {
                if check {
                    progress::check(cx, false)?;
                }
                progress::update(cx, false).map(|()| DoStep::Made)
            }
        }
    }

    fn download<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<DoStep, ErrorKind> {
        let meta = self.file.as_ref().expect("opened to read").metadata();
        #[cfg(test)]
        let meta = if cx.easy().options().file_faults.stat_fails {
            Err(std::io::Error::other("injected"))
        } else {
            meta
        };
        let Ok(meta) = meta else {
            return self.download_unstated(cx);
        };
        let is_dir = meta.is_dir();
        let st_size = i64::try_from(meta.len()).expect("a file's size fits its offset type");
        cx.report_mut().set_filetime(meta.mtime());
        // A file the condition rules out is not read, nor are its headers
        // made, unless a range is asked for (`file_do`).
        let options = cx.easy().options();
        if let Some(condition) = options
            .time_condition
            .filter(|_| options.ranged().is_none())
            && let Err(unmet) = condition.met_by(meta.mtime())
        {
            trace::info(cx, format_args!("{unmet}"));
            cx.report_mut().set_condition_unmet();
            return Ok(DoStep::Made);
        }
        let mut line = Text::<80>::new();
        if !is_dir {
            write!(line, "Content-Length: {st_size}\r\n").expect("a header fits");
            self.header(cx, &mut line)?;
            write!(line, "Accept-ranges: bytes\r\n").expect("a header fits");
            self.header(cx, &mut line)?;
        }
        last_modified(meta.mtime(), &mut line)?;
        self.header(cx, &mut line)?;
        line.write_str("\r\n").expect("a header fits");
        self.header(cx, &mut line)?;
        // C's arithmetic, in its signed offsets: -1 is a size not known.
        let mut expected = if is_dir { -1 } else { st_size };
        self.pipeline
            .announce_size(cx, u64::try_from(expected).ok());
        if cx.easy().options().method == Method::Head {
            return Ok(DoStep::Made);
        }
        let Span {
            mut resume, max, ..
        } = span_of(cx)?;
        if resume < 0 {
            resume += st_size;
        }
        if resume > 0 {
            if resume > expected {
                let kind = ErrorKind::BadDownloadResume;
                return Err(trace::fail(
                    cx,
                    kind,
                    format_args!("failed to resume file:// transfer"),
                ));
            }
            expected -= resume;
        }
        if let Some(max) = max {
            expected = max;
            // No more is delivered (`maxdownload`): a file's reads stop
            // there, a directory's listing is cut.
            self.pipeline.expect(Expect {
                max: u64::try_from(max).ok(),
                ..Expect::default()
            });
        }
        let known = u64::try_from(expected).ok().filter(|&n| n > 0);
        if known.is_some() {
            self.pipeline.announce_size(cx, known);
        }
        // Reached only by the end of a directory its file system sizes at
        // nothing, as btrfs does an empty one: any other resume of a
        // directory is past its size of -1.
        if resume != 0 && is_dir {
            return Err(ErrorKind::BadDownloadResume);
        }
        // Before the start, C's seek fails and returns -1, which only an
        // offset of -1 is: the last byte of an empty file, read from the
        // start. Any other fails.
        let file = self.file.as_mut().expect("opened to read");
        let sought = match u64::try_from(resume) {
            Ok(0) => true,
            Ok(at) => file.seek(SeekFrom::Start(at)).ok() == Some(at),
            Err(_) => resume == -1,
        };
        if !sought {
            return Err(ErrorKind::BadDownloadResume);
        }
        if is_dir {
            self.list(cx)?;
            progress::update(cx, false).map(|()| DoStep::Made)
        } else {
            self.read_body(cx, known)
        }
    }

    /// Read a file that cannot be stat'ed all the same, as C does: without
    /// headers, its size unknown, and with no time condition, as nothing
    /// is known to check it against; a resume needs the size, and fails.
    fn download_unstated<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<DoStep, ErrorKind> {
        let Span { resume, max, .. } = span_of(cx)?;
        if resume < 0 {
            let kind = ErrorKind::ReadError;
            return Err(trace::fail(
                cx,
                kind,
                format_args!("cannot get the size of file."),
            ));
        }
        // Past the size of -1 C has for it.
        if resume > 0 {
            let kind = ErrorKind::BadDownloadResume;
            return Err(trace::fail(
                cx,
                kind,
                format_args!("failed to resume file:// transfer"),
            ));
        }
        // C returns before the body for a head request only after the
        // headers, which it has not made: the body is read, and its first
        // bytes, wanted by none and after no head, are a weird reply. It
        // reads on, the size unknown, and delivers no more than the range
        // asks for (`maxdownload`).
        let head = cx.easy().options().method == Method::Head;
        self.pipeline.expect(Expect {
            no_body: head,
            no_head: head,
            max: max.and_then(|n| u64::try_from(n).ok()),
            ..Expect::default()
        });
        self.read_body(cx, None)
    }

    fn header<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &mut Text<80>,
    ) -> Result<(), ErrorKind> {
        let result = self.pipeline.header(cx, line.bytes(), HeaderOrigin::Header);
        *line = Text::new();
        result
    }

    /// Deliver the file from where it is, `left` bytes if known, else to
    /// its end: its first piece.
    fn read_body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        left: Option<u64>,
    ) -> Result<DoStep, ErrorKind> {
        // The most of a file read at once: the transfer buffer, less the
        // byte C keeps for a terminating zero.
        let most = cx.easy().options().limits.buffer_size.get() - 1;
        let mut buf = Vec::new();
        buf.try_reserve_exact(most)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        #[expect(clippy::disallowed_methods, reason = "reserved above")]
        buf.resize(most, 0);
        self.buf = buf;
        self.read_piece(cx, left)
    }

    /// Read and deliver a piece of the file; at its end, on to the last
    /// progress pass.
    fn read_piece<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        mut left: Option<u64>,
    ) -> Result<DoStep, ErrorKind> {
        let buf = &mut self.buf;
        let most = buf.len();
        let want = left.map_or(most, |n| usize::try_from(n).map_or(most, |n| n.min(most)));
        let file = self.file.as_mut().expect("opened to read");
        // C ends the transfer, successfully, where a read fails; here it
        // fails (DIVERGENCE.md).
        let read = file.read(&mut buf[..want]);
        #[cfg(test)]
        let read = injected(cx, &self.pipeline).map_or(read, Err);
        let n = read.map_err(|_| ErrorKind::ReadError)?;
        if n == 0 {
            self.doing = Doing::Ending { check: false };
            return Ok(DoStep::More);
        }
        if let Some(left) = &mut left {
            *left -= n as u64;
        }
        self.pipeline.body(cx, &self.buf[..n])?;
        self.doing = Doing::Reading(left);
        Ok(DoStep::More)
    }

    /// Deliver a directory's names, a line each, but those starting with a
    /// dot.
    fn list<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        let mut dir = Dir::open(self.c_path()).map_err(|_| ErrorKind::ReadError)?;
        // C stops at a failed read of the directory as at its end; here it
        // fails (DIVERGENCE.md).
        while let Some(name) = dir.next_name() {
            #[cfg(test)]
            let name = injected(cx, &self.pipeline).map_or(name, Err);
            let name = name.map_err(|_| ErrorKind::ReadError)?;
            if name.first() == Some(&b'.') {
                continue;
            }
            self.pipeline.body(cx, name)?;
            self.pipeline.body(cx, b"\n")?;
        }
        Ok(())
    }

    /// Write the body to the path (`file_upload`): the file opened, and
    /// the first piece.
    fn upload<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<DoStep, ErrorKind> {
        // C looks for something after the path's first slash.
        let path = &self.path[..self.path.len() - 1];
        if !path
            .iter()
            .position(|&b| b == b'/')
            .is_some_and(|slash| slash + 1 < path.len())
        {
            return Err(ErrorKind::FileCouldntReadFile);
        }
        let options = cx.easy().options();
        let keep = match options.resume {
            Some(_) => Keep::Everything,
            None => Keep::Nothing,
        };
        let mode = options.new_file_mode.bits().into();
        let Ok(target) = fs::open_write(self.c_path(), keep, mode) else {
            let detail: [&[u8]; 3] = [b"cannot open ", path, b" for writing"];
            return Err(trace::fail_with(cx, ErrorKind::WriteError, &detail));
        };
        let resume = options.resume;
        let upload = Upload::open(cx)?;
        if let Some(size) = upload.size() {
            upload::announce_size(cx, Some(size));
        }
        let skip = match resume {
            None => 0,
            Some(Resume::At(n)) => n.get(),
            Some(Resume::AtEnd) => match target.metadata() {
                Ok(meta) => meta.len(),
                Err(_) => {
                    let detail: [&[u8]; 2] = [b"cannot get the size of ", path];
                    return Err(trace::fail_with(cx, ErrorKind::WriteError, &detail));
                }
            },
        };
        let mut buf = Vec::new();
        let room = cx.easy().options().limits.upload_buffer.get();
        buf.try_reserve_exact(room)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        super::http::zeros(&mut buf, room).map_err(|_| ErrorKind::OutOfMemory)?;
        // The reader is set as the body is first read (`Curl_client_read`).
        upload.trace_set(cx);
        self.file = Some(target);
        self.buf = buf;
        self.write_piece(cx, upload, skip)
    }

    /// Read a piece of the body and write it; at its end, on to the last
    /// progress pass.
    fn write_piece<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        mut upload: Upload,
        mut skip: u64,
    ) -> Result<DoStep, ErrorKind> {
        // Not pausable: a pause is a read error.
        let got = upload.read(cx, &mut self.buf, false);
        upload::client_read(cx, self.buf.len(), &got);
        let got = got?;
        if got.n == 0 {
            self.doing = Doing::Ending { check: false };
            return Ok(DoStep::More);
        }
        let skipped = usize::try_from(skip).map_or(got.n, |s| s.min(got.n));
        skip -= skipped as u64;
        let body = &self.buf[skipped..got.n];
        let target = self.file.as_mut().expect("opened to write");
        target.write_all(body).map_err(|_| ErrorKind::SendError)?;
        cx.report_mut().sizes_mut().upload += body.len() as u64;
        // Not read again past its end (`file_upload`'s `eos`).
        self.doing = if got.eos {
            Doing::Ending { check: true }
        } else {
            Doing::Writing { upload, skip }
        };
        Ok(DoStep::More)
    }
}

/// Where a download starts and how much of it is asked for, in C's
/// signed offsets: a start below zero counts back from the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    resume: i64,
    max: Option<i64>,
    /// The two numbers as read, 0 for one missing.
    from: i64,
    to: i64,
}

impl Span {
    /// What the debug build traces of it (`Curl_range`'s `DEBUGF`).
    #[cfg(feature = "debug-hooks")]
    fn trace<H: Host>(self, cx: &mut StepCx<'_, H>) {
        let Span {
            resume,
            max,
            from,
            to,
        } = self;
        match max {
            None => trace::info(cx, format_args!("RANGE {from} to end of file")),
            Some(_) if resume < 0 => trace::info(cx, format_args!("RANGE the last {to} bytes")),
            Some(max) => trace::info(cx, format_args!("RANGE from {from} getting {max} bytes")),
        }
        let max = max.unwrap_or(-1);
        trace::info(
            cx,
            format_args!("range-download from {from} to {to}, totally {max} bytes"),
        );
    }
}

/// The span of the range asked for, if one is (`Curl_range`): `X-`, from X
/// to the end; `-Y`, the last Y bytes; `X-Y`, from X to Y. Whatever
/// follows the second number is not read. C makes a resume point a range
/// first (`setup_range`): N from N on, and its -1 the last byte.
fn span(ranged: Option<Ranged<'_>>) -> Result<Option<Span>, ErrorKind> {
    let range: &[u8] = match ranged {
        None => return Ok(None),
        // `N-`, read back as N.
        Some(Ranged::Resume(Resume::At(from))) => {
            let from = i64::try_from(from.get()).unwrap_or(i64::MAX);
            return Ok(Some(Span {
                resume: from,
                max: None,
                from,
                to: 0,
            }));
        }
        Some(Ranged::Resume(Resume::AtEnd)) => b"-1-",
        Some(Ranged::Given(given)) => given,
    };
    let (from, rest) = match number(range) {
        Some((n, rest)) => (Some(n), rest),
        None => (None, range),
    };
    let Some(rest) = rest.strip_prefix(b"-") else {
        return Err(ErrorKind::RangeError);
    };
    let span = match (from, number(rest)) {
        // No first number and no second, `-`, is from 0 on.
        (from, None) => Span {
            resume: from.unwrap_or(0),
            max: None,
            from: from.unwrap_or(0),
            to: 0,
        },
        (None, Some((0, _))) => return Err(ErrorKind::RangeError),
        (None, Some((to, _))) => Span {
            resume: -to,
            max: Some(to),
            from: 0,
            to,
        },
        (Some(from), Some((to, _))) => {
            if from > to || to - from == i64::MAX {
                return Err(ErrorKind::RangeError);
            }
            Span {
                resume: from,
                max: Some(to - from + 1),
                from,
                to,
            }
        }
    };
    Ok(Some(span))
}

/// The span of the range asked for, traced as the debug build traces it;
/// none, the whole file.
fn span_of<H: Host>(cx: &mut StepCx<'_, H>) -> Result<Span, ErrorKind> {
    let span = span(cx.easy().options().ranged())?;
    #[cfg(feature = "debug-hooks")]
    if let Some(span) = span {
        span.trace(cx);
    }
    Ok(span.unwrap_or(Span {
        resume: 0,
        max: None,
        from: 0,
        to: 0,
    }))
}

/// A number at the start of `s` and what follows it, as
/// `curlx_str_number` reads one: digits, and none past what an offset
/// holds.
fn number(s: &[u8]) -> Option<(i64, &[u8])> {
    let len = s.iter().take_while(|b| b.is_ascii_digit()).count();
    if len == 0 {
        return None;
    }
    let mut n: i64 = 0;
    for &d in &s[..len] {
        n = n.checked_mul(10)?.checked_add(i64::from(d - b'0'))?;
    }
    Some((n, &s[len..]))
}

/// The failure a test has the next read meet, if any.
#[cfg(test)]
fn injected<H: Host>(cx: &StepCx<'_, H>, pipeline: &Pipeline) -> Option<std::io::Error> {
    let at = cx.easy().options().file_faults.read_fails_at?;
    (pipeline.bytecount() >= at).then(|| std::io::Error::other("injected"))
}

/// The header line of a modification time, `t` seconds after the epoch,
/// in UTC. A year past what C's `struct tm` holds is BadFunctionArgument,
/// as `gmtime_r` fails on it.
fn last_modified(t: i64, out: &mut Text<80>) -> Result<(), ErrorKind> {
    let date = HttpDate::of(t).map_err(|_| ErrorKind::BadFunctionArgument)?;
    write!(out, "Last-Modified: {date}\r\n").expect("a header fits");
    Ok(())
}

#[cfg(test)]
mod tests;
