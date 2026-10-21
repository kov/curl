//! `file:`, the local file system (`lib/file.c`). The request is the
//! whole transfer, done in DO: a download reads a file, or lists a
//! directory, into the pipeline; an upload writes the body to a file.

use core::ffi::CStr;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::MetadataExt as _;

use curl_alloc::TryVec;
use curl_os::fs::{self, Dir, Keep};

use crate::deliver::{Pipeline, Reach};
use crate::error::ErrorKind;
use crate::handler::HeaderOrigin;
use crate::multi::Host;
use crate::multi::state::{StepCx, url_error};
use crate::options::{Method, Options, Resume};
use crate::progress;
use crate::text::Text;
use crate::upload::{self, Upload};
use crate::url::{self, GetOptions, Part, Url};

/// The most of a file read at once: the transfer buffer, less the byte C
/// keeps for a terminating zero.
const READ_BUFFER: usize = 16384 - 1;

/// The most of an upload's body read at once (`UPLOADBUFFER_DEFAULT`).
const UPLOAD_BUFFER: usize = 65536;

/// A request for one path.
#[derive(Debug)]
pub(crate) struct Request {
    /// The path, decoded, with a zero byte after it.
    path: Vec<u8>,
    /// Open to read, for anything but an upload.
    file: Option<File>,
    pipeline: Pipeline,
}

impl Request {
    /// The path `url` names, opened to read unless the request is an
    /// upload (`file_connect`). The host is not looked at: the URL's
    /// parser allows only this one.
    pub(crate) fn open(url: &Url, options: &Options) -> Result<Request, ErrorKind> {
        // C asks for the path URL-encoded, which the parser has made it
        // already.
        let path = url.get(Part::Path, GetOptions::NONE).map_err(url_error)?;
        // A zero byte in a path is foul play.
        let mut path = url::decode_but_zero(&path)
            .map_err(url_error)?
            .ok_or(ErrorKind::UrlMalformat)?;
        path.try_push(0).map_err(|_| ErrorKind::OutOfMemory)?;
        let mut request = Request {
            path,
            file: None,
            pipeline: Pipeline::new(Reach::Local),
        };
        if options.method != Method::Upload {
            // "Could not open file %s"
            let file =
                fs::open_read(request.c_path()).map_err(|_| ErrorKind::FileCouldntReadFile)?;
            request.file = Some(file);
        }
        Ok(request)
    }

    fn c_path(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.path).expect("a path without zero bytes, ended by one")
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    /// The whole transfer (`file_do`).
    pub(crate) fn do_it<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        match cx.easy().options().method {
            Method::Upload => self.upload(cx),
            Method::Get | Method::Head => self.download(cx),
        }
    }

    fn download<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        // Where C cannot stat the file it reads it all the same; here a
        // failure is a failure.
        let meta = self
            .file
            .as_ref()
            .expect("opened to read")
            .metadata()
            .map_err(|_| ErrorKind::ReadError)?;
        let is_dir = meta.is_dir();
        let st_size = i64::try_from(meta.len()).expect("a file's size fits its offset type");
        cx.report_mut().set_filetime(meta.mtime());
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
        let options = cx.easy().options();
        if options.method == Method::Head {
            return Ok(());
        }
        // C makes the resume point a range and reads it back
        // (`setup_range`, `Curl_range`): "N-" from N on, and C's -1,
        // "-1-", the last byte.
        let (mut resume, max) = match options.resume {
            None => (0, None),
            Some(Resume::At(n)) => (i64::try_from(n.get()).unwrap_or(i64::MAX), None),
            Some(Resume::AtEnd) => (-1, Some(1)),
        };
        if resume < 0 {
            resume += st_size;
        }
        if resume > 0 {
            if resume > expected {
                // "failed to resume file:// transfer"
                return Err(ErrorKind::BadDownloadResume);
            }
            expected -= resume;
        }
        if let Some(max) = max {
            expected = max;
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
        // The last byte of an empty file is at -1, where C's seek fails
        // and returns the -1 it is compared with: it reads from the start.
        let file = self.file.as_mut().expect("opened to read");
        if let Ok(at) = u64::try_from(resume)
            && at > 0
            && file.seek(SeekFrom::Start(at)).ok() != Some(at)
        {
            return Err(ErrorKind::BadDownloadResume);
        }
        if is_dir {
            self.list(cx)?;
        } else {
            self.read_body(cx, known)?;
        }
        progress::update(cx, false)
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
    /// its end.
    fn read_body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        mut left: Option<u64>,
    ) -> Result<(), ErrorKind> {
        let file = self.file.as_mut().expect("opened to read");
        let mut buf = Vec::new();
        buf.try_extend_from_slice(&[0; READ_BUFFER])
            .map_err(|_| ErrorKind::OutOfMemory)?;
        loop {
            let want = left.map_or(READ_BUFFER, |n| {
                usize::try_from(n).map_or(READ_BUFFER, |n| n.min(READ_BUFFER))
            });
            // C ends the transfer, successfully, where a read fails; here
            // it fails.
            let n = file
                .read(&mut buf[..want])
                .map_err(|_| ErrorKind::ReadError)?;
            if n == 0 {
                return Ok(());
            }
            if let Some(left) = &mut left {
                *left -= n as u64;
            }
            self.pipeline.body(cx, &buf[..n])?;
            progress::check(cx, false)?;
        }
    }

    /// Deliver a directory's names, a line each, but those starting with a
    /// dot.
    fn list<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        let mut dir = Dir::open(self.c_path()).map_err(|_| ErrorKind::ReadError)?;
        // C stops at a failed read of the directory as at its end; here it
        // fails.
        while let Some(name) = dir.next_name() {
            let name = name.map_err(|_| ErrorKind::ReadError)?;
            if name.first() == Some(&b'.') {
                continue;
            }
            self.pipeline.body(cx, name)?;
            self.pipeline.body(cx, b"\n")?;
        }
        Ok(())
    }

    /// Write the body to the path (`file_upload`).
    fn upload<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
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
        // "cannot open %s for writing"
        let mut target = fs::open_write(self.c_path(), keep, options.new_file_mode.bits().into())
            .map_err(|_| ErrorKind::WriteError)?;
        let resume = options.resume;
        let mut upload = Upload::new(&options.upload);
        if let Some(size) = upload.size() {
            upload::announce_size(cx, Some(size));
        }
        // What of the body is stored already, and skipped.
        let mut skip = match resume {
            None => 0,
            Some(Resume::At(n)) => n.get(),
            // "cannot get the size of %s"
            Some(Resume::AtEnd) => target.metadata().map_err(|_| ErrorKind::WriteError)?.len(),
        };
        let mut buf = Vec::new();
        buf.try_extend_from_slice(&[0; UPLOAD_BUFFER])
            .map_err(|_| ErrorKind::OutOfMemory)?;
        loop {
            // Not pausable: a pause is a read error.
            let got = upload.read(cx, &mut buf, false)?;
            if got.n == 0 {
                break;
            }
            let skipped = usize::try_from(skip).map_or(got.n, |s| s.min(got.n));
            skip -= skipped as u64;
            let body = &buf[skipped..got.n];
            target.write_all(body).map_err(|_| ErrorKind::SendError)?;
            cx.report_mut().sizes_mut().upload += body.len() as u64;
            // After the body's end, a read gives nothing, without asking
            // a handler.
            progress::check(cx, false)?;
        }
        progress::update(cx, false)
    }
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The header line of a modification time, `t` seconds after the epoch,
/// in UTC. A year past what C's `struct tm` holds is BadFunctionArgument,
/// as `gmtime_r` fails on it.
fn last_modified(t: i64, out: &mut Text<80>) -> Result<(), ErrorKind> {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // 1970-01-01 was a Thursday.
    let weekday = (days + 4).rem_euclid(7);
    let (year, month, day) = civil(days);
    if i32::try_from(year - 1900).is_err() {
        return Err(ErrorKind::BadFunctionArgument);
    }
    write!(
        out,
        "Last-Modified: {}, {day:02} {} {year:4} {:02}:{:02}:{:02} GMT\r\n",
        WEEKDAYS[weekday as usize],
        MONTHS[month as usize - 1],
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
    .expect("a header fits");
    Ok(())
}

/// The proleptic Gregorian year, month and day of `days` after
/// 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests;
