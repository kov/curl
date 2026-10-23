//! `file:` transfers on a scratch directory, against what C's do: each
//! expectation of headers, sizes, calls and results was read off the C
//! build running the same transfer.

use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use curl_alloc::TryArc;

use crate::conn::io::FakeNet;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{
    Handler, HeaderHandler, HeaderOrigin, ProgressHandler, ProgressNow, ProgressVerdict, Read,
    ReadHandler, TextSink, Write, WriteHandler,
};
use crate::id::ArenaPolicy;
use crate::multi::{Env, Multi, NoEvents, TransferCx};
use crate::options::{FileMode, Method, Progress, Resume, UploadSource};
use crate::report::{HeaderError, Origins, Request};
use crate::text::Text;
use crate::time::ManualClock;

use super::last_modified;

/// A directory of its own for a test, removed after it.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("curl-core-file-{}-{name}", std::process::id()));
        // Left over from a run that did not finish.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }

    fn url(&self, name: &str) -> Vec<u8> {
        format!("file://{}/{name}", self.0.display()).into_bytes()
    }

    /// `name` holding `content`, modified at `mtime` seconds after the
    /// epoch.
    fn file(&self, name: &str, content: &[u8], mtime: u64) {
        let path = self.0.join(name);
        std::fs::write(&path, content).unwrap();
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(mtime))
            .unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.0.join(name)).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// 2000-01-01 12:00:00 UTC, a Saturday.
const Y2K_NOON: u64 = 946_728_000;

/// What a transfer's handlers saw, in order.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<Event>>>);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Header(Vec<u8>),
    Body(Vec<u8>),
    Progress(ProgressNow),
}

impl WriteHandler for Seen {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.lock().unwrap().push(Event::Body(body.to_vec()));
        Write::Accepted
    }
}

impl HeaderHandler for Seen {
    fn header(&self, _: &mut TransferCx<'_>, line: &[u8], o: HeaderOrigin) -> Write {
        assert_eq!(o, HeaderOrigin::Header);
        self.0.lock().unwrap().push(Event::Header(line.to_vec()));
        Write::Accepted
    }
}

impl ProgressHandler for Seen {
    fn progress(&self, _: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
        self.0.lock().unwrap().push(Event::Progress(now));
        ProgressVerdict::Continue
    }
}

impl Seen {
    fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }

    fn headers(&self) -> Vec<Vec<u8>> {
        self.filter(|e| match e {
            Event::Header(h) => Some(h.clone()),
            _ => None,
        })
    }

    fn body(&self) -> Vec<u8> {
        self.filter(|e| match e {
            Event::Body(b) => Some(b.clone()),
            _ => None,
        })
        .concat()
    }

    fn progress(&self) -> Vec<ProgressNow> {
        self.filter(|e| match e {
            Event::Progress(p) => Some(*p),
            _ => None,
        })
    }

    fn filter<T>(&self, f: impl Fn(&Event) -> Option<T>) -> Vec<T> {
        self.0.lock().unwrap().iter().filter_map(f).collect()
    }
}

/// An easy handle for `url`, its output and progress seen.
fn easy(url: &[u8]) -> (Easy, Seen) {
    let mut e = Easy::new();
    e.options_mut().set_url(Some(url)).unwrap();
    let seen = Seen::default();
    let cb = &mut e.options_mut().callbacks;
    cb.write = Some(Handler::write(seen.clone()).unwrap());
    cb.header = Some(Handler::header(seen.clone()).unwrap());
    e.options_mut().progress = Progress::Handler(Handler::progress(seen.clone()).unwrap());
    (e, seen)
}

/// Run `e` to its end in a multi of its own; its result and the handle.
fn run(e: Easy) -> (Result<(), ErrorKind>, Easy) {
    let clock = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    assert_eq!(m.perform(&mut NoEvents).unwrap(), 0, "over in one pass");
    let result = m.info_read().expect("a message").result;
    (result, *m.remove(id, &mut NoEvents).unwrap().easy)
}

fn down(total: Option<u64>, now: u64) -> ProgressNow {
    ProgressNow {
        download_total: total,
        downloaded: now,
        upload_total: None,
        uploaded: 0,
    }
}

fn up(now: u64) -> ProgressNow {
    ProgressNow {
        uploaded: now,
        ..down(None, 0)
    }
}

const SMALL_HEADERS: [&[u8]; 4] = [
    b"Content-Length: 5\r\n",
    b"Accept-ranges: bytes\r\n",
    b"Last-Modified: Sat, 01 Jan 2000 12:00:00 GMT\r\n",
    b"\r\n",
];

/// A file's headers, then its body; progress twice before the request,
/// after the body's write and at its end, then after DO, after DID and in
/// DONE. The headers are not kept for the headers API.
#[test]
fn a_file_is_its_headers_then_its_body() {
    let s = Scratch::new("small");
    s.file("small", b"hello", Y2K_NOON);
    let (e, seen) = easy(&s.url("small"));
    let (r, e) = run(e);
    assert_eq!(r, Ok(()));
    let mut want: Vec<Event> = vec![Event::Progress(down(None, 0)); 2];
    want.extend(SMALL_HEADERS.map(|h| Event::Header(h.to_vec())));
    want.push(Event::Body(b"hello".to_vec()));
    want.extend(vec![Event::Progress(down(Some(5), 5)); 5]);
    assert_eq!(seen.events(), want);
    let report = e.report();
    assert_eq!(report.filetime(), Some(Y2K_NOON as i64));
    assert_eq!(report.sizes().download_expected(), Some(5));
    assert_eq!(report.sizes().download(), 5);
    let stored = report
        .headers()
        .get(b"Content-Length", 0, Origins::ALL, Request::Last);
    assert_eq!(stored.err(), Some(HeaderError::NoHeaders));
}

/// With the headers included, the write handler gets them before the
/// body.
#[test]
fn included_headers_are_written_before_the_body() {
    let s = Scratch::new("include");
    s.file("f", b"hello", Y2K_NOON);
    let (mut e, seen) = easy(&s.url("f"));
    e.options_mut().output.include_header = true;
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(
        seen.body(),
        [&SMALL_HEADERS.concat()[..], b"hello"].concat()
    );
}

/// A file larger than the buffer is read in pieces one byte short of it,
/// progress checked after each.
#[test]
fn a_large_file_is_read_in_pieces() {
    let s = Scratch::new("big");
    s.file("big", &[7; 40000], Y2K_NOON);
    let (e, seen) = easy(&s.url("big"));
    assert_eq!(run(e).0, Ok(()));
    let writes: Vec<usize> = seen
        .events()
        .iter()
        .filter_map(|e| match e {
            Event::Body(b) => Some(b.len()),
            _ => None,
        })
        .collect();
    assert_eq!(writes, [16383, 16383, 7234]);
    let total = Some(40000);
    let mut want = vec![down(None, 0); 2];
    want.extend([down(total, 16383), down(total, 32766)]);
    want.extend(vec![down(total, 40000); 5]);
    assert_eq!(seen.progress(), want);
}

/// A file is read as far as it was when the transfer looked at it, though
/// it grows during the transfer.
#[test]
fn a_file_is_read_as_far_as_its_size() {
    struct Grower {
        path: PathBuf,
        seen: Seen,
    }
    impl WriteHandler for Grower {
        fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
            if self.seen.body().is_empty() {
                use std::io::Write as _;
                let mut f = std::fs::File::options()
                    .append(true)
                    .open(&self.path)
                    .unwrap();
                f.write_all(b"0123456789").unwrap();
            }
            self.seen.write(cx, body)
        }
    }
    let s = Scratch::new("grow");
    s.file("f", &[0; 20000], Y2K_NOON);
    let (mut e, seen) = easy(&s.url("f"));
    let grower = Grower {
        path: s.0.join("f"),
        seen: seen.clone(),
    };
    e.options_mut().callbacks.write = Some(Handler::write(grower).unwrap());
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(seen.body(), [0; 20000]);
}

/// An empty file has its headers and nothing more: progress at the end of
/// the read, not after a write.
#[test]
fn an_empty_file_is_its_headers() {
    let s = Scratch::new("empty");
    s.file("empty", b"", Y2K_NOON);
    let (e, seen) = easy(&s.url("empty"));
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(seen.headers()[0], b"Content-Length: 0\r\n");
    assert_eq!(seen.body(), b"");
    // Its size is known: nothing.
    let mut want = vec![down(None, 0); 2];
    want.extend(vec![down(Some(0), 0); 4]);
    assert_eq!(seen.progress(), want);
}

/// A directory is its names, a line each, but those starting with a dot,
/// without a size; progress only at the end of the listing.
#[test]
fn a_directory_is_its_names() {
    let s = Scratch::new("dir");
    std::fs::create_dir(s.0.join("d")).unwrap();
    for name in ["a", ".hidden", "bb"] {
        std::fs::write(s.0.join("d").join(name), b"").unwrap();
    }
    let (e, seen) = easy(&s.url("d/"));
    let (r, e) = run(e);
    assert_eq!(r, Ok(()));
    let headers = seen.headers();
    assert_eq!(headers.len(), 2);
    assert!(headers[0].starts_with(b"Last-Modified: "), "{headers:?}");
    assert_eq!(headers[1], b"\r\n");
    let body = seen.body();
    let mut names: Vec<&[u8]> = body.split_inclusive(|&b| b == b'\n').collect();
    names.sort();
    assert_eq!(names, [&b"a\n"[..], b"bb\n"]);
    let mut want = vec![down(None, 0); 2];
    want.extend(vec![down(None, 5); 4]);
    assert_eq!(seen.progress(), want);
    assert_eq!(e.report().sizes().download_expected(), None);
}

/// A file whose read fails is a read error, though its headers went out:
/// `/proc/self/mem` opens, and its first read, at address 0, fails. C
/// takes the failed read for the end of the file and succeeds with an
/// empty body (DIVERGENCE.md).
#[cfg(target_os = "linux")]
#[test]
fn a_file_that_cannot_be_read_fails() {
    let (e, seen) = easy(b"file:///proc/self/mem");
    assert_eq!(run(e).0, Err(ErrorKind::ReadError));
    assert_eq!(seen.headers().last().unwrap(), b"\r\n");
    assert_eq!(seen.body(), b"");
}

/// A read failing partway through the file fails the transfer after what
/// was read; C ends there and reports success for the truncated body
/// (DIVERGENCE.md).
#[test]
fn a_read_failing_partway_fails() {
    let s = Scratch::new("readfail");
    s.file("f", &[7; 40000], Y2K_NOON);
    let (mut e, seen) = easy(&s.url("f"));
    e.options_mut().file_faults.read_fails_at = Some(1);
    assert_eq!(run(e).0, Err(ErrorKind::ReadError));
    assert_eq!(seen.body(), [7; 16383]);
}

/// A directory's read failing partway through the listing fails the
/// transfer after the names read; C ends there and reports success for
/// the truncated listing (DIVERGENCE.md).
#[test]
fn a_listing_failing_partway_fails() {
    let s = Scratch::new("listfail");
    std::fs::create_dir(s.0.join("d")).unwrap();
    for name in ["a", "b", "c"] {
        std::fs::write(s.0.join("d").join(name), b"").unwrap();
    }
    let (mut e, seen) = easy(&s.url("d/"));
    e.options_mut().file_faults.read_fails_at = Some(1);
    assert_eq!(run(e).0, Err(ErrorKind::ReadError));
    assert_eq!(seen.body().len(), 2, "one name and its newline");
}

fn unstated(s: &Scratch, setup: impl FnOnce(&mut Easy)) -> (Result<(), ErrorKind>, Seen, Easy) {
    let (mut e, seen) = easy(&s.url("f"));
    e.options_mut().file_faults.stat_fails = true;
    setup(&mut e);
    let (r, e) = run(e);
    (r, seen, e)
}

/// A file that cannot be stat'ed is read all the same, as C reads it
/// (`file_do`): no headers, no size, no file time, and a time condition
/// that would rule it out not checked.
#[test]
fn a_file_that_cannot_be_stated_is_read_without_its_size() {
    use crate::options::{Condition, TimeCondition};
    let s = Scratch::new("unstated");
    s.file("f", b"hello", Y2K_NOON);
    let (r, seen, e) = unstated(&s, |_| {});
    assert_eq!(r, Ok(()));
    assert!(seen.headers().is_empty());
    assert_eq!(seen.body(), b"hello");
    assert_eq!(e.report().sizes().download_expected(), None);
    assert_eq!(e.report().filetime(), None);
    let mut want = vec![down(None, 0); 2];
    want.extend(vec![down(None, 5); 5]);
    assert_eq!(seen.progress(), want);
    let (r, seen, e) = unstated(&s, |e| {
        e.options_mut().time_condition = Some(TimeCondition {
            when: Condition::ModifiedSince,
            time: Y2K_NOON as i64,
        });
    });
    assert_eq!(r, Ok(()));
    assert_eq!(seen.body(), b"hello");
    assert!(!e.report().condition_unmet());
}

/// Without its size, a file cannot be resumed: from its end is a read
/// error, from anywhere else past the size C takes for unknown, -1.
#[test]
fn a_file_that_cannot_be_stated_cannot_be_resumed() {
    let s = Scratch::new("unstatedresume");
    s.file("f", b"hello", Y2K_NOON);
    let (r, seen, _) = unstated(&s, |e| e.options_mut().resume = Some(Resume::AtEnd));
    assert_eq!(r, Err(ErrorKind::ReadError));
    assert_eq!(seen.body(), b"");
    let (r, seen, _) = unstated(&s, |e| e.options_mut().resume = Some(at(1)));
    assert_eq!(r, Err(ErrorKind::BadDownloadResume));
    assert_eq!(seen.body(), b"");
}

/// A head request on a file that cannot be stat'ed has no headers to end
/// at: C reads the body, and its first bytes, after no head, are a weird
/// reply; an empty file is fine.
#[test]
fn a_head_request_on_a_file_that_cannot_be_stated_reads_its_body() {
    let s = Scratch::new("unstatedhead");
    s.file("f", b"hello", Y2K_NOON);
    let head = |e: &mut Easy| e.options_mut().method = Method::Head;
    let (r, seen, _) = unstated(&s, head);
    assert_eq!(r, Err(ErrorKind::WeirdServerReply));
    assert!(
        seen.events()
            .iter()
            .all(|e| matches!(e, Event::Progress(_)))
    );
    s.file("f", b"", Y2K_NOON);
    let (r, seen, _) = unstated(&s, head);
    assert_eq!(r, Ok(()));
    assert!(seen.headers().is_empty());
}

/// A file that cannot be opened ends the transfer before a connection,
/// without progress, every time taken at the end.
#[test]
fn a_missing_file_cannot_be_read() {
    let s = Scratch::new("missing");
    let (e, seen) = easy(&s.url("missing"));
    let (r, e) = run(e);
    assert_eq!(r, Err(ErrorKind::FileCouldntReadFile));
    assert_eq!(seen.events(), []);
    let t = e.report().timings();
    assert_eq!(t.namelookup(), Duration::ZERO, "never connected");
    assert_eq!(t.pretransfer(), Duration::from_micros(1));
    assert_eq!(t.starttransfer(), Duration::from_micros(1));
}

/// A zero byte in the path is a malformed URL; other control bytes are
/// part of the name.
#[test]
fn a_zero_byte_in_the_path_is_malformed() {
    let s = Scratch::new("zero");
    let (e, _) = easy(&s.url("a%00b"));
    assert_eq!(run(e).0, Err(ErrorKind::UrlMalformat));
    s.file("a\x01b", b"x", Y2K_NOON);
    let (e, seen) = easy(&s.url("a%01b"));
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(seen.body(), b"x");
}

/// A head request is the headers, and the size, alone.
#[test]
fn a_head_request_is_the_headers() {
    let s = Scratch::new("head");
    s.file("f", b"hello", Y2K_NOON);
    let (mut e, seen) = easy(&s.url("f"));
    e.options_mut().method = Method::Head;
    let (r, e) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(seen.headers(), SMALL_HEADERS);
    assert_eq!(seen.body(), b"");
    let mut want = vec![down(None, 0); 2];
    want.extend(vec![down(Some(5), 0); 3]);
    assert_eq!(seen.progress(), want);
    assert_eq!(e.report().sizes().download_expected(), Some(5));
}

fn resumed(s: &Scratch, name: &str, resume: Resume) -> (Result<(), ErrorKind>, Seen, Easy) {
    let (mut e, seen) = easy(&s.url(name));
    e.options_mut().resume = Some(resume);
    let (r, e) = run(e);
    (r, seen, e)
}

fn at(n: u64) -> Resume {
    Resume::At(NonZeroU64::new(n).unwrap())
}

/// A resumed download skips into the file, its headers still the whole
/// file's: to its end is nothing; past it, after the headers, no resume.
#[test]
fn a_download_resumes_into_the_file() {
    let s = Scratch::new("resume");
    s.file("f", b"hello", Y2K_NOON);
    let (r, seen, e) = resumed(&s, "f", at(2));
    assert_eq!(r, Ok(()));
    assert_eq!(seen.headers(), SMALL_HEADERS);
    assert_eq!(seen.body(), b"llo");
    assert_eq!(e.report().sizes().download_expected(), Some(3));
    let (r, seen, e) = resumed(&s, "f", at(5));
    assert_eq!(r, Ok(()));
    assert_eq!(seen.body(), b"");
    assert_eq!(
        e.report().sizes().download_expected(),
        Some(5),
        "unknown is not announced"
    );
    let (r, seen, e) = resumed(&s, "f", at(9));
    assert_eq!(r, Err(ErrorKind::BadDownloadResume));
    assert_eq!(seen.headers(), SMALL_HEADERS);
    // Twice before the request, and once as it is done with.
    let mut want = vec![down(None, 0); 2];
    want.push(down(Some(5), 0));
    assert_eq!(seen.progress(), want);
    // Ended in DO: DID's time is taken at the end.
    assert_eq!(e.report().timings().pretransfer(), Duration::from_micros(1));
}

/// Resuming at the end is the last byte, as C's -1 is the range "-1-";
/// an empty file's is nothing, announced as a byte.
#[test]
fn a_download_resumed_at_the_end_is_the_last_byte() {
    let s = Scratch::new("end");
    s.file("f", b"hello", Y2K_NOON);
    let (r, seen, e) = resumed(&s, "f", Resume::AtEnd);
    assert_eq!(r, Ok(()));
    assert_eq!(seen.body(), b"o");
    assert_eq!(e.report().sizes().download_expected(), Some(1));
    s.file("empty", b"", Y2K_NOON);
    let (r, seen, e) = resumed(&s, "empty", Resume::AtEnd);
    assert_eq!(r, Ok(()));
    assert_eq!(seen.body(), b"");
    assert_eq!(e.report().sizes().download_expected(), Some(1));
}

/// A directory cannot be resumed into.
#[test]
fn a_directory_cannot_be_resumed() {
    let s = Scratch::new("dirresume");
    std::fs::create_dir(s.0.join("d")).unwrap();
    for resume in [at(3), Resume::AtEnd] {
        let (r, seen, _) = resumed(&s, "d/", resume);
        assert_eq!(r, Err(ErrorKind::BadDownloadResume), "{resume:?}");
        assert_eq!(seen.body(), b"");
    }
}

/// A write handler cannot pause a file: there is no input to stop.
#[test]
fn a_pausing_write_fails() {
    struct Pauser;
    impl WriteHandler for Pauser {
        fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
            Write::Pause
        }
    }
    let s = Scratch::new("pause");
    s.file("f", b"hello", Y2K_NOON);
    let (mut e, _) = easy(&s.url("f"));
    e.options_mut().callbacks.write = Some(Handler::write(Pauser).unwrap());
    assert_eq!(run(e).0, Err(ErrorKind::WriteError));
}

/// Reads `left` bytes of `u`, as much as each read has room for.
struct Feeder {
    left: crate::test_cell::Cell<usize>,
}

impl ReadHandler for Feeder {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        let n = self.left.get().min(buf.len());
        buf[..n].fill(b'u');
        self.left.set(self.left.get() - n);
        NonZeroUsize::new(n).map_or(Read::Eof, Read::Data)
    }
}

fn upload(url: &[u8], source: UploadSource) -> (Easy, Seen) {
    let (mut e, seen) = easy(url);
    e.options_mut().method = Method::Upload;
    e.options_mut().upload = source;
    (e, seen)
}

fn fed(n: usize) -> UploadSource {
    UploadSource::Read {
        handler: Handler::read(Feeder {
            left: crate::test_cell::Cell::new(n),
        })
        .unwrap(),
        rewind: None,
        size: None,
    }
}

fn bytes(b: &[u8]) -> UploadSource {
    UploadSource::Bytes(TryArc::try_new(b.to_vec()).unwrap())
}

/// The text lines `e` traces, `components` on.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<String>>>);

impl crate::handler::DebugHandler for Lines {
    fn debug(&self, _: &mut TransferCx<'_>, kind: crate::handler::DebugKind, data: &[u8]) {
        if kind == crate::handler::DebugKind::Text {
            let line = String::from_utf8(data.to_vec()).unwrap();
            self.0.lock().unwrap().push(line.trim_end().to_owned());
        }
    }
}

fn traced(e: &mut Easy, components: &[u8]) -> Lines {
    let lines = Lines::default();
    e.options_mut().output.verbose = true;
    e.options_mut().callbacks.debug = Some(Handler::debug(lines.clone()).unwrap());
    let c = crate::components::Components::new().unwrap();
    c.configure(components);
    e.set_components(Some(c));
    lines
}

/// An upload's body is read through C's readers, set as it is first read,
/// and not read again past its end (`file_upload`, `Curl_client_read`).
#[test]
fn an_upload_is_read_as_c_reads_it() {
    let s = Scratch::new("upload-read");
    let (mut e, _) = upload(&s.url("new"), bytes(b"short"));
    let lines = traced(&mut e, b"read");
    let (r, _) = run(e);
    assert_eq!(r, Ok(()));
    let lines: Vec<_> = lines
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.starts_with("[READ] "))
        .cloned()
        .collect();
    assert_eq!(
        lines,
        [
            "[READ] client_reset, clear readers",
            "[READ] add buf reader, len=5 -> 0",
            "[READ] cr_buf_read(len=65536) -> 0, nread=5, eos=1",
            "[READ] client_read(len=65536) -> 0, nread=5, eos=1",
            "[READ] client_reset, clear readers",
        ]
    );
}

/// An upload writes the body to the file, created or emptied, in pieces of
/// the upload buffer; progress after each piece written and at the end.
#[test]
fn an_upload_writes_the_file() {
    let s = Scratch::new("upload");
    let (mut e, seen) = upload(&s.url("new"), fed(70000));
    e.options_mut().new_file_mode = FileMode::new(0o600).unwrap();
    let (r, e) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(s.read("new"), [b'u'; 70000]);
    let mode = std::fs::metadata(s.0.join("new"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let mut want = vec![up(0); 2];
    want.push(up(65536));
    want.extend(vec![up(70000); 5]);
    assert_eq!(seen.progress(), want);
    assert_eq!(e.report().sizes().upload(), 70000);
    assert_eq!(e.report().sizes().upload_expected(), None);
    // An existing file is emptied first.
    let (e, _) = upload(&s.url("new"), bytes(b"short"));
    let (r, e) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(s.read("new"), b"short");
    assert_eq!(e.report().sizes().upload_expected(), Some(5));
}

/// A send limit does not cut an upload to a file short: the file gets the
/// whole body. C's `file_upload` reads through the limit, takes the read
/// it refuses once the limit is spent for the end, and succeeds with the
/// file truncated to a step's worth (`curl --limit-rate 1000 -T 5k
/// file://` writes 1000 bytes and exits 0).
#[test]
fn a_send_limit_does_not_cut_an_upload_short() {
    let s = Scratch::new("uplimit");
    let (mut e, _) = upload(&s.url("f"), fed(70000));
    e.options_mut().flow.make_mut().unwrap().max_send_speed = std::num::NonZeroU64::new(1000);
    let (r, _) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(s.read("f"), [b'u'; 70000]);
}

/// A resumed upload appends what of the body is past the resume point; at
/// the end, past what the file holds already.
#[test]
fn an_upload_resumes_by_appending() {
    let s = Scratch::new("upresume");
    s.file("f", b"0123456789", Y2K_NOON);
    let (mut e, _) = upload(&s.url("f"), bytes(b"abcdefghijXYZ"));
    e.options_mut().resume = Some(at(10));
    let (r, e) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(s.read("f"), b"0123456789XYZ");
    assert_eq!(e.report().sizes().upload(), 3);
    let (mut e, _) = upload(&s.url("f"), bytes(b"abcdefghijklmnop"));
    e.options_mut().resume = Some(Resume::AtEnd);
    let (r, e) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(s.read("f"), b"0123456789XYZnop");
    assert_eq!(e.report().sizes().upload(), 3);
    // A resume point past a piece skips all of it, and the next one too.
    let (mut e, _) = upload(&s.url("g"), fed(70000));
    e.options_mut().resume = Some(at(69990));
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(s.read("g"), [b'u'; 10]);
}

/// An upload to a path that cannot be written is a write error; to the
/// root, which names nothing, a read error, as C has it.
#[test]
fn an_upload_needs_a_file_to_write() {
    let s = Scratch::new("upfail");
    let (e, _) = upload(&s.url("missing/f"), bytes(b"x"));
    assert_eq!(run(e).0, Err(ErrorKind::WriteError));
    let (e, _) = upload(b"file:///", bytes(b"x"));
    assert_eq!(run(e).0, Err(ErrorKind::FileCouldntReadFile));
    // A slash after the first is something: the root again, which cannot
    // be written as a file.
    let (e, _) = upload(b"file:////", bytes(b"x"));
    assert_eq!(run(e).0, Err(ErrorKind::WriteError));
}

/// The URL rules reach the parser: a user name refused, a path kept as
/// it is.
#[test]
fn the_url_rules_apply_to_a_file_url() {
    let s = Scratch::new("rules");
    s.file("f", b"x", Y2K_NOON);
    // A file URL has no room for a user: another scheme shows the rule.
    let (e, _) = easy(b"script://user@a");
    assert_eq!(run(e).0, Ok(()));
    let (mut e, _) = easy(b"script://user@a");
    e.options_mut().url_rules.disallow_user = true;
    assert_eq!(run(e).0, Err(ErrorKind::LoginDenied));
    // Through a directory that is not there: resolved, the path is the
    // file; as it is, it is not found.
    let dotted = s.url("missing/../f");
    let (e, seen) = easy(&dotted);
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(seen.body(), b"x");
    let (mut e, _) = easy(&dotted);
    e.options_mut().url_rules.path_as_is = true;
    assert_eq!(run(e).0, Err(ErrorKind::FileCouldntReadFile));
}

/// A read handler cannot pause an upload to a file.
#[test]
fn a_pausing_read_fails() {
    struct Pauser;
    impl ReadHandler for Pauser {
        fn read(&self, _: &mut TransferCx<'_>, _: &mut [u8]) -> Read {
            Read::Pause
        }
    }
    let s = Scratch::new("readpause");
    let source = UploadSource::Read {
        handler: Handler::read(Pauser).unwrap(),
        rewind: None,
        size: None,
    };
    let (e, _) = upload(&s.url("f"), source);
    assert_eq!(run(e).0, Err(ErrorKind::ReadError));
    // Nor can a part's handler pause a tree's.
    let mut tree = crate::mime::Mime::new(
        crate::mime::Boundary::draw(|| Ok::<_, std::convert::Infallible>(0)).unwrap(),
    );
    tree.add(crate::mime::Part {
        name: Some(b"p".to_vec()),
        content: crate::mime::Content::Read {
            handler: Handler::read(Pauser).unwrap(),
            rewind: None,
            size: None,
        },
        ..crate::mime::Part::default()
    })
    .unwrap();
    let tree = crate::mime::Fixed::new(TryArc::try_new(tree).unwrap());
    let (e, _) = upload(
        &s.url("t"),
        UploadSource::Mime(Handler::mime(tree).unwrap()),
    );
    assert_eq!(run(e).0, Err(ErrorKind::ReadError));
}

fn modified(t: i64) -> Result<String, ErrorKind> {
    let mut out = Text::<80>::new();
    last_modified(t, &mut out)?;
    Ok(String::from_utf8(out.bytes().to_vec()).unwrap())
}

/// The modification time, in UTC, before and after the epoch.
#[test]
fn the_modification_time_is_a_date() {
    let line = |s: &str| Ok(format!("Last-Modified: {s} GMT\r\n"));
    assert_eq!(modified(0), line("Thu, 01 Jan 1970 00:00:00"));
    assert_eq!(modified(Y2K_NOON as i64), line("Sat, 01 Jan 2000 12:00:00"));
    assert_eq!(modified(951_825_599), line("Tue, 29 Feb 2000 11:59:59"));
    assert_eq!(modified(-1), line("Wed, 31 Dec 1969 23:59:59"));
    assert_eq!(modified(-62_135_596_800), line("Mon, 01 Jan    1 00:00:00"));
    assert_eq!(
        modified(253_402_300_800),
        line("Sat, 01 Jan 10000 00:00:00")
    );
    // A year past C's `int` years.
    assert_eq!(modified(i64::MAX), Err(ErrorKind::BadFunctionArgument));
    // The last year `struct tm` holds, and the first it does not.
    assert_eq!(
        modified(67_768_036_160_140_800),
        line("Wed, 01 Jan 2147485547 00:00:00")
    );
    assert_eq!(
        modified(67_768_036_191_676_800),
        Err(ErrorKind::BadFunctionArgument)
    );
}

/// The leap years of the Gregorian calendar: every fourth, but not every
/// hundredth, but every four hundredth.
#[test]
fn the_calendar_has_its_leap_years() {
    let line = |s: &str| Ok(format!("Last-Modified: {s} GMT\r\n"));
    for (t, date) in [
        (-2_203_977_600, "Wed, 28 Feb 1900 00:00:00"),
        (-2_203_891_200, "Thu, 01 Mar 1900 00:00:00"),
        (4_107_542_399, "Sun, 28 Feb 2100 23:59:59"),
        (4_107_542_400, "Mon, 01 Mar 2100 00:00:00"),
        (13_574_606_400, "Tue, 29 Feb 2400 12:00:00"),
        (13_569_465_599, "Fri, 31 Dec 2399 23:59:59"),
        (-11_670_998_400, "Tue, 29 Feb 1600 00:00:00"),
        (-11_644_473_600, "Mon, 01 Jan 1601 00:00:00"),
        (253_402_300_799, "Fri, 31 Dec 9999 23:59:59"),
        (-86_400, "Wed, 31 Dec 1969 00:00:00"),
    ] {
        assert_eq!(modified(t), line(date), "{t}");
    }
}

/// Text for the user, kept.
#[derive(Clone, Default)]
struct Stderr(Arc<Mutex<Vec<u8>>>);

impl TextSink for Stderr {
    fn write(&self, text: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(text);
    }
}

/// The meter of a file's transfer, over within a second, is drawn once,
/// at the start, and its line ended: the request never exchanges, so its
/// last pass shows nothing new (C's `req.done` stays false), as C's
/// `curl -o O file://...` prints.
#[test]
fn a_file_draws_its_meter_once() {
    let s = Scratch::new("meter");
    s.file("f", b"hello", Y2K_NOON);
    let (mut e, _) = easy(&s.url("f"));
    let stderr = Stderr::default();
    e.options_mut().progress = Progress::Meter;
    e.options_mut().callbacks.stderr = Some(Handler::text(stderr.clone()).unwrap());
    let (result, _) = run(e);
    assert_eq!(result, Ok(()));
    let drawn = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        drawn,
        "  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current\n                                 Dload  Upload  Total   Spent   Left   Speed\n\r  0      0   0      0   0      0      0      0                              0\n"
    );
}

/// A file the time condition rules out is not read, nor are its headers
/// made, unless a range is asked for.
#[test]
fn a_file_the_time_condition_rules_out_is_not_read() {
    use crate::options::{Condition, TimeCondition};
    let s = Scratch::new("timecond");
    s.file("f", b"hello", Y2K_NOON);
    let fetch = |time: i64, resume: Option<Resume>| {
        let (mut e, seen) = easy(&s.url("f"));
        e.options_mut().time_condition = Some(TimeCondition {
            when: Condition::ModifiedSince,
            time,
        });
        e.options_mut().resume = resume;
        let (r, e) = run(e);
        assert_eq!(r, Ok(()));
        (seen, e.report().condition_unmet())
    };
    let (seen, unmet) = fetch(Y2K_NOON as i64, None);
    assert!(seen.headers().is_empty());
    assert_eq!(seen.body(), b"");
    assert!(unmet);
    let (seen, unmet) = fetch(Y2K_NOON as i64 - 1, None);
    assert_eq!(seen.headers(), SMALL_HEADERS);
    assert_eq!(seen.body(), b"hello");
    assert!(!unmet);
    let (seen, unmet) = fetch(Y2K_NOON as i64, Some(at(2)));
    assert_eq!(seen.body(), b"llo");
    assert!(!unmet);
}

/// A range is read as `Curl_range` reads it: `X-`, `-Y` and `X-Y`, a
/// number past an offset's none, what follows the second number left
/// unread; `-0`, a start past the end and one with no dash after it are
/// errors. A resume point is the range `N-`, C's -1 `-1-`.
#[test]
fn a_range_is_read_as_c_reads_it() {
    use super::{Span, span};
    use crate::options::Ranged;
    let of = |r: &[u8]| span(Some(Ranged::Given(r))).map(|s| s.map(|s| (s.resume, s.max)));
    assert_eq!(of(b"3-"), Ok(Some((3, None))));
    assert_eq!(of(b"-"), Ok(Some((0, None))));
    assert_eq!(of(b"-9"), Ok(Some((-9, Some(9)))));
    assert_eq!(of(b"1-4"), Ok(Some((1, Some(4)))));
    assert_eq!(of(b"2-3,5-6"), Ok(Some((2, Some(2)))));
    assert_eq!(of(b"3-a"), Ok(Some((3, None))));
    assert_eq!(of(b"-5-"), Ok(Some((-5, Some(5)))));
    assert_eq!(of(b"4-4"), Ok(Some((4, Some(1)))));
    assert_eq!(of(b"1-9223372036854775807"), Ok(Some((1, Some(i64::MAX)))));
    assert_eq!(of(b"1-99999999999999999999"), Ok(Some((1, None))));
    assert_eq!(of(b"-99999999999999999999"), Ok(Some((0, None))));
    for bad in [
        &b"-0"[..],
        b"5-2",
        b"abc",
        b"",
        b"3",
        b"99999999999999999999-",
        b"0-9223372036854775807",
    ] {
        assert_eq!(of(bad), Err(ErrorKind::RangeError), "{bad:?}");
    }
    assert_eq!(span(None), Ok(None));
    let resumed = |r| span(Some(Ranged::Resume(r))).unwrap().unwrap();
    assert_eq!(
        resumed(at(7)),
        Span {
            resume: 7,
            max: None,
            from: 7,
            to: 0
        }
    );
    assert_eq!(
        resumed(Resume::AtEnd),
        Span {
            resume: -1,
            max: Some(1),
            from: 0,
            to: 1
        }
    );
}

fn ranged(s: &Scratch, name: &str, range: &[u8]) -> (Result<(), ErrorKind>, Seen, Easy) {
    let (mut e, seen) = easy(&s.url(name));
    e.options_mut().range = Some(range.to_vec());
    let (r, e) = run(e);
    (r, seen, e)
}

/// A download delivers the range asked for, its size announced as the
/// range's however much of it the file has; the last bytes past the
/// start, a start past the end and a bad range fail after the headers.
#[test]
fn a_download_delivers_its_range() {
    let s = Scratch::new("range");
    s.file("f", b"1234567890\n", Y2K_NOON);
    for (range, body, size) in [
        (&b"1-4"[..], &b"2345"[..], Some(4)),
        (b"-3", b"90\n", Some(3)),
        (b"8-", b"90\n", Some(3)),
        (b"0-99", b"1234567890\n", Some(100)),
        (b"-1", b"\n", Some(1)),
    ] {
        let (r, seen, e) = ranged(&s, "f", range);
        assert_eq!(r, Ok(()), "{range:?}");
        assert_eq!(seen.body(), body, "{range:?}");
        assert_eq!(e.report().sizes().download_expected(), size, "{range:?}");
    }
    for (range, error) in [
        (&b"-100"[..], ErrorKind::BadDownloadResume),
        (b"20-30", ErrorKind::BadDownloadResume),
        (b"-0", ErrorKind::RangeError),
        (b"5-2", ErrorKind::RangeError),
    ] {
        let (r, seen, _) = ranged(&s, "f", range);
        assert_eq!(r, Err(error), "{range:?}");
        assert_eq!(seen.headers().len(), 4, "{range:?}");
        assert_eq!(seen.body(), b"", "{range:?}");
    }
    // A head request is the headers, the range not read.
    let (mut e, seen) = easy(&s.url("f"));
    e.options_mut().range = Some(b"-0".to_vec());
    e.options_mut().method = Method::Head;
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(seen.headers().len(), 4);
}

/// A directory's listing is cut at the range's size; any start in it
/// fails.
#[test]
fn a_directory_listing_is_cut_at_its_range() {
    let s = Scratch::new("dirrange");
    std::fs::create_dir(s.0.join("d")).unwrap();
    std::fs::write(s.0.join("d/abcdef"), b"").unwrap();
    let (r, seen, _) = ranged(&s, "d/", b"0-3");
    assert_eq!(r, Ok(()));
    assert_eq!(seen.body(), b"abcd");
    let (r, _, _) = ranged(&s, "d/", b"1-3");
    assert_eq!(r, Err(ErrorKind::BadDownloadResume));
}

/// A file that cannot be stat'ed delivers no more than a range from its
/// start; the last bytes need its size, and any other start fails.
#[test]
fn a_file_that_cannot_be_stated_delivers_a_range_from_its_start() {
    let s = Scratch::new("unstatedrange");
    s.file("f", b"hello", Y2K_NOON);
    let range = |r: &'static [u8]| move |e: &mut Easy| e.options_mut().range = Some(r.to_vec());
    let (r, seen, _) = unstated(&s, range(b"0-2"));
    assert_eq!((r, seen.body()), (Ok(()), b"hel".to_vec()));
    let (r, seen, _) = unstated(&s, range(b"-2"));
    assert_eq!((r, seen.body()), (Err(ErrorKind::ReadError), Vec::new()));
    let (r, _, _) = unstated(&s, range(b"1-2"));
    assert_eq!(r, Err(ErrorKind::BadDownloadResume));
}

/// With a range asked for, a time condition is not checked.
#[test]
fn a_range_reads_past_a_time_condition() {
    use crate::options::{Condition, TimeCondition};
    let s = Scratch::new("rangecond");
    s.file("f", b"hello", Y2K_NOON);
    let (mut e, seen) = easy(&s.url("f"));
    e.options_mut().range = Some(b"1-".to_vec());
    e.options_mut().time_condition = Some(TimeCondition {
        when: Condition::ModifiedSince,
        time: Y2K_NOON as i64 + 1,
    });
    let (r, e) = run(e);
    assert_eq!(r, Ok(()));
    assert_eq!(seen.body(), b"ello");
    assert!(!e.report().condition_unmet());
}

/// The debug build traces the range as C's does (`Curl_range`'s
/// `DEBUGF`), the lines taken from the C build for a file of 5 bytes.
#[cfg(feature = "debug-hooks")]
#[test]
fn the_debug_build_traces_the_range() {
    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<String>>>);
    impl crate::handler::DebugHandler for Lines {
        fn debug(&self, _: &mut TransferCx<'_>, kind: crate::handler::DebugKind, data: &[u8]) {
            if kind == crate::handler::DebugKind::Text {
                let line = String::from_utf8_lossy(data).into_owned();
                self.0.lock().unwrap().push(line);
            }
        }
    }
    let s = Scratch::new("rangetrace");
    s.file("f", b"hello", Y2K_NOON);
    for (range, want) in [
        (
            &b"1-2"[..],
            [
                "RANGE from 1 getting 2 bytes",
                "range-download from 1 to 2, totally 2 bytes",
            ],
        ),
        (
            b"0-1",
            [
                "RANGE from 0 getting 2 bytes",
                "range-download from 0 to 1, totally 2 bytes",
            ],
        ),
        (
            b"-2",
            [
                "RANGE the last 2 bytes",
                "range-download from 0 to 2, totally 2 bytes",
            ],
        ),
        (
            b"3-",
            [
                "RANGE 3 to end of file",
                "range-download from 3 to 0, totally -1 bytes",
            ],
        ),
    ] {
        let (mut e, _) = easy(&s.url("f"));
        let lines = Lines::default();
        e.options_mut().range = Some(range.to_vec());
        e.options_mut().output.verbose = true;
        e.options_mut().callbacks.debug = Some(Handler::debug(lines.clone()).unwrap());
        assert_eq!(run(e).0, Ok(()));
        let got: Vec<String> = lines
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.to_ascii_lowercase().starts_with("range"))
            .map(|l| l.trim_end().to_string())
            .collect();
        assert_eq!(got, want, "{range:?}");
    }
}

/// A handler is given no more room than is left of the upload's size, so
/// the file is written no further than it.
#[test]
fn an_upload_is_written_no_further_than_its_size() {
    struct OneThenAll(crate::test_cell::Cell<usize>);
    impl ReadHandler for OneThenAll {
        fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
            let data = b"abcdefghij";
            let at = self.0.get();
            let n = if at == 0 {
                1
            } else {
                buf.len().min(data.len() - at)
            };
            buf[..n].copy_from_slice(&data[at..at + n]);
            self.0.set(at + n);
            NonZeroUsize::new(n).map_or(Read::Eof, Read::Data)
        }
    }
    let s = Scratch::new("upsize");
    let source = UploadSource::Read {
        handler: Handler::read(OneThenAll(crate::test_cell::Cell::new(0))).unwrap(),
        rewind: None,
        size: Some(5),
    };
    let (e, _) = upload(&s.url("f"), source);
    assert_eq!(run(e).0, Ok(()));
    assert_eq!(s.read("f"), b"abcde");
}
