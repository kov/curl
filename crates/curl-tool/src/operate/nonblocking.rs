//! `-T .`: standard input uploaded without blocking (`tool_read_cb`,
//! `tool_readbusy_cb`). A read that finds nothing there pauses the
//! upload, and the next call the library makes into the tool for the
//! transfer, of its progress or with its output, lets it go on. Also
//! the wait under `--max-time` that the reads of every upload make.
//!
//! On Windows standard input cannot be read without waiting, so C's tool
//! has a thread read it into one end of a loopback TCP connection and
//! reads the other end without waiting (`win32_stdin_read_thread`); so
//! does this.

use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroUsize;
#[cfg(unix)]
use std::os::fd::AsFd as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use curl_alloc::{OutOfMemory, TryArc};
use curl_core::handler::{
    Handler, ProgressHandler, ProgressNow, ProgressVerdict, Read, ReadHandler, Write, WriteHandler,
};
use curl_core::multi::{PauseRequest, TransferCx};
#[cfg(unix)]
use curl_os::poll::{Events, PollFd, poll};

use crate::bar::Bar;

/// A transfer's standard input, made nonblocking, and whether its upload
/// waits for it (C's `readbusy`).
#[derive(Clone)]
pub(super) struct Stdin(TryArc<State>);

struct State {
    file: TryArc<Mutex<File>>,
    /// Where it is read from on Windows: the loopback connection a thread
    /// writes it into, or none, when that could not be set up and it is
    /// read as it is.
    #[cfg(windows)]
    relay: Option<std::net::TcpStream>,
    /// The last read found nothing, and paused the upload.
    busy: AtomicBool,
    /// What was uploaded when the progress was last told (`ulprev`).
    uploaded: AtomicU64,
}

/// Why standard input is not there to upload.
pub(super) enum Unopened {
    OutOfMemory,
    Io,
}

impl Stdin {
    /// Standard input, its reads made not to wait (`check_stdin_upload`);
    /// a failure to make them so is warned of, as C's, and they wait.
    pub(super) fn open(msgs: &crate::msgs::Messages) -> Result<Stdin, Unopened> {
        let file = curl_os::fs::stdin().map_err(|_| Unopened::Io)?;
        #[cfg(unix)]
        if let Err(e) = curl_os::fs::set_nonblocking(&file) {
            // C names the descriptor it reads, 0; this one is its copy.
            let why = crate::os_message(&e);
            msgs.warn(&[b"fcntl failed on fd=0: ", why.as_bytes()]);
        }
        #[cfg(windows)]
        let relay = match curl_os::fs::stdin().and_then(relay::start) {
            Ok(relay) => Some(relay),
            Err(_) => {
                msgs.warn(&[
                    b"win32_stdin_read_thread returned INVALID_SOCKET falling back to blocking mode",
                ]);
                None
            }
        };
        let file = TryArc::try_new(Mutex::new(file)).map_err(|_| Unopened::OutOfMemory)?;
        let state = State {
            file,
            #[cfg(windows)]
            relay,
            busy: AtomicBool::new(false),
            uploaded: AtomicU64::new(0),
        };
        Ok(Stdin(
            TryArc::try_new(state).map_err(|_| Unopened::OutOfMemory)?,
        ))
    }

    /// The file, for what starts the upload over.
    pub(super) fn file(&self) -> TryArc<Mutex<File>> {
        self.0.file.clone()
    }

    /// What reads it for an attempt, which `limit` bounds.
    pub(super) fn reader(
        &self,
        limit: Option<ReadLimit>,
    ) -> Result<Handler<dyn ReadHandler>, OutOfMemory> {
        Handler::read(Reader {
            stdin: self.clone(),
            limit,
        })
    }

    /// `inner`, the upload let go on after each piece of output it takes
    /// (`tool_write_cb`).
    pub(super) fn writer(
        &self,
        inner: Handler<dyn WriteHandler>,
    ) -> Result<Handler<dyn WriteHandler>, OutOfMemory> {
        Handler::write(Unpausing {
            inner,
            stdin: self.clone(),
        })
    }

    /// `bar`, the upload let go on each time it is drawn: not when it
    /// comes too soon after the last (`tool_progress_cb`).
    pub(super) fn bar(&self, bar: &Bar) -> Result<Handler<dyn ProgressHandler>, OutOfMemory> {
        Handler::progress(Drawing {
            bar: bar.clone(),
            stdin: self.clone(),
        })
    }

    /// `inner`, the upload let go on each time it is told of the progress
    /// and goes on (`xferinfo_cb`).
    pub(super) fn progress(
        &self,
        inner: Handler<dyn ProgressHandler>,
    ) -> Result<Handler<dyn ProgressHandler>, OutOfMemory> {
        Handler::progress(Unpausing {
            inner,
            stdin: self.clone(),
        })
    }

    /// The progress handler of a transfer that has no other, which lets
    /// the upload go on, and has the library draw its meter as well
    /// unless `quiet` (`tool_readbusy_cb`).
    pub(super) fn waker(&self, quiet: bool) -> Result<Handler<dyn ProgressHandler>, OutOfMemory> {
        Handler::progress(Waker {
            stdin: self.clone(),
            quiet,
        })
    }

    /// The upload waits for standard input no more
    /// (`curl_easy_pause(CURLPAUSE_CONT)`).
    fn unpause(&self, cx: &mut TransferCx<'_>) {
        if self.0.busy.swap(false, Ordering::Relaxed) {
            // A replay of held output that fails fails the transfer at its
            // next step, so the result has nothing more to say; C's tool
            // ignores it too.
            let _ = cx.pause(cx.me(), PauseRequest::CONT);
        }
    }

    /// Wait up to `timeout` for something to read (`waitfd`).
    #[cfg(unix)]
    fn wait(&self, timeout: Duration) {
        wait_readable(&self.0.file.lock().expect("no panic holds it"), timeout);
    }

    /// Sleep for `timeout` (`curlx_wait_ms`): Windows cannot wait for a
    /// file to have something to read.
    #[cfg(windows)]
    fn wait(&self, timeout: Duration) {
        std::thread::sleep(timeout);
    }

    /// Read some of it into `buf`: from the relay on Windows, if there is
    /// one.
    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(windows)]
        if let Some(relay) = &self.0.relay {
            return (&*relay).read(buf);
        }
        self.0.file.lock().expect("no panic holds it").read(buf)
    }
}

/// Wait up to `timeout` for `file` to have something to read (`waitfd`).
#[cfg(unix)]
fn wait_readable(file: &File, timeout: Duration) {
    let mut fds = [PollFd::new(file.as_fd(), Events::IN)];
    // What came of it is the next read's to find, as in C.
    let _ = poll(&mut fds, timeout);
}

/// `--max-time` as the tool's reads of what it uploads see it, counted
/// from the attempt's start (`tool_read_cb`'s `per->start`).
#[derive(Clone, Copy, Debug)]
pub(super) struct ReadLimit {
    start: Instant,
    timeout: Duration,
}

impl ReadLimit {
    /// `timeout` from now, if there is one.
    pub(super) fn starting_now(timeout: Option<Duration>) -> Option<ReadLimit> {
        timeout.map(|timeout| ReadLimit {
            start: Instant::now(),
            timeout,
        })
    }

    /// Before a read of `file`: past the time allowed, there is nothing
    /// more to send (false); before it, wait for the rest of it for
    /// something to read, except on Windows, which cannot wait for a file.
    /// A file that blocks is then read as it is.
    pub(super) fn wait(self, file: &Mutex<File>) -> bool {
        let Some(left) = self.timeout.checked_sub(self.start.elapsed()) else {
            return false;
        };
        #[cfg(unix)]
        wait_readable(&file.lock().expect("no panic holds it"), left);
        #[cfg(windows)]
        let _ = (file, left);
        true
    }
}

/// Reads standard input for one attempt (`tool_read_cb`).
struct Reader {
    stdin: Stdin,
    /// `--max-time`.
    limit: Option<ReadLimit>,
}

impl ReadHandler for Reader {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        if let Some(limit) = self.limit
            && !limit.wait(&self.stdin.0.file)
        {
            return Read::Eof;
        }
        let state = &self.stdin.0;
        let read = loop {
            match self.stdin.read(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                read => break read,
            }
        };
        match read {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                state.busy.store(true, Ordering::Relaxed);
                Read::Pause
            }
            // C takes a failed read for the end of the file; here it fails
            // the transfer rather than send part of the input as all of it
            // (DIVERGENCE.md).
            Err(_) => Read::Fail,
            Ok(n) => {
                state.busy.store(false, Ordering::Relaxed);
                NonZeroUsize::new(n).map_or(Read::Eof, Read::Data)
            }
        }
    }
}

/// A handler of the tool's, which lets the upload go on after it.
struct Unpausing<H> {
    inner: H,
    stdin: Stdin,
}

impl WriteHandler for Unpausing<Handler<dyn WriteHandler>> {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
        let wrote = self.inner.write(cx, body);
        self.stdin.unpause(cx);
        wrote
    }
}

impl ProgressHandler for Unpausing<Handler<dyn ProgressHandler>> {
    fn progress(&self, cx: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
        let verdict = self.inner.progress(cx, now);
        // One that stops the transfer stops it before.
        if verdict != ProgressVerdict::Abort {
            self.stdin.unpause(cx);
        }
        verdict
    }
}

/// `tool_progress_cb`.
struct Drawing {
    bar: Bar,
    stdin: Stdin,
}

impl ProgressHandler for Drawing {
    fn progress(&self, cx: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
        if self.bar.update(now) {
            self.stdin.unpause(cx);
        }
        ProgressVerdict::Continue
    }
}

/// `tool_readbusy_cb`.
struct Waker {
    stdin: Stdin,
    /// No meter: `--no-progress-meter`, `--silent`, or output to a
    /// terminal.
    quiet: bool,
}

impl ProgressHandler for Waker {
    fn progress(&self, cx: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict {
        let state = &self.stdin.0;
        if state.busy.load(Ordering::Relaxed) {
            // Nothing went since the last call: a moment for input to come,
            // so that a paused upload does not spin.
            if state.uploaded.load(Ordering::Relaxed) == now.uploaded {
                self.stdin.wait(Duration::from_millis(1));
            }
            self.stdin.unpause(cx);
        }
        state.uploaded.store(now.uploaded, Ordering::Relaxed);
        if self.quiet {
            ProgressVerdict::Continue
        } else {
            ProgressVerdict::ContinueWithMeter
        }
    }
}

/// The thread that reads standard input into a loopback TCP connection on
/// Windows, and the end it is read from (`win32_stdin_read_thread`).
#[cfg(windows)]
mod relay {
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};

    /// The UCRT's `BUFSIZ`: what the thread reads at a time.
    const BUFSIZ: usize = 512;

    /// Set it up as C does: a listener on a loopback port, a connection to
    /// it, accepted; a random number sent from the reading end and checked
    /// at the writing one, so that no other connection gets the input;
    /// the reading end not waiting; then the thread started on `input`, a
    /// copy of standard input's handle, writing into the other end.
    pub(super) fn start(input: File) -> io::Result<TcpStream> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let reading = TcpStream::connect(listener.local_addr()?)?;
        let (writing, _) = listener.accept()?;
        drop(listener);
        let mut auth = [0u8; 8];
        curl_os::random::fill(&mut auth)?;
        (&reading).write_all(&auth)?;
        let mut got = [0u8; 8];
        (&writing).read_exact(&mut got)?;
        if got != auth {
            return Err(io::Error::other("relay peer auth failed"));
        }
        reading.set_nonblocking(true)?;
        // The thread lives as long as the process, as C's does, so what
        // starting it allocates is not counted as left behind.
        let spawn = move || std::thread::Builder::new().spawn(move || pump(input, &writing));
        #[cfg(feature = "debug-hooks")]
        let spawned = curl_alloc::track::untracked(spawn);
        #[cfg(not(feature = "debug-hooks"))]
        let spawned = spawn();
        spawned?;
        Ok(reading)
    }

    /// Copy `input` into `writing` until it ends or fails, then end the
    /// connection's sending and wait for the other end to close
    /// (`win_stdin_thread_func`).
    fn pump(mut input: File, writing: &TcpStream) {
        let mut buf = [0u8; BUFSIZ];
        loop {
            let n = match input.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if !matches!((&*writing).write(&buf[..n]), Ok(sent) if sent == n) {
                break;
            }
        }
        if writing.shutdown(Shutdown::Write).is_ok() {
            let mut rest = [0u8; 1024];
            while matches!((&*writing).read(&mut rest), Ok(n) if n > 0) {}
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// What the thread reads comes out of the reading end whole, and
        /// ends where the input does.
        #[test]
        fn the_input_comes_out_of_the_reading_end_whole() {
            let path = std::env::temp_dir().join(format!("curl-relay-{}", std::process::id()));
            let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
            std::fs::write(&path, &data).unwrap();
            let reading = start(File::open(&path).unwrap()).unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 700];
            loop {
                match (&reading).read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            assert_eq!(got, data);
            std::fs::remove_file(&path).unwrap();
        }
    }
}
