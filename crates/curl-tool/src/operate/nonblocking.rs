//! `-T .`: standard input uploaded without blocking (`tool_read_cb`,
//! `tool_readbusy_cb`). A read that finds nothing there pauses the
//! upload, and the next call the library makes into the tool for the
//! transfer, of its progress or with its output, lets it go on.

use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroUsize;
use std::os::fd::AsFd as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use curl_alloc::{OutOfMemory, TryArc};
use curl_core::handler::{
    Handler, ProgressHandler, ProgressNow, ProgressVerdict, Read, ReadHandler, Write, WriteHandler,
};
use curl_core::multi::{PauseRequest, TransferCx};
use curl_os::poll::{Events, PollFd, poll};

use crate::bar::Bar;

/// A transfer's standard input, made nonblocking, and whether its upload
/// waits for it (C's `readbusy`).
#[derive(Clone)]
pub(super) struct Stdin(TryArc<State>);

struct State {
    file: TryArc<Mutex<File>>,
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
        if let Err(e) = curl_os::fs::set_nonblocking(&file) {
            // C names the descriptor it reads, 0; this one is its copy.
            let why = crate::os_message(&e);
            msgs.warn(&[b"fcntl failed on fd=0: ", why.as_bytes()]);
        }
        let file = TryArc::try_new(Mutex::new(file)).map_err(|_| Unopened::OutOfMemory)?;
        let state = State {
            file,
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

    /// What reads it for an attempt started now, which `timeout` bounds.
    pub(super) fn reader(
        &self,
        timeout: Option<Duration>,
    ) -> Result<Handler<dyn ReadHandler>, OutOfMemory> {
        Handler::read(Reader {
            stdin: self.clone(),
            start: Instant::now(),
            timeout,
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
    fn wait(&self, timeout: Duration) {
        let file = self.0.file.lock().expect("no panic holds it");
        let mut fds = [PollFd::new(file.as_fd(), Events::IN)];
        // What came of it is the next read's to find, as in C.
        let _ = poll(&mut fds, timeout);
    }
}

/// Reads standard input for one attempt (`tool_read_cb`).
struct Reader {
    stdin: Stdin,
    /// When the attempt started (`per->start`).
    start: Instant,
    /// `--max-time`.
    timeout: Option<Duration>,
}

impl ReadHandler for Reader {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        if let Some(timeout) = self.timeout {
            // Past the time allowed, there is nothing more to send; before
            // it, the read waits for the rest of it.
            let Some(left) = timeout.checked_sub(self.start.elapsed()) else {
                return Read::Eof;
            };
            self.stdin.wait(left);
        }
        let state = &self.stdin.0;
        let read = loop {
            match state.file.lock().expect("no panic holds it").read(buf) {
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
