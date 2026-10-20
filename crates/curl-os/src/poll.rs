//! Waiting for sockets: `poll(2)` over a slice of descriptors (`Curl_poll`).

#![allow(unsafe_code)]

use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Duration;

/// What to wait for on a descriptor, and what happened to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Events(i16);

impl Events {
    pub const NONE: Events = Events(0);
    pub const IN: Events = Events(libc::POLLIN);
    pub const PRI: Events = Events(libc::POLLPRI);
    pub const OUT: Events = Events(libc::POLLOUT);
    /// Only ever reported, never asked for.
    pub const ERR: Events = Events(libc::POLLERR);
    pub const HUP: Events = Events(libc::POLLHUP);
    pub const NVAL: Events = Events(libc::POLLNVAL);

    pub fn contains(self, other: Events) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for Events {
    type Output = Events;

    fn bitor(self, other: Events) -> Events {
        Events(self.0 | other.0)
    }
}

impl std::ops::BitOrAssign for Events {
    fn bitor_assign(&mut self, other: Events) {
        self.0 |= other.0;
    }
}

/// One descriptor to poll, borrowed for as long as the entry lives: the
/// kernel is never handed a descriptor that may have been closed.
#[repr(transparent)]
pub struct PollFd<'a> {
    raw: libc::pollfd,
    _fd: PhantomData<BorrowedFd<'a>>,
}

impl<'a> PollFd<'a> {
    pub fn new(fd: BorrowedFd<'a>, events: Events) -> Self {
        PollFd {
            raw: libc::pollfd {
                fd: fd.as_raw_fd(),
                events: events.0,
                revents: 0,
            },
            _fd: PhantomData,
        }
    }

    /// What the last `poll` reported for this descriptor.
    pub fn revents(&self) -> Events {
        Events(self.raw.revents)
    }
}

/// Wait up to `timeout` for any of `fds` to be ready; with none, sleep
/// for `timeout`. Returns how many have events. A signal ending the wait
/// early counts as nothing ready, as in C.
pub fn poll(fds: &mut [PollFd<'_>], timeout: Duration) -> io::Result<u32> {
    for fd in fds.iter_mut() {
        fd.raw.revents = 0;
    }
    // Rounded up, so a wait never ends before its time; capped at what
    // `poll` takes.
    let ms = timeout.as_nanos().div_ceil(1_000_000);
    let ms = i32::try_from(ms).unwrap_or(i32::MAX);
    let n = libc::nfds_t::try_from(fds.len()).expect("descriptor counts fit nfds_t");
    // SAFETY: `PollFd` is `repr(transparent)` over `libc::pollfd`, so the
    // slice is `n` valid `pollfd`s; each borrows its descriptor, which
    // therefore stays open for the call. The kernel writes only
    // `revents`, inside the slice.
    let rc = unsafe { libc::poll(fds.as_mut_ptr().cast::<libc::pollfd>(), n, ms) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        return Err(err);
    }
    Ok(u32::try_from(rc).expect("poll counts at most the descriptors given"))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    use super::*;

    #[test]
    fn reports_the_ready_descriptor_only() {
        let (mut a, b) = UnixStream::pair().unwrap();
        let (_c, d) = UnixStream::pair().unwrap();
        a.write_all(b"x").unwrap();
        let mut fds = [
            PollFd::new(b.as_fd(), Events::IN),
            PollFd::new(d.as_fd(), Events::IN),
        ];
        assert_eq!(poll(&mut fds, Duration::from_secs(5)).unwrap(), 1);
        assert!(fds[0].revents().contains(Events::IN));
        assert!(fds[1].revents().is_empty());
    }

    #[test]
    fn waits_out_its_timeout_with_nothing_ready() {
        let (_a, b) = UnixStream::pair().unwrap();
        let mut fds = [PollFd::new(b.as_fd(), Events::IN)];
        let start = Instant::now();
        assert_eq!(poll(&mut fds, Duration::from_millis(30)).unwrap(), 0);
        assert!(start.elapsed() >= Duration::from_millis(30));
        let start = Instant::now();
        assert_eq!(poll(&mut [], Duration::from_millis(30)).unwrap(), 0);
        assert!(
            start.elapsed() >= Duration::from_millis(30),
            "no descriptors: a sleep"
        );
    }

    #[test]
    fn a_sub_millisecond_timeout_still_waits() {
        let start = Instant::now();
        assert_eq!(poll(&mut [], Duration::from_micros(10)).unwrap(), 0);
        assert!(start.elapsed() >= Duration::from_micros(10));
    }

    extern "C" fn ignore(_: libc::c_int) {}

    /// A signal that interrupts the wait ends it with nothing ready.
    #[test]
    #[cfg_attr(miri, ignore = "Miri has no sigaction")]
    fn an_interrupted_wait_reports_nothing_ready() {
        // SAFETY: all-zero bytes are a valid, empty `sigaction`.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = ignore as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: `action` is valid and lives through the call; its handler
        // does nothing, so it is async-signal-safe. `SA_RESTART` is left
        // out on purpose, so that `poll` sees EINTR.
        let rc = unsafe { libc::sigaction(libc::SIGUSR1, &raw const action, std::ptr::null_mut()) };
        assert_eq!(rc, 0);
        // SAFETY: `pthread_self` has no preconditions.
        let me = unsafe { libc::pthread_self() };
        let (_a, b) = UnixStream::pair().unwrap();
        let done = std::sync::atomic::AtomicBool::new(false);
        let start = Instant::now();
        let got = std::thread::scope(|scope| {
            // Signalled until the wait ends, so one sent before it began
            // cannot leave it waiting out its timeout.
            scope.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(5));
                    // SAFETY: `me` is the scope's thread, which outlives
                    // this one.
                    unsafe { libc::pthread_kill(me, libc::SIGUSR1) };
                }
            });
            let mut fds = [PollFd::new(b.as_fd(), Events::IN)];
            let got = poll(&mut fds, Duration::from_secs(10));
            done.store(true, std::sync::atomic::Ordering::Release);
            got
        });
        assert_eq!(got.unwrap(), 0);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the signal ended the wait"
        );
    }
}
