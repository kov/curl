//! Waking a waiting multi from another thread (`curl_multi_wakeup`,
//! `lib/socketpair.c`): an eventfd, as C makes one where the system has
//! it (`wakeup_eventfd`), written by those that wake and polled by the
//! waiting thread. It is nonblocking, so a wake never waits and a drain
//! stops once the count is read.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

/// Shared between the waiting thread and those that wake it.
#[derive(Debug)]
pub struct Waker(OwnedFd);

impl Waker {
    pub fn new() -> io::Result<Waker> {
        // SAFETY: `eventfd` takes no pointers; a negative result is an
        // error.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just opened and is owned by nothing else.
        Ok(Waker(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Make the next poll of [`Waker::fd`] report it readable
    /// (`Curl_wakeup_signal`): one added to the count. A count that cannot
    /// grow is a wake already pending, not an error.
    pub fn wake(&self) -> io::Result<()> {
        let one = 1u64.to_ne_bytes();
        loop {
            // SAFETY: the descriptor is open while `self` lives, and the
            // buffer is the 8 bytes an eventfd is written with.
            let n = unsafe { libc::write(self.0.as_raw_fd(), one.as_ptr().cast(), one.len()) };
            if n >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(e),
            }
        }
    }

    /// Consume every pending wake (`Curl_wakeup_consume`): reading the
    /// count resets it.
    pub fn drain(&self) -> io::Result<()> {
        let mut count = [0u8; 8];
        loop {
            // SAFETY: as in `wake`; the buffer has room for the count.
            let n =
                unsafe { libc::read(self.0.as_raw_fd(), count.as_mut_ptr().cast(), count.len()) };
            if n >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(e),
            }
        }
    }

    /// The descriptor to poll for reading.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use std::time::Duration;

    use super::*;
    use crate::poll::{Events, PollFd, poll};

    fn woken(w: &Waker) -> bool {
        let mut fds = [PollFd::new(w.fd(), Events::IN)];
        poll(&mut fds, Duration::ZERO).unwrap() == 1
    }

    #[test]
    fn a_wake_is_seen_until_drained() {
        let w = Waker::new().unwrap();
        assert!(!woken(&w));
        w.wake().unwrap();
        w.wake().unwrap();
        assert!(woken(&w));
        w.drain().unwrap();
        assert!(!woken(&w), "every pending wake consumed at once");
    }

    /// One descriptor, an eventfd, as C's (`wakeup_eventfd`): a process
    /// short of descriptors still gets its waker, and the descriptors
    /// after it are numbered as C numbers them.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot read a descriptor's link")]
    fn the_waker_is_one_eventfd() {
        let w = Waker::new().unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&w.fd());
        let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
        assert_eq!(link.to_str(), Some("anon_inode:[eventfd]"));
        // SAFETY: `fcntl` on a descriptor `w` holds open.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0, "nonblocking");
        // SAFETY: as above.
        let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0, "closed on exec");
    }

    /// A wake with one already pending past counting is no error, as C's
    /// "wakeup is already ongoing"; a drain with none pending is none
    /// (`Curl_wakeup_signal`, `Curl_wakeup_consume` on `EAGAIN`).
    #[test]
    fn a_full_count_wakes_and_an_empty_one_drains() {
        use std::io::Write as _;
        let w = Waker::new().unwrap();
        w.drain().unwrap();
        assert!(!woken(&w));
        // The most an eventfd counts: one more would block.
        let mut count = std::fs::File::from(w.fd().try_clone_to_owned().unwrap());
        count.write_all(&(u64::MAX - 1).to_ne_bytes()).unwrap();
        w.wake().unwrap();
        assert!(woken(&w));
        w.drain().unwrap();
        assert!(!woken(&w));
        w.drain().unwrap();
    }

    #[test]
    fn many_wakes_drain_as_one() {
        let w = Waker::new().unwrap();
        // Far more than a socket buffer would hold, one each.
        for _ in 0..1_000_000 {
            w.wake().unwrap();
        }
        w.drain().unwrap();
        assert!(!woken(&w));
    }

    #[test]
    fn another_thread_wakes_a_waiting_one() {
        let w = Waker::new().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(20));
                w.wake().unwrap();
            });
            let mut fds = [PollFd::new(w.fd(), Events::IN)];
            assert_eq!(poll(&mut fds, Duration::from_secs(10)).unwrap(), 1);
        });
    }
}
