//! Waking a waiting multi from another thread (`curl_multi_wakeup`,
//! `lib/socketpair.c`): a connected socket pair, written on one end and
//! polled on the other. Both ends are nonblocking, so no signal
//! interrupts a wake or a drain.

use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;

/// Shared between the waiting thread and those that wake it.
#[derive(Debug)]
pub struct Waker {
    /// Polled by the waiting thread.
    read: UnixStream,
    write: UnixStream,
}

impl Waker {
    pub fn new() -> io::Result<Waker> {
        let (read, write) = UnixStream::pair()?;
        read.set_nonblocking(true)?;
        write.set_nonblocking(true)?;
        Ok(Waker { read, write })
    }

    /// Make the next poll of [`Waker::fd`] report it readable. A wake
    /// already pending is enough: a full pipe is not an error.
    pub fn wake(&self) -> io::Result<()> {
        match (&self.write).write(&[1]) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Consume every pending wake.
    pub fn drain(&self) -> io::Result<()> {
        let mut buf = [0u8; 64];
        loop {
            match (&self.read).read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// The end to poll for reading.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn waking_more_than_the_pipe_holds_is_fine() {
        let w = Waker::new().unwrap();
        // Far more than a socket buffer holds, one byte each.
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
