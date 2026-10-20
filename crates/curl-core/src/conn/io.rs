//! The engine's way to the network, and the fake that stands in for it in
//! tests. Only `conn` and `Multi::wait` call it.

use std::io;
use std::time::Duration;

pub use curl_os::poll::{Events, PollFd};

/// The network as the engine reaches it.
pub trait Net {
    /// Wait up to `timeout` for any of `fds` to be ready; with none, sleep.
    /// Returns how many have events; a signal ending the wait early counts
    /// as nothing ready.
    fn poll(&mut self, fds: &mut [PollFd<'_>], timeout: Duration) -> io::Result<u32>;
}

/// The operating system's network.
#[derive(Debug, Default)]
pub struct SystemNet;

impl Net for SystemNet {
    fn poll(&mut self, fds: &mut [PollFd<'_>], timeout: Duration) -> io::Result<u32> {
        curl_os::poll::poll(fds, timeout)
    }
}

/// A network where waiting takes no time: a poll that finds nothing ready
/// moves the clock on by its timeout instead of sleeping. Real descriptors
/// given to it, a waker's or the application's, are still polled.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct FakeNet {
    clock: crate::time::ManualClock,
}

#[cfg(any(test, feature = "test-util"))]
impl FakeNet {
    /// A network whose waits move `clock`.
    pub fn new(clock: crate::time::ManualClock) -> FakeNet {
        FakeNet { clock }
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Net for FakeNet {
    fn poll(&mut self, fds: &mut [PollFd<'_>], timeout: Duration) -> io::Result<u32> {
        let ready = curl_os::poll::poll(fds, Duration::ZERO)?;
        if ready == 0 {
            self.clock.advance(timeout);
        }
        Ok(ready)
    }
}
