//! What the tests' servers on loopback share: an accept bounded in time,
//! so that a client that never connects fails the test that waits for it
//! rather than hanging it, the server's thread blocked in `accept` and the
//! test in joining it.
//!
//! Only tests use it, and a client that never comes is a failed test.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use curl_os::poll::{Events, PollFd, poll};
use curl_os::socket::AsSocket as _;

/// How long a server waits for its client: far longer than a client on
/// loopback takes, even on a loaded machine.
pub const CONNECT_WITHIN: Duration = Duration::from_secs(30);

/// The next connection to `listener`, as `TcpListener::accept` takes it;
/// panics, naming the listener, if no client connects within
/// [`CONNECT_WITHIN`].
pub fn accept(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    accept_within(listener, CONNECT_WITHIN)
}

/// As [`accept`], waiting `within`.
pub fn accept_within(listener: &TcpListener, within: Duration) -> (TcpStream, SocketAddr) {
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let mut fds = [PollFd::new(listener.borrow_socket(), Events::IN)];
        // A wait ended early, by a signal or by rounding, is waited again
        // for what is left.
        if poll(&mut fds, left).expect("polling the listener") > 0 {
            return listener.accept().expect("accepting the client");
        }
        if left.is_zero() {
            let at = listener.local_addr().expect("the listener's address");
            panic!("no client connected to {at} within {within:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::sync::mpsc;

    /// A client that never connects fails the server's accept within its
    /// bound, saying so, rather than leaving it blocked: the wait here is
    /// bounded too, so a fault that blocks fails this test as well.
    #[test]
    fn a_client_that_never_connects_fails_the_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap();
        let (told, heard) = mpsc::channel();
        std::thread::spawn(move || {
            let accepted = std::panic::catch_unwind(|| {
                accept_within(&listener, Duration::from_millis(200));
            });
            let said = accepted.err().map(|e| match e.downcast::<String>() {
                Ok(s) => *s,
                Err(_) => String::from("a panic without a message"),
            });
            told.send(said).unwrap();
        });
        let said = heard
            .recv_timeout(Duration::from_secs(10))
            .expect("the accept still waits");
        assert_eq!(
            said.as_deref(),
            Some(format!("no client connected to {at} within 200ms").as_str())
        );
    }

    /// A client that connects is accepted, its stream blocking as
    /// `TcpListener::accept` gives it.
    #[test]
    fn a_client_that_connects_is_accepted() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(at).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            c.write_all(b"hi").unwrap();
            c
        });
        let (mut s, from) = accept_within(&listener, Duration::from_secs(10));
        let mut got = [0u8; 2];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hi");
        let c = client.join().unwrap();
        assert_eq!(from, c.local_addr().unwrap());
    }
}
