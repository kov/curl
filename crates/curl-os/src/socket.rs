//! A socket, by the same names on each platform: a descriptor on Unix
//! (`BorrowedFd`, `OwnedFd`, `RawFd`), a Winsock `SOCKET` on Windows
//! (`BorrowedSocket`, `OwnedSocket`, `RawSocket`). Code above `curl-os`
//! names a socket through these, not through `std::os::fd` or
//! `std::os::windows::io`.

#[cfg(unix)]
pub use std::os::fd::{BorrowedFd as BorrowedSocket, OwnedFd as OwnedSocket, RawFd as RawSocket};
#[cfg(windows)]
pub use std::os::windows::io::{BorrowedSocket, OwnedSocket, RawSocket};

/// The number the system knows `socket` by, as a key: it names the socket
/// only while the borrow lasts.
pub fn raw(socket: BorrowedSocket<'_>) -> RawSocket {
    #[cfg(unix)]
    {
        std::os::fd::AsRawFd::as_raw_fd(&socket)
    }
    #[cfg(windows)]
    {
        std::os::windows::io::AsRawSocket::as_raw_socket(&socket)
    }
}

/// What holds a socket it can lend: a std socket, or one of this
/// crate's.
pub trait AsSocket {
    fn borrow_socket(&self) -> BorrowedSocket<'_>;
}

#[cfg(unix)]
impl<T: std::os::fd::AsFd> AsSocket for T {
    fn borrow_socket(&self) -> BorrowedSocket<'_> {
        self.as_fd()
    }
}

#[cfg(windows)]
impl<T: std::os::windows::io::AsSocket> AsSocket for T {
    fn borrow_socket(&self) -> BorrowedSocket<'_> {
        self.as_socket()
    }
}
