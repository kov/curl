//! The tool's own socket handlers: `--mptcp`'s opener
//! (`src/tool_cb_soc.c`) and the configurer that marks each socket with
//! `--ip-tos` and `--vlan-priority` (`config2setopts.c`'s
//! `sockopt_callback`).

use std::io;
use std::net::SocketAddr;

use curl_alloc::try_box;
use curl_core::conn::io::{Protocol, Socket, SocketOption};
use curl_core::handler::{Configured, SocketConfigurer, SocketOpener, SocketToSet};
use curl_core::multi::TransferCx;

use crate::msgs::Messages;

/// Opens each socket speaking Multipath TCP in place of TCP
/// (`tool_socket_open_mptcp_cb`).
pub(crate) struct Mptcp;

impl SocketOpener for Mptcp {
    fn open(
        &self,
        _: &mut TransferCx<'_>,
        address: &mut SocketAddr,
    ) -> io::Result<Box<dyn Socket>> {
        // As the opener is asked for one: neither connected nor
        // nonblocking yet.
        let socket = curl_core::conn::io::open(*address, Protocol::Mptcp, false)?;
        Ok(try_box(socket).map_err(|_| io::ErrorKind::OutOfMemory)?)
    }
}

/// Sets the type of service and the priority of each socket, warning of
/// one the system refuses; the socket connects either way.
pub(crate) struct Marking {
    /// 0 sets none.
    pub(crate) type_of_service: u8,
    /// 0 sets none.
    pub(crate) priority: u8,
    pub(crate) msgs: Messages,
}

impl SocketConfigurer for Marking {
    fn configure(&self, _: &mut TransferCx<'_>, socket: SocketToSet<'_>) -> Configured {
        let failed = |e: &io::Error, what: &[u8], value: u8| {
            let errno = e.raw_os_error().map_or(0, i32::unsigned_abs);
            let (mut v, mut n) = ([0; 10], [0; 10]);
            self.msgs.warn(&[
                what,
                decimal(u32::from(value), &mut v),
                b" failed with errno ",
                decimal(errno, &mut n),
                b": ",
                crate::os_message(e).as_bytes(),
            ]);
        };
        let tos = self.type_of_service;
        if tos > 0
            && let Err(e) = socket.set(SocketOption::TypeOfService(i32::from(tos)))
        {
            failed(&e, b"Setting type of service to ", tos);
        }
        let priority = self.priority;
        if priority > 0
            && let Err(e) = socket.set(SocketOption::Priority(i32::from(priority)))
        {
            failed(&e, b"VLAN priority ", priority);
        }
        Configured::Ok
    }
}

/// `n` in decimal, made in `buf`, as `warnf` makes its message without
/// allocating.
fn decimal(mut n: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &buf[at..];
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn numbers_are_written_in_decimal() {
        let mut buf = [0; 10];
        assert_eq!(super::decimal(0, &mut buf), b"0");
        assert_eq!(super::decimal(7, &mut buf), b"7");
        assert_eq!(super::decimal(255, &mut buf), b"255");
        assert_eq!(super::decimal(u32::MAX, &mut buf), b"4294967295");
    }
}
