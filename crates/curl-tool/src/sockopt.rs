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
    use std::net::SocketAddr;

    use curl_core::conn::io::{Conversation, FakeNet, Peer, SocketOption as O};
    use curl_core::easy::Easy;
    use curl_core::handler::Handler;
    use curl_core::id::ArenaPolicy;
    use curl_core::multi::{Env, Multi, NoEvents};
    use curl_core::time::ManualClock;

    use super::Marking;
    use crate::easysrc::{Pointer, Setopt};
    use crate::msgs::Messages;

    /// Each socket is marked only with what is asked, after the
    /// library's own option; 0 asks for nothing (`sockopt_callback`'s
    /// `> 0`).
    #[test]
    fn a_socket_is_marked_as_asked() {
        let at = SocketAddr::from(([127, 0, 0, 1], 3));
        for (tos, priority, want) in [
            (0, 0, &[O::NoDelay][..]),
            (32, 0, &[O::NoDelay, O::TypeOfService(32)]),
            (0, 7, &[O::NoDelay, O::Priority(7)]),
            (1, 1, &[O::NoDelay, O::TypeOfService(1), O::Priority(1)]),
        ] {
            let clock = ManualClock::new().unwrap();
            let talk = Conversation::new(b"", false);
            let net = FakeNet::new(clock.clone())
                .with_peer(at, Peer::Silent)
                .with_conversation(at, talk.clone());
            let env = Env {
                clock: Box::new(clock),
                net: Box::new(net),
                arena: ArenaPolicy::new(16, 0).unwrap(),
                waker: None,
            };
            let mut m: Multi = Multi::new(env).unwrap();
            let mut easy = Easy::new();
            let mut s = Setopt::new(&mut easy, None);
            let url = b"tcp://127.0.0.1:3/";
            s.str("CURLOPT_URL", Some(url), |o| {
                o.set_url(Some(url)).unwrap();
                Ok(())
            })
            .unwrap();
            let marking = Marking {
                type_of_service: tos,
                priority,
                msgs: Messages::new(),
            };
            s.ptr("CURLOPT_SOCKOPTFUNCTION", Pointer::Function, |o| {
                o.sockets.make_mut().unwrap().configure =
                    Some(Handler::socket_configurer(marking).unwrap());
                Ok(())
            })
            .unwrap();
            m.add(Box::new(easy), (), &mut NoEvents).unwrap();
            m.perform(&mut NoEvents).unwrap();
            assert_eq!(
                talk.options(),
                want,
                "type of service {tos}, priority {priority}"
            );
        }
    }

    #[test]
    fn numbers_are_written_in_decimal() {
        let mut buf = [0; 10];
        assert_eq!(super::decimal(0, &mut buf), b"0");
        assert_eq!(super::decimal(7, &mut buf), b"7");
        assert_eq!(super::decimal(255, &mut buf), b"255");
        assert_eq!(super::decimal(u32::MAX, &mut buf), b"4294967295");
    }
}
