use super::*;

fn oack(p: &[u8], requested: usize, uploading: bool) -> (Result<Oack, OackRefused>, Vec<String>) {
    let mut said = Vec::new();
    let got = parse_oack(p, requested, uploading, &mut |args| {
        said.push(args.to_string())
    });
    (got, said)
}

/// The block size and the file's size are read, each said; the size is
/// not taken for an upload, and other options are passed over.
#[test]
fn an_oack_is_read() {
    let (got, said) = oack(
        b"blksize\x001024\0tsize\x005000\0timeout\x006\0",
        1024,
        false,
    );
    assert_eq!(
        got,
        Ok(Oack {
            blksize: 1024,
            tsize: Some(5000)
        })
    );
    assert_eq!(
        said,
        [
            "got option=(blksize) value=(1024)",
            "blksize parsed from OACK (1024) requested (1024)",
            "got option=(tsize) value=(5000)",
            "tsize parsed from OACK (5000)",
            "got option=(timeout) value=(6)",
        ]
    );
    let (got, _) = oack(b"TSIZE\x005000\0", 512, true);
    assert_eq!(
        got,
        Ok(Oack {
            blksize: 512,
            tsize: None
        })
    );
    // A size that is no number is passed over.
    let (got, _) = oack(b"tsize\0x\0", 512, false);
    assert_eq!(got.unwrap().tsize, None);
    assert_eq!(oack(b"", 512, false).0.unwrap().blksize, BLKSIZE_DEFAULT);
    // The bounds themselves are taken.
    let (got, _) = oack(b"blksize\x0065464\0", 65464, false);
    assert_eq!(got.unwrap().blksize, 65464);
    let (got, _) = oack(b"blksize\x008\0", 512, false);
    assert_eq!(got.unwrap().blksize, 8);
}

/// An OACK cut short, or with a block size C cannot take, is refused,
/// said as C says it.
#[test]
fn a_bad_oack_is_refused() {
    for (p, want) in [
        (&b"blksize"[..], "Malformed ACK packet, rejecting"),
        (b"blksize\0", "Malformed ACK packet, rejecting"),
        (b"blksize\x001024", "Malformed ACK packet, rejecting"),
        (
            b"blksize\x0070000\0",
            "blksize is larger than max supported (65464)",
        ),
        (
            b"blksize\0x\0",
            "blksize is larger than max supported (65464)",
        ),
        (b"blksize\x000\0", "invalid blocksize value in OACK packet"),
        (
            b"blksize\x007\0",
            "blksize is smaller than min supported (8)",
        ),
        (
            b"blksize\x002048\0",
            "server requested blksize larger than allocated (2048)",
        ),
        (b"tsize\x000z\0", "invalid tsize -:z:- value in OACK packet"),
    ] {
        let (got, _) = oack(p, 1024, false);
        assert_eq!(got.unwrap_err().to_string(), want, "{p:?}");
    }
}

/// The request names the file and the mode, then the options C asks
/// for, each ended by a zero byte.
#[test]
fn the_first_packet_is_made_as_c_makes_it() {
    let mut out = Vec::new();
    first_packet(&mut out, false, b"f.txt", false, 512, None).unwrap();
    assert_eq!(out, b"\0\x01f.txt\0octet\0");
    first_packet(&mut out, true, b"f", true, 512, Some((7, 1024, 3))).unwrap();
    assert_eq!(
        out,
        b"\0\x02f\0netascii\0tsize\x007\0blksize\x001024\0timeout\x003\0"
    );
    // A name that leaves no room for the mode and four bytes.
    let long = [b'a'; 504];
    assert_eq!(
        first_packet(&mut out, false, &long, false, 512, None),
        Err(FirstRefused::NameTooLong)
    );
    let fits = [b'a'; 503];
    first_packet(&mut out, false, &fits, false, 512, None).unwrap();
    // Options past the default block's room.
    let fits = [b'a'; 473];
    first_packet(&mut out, false, &fits, false, 512, Some((0, 512, 1))).unwrap();
    assert_eq!(out.len(), 512);
    // The last, a byte past it.
    let near = [b'a'; 474];
    assert_eq!(
        first_packet(&mut out, false, &near, false, 512, Some((0, 512, 1))),
        Err(FirstRefused::OptionsTooLong)
    );
}

/// The server's codes, and the ends without answer, are C's errors.
#[test]
fn failures_are_c_s_errors() {
    for (code, kind) in [
        (0, ErrorKind::TftpIllegal),
        (1, ErrorKind::TftpNotfound),
        (2, ErrorKind::TftpPerm),
        (3, ErrorKind::RemoteDiskFull),
        (4, ErrorKind::TftpIllegal),
        (5, ErrorKind::TftpUnknownid),
        (6, ErrorKind::RemoteFileExists),
        (7, ErrorKind::TftpNosuchuser),
        (8, ErrorKind::AbortedByCallback),
    ] {
        assert_eq!(Failure::Server(code).kind(), kind, "{code}");
    }
    assert_eq!(Failure::Timeout.kind(), ErrorKind::OperationTimedout);
    assert_eq!(Failure::NoResponse.kind(), ErrorKind::CouldntConnect);
}

/// Block numbers wrap at 16 bits.
#[test]
fn blocks_wrap() {
    assert_eq!(next_block(65535), 0);
    assert_eq!(next_block(7), 8);
    assert_eq!(strnlen(b"ab\0c"), 2);
    assert_eq!(strnlen(b"abc"), 3);
}

/// The block size an application asks for is brought within TFTP's
/// bounds, 0 among them, as C's `value_range` brings it.
#[test]
fn block_sizes_are_clamped() {
    assert_eq!(TftpBlockSize::clamped(0).get(), 8);
    assert_eq!(TftpBlockSize::clamped(400).get(), 400);
    assert_eq!(TftpBlockSize::clamped(1 << 40).get(), 65464);
}

static SAMPLES: &[&[u8]] = &[
    b"blksize\x001024\0tsize\x005000\0",
    b"tsize\x000\0",
    b"timeout\x006\0blksize\x008\0",
];

proptest::proptest! {
    #![proptest_config(crate::untrusted::config(512))]

    /// Whatever an OACK holds, it is read or refused.
    #[test]
    fn any_oack_is_read_or_refused(
        p in crate::untrusted::mutated(SAMPLES),
        requested in 8usize..70000,
        uploading in proptest::bool::ANY,
    ) {
        let (got, _) = oack(&p, requested, uploading);
        if let Ok(o) = got {
            proptest::prop_assert!(o.blksize <= requested.max(BLKSIZE_DEFAULT));
            proptest::prop_assert!(o.blksize >= 8);
        }
    }
}

mod over_the_wire {
    use std::net::SocketAddr;

    use crate::conn::io::Conversation;
    use crate::error::ErrorKind;
    use crate::options::{Method, Options, TftpBlockSize, UploadSource};
    use crate::proto::raw::wire::{PORT, Ran, against};

    /// A bind's `EINVAL`, on Windows in Winsock's words from C's table.
    #[cfg(unix)]
    const INVALID: &str = "bind() failed; Invalid argument\n";
    #[cfg(windows)]
    const INVALID: &str = "bind() failed; Invalid arguments\n";

    const RRQ: &[u8] = b"\0\x01f\0octet\0tsize\x000\0blksize\x00512\0timeout\x003\0";

    fn data(block: u16, bytes: &[u8]) -> Vec<u8> {
        [&[0, 3][..], &block.to_be_bytes(), bytes].concat()
    }

    fn ack(block: u16) -> Vec<u8> {
        [&[0, 4][..], &block.to_be_bytes()].concat()
    }

    fn fetch(replies: &[&[u8]], set: impl FnOnce(&mut Options)) -> (Vec<u8>, Ran) {
        let talk = Conversation::replies(replies, false).per_send();
        against(talk, "tftp://127.0.0.1:PORT/f", set)
    }

    fn upload(replies: &[&[u8]], body: &[u8]) -> (Vec<u8>, Ran) {
        let talk = Conversation::replies(replies, false).per_send();
        against(talk, "tftp://127.0.0.1:PORT/f", |o| {
            o.method = Method::Upload;
            o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(body.to_vec()).unwrap());
        })
    }

    /// A download asks for the file with C's options, and acknowledges
    /// each block, the short one last.
    #[test]
    fn a_download_is_acknowledged_block_by_block() {
        let full = [b'a'; 512];
        let (said, ran) = fetch(&[&data(1, &full), &data(2, b"end")], |_| {});
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert_eq!(ran.body, [&full[..], b"end"].concat());
        assert_eq!(said, [RRQ, &ack(1), &ack(2)].concat());
        assert!(ran.text.contains("Connected for receive\n"), "{}", ran.text);
        assert!(
            ran.text
                .contains("set timeouts for state 0; Total 10000, retry 3 maxtry 3\n"),
            "{}",
            ran.text
        );
    }

    /// A block sent again is acknowledged and not delivered twice.
    #[test]
    fn a_block_sent_again_is_not_delivered_again() {
        let full = [b'b'; 512];
        let (said, ran) = fetch(&[&data(1, &full), &data(1, &full), &data(2, b"")], |_| {});
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert_eq!(ran.body, full);
        assert_eq!(said, [RRQ, &ack(1), &ack(1), &ack(2)].concat());
        assert!(
            ran.text
                .contains("Received last DATA packet block 1 again.\n"),
            "{}",
            ran.text
        );
    }

    /// The server's OACK sets the block size and the file's size, and is
    /// acknowledged as block 0; without options none is asked for.
    #[test]
    fn an_oack_is_acknowledged_and_taken() {
        let oack = b"\0\x06blksize\x00600\0tsize\x003\0";
        let (said, ran) = fetch(&[oack, &data(1, b"abc")], |o| {
            o.small.make_mut().unwrap().tftp_blksize = Some(TftpBlockSize::clamped(600));
        });
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert_eq!(ran.body, b"abc");
        let rrq = b"\0\x01f\0octet\0tsize\x000\0blksize\x00600\0timeout\x003\0";
        assert_eq!(said, [&rrq[..], &ack(0), &ack(1)].concat());
        assert!(
            ran.text
                .contains("blksize parsed from OACK (600) requested (600)\n"),
            "{}",
            ran.text
        );
        let (said, ran) = fetch(&[&data(1, b"x")], |o| {
            o.small.make_mut().unwrap().tftp_no_options = true;
        });
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert_eq!(said, [&b"\0\x01f\0octet\0"[..], &ack(1)].concat());
    }

    /// A block shorter than the size agreed ends the download: one of
    /// 512 bytes, of a transfer agreed at 600.
    #[test]
    fn a_short_block_ends_the_download() {
        let oack = b"\0\x06blksize\x00600\0";
        let (_, ran) = fetch(&[oack, &data(1, &[b'c'; 512])], |o| {
            o.small.make_mut().unwrap().tftp_blksize = Some(TftpBlockSize::clamped(600));
        });
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert_eq!(ran.body.len(), 512);
    }

    /// The server's error is C's error for its code, its text traced if
    /// it is ended.
    #[test]
    fn an_error_packet_fails_with_its_code() {
        let (_, ran) = fetch(&[b"\0\x05\0\x01File not found\0"], |_| {});
        assert_eq!(
            ran.result,
            Some(Err(ErrorKind::TftpNotfound)),
            "{}",
            ran.text
        );
        assert!(
            ran.text.contains("TFTP error: File not found\n"),
            "{}",
            ran.text
        );
        let (_, ran) = fetch(&[b"\0\x05\0\x03full"], |_| {});
        assert_eq!(ran.result, Some(Err(ErrorKind::RemoteDiskFull)));
        assert!(!ran.text.contains("TFTP error"), "{}", ran.text);
    }

    /// Once the server answered, a datagram from elsewhere fails the
    /// transfer.
    #[test]
    fn a_datagram_from_another_address_fails() {
        let other = SocketAddr::from(([127, 0, 0, 2], PORT));
        let full = [b'a'; 512];
        let talk = Conversation::replies(&[&data(1, &full), &data(2, b"")], false)
            .per_send()
            .datagrams_from(1, other);
        let (_, ran) = against(talk, "tftp://127.0.0.1:PORT/f", |_| {});
        assert_eq!(ran.result, Some(Err(ErrorKind::RecvError)), "{}", ran.text);
        assert!(
            ran.text.contains("Data received from another address"),
            "{}",
            ran.text
        );
        assert_eq!(ran.body, full);
    }

    /// A datagram too short for its head is taken as a time-out, the
    /// request sent again.
    #[test]
    fn a_short_datagram_is_taken_as_a_time_out() {
        let (said, ran) = fetch(&[b"\0\x03", &data(1, b"z")], |_| {});
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert_eq!(ran.body, b"z");
        assert_eq!(said, [RRQ, RRQ, &ack(1)].concat());
        assert!(
            ran.text.contains("Received too short packet"),
            "{}",
            ran.text
        );
    }

    /// No answer at all: the request is sent again on each time-out
    /// until the retries, set while the connect timeout ruled, run out.
    #[test]
    fn a_silent_server_fails_to_connect() {
        let (said, ran) = fetch(&[], |o| {
            o.limits.total = crate::time::TimeLimit::from_millis(0);
        });
        assert_eq!(
            ran.result,
            Some(Err(ErrorKind::CouldntConnect)),
            "{}",
            ran.text
        );
        assert!(
            ran.text
                .contains("set timeouts for state 0; Total 300000, retry 6 maxtry 50\n"),
            "{}",
            ran.text
        );
        let rrq = b"\0\x01f\0octet\0tsize\x000\0blksize\x00512\0timeout\x006\0";
        assert_eq!(said, rrq.repeat(50));
        // Bounded by the transfer's time instead.
        let (said, ran) = fetch(&[], |_| {});
        assert_eq!(ran.result, Some(Err(ErrorKind::OperationTimedout)));
        assert_eq!(said, RRQ.repeat(3));
    }

    /// An upload sends its blocks, each when the last is acknowledged,
    /// counted once.
    #[test]
    fn an_upload_sends_block_after_block() {
        let body = [b'u'; 600];
        let (said, ran) = upload(&[&ack(0), &ack(1), &ack(2)], &body);
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        let wrq = b"\0\x02f\0octet\0tsize\x00600\0blksize\x00512\0timeout\x003\0";
        let blocks = [&wrq[..], &data(1, &body[..512]), &data(2, &body[512..])].concat();
        assert_eq!(said, blocks);
        assert_eq!(ran.counted.1, 600);
        assert!(
            ran.text.contains("Connected for transmit\n"),
            "{}",
            ran.text
        );
    }

    /// An acknowledgement of another block sends the last block again.
    #[test]
    fn a_wrong_acknowledgement_sends_the_block_again() {
        let body = [b'v'; 5];
        let (said, ran) = upload(&[&ack(0), &ack(7), &ack(1)], &body);
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        let block = data(1, &body);
        assert!(said.ends_with(&[&block[..], &block].concat()), "{said:?}");
        assert!(
            ran.text.contains("Received ACK for block 7, expecting 1\n"),
            "{}",
            ran.text
        );
    }

    /// What a transfer through an HTTP proxy asked of it, the proxy giving
    /// `answer`.
    fn through_proxy(answer: &[u8]) -> (Vec<u8>, Ran) {
        fetch(&[answer], |o| {
            o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        })
    }

    /// Asked for a tunnel of datagrams, a proxy refusing it fails the
    /// transfer with what C says.
    #[test]
    fn a_proxy_is_asked_for_a_connect_udp_tunnel() {
        let (said, ran) = through_proxy(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            ran.result,
            Some(Err(ErrorKind::CouldntConnect)),
            "{}",
            ran.text
        );
        let head = String::from_utf8_lossy(&said);
        assert!(head.starts_with("GET http://"), "{head}");
        assert!(
            head.contains("/.well-known/masque/udp/127.0.0.1/"),
            "{head}"
        );
        assert!(head.contains("\r\nUpgrade: connect-udp\r\n"), "{head}");
        assert!(
            ran.text
                .contains("CONNECT-UDP tunnel failed, response 404\n"),
            "{}",
            ran.text
        );
    }

    /// A tunnel granted leaves the socket connected to the proxy, which
    /// the transfer's bind fails on, before anything of TFTP is sent.
    #[test]
    fn a_tunnel_granted_fails_to_bind() {
        let (said, ran) =
            through_proxy(b"HTTP/1.1 101 Switching Protocols\r\nCapsule-Protocol: ?1\r\n\r\n");
        assert_eq!(
            ran.result,
            Some(Err(ErrorKind::CouldntConnect)),
            "{}",
            ran.text
        );
        assert!(ran.text.contains(INVALID), "{}", ran.text);
        let head = String::from_utf8_lossy(&said);
        assert!(head.ends_with("\r\n\r\n"), "nothing after the head: {head}");
    }

    /// What a transfer asked of a proxy granting its tunnel, the network
    /// and the socket's local end as said.
    fn tunnel_bound(
        net: impl FnOnce(crate::conn::io::FakeNet) -> crate::conn::io::FakeNet,
        bind: crate::options::LocalBind,
    ) -> (Vec<u8>, Ran) {
        use crate::conn::io::{FakeNet, Peer};
        use crate::id::ArenaPolicy;
        use crate::multi::{Env, Multi};
        use crate::time::ManualClock;
        let clock = ManualClock::new().unwrap();
        let at = SocketAddr::from(([127, 0, 0, 1], PORT));
        let granted = b"HTTP/1.1 101 Switching Protocols\r\nCapsule-Protocol: ?1\r\n\r\n";
        let talk = Conversation::replies(&[granted], false).per_send();
        let fake = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk.clone());
        let env = Env {
            clock: Box::new(clock),
            net: Box::new(net(fake)),
            arena: ArenaPolicy::new(16, 0).unwrap(),
            waker: None,
        };
        let mut m: Multi = Multi::with_env(env).unwrap();
        let url = format!("tftp://127.0.0.1:{PORT}/f");
        let ran = crate::proto::raw::wire::transfer(&mut m, &url, |o| {
            o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
            o.sockets.make_mut().unwrap().local = bind;
        });
        drop(m);
        (talk.received(), ran)
    }

    /// An interface bound by its name is not a socket bound
    /// (`bits.bound`): the transfer's own bind goes on, and fails. A bind
    /// by name is Linux's (`SO_BINDTODEVICE`): elsewhere the name is
    /// taken for a host, resolved, and the bind fails as C's does on
    /// macOS (`curl --interface eth9` exits 45 there).
    #[cfg(unix)]
    #[test]
    fn an_interface_named_does_not_spare_the_bind() {
        use crate::options::{Interface, LocalBind};
        let bind = LocalBind {
            interface: Interface::parse(b"eth9").unwrap(),
            ..LocalBind::NONE
        };
        let (_, ran) = tunnel_bound(|n| n.with_device("eth9"), bind);
        let want = if cfg!(target_os = "linux") {
            ErrorKind::CouldntConnect
        } else {
            ErrorKind::InterfaceFailed
        };
        assert_eq!(ran.result, Some(Err(want)), "{}", ran.text);
        if cfg!(target_os = "linux") {
            assert!(ran.text.contains(INVALID), "{}", ran.text);
        } else {
            assert!(
                ran.text.contains("Could not bind to 'eth9' with errno "),
                "{}",
                ran.text
            );
        }
    }

    /// A socket its connect bound to a port is spared the transfer's bind,
    /// and its request fails to send; C sends it on the socket connected
    /// to the proxy (DIVERGENCE.md).
    #[test]
    fn a_socket_bound_to_a_port_fails_to_send_through_a_tunnel() {
        let bind = crate::options::LocalBind {
            port: 41000,
            ..crate::options::LocalBind::NONE
        };
        let (said, ran) = tunnel_bound(|n| n, bind);
        assert_eq!(ran.result, Some(Err(ErrorKind::SendError)), "{}", ran.text);
        let head = String::from_utf8_lossy(&said);
        assert!(head.ends_with("\r\n\r\n"), "nothing after the head: {head}");
    }

    /// Through a SOCKS proxy the handshake goes over TCP, and the proxy
    /// refusing it fails it; C opens a UDP socket to the proxy and fails to send
    /// on it, with the same code (DIVERGENCE.md).
    #[test]
    fn a_socks_proxy_is_spoken_to_over_tcp() {
        let (said, ran) = fetch(&[b"\x05\xff"], |o| {
            o.proxy.make_mut().unwrap().url =
                Some(format!("socks5://127.0.0.1:{PORT}").into_bytes());
        });
        assert_eq!(ran.result, Some(Err(ErrorKind::Proxy)), "{}", ran.text);
        assert_eq!(said[0], 5, "the SOCKS5 greeting: {said:?}");
    }

    /// What the paused writer took, and whether it paused yet.
    #[derive(Clone, Default)]
    struct PausesFirst {
        took: std::sync::Arc<curl_alloc::Lock<Vec<u8>>>,
        paused: std::sync::Arc<crate::test_cell::Cell<bool>>,
    }

    impl crate::handler::WriteHandler for PausesFirst {
        fn write(
            &self,
            _: &mut crate::multi::TransferCx<'_>,
            body: &[u8],
        ) -> crate::handler::Write {
            if !self.paused.replace(true) {
                return crate::handler::Write::Pause;
            }
            self.took.lock().unwrap().extend_from_slice(body);
            crate::handler::Write::Took(body.len())
        }
    }

    /// A TFTP transfer, unlimited in time, on `m`.
    fn added(
        m: &mut crate::multi::Multi,
        set: impl FnOnce(&mut Options),
    ) -> crate::multi::TransferId {
        use crate::libraries::{Libraries, SharedLibraries};
        let mut e = crate::easy::Easy::new();
        e.set_libraries(SharedLibraries::new(Libraries::NONE).unwrap());
        let o = e.options_mut();
        o.set_url(Some(format!("tftp://127.0.0.1:{PORT}/f").as_bytes()))
            .unwrap();
        o.limits.total = crate::time::TimeLimit::from_millis(0);
        set(o);
        m.add(Box::new(e), (), &mut crate::multi::NoEvents).unwrap()
    }

    /// Output a paused writer holds keeps the transfer from ending, the
    /// exchange over or not, until it is taken.
    #[test]
    fn a_paused_block_is_held_until_taken() {
        use crate::deliver::PauseRequest;
        use crate::multi::{NoEvents, drive_to_completion};
        let talk = Conversation::replies(&[&data(1, b"abc")], false).per_send();
        let mut m = crate::proto::raw::wire::serving(&[&talk]);
        let writer = PausesFirst::default();
        let w = writer.clone();
        let id = added(&mut m, |o| {
            o.callbacks.write = Some(crate::handler::Handler::write(w).unwrap());
        });
        for _ in 0..10 {
            m.perform(&mut NoEvents).unwrap();
        }
        assert_eq!(
            talk.received(),
            [RRQ6, &ack(1)].concat(),
            "the exchange is over"
        );
        assert!(m.info_read().is_none(), "not over while output is held");
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(*writer.took.lock().unwrap(), b"abc");
    }

    /// Waiting for an answer, the transfer asks to be run again a second
    /// after it last looked, for a time-out the socket cannot tell.
    #[test]
    fn an_answer_is_waited_for_a_second_at_a_time() {
        use crate::multi::NoEvents;
        let talk = Conversation::replies(&[], false).per_send();
        let mut m = crate::proto::raw::wire::serving(&[&talk]);
        added(&mut m, |_| {});
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(talk.received(), RRQ6);
        assert_eq!(m.timeout(), Some(std::time::Duration::from_secs(1)));
    }

    /// The retries are set from the time left: within an hour, a fifth
    /// of its seconds, each of what is left of them; an hour or more is
    /// taken as fifteen seconds.
    #[test]
    fn the_retries_follow_the_time_left() {
        for (ms, said) in [
            (3_599_000, "Total 3599000, retry 71 maxtry 50"),
            (3_600_000, "Total 3600000, retry 5 maxtry 3"),
            (14_000, "Total 14000, retry 4 maxtry 3"),
            (499, "Total 499, retry 1 maxtry 3"),
        ] {
            let (_, ran) = fetch(&[&data(1, b"")], |o| {
                o.limits.total = crate::time::TimeLimit::from_millis(ms);
                o.limits.connect = crate::time::TimeLimit::from_millis(ms);
            });
            assert!(
                ran.text
                    .contains(&format!("set timeouts for state 0; {said}\n")),
                "{ms}: {}",
                ran.text
            );
        }
    }

    const RRQ6: &[u8] = b"\0\x01f\0octet\0tsize\x000\0blksize\x00512\0timeout\x006\0";

    /// Silent after a block, the server is sent the block's ACK again on
    /// each time-out until the retries run out, a time-out the error.
    #[test]
    fn a_silence_after_a_block_times_out() {
        let full = [b'a'; 512];
        let (said, ran) = fetch(&[&data(1, &full)], |o| {
            o.limits.total = crate::time::TimeLimit::from_millis(0);
        });
        assert_eq!(
            ran.result,
            Some(Err(ErrorKind::OperationTimedout)),
            "{}",
            ran.text
        );
        assert_eq!(said, [RRQ6, &ack(1), &ack(1), &ack(1), &ack(1)].concat());
        assert!(
            ran.text
                .contains("set timeouts for state 1; Total 0, retry 5 maxtry 3\n"),
            "{}",
            ran.text
        );
        assert!(
            ran.text
                .contains("Timeout waiting for block 2 ACK. Retries = 4\n"),
            "{}",
            ran.text
        );
        assert!(!ran.text.contains("TFTP response timeout"), "{}", ran.text);
    }

    /// A block the writer refuses fails the transfer; past the first,
    /// the server is told so, with the block it last had acknowledged,
    /// as C tells it (none is told of the first, its state not yet RX).
    #[test]
    fn a_refused_block_tells_the_server() {
        struct RefusesSecond(crate::test_cell::Cell<bool>);
        impl crate::handler::WriteHandler for RefusesSecond {
            fn write(
                &self,
                _: &mut crate::multi::TransferCx<'_>,
                body: &[u8],
            ) -> crate::handler::Write {
                if self.0.replace(true) {
                    return crate::handler::Write::Fail;
                }
                crate::handler::Write::Took(body.len())
            }
        }
        let full = [b'a'; 512];
        let refuses = RefusesSecond(crate::test_cell::Cell::new(false));
        let (said, ran) = fetch(&[&data(1, &full), &data(2, b"abc")], |o| {
            o.callbacks.write = Some(crate::handler::Handler::write(refuses).unwrap());
        });
        assert_eq!(ran.result, Some(Err(ErrorKind::WriteError)), "{}", ran.text);
        assert_eq!(said, [RRQ, &ack(1), b"\0\x05\0\x01"].concat());
    }

    /// A block shorter than 512 bytes by any amount is the last; a
    /// datagram longer than a block is cut to one, as C reads it.
    #[test]
    fn blocks_are_read_at_most_a_block_long() {
        let (said, ran) = fetch(&[&data(1, &[b'a'; 510])], |_| {});
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert_eq!(said, [RRQ, &ack(1)].concat());
        let (_, ran) = fetch(&[&data(1, &[b'b'; 600]), &data(2, b"")], |_| {});
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert_eq!(ran.body, [b'b'; 512]);
    }

    /// An empty last block delivers nothing, not even an empty piece.
    #[test]
    fn an_empty_block_is_not_written() {
        #[derive(Clone, Default)]
        struct Pieces(std::sync::Arc<curl_alloc::Lock<Vec<usize>>>);
        impl crate::handler::WriteHandler for Pieces {
            fn write(
                &self,
                _: &mut crate::multi::TransferCx<'_>,
                body: &[u8],
            ) -> crate::handler::Write {
                self.0.lock().unwrap().push(body.len());
                crate::handler::Write::Took(body.len())
            }
        }
        let pieces = Pieces::default();
        let p = pieces.clone();
        let (_, ran) = fetch(&[&data(1, &[b'c'; 512]), &data(2, b"")], |o| {
            o.callbacks.write = Some(crate::handler::Handler::write(p).unwrap());
        });
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert_eq!(*pieces.0.lock().unwrap(), [512]);
    }

    /// A first ACK for another block, or one for 65535 past block 0,
    /// is answered with what was sent last; only 65535 at block 0 is
    /// taken, as tftpd-hpa sends it when the count wraps.
    #[test]
    fn a_first_ack_must_be_for_block_0() {
        let (said, ran) = upload(&[&ack(5), &ack(0), &ack(1)], b"xy");
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert!(
            ran.text.contains("Received ACK for block 5, expecting 0\n"),
            "{}",
            ran.text
        );
        assert!(said.ends_with(&data(1, b"xy")), "{said:?}");
        let (_, ran) = upload(&[&ack(0), &ack(65535), &ack(1)], b"xy");
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        assert!(
            ran.text
                .contains("Received ACK for block 65535, expecting 1\n"),
            "{}",
            ran.text
        );
        assert!(!ran.text.contains("Unexpected packet"), "{}", ran.text);
    }

    /// Wrong ACKs past the retries give the upload up.
    #[test]
    fn wrong_acks_give_up_the_upload() {
        let (said, ran) = upload(&[&ack(0), &ack(7), &ack(7), &ack(7), &ack(7)], b"z");
        assert_eq!(ran.result, Some(Err(ErrorKind::SendError)), "{}", ran.text);
        assert!(
            ran.text
                .contains("tftp_tx: giving up waiting for block 1 ack\n"),
            "{}",
            ran.text
        );
        let block = data(1, b"z");
        assert!(said.ends_with(&block.repeat(4)), "{said:?}");
    }

    /// Silent after a block, the server is sent it again on each time-out,
    /// counted once, until the retries run out.
    #[test]
    fn a_silence_during_an_upload_times_out() {
        let talk = Conversation::replies(&[&ack(0)], false).per_send();
        let body = b"hello";
        let (said, ran) = against(talk, "tftp://127.0.0.1:PORT/f", |o| {
            o.method = Method::Upload;
            o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(body.to_vec()).unwrap());
            o.limits.total = crate::time::TimeLimit::from_millis(0);
        });
        assert_eq!(
            ran.result,
            Some(Err(ErrorKind::OperationTimedout)),
            "{}",
            ran.text
        );
        let block = data(1, body);
        assert!(said.ends_with(&block.repeat(4)), "{said:?}");
        assert!(!said.ends_with(&block.repeat(5)), "{said:?}");
        assert_eq!(ran.counted.1, 5);
    }

    /// A block is filled from as many reads as the upload takes to give
    /// it.
    #[test]
    fn a_block_is_filled_from_many_reads() {
        struct Trickle(curl_alloc::Lock<usize>);
        impl crate::handler::ReadHandler for Trickle {
            fn read(
                &self,
                _: &mut crate::multi::TransferCx<'_>,
                buf: &mut [u8],
            ) -> crate::handler::Read {
                let mut left = self.0.lock().unwrap();
                let n = (*left).min(100).min(buf.len());
                if n == 0 {
                    return crate::handler::Read::Eof;
                }
                *left -= n;
                buf[..n].fill(b'r');
                crate::handler::Read::Data(std::num::NonZeroUsize::new(n).unwrap())
            }
        }
        let talk = Conversation::replies(&[&ack(0), &ack(1), &ack(2)], false).per_send();
        let (said, ran) = against(talk, "tftp://127.0.0.1:PORT/f", |o| {
            o.method = Method::Upload;
            o.upload = UploadSource::Read {
                handler: crate::handler::Handler::read(Trickle(curl_alloc::Lock::new(600)))
                    .unwrap(),
                rewind: None,
                size: Some(600),
            };
        });
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        let blocks = [&data(1, &[b'r'; 512])[..], &data(2, &[b'r'; 88])].concat();
        assert!(said.ends_with(&blocks), "{said:?}");
    }

    /// While an answer is awaited, the transfer waits for its socket to
    /// be readable.
    #[test]
    fn an_answer_is_waited_for_on_the_socket() {
        use crate::multi::NoEvents;
        let talk = Conversation::replies(&[], false).per_send();
        let mut m = crate::proto::raw::wire::serving(&[&talk]);
        added(&mut m, |_| {});
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(
            crate::proto::raw::wire::waits(&mut m),
            [crate::conn::io::Events::IN]
        );
    }
}
