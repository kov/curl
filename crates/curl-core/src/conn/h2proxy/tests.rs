use super::*;

/// The proxy's answer is held to C's limit exactly (`Curl_dynhds_add`
/// under `Curl_http_resp_make`): a mebibyte of names and values over all
/// its fields, and no limit on their count; a field that fills what is
/// left is kept, one byte more is not.
#[test]
fn a_proxy_s_answer_is_held_to_c_s_limit_at_its_edges() {
    let max = Answer::MAX_BYTES;
    let mut a = Answer::new(200);
    assert_eq!(a.add(b"a", &vec![b'x'; max / 2 - 1]), Ok(()));
    let left = max - max / 2;
    assert_eq!(a.add(b"b", &vec![b'x'; left]), Err(OutOfMemory));
    assert_eq!(a.add(b"b", &vec![b'x'; left - 1]), Ok(()));
    assert_eq!(a.add(b"c", b""), Err(OutOfMemory));

    // A name alone filling the room is kept; one longer than it is not.
    let mut a = Answer::new(200);
    assert_eq!(a.add(&vec![b'n'; max + 1], b""), Err(OutOfMemory));
    assert_eq!(a.add(&vec![b'n'; max], b""), Ok(()));

    let mut a = Answer::new(200);
    for _ in 0..10_000 {
        assert_eq!(a.add(b"a", b"b"), Ok(()));
    }
}

/// The tunnel's stream closed with an error is one the proxy reset, as
/// C's `proxy_h2_on_stream_close` takes it, even with no RST_STREAM
/// before, as when a GOAWAY refuses it; closed with none, it is not.
#[test]
fn a_tunnel_closed_with_an_error_was_reset() {
    for (error, reset) in [(H2Error::REFUSED_STREAM, true), (H2Error::NO_ERROR, false)] {
        let mut t = Tunnel::new();
        t.stream = Some(StreamId(1));
        let closed = Event::Closed {
            stream: StreamId(1),
            error,
        };
        assert_eq!(t.heard(&closed), Ok(Heard::Fine));
        assert_eq!((t.closed, t.error, t.reset), (true, error, reset));
    }
}

/// The tunnel's DATA as a proxy sends it: `len` bytes counting on from
/// `from`, so bytes out of place show.
fn counting(from: usize, len: usize) -> Vec<u8> {
    (from..from + len).map(|i| (i % 251) as u8).collect()
}

/// What the tunnel holds is stored in about as much again, however long
/// the download: a read that leaves some of a DATA held while the next
/// comes lets go of what it read, as C's buffer frees each chunk read
/// (`recvbuf`). Each DATA here comes with half the one before still held,
/// so what is held never runs dry for the buffer to start over at.
#[test]
fn what_the_tunnel_read_is_let_go_of_while_more_comes() {
    const DATA: usize = 16 * 1024;
    let mut t = Tunnel::new();
    t.stream = Some(StreamId(1));
    let (mut came, mut taken) = (0, 0);
    let mut buf = vec![0; DATA];
    for round in 0..100 {
        let bytes = counting(came, DATA);
        came += DATA;
        let data = Event::Data {
            stream: StreamId(1),
            bytes: &bytes,
        };
        assert_eq!(t.heard(&data), Ok(Heard::Fine));
        let want = if round == 0 { DATA / 2 } else { DATA };
        assert_eq!(t.take(&mut buf[..want]), want);
        assert_eq!(buf[..want], counting(taken, want), "round {round}");
        taken += want;
        assert_eq!(t.held().len(), DATA / 2);
        let held_most = DATA + DATA / 2;
        assert!(
            t.stored() <= 4 * (held_most + DATA),
            "round {round}: {} stored for {} held",
            t.stored(),
            t.held().len()
        );
    }
}

/// The layer under the tunnel: alive, with nothing to read or send.
#[derive(Debug)]
struct Under;

impl Part<Below<'_>> for Under {
    fn is_alive(&mut self, _: &mut dyn LayerCx, _: Below<'_>) -> Alive {
        Alive::Alive {
            input_pending: false,
        }
    }
}

impl Layer for Under {
    fn recv(&mut self, _: &mut dyn LayerCx, _: Below<'_>, _: &mut [u8]) -> io::Result<Recv> {
        Ok(Recv::WouldBlock)
    }

    fn send(&mut self, _: &mut dyn LayerCx, _: Below<'_>, _: &[u8]) -> io::Result<Sent> {
        Ok(Sent::WouldBlock)
    }
}

/// A layer under the tunnel whose connection never runs dry: each read
/// is a whole chunk, one PING frame of the fake library's, until `most`
/// have been read.
#[derive(Debug)]
struct Flood {
    reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    most: usize,
}

impl Part<Below<'_>> for Flood {}

impl Layer for Flood {
    fn recv(&mut self, _: &mut dyn LayerCx, _: Below<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        let reads = 1 + self
            .reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if reads > self.most {
            return Ok(Recv::WouldBlock);
        }
        let (line, end) = buf.split_at_mut(buf.len() - 1);
        line.fill(b' ');
        line[0] = b'P';
        end[0] = b'\n';
        Ok(Recv::Data(std::num::NonZeroUsize::new(buf.len()).unwrap()))
    }

    fn send(&mut self, _: &mut dyn LayerCx, _: Below<'_>, _: &[u8]) -> io::Result<Sent> {
        Ok(Sent::WouldBlock)
    }
}

/// A proxy whose frames come as fast as they are read gives the others
/// their turn: one read of the connection takes in 16 KiB before the
/// tunnel is established, the tunnel's window after, and its transfer is
/// marked to run again (`proxy_h2_progress_ingress`).
#[test]
fn a_proxy_s_flood_of_frames_gives_the_others_their_turn() {
    use crate::conn::quic::tests::Scripted;
    for (state, reads) in [
        (TunnelState::Connect, 1),
        (TunnelState::Established, TUNNEL_WINDOW as usize / CHUNK),
    ] {
        let mut p = H2Proxy::open(&crate::http2::fake::FakeH2, 100).unwrap();
        p.tunnel.state = state;
        let socket = Scripted::default();
        let reads_made = std::sync::Arc::default();
        let flood = Flood {
            reads: std::sync::Arc::clone(&reads_made),
            most: 1000,
        };
        let mut layers: [Box<dyn Layer>; 1] = [Box::new(flood)];
        let mut asked = crate::conn::h3proxy::tests::Asked::new(false);
        assert_eq!(
            p.ingress(&mut asked, Below::new(&mut layers, &socket)),
            Ok(())
        );
        let made = reads_made.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(made, reads, "{state:?}");
        let marked = asked.calls.iter().filter(|c| *c == "mark_dirty").count();
        assert_eq!(marked, 1, "{state:?}");
    }
}

/// A tunnel whose session a fatal failure ended is dead, whatever is
/// below, and shuts down at once, saying no goodbye it could not send
/// (`Curl_ngh2_valid` in `cf_h2_proxy_is_alive` and
/// `cf_h2_proxy_shutdown`); before, it is alive, and says GOAWAY.
#[test]
fn a_tunnel_whose_session_ended_is_dead_and_says_no_goodbye() {
    use crate::conn::quic::tests::Scripted;
    use crate::tls::Notes;
    for ended in [false, true] {
        let mut p = H2Proxy::open(&crate::http2::fake::FakeH2, 100).unwrap();
        p.tunnel.state = TunnelState::Established;
        if ended {
            // A frame its reader fails ends the session, as nghttp2's
            // callback failure does.
            let read = p.session.recv(b"S\n", &mut |_| Heard::Failed);
            assert!(read.is_err_and(|e| e.fatal), "{read:?}");
        }
        let socket = Scripted::default();
        let mut layers: [Box<dyn Layer>; 1] = [Box::new(Under)];
        let mut notes = Notes::default();
        let alive = p.is_alive(&mut notes, Below::new(&mut layers, &socket));
        let expected = if ended {
            Alive::Dead
        } else {
            Alive::Alive {
                input_pending: false,
            }
        };
        assert_eq!(alive, expected, "ended {ended}");
        let shut = p.shutdown(&mut notes, Below::new(&mut layers, &socket));
        if ended {
            assert_eq!(shut, Ok(Handshake::Done));
            assert!(!p.sent_goaway);
        } else {
            assert!(shut.is_ok(), "{shut:?}");
            assert!(p.sent_goaway);
        }
    }
}
