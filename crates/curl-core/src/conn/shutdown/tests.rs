use super::*;

/// The set holds what C's caps allow: the total limit less the multi's
/// own pool, 1 once none is left, and with no limit a quarter of the
/// pool, at least 128 (`cpool_discard_conn`).
#[test]
fn the_set_is_capped_as_c_caps_it() {
    let max = |n| NonZeroU32::new(n);
    assert_eq!(max_shutdowns(max(10), 3), 7);
    assert_eq!(max_shutdowns(max(10), 10), 1);
    assert_eq!(max_shutdowns(max(10), 12), 1);
    assert_eq!(max_shutdowns(None, 0), 128);
    assert_eq!(max_shutdowns(None, 600), 150);
}

/// Logs each shutdown asked of it, waiting the first time.
#[derive(Debug)]
struct Logged {
    name: &'static str,
    waited: bool,
    log: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
}

impl crate::conn::layer::Layer for Logged {
    fn recv(
        &mut self,
        cx: &mut dyn crate::conn::layer::LayerCx,
        below: crate::conn::layer::Below<'_>,
        buf: &mut [u8],
    ) -> std::io::Result<crate::conn::io::Recv> {
        below.recv(cx, buf)
    }

    fn send(
        &mut self,
        cx: &mut dyn crate::conn::layer::LayerCx,
        below: crate::conn::layer::Below<'_>,
        bytes: &[u8],
    ) -> std::io::Result<crate::conn::io::Sent> {
        below.send(cx, bytes)
    }

    fn shutdown(
        &mut self,
        _: &mut dyn crate::conn::layer::LayerCx,
        _: crate::conn::layer::Below<'_>,
    ) -> Result<Handshake, crate::error::ErrorKind> {
        self.log.lock().unwrap().push(self.name);
        if std::mem::replace(&mut self.waited, true) {
            Ok(Handshake::Done)
        } else {
            Ok(Handshake::Waiting)
        }
    }
}

/// A stream's layers shut down from the top, one at a time: the one below
/// starts only once the one above is done, and one done is not asked
/// again (`Curl_cshutdn_try_once_idx`); the socket's own shutdown, the
/// drain, comes last.
#[test]
fn layers_shut_down_from_the_top_one_at_a_time() {
    use crate::conn::Stream;
    use crate::conn::io::{Closer, Conversation, FakeNet, Peer, Sock};
    use crate::time::{Clock as _, ManualClock};
    let clock = ManualClock::new().unwrap();
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let talk = Conversation::replies(&[], false);
    let mut net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let socket = Sock::new(crate::conn::io::dial(&mut net, at), Closer::System);
    let mut stream = Stream::new(socket);
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    for name in ["bottom", "top"] {
        let layer = Logged {
            name,
            waited: false,
            log: log.clone(),
        };
        stream
            .layers_mut()
            .push(curl_alloc::try_box(layer).unwrap())
            .unwrap();
    }
    let mut cx = Silent(clock.now());
    let mut shut = 0;
    let mut tries = Vec::new();
    for _ in 0..3 {
        tries.push(stream.shutdown(&mut cx, &mut shut).unwrap());
    }
    use Handshake::{Done, Waiting};
    assert_eq!(tries, [Waiting, Waiting, Done]);
    assert_eq!(*log.lock().unwrap(), ["top", "top", "bottom", "bottom"]);
    assert_eq!(shut, 2);
    assert_eq!(talk.reads(), (1, 1024), "drained once, last");
    net.close(stream.into_socket());
}
