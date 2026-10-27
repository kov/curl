use super::*;
use crate::conn::layer::Silent;
use crate::conn::quic::tests::{Act, Scripted};
use crate::http3::fake::{FakeHttp3, Script};
use crate::http3::{ClientSetup, Http3};
use crate::time::{Clock, ManualClock, SharedClock};
use crate::tls::Notes;
use std::sync::{Arc, Mutex};

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
    let mut cx = Silent(ManualClock::new().unwrap().now());
    let mut t = Tunnel::new();
    t.life = Life::Open {
        stream: StreamId(0),
        flow_blocked: false,
    };
    let (mut came, mut taken) = (0, 0);
    let mut buf = vec![0; DATA];
    for round in 0..100 {
        let bytes = counting(came, DATA);
        came += DATA;
        let heard = t.heard(&mut cx, StreamId(0), StreamEvent::Data(&bytes));
        assert_eq!(heard, Heard::Fine);
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

fn data(stream: i64, bytes: &[u8]) -> (StreamId, StreamEvent<'_>) {
    (StreamId(stream), StreamEvent::Data(bytes))
}

fn header<'a>(
    stream: i64,
    name: &'a [u8],
    value: &'a [u8],
    status: bool,
) -> (StreamId, StreamEvent<'a>) {
    let event = StreamEvent::Header {
        name,
        value,
        status,
    };
    (StreamId(stream), event)
}

fn open(stream: i64, flow_blocked: bool) -> Life {
    Life::Open {
        stream: StreamId(stream),
        flow_blocked,
    }
}

fn gone(stream: i64) -> Life {
    Life::Closed {
        stream: StreamId(stream),
        reset: None,
    }
}

fn tunnel_on(stream: i64) -> Tunnel {
    let mut tunnel = Tunnel::new();
    tunnel.life = open(stream, false);
    tunnel
}

/// What `tunnel` makes of `event` on its stream.
fn hear(
    tunnel: &mut Tunnel,
    cx: &mut dyn LayerCx,
    (stream, event): (StreamId, StreamEvent<'_>),
) -> Heard {
    tunnel.heard(cx, stream, event)
}

/// Whether `tunnel`'s answer is final.
fn answered(tunnel: &Tunnel) -> bool {
    matches!(tunnel.answer, Answering::Final(_))
}

/// The stream's id as the traces say it, -1 once it is gone.
#[test]
fn a_tunnel_s_id_is_its_stream_s_or_minus_one() {
    let mut tunnel = Tunnel::new();
    assert_eq!(tunnel.id(), -1);
    tunnel.life = open(4, false);
    assert_eq!(tunnel.id(), 4);
}

/// The tunnel's DATA are held for the layer above, each traced as C
/// traces it, and its receive window opened to what is held allowing
/// for 512 KiB again (`cf_h3_proxy_upd_rx_win`): at once from the
/// initial 32 KiB, then by what the layer above reads.
#[test]
fn a_tunnel_s_window_is_kept_open_to_what_it_holds() {
    let mut notes = Notes::default();
    let mut tunnel = tunnel_on(4);
    assert_eq!(
        hear(&mut tunnel, &mut notes, data(4, &[1; 1000])),
        Heard::Fine
    );
    assert_eq!(
        hear(&mut tunnel, &mut notes, data(4, &[2; 1000])),
        Heard::Fine
    );
    assert_eq!(
        notes.0,
        [
            "trace: [cb_h3_proxy_recv_data] [4] DATA len=1000, total=1000",
            "trace: [4] DATA len=1000, rx win=31768",
            "trace: [4] rx window, extend 31768 (buffered 1000) by 491520 bytes",
            "trace: [cb_h3_proxy_recv_data] [4] DATA len=1000, total=2000",
            "trace: [4] DATA len=1000, rx win=522288",
        ]
    );
    assert_eq!(tunnel.held().len(), 2000);
    assert_eq!(tunnel.held()[..1000], [1; 1000]);
    assert_eq!(tunnel.rx_offset_max, 512 * 1024);
    assert_eq!(tunnel.extend, 491_520);
    // The layer above reads some: the window opens by as much.
    notes.0.clear();
    assert_eq!(tunnel.take(&mut [0; 1500]), 1500);
    tunnel.update_window(&mut notes);
    assert_eq!(
        notes.0,
        ["trace: [4] rx window, extend 522288 (buffered 500) by 1500 bytes"]
    );
    assert_eq!(tunnel.rx_offset_max, 512 * 1024 + 1500);
    assert_eq!(tunnel.extend, 491_520 + 1500);
    // What is read is let go before the next DATA are kept.
    assert_eq!(tunnel.take(&mut [0; 500]), 500);
    hear(&mut tunnel, &mut notes, data(4, &[3; 10]));
    assert_eq!(tunnel.held(), [3; 10]);
    // A stream gone opens nothing.
    notes.0.clear();
    tunnel.life = gone(4);
    let held = tunnel.held().len();
    assert_eq!(tunnel.take(&mut vec![0; held]), held);
    tunnel.update_window(&mut notes);
    assert!(notes.0.is_empty());
}

/// A window is opened no further than the offset's limit, and not at
/// all once it is there.
#[test]
fn a_tunnel_s_window_stops_at_the_largest_offset() {
    let mut notes = Notes::default();
    let mut tunnel = tunnel_on(0);
    tunnel.rx_offset = u64::MAX - 100;
    tunnel.rx_offset_max = u64::MAX - 100;
    tunnel.update_window(&mut notes);
    assert_eq!(
        notes.0,
        ["trace: [0] rx window, extend 0 (buffered 0) by 100 bytes"]
    );
    assert_eq!(tunnel.rx_offset_max, u64::MAX);
    notes.0.clear();
    tunnel.rx_offset = u64::MAX;
    tunnel.update_window(&mut notes);
    assert!(notes.0.is_empty());
    assert_eq!(tunnel.extend, 100);
}

/// The answer read is the stream's own, an interim one's replaced by
/// the next, and the final one's fields are all it has: another
/// stream's, and fields after it, are let be.
#[test]
fn a_tunnel_s_answer_is_its_stream_s_final_one() {
    let mut notes = Notes::default();
    let mut tunnel = tunnel_on(0);
    let done = (StreamId(0), StreamEvent::HeadersDone);
    for event in [
        header(0, b":status", b"103", true),
        header(0, b"link", b"</a>", false),
        (StreamId(0), StreamEvent::HeadersDone),
    ] {
        assert_eq!(hear(&mut tunnel, &mut notes, event), Heard::Fine);
    }
    assert!(!answered(&tunnel), "a 103 is interim");
    for event in [
        header(0, b":status", b"200", true),
        header(4, b"other", b"stream", false),
        header(0, b"via", b"proxy", false),
        done,
        header(0, b"after", b"final", false),
        header(4, b":status", b"500", true),
    ] {
        assert_eq!(hear(&mut tunnel, &mut notes, event), Heard::Fine);
    }
    let Answering::Final(Some(answer)) = &tunnel.answer else {
        panic!("the final answer is read");
    };
    assert_eq!(answer.status, 200);
    assert_eq!(answer.fields, [(b"via".to_vec(), b"proxy".to_vec())]);
    assert_eq!(
        notes.0,
        [
            "trace: [0] header: link: </a>",
            "trace: [0] end_headers, status=103",
            "trace: [0] header: via: proxy",
            "trace: [0] end_headers, status=200",
        ]
    );
}

/// A context that notes each call it is asked, and answers each with
/// `yes` or something of its own.
struct Asked {
    calls: Vec<String>,
    yes: bool,
    report: crate::report::TransferReport,
}

impl LayerCx for Asked {
    fn now(&self) -> Instant {
        crate::time::Clock::now(&crate::time::ManualClock::new().unwrap())
    }
    fn of(&mut self, _: Component, line: std::fmt::Arguments<'_>) {
        self.calls.push(format!("of {line}"));
    }
    fn info(&mut self, line: std::fmt::Arguments<'_>) {
        self.calls.push(format!("info {line}"));
    }
    fn socket_failed(&mut self, e: &io::Error) {
        self.calls.push(format!("socket_failed {e}"));
    }
    fn fails(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
        self.calls.push(format!("fails {why}"));
        kind
    }
    fn of_with(&mut self, _: Component, parts: &[&[u8]]) {
        self.calls
            .push(format!("of {}", String::from_utf8_lossy(&parts.concat())));
    }
    fn info_with(&mut self, parts: &[&[u8]]) {
        self.calls
            .push(format!("info {}", String::from_utf8_lossy(&parts.concat())));
    }
    fn fails_with(&mut self, kind: ErrorKind, parts: &[&[u8]]) -> ErrorKind {
        self.calls.push(format!(
            "fails {}",
            String::from_utf8_lossy(&parts.concat())
        ));
        kind
    }
    fn bytes(&mut self, kind: crate::handler::DebugKind, bytes: &[u8]) {
        self.calls.push(format!("bytes {kind:?} {bytes:?}"));
    }
    fn debugs(&self) -> bool {
        self.yes
    }
    fn verbose(&self) -> bool {
        self.yes
    }
    fn certinfo_report(&mut self) -> Option<&mut crate::report::TransferReport> {
        Some(&mut self.report)
    }
    fn tls_verified(&mut self, filter: Component, result: i64) {
        self.calls.push(format!("tls_verified {filter:?} {result}"));
    }
    fn configures_tls(&self) -> bool {
        self.yes
    }
    fn configure_tls(&mut self, _: crate::tls::TlsNative) -> Result<(), ErrorKind> {
        Err(ErrorKind::SslEngineInitfailed)
    }
    fn pause_recv(&mut self) {
        self.calls.push("pause_recv".to_string());
    }
    fn unix_time(&self) -> i64 {
        1_700_000_000
    }
    fn has_tls_sessions(&self) -> bool {
        self.yes
    }
    fn tls_sessions(&mut self, _: &mut dyn FnMut(&mut crate::tls::SessionCache, &mut dyn LayerCx)) {
        self.calls.push("tls_sessions".to_string());
    }
    fn quic_due(&mut self, wait: std::time::Duration) {
        self.calls.push(format!("quic_due {wait:?}"));
    }
}

/// A call into the proxy's connection says to the transfer all it is
/// told and answers as the transfer does, but for its streams'
/// events, which are the tunnel's.
#[test]
fn a_call_into_the_proxy_s_connection_is_the_transfer_s() {
    use crate::conn::io::{Conversation, FakeNet, Peer};
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let mut net = FakeNet::new(crate::time::ManualClock::new().unwrap())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, Conversation::new(b"", false));
    let socket = crate::conn::io::dial(&mut net, at);
    for yes in [true, false] {
        let mut asked = Asked {
            calls: Vec::new(),
            yes,
            report: crate::report::TransferReport::default(),
        };
        let report: *const crate::report::TransferReport = &asked.report;
        let mut tunnel = tunnel_on(0);
        let mut room = Vec::new();
        let mut over = Tunnelled {
            cx: &mut asked,
            socket: &*socket,
            tunnel: &mut tunnel,
            room: &mut room,
        };
        assert_eq!(over.debugs(), yes);
        assert_eq!(over.verbose(), yes);
        assert_eq!(over.configures_tls(), yes);
        assert_eq!(over.has_tls_sessions(), yes);
        assert_eq!(over.unix_time(), 1_700_000_000);
        assert!(std::ptr::eq(over.certinfo_report().unwrap(), report));
        let native = crate::tls::TlsNative::new(std::ptr::NonNull::dangling(), None);
        assert_eq!(
            over.configure_tls(native),
            Err(ErrorKind::SslEngineInitfailed)
        );
        over.info(format_args!("said"));
        over.socket_failed(&io::Error::other("gone"));
        over.bytes(crate::handler::DebugKind::DataIn, b"in");
        over.tls_verified(Component::H3Proxy, 18);
        over.pause_recv();
        over.tls_sessions(&mut |_, _| {});
        over.quic_due(std::time::Duration::from_millis(5));
        assert_eq!(
            over.h3_event(StreamId(0), StreamEvent::Data(b"tunnelled")),
            Heard::Fine
        );
        assert_eq!(
            asked.calls,
            [
                "info said",
                "socket_failed gone",
                "bytes DataIn [105, 110]",
                "tls_verified H3Proxy 18",
                "pause_recv",
                "tls_sessions",
                "quic_due 5ms",
                "of [cb_h3_proxy_recv_data] [0] DATA len=9, total=9",
                "of [0] DATA len=9, rx win=32759",
                "of [0] rx window, extend 32759 (buffered 9) by 491520 bytes",
            ]
        );
        assert_eq!(tunnel.held(), b"tunnelled");
    }
}

/// The tunnel over a connection to the proxy made by the fake library
/// running `script`, its handshake not begun, and the clock it reads.
fn proxy(script: &Arc<Mutex<Script>>) -> (H3Proxy, ManualClock) {
    let clock = ManualClock::new().unwrap();
    let remote = std::net::SocketAddr::from(([127, 0, 0, 1], 443));
    let setup = ClientSetup {
        local: std::net::SocketAddr::from(([127, 0, 0, 1], 40000)),
        remote,
        now: clock.now(),
        handshake_timeout: std::time::Duration::from_secs(10),
        max_window: 1 << 20,
        stream_window: 1 << 15,
        max_streams: 100,
    };
    let conn = FakeHttp3::new(script.clone())
        .client(&setup, crate::tls::fake::quic_session().unwrap())
        .unwrap();
    let identity = crate::tls::TlsIdentity::of(&Default::default(), Default::default()).unwrap();
    let origin =
        crate::conn::Peer::new(crate::proto::http::HTTPS, b"proxy.test".to_vec(), 443, None);
    let peer =
        crate::tls::SessionPeer::new(&identity, &origin, None, &"test", crate::conn::Dial::Quic)
            .unwrap();
    let shared = SharedClock::new(Box::new(clock.clone())).unwrap();
    let quic = Quic::new(conn, peer, remote, shared, H3P, false).unwrap();
    (H3Proxy::new(Box::new(quic), false), clock)
}

/// The layer under the tunnel: alive, with nothing to read or send,
/// and data pending if `pending`.
#[derive(Debug)]
struct Under {
    pending: bool,
}

impl Part<Below<'_>> for Under {
    fn data_pending(&self, _: Below<'_>) -> bool {
        self.pending
    }

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

/// Hold a packet the socket will not take: the connection then has
/// something to send.
fn hold_a_packet(p: &mut H3Proxy, script: &Arc<Mutex<Script>>) {
    script.lock().unwrap().out.extend([vec![9; 100], vec![]]);
    let socket = Scripted::default();
    socket.sends.lock().unwrap().push_back(Act::Block);
    p.egress(&mut Notes::default(), &socket).unwrap();
}

/// The poll asks to read for a window shut, the connection's or the
/// stream's, and to write while the stream may or packets wait; with
/// no stream it is left as it is (`cf_h3_proxy_adjust_pollset`).
#[test]
fn a_tunnel_s_poll_is_as_its_windows_say() {
    let script = Script::new();
    let (mut p, _) = proxy(&script);
    let (none, r, w, rw) = (
        Events::NONE,
        Events::IN,
        Events::OUT,
        Events::IN | Events::OUT,
    );
    p.tunnel.life = open(0, false);
    for wanted in [none, r, w, rw] {
        assert_eq!(p.adjust_pollset(wanted), wanted);
    }
    // The stream may send no more: a send waits on reading.
    p.tunnel.life = open(0, true);
    assert_eq!(p.adjust_pollset(w), r);
    assert_eq!(p.adjust_pollset(rw), r);
    assert_eq!(p.adjust_pollset(r), r);
    p.tunnel.life = open(0, false);
    // The connection may send no more: a send reads too.
    script.lock().unwrap().no_send_room = true;
    assert_eq!(p.adjust_pollset(w), rw);
    assert_eq!(p.adjust_pollset(r), r);
    script.lock().unwrap().no_send_room = false;
    // Packets wait for the socket: it writes, whatever is wanted.
    hold_a_packet(&mut p, &script);
    assert_eq!(p.connect_interest(), rw);
    assert_eq!(p.adjust_pollset(none), w);
    assert_eq!(p.adjust_pollset(r), rw);
    p.tunnel.life = open(0, true);
    assert_eq!(p.adjust_pollset(w), rw);
    // No stream, none of it.
    p.tunnel.life = gone(0);
    for wanted in [none, r, w, rw] {
        assert_eq!(p.adjust_pollset(wanted), wanted);
    }
}

/// The connection waits to read as the `CONNECT` goes, and to write
/// too while packets wait.
#[test]
fn a_tunnel_s_connect_waits_as_its_connection_does() {
    let script = Script::new();
    let (p, _) = proxy(&script);
    assert_eq!(p.connect_interest(), Events::IN);
    assert!(!p.tunnel_closed());
}

/// Data is pending while the tunnel holds some for the layer above,
/// or the layers below have some.
#[test]
fn a_tunnel_s_data_is_pending_held_or_below() {
    let script = Script::new();
    let (mut p, _) = proxy(&script);
    let socket = Scripted::default();
    for (held, below, pending) in [
        (false, false, false),
        (false, true, true),
        (true, false, true),
        (true, true, true),
    ] {
        p.tunnel.recv = crate::conn::buf::HeldBytes::default();
        if held {
            p.tunnel.recv.push(b"held").unwrap();
        }
        let mut layers: [Box<dyn Layer>; 1] = [Box::new(Under { pending: below })];
        assert_eq!(
            p.data_pending(Below::new(&mut layers, &socket)),
            pending,
            "held {held}, below {below}"
        );
    }
}

/// The tunnel is alive while its connection may be used, as the
/// peer's idle timeout says, and what is below is.
#[test]
fn a_tunnel_is_alive_while_its_connection_is_usable() {
    let script = Script::new();
    script.lock().unwrap().idle = Some(std::time::Duration::from_secs(30));
    let (mut p, clock) = proxy(&script);
    let socket = Scripted::default();
    let mut layers: [Box<dyn Layer>; 1] = [Box::new(Under { pending: false })];
    let mut notes = Notes::default();
    assert_eq!(
        p.is_alive(&mut notes, Below::new(&mut layers, &socket)),
        Alive::Alive {
            input_pending: false
        }
    );
    clock.advance(std::time::Duration::from_secs(31));
    assert_eq!(
        p.is_alive(&mut notes, Below::new(&mut layers, &socket)),
        Alive::Dead
    );
}

/// The layer is the `H3-PROXY` filter, the tunnel C's chain names,
/// and says what its send or receive failed with.
#[test]
fn a_tunnel_is_the_h3_proxy_filter() {
    let script = Script::new();
    let (mut p, _) = proxy(&script);
    assert_eq!(p.filter(), Some(Component::H3Proxy));
    assert_eq!(
        p.query(LayerQuery::Tunnel),
        Some(LayerAnswer::Tunnel(Component::H3Proxy))
    );
    assert_eq!(p.query(LayerQuery::Failure), None);
    assert_eq!(p.query(LayerQuery::Alpn), None);
    p.failed(ErrorKind::SendError);
    assert_eq!(
        p.query(LayerQuery::Failure),
        Some(LayerAnswer::Failure(ErrorKind::SendError))
    );
}

/// The layer above's bytes go as the stream's body as far as the
/// library takes them, traced as C traces it; none taken is to wait,
/// sending nothing (`cf_h3_proxy_send`'s `CURLE_AGAIN`), and a send
/// the socket fails fails, as does a packet sent alone.
#[test]
fn a_send_into_the_tunnel_is_the_stream_s_body() {
    let script = Script::new();
    let (mut p, _) = proxy(&script);
    p.tunnel.life = open(0, false);
    let socket = Scripted::default();
    let mut layers: [Box<dyn Layer>; 0] = [];
    let mut notes = Notes::default();
    assert_eq!(
        p.send(&mut notes, Below::new(&mut layers, &socket), b"abc")
            .unwrap(),
        Sent::Bytes(NonZeroUsize::new(3).unwrap())
    );
    script.lock().unwrap().body.held_max = Some(3);
    script.lock().unwrap().out.extend([vec![8; 50], vec![]]);
    let sent = socket.sent.lock().unwrap().len();
    assert_eq!(
        p.send(&mut notes, Below::new(&mut layers, &socket), b"def")
            .unwrap(),
        Sent::WouldBlock
    );
    assert_eq!(
        socket.sent.lock().unwrap().len(),
        sent,
        "nothing goes while the send waits"
    );
    let sends: Vec<&String> = notes.0.iter().filter(|l| l.contains("cf_send")).collect();
    assert_eq!(
        sends,
        [
            "trace: [0] cf_send, add to sendbuf(len=3) -> 0, 3",
            "trace: [0] cf_send(len=3) -> 0, 3",
            "trace: [0] cf_send, add to sendbuf(len=3) -> 81, 0",
            "trace: [0] cf_send(len=3) -> 81, 0",
        ]
    );
    // The socket fails the packets the send makes.
    script.lock().unwrap().body.held_max = None;
    socket.sends.lock().unwrap().push_back(Act::Fail(111));
    assert!(
        p.send(&mut notes, Below::new(&mut layers, &socket), b"ghi")
            .is_err()
    );
    // And so does a packet sent as the `CONNECT` goes.
    script.lock().unwrap().out.extend([vec![9; 100], vec![]]);
    socket.sends.lock().unwrap().push_back(Act::Fail(111));
    assert!(p.egress(&mut notes, &socket).is_err());
}
