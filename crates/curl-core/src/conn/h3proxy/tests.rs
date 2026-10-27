use super::*;
use crate::conn::layer::Silent;
use crate::time::{Clock as _, ManualClock};

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
    t.stream = Some(StreamId(0));
    let (mut came, mut taken) = (0, 0);
    let mut buf = vec![0; DATA];
    for round in 0..100 {
        let bytes = counting(came, DATA);
        came += DATA;
        let heard = t.heard(
            &mut cx,
            Event::Data {
                stream: StreamId(0),
                bytes: &bytes,
            },
        );
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
