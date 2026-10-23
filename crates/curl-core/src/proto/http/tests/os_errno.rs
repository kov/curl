//! The operating system's error number a transfer keeps (`os_errno`):
//! that of the last call on a socket that failed, a connect, a send or a
//! receive (`cf-socket.c`), whether or not the transfer failed with it;
//! none again once the handle's next transfer starts (`easy_perform`,
//! `curl_multi_add_handle`).

use std::net::IpAddr;

use super::*;

/// As Linux numbers them, as the fake network gives them.
const ECONNREFUSED: i32 = 111;
const EPIPE: i32 = 32;

fn errno(ran: &Ran) -> Option<i32> {
    ran.easy.report().os_errno().map(|e| e.get())
}

/// A refused connect keeps its number.
#[test]
fn a_refused_connect_keeps_its_number() {
    let mut m = serving(Peer::Refuses, &[]);
    let ran = get(&mut m, "/", Conversation::replies(&[], false), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(errno(&ran), Some(ECONNREFUSED));
}

/// An address refused before another connects: the refusal's number is
/// kept though the transfer succeeds, as C's socket filter keeps it for
/// each attempt that fails (`cf_tcp_connect`).
#[test]
fn a_refused_attempt_s_number_outlives_the_next_s_success() {
    let talk = Conversation::replies(&[OK], false);
    let v6 = IpAddr::from(std::net::Ipv6Addr::LOCALHOST);
    let v4 = IpAddr::from([127, 0, 0, 1]);
    let clock = ManualClock::new().unwrap();
    let net = FakeNet::new(clock.clone())
        .with_name("dual.example", &[v6, v4])
        .with_peer(SocketAddr::new(v6, PORT), Peer::Refuses)
        .with_peer(SocketAddr::new(v4, PORT), Peer::Accepts)
        .with_conversation(SocketAddr::new(v4, PORT), talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let ran = get(&mut m, "/", talk, |o| {
        let url = format!("http://dual.example:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(errno(&ran), Some(ECONNREFUSED));
}

/// A send the peer refuses keeps its number; the handle's next transfer
/// starts without one.
#[test]
fn a_failed_send_keeps_its_number_until_the_next_transfer() {
    let broken = Conversation::replies(&[OK], false).breaking_after(0);
    let mut m = serving(Peer::Accepts, &[&broken]);
    let ran = get(&mut m, "/", broken, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    assert_eq!(errno(&ran), Some(EPIPE));
    let (mut m, talk, _) = server(&[OK], false);
    let again = get_with(&mut m, ran.easy, "/", talk, |_| {});
    assert_eq!(again.result, Ok(()));
    assert_eq!(errno(&again), None);
}

/// A transfer whose sockets all do as asked has no number.
#[test]
fn a_transfer_without_a_socket_failure_has_none() {
    let ran = run("/", OK, false, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(errno(&ran), None);
}

/// A connect refused at once, before its socket is polled, keeps its
/// number (`socket_connect_result`).
#[test]
fn an_immediate_refusal_keeps_its_number() {
    let clock = ManualClock::new().unwrap();
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(FakeNet::new(clock)),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let ran = get(&mut m, "/", Conversation::replies(&[], false), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    assert!(
        ran.seen
            .text()
            .iter()
            .any(|l| l.starts_with("Immediate connect fail for 127.0.0.1")),
        "{:?}",
        ran.seen.text()
    );
    assert_eq!(errno(&ran), Some(ECONNREFUSED));
}
