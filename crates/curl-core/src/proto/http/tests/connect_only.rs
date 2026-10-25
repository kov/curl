//! A transfer that only connects (`CURLOPT_CONNECT_ONLY`): its connection
//! kept for the handle, which sends and receives on it itself
//! (`curl_easy_send`, `curl_easy_recv`), until it leaves its multi or runs
//! again.

use super::*;
use crate::multi::raw::RawIo;
use crate::options::ConnectOnly;

/// A verbose transfer of `e` to the test's server that only connects.
fn connect_only(e: &mut Easy) -> Seen {
    let seen = Seen::default();
    let o = e.options_mut();
    let url = format!("http://127.0.0.1:{PORT}/");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.output.verbose = true;
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.connect_only = ConnectOnly::Yes;
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    seen
}

/// Receive what comes, until something does.
fn recv_some(mut recv: impl FnMut(&mut [u8]) -> Result<RawIo, ErrorKind>) -> Vec<u8> {
    let mut buf = [0u8; 256];
    for _ in 0..100 {
        match recv(&mut buf).unwrap() {
            RawIo::Bytes(n) => return buf[..n].to_vec(),
            RawIo::WouldBlock => {}
        }
    }
    panic!("nothing came");
}

/// The transfer sends nothing and is done once connected; its handle
/// then sends and receives on the connection, whose socket it is told,
/// and the connection closes, said so, as the handle leaves the multi.
#[test]
fn a_handle_that_only_connects_talks_on_its_connection() {
    let (mut m, talk, _) = server(&[OK], false);
    let mut e = Easy::new();
    let seen = connect_only(&mut e);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    assert!(talk.received().is_empty());
    let text = seen.text();
    assert!(
        text.contains(&format!(
            "Connection #0 to host 127.0.0.1:{PORT} left intact\n"
        )),
        "{text:?}"
    );
    assert!(m.active_socket(id).unwrap().is_some());
    let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let sent = m.send_raw(id, request).unwrap().unwrap();
    assert_eq!(sent, RawIo::Bytes(request.len()));
    assert_eq!(talk.received(), request);
    let got = recv_some(|buf| m.recv_raw(id, buf).unwrap());
    assert!(
        got.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "{}",
        String::from_utf8_lossy(&got)
    );
    m.remove(id, &mut NoEvents).unwrap();
    assert!(seen.text().contains(&"closing connection #0\n".to_string()));
}

/// A handle that asked for no such thing is refused, and one whose
/// connection is gone forgets it, naming none, as C's lookup does.
#[test]
fn raw_bytes_need_the_handle_s_own_connection() {
    let (mut m, _talk, _) = server(&[OK], false);
    let mut e = Easy::new();
    let seen = connect_only(&mut e);
    e.options_mut().connect_only = ConnectOnly::No;
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(
        m.recv_raw(id, &mut buf).unwrap(),
        Err(ErrorKind::UnsupportedProtocol)
    );
    let failure = m.easy(id).unwrap().report().failure().map(<[u8]>::to_vec);
    assert_eq!(failure.as_deref(), Some(&b"CONNECT_ONLY is required"[..]));
    let removed = m.remove(id, &mut NoEvents).unwrap();
    let mut e = *removed.easy;
    e.options_mut().connect_only = ConnectOnly::Yes;
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    assert_eq!(
        m.send_raw(id, b"x").unwrap(),
        Err(ErrorKind::UnsupportedProtocol)
    );
    assert_eq!(m.active_socket(id).unwrap(), None);
    drop(seen);
}

/// In a handle's own multi, as a perform runs it, the connection stays
/// as the handle comes out; the next transfer closes it if the handle
/// used it, and leaves it to the multi if not.
#[test]
fn a_handle_s_own_multi_keeps_the_connection_until_used_and_run_again() {
    let (mut m, talk, _) = server(&[OK], false);
    m.make_handle_own();
    let mut e = Easy::new();
    let seen = connect_only(&mut e);
    e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    assert!(m.active_socket_for(&mut e).is_some());
    let sent = m.send_raw_for(&mut e, b"GET / HTTP/1.1\r\n\r\n").unwrap();
    assert!(matches!(sent, RawIo::Bytes(_)));
    assert!(!talk.received().is_empty());
    e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    let text = seen.text();
    assert_eq!(
        text.iter()
            .filter(|l| *l == "closing connection #0\n")
            .count(),
        1,
        "{text:?}"
    );
    // The second one's, unused, is not closed by a third.
    e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    assert!(!seen.text().contains(&"closing connection #1\n".to_string()));
}

/// Changing to or from a share that keeps connections forgets the last
/// connection (`Curl_share_easy_link`), which another pool cannot name.
#[test]
fn a_share_of_connections_forgets_the_last_connection() {
    let (mut m, _talk, _) = server(&[OK], false);
    m.make_handle_own();
    let mut e = Easy::new();
    let _seen = connect_only(&mut e);
    e.perform_in(&mut m, crate::easy::Drive::Waits).unwrap();
    assert!(e.report().conn_number().is_some());
    // A share that keeps no connections changes nothing.
    e.set_share(Some(crate::share::Share::new().unwrap()));
    assert!(m.active_socket_for(&mut e).is_some());
    let share = crate::share::Share::new().unwrap();
    share.keep(crate::share::Kind::Connections).unwrap();
    e.set_share(Some(share));
    assert!(e.report().conn_number().is_none());
    assert!(m.active_socket_for(&mut e).is_none());
    assert_eq!(
        m.send_raw_for(&mut e, b"x"),
        Err(ErrorKind::UnsupportedProtocol)
    );
}

/// A transfer that only connects makes a new connection, never reusing
/// an idle one (`url_attach_existing` is not asked).
#[test]
fn a_handle_that_only_connects_makes_a_new_connection() {
    let (mut m, _talk, _) = server(&[OK], false);
    let ran = get(&mut m, "/", Conversation::replies(&[], false), |_| {});
    assert_eq!(ran.result, Ok(()));
    let mut e = Easy::new();
    let seen = connect_only(&mut e);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    let text = seen.text();
    assert!(
        text.contains(&format!(
            "Connection #1 to host 127.0.0.1:{PORT} left intact\n"
        )),
        "{text:?}"
    );
    m.remove(id, &mut NoEvents).unwrap();
}

/// Over a real socket, a handle's own perform leaves it the connection:
/// its socket is told, and it sends and receives on it.
#[test]
fn a_perform_that_only_connects_leaves_the_handle_its_socket() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let mut got = [0u8; 4];
        peer.read_exact(&mut got).unwrap();
        peer.write_all(b"pong").unwrap();
        got
    });
    let mut e = Easy::new();
    let url = format!("http://127.0.0.1:{port}/");
    e.options_mut().set_url(Some(url.as_bytes())).unwrap();
    e.options_mut().connect_only = ConnectOnly::Yes;
    assert_eq!(e.active_socket(), None);
    e.perform().unwrap();
    assert!(e.active_socket().is_some());
    let mut sent = 0;
    while sent < 4 {
        match e.send_raw(&b"ping"[sent..]).unwrap() {
            RawIo::Bytes(n) => sent += n,
            RawIo::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(5)),
        }
    }
    let mut got = Vec::new();
    while got.len() < 4 {
        let mut buf = [0u8; 8];
        match e.recv_raw(&mut buf).unwrap() {
            RawIo::Bytes(0) => break,
            RawIo::Bytes(n) => got.extend_from_slice(&buf[..n]),
            RawIo::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(5)),
        }
    }
    assert_eq!(got, b"pong");
    assert_eq!(&server.join().unwrap(), b"ping");
}
