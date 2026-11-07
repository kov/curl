//! LDAP's messages as a server sends them, for the tests' fake servers.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::thread;

/// A BER element: `tag`, its length and `content`.
pub(crate) fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    if content.len() < 128 {
        v.push(content.len() as u8);
    } else {
        v.push(0x82);
        v.extend_from_slice(&(content.len() as u16).to_be_bytes());
    }
    v.extend_from_slice(content);
    v
}

/// An LDAP message of `id` holding `op`.
pub(crate) fn ldap_message(id: u8, op: &[u8]) -> Vec<u8> {
    let mut content = ber(0x02, &[id]);
    content.extend_from_slice(op);
    ber(0x30, &content)
}

/// A result operation of `tag`: `code`, an empty matched name and `info`.
pub(crate) fn result_op(tag: u8, code: u8, info: &[u8]) -> Vec<u8> {
    let mut content = ber(0x0a, &[code]);
    content.extend_from_slice(&ber(0x04, b""));
    content.extend_from_slice(&ber(0x04, info));
    ber(tag, &content)
}

/// An entry named `dn` with `attrs`, each its type and values.
pub(crate) fn entry_op(dn: &[u8], attrs: &[(&[u8], &[&[u8]])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (name, values) in attrs {
        let mut set = Vec::new();
        for v in *values {
            set.extend_from_slice(&ber(0x04, v));
        }
        let mut a = ber(0x04, name);
        a.extend_from_slice(&ber(0x31, &set));
        list.extend_from_slice(&ber(0x30, &a));
    }
    let mut content = ber(0x04, dn);
    content.extend_from_slice(&ber(0x30, &list));
    ber(0x64, &content)
}

/// One LDAP message read off `s`: its operation's tag and the whole
/// message; none at the end.
fn read_message(s: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    if s.read_exact(&mut head).is_err() {
        return None;
    }
    assert_eq!(head[0], 0x30, "a message");
    let len = if head[1] < 0x80 {
        usize::from(head[1])
    } else {
        let mut n = vec![0u8; usize::from(head[1] & 0x7f)];
        s.read_exact(&mut n).unwrap();
        n.iter().fold(0, |a, &b| a << 8 | usize::from(b))
    };
    let mut content = vec![0u8; len];
    s.read_exact(&mut content).unwrap();
    // The message id, an integer, then the operation.
    let id_len = usize::from(content[1]);
    let op = content[2 + id_len];
    Some((op, content))
}

/// The id of the message `content` is.
fn id_of(content: &[u8]) -> u8 {
    assert_eq!((content[0], content[1]), (0x02, 1), "a one-byte id");
    content[2]
}

/// The requests a server was sent, each its operation's tag and the
/// whole message.
pub(crate) type Requests = Vec<(u8, Vec<u8>)>;

/// A server on a port of its own that answers each request as `answer`
/// says, a message for each, and gives the requests it was sent, each its
/// operation's tag and the whole message.
pub(crate) fn serve(answer: fn(u8, u8) -> Vec<Vec<u8>>) -> (u16, thread::JoinHandle<Requests>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut s, _) = curl_core::test_server::accept(&listener);
        let mut got = Vec::new();
        while let Some((op, content)) = read_message(&mut s) {
            for m in answer(op, id_of(&content)) {
                s.write_all(&m).unwrap();
            }
            got.push((op, content));
        }
        got
    });
    (port, server)
}

/// The answers of a server that finds two entries: a bind taken, then
/// the search's entries and its result, `code`.
pub(crate) fn finds_two(op: u8, id: u8, code: u8) -> Vec<Vec<u8>> {
    match op {
        0x60 => vec![ldap_message(id, &result_op(0x61, 0, b""))],
        0x63 => vec![
            ldap_message(
                id,
                &entry_op(b"cn=a,dc=x", &[(b"cn", &[b"a", b"b"]), (b"sn", &[])]),
            ),
            ldap_message(id, &entry_op(b"cn=c,dc=x", &[(b"photo", &[b"\x00\x01"])])),
            ldap_message(id, &result_op(0x65, code, b"")),
        ],
        _ => Vec::new(),
    }
}

/// The operations' tags of the requests a server was sent.
pub(crate) fn ops(got: &[(u8, Vec<u8>)]) -> Vec<u8> {
    got.iter().map(|(op, _)| *op).collect()
}
