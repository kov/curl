//! The multi component's trace (`CURL_TRC_M`): each change of C's state,
//! the times taken, the transfer coming and going, and what `multi_done`
//! does with the connection; and the TCP component's sends and receives.
//! Each expected sequence is the C build's for the same transfer, the
//! times left out.

use super::*;
use crate::components::Components;
use crate::conn::io::Peer;

/// A handle tracing the multi component.
fn tracing_multi() -> Easy {
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"multi");
    e.set_components(Some(components));
    e
}

/// The multi component's lines a run traced, the times blanked.
fn multi_lines(ran: &Ran) -> Vec<String> {
    ran.seen
        .text()
        .into_iter()
        .filter(|l| l.starts_with("[MULTI] "))
        .map(|l| {
            let l = l.trim_end();
            match l.find(" added ").filter(|_| l.ends_with("us")) {
                Some(at) => format!("{} added Nus", &l[..at]),
                None => l.to_owned(),
            }
        })
        .collect()
}

fn expect(lines: &str) -> Vec<String> {
    lines
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The states a request goes through, from the transfer's coming to its
/// going, the times among them.
const WHOLE_START: &str = "[MULTI] [INIT] added to multi, mid=1, running=1, total=2
    [MULTI] [INIT] -> [SETUP]
    [MULTI] [SETUP] [PGRS-STARTOP] set
    [MULTI] [SETUP] [PGRS-STARTSINGLE] set
    [MULTI] [SETUP] -> [CONNECT]
    [MULTI] [CONNECT] [PGRS-POSTQUEUE] set
    [MULTI] [CONNECT] [CPOOL] added connection 0. The cache now contains 1 members
    [MULTI] [CONNECT] Curl_conn_setup() -> 0
    [MULTI] [CONNECT] -> [CONNECTING]
    [MULTI] [CONNECTING] [PGRS-NAMELOOKUP] added Nus";

/// A request answered whole, from a new connection kept.
#[test]
fn a_request_is_traced_through_c_s_states() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_multi(), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let mut want = expect(WHOLE_START);
    want.extend(expect(
        "[MULTI] [CONNECTING] [PGRS-CONNECT] added Nus
        [MULTI] [CONNECTING] -> [PROTOCONNECT]
        [MULTI] [PROTOCONNECT] -> [DO]
        [MULTI] [DO] -> [DID]
        [MULTI] [DID] [PGRS-PRETRANSFER] added Nus
        [MULTI] [DID] [PGRS-POSTRANSFER] added Nus
        [MULTI] [DID] -> [PERFORMING]
        [MULTI] [PERFORMING] [PGRS-STARTTRANSFER] added Nus
        [MULTI] [PERFORMING] -> [DONE]
        [MULTI] [DONE] multi_done: status: 0 prem: 0 done: 0
        [MULTI] [DONE] multi_done_locked, in use=0
        [MULTI] [DONE] -> [COMPLETED]
        [MULTI] [COMPLETED] -> [MSGSENT]
        [MULTI] [COMPLETED] removed from multi, mid=1, running=0, total=1",
    ));
    assert_eq!(multi_lines(&ran), want);
}

/// A redirect followed is done with in PERFORMING, and the next request
/// starts from SETUP over the connection kept.
#[test]
fn a_redirect_starts_over_from_setup() {
    let moved = b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 3\r\n\r\nabc";
    let (mut m, talk, _) = server(&[moved, OK], false);
    let ran = get_with(&mut m, tracing_multi(), "/", talk, |o| {
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Ok(()));
    let lines = multi_lines(&ran);
    let from = lines.iter().position(|l| l.contains("multi_done")).unwrap();
    assert_eq!(
        lines[from..],
        expect(
            "[MULTI] [PERFORMING] multi_done: status: 0 prem: 0 done: 0
            [MULTI] [PERFORMING] multi_done_locked, in use=0
            [MULTI] [PERFORMING] [PGRS-REDIRECT] set
            [MULTI] [PERFORMING] -> [SETUP]
            [MULTI] [SETUP] [PGRS-STARTSINGLE] set
            [MULTI] [SETUP] -> [CONNECT]
            [MULTI] [CONNECT] [PGRS-POSTQUEUE] set
            [MULTI] [CONNECT] -> [CONNECTING]
            [MULTI] [CONNECTING] -> [PROTOCONNECT]
            [MULTI] [PROTOCONNECT] -> [DO]
            [MULTI] [DO] -> [DID]
            [MULTI] [DID] [PGRS-PRETRANSFER] added Nus
            [MULTI] [DID] [PGRS-POSTRANSFER] added Nus
            [MULTI] [DID] -> [PERFORMING]
            [MULTI] [PERFORMING] [PGRS-STARTTRANSFER] added Nus
            [MULTI] [PERFORMING] -> [DONE]
            [MULTI] [DONE] multi_done: status: 0 prem: 0 done: 0
            [MULTI] [DONE] multi_done_locked, in use=0
            [MULTI] [DONE] -> [COMPLETED]
            [MULTI] [COMPLETED] -> [MSGSENT]
            [MULTI] [COMPLETED] removed from multi, mid=1, running=0, total=1"
        )[..]
    );
}

/// A refused connect is done with in CONNECTING, its connection
/// terminated, and the times it skipped taken as it completes.
#[test]
fn a_refused_connect_is_done_with_where_it_failed() {
    let mut m = serving(Peer::Refuses, &[]);
    let ran = get_with(
        &mut m,
        tracing_multi(),
        "/",
        Conversation::replies(&[], false),
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let mut want = expect(WHOLE_START);
    want.extend(expect(&format!(
        "[MULTI] [CONNECTING] connect failed -> 7
        [MULTI] [CONNECTING] multi_done: status: 7 prem: 1 done: 0
        [MULTI] [CONNECTING] multi_done_locked, in use=0
        [MULTI] [CONNECTING] multi_done, terminating conn #0 to 127.0.0.1:{PORT}, forbid=0, close=0, premature=1, conn_multiplex=0
        [MULTI] [CONNECTING] -> [COMPLETED]
        [MULTI] [COMPLETED] [PGRS-PRETRANSFER] added Nus
        [MULTI] [COMPLETED] [PGRS-POSTRANSFER] added Nus
        [MULTI] [COMPLETED] [PGRS-STARTTRANSFER] added Nus
        [MULTI] [COMPLETED] -> [MSGSENT]
        [MULTI] [COMPLETED] removed from multi, mid=1, running=0, total=1"
    )));
    assert_eq!(multi_lines(&ran), want);
}

/// A request failed past its request marks its connection to close.
#[test]
fn a_failed_response_closes_its_connection_in_performing() {
    let missing = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc";
    let (mut m, talk, _) = server(&[missing], false);
    let ran = get_with(&mut m, tracing_multi(), "/", talk, |o| {
        o.http.fail_on_error = true;
    });
    assert_eq!(ran.result, Err(ErrorKind::HttpReturnedError));
    let lines = multi_lines(&ran);
    let from = lines.iter().position(|l| l.contains("multi_done")).unwrap();
    assert_eq!(
        lines[from..],
        expect(&format!(
            "[MULTI] [PERFORMING] multi_done: status: 22 prem: 1 done: 0
            [MULTI] [PERFORMING] multi_done_locked, in use=0
            [MULTI] [PERFORMING] multi_done, terminating conn #0 to 127.0.0.1:{PORT}, forbid=0, close=1, premature=1, conn_multiplex=0
            [MULTI] [PERFORMING] -> [COMPLETED]
            [MULTI] [COMPLETED] -> [MSGSENT]
            [MULTI] [COMPLETED] removed from multi, mid=1, running=0, total=1"
        ))[..]
    );
}

/// A handle tracing the TCP component.
fn tracing_tcp() -> Easy {
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"tcp");
    e.set_components(Some(components));
    e
}

/// Each send and receive on the connection is traced with what it asked
/// for and what it came to (`cf_socket_send`, `cf_socket_recv`).
#[test]
fn sends_and_receives_are_traced_as_c() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_tcp(), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let lines: Vec<String> = ran
        .seen
        .text()
        .into_iter()
        .filter(|l| l.starts_with("[TCP] "))
        .map(|l| l.trim_end().to_owned())
        .collect();
    let request = request_of("/").len();
    let reply = OK.len();
    assert_eq!(
        lines,
        [
            format!("[TCP] send(len={request}) -> 0, {request}"),
            // The buffer's size, the library's default.
            format!("[TCP] recv(len=16384) -> 0, {reply}"),
        ]
    );
}
