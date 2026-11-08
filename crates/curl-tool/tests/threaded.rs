//! The threaded resolver's build, against C's (`build/c-threaded`).
#![cfg(feature = "threaded-resolver")]
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::process::Command;

/// An `https` origin's record is asked of the threaded resolver, which
/// answers only for addresses: the setup looks once more as it starts,
/// as C takes the result at once, and goes on without the record,
/// keeping nothing of it. C says the record is not available for each
/// attempt it chooses, one after the other.
#[test]
fn an_origins_record_the_threaded_resolver_cannot_answer_is_not_kept() {
    let run = Command::new(env!("CARGO_BIN_EXE_curl"))
        .args(["-sS", "-v", "-k", "--max-time", "5"])
        .args(["--trace-config", "dns,https-connect"])
        .arg("https://localhost:1/")
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&run.stderr);
    let lines: Vec<&str> = said.lines().collect();
    let at = |want: &str| {
        lines
            .iter()
            .position(|l| *l == want)
            .unwrap_or_else(|| panic!("{want}: {said}"))
    };
    let started = at("* [DNS] [HTTPS] hostip_resolv started -> 81");
    assert_eq!(
        lines[started + 1],
        "* [DNS] cache lookup localhost:1 queries=HTTPS -> 0 not found",
        "{said}"
    );
    let first = at("* [HTTPS-CONNECT] 1st attempt uses h2 from wanted versions");
    assert_eq!(
        lines[first - 1],
        "* [HTTPS-CONNECT] HTTPS-RR not available",
        "{said}"
    );
    assert_eq!(
        lines[first + 1],
        "* [HTTPS-CONNECT] HTTPS-RR not available",
        "{said}"
    );
    assert!(
        !said.contains("cache negative name resolve for localhost:1 type=HTTPS"),
        "{said}"
    );
    let looks = said
        .matches("cache lookup localhost:1 queries=HTTPS")
        .count();
    assert_eq!(looks, 2, "looked at no more: {said}");
}

/// The record's ask is numbered all the same, as C keeps a record of it
/// (`hostip_async_new`): the connect refused, it is told it is not wanted
/// as the transfer is done, and let go of with the handle, as C's
/// threaded build traces them for `https://localhost:1/`.
#[test]
fn the_record_asked_of_the_threaded_resolver_is_let_go_of_as_c_s() {
    let run = Command::new(env!("CARGO_BIN_EXE_curl"))
        .args(["-sS", "-v", "-k", "--max-time", "5"])
        .args(["--trace-config", "dns"])
        .arg("https://localhost:1/")
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&run.stderr);
    let asyncs: Vec<&str> = said.lines().filter(|l| l.ends_with(" async")).collect();
    assert_eq!(
        asyncs,
        ["* [DNS] [1] shutdown async", "* [DNS] [1] destroy async"],
        "{said}"
    );
}

/// The interface's name, resolved blocking as the connection binds, is
/// queued under the number of the record kept of its resolve, the third
/// after the origin's record and its addresses, as C's threaded build
/// says it for `-4 --interface host!localhost4 https://localhost4:1/`.
/// Windows knows no `localhost4`: the machine's own name stands in.
#[test]
fn a_blocking_resolve_is_queued_under_its_record_s_number() {
    let host = if cfg!(windows) {
        std::env::var("COMPUTERNAME").unwrap()
    } else {
        "localhost4".to_owned()
    };
    let run = Command::new(env!("CARGO_BIN_EXE_curl"))
        .args(["-sS", "-v", "-k", "-4", "--max-time", "5"])
        .args(["--trace-config", "dns", "--interface"])
        .arg(format!("host!{host}"))
        .arg(format!("https://{host}:1/"))
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&run.stderr);
    let queued: Vec<&str> = said
        .lines()
        .filter(|l| l.contains("queueing query"))
        .collect();
    assert_eq!(
        queued,
        [
            format!("* [DNS] queueing query [0/2] A {host}:1"),
            format!("* [DNS] queueing query [0/3] A {host}:80"),
        ],
        "{said}"
    );
    assert!(
        said.contains("* [DNS] [3] destroy async\n")
            || said.contains("* [DNS] [3] destroy async\r\n"),
        "{said}"
    );
}

/// A name's resolve is looked at once as it starts, as C's DNS filter
/// takes the result right after starting it (`cf_dns_connect`), and is
/// then left to the resolver's answer: one look, said incomplete, and
/// the wait for AAAA, as C's threaded build says them for
/// `http://localhost4:9/`.
#[cfg(not(windows))]
#[test]
fn a_threaded_resolve_is_looked_at_once_as_it_starts() {
    let run = Command::new(env!("CARGO_BIN_EXE_curl"))
        .args(["-sS", "-v", "--max-time", "5"])
        .args(["--trace-config", "dns"])
        .arg("http://localhost4:9/")
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&run.stderr);
    let lines: Vec<&str> = said.lines().collect();
    let started = lines
        .iter()
        .position(|l| *l == "* [DNS] [A+AAAA] hostip_resolv started -> 81")
        .unwrap_or_else(|| panic!("{said}"));
    assert_eq!(
        lines[started + 1..started + 3],
        [
            "* [DNS] cache lookup localhost4:9 queries=A+AAAA -> 0 not found",
            "* [DNS] [A+AAAA] resolve incomplete, responses=-, ongoing=2 for localhost4:9",
        ],
        "{said}"
    );
    assert!(
        lines[started + 3].starts_with("* [DNS] [A+AAAA] still waiting "),
        "{said}"
    );
    assert_eq!(
        lines[started + 4],
        "* [DNS] Curl_conn_connect(block=0) -> 0, done=0",
        "{said}"
    );
}
