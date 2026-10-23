//! The timer component's trace (`CURL_TRC_TIMER`): each timer armed,
//! with what is left of its wait as it is armed, and cleared, in the
//! places C arms and clears it. Each expected sequence is the C build's
//! for the same transfer; the clock stands still, so the waits are whole.

use super::*;
use crate::components::Components;

/// A handle tracing `components`.
fn tracing(components: &[u8]) -> Easy {
    let mut e = Easy::new();
    let c = Components::new().unwrap();
    c.configure(components);
    e.set_components(Some(c));
    e
}

/// The lines of the components named a run traced, the times blanked.
fn lines_of(ran: &Ran, names: &[&str]) -> Vec<String> {
    ran.seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| names.iter().any(|n| l.starts_with(n)) || l.starts_with("upload completely"))
        .map(|l| match l.find(" added ").filter(|_| l.ends_with("us")) {
            Some(at) => format!("{} added Nus", &l[..at]),
            None => l,
        })
        .collect()
}

/// The leg's limits are armed between its start and CONNECT, and the
/// race's timer cleared as its attempt connects, before the connect time.
#[test]
fn a_leg_arms_its_limits_and_the_race_clears_its_timer() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing(b"timer,multi"), "/", talk, |o| {
        o.limits.connect = crate::time::TimeLimit::from_millis(3000);
    });
    assert_eq!(ran.result, Ok(()));
    let lines = lines_of(&ran, &["[TIMER]", "[MULTI]"]);
    let at = lines
        .iter()
        .position(|l| l.ends_with("[PGRS-STARTSINGLE] set"))
        .unwrap();
    assert_eq!(
        lines[at..at + 4],
        [
            "[MULTI] [SETUP] [PGRS-STARTSINGLE] set",
            "[TIMER] [TIMEOUT] set for 10000000us",
            "[TIMER] [CONNECTTIMEOUT] set for 3000000us",
            "[MULTI] [SETUP] -> [CONNECT]",
        ]
    );
    let at = lines
        .iter()
        .position(|l| l.starts_with("[TIMER] [HAPPY_EYEBALLS]"))
        .unwrap();
    assert_eq!(
        lines[at..at + 2],
        [
            "[TIMER] [HAPPY_EYEBALLS] cleared",
            "[MULTI] [CONNECTING] [PGRS-CONNECT] added Nus",
        ]
    );
    // The wait before the connect is looked at again names each timer
    // armed, the first to fire first, and the one the multi waits for.
    let timers: Vec<_> = lines.iter().filter(|l| l.starts_with("[TIMER]")).collect();
    assert_eq!(
        timers,
        [
            "[TIMER] [TIMEOUT] set for 10000000us",
            "[TIMER] [CONNECTTIMEOUT] set for 3000000us",
            "[TIMER] [CONNECTTIMEOUT] expires in 3000000us",
            "[TIMER] [TIMEOUT] expires in 10000000us",
            "[TIMER] [CONNECTTIMEOUT] gives multi timeout in 3000ms",
            "[TIMER] [HAPPY_EYEBALLS] cleared",
        ]
    );
}

/// A body announced with `Expect: 100-continue` arms the wait once the
/// head has gone; the 100 clears it, and the body's end clears it again
/// (`cr_exp100_done`), after the time the request ended.
#[test]
fn the_wait_for_a_100_is_armed_and_cleared_as_c_does() {
    let continued = [&b"HTTP/1.1 100 Continue\r\n\r\n"[..], OK_EMPTY].concat();
    let (mut m, talk, _) = server(&[&continued], false);
    let ran = get_with(&mut m, tracing(b"timer,multi"), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap(),
        );
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let lines = lines_of(&ran, &["[TIMER] [100", "[MULTI] [PERFORMING] [PGRS-POS"]);
    assert_eq!(
        lines,
        [
            "[TIMER] [100_TIMEOUT] set for 1000000us",
            "[TIMER] [100_TIMEOUT] cleared",
            "[MULTI] [PERFORMING] [PGRS-POSTRANSFER] added Nus",
            "[TIMER] [100_TIMEOUT] cleared",
            "upload completely sent off: 3 bytes",
        ]
    );
}

/// Without a 100, the wait runs out: cleared before it is said.
#[test]
fn a_wait_for_a_100_that_runs_out_is_cleared() {
    let (mut m, talk, clock) = server(&[OK_EMPTY], false);
    let start = clock.now();
    let ran = get_with(&mut m, tracing(b"timer"), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap(),
        );
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
        o.http.continue_wait = crate::options::ContinueWait(Duration::from_millis(300));
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(clock.now().since(start), Duration::from_millis(300));
    let text: Vec<_> = ran
        .seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .collect();
    let at = text
        .iter()
        .position(|l| l == "[TIMER] [100_TIMEOUT] set for 300000us")
        .unwrap();
    // The wait is the one the multi waits for.
    assert_eq!(
        text[at + 1..at + 4],
        [
            "[TIMER] [100_TIMEOUT] gives multi timeout in 300ms",
            "[TIMER] [100_TIMEOUT] cleared",
            "Done waiting for 100-continue"
        ]
    );
}

/// The low-speed check is looked at again a second on, and a receive
/// limit's wait armed for what is left of its step, each time C arms
/// them (`Curl_speedcheck`, `mspeed_check`).
#[test]
fn the_speed_timers_are_armed_with_their_waits() {
    let (mut m, _talks, _clock) = endless_clocked(1);
    let seen = Seen::default();
    let (mut e, drops) = endless_get(|o| {
        o.flow.make_mut().unwrap().max_recv_speed = NonZeroU64::new(RECV_RATE);
        o.flow.make_mut().unwrap().low_speed = Some(crate::options::LowSpeed {
            limit: NonZeroU64::new(1).unwrap(),
            time: std::num::NonZeroU16::new(5).unwrap(),
        });
        o.output.verbose = true;
        o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    });
    let c = Components::new().unwrap();
    c.configure(b"timer");
    e.set_components(Some(c));
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    until_body(&mut m, &drops);
    // The pass's four reads moved the clock 4 ms past the instant both
    // were armed from: the wait left as each is armed is that much short.
    let timers: Vec<_> = seen
        .text()
        .into_iter()
        .filter(|l| l.starts_with("[TIMER]"))
        .collect();
    for want in [
        "[TIMER] [SPEEDCHECK] set for 996000us\n",
        "[TIMER] [TOOFAST] set for 996000us\n",
    ] {
        assert!(timers.iter().any(|l| l == want), "{want}: {timers:?}");
    }
    assert_eq!(m.timeout(), Some(Duration::from_millis(996)));
}
