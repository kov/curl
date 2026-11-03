//! The HTTPS connect filter's trace (`cf-https-connect.c`), with the
//! chain it heads, the lookup of the origin's HTTPS record and the timer
//! it arms while the record is to come (`EXPIRE_ALPN_EYEBALLS`). Each
//! expected sequence is the C build's with `--http1.1`, which offers
//! HTTP/1.1 alone, as this build does; its ports the test's.

use super::*;
use crate::components::Components;
use crate::libraries::{Libraries, Library, SharedLibraries};
use crate::options::IpVersion;
use crate::tls::fake::{self, FakeTls, WELCOME};

/// A handle with the test's fake TLS library, tracing `components`.
fn tracing(components: &[u8]) -> Easy {
    let (_, libraries) = super::tls::tls();
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let c = Components::new().unwrap();
    c.configure(components);
    e.set_components(Some(c));
    e
}

/// The lines a run traced that start with one of `starts`, the times
/// and the multi's waits left out.
fn lines(ran: &Ran, starts: &[&str]) -> Vec<String> {
    ran.seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| starts.iter().any(|s| l.starts_with(s)))
        .filter(|l| !l.contains("] pollset[") && !l.contains("] multi_wait("))
        .filter(|l| !l.contains("[PGRS-") && !l.contains("expires in"))
        .filter(|l| !l.contains("gives multi timeout"))
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

/// A GET of `url` by `e` over `m`, its server answering through the fake
/// TLS library, over IPv4 alone.
fn https_get(m: &mut Multi, e: Easy, url: &str, set: impl FnOnce(&mut Options)) -> Ran {
    let url = url.to_owned();
    get_with(m, e, "/", Conversation::replies(&[], false), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.ip_version = IpVersion::V4;
        set(o);
    })
}

/// A server at `PORT` that answers a TLS handshake and then `OK` on each
/// of `n` connections, closing after it.
fn tls_server(n: usize) -> Multi {
    let response = fake::records(OK).unwrap();
    let talks: Vec<Conversation> = (0..n)
        .map(|_| Conversation::replies(&[WELCOME, &response], true))
        .collect();
    let talks: Vec<&Conversation> = talks.iter().collect();
    serving(Peer::Accepts, &talks)
}

/// For an address, no record is asked for: the chain has one DNS filter,
/// and the filter knows at once there is none, says so for its second
/// attempt and arms no timer.
#[test]
fn an_https_setup_to_an_address_asks_for_no_record() {
    let mut m = tls_server(1);
    let e = tracing(b"multi,setup,https-connect,timer");
    let ran = https_get(&mut m, e, &format!("https://127.0.0.1:{PORT}/"), |_| {});
    assert_eq!(ran.result, Ok(()));
    let got = lines(
        &ran,
        &["[HTTPS-CONNECT]", "[TIMER] [ALPN", "[MULTI] [CONNECTING] c"],
    );
    // The fake's handshake is answered whole as the connect is seen.
    let want = expect(
        "[HTTPS-CONNECT] added
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h1 from wanted versions
        [HTTPS-CONNECT] HTTPS-RR not available
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [HTTPS-CONNECT] connect -> 0, done=0
        [HTTPS-CONNECT] adjust_pollset -> 0, 1 socks
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!HAPPY-EYEBALLS]
        [MULTI] [CONNECTING] cf_setup_connect [0][!DNS][!HTTPS-CONNECT][!SETUP][!SSL][HAPPY-EYEBALLS][TCP]
        [HTTPS-CONNECT] connect -> 0, done=1
        [MULTI] [CONNECTING] connected [0][DNS][HTTPS-CONNECT][SETUP][SSL][HAPPY-EYEBALLS][TCP]
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy",
    );
    assert_eq!(got, want);
}

/// A resolve of the library [`Ares`] stands for: a name's addresses,
/// 127.0.0.1, at once, as c-ares answers `localhost` from the hosts file,
/// or `late`, as a DNS server answers, at the third run; its record at
/// the run `record_at` says, none or `alpn=http/1.1` as it says; the two
/// runs before the third just as it starts.
#[derive(Debug)]
struct AresResolve {
    record: bool,
    late: bool,
    record_at: u32,
    with_alpn: bool,
    performed: u32,
}

impl crate::conn::io::DnsResolve for AresResolve {
    fn perform(&mut self) -> Result<(), curl_alloc::OutOfMemory> {
        self.performed += 1;
        Ok(())
    }
    fn wants(&self) -> &[(Box<dyn crate::conn::io::Socket>, crate::conn::io::Events)] {
        &[]
    }
    fn due(&self, within: std::time::Duration) -> std::time::Duration {
        within
    }
    fn partial(&self) -> Result<crate::conn::io::Partial, curl_alloc::OutOfMemory> {
        // AAAA is not asked for over IPv4 alone.
        Ok(crate::conn::io::Partial {
            addrs: Vec::new(),
            v6_answered: true,
            v4_answered: false,
        })
    }
    fn ongoing(&self) -> (u32, &'static str) {
        let at = if self.record { self.record_at } else { 3 };
        if (self.record || self.late) && self.performed < at {
            (1, "-")
        } else {
            (0, "A")
        }
    }
    fn answer(&mut self) -> Option<Result<Vec<std::net::IpAddr>, crate::conn::io::ResolveFailure>> {
        (!self.record && (!self.late || self.performed >= 3))
            .then(|| Ok(vec![std::net::IpAddr::from([127, 0, 0, 1])]))
    }
    fn record(&mut self) -> Option<crate::doh::RecordAnswer> {
        if self.performed < self.record_at {
            None
        } else if self.with_alpn {
            let rdata = b"\x00\x01\x00\x00\x01\x00\x09\x08http/1.1";
            let record = crate::doh::decode_https_record(rdata).unwrap();
            Some(crate::doh::RecordAnswer::Record(record))
        } else {
            Some(crate::doh::RecordAnswer::NoSuchName)
        }
    }
    fn explain(&self) -> Option<&'static str> {
        None
    }
    fn status(&self) -> i32 {
        // `ARES_ENODATA`.
        1
    }
}

/// A resolver library standing for c-ares, the reference build's: its
/// addresses late if it says so, its record at the run it says, with an
/// ALPN if it says so.
#[derive(Debug)]
struct Ares {
    late: bool,
    record_at: u32,
    with_alpn: bool,
}

impl crate::conn::io::DnsLibrary for Ares {
    fn resolve(
        &self,
        ask: crate::conn::io::DnsAsk<'_>,
        _: &mut crate::conn::io::DnsSay<'_>,
    ) -> Result<Box<dyn crate::conn::io::DnsResolve>, crate::conn::io::DnsRefused> {
        Ok(Box::new(AresResolve {
            record: ask.family.is_none(),
            late: self.late,
            record_at: self.record_at,
            with_alpn: self.with_alpn,
            performed: 0,
        }))
    }
}

/// A handle as [`tracing`]'s, resolving through [`Ares`].
fn tracing_over_ares(components: &[u8]) -> Easy {
    tracing_over(
        &Ares {
            late: false,
            record_at: 3,
            with_alpn: false,
        },
        components,
    )
}

/// The same, resolving through `ares`.
fn tracing_over(ares: &'static Ares, components: &[u8]) -> Easy {
    let tls: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(tls)),
        dns: Some(ares),
        ..Libraries::NONE
    })
    .unwrap();
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let c = Components::new().unwrap();
    c.configure(components);
    e.set_components(Some(c));
    e
}

/// For a name, the record is asked for as the setup's first connect
/// starts, and the timer armed as the attempt starts, with half the
/// happy eyeballs delay; the record is looked for in the cache as the
/// resolve starts, again right after (`Curl_resolv_take_result`), and once
/// more as the answer, none, comes at the next connect and is kept; the
/// timer stays until the transfer completes. The next setup for the name
/// finds the record kept and arms nothing. C's tool over c-ares traces
/// the same lines for `https://localhost:PORT/` twice in one run.
#[test]
fn an_https_setup_to_a_name_waits_for_its_record_once() {
    let mut m = tls_server(2);
    let url = format!("https://localhost:{PORT}/");
    let e = tracing_over_ares(b"multi,https-connect,timer,dns");
    let first = https_get(&mut m, e, &url, |_| {});
    assert_eq!(first.result, Ok(()));
    let starts = [
        "[HTTPS-CONNECT]",
        "[TIMER] [ALPN",
        "[DNS] c",
        "Hostname",
        "HTTPS-RR",
    ];
    let got = lines(&first, &starts);
    let want = expect(&format!(
        "[HTTPS-CONNECT] added
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache lookup localhost:{PORT} queries=A -> 0 not found
        [DNS] cached entry for localhost:{PORT} queries=A
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h1 from wanted versions
        [TIMER] [ALPN_EYEBALLS] set for 100000us
        [HTTPS-CONNECT] connect -> 0, done=0
        [HTTPS-CONNECT] adjust_pollset -> 0, 1 socks
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache negative name resolve for localhost:{PORT} type=HTTPS
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] connect -> 0, done=1
        [DNS] connected filter chain below
        [DNS] connected filter chain below
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy"
    ));
    assert_eq!(got, want);
    let text = first.seen.text();
    let chain = text.iter().find(|l| l.contains("connected [")).unwrap();
    assert_eq!(
        chain,
        "[MULTI] [CONNECTING] connected [0][DNS][DNS][HTTPS-CONNECT][SETUP][SSL][HAPPY-EYEBALLS][TCP]\n"
    );
    assert!(
        text.iter()
            .any(|l| l == "[MULTI] [COMPLETED] [TIMEOUT] all cleared\n"),
        "the timer stays to the end"
    );
    let e = tracing_over_ares(b"https-connect,timer,dns");
    let second = https_get(&mut m, e, &url, |_| {});
    assert_eq!(second.result, Ok(()));
    let got = lines(&second, &starts);
    let want = expect(&format!(
        "[HTTPS-CONNECT] added
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 found
        Hostname localhost was found in DNS cache
        HTTPS-RR localhost:{PORT}: -
        [DNS] cache lookup localhost:{PORT} queries=A -> 0 found
        Hostname localhost was found in DNS cache
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h1 from wanted versions
        [HTTPS-CONNECT] HTTPS-RR not available"
    ));
    assert_eq!(got[..want.len()], want);
    assert!(
        !got.iter().any(|l| l.starts_with("[TIMER] [ALPN")),
        "{got:?}"
    );
}

/// A name's record and its addresses answered by the same connect, after
/// the first attempt started: both are taken, the record's first, before
/// the HTTPS connect filter chooses the second attempt by the record, as
/// the chain's DNS filters head it (`cf_dns_connect` above
/// `cf_hc_connect`). C's tool over c-ares, a DNS server answering the
/// name, traces the same.
#[test]
fn a_record_and_addresses_come_together_are_taken_before_the_second_is_chosen() {
    static LATE: Ares = Ares {
        late: true,
        record_at: 3,
        with_alpn: false,
    };
    let mut m = tls_server(1);
    let url = format!("https://name.test:{PORT}/");
    let e = tracing_over(&LATE, b"https-connect,dns");
    let ran = https_get(&mut m, e, &url, |_| {});
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    let got = lines(
        &ran,
        &[
            "[HTTPS-CONNECT] connect, init",
            "[HTTPS-CONNECT] HTTPS-RR",
            "[HTTPS-CONNECT] 1st",
            "[DNS] cache",
            "[DNS] [A] resolve",
        ],
    );
    let want = expect(&format!(
        "[DNS] cache lookup name.test:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache lookup name.test:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache lookup name.test:{PORT} queries=A -> 0 not found
        [DNS] [A] resolve incomplete, responses=-, ongoing=1 for name.test:{PORT}
        [DNS] cache lookup name.test:{PORT} queries=A -> 0 not found
        [DNS] [A] resolve incomplete, responses=-, ongoing=1 for name.test:{PORT}
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h1 from wanted versions
        [DNS] cache lookup name.test:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache negative name resolve for name.test:{PORT} type=HTTPS
        [DNS] cache lookup name.test:{PORT} queries=A -> 0 not found
        [DNS] [A] resolve complete for name.test:{PORT}
        [DNS] cached entry for name.test:{PORT} queries=A
        [HTTPS-CONNECT] HTTPS-RR not available"
    ));
    assert_eq!(got, want, "{got:#?}");
}

/// A name's record the library has at the start's first look is taken
/// inside the start, as C's `hostip_resolv_start` takes it on
/// `CURLE_AGAIN`: the take's line, `resolve complete`, its resolve's record
/// destroyed, `started -> 0`, then the record kept and said, before the
/// addresses are asked for; none, it is kept as none after `started -> 6`.
/// C's tool over c-ares, a DNS server answering the record at once, was
/// seen to trace the first so.
#[test]
fn a_record_had_at_the_start_s_first_look_is_taken_inside_the_start() {
    static FIRST: Ares = Ares {
        late: false,
        record_at: 1,
        with_alpn: true,
    };
    static NONE_FIRST: Ares = Ares {
        late: false,
        record_at: 1,
        with_alpn: false,
    };
    let starts = [
        "[DNS] cache",
        "[DNS] [HTTPS] ares",
        "[DNS] [HTTPS] resolve",
        "[DNS] [HTTPS] hostip_resolv started",
        "[DNS] [1]",
        "HTTPS-RR",
    ];
    let mut m = tls_server(1);
    let url = format!("https://localhost:{PORT}/");
    let ran = https_get(&mut m, tracing_over(&FIRST, b"dns"), &url, |_| {});
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    let want = expect(&format!(
        "[DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] [HTTPS] ares_take_result, result=0, ares_result=0, ares_status=1, dns=found
        [DNS] [HTTPS] resolve complete for localhost:{PORT}
        [DNS] [1] destroy async
        [DNS] [HTTPS] hostip_resolv started -> 0
        [DNS] cached entry for localhost:{PORT} queries=HTTPS
        HTTPS-RR localhost:{PORT}: 1 . alpn=http/1.1
        [DNS] cache lookup localhost:{PORT} queries=A -> 0 not found"
    ));
    let got = lines(&ran, &starts);
    assert_eq!(got[..want.len()], want, "{got:#?}");
    let mut m = tls_server(1);
    let ran = https_get(&mut m, tracing_over(&NONE_FIRST, b"dns"), &url, |_| {});
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    let want = expect(&format!(
        "[DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] [HTTPS] ares_take_result, result=6, ares_result=0, ares_status=1, dns=not found
        [DNS] [1] destroy async
        [DNS] [HTTPS] hostip_resolv started -> 6
        [DNS] cache negative name resolve for localhost:{PORT} type=HTTPS
        [DNS] cache lookup localhost:{PORT} queries=A -> 0 not found"
    ));
    let got = lines(&ran, &starts);
    assert_eq!(got[..want.len()], want, "{got:#?}");
}

/// The lines of `ran` about its resolves' records, with what they follow:
/// the DNS filters connecting and the transfer done.
fn asyncs(seen: &Seen) -> Vec<String> {
    seen.text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            l.ends_with(" async")
                || l == "[DNS] connected filter chain below"
                || l.contains("multi_done: status")
        })
        .collect()
}

/// Each resolve that answers later is numbered by the multi and kept on
/// the handle until C lets it go: the addresses' as their filter
/// connects, then the record's (`cf_dns_connect`); every one still kept
/// told it is not wanted as a transfer that failed is done, the newest
/// first (`Curl_resolv_shutdown_all`), and let go of as the next request
/// on the handle starts (`Curl_req_hard_reset`), the handle is reset, or it
/// is let go of (`Curl_close`). C's tool over c-ares, a DNS server answering the names,
/// traces the same: to a server that answers, to a port that refuses,
/// again with `--retry`, and to another name.
#[test]
fn resolves_are_let_go_of_where_c_lets_them_go() {
    static LATE: Ares = Ares {
        late: true,
        record_at: 3,
        with_alpn: false,
    };
    let mut m = tls_server(1);
    let get = |m: &mut Multi, e: Easy, url: String| https_get(m, e, &url, |_| {});
    let e = tracing_over(&LATE, b"dns,multi");
    let up = get(&mut m, e, format!("https://name.test:{PORT}/"));
    assert_eq!(up.result, Ok(()), "{:#?}", up.seen.text());
    assert_eq!(
        asyncs(&up.seen),
        expect(
            "[DNS] connected filter chain below
            [DNS] [2] destroy async
            [DNS] connected filter chain below
            [DNS] [1] destroy async
            [MULTI] [DONE] multi_done: status: 0 prem: 0 done: 0"
        )
    );
    // Refused: both kept past the transfer.
    let refused = PORT + 1;
    let e = tracing_over(&LATE, b"dns,multi");
    let failed = get(&mut m, e, format!("https://name.test:{refused}/"));
    assert_eq!(failed.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(
        asyncs(&failed.seen),
        expect(
            "[MULTI] [CONNECTING] multi_done: status: 7 prem: 1 done: 0
            [DNS] [4] shutdown async
            [DNS] [3] shutdown async"
        )
    );
    // Its next request, everything found in the cache now, lets them go
    // as it starts.
    let again = get(&mut m, failed.easy, format!("https://name.test:{refused}/"));
    assert_eq!(again.result, Err(ErrorKind::CouldntConnect));
    assert_eq!(
        asyncs(&again.seen),
        expect(
            "[DNS] [4] destroy async
            [DNS] [3] destroy async
            [MULTI] [CONNECTING] multi_done: status: 7 prem: 1 done: 0"
        )
    );
    // A handle let go of lets go of those it still keeps.
    let e = tracing_over(&LATE, b"dns,multi");
    let other = get(&mut m, e, format!("https://other.test:{refused}/"));
    let seen = other.seen.clone();
    drop(other);
    assert_eq!(
        asyncs(&seen),
        expect(
            "[MULTI] [CONNECTING] multi_done: status: 7 prem: 1 done: 0
            [DNS] [6] shutdown async
            [DNS] [5] shutdown async
            [DNS] [6] destroy async
            [DNS] [5] destroy async"
        )
    );
    // So does one reset, through the handlers it had (`curl_easy_reset`).
    let e = tracing_over(&LATE, b"dns,multi");
    let mut reset = get(&mut m, e, format!("https://reset.test:{refused}/"));
    reset.easy.reset();
    assert_eq!(
        asyncs(&reset.seen),
        expect(
            "[MULTI] [CONNECTING] multi_done: status: 7 prem: 1 done: 0
            [DNS] [8] shutdown async
            [DNS] [7] shutdown async
            [DNS] [8] destroy async
            [DNS] [7] destroy async"
        )
    );
}

/// The threaded resolver resolves no record: each setup for a name looks
/// for it in the cache as it starts the resolve and again right after,
/// goes on without it and keeps nothing, arming no timer, as C's threaded
/// build traces two GETs of `https://localhost:PORT/` in one run.
#[cfg(feature = "threaded-resolver")]
#[test]
fn an_https_setup_to_a_name_goes_on_without_a_record_never_answered() {
    let mut m = tls_server(2);
    let url = format!("https://localhost:{PORT}/");
    let starts = [
        "[HTTPS-CONNECT]",
        "[TIMER] [ALPN",
        "[DNS] c",
        "Hostname",
        "HTTPS-RR",
    ];
    let e = tracing(b"multi,https-connect,timer,dns");
    let first = https_get(&mut m, e, &url, |_| {});
    assert_eq!(first.result, Ok(()));
    let got = lines(&first, &starts);
    let want = expect(&format!(
        "[HTTPS-CONNECT] added
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache lookup localhost:{PORT} queries=A -> 0 not found
        [DNS] cached entry for localhost:{PORT} queries=A
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h1 from wanted versions
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] connect -> 0, done=0
        [HTTPS-CONNECT] adjust_pollset -> 0, 1 socks
        [HTTPS-CONNECT] connect -> 0, done=1
        [DNS] connected filter chain below
        [DNS] connected filter chain below
        [HTTPS-CONNECT] removing connected setup filter
        [HTTPS-CONNECT] destroy"
    ));
    assert_eq!(got, want);
    let e = tracing(b"https-connect,timer,dns");
    let second = https_get(&mut m, e, &url, |_| {});
    assert_eq!(second.result, Ok(()));
    let got = lines(&second, &starts);
    let want = expect(&format!(
        "[HTTPS-CONNECT] added
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache lookup localhost:{PORT} queries=HTTPS -> 0 not found
        [DNS] cache lookup localhost:{PORT} queries=A -> 0 found
        Hostname localhost was found in DNS cache
        [HTTPS-CONNECT] connect, init
        [HTTPS-CONNECT] HTTPS-RR not available
        [HTTPS-CONNECT] 1st attempt uses h1 from wanted versions
        [HTTPS-CONNECT] HTTPS-RR not available"
    ));
    assert_eq!(got[..want.len()], want, "{got:#?}");
    assert!(
        !got.iter().any(|l| l.starts_with("[TIMER] [ALPN")),
        "{got:?}"
    );
}

/// Without ALPN there is no HTTPS connect filter: the setup filter heads
/// the chain, as for plain HTTP (`Curl_cf_https_setup`).
#[test]
fn an_https_setup_without_alpn_has_no_https_connect_filter() {
    let mut m = tls_server(1);
    let e = tracing(b"multi,setup,https-connect,timer");
    let url = format!("https://localhost:{PORT}/");
    let ran = https_get(&mut m, e, &url, |o| {
        o.tls.options.make_mut().unwrap().alpn = false;
    });
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    assert!(
        !text
            .iter()
            .any(|l| l.contains("HTTPS-CONNECT") || l.contains("ALPN_")),
        "{text:?}"
    );
    assert_eq!(
        text.iter()
            .find(|l| l.ends_with("] added\n"))
            .map(String::as_str),
        Some("[SETUP] added\n")
    );
}

/// A failed attempt fails the filter, which says so, and the chain the
/// failure names ends with it, as it holds its attempt apart.
#[test]
fn a_failed_https_setup_names_the_chain_to_its_filter() {
    let mut m = serving(Peer::Refuses, &[]);
    let e = tracing(b"multi,https-connect");
    let ran = https_get(&mut m, e, &format!("https://localhost:{PORT}/"), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let got = lines(
        &ran,
        &["[HTTPS-CONNECT] connect", "[MULTI] [CONNECTING] failed"],
    );
    assert_eq!(
        got,
        expect(
            "[HTTPS-CONNECT] connect, init
            [HTTPS-CONNECT] connect -> 0, done=0
            [HTTPS-CONNECT] connect, all attempts failed
            [HTTPS-CONNECT] connect -> 7, done=0
            [MULTI] [CONNECTING] failed to connect [0][!DNS][!DNS][!HTTPS-CONNECT]"
        )
    );
}

/// What was agreed by ALPN is asked of a new connection twice: by the
/// HTTPS connect filter, from the setup filter, as its attempt wins
/// (`baller_connected`), and by HTTP, from the top of the chain, before
/// its first request (`http_check_new_conn`); the TLS filter answers with
/// what its peer chose. A reused connection is not asked.
#[test]
fn what_alpn_agreed_is_asked_of_a_new_connection_only() {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let response = fake::records(OK).unwrap();
    let talk = Conversation::replies(&[WELCOME, &response, &response], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let url = format!("https://127.0.0.1:{PORT}/");
    let e = || {
        let mut e = tracing(b"setup,ssl,https-connect");
        e.set_libraries(libraries.clone());
        e
    };
    let starts = [
        "[SETUP] query",
        "[SSL] query",
        "[HTTPS-CONNECT] connect ->",
        "using",
    ];
    let first = https_get(&mut m, e(), &url, |_| {});
    assert_eq!(first.result, Ok(()));
    assert_eq!(
        lines(&first, &starts),
        expect(
            "[HTTPS-CONNECT] connect -> 0, done=0
            [SETUP] query ALPN
            [SSL] query ALPN: returning 'http/1.1'
            [HTTPS-CONNECT] connect -> 0, done=1
            [SSL] query ALPN
            [SSL] query ALPN: returning 'http/1.1'
            using HTTP/1.x"
        )
    );
    let again = https_get(&mut m, e(), &url, |_| {});
    assert_eq!(again.result, Ok(()));
    assert_eq!(lines(&again, &starts), Vec::<String>::new());
}

/// Each call of the chain's connect is traced by its top filter as it
/// ends, and each of the TLS filter's by it as it begins and ends; the
/// TLS filter puts its socket in the pollset for what its session waits
/// for.
#[test]
fn the_connect_calls_and_the_tls_filter_s_wait_are_traced() {
    let response = fake::records(OK).unwrap();
    let talk = Conversation::replies(&[WELCOME, &response], true).late_replies();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let e = tracing(b"ssl,dns");
    let ran = https_get(&mut m, e, &format!("https://127.0.0.1:{PORT}/"), |_| {});
    assert_eq!(ran.result, Ok(()));
    let starts = [
        "[SSL] cf_connect",
        "[SSL] adjust",
        "[DNS] Curl_conn_connect",
    ];
    assert_eq!(
        lines(&ran, &starts),
        expect(
            "[DNS] Curl_conn_connect(block=0) -> 0, done=0
            [SSL] cf_connect()
            [SSL] cf_connect() -> 0, done=0
            [DNS] Curl_conn_connect(block=0) -> 0, done=0
            [SSL] adjust_pollset, POLLIN fd=1000
            [SSL] cf_connect()
            [SSL] cf_connect() -> 0, done=1
            [DNS] Curl_conn_connect(block=0) -> 0, done=1
            [SSL] adjust_pollset, POLLIN fd=1000"
        )
    );
}

/// A newest version allowed older than the oldest fails the TLS filter's
/// first connect, before its session's handshake starts
/// (`ssl_prefs_check`), and the chain's connect with it.
#[test]
fn versions_that_allow_none_fail_the_tls_filter_s_connect() {
    let talk = Conversation::replies(&[WELCOME], true);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let e = tracing(b"ssl,dns");
    let ran = https_get(&mut m, e, &format!("https://127.0.0.1:{PORT}/"), |o| {
        let tls = o.tls.options.make_mut().unwrap();
        tls.min_version = crate::options::TlsMinVersion::Tls1_3;
        tls.max_version = crate::options::TlsMaxVersion::Tls1_2;
    });
    assert_eq!(ran.result, Err(ErrorKind::SslConnectError));
    let starts = [
        "[SSL] cf_connect",
        "CURL_SSLVERSION",
        "[DNS] Curl_conn_connect",
    ];
    let got = lines(&ran, &starts);
    assert_eq!(
        got[got.len() - 5..],
        expect(
            "[SSL] cf_connect()
            CURL_SSLVERSION_MAX incompatible with CURL_SSLVERSION
            [SSL] cf_connect() -> 35, done=0
            [DNS] Curl_conn_connect(block=0) -> 35, done=0
            [DNS] Curl_conn_connect(), filter returned 35"
        )
    );
    assert_eq!(talk.received(), b"", "no hello sent");
}

/// The replies of an HTTPS proxy that tunnels, its handshake first; and
/// through the tunnel, the origin's: with TLS if `tls`, else in the
/// clear.
fn https_proxy_tunnel(tls: bool) -> Conversation {
    let established = fake::records(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
    if tls {
        let inner_welcome = fake::records(WELCOME).unwrap();
        let response = fake::records(&fake::records(OK).unwrap()).unwrap();
        Conversation::replies(&[WELCOME, &established, &inner_welcome, &response], true)
    } else {
        let response = fake::records(OK).unwrap();
        Conversation::replies(&[WELCOME, &established, &response], true)
    }
}

/// A GET of `url` through an HTTPS proxy that tunnels, by a handle of
/// the fake library `libraries` tracing all, the lines it traced, each
/// without its transfer's and connection's numbers.
fn through_https_proxy(
    libraries: &SharedLibraries,
    url: &str,
    talk: &Conversation,
    set: impl FnOnce(&mut Options),
) -> Vec<String> {
    let mut m = serving(Peer::Accepts, &[talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let c = Components::new().unwrap();
    c.configure(b"all");
    e.set_components(Some(c));
    let ran = https_get(&mut m, e, url, |o| {
        let proxy = format!("https://127.0.0.1:{PORT}");
        o.proxy.make_mut().unwrap().url = Some(proxy.into_bytes());
        set(o);
    });
    assert_eq!(ran.result, Ok(()));
    ran.seen
        .text()
        .into_iter()
        .map(|l| {
            l.trim_end()
                .split_once("] ")
                .map_or(&*l, |(_, l)| l)
                .to_owned()
        })
        .collect()
}

/// HTTPS through an HTTPS proxy, as C traces its setup: the proxy's TLS
/// and the tunnel's filter added together, the TLS made before the
/// CONNECT, the origin's TLS added once the tunnel is up; the tunnel's
/// answer read a byte at a time through the proxy's TLS
/// (`recv_CONNECT_resp`), so that nothing past it leaves the session.
#[test]
fn tls_in_tls_sets_up_as_c() {
    let (backend, libraries) = super::tls::tls();
    let talk = https_proxy_tunnel(true);
    let got = through_https_proxy(&libraries, "https://origin.example/", &talk, |_| {});
    let picked: Vec<&str> = got
        .iter()
        .map(String::as_str)
        .filter(|l| {
            l.starts_with("[SETUP] added ")
                || l.starts_with("[SSL-PROXY] cf_connect()")
                || l.starts_with("[SSL] cf_connect()")
                || l.starts_with("Establishing")
                || l.contains("query ALPN")
                || l.starts_with("using")
                || l.starts_with("CONNECT")
        })
        .collect();
    assert_eq!(
        picked,
        [
            "[SETUP] added SSL filter for HTTP proxy",
            "[SETUP] added HTTP proxy tunnel filter",
            "[SSL-PROXY] cf_connect()",
            "[SSL-PROXY] cf_connect() -> 0, done=1",
            "[SSL-PROXY] query ALPN",
            "[SSL-PROXY] query ALPN: returning '(nil)'",
            "CONNECT: no ALPN negotiated",
            "Establishing HTTP proxy tunnel to origin.example:443",
            "CONNECT phase completed for HTTP proxy",
            "CONNECT tunnel established, response 200",
            "[SETUP] added SSL filter for origin",
            "[SSL] cf_connect()",
            "[SSL] cf_connect() -> 0, done=1",
            "[SETUP] query ALPN",
            "[SSL] query ALPN: returning '(nil)'",
            "[SSL] query ALPN",
            "[SSL] query ALPN: returning '(nil)'",
            "using HTTP/1.x",
        ],
        "{got:#?}"
    );
    // The answer's bytes, each asked of the proxy's session alone, the
    // first reads made of a session (the log keeps 32).
    assert_eq!(backend.log().asked(), [1; 32]);
}

/// Plain HTTP tunneled through an HTTPS proxy: the tunnel's filter,
/// asked what ALPN agreed, keeps the question (`cf_h1_proxy_query`), so
/// the proxy's TLS below it, which answered for the CONNECT, says
/// nothing.
#[test]
fn a_tunnel_through_an_https_proxy_keeps_the_alpn_question() {
    let (_, libraries) = super::tls::tls();
    let talk = https_proxy_tunnel(false);
    let url = format!("http://127.0.0.1:{PORT}/");
    let got = through_https_proxy(&libraries, &url, &talk, |o| {
        o.proxy.make_mut().unwrap().tunnel = true
    });
    let picked: Vec<&str> = got
        .iter()
        .map(String::as_str)
        .filter(|l| {
            l.contains("query ALPN") || l.starts_with("using") || l.starts_with("[SETUP] added ")
        })
        .collect();
    assert_eq!(
        picked,
        [
            "[SETUP] added SSL filter for HTTP proxy",
            "[SETUP] added HTTP proxy tunnel filter",
            "[SSL-PROXY] query ALPN",
            "[SSL-PROXY] query ALPN: returning '(nil)'",
            "[H1-PROXY] query ALPN",
            "using HTTP/1.x",
        ],
        "{got:#?}"
    );
}

/// Plain HTTP sent whole to an HTTPS proxy, no tunnel: the proxy's TLS is
/// added as the origin's filter is, and said so, with no tunnel's filter
/// (the C build's `--trace-config all` through such a proxy says `added
/// SSL filter for origin`, its chain `[SSL-PROXY]`).
#[test]
fn an_https_proxy_sent_requests_whole_adds_its_tls_as_the_origin_s() {
    let (_, libraries) = super::tls::tls();
    let response = fake::records(OK).unwrap();
    let talk = Conversation::replies(&[WELCOME, &response], true);
    let url = format!("http://127.0.0.1:{PORT}/");
    let got = through_https_proxy(&libraries, &url, &talk, |_| {});
    let picked: Vec<&str> = got
        .iter()
        .map(String::as_str)
        .filter(|l| l.starts_with("[SETUP] added ") || l.contains("reduced to"))
        .collect();
    assert_eq!(
        picked,
        [
            "[SETUP] added SSL filter for origin",
            "[MULTI] [CONNECTING] reduced to [0][SSL-PROXY][TCP]",
        ],
        "{got:#?}"
    );
}

/// The request follows an HTTP proxy's `CONNECT`, so once the tunnel is
/// up what reads it starts over, after the tunnel is said to be
/// established (`cf_h1_proxy_connect`'s `Curl_client_reset`); before
/// and after it, the request's own start and end.
#[test]
fn the_readers_start_over_once_an_http_proxy_s_tunnel_is_up() {
    let (_, libraries) = super::tls::tls();
    let talk = https_proxy_tunnel(false);
    let url = format!("http://127.0.0.1:{PORT}/");
    let got = through_https_proxy(&libraries, &url, &talk, |o| {
        o.proxy.make_mut().unwrap().tunnel = true
    });
    let picked: Vec<&str> = got
        .iter()
        .map(String::as_str)
        .filter(|l| l.starts_with("CONNECT") || l.starts_with("[READ] client_reset"))
        .collect();
    assert_eq!(
        picked,
        [
            "[READ] client_reset, clear readers",
            "CONNECT: no ALPN negotiated",
            "CONNECT phase completed for HTTP proxy",
            "CONNECT tunnel established, response 200",
            "[READ] client_reset, clear readers",
            "[READ] client_reset, clear readers",
        ],
        "{got:#?}"
    );
}

/// A proxy whose TLS agrees to the protocol offered names the tunnel's
/// protocol by it (`http_proxy_cf_connect`): "CONNECT: 'http/1.1'
/// negotiated" in place of "no ALPN negotiated".
#[test]
fn a_tunnel_says_the_protocol_its_proxy_negotiated() {
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    let talk = https_proxy_tunnel(true);
    let got = through_https_proxy(&libraries, "https://origin.example/", &talk, |_| {});
    let connect: Vec<&str> = got
        .iter()
        .map(String::as_str)
        .filter(|l| l.starts_with("CONNECT:"))
        .collect();
    assert_eq!(connect, ["CONNECT: 'http/1.1' negotiated"], "{got:?}");
}

/// An HTTPS setup to a name has two DNS filters, the record's added
/// above the addresses', which is not: each made as the chain is set up,
/// each started as its first connect reaches it, the record's first, and
/// both told the chain below connected and gone once it is. The C build
/// traces the same lines (`cf_dns_create`, `cf_dns_start`).
#[test]
fn an_https_setup_to_a_name_has_the_record_s_dns_filter_and_the_addresses() {
    let mut m = tls_server(1);
    let url = format!("https://localhost:{PORT}/");
    let e = tracing(b"https-connect,dns");
    let ran = https_get(&mut m, e, &url, |_| {});
    assert_eq!(ran.result, Ok(()));
    let starts = [
        "[DNS] [HTTPS] c",
        "[DNS] [A] c",
        "[DNS] added",
        "[DNS] connected",
        "[DNS] removing",
        "[DNS] destroy",
        "[HTTPS-CONNECT] added",
    ];
    let want = expect(&format!(
        "[HTTPS-CONNECT] added
        [DNS] [HTTPS] created DNS filter for localhost:{PORT}, transport=3
        [DNS] added
        [DNS] [A] created DNS filter for localhost:{PORT}, transport=3
        [DNS] [HTTPS] cf_dns_start host localhost:{PORT}
        [DNS] [A] cf_dns_start host localhost:{PORT}
        [DNS] connected filter chain below
        [DNS] connected filter chain below
        [DNS] removing connected setup filter
        [DNS] destroy
        [DNS] removing connected setup filter
        [DNS] destroy"
    ));
    assert_eq!(lines(&ran, &starts), want);
}
