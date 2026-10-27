//! C's HTTPS connect filter (`lib/cf-https-connect.c`), which heads the
//! setup of a connection to an `https` origin: it chooses the HTTP
//! versions its attempts offer by ALPN, from the origin's HTTPS record
//! (HTTPS-RR) and the transfer's wanted versions, and races them. Without
//! HTTP/3 wanted it makes one attempt, offering HTTP/2 and HTTP/1.1 or
//! HTTP/1.1 alone, so the race is its trace and its timer: C arms its
//! wait for a second attempt (`EXPIRE_ALPN_EYEBALLS`) as the attempt
//! starts while the record is still to come.
//!
//! The engine resolves no HTTPS record yet. It asks where the reference
//! build's resolver would: for the origin's name, unless that is an
//! address, as the setup's first connect starts; and it has the answer
//! the resolver gives a name without a record, none, at the setup's next
//! connect, as C's comes back from a local resolver before the first
//! attempt is looked at again. The answer is kept in the DNS cache beside
//! the name's addresses, as C keeps it, so a later setup for the name
//! finds it and arms no timer.

use super::{Connecting, StepCx};
use crate::components::Component;
use crate::conn::{Dial, Tcp};
use crate::conn::{HttpsLookup, address};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::timers::{Deadlines, TimerKind};
use crate::share::Kind;
use crate::trace::{self, Bytes};

/// The HTTPS connect filter heading a setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpsConnect {
    record: Record,
    /// Its first attempt's version, once started (`connect, init`).
    first: Option<Alpn>,
    /// Its second, an HTTP/2-or-1 attempt over TCP after an HTTP/3 one
    /// (`ballers[1]`).
    second: Second,
}

/// The HTTP version an attempt's ALPN offers first (`alpnid`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alpn {
    H3,
    H2,
    H1,
}

impl Alpn {
    fn name(self) -> &'static str {
        match self {
            Alpn::H3 => "h3",
            Alpn::H2 => "h2",
            Alpn::H1 => "h1",
        }
    }
}

/// The second attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Second {
    /// Not chosen until the origin's record is known
    /// (`ballers_complete`).
    Unchosen,
    /// There is none.
    None,
    /// Chosen, to start as the first fails or at its timeouts.
    Due(Alpn),
    /// Started, and failed if `.1`.
    Started(Alpn, bool),
}

/// Where the origin's HTTPS record is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record {
    /// None is asked for: the origin is an address
    /// (`cf_dns_add_resolve`).
    NotAsked,
    /// To be looked for as the setup's first connect starts.
    Unasked,
    /// Asked for, the answer still to come.
    Pending,
    /// Known: the origin has none (`HTTPS-RR not available`).
    Known,
}

impl HttpsConnect {
    /// The filter a new connection over `route` gets, if any: one to an
    /// `https` origin with ALPN on, which no proxy forwards to
    /// (`Curl_cf_https_setup`).
    pub(super) fn heading(route: &Tcp, alpn: bool) -> Option<HttpsConnect> {
        let https = route.origin.scheme().name == "https";
        let forwarded = route.proxy.as_ref().is_some_and(|p| p.forward);
        if !https || forwarded || !alpn {
            return None;
        }
        let record = if address(route.target().name()).is_some() {
            Record::NotAsked
        } else {
            Record::Unasked
        };
        Some(HttpsConnect {
            record,
            first: None,
            second: Second::Unchosen,
        })
    }

    /// Whether a filter asks for the origin's record, which the chain
    /// shows as a DNS filter of its own above the addresses'.
    pub(crate) fn asks(&self) -> bool {
        self.record != Record::NotAsked
    }
}

/// A connect call of the setup begins (`Curl_conn_connect` from the top
/// of the chain): its first looks for the origin's record, as the
/// filter that asks for it starts (`cf_dns_start`); one after the
/// attempt started has the answer.
pub(super) fn connect_call<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    let Some(h) = c.https.as_mut() else {
        return Ok(());
    };
    match h.record {
        Record::Unasked => {
            h.record = look_up(&c.route, cx);
            Ok(())
        }
        Record::Pending if let Some(first) = h.first => {
            answered(&c.route, cx)?;
            h.record = Record::Known;
            let second = choose_second(c, cx, first);
            c.https.as_mut().expect("the filter heads the setup").second = second;
            Ok(())
        }
        Record::NotAsked | Record::Pending | Record::Known => Ok(()),
    }
}

/// The origin's record looked for in the cache, as C traces it
/// (`hostip_resolv`, `Curl_dnscache_get`): what the setup knows of it.
fn look_up<H: Host>(route: &Tcp, cx: &mut StepCx<'_, H>) -> Record {
    let peer = route.target();
    let (name, port) = (Bytes(peer.name()), peer.port());
    let dns = Component::Dns;
    // The C debug build's line.
    #[cfg(feature = "debug-hooks")]
    trace::of(
        cx,
        dns,
        format_args!("[HTTPS] hostip_resolv({name}:{port})"),
    );
    let max_age = cx.easy().options().limits.reuse.dns_max_age;
    let now = cx.rest.now;
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
    let found = names.section(|d| d.lookup_https((peer.name(), port), max_age, now));
    if found == HttpsLookup::Stale {
        trace::info(cx, format_args!("Hostname in DNS cache was stale, zapped"));
    }
    let not = if found == HttpsLookup::Found {
        ""
    } else {
        "not "
    };
    trace::of(
        cx,
        dns,
        format_args!("cache lookup {name}:{port} queries=HTTPS -> 0 {not}found"),
    );
    if found == HttpsLookup::Found {
        trace::info(cx, format_args!("Hostname {name} was found in DNS cache"));
        trace::info(cx, format_args!("HTTPS-RR {name}:{port}: -"));
        Record::Known
    } else {
        // The resolver answers later (`CURLE_AGAIN`).
        let again = crate::error::AGAIN_NUMBER;
        trace::of(
            cx,
            dns,
            format_args!("[HTTPS] hostip_resolv started -> {again}"),
        );
        Record::Pending
    }
}

/// The resolver's answer came: no record, kept as the name's
/// (`Curl_dnscache_add_negative`).
fn answered<H: Host>(route: &Tcp, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    let peer = route.target();
    let now = cx.rest.now;
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
    names
        .section(|d| d.put_https(peer.name(), peer.port(), now))
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let (name, port) = (Bytes(peer.name()), peer.port());
    trace::of(
        cx,
        Component::Dns,
        format_args!("cache negative name resolve for {name}:{port} type=HTTPS"),
    );
    Ok(())
}

/// HTTP/2 is offered where a library speaks it and the request may.
fn h2_offered<H: Host>(c: &Connecting, cx: &mut StepCx<'_, H>) -> bool {
    c.proto.http_versions(cx.easy().options()).h2 && cx.easy().libraries().h2.is_some()
}

/// The second attempt, as the origin's record is known to be none: the
/// first wanted version other than the first's, HTTP/2 or HTTP/1 after
/// HTTP/3 and none after either of those, as each offers the other
/// (`cf_hc_set_baller2`, `cf_hc_get_first_alpn`).
fn choose_second<H: Host>(c: &Connecting, cx: &mut StepCx<'_, H>, first: Alpn) -> Second {
    let hc = Component::HttpsConnect;
    trace::of(cx, hc, format_args!("HTTPS-RR not available"));
    let h1 = c.proto.http_versions(cx.easy().options()).h1;
    let second = match first {
        Alpn::H3 if h2_offered(c, cx) => Alpn::H2,
        Alpn::H3 if h1 => Alpn::H1,
        Alpn::H3 | Alpn::H2 | Alpn::H1 => return Second::None,
    };
    let name = second.name();
    trace::of(
        cx,
        hc,
        format_args!("2nd attempt uses {name} from wanted versions"),
    );
    Second::Due(second)
}

/// The setup's first attempt starts (`cf_hc_connect`'s INIT): its
/// version chosen, one that a build without HTTP/2 can speak, its second
/// chosen if the record is known, and the wait for the second armed
/// while there may be one.
pub(super) fn start<H: Host>(
    c: &mut Connecting,
    deadlines: &mut Deadlines,
    cx: &mut StepCx<'_, H>,
) {
    if c.https.is_none_or(|h| h.first.is_some()) {
        return;
    }
    let hc = Component::HttpsConnect;
    trace::of(cx, hc, format_args!("connect, init"));
    trace::of(cx, hc, format_args!("HTTPS-RR not available"));
    // The first of the wanted versions it can speak, HTTP/3, HTTP/2,
    // HTTP/1, as its ALPN offers them (`cf_hc_get_first_alpn`): HTTP/3
    // where the plan dials QUIC, which it does where HTTP/3 may be
    // spoken; where it may not, the reason is said as it is looked at.
    let h2 = h2_offered(c, cx);
    let dial = c.lease.setup_route().map_or(c.route.dial, |r| r.dial);
    let first = match dial {
        Dial::Quic => Alpn::H3,
        Dial::Tcp => {
            if c.proto.http_versions(cx.easy().options()).h3
                && let Some((kind, why)) = super::quic_refused(&c.route, true)
            {
                trace::fail(cx, kind, format_args!("{why}"));
            }
            if h2 { Alpn::H2 } else { Alpn::H1 }
        }
    };
    let name = first.name();
    trace::of(
        cx,
        hc,
        format_args!("1st attempt uses {name} from wanted versions"),
    );
    let h = c.https.as_mut().expect("the filter heads the setup");
    h.first = Some(first);
    if h.record != Record::Pending {
        let second = choose_second(c, cx, first);
        c.https.as_mut().expect("the filter heads the setup").second = second;
    }
    let h = c.https.as_mut().expect("the filter heads the setup");
    if h.record == Record::Pending || matches!(h.second, Second::Due(_)) {
        let wait = cx.easy().options().limits.eyeballs.0 / 2;
        super::arm(deadlines, cx, TimerKind::AlpnEyeballs, wait);
    }
}

/// The attempt the lease held failed with `kind`: whether the race
/// outlives it, its other attempt still to start or running, or the
/// record that chooses it still to come; or fails with it, which
/// `all_failed` then says.
pub(super) fn attempt_failed(c: &mut Connecting, kind: ErrorKind) -> bool {
    let (Some(h), Some(race)) = (c.https.as_mut(), c.race.as_mut()) else {
        return false;
    };
    match h.second {
        // The first's, in the lease until the second starts.
        Second::Unchosen | Second::Due(_) => {
            race.first_failed = Some(kind);
            true
        }
        Second::None => false,
        Second::Started(alpn, _) => {
            h.second = Second::Started(alpn, true);
            true
        }
    }
}

/// The first attempt, set aside as the second runs, failed with `kind`.
pub(super) fn first_failed(c: &mut Connecting, kind: ErrorKind) {
    c.race.as_mut().expect("a race of two").first_failed = Some(kind);
}

/// Whether the second attempt starts now, as the first failed or did not
/// answer in time (`time_to_start_baller2`): said, and the hard timeout
/// armed again where the first has answered by the soft one.
pub(super) fn second_due<H: Host>(
    c: &mut Connecting,
    deadlines: &mut Deadlines,
    cx: &mut StepCx<'_, H>,
) -> bool {
    let (Some(h), Some(race)) = (c.https.as_ref(), c.race.as_deref_mut()) else {
        return false;
    };
    let (Some(first), Second::Due(second)) = (h.first, h.second) else {
        return false;
    };
    let hc = Component::HttpsConnect;
    let (one, two) = (first.name(), second.name());
    if race.first_failed.is_some() {
        trace::of(cx, hc, format_args!("{one} baller failed, starting {two}"));
        return true;
    }
    let now = cx.now();
    let hard = cx.easy().options().limits.eyeballs.0;
    let soft = hard / 2;
    let elapsed = now.since(race.at);
    // C counts in whole milliseconds.
    let elapsed_ms = elapsed.as_millis();
    if elapsed_ms >= hard.as_millis() {
        let hard = hard.as_millis();
        trace::of(
            cx,
            hc,
            format_args!("{one} inconclusive after {hard}, starting {two}"),
        );
        return true;
    }
    if elapsed_ms >= soft.as_millis() {
        if !race.replied {
            let reply = c.lease.reply_ms();
            race.replied = reply.is_some();
            let shown = reply.map_or(-1, |ms| i128::try_from(ms).unwrap_or(i128::MAX));
            trace::of(
                cx,
                Component::HappyEyeballs,
                format_args!("query connect reply: {shown}ms"),
            );
        }
        if !race.replied {
            let soft = soft.as_millis();
            trace::of(
                cx,
                hc,
                format_args!("{one} has not seen any data after {soft}ms, starting {two}"),
            );
            return true;
        }
        let at = deadlines.arm_in(TimerKind::AlpnEyeballs, now, hard.saturating_sub(elapsed));
        super::trace_set(cx, TimerKind::AlpnEyeballs, at);
    }
    false
}

/// The second attempt started.
pub(super) fn second_started(c: &mut Connecting) {
    let h = c.https.as_mut().expect("a race of two");
    let Second::Due(alpn) = h.second else {
        panic!("a second is due");
    };
    h.second = Second::Started(alpn, false);
}

/// Every attempt failed: the setup fails with the first's failure.
pub(super) fn all_failed(c: &Connecting) -> Option<ErrorKind> {
    let h = c.https.as_ref()?;
    let failed = c.race.as_ref()?.first_failed?;
    match h.second {
        Second::Started(_, true) | Second::None => Some(failed),
        Second::Unchosen | Second::Due(_) | Second::Started(_, false) => None,
    }
}

/// A connect call of the setup ends, the filter's attempt started: under
/// way, done, or failed (`cf_hc_connect`'s last line, after `connect,
/// all attempts failed` for a failure).
pub(super) fn call_ended<H: Host>(
    https: Option<HttpsConnect>,
    cx: &mut StepCx<'_, H>,
    ended: Result<bool, ErrorKind>,
) {
    if !https.is_some_and(|h| h.first.is_some()) {
        return;
    }
    let hc = Component::HttpsConnect;
    let (code, done) = match ended {
        Ok(done) => (trace::Code(Ok(())), u8::from(done)),
        Err(kind) => {
            trace::of(cx, hc, format_args!("connect, all attempts failed"));
            (trace::Code(Err(kind)), 0)
        }
    };
    trace::of(cx, hc, format_args!("connect -> {code}, done={done}"));
}
