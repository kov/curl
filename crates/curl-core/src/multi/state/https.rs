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
use crate::proto::ProtoState;
use crate::proto::http::Negotiation;
use crate::share::Kind;
use crate::trace::{self, Bytes};

/// The HTTPS connect filter heading a setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpsConnect {
    record: Record,
    /// Its first attempt's version, once started (`connect, init`).
    first: Option<Alpn>,
    /// Its second, of another version, over QUIC where the first is over
    /// TCP or the other way round (`ballers[1]`).
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

impl From<crate::altsvc::Alpn> for Alpn {
    fn from(alpn: crate::altsvc::Alpn) -> Alpn {
        match alpn {
            crate::altsvc::Alpn::H3 => Alpn::H3,
            crate::altsvc::Alpn::H2 => Alpn::H2,
            crate::altsvc::Alpn::H1 => Alpn::H1,
        }
    }
}

/// What an attempt's version was chosen from, as the trace says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Source {
    /// The version an alternative service for the origin names.
    Preferred,
    Wanted,
    Allowed,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::Preferred => "preferred version",
            Source::Wanted => "wanted versions",
            Source::Allowed => "allowed versions",
        }
    }
}

/// What the versions of a setup's attempts are chosen from: the
/// transfer's negotiation, whether a library speaks HTTP/2, and whether
/// HTTP/3 may be spoken over the route, which is asked only as it is
/// weighed (`cf_hc_may_h3`).
pub(super) struct Choosing {
    neg: Negotiation,
    h2: bool,
    may_h3: bool,
    /// HTTP/3 was weighed.
    asked_h3: std::cell::Cell<bool>,
}

impl Choosing {
    /// The choice for the setup `c`, over `route`.
    pub(super) fn of<H: Host>(proto: &ProtoState, route: &Tcp, cx: &StepCx<'_, H>) -> Choosing {
        let neg = proto
            .negotiation()
            .expect("an HTTPS connect filter heads an HTTP setup");
        Choosing {
            neg,
            h2: cx.easy().libraries().h2.is_some(),
            may_h3: super::may_quic(cx, route, proto.http_versions().h3_only()),
            asked_h3: std::cell::Cell::new(false),
        }
    }

    fn may_h3(&self) -> bool {
        self.asked_h3.set(true);
        self.may_h3
    }

    /// The preferred version, if allowed and not `not`
    /// (`cf_hc_get_pref_alpn`): HTTP/1 not after HTTP/2, which offers it.
    fn preferred(&self, not: Option<Alpn>) -> Option<Alpn> {
        let preferred = Alpn::from(self.neg.preferred()?);
        let ok = match preferred {
            Alpn::H3 => self.may_h3() && not != Some(Alpn::H3),
            Alpn::H2 => self.h2 && not != Some(Alpn::H2),
            Alpn::H1 => not != Some(Alpn::H1) && not != Some(Alpn::H2),
        };
        ok.then_some(preferred)
    }

    /// The first of `set` that may be spoken, HTTP/3, HTTP/2, HTTP/1, but
    /// `not`, and neither HTTP/2 nor HTTP/1 after either, as each offers
    /// the other (`cf_hc_get_first_alpn`).
    fn first_of(&self, set: crate::altsvc::Versions, not: Option<Alpn>) -> Option<Alpn> {
        let h1_or_h2 = not != Some(Alpn::H1) && not != Some(Alpn::H2);
        if not != Some(Alpn::H3) && set.h3 && self.may_h3() {
            Some(Alpn::H3)
        } else if h1_or_h2 && set.h2 && self.h2 {
            Some(Alpn::H2)
        } else if h1_or_h2 && set.h1 {
            Some(Alpn::H1)
        } else {
            None
        }
    }

    /// The first attempt's version and where it came from: the preferred,
    /// else the first wanted, else the first allowed
    /// (`cf_hc_set_baller1`).
    pub(super) fn first(&self) -> Option<(Alpn, Source)> {
        self.preferred(None)
            .map(|a| (a, Source::Preferred))
            .or_else(|| {
                self.first_of(self.neg.wanted, None)
                    .map(|a| (a, Source::Wanted))
            })
            .or_else(|| {
                self.first_of(self.neg.allowed, None)
                    .map(|a| (a, Source::Allowed))
            })
    }

    /// The second's after `first`: the preferred, else the first wanted
    /// (`cf_hc_set_baller2`).
    fn second(&self, first: Alpn) -> Option<(Alpn, Source)> {
        self.preferred(Some(first))
            .map(|a| (a, Source::Preferred))
            .or_else(|| {
                self.first_of(self.neg.wanted, Some(first))
                    .map(|a| (a, Source::Wanted))
            })
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
            // Whether the first's choice weighed HTTP/3, as it does again.
            let choosing = Choosing::of(&c.proto, &c.route, cx);
            choosing.first();
            let said = choosing.asked_h3.get();
            let second = choose_second(c, cx, first, said);
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

/// HTTP/3 was weighed, for the first time, and may not be spoken over
/// the route: why, said once, as C asks once (`cf_hc_may_h3`).
fn h3_refused<H: Host>(c: &Connecting, cx: &mut StepCx<'_, H>, asked: bool) {
    if !asked {
        return;
    }
    if let Some((kind, why)) = super::quic_refused(&c.route, true) {
        trace::fail(cx, kind, format_args!("{why}"));
    }
}

/// The second attempt, as the origin's record is known to be none; why
/// HTTP/3 may not be spoken is said if the first's choice did not weigh
/// it already, which `said` tells.
fn choose_second<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
    first: Alpn,
    said: bool,
) -> Second {
    let hc = Component::HttpsConnect;
    trace::of(cx, hc, format_args!("HTTPS-RR not available"));
    let choosing = Choosing::of(&c.proto, &c.route, cx);
    let second = choosing.second(first);
    h3_refused(c, cx, choosing.asked_h3.get() && !said);
    let Some((second, source)) = second else {
        return Second::None;
    };
    let (name, source) = (second.name(), source.name());
    trace::of(
        cx,
        hc,
        format_args!("2nd attempt uses {name} from {source}"),
    );
    Second::Due(second)
}

/// Whether the setup `c` would race a second attempt against its first,
/// as the origin's record, known or not, chooses none.
pub(super) fn may_race<H: Host>(c: &Connecting, cx: &StepCx<'_, H>) -> bool {
    let Some(first) = c.https.and_then(|h| h.first) else {
        return false;
    };
    Choosing::of(&c.proto, &c.route, cx).second(first).is_some()
}

/// The setup's first attempt starts (`cf_hc_connect`'s INIT): its
/// version chosen, the one the plan dialed for, its second chosen if
/// the record is known, and the wait for the second armed while there
/// may be one.
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
    let choosing = Choosing::of(&c.proto, &c.route, cx);
    let first = choosing.first();
    let said = choosing.asked_h3.get();
    h3_refused(c, cx, said);
    let (first, source) = first.expect("the plan dials an attempt it can choose");
    let dial = c.lease.setup_route().map_or(c.route.dial, |r| r.dial);
    assert_eq!(
        first == Alpn::H3,
        dial == Dial::Quic,
        "the plan dials for the first attempt"
    );
    // HTTP/1.1 alone is offered by an attempt in HTTP/1.
    if first == Alpn::H1 {
        c.proto.negotiation_mut().expect("an HTTP setup").h1_first();
    }
    let (name, source) = (first.name(), source.name());
    trace::of(
        cx,
        hc,
        format_args!("1st attempt uses {name} from {source}"),
    );
    let h = c.https.as_mut().expect("the filter heads the setup");
    h.first = Some(first);
    if h.record != Record::Pending {
        let second = choose_second(c, cx, first, said);
        c.https.as_mut().expect("the filter heads the setup").second = second;
    }
    let h = c.https.as_mut().expect("the filter heads the setup");
    if h.record == Record::Pending || matches!(h.second, Second::Due(_)) {
        let wait = cx.easy().options().limits.eyeballs.0 / 2;
        super::arm(deadlines, cx, TimerKind::AlpnEyeballs, wait);
    }
}

/// Whether the attempt out of the lease, its QUIC one, is the first: it
/// is then driven, and polled, before the lease's.
pub(super) fn aside_leads(c: &Connecting) -> bool {
    c.https.is_some_and(|h| h.first == Some(Alpn::H3))
}

/// The attempt the lease held failed with `kind`: whether the race
/// outlives it, its other attempt still to start or running, or the
/// record that chooses it still to come; or fails with it, which
/// `all_failed` then says. The lease holds the first but where an
/// HTTP/3 first was set aside for the second.
pub(super) fn attempt_failed(c: &mut Connecting, kind: ErrorKind) -> bool {
    let leads = aside_leads(c);
    let (Some(h), Some(race)) = (c.https.as_mut(), c.race.as_mut()) else {
        return false;
    };
    match h.second {
        Second::Unchosen | Second::Due(_) => {
            race.first_failed = Some(kind);
            true
        }
        Second::None => false,
        Second::Started(alpn, _) if leads => {
            h.second = Second::Started(alpn, true);
            true
        }
        Second::Started(..) => {
            race.first_failed = Some(kind);
            true
        }
    }
}

/// The attempt out of the lease failed with `kind`: the first, an HTTP/3
/// one set aside, or the second, an HTTP/3 one after a first over TCP.
pub(super) fn aside_failed(c: &mut Connecting, kind: ErrorKind) {
    let leads = aside_leads(c);
    let h = c.https.as_mut().expect("a race of two");
    if leads {
        c.race.as_mut().expect("a race of two").first_failed = Some(kind);
    } else if let Second::Started(alpn, _) = h.second {
        h.second = Second::Started(alpn, true);
    }
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

/// The second attempt starts: its version.
pub(super) fn second_started(c: &mut Connecting) -> Alpn {
    let h = c.https.as_mut().expect("a race of two");
    let Second::Due(alpn) = h.second else {
        panic!("a second is due");
    };
    h.second = Second::Started(alpn, false);
    alpn
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::altsvc::Alpn as Named;
    use crate::options::HttpVersion;

    fn choosing(
        version: HttpVersion,
        preferred: Option<Named>,
        h2: bool,
        may_h3: bool,
    ) -> Choosing {
        let mut neg = Negotiation::new(version);
        if let Some(p) = preferred {
            // As an alternative for the origin itself has it.
            match p {
                Named::H1 => neg.wanted.h1 = true,
                Named::H2 => neg.wanted.h2 = true,
                Named::H3 => neg.wanted.h3 = true,
            }
            neg.preferred = Some(p);
        }
        Choosing {
            neg,
            h2,
            may_h3,
            asked_h3: std::cell::Cell::new(false),
        }
    }

    /// An attempt's version and where it came from.
    type Attempt = Option<(Alpn, Source)>;

    /// The two attempts' versions and where each came from, and whether
    /// HTTP/3 was weighed, as `cf_hc_set_baller1` and `_baller2` choose.
    fn chosen(c: &Choosing) -> (Attempt, Attempt, bool) {
        let first = c.first();
        let second = first.and_then(|(f, _)| c.second(f));
        (first, second, c.asked_h3.get())
    }

    #[test]
    fn the_attempts_are_chosen_as_c_chooses_them() {
        use Alpn::{H1, H2, H3};
        use HttpVersion::{Any, Http3, Http3Only};
        use Source::{Preferred as P, Wanted as W};
        let cases = [
            // version, preferred, HTTP/2 library, HTTP/3 may be spoken
            ((Any, None, true, true), (Some((H2, W)), None, false)),
            ((Any, None, false, true), (Some((H1, W)), None, false)),
            (
                (Http3, None, true, true),
                (Some((H3, W)), Some((H2, W)), true),
            ),
            (
                (Http3, None, false, true),
                (Some((H3, W)), Some((H1, W)), true),
            ),
            ((Http3, None, true, false), (Some((H2, W)), None, true)),
            ((Http3Only, None, true, true), (Some((H3, W)), None, true)),
            (
                (Any, Some(Named::H3), true, true),
                (Some((H3, P)), Some((H2, W)), true),
            ),
            (
                (Any, Some(Named::H3), true, false),
                (Some((H2, W)), None, true),
            ),
            (
                (Any, Some(Named::H1), true, true),
                (Some((H1, P)), None, false),
            ),
            (
                (Http3, Some(Named::H1), true, true),
                (Some((H1, P)), Some((H3, W)), true),
            ),
            (
                (Http3, Some(Named::H2), true, true),
                (Some((H2, P)), Some((H3, W)), true),
            ),
        ];
        for ((version, preferred, h2, may_h3), want) in cases {
            let c = choosing(version, preferred, h2, may_h3);
            assert_eq!(chosen(&c), want, "{version:?} {preferred:?} {h2} {may_h3}");
        }
    }

    /// With none of the wanted versions to be spoken, the first allowed
    /// is tried; a version preferred that is not allowed is not.
    #[test]
    fn the_allowed_versions_are_the_last_resort() {
        let mut c = choosing(HttpVersion::Http3Only, None, true, false);
        c.neg.allowed = crate::altsvc::Versions {
            h1: true,
            h2: true,
            h3: true,
        };
        assert_eq!(c.first(), Some((Alpn::H2, Source::Allowed)));
        let mut c = choosing(HttpVersion::Any, Some(Named::H2), true, true);
        c.neg.allowed.h2 = false;
        assert_eq!(c.first().map(|(a, _)| a), Some(Alpn::H2));
        assert_eq!(c.first().map(|(_, s)| s), Some(Source::Wanted));
    }
}
