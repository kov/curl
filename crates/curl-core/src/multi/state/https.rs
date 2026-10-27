//! C's HTTPS connect filter (`lib/cf-https-connect.c`), which heads the
//! setup of a connection to an `https` origin: it chooses the HTTP
//! versions its attempts offer by ALPN, from the origin's HTTPS record
//! (HTTPS-RR) and the transfer's wanted versions, and races them. A build
//! without HTTP/2 makes one attempt, offering HTTP/1.1, so the race is its
//! trace and its timer: C arms its wait for a second attempt
//! (`EXPIRE_ALPN_EYEBALLS`) as the attempt starts while the record is
//! still to come.
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
    /// Its attempt started (`connect, init`).
    started: bool,
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
            started: false,
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
        Record::Pending if h.started => {
            answered(&c.route, cx)?;
            h.record = Record::Known;
            trace::of(
                cx,
                Component::HttpsConnect,
                format_args!("HTTPS-RR not available"),
            );
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

/// The setup's first attempt starts (`cf_hc_connect`'s INIT): its
/// version chosen, one that a build without HTTP/2 can speak, and the
/// wait for a second armed if the record is still to come; known, it
/// says there is no second.
pub(super) fn start<H: Host>(
    c: &mut Connecting,
    deadlines: &mut Deadlines,
    cx: &mut StepCx<'_, H>,
) {
    let Some(h) = c.https.as_mut().filter(|h| !h.started) else {
        return;
    };
    h.started = true;
    let hc = Component::HttpsConnect;
    trace::of(cx, hc, format_args!("connect, init"));
    trace::of(cx, hc, format_args!("HTTPS-RR not available"));
    // HTTP/3 alone is its one attempt's (`cf_hc_get_first_alpn`).
    let first = match c.route.dial {
        Dial::Quic => "h3",
        Dial::Tcp => "h1",
    };
    trace::of(
        cx,
        hc,
        format_args!("1st attempt uses {first} from wanted versions"),
    );
    match h.record {
        Record::Pending => {
            let wait = cx.easy().options().limits.eyeballs.0 / 2;
            super::arm(deadlines, cx, TimerKind::AlpnEyeballs, wait);
        }
        Record::NotAsked | Record::Known => {
            trace::of(cx, hc, format_args!("HTTPS-RR not available"));
        }
        Record::Unasked => unreachable!("the record is looked for as the setup's connect starts"),
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
    if !https.is_some_and(|h| h.started) {
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
