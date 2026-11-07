//! C's HTTPS connect filter (`lib/cf-https-connect.c`), which heads the
//! setup of a connection to an `https` origin: it chooses the HTTP
//! versions its attempts offer by ALPN, from the origin's HTTPS record
//! (HTTPS-RR) and the transfer's wanted versions, and races them. Without
//! HTTP/3 wanted it makes one attempt, offering HTTP/2 and HTTP/1.1 or
//! HTTP/1.1 alone, so the race is its trace and its timer: C arms its
//! wait for a second attempt (`EXPIRE_ALPN_EYEBALLS`) as the attempt
//! starts while the record is still to come.
//!
//! The record is asked for where the reference build's resolver would: for
//! the origin's name, unless that is an address, as the setup's first
//! connect starts. Over DoH its answer comes as its probe ends; a resolver
//! that cannot ask has the answer a name without a record gets, none, at
//! the setup's next connect. The answer is kept in the DNS cache beside the
//! name's addresses, as C keeps it, so a later setup for the name finds it,
//! chooses by it and arms no timer.

use super::RecordLookup;
use super::names;
use super::{Connecting, SetupLend, StepCx};
use crate::components::Component;
use crate::conn::asyncs::Holder;
use crate::conn::{ConnectMachine, Dial, NetRoute, Reply};
use crate::conn::{HttpsLookup, address};
use crate::doh::RecordAnswer;
use crate::doh::{HttpsRecord, RecordAlpn};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::timers::{Deadlines, TimerKind};
use crate::proto::http::Negotiation;
use crate::share::Kind;
use crate::text::Text;
use crate::trace;
use curl_alloc::OutOfMemory;
use curl_alloc::TryArc;

/// The HTTPS connect filter heading a setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpsConnect {
    /// Its first attempt's version, once started (`connect, init`).
    first: Option<Alpn>,
    /// What is known of the record came before the first was chosen: from
    /// the cache, or answered before `connect, init`.
    first_by_record: bool,
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
    /// The version the origin's HTTPS record names.
    Record,
    /// The version an alternative service for the origin names.
    Preferred,
    Wanted,
    Allowed,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::Record => "HTTPS-RR",
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
    /// The origin's HTTPS record, if it has one for this very port.
    record: Option<TryArc<HttpsRecord>>,
}

impl Choosing {
    /// The choice for the setup of `request`'s connection, over `route`.
    pub(super) fn of<H: Host>(
        request: &dyn SetupLend,
        route: &NetRoute,
        cx: &StepCx<'_, H>,
    ) -> Choosing {
        let neg = request
            .negotiation()
            .expect("an HTTPS connect filter heads an HTTP setup");
        Choosing {
            neg,
            h2: cx.easy().libraries().h2.is_some(),
            may_h3: super::may_quic(cx, route),
            asked_h3: std::cell::Cell::new(false),
            record: None,
        }
    }

    /// The same, choosing by the origin's record `record` if it applies to
    /// the origin (`Curl_httpsrr_applicable`), and, as C does not take up
    /// `no-default-alpn`, not if it has that.
    pub(super) fn by_record(mut self, record: Option<&TryArc<HttpsRecord>>, port: u16) -> Choosing {
        self.record = record
            .filter(|r| r.is_for_origin(port) && !r.no_default_alpn)
            .cloned();
        self
    }

    /// The first of the record's versions that is allowed, but `not`
    /// (`cf_hc_get_httpsrr_alpn`).
    fn recorded(&self, not: Option<Alpn>) -> Option<Alpn> {
        let record = self.record.as_ref()?;
        record.alpns.iter().find_map(|&alpn| {
            let (alpn, ok) = match alpn {
                RecordAlpn::H3 => (Alpn::H3, self.neg.allowed.h3 && self.may_h3()),
                RecordAlpn::H2 => (Alpn::H2, self.neg.allowed.h2),
                RecordAlpn::H1 => (Alpn::H1, self.neg.allowed.h1),
            };
            (Some(alpn) != not && ok).then_some(alpn)
        })
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
        self.recorded(None)
            .map(|a| (a, Source::Record))
            .or_else(|| self.preferred(None).map(|a| (a, Source::Preferred)))
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
        self.recorded(Some(first))
            .map(|a| (a, Source::Record))
            .or_else(|| self.preferred(Some(first)).map(|a| (a, Source::Preferred)))
            .or_else(|| {
                self.first_of(self.neg.wanted, Some(first))
                    .map(|a| (a, Source::Wanted))
            })
    }
}

/// What a setup's handshake knows of the origin's HTTPS record
/// (`Curl_conn_dns_resolved_https`, `Curl_conn_dns_get_https`).
#[derive(Clone, Copy, Debug)]
pub(super) enum RecordNow<'a> {
    /// Asked for, its answer still to come.
    Coming,
    /// Known, or not asked for: the record, if the origin has one.
    Known(Option<&'a HttpsRecord>),
}

impl<'a> RecordNow<'a> {
    /// What the setup whose record is asked for as `ask` says, which knows
    /// `record`, knows. A filter put in with the origin's TLS has not
    /// started as the session is made, and is known to bring nothing
    /// (`Curl_resolv_knows_https` of no resolve); a setup with no such
    /// filter asks for none.
    pub(super) fn of(
        ask: Option<&RecordAsk>,
        record: Option<&'a TryArc<HttpsRecord>>,
    ) -> RecordNow<'a> {
        match ask.map(|a| (a.by, a.at)) {
            Some((Asker::Head, Record::Unasked) | (_, Record::Pending)) => RecordNow::Coming,
            Some((Asker::Tls, Record::Unasked) | (_, Record::Known)) | None => {
                RecordNow::Known(record.map(|r| &**r))
            }
        }
    }

    /// The ECHConfigList of the record, if known and about the origin
    /// itself, at `port` (`Curl_httpsrr_is_for_peer`), and it has one.
    pub(super) fn ech_configs(self, port: u16) -> Option<&'a [u8]> {
        match self {
            RecordNow::Known(Some(r)) => r.ech_for(port),
            RecordNow::Known(None) | RecordNow::Coming => None,
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
    /// Started: running beside the first, or failed, as the race's
    /// second attempt says.
    Started(Alpn),
}

/// The DNS filter that asks for the origin's HTTPS record, and where its
/// asking is. There is none for an origin that is an address
/// (`cf_dns_add_resolve`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecordAsk {
    by: Asker,
    at: Record,
}

/// Why the filter is there, which says where in the chain it is and when
/// it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asker {
    /// The HTTPS connect filter's, above the name's DNS filter, made with
    /// the chain (`cf_hc_add`) and started by its first connect.
    Head,
    /// The origin's TLS's, put in with it after the chain's DNS filters
    /// for ECH that takes its configurations from the record
    /// (`Curl_cf_ssl_insert_after`), where no HTTPS connect filter heads
    /// the setup, and started as the pollset after is made
    /// (`cf_dns_adjust_pollset`): the session is made before.
    Tls,
}

impl RecordAsk {
    /// The HTTPS connect filter's, unless the origin of `route` is an
    /// address.
    pub(super) fn heading(route: &NetRoute) -> Option<RecordAsk> {
        asked_for(route).then_some(RecordAsk {
            by: Asker::Head,
            at: Record::Unasked,
        })
    }

    /// The one the origin's TLS puts in as it is added to a setup no
    /// HTTPS connect filter heads, made with `ech`: for an HTTP origin,
    /// `https` or `wss`, whose ECH takes its configurations from the
    /// record (`Curl_ssl_need_httpsrr`), unless the origin is an address.
    pub(super) fn with_tls(route: &NetRoute, ech: &crate::options::Ech) -> Option<RecordAsk> {
        let http = matches!(route.origin.scheme().name(), "https" | "wss");
        (http && ech.needs_record() && asked_for(route)).then_some(RecordAsk {
            by: Asker::Tls,
            at: Record::Unasked,
        })
    }

    /// Whether the HTTPS connect filter asks: its filter is above the
    /// name's in the chain, where the TLS's is below the others.
    pub(crate) fn heads(&self) -> bool {
        self.by == Asker::Head
    }
}

/// Whether a record is asked for the origin of `route`: not for an
/// address.
fn asked_for(route: &NetRoute) -> bool {
    address(route.target().name()).is_none()
}

/// Where the origin's HTTPS record is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record {
    /// To be looked for as its filter starts.
    Unasked,
    /// Asked for, the answer still to come.
    Pending,
    /// Known: what is known of it is the setup's `record`.
    Known,
}

impl HttpsConnect {
    /// The filter a new connection over `route` gets, if any: one to an
    /// `https` origin with ALPN on, which no proxy forwards to
    /// (`Curl_cf_https_setup`).
    pub(super) fn heading(route: &NetRoute, alpn: bool) -> Option<HttpsConnect> {
        let https = route.origin.scheme().name() == "https";
        let forwarded = route.proxy.as_ref().is_some_and(|p| p.forward);
        if !https || forwarded || !alpn {
            return None;
        }
        Some(HttpsConnect {
            first: None,
            first_by_record: false,
            second: Second::Unchosen,
        })
    }
}

/// A connect call of the setup begins (`Curl_conn_connect` from the top
/// of the chain): the HTTPS connect filter's first looks for the origin's
/// record, as the filter that asks for it starts (`cf_dns_start`); one
/// after the record's filter started has the answer.
pub(super) fn connect_call<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    let Some(ask) = c.record_ask.as_mut() else {
        return Ok(());
    };
    match (ask.by, ask.at) {
        (Asker::Head, Record::Unasked) => {
            let (record, kept, lookup) = look_up(&c.route, true, cx)?;
            ask.at = record;
            if let Some(h) = c.https.as_mut() {
                h.first_by_record = kept.is_some();
            }
            c.record = kept;
            c.record_lookup = lookup;
            Ok(())
        }
        // It starts as the pollset is made.
        (Asker::Tls, Record::Unasked) => Ok(()),
        (_, Record::Pending) if c.record_lookup.is_some() => {
            // Looked for in the cache first, where another transfer may
            // have kept it meanwhile, which ends this one's resolve
            // (`Curl_resolv_take_result`).
            if let HttpsLookup::Found(kept) = cached(&c.route, cx) {
                say_lookup(&c.route, true, cx);
                found_since(&c.route, kept.as_ref(), cx);
                c.record_lookup = None;
                cx.libraries_closed();
                c.record = kept;
                known(c);
                return Ok(());
            }
            let lookup = c.record_lookup.as_mut().expect("looked at above");
            let (found, doh) = match lookup {
                RecordLookup::Doh(lookup) => {
                    say_lookup(&c.route, false, cx);
                    (lookup.https(), true)
                }
                RecordLookup::Library(resolve) => {
                    say_lookup(&c.route, false, cx);
                    resolve.perform().map_err(|_| ErrorKind::OutOfMemory)?;
                    cx.libraries_closed();
                    (resolve.record(), false)
                }
            };
            let Some(found) = found else {
                say_incomplete(&c.route, cx);
                return Ok(());
            };
            if doh {
                trace::of(cx, Component::Dns, format_args!("[DoH] probe done"));
            } else {
                let (result, dns) = match &found {
                    RecordAnswer::Record(_) | RecordAnswer::NoRecord => (0, ""),
                    RecordAnswer::NoSuchName | RecordAnswer::Failed => (6, "not "),
                };
                if let Some(RecordLookup::Library(r)) = &c.record_lookup {
                    let status = r.status();
                    trace::of(
                        cx,
                        Component::Dns,
                        format_args!(
                            "[HTTPS] ares_take_result, result={result}, ares_result=0, \
                             ares_status={status}, dns={dns}found"
                        ),
                    );
                }
            }
            c.record_lookup = None;
            cx.libraries_closed();
            let came = match found {
                RecordAnswer::Record(record) => Came::Record(try_arc(record)?),
                RecordAnswer::NoRecord => Came::NoRecord,
                RecordAnswer::NoSuchName => Came::Negative,
                RecordAnswer::Failed => Came::Failed,
            };
            // The cache was looked in just above, once, as C's take looks
            // (`Curl_resolv_take_result`).
            answer_came(c, cx, came, doh, false)
        }
        // Asked for where nothing answers, the first attempt started, it
        // is known to be none; the TLS's filter, the session made, too.
        (_, Record::Pending) if c.https.is_none_or(|h| h.first.is_some()) => {
            answer_came(c, cx, Came::Negative, false, true)
        }
        (_, Record::Pending | Record::Known) => Ok(()),
    }
}

/// The filter the origin's TLS put in starts as the pollset is made after
/// the call it was put in (`cf_dns_adjust_pollset`): the record is looked
/// for as the HTTPS connect filter's is as it starts.
pub(super) fn tls_ask_starts<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    let Some(ask) = c.record_ask else {
        return Ok(());
    };
    if (ask.by, ask.at) != (Asker::Tls, Record::Unasked) {
        return Ok(());
    }
    let peer = c.route.target();
    let at = Text::<8>::clipped(format_args!(":{}", peer.port())).0;
    trace::of_with(
        cx,
        Component::DnsFilter,
        &[
            b"adjust_pollset, starting ",
            peer.name(),
            at.bytes(),
            b" queries=HTTPS",
        ],
    );
    let (record, kept, lookup) = look_up(&c.route, false, cx)?;
    c.record_ask = Some(RecordAsk { at: record, ..ask });
    c.record = kept;
    c.record_lookup = lookup;
    Ok(())
}

/// The record is known: come before the HTTPS connect filter's first
/// attempt is chosen, it chooses it.
fn known(c: &mut Connecting) {
    let ask = c.record_ask.as_mut().expect("the record was asked for");
    ask.at = Record::Known;
    if let Some(h) = c.https.as_mut()
        && h.first.is_none()
    {
        h.first_by_record = true;
    }
}

/// What came of asking for a name's record.
enum Came {
    Record(TryArc<HttpsRecord>),
    NoRecord,
    /// That the name has none, which the cache's age treats as it does a
    /// name that does not exist (`Curl_dnscache_add_negative`).
    Negative,
    /// Nothing that can be kept.
    Failed,
}

fn try_arc(record: HttpsRecord) -> Result<TryArc<HttpsRecord>, ErrorKind> {
    TryArc::try_new(record).map_err(|_| ErrorKind::OutOfMemory)
}

/// What is known of the origin's record came: kept, and the second attempt
/// chosen by it if the first has started. The cache is looked in first
/// if `look`, as the answer is taken (`Curl_resolv_take_result`): kept by
/// another transfer since, it is not kept again.
fn answer_came<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
    came: Came,
    doh: bool,
    look: bool,
) -> Result<(), ErrorKind> {
    let found = if look {
        cached(&c.route, cx)
    } else {
        HttpsLookup::Missing
    };
    if let HttpsLookup::Found(kept) = found {
        found_since(&c.route, kept.as_ref(), cx);
        c.record = kept;
    } else {
        let taken = if doh { Taken::OverDoh } else { Taken::Later };
        answered(&c.route, &came, taken, cx)?;
        if let Came::Record(record) = came {
            c.record = Some(record);
        }
    }
    // Come before the first attempt is chosen, it chooses it, as C's
    // `connect, init` asks the DNS filter for what it has taken. Come
    // after, it chooses the second as the filter's own connect runs, below
    // the DNS filters (`second_chosen`).
    known(c);
    Ok(())
}

/// The filter's own connect, below the chain's DNS filters, which have
/// taken what came of the record and of the addresses: with the record
/// known since the first attempt started, the second is chosen by it
/// (`cf_hc_connect`'s `cf_hc_set_baller2`).
pub(super) fn second_chosen<H: Host>(c: &mut Connecting, cx: &mut StepCx<'_, H>) {
    let (Some(h), Some(ask)) = (c.https, c.record_ask) else {
        return;
    };
    let (Record::Known, Some(first), Second::Unchosen) = (ask.at, h.first, h.second) else {
        return;
    };
    // Whether the first's choice weighed HTTP/3, as it does again.
    let choosing = first_choosing(c, cx);
    choosing.first();
    let said = choosing.asked_h3.get();
    let second = choose_second(c, cx, first, said);
    c.https.as_mut().expect("the filter heads the setup").second = second;
}

/// The cache looked at for the record, there or not (`Curl_dnscache_get`).
fn say_lookup<H: Host>(route: &NetRoute, found: bool, cx: &mut StepCx<'_, H>) {
    let peer = route.target();
    let at = Text::<8>::clipped(format_args!(":{}", peer.port())).0;
    let said: &[u8] = if found { b"found" } else { b"not found" };
    trace::of_with(
        cx,
        Component::Dns,
        &[
            b"cache lookup ",
            peer.name(),
            at.bytes(),
            b" queries=HTTPS -> 0 ",
            said,
        ],
    );
}

/// The choice of the setup's attempts, by what is known of the record.
fn choosing<H: Host>(c: &Connecting, cx: &StepCx<'_, H>) -> Choosing {
    Choosing::of(&c.proto, &c.route, cx).by_record(c.record.as_ref(), c.route.origin.port())
}

/// The choice of the first attempt: by the record only if it came before
/// the choice is made, as C's `connect, init` asks the DNS filter for it.
fn first_choosing<H: Host>(c: &Connecting, cx: &StepCx<'_, H>) -> Choosing {
    if c.https.is_some_and(|h| h.first_by_record) {
        choosing(c, cx)
    } else {
        Choosing::of(&c.proto, &c.route, cx)
    }
}

/// The debug build's `CURL_DBG_AWAIT_HTTPSRR`: the setup waits for the
/// record before its attempts.
fn awaits_record() -> bool {
    #[cfg(feature = "debug-hooks")]
    {
        let mut buf = [0u8; 4];
        curl_os::env::var_into(b"CURL_DBG_AWAIT_HTTPSRR", &mut buf).is_some()
    }
    #[cfg(not(feature = "debug-hooks"))]
    {
        false
    }
}

/// Whether the setup goes no further until its record's answer comes,
/// said as it does (`cf_hc_connect`).
pub(super) fn awaiting<H: Host>(c: &Connecting, cx: &mut StepCx<'_, H>) -> bool {
    let waits = c.record_lookup.is_some() && c.https.is_some_and(|h| h.first.is_none());
    if waits && awaits_record() {
        trace::of(
            cx,
            Component::HttpsConnect,
            format_args!("awaiting HTTPS-RR"),
        );
        return true;
    }
    false
}

/// What `line` says of the record: none, one of no use here, or the record
/// (`cf_dns_report`).
fn say_record<H: Host>(
    route: &NetRoute,
    record: Option<&TryArc<HttpsRecord>>,
    cx: &mut StepCx<'_, H>,
) {
    let peer = route.target();
    let at = Text::<8>::clipped(format_args!(":{}", peer.port())).0;
    let (name, at) = (peer.name(), at.bytes());
    match record {
        None => trace::info_with(cx, &[b"HTTPS-RR ", name, at, b": -"]),
        Some(r) if !r.is_for_origin(route.origin.port()) => {
            trace::info_with(cx, &[b"HTTPS-RR ", name, at, b": not applicable"]);
        }
        Some(r) => match r.print() {
            Ok(shown) => trace::info_with(cx, &[b"HTTPS-RR ", name, at, b": ", &shown]),
            Err(_) => trace::info(cx, format_args!("Error printing HTTPS-RR information")),
        },
    }
}

/// What the setup knows of the record, what it is, and the resolve under way.
type LookedUp = (Record, Option<TryArc<HttpsRecord>>, Option<RecordLookup>);

/// The origin's record looked for in the cache, as C traces it
/// (`hostip_resolv`, `Curl_dnscache_get`): what the setup knows of it.
/// A filter started by its connect takes the answer at once if it can
/// (`cf_dns_connect`'s `Curl_resolv_take_result`); one started as the
/// pollset is made does not (`cf_dns_adjust_pollset`), unless `take`.
fn look_up<H: Host>(
    route: &NetRoute,
    take: bool,
    cx: &mut StepCx<'_, H>,
) -> Result<LookedUp, ErrorKind> {
    let peer = route.target();
    let (name, port) = (peer.name(), peer.port());
    let at = Text::<8>::clipped(format_args!(":{port}")).0;
    let at = at.bytes();
    let dns = Component::Dns;
    super::names::record_started(cx, route);
    // Over a Unix socket the filter resolves the socket in place of the
    // record (`cf_dns_start` asks for its address alone), which is then
    // known to be none.
    if peer.is_unix() {
        return Ok((Record::Known, None, None));
    }
    // The C debug build's line.
    #[cfg(feature = "debug-hooks")]
    trace::of_with(cx, dns, &[b"[HTTPS] hostip_resolv(", name, at, b")"]);
    let found = cached(route, cx);
    let not = if matches!(found, HttpsLookup::Found(_)) {
        ""
    } else {
        "not "
    };
    trace::of_with(
        cx,
        dns,
        &[
            b"cache lookup ",
            name,
            at,
            b" queries=HTTPS -> 0 ",
            not.as_bytes(),
            b"found",
        ],
    );
    if let HttpsLookup::Found(kept) = found {
        trace::info_with(cx, &[b"Hostname ", name, b" was found in DNS cache"]);
        say_record(route, kept.as_ref(), cx);
        Ok((Record::Known, kept, None))
    } else {
        // Without DoH or a resolver library, the network's resolver is
        // asked if it says so, and never answers: C's threaded one
        // resolves only addresses (`Curl_async_getaddrinfo`).
        let mut unanswered = false;
        let mut refused = false;
        let lookup = if cx.easy().options().doh.url.is_some() {
            match crate::multi::doh::start_https(cx, name, peer.port()) {
                Ok(lookup) => Some(RecordLookup::Doh(lookup)),
                Err(_) => return Err(ErrorKind::OutOfMemory),
            }
        } else {
            match crate::multi::dns::start(cx, name, peer.port(), None) {
                Some(Ok(resolve)) => Some(RecordLookup::Library(resolve)),
                Some(Err(crate::conn::io::DnsRefused::OutOfMemory)) => {
                    return Err(ErrorKind::OutOfMemory);
                }
                // Refused settings fail the addresses' resolve as well.
                Some(Err(_)) => {
                    refused = true;
                    None
                }
                None => {
                    cx.rest
                        .net
                        .with_resolver(&mut |r| unanswered = r.asked_for_records());
                    None
                }
            }
        };
        // Its record is made as it is asked for (`hostip_async_new`), and
        // goes at once if the asking failed; the resolver C's threaded
        // build asks, or the one a library-less build stands in for, keeps
        // it as a library's resolve does.
        let oom = |OutOfMemory| ErrorKind::OutOfMemory;
        names::async_kept(cx, Holder::Record).map_err(oom)?;
        if refused {
            names::async_gone(cx, Holder::Record);
        }
        let mut lookup = lookup;
        if let Some(found) = look_in_start(route, &mut lookup, cx)? {
            return taken_by_library(route, found, Taken::InStart, lookup, cx);
        }
        // The resolver answers later (`CURLE_AGAIN`).
        let again = crate::error::AGAIN_NUMBER;
        trace::of(
            cx,
            dns,
            format_args!("[HTTPS] hostip_resolv started -> {again}"),
        );
        // A resolver that never answers a record says nothing of it, and
        // the setup goes on without one, as below.
        if !take {
            let record = if unanswered {
                Record::Known
            } else {
                Record::Pending
            };
            return Ok((record, None, lookup));
        }
        // The answer is asked for at once, the cache looked in first
        // (`Curl_resolv_take_result`).
        if let HttpsLookup::Found(kept) = cached(route, cx) {
            found_since(route, kept.as_ref(), cx);
            return Ok((Record::Known, kept, None));
        }
        if matches!(lookup, Some(RecordLookup::Library(_))) {
            say_lookup(route, false, cx);
            // Its answer is taken if the library has it by now, as one
            // it had as it was asked (`hostip_resolv_take_result`).
            if let Some(found) = look_at_library(route, &mut lookup, cx)? {
                return taken_by_library(route, found, Taken::Later, lookup, cx);
            }
        }
        // It is looked at as a library is, and says nothing of the record,
        // then or after: the setup goes on without one and keeps nothing of
        // it, as C's threaded build does.
        if unanswered {
            say_lookup(route, false, cx);
            return Ok((Record::Known, None, None));
        }
        Ok((Record::Pending, None, lookup))
    }
}

/// A library's resolve looked at inside its start if its query is out,
/// as `hostip_resolv_start` looks on `CURLE_AGAIN`: what it has then, with
/// the library's status. One the library had as it was asked is not
/// looked for: C's c-ares then returns `CURLE_OK`, and the answer is
/// taken at the next look (`Curl_async_getaddrinfo`).
fn look_in_start<H: Host>(
    route: &NetRoute,
    lookup: &mut Option<RecordLookup>,
    cx: &mut StepCx<'_, H>,
) -> Result<Option<(RecordAnswer, i32)>, ErrorKind> {
    let Some(RecordLookup::Library(resolve)) = lookup else {
        return Ok(None);
    };
    if resolve.ongoing().0 == 0 {
        return Ok(None);
    }
    look_at_library(route, lookup, cx)
}

/// The record's answer, `found`, taken where `taken` says, the library's
/// `status` said with it (`hostip_resolv_take_result`): the resolve,
/// `lookup`, let go; taken inside its start, its record goes with the
/// start's end, among the answer's lines (`hostip_resolv_start`'s
/// `Curl_async_destroy`).
fn taken_by_library<H: Host>(
    route: &NetRoute,
    (found, status): (RecordAnswer, i32),
    taken: Taken,
    lookup: Option<RecordLookup>,
    cx: &mut StepCx<'_, H>,
) -> Result<LookedUp, ErrorKind> {
    let (result, dns) = match &found {
        RecordAnswer::Record(_) | RecordAnswer::NoRecord => (0, ""),
        RecordAnswer::NoSuchName | RecordAnswer::Failed => (6, "not "),
    };
    trace::of(
        cx,
        Component::Dns,
        format_args!(
            "[HTTPS] ares_take_result, result={result}, ares_result=0, \
             ares_status={status}, dns={dns}found"
        ),
    );
    drop(lookup);
    cx.libraries_closed();
    let came = match found {
        RecordAnswer::Record(record) => Came::Record(try_arc(record)?),
        RecordAnswer::NoRecord => Came::NoRecord,
        RecordAnswer::NoSuchName => Came::Negative,
        RecordAnswer::Failed => Came::Failed,
    };
    answered(route, &came, taken, cx)?;
    let kept = match came {
        Came::Record(record) => Some(record),
        _ => None,
    };
    Ok((Record::Known, kept, None))
}

/// A library's resolve run once, as C looks for the answer inside the
/// start and again just after it (`hostip_resolv`): what it has then, with
/// the library's status.
fn look_at_library<H: Host>(
    route: &NetRoute,
    lookup: &mut Option<RecordLookup>,
    cx: &mut StepCx<'_, H>,
) -> Result<Option<(RecordAnswer, i32)>, ErrorKind> {
    let Some(RecordLookup::Library(resolve)) = lookup else {
        return Ok(None);
    };
    resolve.perform().map_err(|_| ErrorKind::OutOfMemory)?;
    cx.libraries_closed();
    if resolve.ongoing().0 > 0 {
        say_incomplete(route, cx);
        return Ok(None);
    }
    Ok(resolve.record().map(|found| (found, resolve.status())))
}

/// A record's query not yet answered.
fn say_incomplete<H: Host>(route: &NetRoute, cx: &mut StepCx<'_, H>) {
    let peer = route.target();
    let at = Text::<8>::clipped(format_args!(":{}", peer.port())).0;
    trace::of_with(
        cx,
        Component::Dns,
        &[
            b"[HTTPS] resolve incomplete, responses=-, ongoing=1 for ",
            peer.name(),
            at.bytes(),
        ],
    );
}

/// The origin's record looked for in the cache, under the share's lock
/// when the share keeps names (`Curl_dnscache_get`); one gone stale is
/// dropped and said to be.
fn cached<H: Host>(route: &NetRoute, cx: &mut StepCx<'_, H>) -> HttpsLookup {
    let peer = route.target();
    let max_age = cx.easy().options().limits.reuse.dns_max_age;
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
    let found = names.section(|d| d.lookup_https((peer.name(), peer.port()), max_age));
    if matches!(found, HttpsLookup::Stale) {
        trace::info(cx, format_args!("Hostname in DNS cache was stale, zapped"));
    }
    found
}

/// The record, asked for, was kept by another transfer meanwhile: the
/// resolve is let go (`Curl_resolv_take_result`), and what is kept is
/// the answer, none.
fn found_since<H: Host>(
    route: &NetRoute,
    kept: Option<&TryArc<HttpsRecord>>,
    cx: &mut StepCx<'_, H>,
) {
    let name = route.target().name();
    trace::info_with(cx, &[b"Hostname '", name, b"' was found in DNS cache"]);
    names::async_shut(cx, Holder::Record);
    say_record(route, kept, cx);
}

/// Where the record's answer was taken.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Taken {
    /// From DoH's probe, at a look after the start.
    OverDoh,
    /// From a library, at a look after the start.
    Later,
    /// From a library, inside the start, whose end is said among the
    /// answer's lines (`hostip_resolv`).
    InStart,
}

/// The answer came, a record or none, kept as the name's
/// (`Curl_dnsc_mk_https`, `Curl_dnscache_add_negative`).
fn answered<H: Host>(
    route: &NetRoute,
    came: &Came,
    taken: Taken,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    let peer = route.target();
    let (name, port) = (peer.name(), peer.port());
    let at = Text::<8>::clipped(format_args!(":{port}")).0;
    let at = at.bytes();
    let doh = taken == Taken::OverDoh;
    let done = |cx: &mut StepCx<'_, H>| {
        if doh {
            trace::of(cx, Component::Dns, format_args!("[DoH] probe done"));
        }
    };
    // Taken inside the start, the resolve's record goes, and the start
    // says how it ended (`Curl_async_destroy`, `hostip_resolv`).
    let started = |cx: &mut StepCx<'_, H>, code: u32| {
        if taken == Taken::InStart {
            names::async_gone(cx, Holder::Record);
            trace::of(
                cx,
                Component::Dns,
                format_args!("[HTTPS] hostip_resolv started -> {code}"),
            );
        }
    };
    let record = match came {
        Came::Failed => {
            started(cx, 6);
            done(cx);
            return Ok(());
        }
        Came::Record(record) => Some(record),
        Came::NoRecord | Came::Negative => None,
    };
    let negative = matches!(came, Came::Negative);
    let complete = |cx: &mut StepCx<'_, H>| {
        trace::of_with(
            cx,
            Component::Dns,
            &[b"[HTTPS] resolve complete for ", name, at],
        );
    };
    // A library's answer is taken and its start ends before it is kept,
    // each said on its side of the cache's lock (`Curl_resolv_take_result`,
    // `hostip_resolv`); only DoH's says itself and is kept before it is
    // taken.
    if !doh {
        if negative {
            started(cx, 6);
        } else {
            complete(cx);
            started(cx, 0);
        }
    }
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
    names
        .section(|d| d.put_https(name, port, record.cloned(), negative))
        .map_err(|_| ErrorKind::OutOfMemory)?;
    if negative {
        done(cx);
        let line: [&[u8]; 4] = [
            b"cache negative name resolve for ",
            name,
            at,
            b" type=HTTPS",
        ];
        trace::of_with(cx, Component::Dns, &line);
        return Ok(());
    }
    let entry: [&[u8]; 4] = [b"cached entry for ", name, at, b" queries=HTTPS"];
    if doh {
        match record.map(|r| r.print()) {
            Some(Ok(shown)) => trace::of_with(cx, Component::Dns, &[b"[HTTPS] record: ", &shown]),
            Some(Err(_)) => {}
            None => trace::of(
                cx,
                Component::Dns,
                format_args!("[HTTPS] no record available"),
            ),
        }
        trace::of_with(cx, Component::Dns, &entry);
        done(cx);
        complete(cx);
    }
    trace::of_with(cx, Component::Dns, &entry);
    say_record(route, record, cx);
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
    let shown = if c.record.is_some() { "" } else { "not " };
    trace::of(cx, hc, format_args!("HTTPS-RR {shown}available"));
    let choosing = choosing(c, cx);
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

/// Whether the setup `c` may race a second attempt against its first:
/// one chosen by what is known, or one the origin's record, still to
/// come, may choose. C's filter gives up only once its second is chosen
/// (`cf_hc_connect`'s `ballers_complete`), which waits for the record
/// (`cf_hc_set_baller2`).
pub(super) fn may_race<H: Host>(c: &Connecting, cx: &StepCx<'_, H>) -> bool {
    let Some(h) = c.https else {
        return false;
    };
    let Some(first) = h.first else {
        return false;
    };
    pending(c) || choosing(c, cx).second(first).is_some()
}

/// Whether the record is asked for, its answer still to come.
fn pending(c: &Connecting) -> bool {
    c.record_ask.is_some_and(|a| a.at == Record::Pending)
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
    let by_record = c.https.is_some_and(|h| h.first_by_record) && c.record.is_some();
    let shown = if by_record { "" } else { "not " };
    trace::of(cx, hc, format_args!("HTTPS-RR {shown}available"));
    let choosing = first_choosing(c, cx);
    let first = choosing.first();
    let said = choosing.asked_h3.get();
    h3_refused(c, cx, said);
    let (first, source) = first.expect("the plan dials an attempt it can choose");
    // The plan dialed by what was kept of the record then, which the
    // answer may have changed; nothing of the dial has started.
    c.lead_mut().set_dial(if first == Alpn::H3 {
        Dial::Quic
    } else {
        Dial::Stream
    });
    // HTTP/1.1 alone is offered by an attempt in HTTP/1.
    if first == Alpn::H1 {
        let request: &mut dyn SetupLend = &mut c.proto;
        request.negotiation_mut().expect("an HTTP setup").h1_first();
    }
    let (name, source) = (first.name(), source.name());
    trace::of(
        cx,
        hc,
        format_args!("1st attempt uses {name} from {source}"),
    );
    let h = c.https.as_mut().expect("the filter heads the setup");
    h.first = Some(first);
    if !pending(c) {
        let second = choose_second(c, cx, first, said);
        c.https.as_mut().expect("the filter heads the setup").second = second;
    }
    let h = c.https.expect("the filter heads the setup");
    if pending(c) || matches!(h.second, Second::Due(_)) {
        let wait = cx.easy().options().limits.eyeballs.0 / 2;
        super::arm(deadlines, cx, TimerKind::AlpnEyeballs, wait);
    }
}

/// Whether the attempt beside the lead, its QUIC one, is the first: it is
/// then driven, and polled, before the lead.
pub(super) fn other_leads(c: &Connecting) -> bool {
    c.https.is_some_and(|h| h.first == Some(Alpn::H3))
}

/// The leading attempt failed with `kind`: whether the race outlives it,
/// its other attempt still to start or running, or the record that
/// chooses it still to come; or fails with it, which `all_failed` then
/// says. The first leads but where a TCP second leads beside an HTTP/3
/// first.
pub(super) fn attempt_failed(c: &mut Connecting, kind: ErrorKind) -> bool {
    let leads = other_leads(c);
    let (Some(h), Some(race)) = (c.https.as_ref(), c.race.as_mut()) else {
        return false;
    };
    match h.second {
        Second::Unchosen | Second::Due(_) => {
            race.first_failed = Some(kind);
            true
        }
        Second::None => false,
        Second::Started(_) if leads => true,
        Second::Started(_) => {
            race.first_failed = Some(kind);
            true
        }
    }
}

/// The attempt beside the lead failed with `kind`: the first, an HTTP/3
/// one beside a TCP second, or the second, an HTTP/3 one beside a first
/// over TCP.
pub(super) fn other_failed(c: &mut Connecting, kind: ErrorKind) {
    if other_leads(c) {
        c.race.as_mut().expect("a race of two").first_failed = Some(kind);
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
    // In milliseconds, as C counts them.
    let elapsed_ms = now.ms_since(race.at);
    if elapsed_ms >= crate::time::millis(hard) {
        let hard = hard.as_millis();
        trace::of(
            cx,
            hc,
            format_args!("{one} inconclusive after {hard}, starting {two}"),
        );
        return true;
    }
    if elapsed_ms >= crate::time::millis(soft) {
        if !race.replied {
            race.replied = match c.lease.setup().map(ConnectMachine::reply) {
                Some(Reply::Dialed(heard)) => heard,
                Some(Reply::Racing(reply)) => {
                    let shown = reply.unwrap_or(-1);
                    trace::of(
                        cx,
                        Component::HappyEyeballs,
                        format_args!("query connect reply: {shown}ms"),
                    );
                    reply.is_some()
                }
                None => {
                    trace::of(
                        cx,
                        Component::HappyEyeballs,
                        format_args!("query connect reply: -1ms"),
                    );
                    false
                }
            };
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
        let left_ms = crate::time::millis(hard).saturating_sub(elapsed_ms).max(0);
        let left = std::time::Duration::from_millis(left_ms.unsigned_abs());
        let at = deadlines.arm_in(TimerKind::AlpnEyeballs, now, left);
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
    h.second = Second::Started(alpn);
    alpn
}

/// Every attempt failed: the setup fails with the first's failure.
pub(super) fn all_failed(c: &Connecting) -> Option<ErrorKind> {
    let h = c.https.as_ref()?;
    let race = c.race.as_ref()?;
    let failed = race.first_failed?;
    match h.second {
        Second::Started(_) if race.second.running().is_none() => Some(failed),
        Second::None => Some(failed),
        Second::Unchosen | Second::Due(_) | Second::Started(_) => None,
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
            neg.alt_svc = Some(crate::proto::http::AltSvcSaid::Prefers(p));
        }
        Choosing {
            neg,
            h2,
            may_h3,
            asked_h3: std::cell::Cell::new(false),
            record: None,
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

    /// The record's versions come first, in its order, if allowed and if
    /// it is about the origin itself; `no-default-alpn` is not taken up.
    #[test]
    fn an_origins_record_chooses_first() {
        let record = |f: &dyn Fn(&mut HttpsRecord)| {
            let mut r = crate::doh::decode_https_record(b"\x00\x01\x00").unwrap();
            r.alpns.extend_from_slice(&[RecordAlpn::H1, RecordAlpn::H2]);
            f(&mut r);
            TryArc::try_new(r).unwrap()
        };
        let c = || {
            let mut c = choosing(HttpVersion::Any, None, true, true);
            c.neg.allowed.h1 = true;
            c.neg.allowed.h2 = true;
            c
        };
        let plain = record(&|_| ());
        let by = c().by_record(Some(&plain), 443);
        assert_eq!(by.first(), Some((Alpn::H1, Source::Record)));
        assert_eq!(by.second(Alpn::H1), Some((Alpn::H2, Source::Record)));
        let no_h1 = {
            let mut c = c();
            c.neg.allowed.h1 = false;
            c.by_record(Some(&plain), 443)
        };
        assert_eq!(no_h1.first(), Some((Alpn::H2, Source::Record)));
        let elsewhere = record(&|r| r.port = Some(8443));
        assert_eq!(
            c().by_record(Some(&elsewhere), 443).first().map(|f| f.1),
            Some(Source::Wanted)
        );
        assert_eq!(
            c().by_record(Some(&elsewhere), 8443).first().map(|f| f.1),
            Some(Source::Record)
        );
        let other = record(&|r| r.target = b"other.test".to_vec());
        assert_eq!(
            c().by_record(Some(&other), 443).first().map(|f| f.1),
            Some(Source::Wanted)
        );
        let no_default = record(&|r| r.no_default_alpn = true);
        assert_eq!(
            c().by_record(Some(&no_default), 443).first().map(|f| f.1),
            Some(Source::Wanted)
        );
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
