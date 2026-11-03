//! Names resolved over DNS over HTTPS (`lib/vdns/doh.c`): the setup that
//! wants a name adds a transfer of its own per query, each posting a DNS
//! message to the application's server, and is run again as each ends.
//!
//! A probe cannot outlive what it was started for. The `Lookup` the
//! setup's pending resolve holds is the one owner of the resolve, and
//! whichever way that resolve ends, it drops. Each probe holds a `Probe`:
//! its query's place in the state they share, which says the master is gone
//! from then on. Its writes then fail, its end is told to no one, and the
//! multi takes it out (`Multi::reap`) at the end of any call that may have
//! dropped one. No teardown path has anything to remember, and a master's
//! row reused by another transfer reaches nothing: its `TransferId` is
//! stale and the new transfer has no `Lookup`.
//!
//! The lookups of a multi share one count of those dropped, `Released`,
//! which the drop itself bumps: the multi looks through its transfers for
//! probes to take out only when that count moved since it last looked, or
//! as a transfer is removed.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use curl_alloc::{OutOfMemory, TryArc, TryVec, try_box};

use super::timers::TimeLeft;
use super::{EventCx, Host, Owner, Rows, Slots, StepCx, TransferId};
use crate::conn::ConnectError;
use crate::conn::io::{Family, ResolveFailure};
use crate::doh::{
    DohError, HttpsRecord, QueryType, RecordAnswer, RecordError, decode_answer,
    decode_https_record, encode_query,
};
use crate::error::ErrorKind;
use crate::handler::{Handler, Write, WriteHandler};
use crate::multi::TransferCx;
use crate::trace;

/// The most of an answer kept (`DYN_DOH_RESPONSE`).
pub(super) const MAX_RESPONSE: usize = 3000;

/// How one query stands.
#[derive(Debug)]
enum Query {
    /// None was asked: the family was not wanted.
    Unasked,
    /// Its probe runs, what it read so far here.
    Waiting(Vec<u8>),
    /// Its probe ended: what it gave, none if it failed.
    Ended(Result<Vec<IpAddr>, QueryFailure>),
}

/// How a query failed, which decides what the failure of the lookup says of
/// the name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryFailure {
    /// The server said no such name.
    NoSuchName,
    /// Anything else, which says nothing of the name.
    Other,
}

/// The state a resolve and its probes share.
#[derive(Debug)]
struct State {
    /// Set as the lookup drops: the master wants nothing any more.
    gone: bool,
    /// IPv6's, then IPv4's, as the probes start; or, for a resolve of a
    /// name's HTTPS record, its one query, the first.
    queries: [Query; 2],
    /// The HTTPS record found.
    record: Option<HttpsRecord>,
    /// The multi's count of lookups dropped.
    released: Released,
}

/// How many of a multi's lookups have dropped: one count, the multi's,
/// shared with the state of each of its resolves.
#[derive(Clone, Debug)]
pub(crate) struct Released(TryArc<AtomicU64>);

impl Released {
    fn new() -> Result<Released, OutOfMemory> {
        TryArc::try_new(AtomicU64::new(0)).map(Released)
    }

    fn count(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

/// Whether the multi has probes to look for: the count of lookups dropped
/// as it last looked. The count is made with the multi's first resolve
/// over DoH.
#[derive(Debug, Default)]
pub(super) struct Reaping {
    released: Option<Released>,
    seen: u64,
    /// How often the multi asked, and how often it looked, for the tests.
    #[cfg(test)]
    pub(super) asked: u32,
    #[cfg(test)]
    pub(super) looked: u32,
}

impl Reaping {
    /// The count each resolve started here shares, made if none was.
    fn share(&mut self) -> Result<Released, OutOfMemory> {
        if let Some(released) = &self.released {
            return Ok(released.clone());
        }
        Ok(self.released.insert(Released::new()?).clone())
    }

    /// Whether a lookup dropped since the last time this said so, or
    /// `anyway`: the count is read before the look, so that one dropping
    /// during it is looked for the next time.
    pub(super) fn due(&mut self, anyway: bool) -> bool {
        #[cfg(test)]
        {
            self.asked += 1;
        }
        let count = self.released.as_ref().map_or(0, Released::count);
        let moved = count != self.seen;
        self.seen = count;
        moved || anyway
    }
}

type Shared = TryArc<Mutex<State>>;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, State> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The resolve as the setup holds it. Dropped, whichever way the resolve
/// ended, its probes are of no use to anyone (`Curl_doh_cleanup`).
#[derive(Debug)]
pub(crate) struct Lookup(Shared);

impl Drop for Lookup {
    fn drop(&mut self) {
        let mut state = lock(&self.0);
        state.gone = true;
        state.released.0.fetch_add(1, Ordering::Release);
    }
}

/// A probe's place in its resolve (`CURL_EZM_DOH_PROBE`).
#[derive(Clone, Debug)]
pub(crate) struct Probe {
    shared: Shared,
    query: usize,
    what: QueryType,
}

impl Probe {
    /// Whether nobody wants what it finds: it is to be taken out.
    pub(super) fn orphaned(&self) -> bool {
        lock(&self.shared).gone
    }
}

impl Probe {
    /// `body` kept for the probe's end, if anyone wants it and there is
    /// room for it.
    pub(super) fn accepts(&self, body: &[u8]) -> bool {
        let mut state = lock(&self.shared);
        if state.gone {
            return false;
        }
        let Query::Waiting(kept) = &mut state.queries[self.query] else {
            return false;
        };
        kept.len().saturating_add(body.len()) <= MAX_RESPONSE
            && kept.try_extend_from_slice(body).is_ok()
    }
}

/// A probe's body, kept for its end (`doh_probe_write_cb`).
struct ProbeBody(Probe);

impl WriteHandler for ProbeBody {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        if self.0.accepts(body) {
            Write::Accepted
        } else {
            Write::Fail
        }
    }
}

/// A lookup and one query's probe, for the tests.
#[cfg(test)]
pub(super) fn orphan_for_test() -> (Lookup, Probe) {
    let shared = TryArc::try_new(Mutex::new(State {
        gone: false,
        queries: [Query::Waiting(Vec::new()), Query::Unasked],
        record: None,
        released: Released::new().unwrap(),
    }))
    .unwrap();
    let probe = Probe {
        shared: shared.clone(),
        query: 0,
        what: QueryType::Aaaa,
    };
    (Lookup(shared), probe)
}

/// How the lookup stands, its probes' answers taken as they end.
#[derive(Debug)]
pub(crate) enum Polled {
    /// `ongoing` probes run still; `responses` names those that ended.
    Waiting {
        ongoing: u32,
        responses: &'static str,
    },
    /// Every probe ended: the addresses, IPv6's first, or why none.
    Done(Result<Vec<IpAddr>, ResolveFailure>),
}

impl Lookup {
    /// As `Curl_doh_take_result`: nothing until every probe ended; a name
    /// is said not to exist only if no query failed but by saying so.
    /// What the queries that ended have found (`Curl_resolv_get_ai`).
    pub(crate) fn partial(&self) -> Result<crate::conn::io::Partial, OutOfMemory> {
        let state = lock(&self.0);
        let mut addrs = Vec::new();
        for query in &state.queries {
            if let Query::Ended(Ok(found)) = query {
                addrs.try_extend_from_slice(found)?;
            }
        }
        Ok(crate::conn::io::Partial {
            addrs,
            v6_answered: !matches!(state.queries[0], Query::Waiting(_)),
            v4_answered: !matches!(state.queries[1], Query::Waiting(_)),
        })
    }

    /// What a resolve of an HTTPS record came to, once its query ended
    /// (`Curl_doh_take_result`).
    pub(crate) fn https(&self) -> Option<RecordAnswer> {
        let mut state = lock(&self.0);
        Some(match state.queries[0] {
            Query::Ended(Ok(_)) => match state.record.take() {
                Some(record) => RecordAnswer::Record(record),
                None => RecordAnswer::NoRecord,
            },
            Query::Ended(Err(QueryFailure::NoSuchName)) => RecordAnswer::NoSuchName,
            Query::Ended(Err(QueryFailure::Other)) => RecordAnswer::Failed,
            _ => return None,
        })
    }

    pub(crate) fn poll(&self) -> Polled {
        let mut state = lock(&self.0);
        let ended = |q: &Query| matches!(q, Query::Ended(_));
        let [v6, v4] = &state.queries;
        let waiting = |q: &Query| matches!(q, Query::Waiting(_));
        if waiting(v6) || waiting(v4) {
            return Polled::Waiting {
                ongoing: u32::from(waiting(v6)) + u32::from(waiting(v4)),
                responses: match (ended(v6), ended(v4)) {
                    (true, false) => "AAAA",
                    (false, true) => "A",
                    _ => "-",
                },
            };
        }
        let mut addrs = Vec::new();
        let mut negative = true;
        for query in &mut state.queries {
            if let Query::Ended(ended) = query {
                match ended {
                    Ok(found) if addrs.is_empty() => addrs = std::mem::take(found),
                    Ok(found) => {
                        if addrs.try_extend_from_slice(found).is_err() {
                            return Polled::Done(Err(ResolveFailure::OutOfMemory));
                        }
                    }
                    Err(QueryFailure::NoSuchName) => {}
                    Err(QueryFailure::Other) => negative = false,
                }
            }
        }
        Polled::Done(if !addrs.is_empty() {
            Ok(addrs)
        } else if negative {
            Err(ResolveFailure::NotFound)
        } else {
            Err(ResolveFailure::Failed)
        })
    }
}

/// Start the resolve of `name` in `family` over DoH, if the transfer of
/// `cx` wants that, a probe for each query, IPv6's first as it has the
/// preference in happy eyeballing (`Curl_doh`).
pub(crate) fn start<H: Host>(
    cx: &mut StepCx<'_, H>,
    name: &[u8],
    family: Family,
) -> Result<Lookup, ConnectError> {
    let released = cx
        .rest
        .reaping
        .share()
        .map_err(|OutOfMemory| ConnectError::OutOfMemory)?;
    let mut queries = [Query::Unasked, Query::Unasked];
    if family != Family::V4 {
        queries[0] = Query::Waiting(Vec::new());
    }
    if family != Family::V6 {
        queries[1] = Query::Waiting(Vec::new());
    }
    let shared = TryArc::try_new(Mutex::new(State {
        gone: false,
        queries,
        record: None,
        released,
    }))
    .map_err(|OutOfMemory| ConnectError::OutOfMemory)?;
    // Whatever failed part of the way, the probes started go with this.
    let lookup = Lookup(shared.clone());
    for (query, what) in [(0, QueryType::Aaaa), (1, QueryType::A)] {
        if matches!(lock(&shared).queries[query], Query::Waiting(_)) {
            let probe = Probe {
                shared: shared.clone(),
                query,
                what,
            };
            run_probe(cx, name, probe)?;
        }
    }
    Ok(lookup)
}

/// Start the resolve of `name`'s HTTPS record on `port` over DoH, named as
/// a record for another port than HTTPS's is (`Curl_doh`).
pub(crate) fn start_https<H: Host>(
    cx: &mut StepCx<'_, H>,
    name: &[u8],
    port: u16,
) -> Result<Lookup, ConnectError> {
    let oom = |OutOfMemory| ConnectError::OutOfMemory;
    let released = cx.rest.reaping.share().map_err(oom)?;
    let shared = TryArc::try_new(Mutex::new(State {
        gone: false,
        queries: [Query::Waiting(Vec::new()), Query::Unasked],
        record: None,
        released,
    }))
    .map_err(oom)?;
    let lookup = Lookup(shared.clone());
    let mut asked = Vec::new();
    if port != 443 {
        let prefix = crate::text::Text::<24>::clipped(format_args!("_{port}._https."));
        asked.try_extend_from_slice(prefix.0.bytes()).map_err(oom)?;
    }
    asked.try_extend_from_slice(name).map_err(oom)?;
    let probe = Probe {
        shared,
        query: 0,
        what: QueryType::Https,
    };
    run_probe(cx, &asked, probe)?;
    Ok(lookup)
}

/// One probe made and added (`doh_probe_run`).
fn run_probe<H: Host>(
    cx: &mut StepCx<'_, H>,
    name: &[u8],
    probe: Probe,
) -> Result<(), ConnectError> {
    let oom = |OutOfMemory| ConnectError::OutOfMemory;
    let query = match encode_query(name, probe.what) {
        Ok(query) => query,
        // C says so, and fails as if out of memory.
        Err(e) => {
            trace::fail(
                cx,
                ErrorKind::OutOfMemory,
                format_args!("Failed to encode DoH packet [{}]", number(e)),
            );
            return Err(ConnectError::OutOfMemory);
        }
    };
    // What is left of the master's time is the probe's.
    let left = match cx.time_left() {
        TimeLeft::Unlimited => None,
        TimeLeft::Remaining(left) => Some(left),
        TimeLeft::Expired(_) => {
            return Err(ConnectError::Failed(None, ErrorKind::OperationTimedout));
        }
    };
    let body = Handler::write(ProbeBody(probe.clone())).map_err(oom)?;
    let easy = cx.easy().doh_probe(&query, body, left).map_err(oom)?;
    let easy = try_box(easy).map_err(oom)?;
    let master = cx.me;
    let rest = &mut cx.rest;
    let t = &mut rest.tell;
    let mut ecx = EventCx {
        alive: &*t.alive,
        slots: &mut *t.slots,
        limits: &mut *t.limits,
        notify: &mut *t.notify,
        counts: t.counts.get(),
        sockets: &mut *t.sockets,
        // The pool is the step's, apart from the multi meanwhile.
        pool: None,
    };
    let (easy, host) = rest.events.internal(&mut ecx, master, easy).map_err(oom)?;
    let rows = Rows {
        slots: &mut *rest.tell.slots,
        timers: &mut *rest.timers,
        dirty: &mut *rest.dirty,
        notify: &mut *rest.tell.notify,
    };
    let owner = Owner::Internal {
        master,
        host,
        probe,
    };
    let id = match super::insert(
        rows,
        &mut *rest.tell.counts,
        &mut rest.caches.pool,
        easy,
        owner,
    ) {
        Ok(id) => id,
        Err((refused, owner)) => {
            if let Owner::Internal { host: Some(h), .. } = owner {
                rest.events.internal_gone(refused.easy, h);
            }
            return Err(ConnectError::OutOfMemory);
        }
    };
    rest.tell.counts.internal_added();
    rest.dirty.insert(id.index());
    // The host is not told of it (`MultiEvents::added`): its id is no
    // call's to take.
    let mut cx = StepCx::new(id, rest.reborrow());
    super::trace_membership(&mut cx, "added to");
    Ok(())
}

/// What C says of a record it refuses, its `CURLcode`'s words.
fn record_error(e: RecordError) -> &'static str {
    match e {
        RecordError::BadParameter => ErrorKind::BadFunctionArgument.message(),
        RecordError::BadName | RecordError::OutOfMemory => ErrorKind::OutOfMemory.message(),
        RecordError::Weird => ErrorKind::WeirdServerReply.message(),
        RecordError::BadAlpn => ErrorKind::BadContentEncoding.message(),
    }
}

/// C's number for a query that cannot be made, as its failure says it.
fn number(e: DohError) -> u8 {
    match e {
        DohError::BadLabel => 1,
        DohError::OutOfRange => 2,
        DohError::TooSmall => 4,
        DohError::OutOfMemory => 5,
        DohError::RdataLength => 6,
        DohError::Malformed => 7,
        DohError::BadRcode => 8,
        DohError::UnexpectedType => 9,
        DohError::UnexpectedClass => 10,
        DohError::BadId => 12,
        DohError::NameTooLong => 13,
        DohError::NoSuchName => 14,
    }
}

/// The probe `cx` is for ended with `result`: its answer read into its
/// resolve, and its master, `master`, run again (`doh_probe_done`).
pub(super) fn probe_done<H: Host>(
    cx: &mut StepCx<'_, H>,
    probe: &Probe,
    master: TransferId,
    result: Result<(), ErrorKind>,
) {
    let name = probe.what.name();
    let mut state = lock(&probe.shared);
    if state.gone {
        return;
    }
    let Query::Waiting(body) = std::mem::replace(
        &mut state.queries[probe.query],
        Query::Ended(Err(QueryFailure::Other)),
    ) else {
        return;
    };
    let code = cx.easy().report().response_code().unwrap_or(0);
    let ended = match result {
        Err(kind) => {
            trace::info(cx, format_args!("[DoH] [{name}] error: {}", kind.message()));
            Err(QueryFailure::Other)
        }
        Ok(()) if !(200..300).contains(&code) => {
            trace::info(cx, format_args!("[DoH] [{name}] error: HTTP status {code}"));
            Err(QueryFailure::Other)
        }
        Ok(()) => match decode_answer(&body, probe.what) {
            Err(e) => {
                trace::info(
                    cx,
                    format_args!("[DoH] [{name}] error decoding response: {e}"),
                );
                Err(match e {
                    DohError::NoSuchName => QueryFailure::NoSuchName,
                    _ => QueryFailure::Other,
                })
            }
            Ok(answer) if probe.what == QueryType::Https && !answer.https.is_empty() => {
                let n = answer.https.len();
                trace::of(
                    cx,
                    crate::components::Component::Dns,
                    format_args!("[HTTPS] got {n} records"),
                );
                match decode_https_record(answer.https[0]) {
                    Ok(record) => {
                        state.record = Some(record);
                        trace::info(cx, format_args!("DoH request complete, 0 to go"));
                        Ok(Vec::new())
                    }
                    Err(e) => {
                        let why = record_error(e);
                        trace::info(cx, format_args!("[DoH] error decoding HTTPS RR: {why}"));
                        Err(QueryFailure::Other)
                    }
                }
            }
            Ok(answer) => {
                let waiting = state
                    .queries
                    .iter()
                    .filter(|q| matches!(q, Query::Waiting(_)))
                    .count();
                trace::info(cx, format_args!("DoH request complete, {waiting} to go"));
                Ok(answer.addrs)
            }
        },
    };
    state.queries[probe.query] = Query::Ended(ended);
    drop(state);
    cx.wake(master);
}

/// Whether the master of the internal transfer `id` is gone, its `Lookup`
/// with it.
pub(super) fn orphan<H: Host>(slots: &Slots<H>, id: TransferId) -> bool {
    let Some(slot) = slots.get(id) else {
        return false;
    };
    match &slot.owner {
        Owner::App(_) => false,
        Owner::Internal { master, probe, .. } => probe.orphaned() || slots.get(*master).is_none(),
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::disallowed_macros)]
mod tests {
    use super::*;

    fn lookup(queries: [Query; 2]) -> Lookup {
        let shared = TryArc::try_new(Mutex::new(State {
            gone: false,
            queries,
            record: None,
            released: Released::new().unwrap(),
        }))
        .unwrap();
        Lookup(shared)
    }

    fn polled(queries: [Query; 2]) -> Polled {
        lookup(queries).poll()
    }

    /// What has come while a probe runs: the addresses of the queries that
    /// ended, and which have, a query never asked counted as answered.
    #[test]
    fn a_lookup_going_on_says_which_queries_answered() {
        let waiting = || Query::Waiting(Vec::new());
        let ip = |a: &str| a.parse::<IpAddr>().unwrap();
        for (queries, v6, v4, addrs) in [
            ([waiting(), waiting()], false, false, vec![]),
            ([found("::1"), waiting()], true, false, vec![ip("::1")]),
            (
                [waiting(), found("127.0.0.1")],
                false,
                true,
                vec![ip("127.0.0.1")],
            ),
            ([Query::Unasked, waiting()], true, false, vec![]),
            ([waiting(), Query::Unasked], false, true, vec![]),
        ] {
            let part = lookup(queries).partial().unwrap();
            assert_eq!((part.v6_answered, part.v4_answered), (v6, v4), "{part:?}");
            assert_eq!(part.addrs, addrs);
        }
    }

    fn found(a: &str) -> Query {
        Query::Ended(Ok(vec![a.parse().unwrap()]))
    }

    /// While a probe runs the resolve says how many do and which ended,
    /// as `Curl_resolv_query_str` names them.
    #[test]
    fn a_lookup_waiting_says_what_ended() {
        let waiting = || Query::Waiting(Vec::new());
        for (queries, ongoing, named) in [
            ([waiting(), waiting()], 2, "-"),
            ([found("::1"), waiting()], 1, "AAAA"),
            ([waiting(), found("127.0.0.1")], 1, "A"),
            ([Query::Unasked, waiting()], 1, "-"),
        ] {
            let Polled::Waiting {
                ongoing: o,
                responses,
            } = polled(queries)
            else {
                panic!("a probe runs");
            };
            assert_eq!((o, responses), (ongoing, named));
        }
    }

    /// Once every probe ended: the addresses, IPv6's first; no such name
    /// only if every query said so; anything else a failure.
    #[test]
    fn a_lookup_done_gives_its_answer() {
        let done = |queries| match polled(queries) {
            Polled::Done(answer) => answer,
            Polled::Waiting { .. } => panic!("every probe ended"),
        };
        let ip = |a: &str| a.parse::<IpAddr>().unwrap();
        assert_eq!(
            done([found("::1"), found("127.0.0.1")]),
            Ok(vec![ip("::1"), ip("127.0.0.1")])
        );
        assert_eq!(
            done([Query::Unasked, found("127.0.0.1")]),
            Ok(vec![ip("127.0.0.1")])
        );
        let none = || Query::Ended(Err(QueryFailure::NoSuchName));
        let other = || Query::Ended(Err(QueryFailure::Other));
        assert_eq!(done([none(), none()]), Err(ResolveFailure::NotFound));
        assert_eq!(done([none(), other()]), Err(ResolveFailure::Failed));
        assert_eq!(
            done([other(), found("127.0.0.1")]),
            Ok(vec![ip("127.0.0.1")])
        );
    }

    /// The numbers C's `DOHcode` gives each failure to make a query.
    #[test]
    fn a_query_that_cannot_be_made_is_numbered_as_c_numbers_it() {
        for (e, n) in [
            (DohError::BadLabel, 1),
            (DohError::OutOfRange, 2),
            (DohError::TooSmall, 4),
            (DohError::OutOfMemory, 5),
            (DohError::RdataLength, 6),
            (DohError::Malformed, 7),
            (DohError::BadRcode, 8),
            (DohError::UnexpectedType, 9),
            (DohError::UnexpectedClass, 10),
            (DohError::BadId, 12),
            (DohError::NameTooLong, 13),
            (DohError::NoSuchName, 14),
        ] {
            assert_eq!(number(e), n, "{e:?}");
        }
    }

    /// A record refused is said in the words of C's `CURLcode` for it.
    #[test]
    fn a_record_refused_is_said_in_cs_words() {
        for (e, words) in [
            (
                RecordError::BadParameter,
                "A libcurl function was given a bad argument",
            ),
            (RecordError::BadName, "Out of memory"),
            (RecordError::OutOfMemory, "Out of memory"),
            (RecordError::Weird, "Weird server reply"),
            (
                RecordError::BadAlpn,
                "Unrecognized or bad HTTP Content or Transfer-Encoding",
            ),
        ] {
            assert_eq!(record_error(e), words, "{e:?}");
        }
    }
}
