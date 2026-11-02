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

use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

use curl_alloc::{OutOfMemory, TryArc, TryVec, try_box};

use super::timers::TimeLeft;
use super::{EventCx, Host, Owner, Rows, Slots, StepCx, TransferId};
use crate::conn::ConnectError;
use crate::conn::io::{Family, ResolveFailure};
use crate::doh::{DohError, QueryType, decode_answer, encode_query};
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
    /// IPv6's, then IPv4's, as the probes start.
    queries: [Query; 2],
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
        lock(&self.0).gone = true;
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
    // What is left of the master's time is the probe's. Past it, the master
    // fails as its own timer says as soon as it is next run.
    let left = match cx.time_left() {
        TimeLeft::Unlimited => None,
        TimeLeft::Remaining(left) => Some(left),
        TimeLeft::Expired(_) => Some(std::time::Duration::from_millis(1)),
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
    let slot = rest.tell.slots.get(id).expect("just added");
    if let Owner::Internal { host: Some(h), .. } = &slot.owner {
        rest.events.added(id, h);
    }
    let mut cx = StepCx::new(id, rest.reborrow());
    super::trace_membership(&mut cx, "added to");
    Ok(())
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
