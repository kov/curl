//! The threaded resolver (`lib/vdns/asyn-thrdd.c`, `thrdpool.c`,
//! `thrdqueue.c`): each resolve's queries are queued for a pool of threads,
//! each query a thread's `getaddrinfo`, and a finished one wakes the multi
//! through the resolver's eventfd, as C's `wakeup_internal` does.
//!
//! The pool keeps no thread while idle: one is started for a query when
//! none is idle, up to the most allowed, and one idle longer than the
//! idle time ends (C's `min_threads` is 0). A thread that cannot be
//! started leaves its query queued; the next start, or the multi's next
//! pass, tries again.
//!
//! Each resolve is handed to its waiter as a `Handle` owning its place in
//! the resolver: everything of it, its queries queued and its answers,
//! lives under the resolver's lock beside the threads', and the handle
//! dropped takes it all out, whoever drops it and wherever.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};

use super::io::{Family, Partial, Resolve, ResolveFailure, Resolver, Resolving, Waiter, Waker};

/// How many threads a pool keeps at most, and how long an idle one
/// waits for work before it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threads {
    pub max: NonZeroU32,
    pub idle: Duration,
}

impl Threads {
    /// A multi made for an easy handle's transfer (`curl_easy_perform`).
    pub const EASY: Threads = Threads {
        max: NonZeroU32::new(2).expect("not 0"),
        idle: Duration::from_millis(10),
    };

    /// Any other multi (`CURLMOPT_RESOLVE_THREADS_MAX`'s default).
    pub const MULTI: Threads = Threads {
        max: NonZeroU32::new(20).expect("not 0"),
        idle: Duration::from_millis(2000),
    };
}

/// The C debug build's variables for the resolver, read as it is made:
/// each query held back `delay` before it is asked
/// (`CURL_DBG_RESOLV_DELAY`), or held back `fail_delay` and up to 255 ms
/// more and then failed, as a name that does not exist if `fail_negative`
/// (`CURL_DBG_RESOLV_FAIL_DELAY`, `CURL_DBG_RESOLV_FAIL_NEGATIVE`); at most
/// `max_threads` threads (`CURL_DBG_RESOLV_MAX_THREADS`, 0 not taken); and
/// the first `fail_starts` threads not started
/// (`CURL_DBG_THRDPOOL_FAIL_STARTS`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DebugVars {
    pub delay: Option<Duration>,
    pub fail_delay: Option<Duration>,
    pub fail_negative: bool,
    pub max_threads: Option<NonZeroU32>,
    pub fail_starts: u32,
}

/// The debug build's variables as the environment sets them, each value
/// as given, or `fail_negative` set at all.
#[derive(Clone, Copy, Debug, Default)]
pub struct GivenVars<'a> {
    pub delay: Option<&'a [u8]>,
    pub fail_delay: Option<&'a [u8]>,
    pub fail_negative: bool,
    pub max_threads: Option<&'a [u8]>,
    pub fail_starts: Option<&'a [u8]>,
}

impl DebugVars {
    /// As the environment sets them, in a debug build; none in another.
    pub fn from_env() -> DebugVars {
        #[cfg(feature = "debug-hooks")]
        {
            use curl_os::env::{is_set, var_into};
            let mut bufs = [[0u8; 32]; 4];
            let [delay, fail_delay, max_threads, fail_starts] = &mut bufs;
            DebugVars::from_given(GivenVars {
                delay: var_into(b"CURL_DBG_RESOLV_DELAY", delay),
                fail_delay: var_into(b"CURL_DBG_RESOLV_FAIL_DELAY", fail_delay),
                fail_negative: is_set(b"CURL_DBG_RESOLV_FAIL_NEGATIVE"),
                max_threads: var_into(b"CURL_DBG_RESOLV_MAX_THREADS", max_threads),
                fail_starts: var_into(b"CURL_DBG_THRDPOOL_FAIL_STARTS", fail_starts),
            })
        }
        #[cfg(not(feature = "debug-hooks"))]
        DebugVars::default()
    }

    /// The variables' values read as C reads them: each a number it
    /// starts with, no larger than C's type holds; a delay of 0 is none,
    /// and so are no threads.
    pub fn from_given(given: GivenVars<'_>) -> DebugVars {
        let max = u64::from(u32::MAX);
        let ms = |v| number(v, max).map(Duration::from_millis);
        DebugVars {
            delay: ms(given.delay).filter(|d| !d.is_zero()),
            fail_delay: ms(given.fail_delay),
            fail_negative: given.fail_negative,
            max_threads: number(given.max_threads, max)
                .and_then(|n| NonZeroU32::new(u32::try_from(n).expect("no larger than max"))),
            fail_starts: number(given.fail_starts, i32::MAX as u64)
                .map_or(0, |n| u32::try_from(n).expect("no larger than max")),
        }
    }
}

/// The number `given` starts with, if it is one no larger than `max`
/// (`curlx_str_number`).
fn number(given: Option<&[u8]>, max: u64) -> Option<u64> {
    let digits = given?.iter().take_while(|b| b.is_ascii_digit());
    let mut n: Option<u64> = None;
    for &d in digits {
        let next = n.unwrap_or(0) * 10 + u64::from(d - b'0');
        if next > max {
            return None;
        }
        n = Some(next);
    }
    n
}

/// Which resolve of a resolver's a query is for: numbered on from the
/// last, in 64 bits, never met again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Id(u64);

/// One query of a resolve: one family's addresses.
#[derive(Debug)]
struct Query {
    id: Id,
    name: Vec<u8>,
    family: Family,
    /// What the debug build makes of it: held back before it is asked;
    /// or held back and failed so, not asked at all.
    delay: Option<Duration>,
    fail: Option<(Duration, ResolveFailure)>,
}

/// A query's answer.
#[derive(Debug)]
struct Done {
    id: Id,
    family: Family,
    result: Result<Vec<IpAddr>, ResolveFailure>,
}

/// What the threads, the resolver and its resolves share, under the
/// lock.
#[derive(Debug, Default)]
struct State {
    queue: Vec<Query>,
    done: Vec<Done>,
    /// The resolves whose answers are not taken, each until it is or its
    /// handle is dropped.
    resolving: Vec<Ongoing>,
    /// The threads started, joined as they end, or as the resolver goes.
    handles: Vec<JoinHandle<()>>,
    /// Threads started and not ended, and of them those waiting for work.
    threads: u32,
    idle: u32,
    threads_max: u32,
    idle_time: Duration,
    /// The threads are waited for as the resolver goes, unless the
    /// application asked to exit quickly (`CURLMOPT_QUICK_EXIT`).
    join: bool,
    /// The resolver is gone: the threads end as their query does, and
    /// the queries still queued go with it.
    aborted: bool,
    /// The last thread wanted could not be started: queries wait for the
    /// next try.
    start_failed: bool,
    /// The debug build's starts still to fail.
    fail_starts: u32,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    /// A query was queued, or the pool aborted.
    work: Condvar,
    /// A query was answered.
    answered: Condvar,
    waker: TryArc<Waker>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("no thread panics holding the resolver's lock")
    }
}

/// A resolve whose queries are out.
#[derive(Debug)]
struct Ongoing {
    id: Id,
    waiter: Waiter,
    /// Its queries not answered yet.
    left: u8,
    /// IPv6's addresses were asked for.
    asked_v6: bool,
    /// IPv4's were.
    asked_v4: bool,
    v6: Option<Result<Vec<IpAddr>, ResolveFailure>>,
    v4: Option<Result<Vec<IpAddr>, ResolveFailure>>,
    /// Its queries left when it was last told of.
    told: Option<u8>,
}

/// The threaded resolver of one multi.
#[derive(Debug)]
pub struct ThreadedResolver {
    shared: TryArc<Shared>,
    next: Id,
    debug: DebugVars,
}

impl ThreadedResolver {
    pub fn new(threads: Threads) -> Result<ThreadedResolver, std::io::Error> {
        let waker = TryArc::try_new(Waker::new()?)
            .map_err(|OutOfMemory| std::io::ErrorKind::OutOfMemory)?;
        let state = State {
            threads_max: threads.max.get(),
            idle_time: threads.idle,
            join: true,
            ..State::default()
        };
        let shared = TryArc::try_new(Shared {
            state: Mutex::new(state),
            work: Condvar::new(),
            answered: Condvar::new(),
            waker,
        })
        .map_err(|OutOfMemory| std::io::ErrorKind::OutOfMemory)?;
        Ok(ThreadedResolver {
            shared,
            next: Id(0),
            debug: DebugVars::default(),
        })
    }

    /// One that does what the debug build's variables `vars` say.
    pub fn with_debug(
        threads: Threads,
        vars: DebugVars,
    ) -> Result<ThreadedResolver, std::io::Error> {
        let mut r = ThreadedResolver::new(Threads {
            max: vars.max_threads.unwrap_or(threads.max),
            ..threads
        })?;
        r.shared.lock().fail_starts = vars.fail_starts;
        r.debug = vars;
        Ok(r)
    }

    /// Queue `queries`, starting a thread for them if none is idle.
    fn queue(&mut self, queries: &mut Vec<Query>) -> Result<(), OutOfMemory> {
        {
            let mut state = self.shared.lock();
            state
                .queue
                .try_reserve(queries.len())
                .map_err(|_| OutOfMemory)?;
            for q in queries.drain(..) {
                state.queue.try_push(q)?;
            }
        }
        self.shared.work.notify_all();
        start_threads(&self.shared);
        Ok(())
    }
}

/// As many threads as the queue wants and the most allows; one that
/// cannot be started leaves its query queued for the next try. None once
/// the resolver is gone, which empties the queue.
fn start_threads(shared: &TryArc<Shared>) {
    reap(shared);
    loop {
        {
            let mut state = shared.lock();
            let wanted = state.queue.len() as u32;
            if wanted <= state.idle || state.threads >= state.threads_max {
                state.start_failed = false;
                return;
            }
            if state.fail_starts > 0 {
                state.fail_starts -= 1;
                state.start_failed = true;
                return;
            }
            state.threads += 1;
        }
        let for_thread = shared.clone();
        // std's start allocates without asking: a failure to start
        // that it reports leaves the query for the next try.
        let started = std::thread::Builder::new()
            .name("curl-resolver".into())
            .spawn(move || work(&for_thread));
        let mut state = shared.lock();
        match started {
            // Without room to keep its handle, it runs detached.
            Ok(handle) => {
                let _detached = state.handles.try_push(handle);
            }
            Err(_) => {
                state.threads -= 1;
                state.start_failed = true;
                return;
            }
        }
    }
}

/// Join the threads that have ended.
fn reap(shared: &Shared) {
    let mut ended = Vec::new();
    {
        let mut state = shared.lock();
        let mut at = 0;
        while at < state.handles.len() {
            if state.handles[at].is_finished() {
                // Without room to hold it, it is joined at the next reap.
                if ended.try_push(state.handles.swap_remove(at)).is_err() {
                    break;
                }
            } else {
                at += 1;
            }
        }
    }
    for handle in ended {
        handle.join().expect("a resolver thread does not panic");
    }
}

/// Move the answers the threads gave to their resolves; one for a
/// resolve dropped is dropped.
fn collect(state: &mut State) {
    let done = std::mem::take(&mut state.done);
    for d in done {
        let Some(r) = state.resolving.iter_mut().find(|r| r.id == d.id) else {
            continue;
        };
        match d.family {
            Family::V6 => r.v6 = Some(d.result),
            _ => r.v4 = Some(d.result),
        }
        r.left -= 1;
    }
}

/// A resolve's answer from its queries': every address, IPv6's first; or
/// with none, a failure, negative only if every query said the name has
/// none (`Curl_async_take_result`).
fn merged(
    v6: Option<Result<Vec<IpAddr>, ResolveFailure>>,
    v4: Option<Result<Vec<IpAddr>, ResolveFailure>>,
) -> Result<Vec<IpAddr>, ResolveFailure> {
    let mut addrs = Vec::new();
    let mut failures = [None, None];
    for (at, answer) in [v6, v4].into_iter().enumerate() {
        match answer {
            Some(Ok(found)) => addrs.try_extend_from_slice(&found)?,
            Some(Err(why)) => failures[at] = Some(why),
            None => {}
        }
    }
    if !addrs.is_empty() {
        return Ok(addrs);
    }
    let negative =
        |f: &ResolveFailure| matches!(f, ResolveFailure::NotFound | ResolveFailure::NoData);
    let failed = failures.iter().flatten();
    match failed.clone().find(|f| !negative(f)) {
        Some(&why) => Err(why),
        None if failed.clone().any(|f| *f == ResolveFailure::NotFound) => {
            Err(ResolveFailure::NotFound)
        }
        None => Err(ResolveFailure::NoData),
    }
}

/// A thread's life: take a query, answer it, wake the multi; wait for the
/// next, and end once idle past the idle time, or as the pool aborts
/// (`thrdslot_run`).
fn work(shared: &Shared) {
    let mut state = shared.lock();
    loop {
        if state.aborted {
            break;
        }
        if !state.queue.is_empty() {
            let q = state.queue.remove(0);
            drop(state);
            if let Some(delay) = q.delay {
                std::thread::sleep(delay);
            }
            let result = match q.fail {
                Some((delay, why)) => {
                    std::thread::sleep(delay);
                    Err(why)
                }
                None => curl_os::resolve::lookup(&q.name, q.family),
            };
            state = shared.lock();
            let done = Done {
                id: q.id,
                family: q.family,
                result,
            };
            // Without room for it, the answer is that memory ran out.
            if let Err(OutOfMemory) = state.done.try_push(done) {
                let lost = Done {
                    id: q.id,
                    family: q.family,
                    result: Err(ResolveFailure::OutOfMemory),
                };
                if state.done.try_push(lost).is_err() {
                    continue;
                }
            }
            shared.answered.notify_all();
            // A wake that fails leaves the answer for the next pass.
            let _unsaid = shared.waker.wake();
            continue;
        }
        if state.threads > state.threads_max {
            break;
        }
        state.idle += 1;
        let idle_time = state.idle_time;
        let (next, waited) = shared
            .work
            .wait_timeout(state, idle_time)
            .expect("no thread panics holding the resolver's lock");
        state = next;
        state.idle -= 1;
        if waited.timed_out() && state.queue.is_empty() {
            break;
        }
    }
    state.threads -= 1;
}

impl Resolver for ThreadedResolver {
    fn start(
        &mut self,
        name: &[u8],
        family: Family,
        waiter: Waiter,
    ) -> Result<Resolve, ResolveFailure> {
        let id = self.next;
        self.next = Id(id.0 + 1);
        // Both families are a query each, IPv6's queued first.
        let families: &[Family] = match family {
            Family::Any => &[Family::V6, Family::V4],
            Family::V4 => &[Family::V4],
            Family::V6 => &[Family::V6],
        };
        let mut queries = Vec::new();
        for &family in families {
            let mut copy = Vec::new();
            copy.try_extend_from_slice(name)?;
            let fail = self.debug.fail_delay.map(|delay| {
                // A random byte more, as C's debug build adds.
                let mut more = [0u8];
                let _unrandom = curl_os::random::fill(&mut more);
                let why = match self.debug.fail_negative {
                    true => ResolveFailure::NotFound,
                    false => ResolveFailure::Failed,
                };
                (delay + Duration::from_millis(u64::from(more[0])), why)
            });
            queries.try_push(Query {
                id,
                name: copy,
                family,
                delay: self.debug.delay,
                fail,
            })?;
        }
        self.shared.lock().resolving.try_push(Ongoing {
            id,
            waiter,
            left: families.len() as u8,
            v6: None,
            v4: None,
            asked_v6: families.contains(&Family::V6),
            asked_v4: families.iter().any(|&f| f != Family::V6),
            told: None,
        })?;
        // Held from here, so that whatever fails takes it out again.
        let handle = Handle {
            shared: self.shared.clone(),
            id,
        };
        self.queue(&mut queries)?;
        Ok(Resolve::Pending {
            resolve: try_box(handle)?,
            v6: families.contains(&Family::V6),
            v4: families.contains(&Family::V4),
        })
    }

    fn answered(&mut self, each: &mut dyn FnMut(Waiter)) {
        // The wake is taken as the answers are.
        let _drained = self.shared.waker.drain();
        {
            let mut state = self.shared.lock();
            collect(&mut state);
            for r in &mut state.resolving {
                // Each answer is told of, as what came may be connected to.
                if r.told != Some(r.left) && (r.left == 0 || r.v6.is_some() || r.v4.is_some()) {
                    r.told = Some(r.left);
                    each(r.waiter);
                }
            }
        }
        start_threads(&self.shared);
    }

    fn waker(&self) -> Option<TryArc<Waker>> {
        Some(self.shared.waker.clone())
    }

    /// Nothing: C's threaded resolver gives no reason
    /// (`async_thrdd_check_done`).
    fn explain(&self, _: ResolveFailure) -> Option<&'static str> {
        None
    }

    fn pool(&self) -> Option<ResolverThreads> {
        Some(ResolverThreads(self.shared.clone()))
    }

    fn retry(&self) -> Option<Duration> {
        let state = self.shared.lock();
        (state.start_failed && !state.queue.is_empty()).then_some(Duration::from_millis(100))
    }

    /// Asked, as C's threaded build asks it for a name's HTTPS record,
    /// which it never answers.
    fn asked_for_records(&self) -> bool {
        true
    }
}

/// One resolve of the threaded resolver's, held by what waits for it.
#[derive(Debug)]
struct Handle {
    shared: TryArc<Shared>,
    id: Id,
}

impl Resolving for Handle {
    fn answer(&mut self) -> Option<Result<Vec<IpAddr>, ResolveFailure>> {
        let taken = {
            let mut state = self.shared.lock();
            collect(&mut state);
            let at = state
                .resolving
                .iter()
                .position(|r| r.id == self.id)
                .expect("a resolve's answer is taken once");
            (state.resolving[at].left == 0).then(|| state.resolving.remove(at))
        };
        match taken {
            Some(r) => Some(merged(r.v6, r.v4)),
            None => {
                // A query a thread could not be started for is tried again.
                start_threads(&self.shared);
                None
            }
        }
    }

    fn partial(&mut self) -> Result<Option<Partial>, OutOfMemory> {
        let mut state = self.shared.lock();
        collect(&mut state);
        let Some(r) = state.resolving.iter().find(|r| r.id == self.id) else {
            return Ok(None);
        };
        let mut addrs = Vec::new();
        for found in [&r.v6, &r.v4].into_iter().flatten().flatten() {
            addrs.try_extend_from_slice(found)?;
        }
        Ok(Some(Partial {
            addrs,
            v6_answered: r.v6.is_some() || !r.asked_v6,
            v4_answered: r.v4.is_some() || !r.asked_v4,
        }))
    }

    fn wait(&mut self) -> Result<Vec<IpAddr>, ResolveFailure> {
        loop {
            if let Some(answer) = self.answer() {
                return answer;
            }
            let state = self.shared.lock();
            // With the resolver gone, its queries queued are too.
            if state.aborted {
                return Err(ResolveFailure::Failed);
            }
            if state.done.is_empty() {
                // Woken by any answer, or after a while to start a
                // thread again.
                let _waited = self
                    .shared
                    .answered
                    .wait_timeout(state, Duration::from_millis(100))
                    .expect("no thread panics holding the resolver's lock");
            }
        }
    }
}

impl Drop for Handle {
    /// Its place let go of, its answer taken or not: its queries still
    /// queued go, and an answer that comes after is dropped as it is
    /// collected (`Curl_resolv_destroy`).
    fn drop(&mut self) {
        let id = self.id;
        let mut state = self.shared.lock();
        state.resolving.retain(|r| r.id != id);
        state.queue.retain(|q| q.id != id);
    }
}

/// The settings of a resolver's pool, reached beside the resolver that
/// owns it: the multi keeps one, so that an option set from inside its
/// callbacks, while a transfer holds the network, reaches the pool.
#[derive(Clone, Debug)]
pub struct ResolverThreads(TryArc<Shared>);

impl ResolverThreads {
    /// The most threads kept (`CURLMOPT_RESOLVE_THREADS_MAX`). A query
    /// queued for want of a thread gets one at the multi's next pass,
    /// which the wake brings on (`Curl_thrdq_set_props`).
    pub fn set_max_threads(&self, max: NonZeroU32) {
        let mut state = self.0.lock();
        state.threads_max = max.get();
        if state.queue.len() as u32 > state.idle {
            // A wake that fails leaves the queries for the next pass.
            let _unsaid = self.0.waker.wake();
        }
    }

    /// Whether the threads are waited for as the resolver goes; not, as
    /// the application asks to exit quickly (`CURLMOPT_QUICK_EXIT`).
    pub fn set_join(&self, join: bool) {
        self.0.lock().join = join;
    }

    /// The most threads, and whether they are joined.
    #[cfg(test)]
    pub(crate) fn settings(&self) -> (u32, bool) {
        let state = self.0.lock();
        (state.threads_max, state.join)
    }
}

impl Drop for ThreadedResolver {
    fn drop(&mut self) {
        let handles = {
            let mut state = self.shared.lock();
            state.aborted = true;
            state.queue.clear();
            std::mem::take(&mut state.handles)
        };
        self.shared.work.notify_all();
        if self.shared.lock().join {
            for handle in handles {
                handle.join().expect("a resolver thread does not panic");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resolve of `name` in `family` started, to wait for.
    fn start(r: &mut ThreadedResolver, name: &[u8], family: Family) -> Box<dyn Resolving> {
        match r.start(name, family, Waiter::NONE) {
            Ok(Resolve::Pending { resolve, .. }) => resolve,
            other => panic!("{other:?}"),
        }
    }

    /// Every resolve's answer, waited for, as `answered` tells of each.
    fn answer_all(resolves: &mut [Box<dyn Resolving>]) -> Vec<Result<Vec<IpAddr>, ResolveFailure>> {
        resolves.iter_mut().map(|r| r.wait()).collect()
    }

    /// How many resolves the resolver holds, and how many queries wait.
    fn held(r: &ThreadedResolver) -> (usize, usize) {
        let state = r.shared.lock();
        (state.resolving.len(), state.queue.len())
    }

    /// A name resolves in a thread: the start gives a resolve to wait for,
    /// whose answer comes, and the multi is told which transfer's it is.
    #[test]
    fn a_name_resolves_in_a_thread() {
        let mut r = ThreadedResolver::new(Threads::MULTI).unwrap();
        let answer = start(&mut r, b"localhost", Family::V4).wait().unwrap();
        assert!(answer.contains(&IpAddr::from([127, 0, 0, 1])), "{answer:?}");
        let mut resolve = start(&mut r, b"localhost", Family::V4);
        // Told once, then taken.
        let mut told = Vec::new();
        while told.is_empty() {
            r.answered(&mut |w| told.push(w));
        }
        assert_eq!(told, [Waiter::NONE]);
        r.answered(&mut |_| panic!("told twice"));
        assert!(resolve.answer().unwrap().is_ok());
        assert_eq!(held(&r), (0, 0), "taken");
    }

    /// Both families are two queries, IPv6's addresses first; a name
    /// that does not exist is a negative answer.
    #[test]
    fn both_families_are_two_queries() {
        let mut r = ThreadedResolver::new(Threads::MULTI).unwrap();
        let mut resolves = [
            start(&mut r, b"localhost", Family::Any),
            start(&mut r, b"nonexist.invalid", Family::Any),
        ];
        let answers = answer_all(&mut resolves);
        let found = answers[0].as_ref().unwrap();
        assert!(found.contains(&IpAddr::from([127, 0, 0, 1])), "{found:?}");
        // Each family's answer is kept: IPv6's too, where the system has
        // one for the name.
        for v6 in curl_os::resolve::lookup(b"localhost", Family::V6).unwrap_or_default() {
            assert!(found.contains(&v6), "{v6} in {found:?}");
        }
        if let Some(v6) = found.iter().position(IpAddr::is_ipv6) {
            assert!(
                found[..v6].iter().all(IpAddr::is_ipv6),
                "IPv6's first: {found:?}"
            );
        }
        assert!(
            matches!(
                answers[1],
                Err(ResolveFailure::NotFound | ResolveFailure::NoData)
            ),
            "{:?}",
            answers[1]
        );
    }

    /// A failure has no reason beside the name, as C's threaded resolver
    /// gives none: c-ares's are the reference build's.
    #[test]
    fn a_failure_is_given_no_reason() {
        let r = ThreadedResolver::new(Threads::MULTI).unwrap();
        for why in [
            ResolveFailure::NotFound,
            ResolveFailure::NoData,
            ResolveFailure::Failed,
        ] {
            assert_eq!(r.explain(why), None);
        }
    }

    /// The answer is negative only if every query said so.
    #[test]
    fn a_failure_is_negative_only_if_every_query_says_so() {
        use ResolveFailure::*;
        let addr = IpAddr::from([127, 0, 0, 1]);
        assert_eq!(
            merged(Some(Err(NoData)), Some(Ok(vec![addr]))),
            Ok(vec![addr])
        );
        assert_eq!(
            merged(Some(Err(NoData)), Some(Err(NotFound))),
            Err(NotFound)
        );
        assert_eq!(merged(Some(Err(NoData)), Some(Err(NoData))), Err(NoData));
        assert_eq!(merged(Some(Err(NotFound)), Some(Err(Again))), Err(Again));
        assert_eq!(merged(None, Some(Err(Failed))), Err(Failed));
    }

    /// A resolve is told of as soon as one family has answered, again as
    /// the last does, and not while nothing has come.
    #[test]
    fn a_resolve_is_told_of_as_each_family_answers() {
        let mut r = ThreadedResolver::new(Threads::MULTI).unwrap();
        r.shared
            .lock()
            .resolving
            .try_push(Ongoing {
                id: Id(0),
                waiter: Waiter::NONE,
                left: 2,
                asked_v6: true,
                asked_v4: true,
                v6: None,
                v4: None,
                told: None,
            })
            .unwrap();
        let told = |r: &mut ThreadedResolver| {
            let mut n = 0;
            r.answered(&mut |_| n += 1);
            n
        };
        assert_eq!(told(&mut r), 0, "nothing came");
        {
            let mut state = r.shared.lock();
            state.resolving[0].left = 1;
            state.resolving[0].v4 = Some(Ok(vec![IpAddr::from([127, 0, 0, 1])]));
        }
        assert_eq!(told(&mut r), 1, "A came");
        assert_eq!(told(&mut r), 0, "told once");
        {
            let mut state = r.shared.lock();
            state.resolving[0].left = 0;
            state.resolving[0].v4 = None;
        }
        assert_eq!(told(&mut r), 1, "every query answered, though empty");
        r.shared.lock().resolving.clear();
    }

    /// A resolve dropped while its query is asked leaves nothing in the
    /// resolver: its answer is dropped as it comes, and the multi is not
    /// told of it.
    #[test]
    fn a_resolve_dropped_while_asked_is_never_told() {
        let held_back = DebugVars {
            delay: Some(Duration::from_millis(50)),
            ..DebugVars::default()
        };
        let mut r = ThreadedResolver::with_debug(Threads::EASY, held_back).unwrap();
        let gone = start(&mut r, b"localhost", Family::V4);
        // Its query taken by a thread, out of the queue.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while held(&r) != (1, 0) {
            assert!(std::time::Instant::now() < deadline, "{:?}", held(&r));
            std::thread::yield_now();
        }
        drop(gone);
        assert_eq!(held(&r), (0, 0), "nothing left of it");
        // Its answer comes, and is dropped.
        while r.shared.lock().done.is_empty() {
            assert!(std::time::Instant::now() < deadline, "the answer came");
            std::thread::sleep(Duration::from_millis(1));
        }
        r.answered(&mut |_| panic!("told of a resolve dropped"));
        assert_eq!(held(&r), (0, 0));
        assert!(r.shared.lock().done.is_empty(), "collected");
    }

    /// No more threads than the most run at once, and idle ones end.
    #[test]
    fn threads_are_kept_to_the_most_and_end_when_idle() {
        let mut r = ThreadedResolver::new(Threads {
            max: NonZeroU32::new(2).unwrap(),
            idle: Duration::from_millis(10),
        })
        .unwrap();
        let mut resolves: Vec<_> = (0..6)
            .map(|_| start(&mut r, b"localhost", Family::V4))
            .collect();
        let threads = r.shared.lock().threads;
        assert!(threads <= 2);
        assert!(answer_all(&mut resolves).iter().all(Result::is_ok));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while r.shared.lock().threads > 0 {
            assert!(std::time::Instant::now() < deadline, "idle threads end");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A resolve dropped while its queries wait for a thread takes them
    /// out of the queue, leaving the others', and leaves nothing in the
    /// resolver; and queries waiting for want of a thread, none having
    /// failed to start, ask for no retry.
    #[test]
    fn a_resolve_dropped_takes_its_queries_from_the_queue() {
        let mut r = ThreadedResolver::new(Threads::MULTI).unwrap();
        r.shared.lock().threads_max = 0;
        let gone = start(&mut r, b"localhost", Family::Any);
        let kept = start(&mut r, b"localhost", Family::Any);
        assert_eq!(held(&r), (2, 4));
        assert_eq!(r.retry(), None, "no start failed");
        drop(gone);
        let queued: Vec<_> = r
            .shared
            .lock()
            .queue
            .iter()
            .map(|q| (q.id, q.family))
            .collect();
        assert_eq!(queued, [(Id(1), Family::V6), (Id(1), Family::V4)]);
        assert_eq!(held(&r), (1, 2));
        drop(kept);
        assert_eq!(held(&r), (0, 0), "nothing left");
    }

    /// What has come of a resolve is told while it goes on, and whether
    /// AAAA has answered or was never asked; of one unknown, nothing.
    #[test]
    fn what_came_is_told_while_a_resolve_goes_on() {
        let mut r = ThreadedResolver::new(Threads::MULTI).unwrap();
        let mut v4 = start(&mut r, b"localhost", Family::V4);
        // Its waiter apart from the other's, to tell which is told of.
        let waiter = Waiter(Some(crate::multi::TransferId::lone()));
        let mut any = match r.start(b"localhost", Family::Any, waiter) {
            Ok(Resolve::Pending { resolve, .. }) => resolve,
            other => panic!("{other:?}"),
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut told = 0;
        let part = loop {
            assert!(std::time::Instant::now() < deadline, "not answered");
            r.answered(&mut |w| told += u32::from(w == waiter));
            let part = any.partial().unwrap().expect("it goes on until taken");
            if part.v6_answered && !part.addrs.is_empty() && told >= 1 {
                break part;
            }
            std::thread::yield_now();
        };
        assert!(
            part.addrs.iter().any(|a| a.is_loopback()),
            "{:?}",
            part.addrs
        );
        // A's answer is told as it comes, with AAAA's.
        let part = loop {
            assert!(std::time::Instant::now() < deadline, "A not answered");
            let part = any.partial().unwrap().expect("it goes on until taken");
            if part.v4_answered {
                break part;
            }
            std::thread::yield_now();
        };
        assert!(part.v6_answered, "{part:?}");
        let only_v4 = v4.partial().unwrap().expect("it goes on until taken");
        assert!(only_v4.v6_answered, "AAAA was never asked");
        // Taken, it has nothing more to tell.
        assert!(v4.wait().is_ok());
        assert!(v4.partial().unwrap().is_none(), "gone");
        drop((v4, any));
        let mut only_v6 = start(&mut r, b"localhost", Family::V6);
        let part = only_v6.partial().unwrap().expect("it goes on until taken");
        assert!(part.v4_answered, "A was never asked");
    }

    /// A query asked is not told answered before its answer comes.
    #[test]
    fn a_query_asked_is_not_answered_before_it_comes() {
        let held = DebugVars {
            delay: Some(Duration::from_secs(1)),
            ..DebugVars::default()
        };
        let mut r = ThreadedResolver::with_debug(Threads::MULTI, held).unwrap();
        for (family, v6, v4) in [
            (Family::V4, true, false),
            (Family::V6, false, true),
            (Family::Any, false, false),
        ] {
            let mut resolve = start(&mut r, b"localhost", family);
            let part = resolve.partial().unwrap().expect("it goes on until taken");
            assert_eq!((part.v6_answered, part.v4_answered), (v6, v4), "{family:?}");
        }
    }

    /// An idle thread waits out its idle time while no more than the most
    /// run, though another took the work it was woken for; past the most
    /// (the most lowered), it ends.
    #[test]
    fn an_idle_thread_waits_for_work_within_the_most() {
        let threads_now = |r: &ThreadedResolver| {
            let state = r.shared.lock();
            (state.threads, state.idle)
        };
        let settle = |r: &ThreadedResolver, want: (u32, u32)| {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while threads_now(r) != want {
                assert!(std::time::Instant::now() < deadline, "{:?}", threads_now(r));
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        let start = |r: &mut ThreadedResolver| start(r, b"localhost", Family::V4);
        let long = Duration::from_secs(60);
        // Each query held back a while, so that two at once find no
        // thread idle.
        let held = DebugVars {
            delay: Some(Duration::from_millis(50)),
            ..DebugVars::default()
        };
        let threads = Threads {
            max: NonZeroU32::new(2).unwrap(),
            idle: long,
        };
        let mut r = ThreadedResolver::with_debug(threads, held).unwrap();
        // Two at once take a thread each.
        let mut resolves = [start(&mut r), start(&mut r)];
        assert!(answer_all(&mut resolves).iter().all(Result::is_ok));
        settle(&r, (2, 2));
        // One woken thread takes the next; the other, woken too, waits on.
        assert!(start(&mut r).wait().is_ok());
        std::thread::sleep(Duration::from_millis(20));
        settle(&r, (2, 2));
        // With the most lowered to 1, a thread woken past it ends.
        r.shared.lock().threads_max = 1;
        assert!(start(&mut r).wait().is_ok());
        settle(&r, (1, 1));

        let mut r = ThreadedResolver::new(Threads {
            max: NonZeroU32::MIN,
            idle: long,
        })
        .unwrap();
        assert!(start(&mut r).wait().is_ok());
        std::thread::sleep(Duration::from_millis(20));
        settle(&r, (1, 1));
    }

    /// The resolver going ends its idle threads at once, without waiting
    /// out their idle time.
    #[test]
    fn the_resolver_going_ends_its_threads() {
        let mut r = ThreadedResolver::new(Threads {
            max: NonZeroU32::MIN,
            idle: Duration::from_secs(60),
        })
        .unwrap();
        assert!(start(&mut r, b"localhost", Family::V4).wait().is_ok());
        let shared = r.shared.clone();
        r.shared.lock().join = false;
        drop(r);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while shared.lock().threads > 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the idle thread ended"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// A resolve kept past its resolver, its queries gone with it, fails
    /// when waited for, rather than being waited for for ever, and leaves
    /// nothing as it is dropped.
    #[test]
    fn a_resolve_outliving_its_resolver_fails() {
        let mut r = ThreadedResolver::new(Threads::MULTI).unwrap();
        r.shared.lock().threads_max = 0;
        let mut resolve = start(&mut r, b"localhost", Family::V4);
        let shared = r.shared.clone();
        drop(r);
        assert_eq!(resolve.answer(), None);
        assert_eq!(resolve.wait(), Err(ResolveFailure::Failed));
        drop(resolve);
        assert!(shared.lock().resolving.is_empty());
    }

    /// The settings the multi reaches through the pool are the
    /// resolver's: the most threads bounds those it starts, and a query
    /// left queued for want of a thread wakes the multi when the most is
    /// raised; a quick exit leaves the threads unjoined.
    #[test]
    fn the_pool_s_settings_are_the_resolver_s() {
        let mut r = ThreadedResolver::new(Threads::MULTI).unwrap();
        let pool = r.pool().unwrap();
        pool.set_max_threads(NonZeroU32::MIN);
        let mut resolves: Vec<_> = (0..4)
            .map(|_| start(&mut r, b"localhost", Family::V4))
            .collect();
        let threads = r.shared.lock().threads;
        assert_eq!(threads, 1);
        assert!(answer_all(&mut resolves).iter().all(Result::is_ok));

        assert_eq!(pool.settings(), (1, true));
        pool.set_join(false);
        assert_eq!(pool.settings(), (1, false));

        // A query queued with no thread to take it, in a resolver that has
        // started none: the raise wakes.
        let r = ThreadedResolver::new(Threads::MULTI).unwrap();
        let pool = r.pool().unwrap();
        let waker = r.waker().unwrap();
        let woken = || {
            let fd = [curl_os::poll::PollFd::new(
                waker.fd(),
                curl_os::poll::Events::IN,
            )];
            curl_os::poll::poll(&mut { fd }, Duration::ZERO).unwrap() == 1
        };
        let query = Query {
            id: Id(0),
            name: b"localhost".to_vec(),
            family: Family::V4,
            delay: None,
            fail: None,
        };
        r.shared.lock().threads_max = 0;
        r.shared.lock().queue.push(query);
        assert!(!woken(), "nothing woke yet");
        pool.set_max_threads(NonZeroU32::MIN);
        assert!(woken(), "the raise woke the multi");
        waker.drain().unwrap();
        r.shared.lock().queue.clear();
        pool.set_max_threads(NonZeroU32::MIN);
        assert!(!woken(), "nothing queued, nothing woken");
    }

    /// The debug build's variables are read as C reads them
    /// (`curlx_str_number`): the number each starts with, none past what
    /// its type holds or not starting with a digit; a delay of 0 is none,
    /// as are 0 threads.
    #[test]
    fn the_debug_build_s_variables_are_read_as_c_reads_them() {
        let read = |v: &[u8]| {
            DebugVars::from_given(GivenVars {
                delay: Some(v),
                fail_delay: Some(v),
                max_threads: Some(v),
                fail_starts: Some(v),
                fail_negative: true,
            })
        };
        let ms = Duration::from_millis;
        let some = read(b"42ms");
        assert_eq!(
            some,
            DebugVars {
                delay: Some(ms(42)),
                fail_delay: Some(ms(42)),
                fail_negative: true,
                max_threads: NonZeroU32::new(42),
                fail_starts: 42,
            }
        );
        let zero = read(b"0");
        assert_eq!(
            (
                zero.delay,
                zero.fail_delay,
                zero.max_threads,
                zero.fail_starts
            ),
            (None, Some(ms(0)), None, 0)
        );
        // Past `INT_MAX` for the starts, past `UINT_MAX` for the rest.
        let big = read(b"3000000000");
        assert_eq!(
            (big.delay, big.max_threads, big.fail_starts),
            (Some(ms(3_000_000_000)), NonZeroU32::new(3_000_000_000), 0)
        );
        let past = read(b"4294967296");
        assert_eq!((past.delay, past.max_threads), (None, None));
        assert_eq!(read(b"4294967295").max_threads, NonZeroU32::new(u32::MAX));
        assert_eq!(read(b"2147483647").fail_starts, i32::MAX as u32);
        assert_eq!(
            read(b"x1"),
            DebugVars {
                fail_negative: true,
                ..DebugVars::default()
            }
        );
        assert_eq!(
            DebugVars::from_given(GivenVars::default()),
            DebugVars::default()
        );
    }

    /// The debug build's variables: a held-back failure is negative only
    /// when asked to be; a held-back query still answers; and a thread
    /// that is not started leaves the queries for a retry, 100 ms on,
    /// whose start takes them.
    #[test]
    fn the_debug_build_s_variables_shape_the_resolves() {
        let start = |r: &mut ThreadedResolver| start(r, b"localhost", Family::V4);
        let quick = Duration::from_millis(1);
        for (negative, why) in [
            (false, ResolveFailure::Failed),
            (true, ResolveFailure::NotFound),
        ] {
            let vars = DebugVars {
                fail_delay: Some(quick),
                fail_negative: negative,
                ..DebugVars::default()
            };
            let mut r = ThreadedResolver::with_debug(Threads::EASY, vars).unwrap();
            assert_eq!(start(&mut r).wait(), Err(why));
        }
        let vars = DebugVars {
            delay: Some(Duration::from_millis(20)),
            ..DebugVars::default()
        };
        let mut r = ThreadedResolver::with_debug(Threads::EASY, vars).unwrap();
        let begun = std::time::Instant::now();
        assert!(start(&mut r).wait().is_ok());
        assert!(begun.elapsed() >= Duration::from_millis(20));

        let vars = DebugVars {
            max_threads: NonZeroU32::new(1),
            fail_starts: 2,
            ..DebugVars::default()
        };
        let mut r = ThreadedResolver::with_debug(Threads::MULTI, vars).unwrap();
        assert_eq!(r.shared.lock().threads_max, 1);
        let mut resolve = start(&mut r);
        let threads = r.shared.lock().threads;
        assert_eq!(threads, 0, "the first start failed");
        assert_eq!(r.retry(), Some(Duration::from_millis(100)));
        assert_eq!(resolve.answer(), None, "the second failed");
        assert_eq!(r.retry(), Some(Duration::from_millis(100)));
        assert!(resolve.wait().is_ok(), "the third started");
        assert_eq!(r.retry(), None);
    }
}
