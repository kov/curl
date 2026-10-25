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

use std::net::IpAddr;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use super::io::{Family, Resolve, ResolveFailure, ResolveId, Resolver, Waiter, Waker};

/// How many threads a pool keeps at most, and how long an idle one
/// waits for work before it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threads {
    pub max: u32,
    pub idle: Duration,
}

impl Threads {
    /// A multi made for an easy handle's transfer (`curl_easy_perform`).
    pub const EASY: Threads = Threads {
        max: 2,
        idle: Duration::from_millis(10),
    };

    /// Any other multi (`CURLMOPT_RESOLVE_THREADS_MAX`'s default).
    pub const MULTI: Threads = Threads {
        max: 20,
        idle: Duration::from_millis(2000),
    };
}

/// One query of a resolve: one family's addresses.
#[derive(Debug)]
struct Query {
    id: ResolveId,
    name: Vec<u8>,
    family: Family,
}

/// A query's answer.
#[derive(Debug)]
struct Done {
    id: ResolveId,
    family: Family,
    result: Result<Vec<IpAddr>, ResolveFailure>,
}

/// What the threads and the resolver share, under the lock.
#[derive(Debug, Default)]
struct State {
    queue: Vec<Query>,
    done: Vec<Done>,
    /// Threads started and not ended, and of them those waiting for work.
    threads: u32,
    idle: u32,
    threads_max: u32,
    idle_time: Duration,
    /// The resolver is gone: the threads end as their query does.
    aborted: bool,
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
struct Resolving {
    id: ResolveId,
    waiter: Waiter,
    /// Its queries not answered yet.
    left: u8,
    v6: Option<Result<Vec<IpAddr>, ResolveFailure>>,
    v4: Option<Result<Vec<IpAddr>, ResolveFailure>>,
    told: bool,
}

/// The threaded resolver of one multi.
#[derive(Debug)]
pub struct ThreadedResolver {
    shared: TryArc<Shared>,
    resolving: Vec<Resolving>,
    next: ResolveId,
    /// The threads started, joined as they end, or at the end.
    handles: Vec<JoinHandle<()>>,
    /// The threads are waited for as the resolver goes, unless the
    /// application asked to exit quickly (`CURLMOPT_QUICK_EXIT`).
    join: bool,
}

impl ThreadedResolver {
    pub fn new(threads: Threads) -> Result<ThreadedResolver, std::io::Error> {
        let waker = TryArc::try_new(Waker::new()?)
            .map_err(|OutOfMemory| std::io::ErrorKind::OutOfMemory)?;
        let state = State {
            threads_max: threads.max,
            idle_time: threads.idle,
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
            resolving: Vec::new(),
            next: ResolveId::FIRST,
            handles: Vec::new(),
            join: true,
        })
    }

    /// The most threads kept (`CURLMOPT_RESOLVE_THREADS_MAX`).
    pub fn set_max_threads(&mut self, max: u32) {
        assert!(max > 0, "at least one thread");
        self.shared.lock().threads_max = max;
    }

    /// Whether the threads are waited for as the resolver goes.
    pub fn set_join(&mut self, join: bool) {
        self.join = join;
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
        self.start_threads();
        Ok(())
    }

    /// As many threads as the queue wants and the most allows; one that
    /// cannot be started leaves its query queued for the next try.
    fn start_threads(&mut self) {
        self.reap();
        loop {
            {
                let mut state = self.shared.lock();
                let wanted = state.queue.len() as u32;
                if wanted <= state.idle || state.threads >= state.threads_max {
                    return;
                }
                state.threads += 1;
            }
            let shared = self.shared.clone();
            // std's start allocates without asking: a failure to start
            // that it reports leaves the query for the next try.
            let started = std::thread::Builder::new()
                .name("curl-resolver".into())
                .spawn(move || work(&shared));
            match started {
                // Without room to keep its handle, it runs detached.
                Ok(handle) => {
                    let _detached = self.handles.try_push(handle);
                }
                Err(_) => {
                    self.shared.lock().threads -= 1;
                    return;
                }
            }
        }
    }

    /// Join the threads that have ended.
    fn reap(&mut self) {
        let mut at = 0;
        while at < self.handles.len() {
            if self.handles[at].is_finished() {
                let handle = self.handles.swap_remove(at);
                handle.join().expect("a resolver thread does not panic");
            } else {
                at += 1;
            }
        }
    }

    /// Move the answers the threads gave to their resolves; one for a
    /// resolve cancelled is dropped.
    fn collect(&mut self) {
        let done = std::mem::take(&mut self.shared.lock().done);
        for d in done {
            let Some(r) = self.resolving.iter_mut().find(|r| r.id == d.id) else {
                continue;
            };
            match d.family {
                Family::V6 => r.v6 = Some(d.result),
                _ => r.v4 = Some(d.result),
            }
            r.left -= 1;
        }
    }

    /// The answer of the resolve at `at`, all its queries answered.
    fn take(&mut self, at: usize) -> Result<Vec<IpAddr>, ResolveFailure> {
        let r = self.resolving.remove(at);
        merged(r.v6, r.v4)
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
            let result = curl_os::resolve::lookup(&q.name, q.family);
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
        self.next = id.next();
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
            queries.try_push(Query {
                id,
                name: copy,
                family,
            })?;
        }
        self.resolving.try_push(Resolving {
            id,
            waiter,
            left: families.len() as u8,
            v6: None,
            v4: None,
            told: false,
        })?;
        if let Err(OutOfMemory) = self.queue(&mut queries) {
            self.resolving.pop();
            return Err(ResolveFailure::OutOfMemory);
        }
        Ok(Resolve::Pending(id))
    }

    fn answer(&mut self, id: ResolveId) -> Option<Result<Vec<IpAddr>, ResolveFailure>> {
        self.collect();
        let at = self
            .resolving
            .iter()
            .position(|r| r.id == id)
            .expect("a resolve not taken or cancelled");
        if self.resolving[at].left > 0 {
            // A query a thread could not be started for is tried again.
            self.start_threads();
            return None;
        }
        Some(self.take(at))
    }

    fn wait(&mut self, id: ResolveId) -> Result<Vec<IpAddr>, ResolveFailure> {
        loop {
            if let Some(answer) = self.answer(id) {
                return answer;
            }
            let state = self.shared.lock();
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

    fn cancel(&mut self, id: ResolveId) {
        self.resolving.retain(|r| r.id != id);
        self.shared.lock().queue.retain(|q| q.id != id);
    }

    fn answered(&mut self, each: &mut dyn FnMut(Waiter, ResolveId)) {
        // The wake is taken as the answers are.
        let _drained = self.shared.waker.drain();
        self.collect();
        for r in &mut self.resolving {
            if r.left == 0 && !r.told {
                r.told = true;
                each(r.waiter, r.id);
            }
        }
        self.start_threads();
    }

    fn waker(&self) -> Option<TryArc<Waker>> {
        Some(self.shared.waker.clone())
    }
}

impl Drop for ThreadedResolver {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            state.aborted = true;
            state.queue.clear();
        }
        self.shared.work.notify_all();
        if self.join {
            for handle in self.handles.drain(..) {
                handle.join().expect("a resolver thread does not panic");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every resolve's answer, waited for, as `answered` tells of each.
    fn answer_all(
        r: &mut ThreadedResolver,
        ids: &[ResolveId],
    ) -> Vec<Result<Vec<IpAddr>, ResolveFailure>> {
        ids.iter().map(|&id| r.wait(id)).collect()
    }

    /// A name resolves in a thread: the start gives a resolve to wait for,
    /// whose answer comes, and the multi is told which transfer's it is.
    #[test]
    fn a_name_resolves_in_a_thread() {
        let mut r = ThreadedResolver::new(Threads::MULTI).unwrap();
        let Ok(Resolve::Pending(id)) = r.start(b"localhost", Family::V4, Waiter::NONE) else {
            panic!("pending");
        };
        let answer = r.wait(id).unwrap();
        assert!(answer.contains(&IpAddr::from([127, 0, 0, 1])), "{answer:?}");
        let Ok(Resolve::Pending(id)) = r.start(b"localhost", Family::V4, Waiter::NONE) else {
            panic!("pending");
        };
        // Told once, then taken.
        let mut told = Vec::new();
        while told.is_empty() {
            r.answered(&mut |w, i| told.push((w, i)));
        }
        assert_eq!(told, [(Waiter::NONE, id)]);
        r.answered(&mut |_, _| panic!("told twice"));
        assert!(r.answer(id).unwrap().is_ok());
    }

    /// Both families are two queries, IPv6's addresses first; a name
    /// that does not exist is a negative answer.
    #[test]
    fn both_families_are_two_queries() {
        let mut r = ThreadedResolver::new(Threads::MULTI).unwrap();
        let start = |r: &mut ThreadedResolver, name: &[u8]| match r.start(
            name,
            Family::Any,
            Waiter::NONE,
        ) {
            Ok(Resolve::Pending(id)) => id,
            other => panic!("{other:?}"),
        };
        let ids = [
            start(&mut r, b"localhost"),
            start(&mut r, b"nonexist.invalid"),
        ];
        let answers = answer_all(&mut r, &ids);
        let found = answers[0].as_ref().unwrap();
        assert!(found.contains(&IpAddr::from([127, 0, 0, 1])), "{found:?}");
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

    /// A cancelled resolve's answer is dropped as it comes, and the
    /// multi is not told of it.
    #[test]
    fn a_cancelled_resolve_is_never_told() {
        let mut r = ThreadedResolver::new(Threads::EASY).unwrap();
        let Ok(Resolve::Pending(gone)) = r.start(b"localhost", Family::V4, Waiter::NONE) else {
            panic!("pending");
        };
        r.cancel(gone);
        let Ok(Resolve::Pending(kept)) = r.start(b"localhost", Family::V4, Waiter::NONE) else {
            panic!("pending");
        };
        assert!(r.wait(kept).is_ok());
        r.answered(&mut |_, id| assert_ne!(id, gone));
        assert!(r.resolving.is_empty());
    }

    /// No more threads than the most run at once, and idle ones end.
    #[test]
    fn threads_are_kept_to_the_most_and_end_when_idle() {
        let mut r = ThreadedResolver::new(Threads {
            max: 2,
            idle: Duration::from_millis(10),
        })
        .unwrap();
        let ids: Vec<ResolveId> = (0..6)
            .map(|_| match r.start(b"localhost", Family::V4, Waiter::NONE) {
                Ok(Resolve::Pending(id)) => id,
                other => panic!("{other:?}"),
            })
            .collect();
        assert!(r.shared.lock().threads <= 2);
        assert!(answer_all(&mut r, &ids).iter().all(Result::is_ok));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while r.shared.lock().threads > 0 {
            assert!(std::time::Instant::now() < deadline, "idle threads end");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
