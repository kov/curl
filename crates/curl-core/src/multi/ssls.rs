//! A handle's TLS sessions taken in and given out by the application
//! (`curl_easy_ssls_import`, `curl_easy_ssls_export`), from the cache its
//! transfers use (`cf_ssl_scache_get`): its share's if that keeps them,
//! else, while it is in one, its multi's. A handle with neither has none:
//! an import is refused and an export gives nothing. The multi a handle's
//! `perform` keeps for itself does not count, as C's handle leaves it as
//! each perform ends.
//!
//! No transfer runs for these calls. What they trace is told to the
//! `notes` each is given, as a raw send's is.

use curl_alloc::Lock;
use std::fmt;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use super::raw::Notes;
use super::{Host, Multi, TransferId};
use crate::components::Component;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::Handler;
use crate::share::{Access, Kind, Share, ShareLock, watched};
use crate::time::SystemClock;
use crate::tls::cache::{ExportStop, Exported};
use crate::tls::{SessionCache, SessionExport, SessionFor, unpack_session};
use crate::trace::note_line;

/// Why an export ended early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFailed<E> {
    /// The library's: what `curl_easy_ssls_export` returns.
    Library(ErrorKind),
    /// The value the application's function stopped it with.
    Stopped(E),
}

/// Lines said under a share's lock, held to be said once it is let go. A
/// line it has no memory to hold is not said.
#[derive(Default)]
struct HeldLines(Vec<Vec<u8>>);

impl HeldLines {
    fn hold(&mut self, line: fmt::Arguments<'_>) {
        use fmt::Write as _;
        struct Into<'a>(&'a mut Vec<u8>);
        impl fmt::Write for Into<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.0
                    .try_extend_from_slice(s.as_bytes())
                    .map_err(|_| fmt::Error)
            }
        }
        let mut held = Vec::new();
        if Into(&mut held).write_fmt(line).is_ok() {
            let _not_said = self.0.try_push(held);
        }
    }

    fn say(&self, easy: &Easy, notes: Notes<'_>) {
        for line in &self.0 {
            note_line(easy, Some(Component::Ssls), &mut *notes, |l| {
                l.push_clipped(line);
            });
        }
    }
}

/// The handle's sessions are its share's.
fn kept_share(easy: &Easy) -> Option<&Share> {
    easy.shared(Kind::SslSessions)
}

fn import(
    easy: &Easy,
    own: Option<&mut SessionCache>,
    now: i64,
    who: SessionFor<'_>,
    packed: &[u8],
    notes: Notes<'_>,
) -> Result<(), ErrorKind> {
    let share = kept_share(easy);
    let no_cache = share.is_none() && own.is_none();
    let no_peer = matches!(who, SessionFor::SaltedHmac([]));
    if no_cache || packed.is_empty() || no_peer {
        return Err(ErrorKind::BadFunctionArgument);
    }
    let ticket = match unpack_session(packed) {
        Ok(ticket) => ticket,
        Err(kind) => {
            let n = kind.number();
            note_line(easy, Some(Component::Ssls), notes, |l| {
                l.push_fmt(format_args!("error unpacking data: {n}"));
            });
            return Err(kind);
        }
    };
    let mut lines = HeldLines::default();
    let mut trace = |line: fmt::Arguments<'_>| lines.hold(line);
    let done = match (share, own) {
        (Some(share), _) => watched(
            easy.share_watch.as_deref(),
            share,
            Kind::SslSessions,
            || {
                // Gone since it was chosen, it is no cache.
                match share.sessions().as_mut() {
                    Some(cache) => cache.import(who, ticket, now, &mut trace),
                    None => Err(ErrorKind::BadFunctionArgument),
                }
            },
        ),
        (None, Some(own)) => own.import(who, ticket, now, &mut trace),
        (None, None) => unreachable!("refused above"),
    };
    lines.say(easy, notes);
    done
}

/// Whether the sessions of one cache, a share's or a multi's, are going
/// out to the application's function, and on which thread (C's
/// `is_locked` with its `locking_thread`). Its cache's owner holds it; so
/// do an export under way, which marks it, and whoever must refuse what
/// would want the cache meanwhile, as the shim's gate does: each a key to
/// the one fact, none a copy of it.
#[derive(Clone)]
pub struct SessionsOut(TryArc<Lock<Option<ThreadMark>>>);

/// A thread, told apart from every other one alive: the address of a byte
/// of its own. Unlike `thread::current()`, it takes nothing to make: on a
/// thread Rust did not start, as an application's are, that allocates a
/// handle kept to the thread's end, which C's leak checks report.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ThreadMark(usize);

impl ThreadMark {
    fn here() -> ThreadMark {
        thread_local! {
            // Const and with nothing to drop, so the thread's own storage
            // holds it, made and let go of with the thread.
            static BYTE: u8 = const { 0 };
        }
        ThreadMark(BYTE.with(|b| std::ptr::from_ref(b).addr()))
    }
}

impl SessionsOut {
    /// Not going out.
    pub fn new() -> Result<SessionsOut, OutOfMemory> {
        Ok(SessionsOut(TryArc::try_new(Lock::new(None))?))
    }

    /// Whether they are going out on this thread
    /// (`Curl_ssl_scache_is_locked_by_current_thread`).
    pub fn here(&self) -> bool {
        *self.locked() == Some(ThreadMark::here())
    }

    /// They go out from this thread, or no longer go out.
    fn set(&self, going: bool) {
        *self.locked() = going.then(ThreadMark::here);
    }

    fn locked(&self) -> curl_alloc::LockGuard<'_, Option<ThreadMark>> {
        // Nothing panics holding it: a panic aborts the process.
        self.0.lock().expect("no panic holds its lock")
    }
}

impl fmt::Debug for SessionsOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionsOut")
    }
}

/// An export begun: the sessions made ready and the application's lock
/// function told, to go out with no lock of the library's held and nothing
/// of the multi's borrowed. C holds its cache's lock across the
/// application's function and its gate refuses the calls that would want
/// it from the same thread: the shim's gate asks the cache's `SessionsOut`
/// and refuses them too. A call on another thread waits on C's lock and
/// finds the cache free here, the sessions going out those made ready.
pub struct Exporting {
    exported: Exported,
    /// The mark of the cache the sessions are of, a share's or a multi's,
    /// set while this lasts; none with no cache.
    out: Option<SessionsOut>,
    /// The application's lock function, told until this ends.
    told: Option<Handler<dyn ShareLock>>,
}

/// An export ended, what it has yet to say.
pub struct ExportDone<E> {
    result: Result<(), ExportFailed<E>>,
    line: Option<ExportLine>,
}

enum ExportLine {
    Packing(ErrorKind),
    Exported { tickets: usize, peers: usize },
}

impl<E> ExportDone<E> {
    /// Say what it has to say on `easy`'s trace, and how it ended.
    pub fn end(self, easy: &Easy, notes: Notes<'_>) -> Result<(), ExportFailed<E>> {
        if let Some(line) = &self.line {
            note_line(easy, Some(Component::Ssls), notes, |l| match line {
                ExportLine::Packing(kind) => {
                    let n = kind.number();
                    l.push_fmt(format_args!("error packing data: {n}"));
                }
                ExportLine::Exported { tickets, peers } => {
                    l.push_fmt(format_args!(
                        "exported {tickets} session tickets for {peers} peers"
                    ));
                }
            });
        }
        self.result
    }
}

impl Exporting {
    fn begin(
        easy: &Easy,
        own: Option<(&mut SessionCache, &SessionsOut)>,
        now: i64,
    ) -> Result<Exporting, OutOfMemory> {
        let mut salt = |bytes: &mut [u8]| {
            easy.libraries()
                .random(bytes)
                .map_err(|_| ErrorKind::FailedInit)
        };
        if let Some(share) = kept_share(easy) {
            let out = share.sessions_out_made()?.clone();
            let told = easy.share_watch.clone();
            if let Some(w) = &told {
                w.lock(Kind::SslSessions, Access::Single);
            }
            // Gone since it was chosen, it has nothing to give.
            let exported = share
                .sessions()
                .as_mut()
                .map_or_else(Exported::default, |c| c.export(now, &mut salt));
            out.set(true);
            return Ok(Exporting {
                exported,
                out: Some(out),
                told,
            });
        }
        let Some((cache, out)) = own else {
            return Ok(Exporting {
                exported: Exported::default(),
                out: None,
                told: None,
            });
        };
        let exported = cache.export(now, &mut salt);
        out.set(true);
        Ok(Exporting {
            exported,
            out: Some(out.clone()),
            told: None,
        })
    }

    /// Give each session to `f` in turn, until it stops or the one that
    /// would not pack is reached.
    pub fn deliver<E>(
        self,
        f: &mut dyn FnMut(SessionExport<'_>) -> Result<(), E>,
    ) -> ExportDone<E> {
        for ticket in &self.exported.tickets {
            if let Err(e) = f(ticket.view()) {
                return ExportDone {
                    result: Err(ExportFailed::Stopped(e)),
                    line: None,
                };
            }
        }
        match self.exported.failed {
            Some(ExportStop::Packing(kind)) => ExportDone {
                result: Err(ExportFailed::Library(kind)),
                line: Some(ExportLine::Packing(kind)),
            },
            Some(ExportStop::Other(kind)) => ExportDone {
                result: Err(ExportFailed::Library(kind)),
                line: None,
            },
            None => ExportDone {
                result: Ok(()),
                line: Some(ExportLine::Exported {
                    tickets: self.exported.tickets.len(),
                    peers: self.exported.peers,
                }),
            },
        }
    }
}

impl Drop for Exporting {
    fn drop(&mut self) {
        if let Some(out) = &self.out {
            out.set(false);
        }
        if let Some(w) = &self.told {
            w.unlock(Kind::SslSessions);
        }
    }
}

impl Easy {
    /// Whether the sessions of the cache it uses out of a multi, its
    /// share's, are going out on this thread
    /// (`Curl_ssl_scache_is_locked_by_current_thread`).
    pub fn ssls_going_out(&self) -> bool {
        kept_share(self)
            .and_then(Share::sessions_out)
            .is_some_and(SessionsOut::here)
    }

    /// Keep the session `packed` for `who`, in the cache the handle's
    /// share keeps (`curl_easy_ssls_import`, for a handle in no multi). A
    /// handle whose share keeps none is refused. `packed` is anything at
    /// all: what does not parse is refused.
    pub fn ssls_import(
        &self,
        who: SessionFor<'_>,
        packed: &[u8],
        notes: Notes<'_>,
    ) -> Result<(), ErrorKind> {
        let now = SystemClock::new().unix_time();
        import(self, None, now, who, packed, notes)
    }

    /// Begin giving out the sessions of the cache the handle's share keeps
    /// (`curl_easy_ssls_export`, for a handle in no multi). It fails for
    /// want of memory for the share's mark, made by its first export.
    pub fn ssls_export(&self) -> Result<Exporting, OutOfMemory> {
        Exporting::begin(self, None, SystemClock::new().unix_time())
    }
}

impl<H: Host> Multi<H> {
    /// Whether the sessions of the cache the transfer `id` uses, its
    /// share's or else the multi's, are going out on this thread. `None` if
    /// `id` is not in this multi.
    pub fn easy_ssls_going_out(&self, id: TransferId) -> Option<bool> {
        let easy = &self.slots.app(id)?.easy;
        Some(match kept_share(easy) {
            Some(share) => share.sessions_out().is_some_and(SessionsOut::here),
            None => self
                .caches
                .sessions_out
                .as_ref()
                .is_some_and(SessionsOut::here),
        })
    }

    /// Whether the sessions of the multi's own cache are going out: the
    /// mark itself, to be asked where the multi cannot be reached. None
    /// before the first export from its cache, which makes it.
    pub fn sessions_out(&self) -> Option<&SessionsOut> {
        self.caches.sessions_out.as_ref()
    }

    /// As `Easy::ssls_import`, for the transfer `id` of the multi, which
    /// uses the multi's cache if its share keeps none. `None` if `id` is
    /// not in this multi.
    pub fn ssls_import(
        &mut self,
        id: TransferId,
        who: SessionFor<'_>,
        packed: &[u8],
        notes: Notes<'_>,
    ) -> Option<Result<(), ErrorKind>> {
        let now = self.clock.unix_time();
        let easy = &self.slots.app(id)?.easy;
        let own = &mut self.caches.sessions;
        Some(import(easy, Some(own), now, who, packed, notes))
    }

    /// As `Easy::ssls_export`, for the transfer `id` of the multi. `None`
    /// if `id` is not in this multi; it fails for want of memory to mark
    /// the multi's cache as going out, made by its first export.
    pub fn ssls_export(&mut self, id: TransferId) -> Option<Result<Exporting, OutOfMemory>> {
        let now = self.clock.unix_time();
        let easy = &self.slots.app(id)?.easy;
        if kept_share(easy).is_none() && self.caches.sessions_out.is_none() {
            match SessionsOut::new() {
                Ok(out) => self.caches.sessions_out = Some(out),
                Err(e) => return Some(Err(e)),
            }
        }
        let own = match &self.caches.sessions_out {
            Some(out) => Some((&mut self.caches.sessions, out)),
            None => None,
        };
        Some(Exporting::begin(easy, own, now))
    }

    /// `ExportDone::end` for the transfer `id` of the multi. `None` if `id`
    /// is not in this multi.
    pub fn ssls_export_end<E>(
        &self,
        id: TransferId,
        done: ExportDone<E>,
        notes: Notes<'_>,
    ) -> Option<Result<(), ExportFailed<E>>> {
        Some(done.end(&self.slots.app(id)?.easy, notes))
    }
}

#[cfg(test)]
mod tests;
