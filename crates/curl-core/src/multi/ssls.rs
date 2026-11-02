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

use std::fmt;

use curl_alloc::TryVec as _;

use super::raw::Notes;
use super::{Host, Multi, TransferId};
use crate::components::Component;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::Handler;
use crate::share::{Access, Kind, Share, ShareLock, watched};
use crate::time::{Clock as _, SystemClock};
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
    easy.share().filter(|s| s.keeps(Kind::SslSessions))
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
                let mut sessions = share.sessions();
                let cache = sessions.as_mut().expect("kept while the share keeps them");
                cache.import(who, ticket, now, &mut trace)
            },
        ),
        (None, Some(own)) => own.import(who, ticket, now, &mut trace),
        (None, None) => unreachable!("refused above"),
    };
    lines.say(easy, notes);
    done
}

/// An export begun: the sessions made ready and the application's lock
/// function told, to go out with no lock of the library's held and nothing
/// of the multi's borrowed, so that the application's function may use
/// what it likes. C holds its own lock across that function; the sessions
/// a later call changes are not these.
pub struct Exporting {
    exported: Exported,
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
    fn begin(easy: &Easy, own: Option<&mut SessionCache>, now: i64) -> Exporting {
        let mut salt = |bytes: &mut [u8]| {
            easy.libraries()
                .random(bytes)
                .map_err(|_| ErrorKind::FailedInit)
        };
        if let Some(share) = kept_share(easy) {
            let told = easy.share_watch.clone();
            if let Some(w) = &told {
                w.lock(Kind::SslSessions, Access::Single);
            }
            let mut sessions = share.sessions();
            let cache = sessions.as_mut().expect("kept while the share keeps them");
            let exported = cache.export(now, &mut salt);
            return Exporting { exported, told };
        }
        let exported = own.map_or_else(Exported::default, |c| c.export(now, &mut salt));
        Exporting {
            exported,
            told: None,
        }
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
        if let Some(w) = &self.told {
            w.unlock(Kind::SslSessions);
        }
    }
}

impl Easy {
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
    /// (`curl_easy_ssls_export`, for a handle in no multi).
    pub fn ssls_export(&self) -> Exporting {
        Exporting::begin(self, None, SystemClock::new().unix_time())
    }
}

impl<H: Host> Multi<H> {
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
        let easy = &self.slots.get(id)?.easy;
        let own = &mut self.caches.sessions;
        Some(import(easy, Some(own), now, who, packed, notes))
    }

    /// As `Easy::ssls_export`, for the transfer `id` of the multi. `None`
    /// if `id` is not in this multi.
    pub fn ssls_export(&mut self, id: TransferId) -> Option<Exporting> {
        let now = self.clock.unix_time();
        let easy = &self.slots.get(id)?.easy;
        let own = &mut self.caches.sessions;
        Some(Exporting::begin(easy, Some(own), now))
    }

    /// `ExportDone::end` for the transfer `id` of the multi. `None` if `id`
    /// is not in this multi.
    pub fn ssls_export_end<E>(
        &self,
        id: TransferId,
        done: ExportDone<E>,
        notes: Notes<'_>,
    ) -> Option<Result<(), ExportFailed<E>>> {
        Some(done.end(&self.slots.get(id)?.easy, notes))
    }
}

#[cfg(test)]
mod tests;
