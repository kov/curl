//! A transfer's states and the steps between them (`multi_runsingle`).
//!
//! The variants hold what is valid in them: a connection lease exists from
//! the moment a transfer has a connection until `Done` gives it back, and
//! only `Done` gives it back.

use crate::conn::{ConnLease, Finish, Pool, Route};
use crate::deliver::{Pause, PauseRequest, Pipeline, RecvPause};
use crate::easy::Easy;
use crate::error::{ErrorKind, UrlErrorKind};
use crate::progress::{self, Speedometer};
use crate::proto::{ProtoState, ProtoStep};
use crate::report::{Timer, TransferReport};
use crate::time::Instant;
use crate::url::{GetOptions, ParseOptions, Part, Url};

use super::cx::{EngineRest, TransferCalls};
use super::timers::{Deadlines, Phase, TimeLeft, TimerKind};
use super::{Host, TransferId};

/// A transfer from `add` to `remove`.
#[derive(Debug)]
pub(crate) struct Run {
    pub(crate) state: TransferState,
    pub(crate) deadlines: Deadlines,
}

impl Run {
    pub(crate) fn new(now: Instant) -> Run {
        Run {
            state: TransferState::Init,
            deadlines: Deadlines::new(now, None, None),
        }
    }
}

#[derive(Debug)]
pub(crate) enum TransferState {
    /// Added, not yet run.
    Init,
    /// Holding a connection, the protocol at work.
    Exchanging(Exchanging),
    /// The request is over; the connection goes back at the next step.
    Done(Done),
    /// Over; its message is read or not. Terminal until removed.
    Completed(Completed),
}

#[derive(Debug)]
pub(crate) struct Exchanging {
    lease: ConnLease,
    proto: ProtoState,
}

#[derive(Debug)]
pub(crate) struct Done {
    lease: ConnLease,
    result: Result<(), ErrorKind>,
    /// Ended before the request was complete.
    premature: bool,
}

#[derive(Debug)]
pub(crate) struct Completed {
    pub(crate) outcome: Result<(), ErrorKind>,
    pub(crate) message: Message,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Message {
    Unread,
    Read,
}

/// Whether to step a transfer again in the same pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wake {
    Again,
    Idle,
}

impl TransferState {
    /// Whether the transfer holds a connection lease.
    pub(crate) fn holds_lease(&self) -> bool {
        matches!(self, TransferState::Exchanging(_) | TransferState::Done(_))
    }

    /// The output of the request under way, if its protocol delivers any.
    pub(crate) fn pipeline_mut(&mut self) -> Option<&mut Pipeline> {
        match self {
            TransferState::Exchanging(x) => x.proto.pipeline_mut(),
            _ => None,
        }
    }

    /// Whether the request under way holds output for the application.
    #[cfg(debug_assertions)]
    pub(crate) fn holds_output(&self) -> bool {
        match self {
            TransferState::Exchanging(x) => x.proto.holds_output(),
            _ => false,
        }
    }

    pub(crate) fn is_completed(&self) -> bool {
        matches!(self, TransferState::Completed(_))
    }

    /// End the transfer with `err`: through `Done` if it holds a
    /// connection, straight to `Completed` if not. A transfer already
    /// finishing keeps its result, as `multi_done` runs once.
    pub(crate) fn fail(self, err: ErrorKind) -> TransferState {
        match self {
            TransferState::Init => TransferState::Completed(Completed {
                outcome: Err(err),
                message: Message::Unread,
            }),
            TransferState::Exchanging(x) => TransferState::Done(Done {
                lease: x.lease,
                result: Err(err),
                premature: true,
            }),
            s @ (TransferState::Done(_) | TransferState::Completed(_)) => s,
        }
    }

    /// Take the transfer out of the multi before it completed: give back
    /// its connection, as a premature end (`curl_multi_remove_handle`).
    pub(crate) fn abandon(self, pool: &mut Pool) {
        let lease = match self {
            TransferState::Init | TransferState::Completed(_) => return,
            TransferState::Exchanging(x) => x.lease,
            TransferState::Done(d) => d.lease,
        };
        pool.release(lease, Finish { premature: true });
    }
}

/// What a step needs: the transfer it steps, whose `Run` is out of its
/// slot, and the rest of the multi.
pub(crate) struct StepCx<'a, H: Host> {
    pub(crate) me: TransferId,
    pub(super) rest: EngineRest<'a, H>,
}

impl<H: Host> StepCx<'_, H> {
    pub(crate) fn easy(&self) -> &Easy {
        &self
            .rest
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .easy
    }
}

impl<H: Host> StepCx<'_, H> {
    pub(crate) fn report_mut(&mut self) -> &mut TransferReport {
        self.rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .easy
            .report_mut()
    }

    pub(crate) fn pause(&self) -> Pause {
        self.rest
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .pause
    }

    pub(crate) fn pause_mut(&mut self) -> &mut Pause {
        &mut self
            .rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .pause
    }

    pub(crate) fn now(&self) -> Instant {
        self.rest.now
    }

    pub(crate) fn easy_mut(&mut self) -> &mut Easy {
        &mut self
            .rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .easy
    }

    pub(crate) fn speedometer_mut(&mut self) -> &mut Speedometer {
        &mut self
            .rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .speedometer
    }

    /// The speedometer and the report it writes to.
    pub(crate) fn progress_parts(&mut self) -> (&mut Speedometer, &mut TransferReport) {
        let slot = self
            .rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer");
        (&mut slot.speedometer, slot.easy.report_mut())
    }

    pub(crate) fn mark(&mut self, timer: Timer) {
        let now = self.rest.now;
        self.report_mut().timings_mut().mark(timer, now);
    }
}

impl<H: Host> TransferCalls for StepCx<'_, H> {
    fn me(&self) -> TransferId {
        self.me
    }

    fn easy(&self, id: TransferId) -> Option<&Easy> {
        self.rest.slots.get(id).map(|s| &s.easy)
    }

    fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy> {
        self.rest.slots.get_mut(id).map(|s| &mut s.easy)
    }

    fn pause(&mut self, id: TransferId, req: PauseRequest) -> Result<(), ErrorKind> {
        super::pause_transfer(&mut self.rest, id, req)
    }
}

/// Replay a transfer's held output, from outside its step.
pub(crate) fn flush<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    match run.state.pipeline_mut() {
        Some(p) => p.flush(cx),
        None => Ok(()),
    }
}

/// Run one step of `run`.
pub(crate) fn step<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Wake {
    let state = std::mem::replace(&mut run.state, TransferState::Init);
    let (next, wake) = match state {
        TransferState::Init => {
            let limits = cx.easy().options().limits;
            run.deadlines = Deadlines::new(cx.rest.now, limits.total, limits.connect);
            let now = cx.rest.now;
            cx.report_mut().restart(now);
            *cx.speedometer_mut() = Speedometer::default();
            let next = setup(run, cx);
            if next.is_completed() {
                enter_completed(cx.report_mut(), now, true);
            }
            (next, Wake::Again)
        }
        TransferState::Exchanging(mut x) => {
            let stepped = x.proto.step(cx);
            let expired = matches!(
                run.deadlines.time_left(cx.rest.now, Phase::Transferring),
                TimeLeft::Expired(_)
            );
            match stepped {
                Err(e) => (TransferState::Exchanging(x).fail(e), Wake::Again),
                // Out of time at the end of the pass (transfer.c:382).
                Ok(ProtoStep::Blocked) if expired => (
                    TransferState::Exchanging(x).fail(ErrorKind::OperationTimedout),
                    Wake::Again,
                ),
                Ok(stepped) => {
                    // The end of a receive pass (`Curl_sendrecv`).
                    let done = stepped == ProtoStep::Done;
                    match progress::check(cx, done) {
                        Err(e) => (TransferState::Exchanging(x).fail(e), Wake::Again),
                        Ok(look_again) => {
                            if let Some(wait) = look_again {
                                run.deadlines.arm_in(TimerKind::SpeedCheck, cx.now(), wait);
                            }
                            if done {
                                let done = Done {
                                    lease: x.lease,
                                    result: Ok(()),
                                    premature: false,
                                };
                                (TransferState::Done(done), Wake::Again)
                            } else {
                                (TransferState::Exchanging(x), Wake::Idle)
                            }
                        }
                    }
                }
            }
        }
        TransferState::Done(mut d) => {
            // A last progress pass, unless a callback aborted already
            // (`multi_done`).
            if d.result != Err(ErrorKind::AbortedByCallback)
                && let Err(e) = progress::finish(cx, !d.premature)
                && d.result.is_ok()
            {
                d.result = Err(e);
            }
            let premature = d.premature || is_premature(d.result);
            cx.rest.pool.release(d.lease, Finish { premature });
            // Held output went with the request; a pause the application
            // asked for stays.
            let pause = cx.pause_mut();
            if pause.recv == RecvPause::Held {
                pause.recv = RecvPause::Running;
            }
            let completed = TransferState::Completed(Completed {
                outcome: d.result,
                message: Message::Unread,
            });
            let now = cx.rest.now;
            enter_completed(cx.report_mut(), now, false);
            (completed, Wake::Again)
        }
        s @ TransferState::Completed(_) => (s, Wake::Idle),
    };
    let (next, wake) = progress_after_step(next, wake, cx);
    run.state = next;
    wake
}

/// A step that went well, with a connection, ends with a progress pass
/// (the tail of `multi_runsingle`'s loop, after `is_finished`). The
/// handler may have unpaused held output: it is replayed at once.
fn progress_after_step<H: Host>(
    next: TransferState,
    wake: Wake,
    cx: &mut StepCx<'_, H>,
) -> (TransferState, Wake) {
    match next {
        TransferState::Exchanging(mut x) => {
            let passed = progress::update(cx, false).and_then(|()| match x.proto.pipeline_mut() {
                Some(p) => p.flush(cx),
                None => Ok(()),
            });
            match passed {
                Ok(()) => (TransferState::Exchanging(x), wake),
                Err(e) => (TransferState::Exchanging(x).fail(e), Wake::Again),
            }
        }
        TransferState::Done(d) if d.result.is_ok() => match progress::update(cx, true) {
            Ok(()) => (TransferState::Done(d), wake),
            // An abort ends the request early, closing its connection.
            Err(e) => (
                TransferState::Done(Done {
                    result: Err(e),
                    ..d
                }),
                Wake::Again,
            ),
        },
        s => (s, wake),
    }
}

/// The report of a transfer completing, from before the request was
/// about to be sent or not (`mstate_enter_completed`, `Curl_pgrsCompleted`).
fn enter_completed(report: &mut TransferReport, now: Instant, before_did: bool) {
    let t = report.timings_mut();
    if before_did {
        // The times a jump to the end skipped.
        t.mark(Timer::PreTransfer, now);
        t.mark(Timer::PostTransfer, now);
        t.mark(Timer::StartTransfer, now);
    }
    t.completed(now);
}

/// A transfer that never ran, ended by its multi: its report starts and
/// completes at once.
pub(crate) fn complete_unstarted(easy: &mut Easy, now: Instant) {
    let report = easy.report_mut();
    report.restart(now);
    enter_completed(report, now, true);
}

/// `multi_done` treats these failures as premature whatever the caller
/// said.
fn is_premature(result: Result<(), ErrorKind>) -> bool {
    matches!(
        result,
        Err(ErrorKind::AbortedByCallback | ErrorKind::ReadError | ErrorKind::WriteError)
    )
}

/// C's pretransfer, SETUP and CONNECT, which always run in one pass: the
/// URL, the leg's timers, the protocol and a connection.
fn setup<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> TransferState {
    if cx.easy().options().url().is_none() {
        return TransferState::Init.fail(ErrorKind::UrlMalformat);
    }
    cx.mark(Timer::StartOp);
    run.deadlines.start_leg(cx.rest.now);
    cx.mark(Timer::StartSingle);
    cx.mark(Timer::PostQueue);
    let url = cx.easy().options().url().expect("checked above");
    let parse = ParseOptions {
        guess_scheme: true,
        non_support_scheme: true,
        ..ParseOptions::NONE
    };
    let scheme = Url::parse(url, parse).and_then(|u| u.get(Part::Scheme, GetOptions::NONE));
    let scheme = match scheme {
        Ok(s) => s,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    let Some(proto) = ProtoState::for_scheme(&scheme) else {
        return TransferState::Init.fail(ErrorKind::UnsupportedProtocol);
    };
    let Ok(lease) = cx.rest.pool.acquire(&Route::LOCAL) else {
        return TransferState::Init.fail(ErrorKind::OutOfMemory);
    };
    // A connection without a network has its name at once.
    cx.mark(Timer::NameLookup);
    // DID: about to send, and nothing to send (`mstate_enter_did`).
    cx.mark(Timer::PreTransfer);
    cx.mark(Timer::PostTransfer);
    TransferState::Exchanging(Exchanging { lease, proto })
}

/// A URL's error as a transfer's (`Curl_uc_to_curlcode`).
fn url_error(e: UrlErrorKind) -> ErrorKind {
    match e {
        UrlErrorKind::UnsupportedScheme => ErrorKind::UnsupportedProtocol,
        UrlErrorKind::OutOfMemory => ErrorKind::OutOfMemory,
        UrlErrorKind::UserNotAllowed => ErrorKind::LoginDenied,
        _ => ErrorKind::UrlMalformat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Curl_uc_to_curlcode`.
    #[test]
    fn url_errors_map_as_c_maps_them() {
        assert_eq!(
            url_error(UrlErrorKind::UnsupportedScheme),
            ErrorKind::UnsupportedProtocol
        );
        assert_eq!(url_error(UrlErrorKind::OutOfMemory), ErrorKind::OutOfMemory);
        assert_eq!(
            url_error(UrlErrorKind::UserNotAllowed),
            ErrorKind::LoginDenied
        );
        assert_eq!(
            url_error(UrlErrorKind::BadHostname),
            ErrorKind::UrlMalformat
        );
    }
}
