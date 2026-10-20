//! A transfer's states and the steps between them (`multi_runsingle`).
//!
//! The variants hold what is valid in them: a connection lease exists from
//! the moment a transfer has a connection until `Done` gives it back, and
//! only `Done` gives it back.

use crate::conn::{ConnLease, Finish, Pool, Route};
use crate::easy::Easy;
use crate::error::{ErrorKind, UrlErrorKind};
use crate::proto::{ProtoState, ProtoStep};
use crate::time::Instant;
use crate::url::{GetOptions, ParseOptions, Part, Url};

use super::timers::{Deadlines, Phase, TimeLeft};

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

/// What a step needs from the multi.
pub(crate) struct StepCx<'a> {
    pub(crate) easy: &'a Easy,
    pub(crate) pool: &'a mut Pool,
    pub(crate) now: Instant,
}

/// Run one step of `run`.
pub(crate) fn step(run: &mut Run, cx: &mut StepCx<'_>) -> Wake {
    let state = std::mem::replace(&mut run.state, TransferState::Init);
    let (next, wake) = match state {
        TransferState::Init => {
            let limits = cx.easy.options().limits;
            run.deadlines = Deadlines::new(cx.now, limits.total, limits.connect);
            (setup(run, cx), Wake::Again)
        }
        TransferState::Exchanging(mut x) => match x.proto.step() {
            ProtoStep::Done => (
                TransferState::Done(Done {
                    lease: x.lease,
                    result: Ok(()),
                    premature: false,
                }),
                Wake::Again,
            ),
            // Out of time at the end of the pass (transfer.c:382).
            ProtoStep::Blocked
                if matches!(
                    run.deadlines.time_left(cx.now, Phase::Transferring),
                    TimeLeft::Expired(_)
                ) =>
            {
                (
                    TransferState::Exchanging(x).fail(ErrorKind::OperationTimedout),
                    Wake::Again,
                )
            }
            ProtoStep::Blocked => (TransferState::Exchanging(x), Wake::Idle),
        },
        TransferState::Done(d) => {
            let premature = d.premature || is_premature(d.result);
            cx.pool.release(d.lease, Finish { premature });
            let completed = TransferState::Completed(Completed {
                outcome: d.result,
                message: Message::Unread,
            });
            (completed, Wake::Again)
        }
        s @ TransferState::Completed(_) => (s, Wake::Idle),
    };
    run.state = next;
    wake
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
fn setup(run: &mut Run, cx: &mut StepCx<'_>) -> TransferState {
    let Some(url) = cx.easy.options().url() else {
        return TransferState::Init.fail(ErrorKind::UrlMalformat);
    };
    run.deadlines.start_leg(cx.now);
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
    match cx.pool.acquire(&Route::LOCAL) {
        Ok(lease) => TransferState::Exchanging(Exchanging { lease, proto }),
        Err(_) => TransferState::Init.fail(ErrorKind::OutOfMemory),
    }
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
