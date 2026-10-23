//! Where a transfer is in C's state machine (`CURLMstate`), for the multi
//! component's trace: each of its lines names the state, and each change
//! of state is traced as C's `multistate` traces it. The engine's own
//! states fold several of C's into one, or leave one out; this follows
//! C's.

use crate::components::Component;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::report::{Marked, Timer};
use crate::trace;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum MState {
    #[default]
    Init,
    Pending,
    Setup,
    Connect,
    Connecting,
    ProtoConnect,
    Do,
    Did,
    Performing,
    RateLimiting,
    Done,
    Completed,
    MsgSent,
}

impl MState {
    /// Its name (`CURL_MSTATE_NAME`).
    pub(crate) fn name(self) -> &'static str {
        match self {
            MState::Init => "INIT",
            MState::Pending => "PENDING",
            MState::Setup => "SETUP",
            MState::Connect => "CONNECT",
            MState::Connecting => "CONNECTING",
            MState::ProtoConnect => "PROTOCONNECT",
            MState::Do => "DO",
            MState::Did => "DID",
            MState::Performing => "PERFORMING",
            MState::RateLimiting => "RATELIMITING",
            MState::Done => "DONE",
            MState::Completed => "COMPLETED",
            MState::MsgSent => "MSGSENT",
        }
    }
}

/// A line of the multi component's (`CURL_TRC_M`), after the state the
/// transfer is in.
pub(crate) fn trace<H: Host>(cx: &mut StepCx<'_, H>, args: std::fmt::Arguments<'_>) {
    if trace::traces(cx, Component::Multi) {
        let state = cx.mstate().name();
        trace::of(cx, Component::Multi, format_args!("[{state}] {args}"));
    }
}

/// The transfer goes to `next` (`multistate`): traced in the state it
/// leaves. Nothing is traced for a state it is in already.
pub(crate) fn enter<H: Host>(cx: &mut StepCx<'_, H>, next: MState) {
    if cx.mstate() == next {
        return;
    }
    trace(cx, format_args!("-> [{}]", next.name()));
    cx.set_mstate(next);
}

/// What taking a time did (`Curl_pgrsTimeWas`).
pub(crate) fn marked<H: Host>(cx: &mut StepCx<'_, H>, timer: Timer, marked: Marked) {
    let name = timer.name();
    match marked {
        Marked::Set => trace(cx, format_args!("[{name}] set")),
        Marked::Added(us) => trace(cx, format_args!("[{name}] added {us}us")),
        Marked::Ignored => trace(cx, format_args!("[{name}] ignored")),
    }
}
