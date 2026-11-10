//! Where a transfer's run sits between its steps.

use super::state::Run;
use crate::proto::http::Request;

/// A transfer's run in its slot. It reads as out, `None`, while a step
/// has it, and while its HTTP request is lent to the step of another
/// transfer on its connection (`StepCx::lend_sibling`), which takes the
/// request's box alone and leaves the rest where it is: either way the
/// transfer is in the middle of a step, and nothing else reads, steps or
/// takes it. A sibling is lent once for each packet read for it, so its
/// run is not moved for that.
pub(super) struct Seat(Option<Run>);

impl Seat {
    pub(super) fn new(run: Run) -> Seat {
        Seat(Some(run))
    }

    /// The run, if it is in and whole.
    pub(super) fn as_ref(&self) -> Option<&Run> {
        self.0.as_ref().filter(|run| !run.state.lent())
    }

    /// The run, if it is in and whole.
    pub(super) fn as_mut(&mut self) -> Option<&mut Run> {
        self.0.as_mut().filter(|run| !run.state.lent())
    }

    /// The run, out for a step, if it is in and whole.
    pub(super) fn take(&mut self) -> Option<Run> {
        self.as_ref()?;
        self.0.take()
    }

    /// The run a step took, back.
    pub(super) fn put(&mut self, run: Run) {
        assert!(self.0.is_none(), "a run put back was out");
        self.0 = Some(run);
    }

    /// The HTTP request of the run, which is in and whole, out for a
    /// sibling's step; none, and the run untouched, if it makes no HTTP
    /// request over a connection.
    pub(super) fn lend_http(&mut self) -> Option<Box<Request>> {
        self.as_mut()
            .expect("a sibling's run is in its slot")
            .state
            .lend_http()
    }

    /// The request `lend_http` gave, back in its run, which is whole
    /// again.
    pub(super) fn give_back_http(&mut self, request: Box<Request>) {
        self.0
            .as_mut()
            .expect("a run stays in while its request is lent")
            .state
            .give_back_http(request);
    }
}
