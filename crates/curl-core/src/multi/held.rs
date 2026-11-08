//! A transfer's handle as the multi holds it: read freely, changed only
//! through a call that counts the change in the multi's `Edits`, so that
//! what a step keeps of the handle's options (`StepCx::verbose`) is
//! known good while the count stays. No other way to the handle's
//! options as `&mut` is left: a change that would bypass the count does
//! not compile.

use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::easy::Easy;
use crate::report::TransferReport;

/// The count of changes to a multi's handles, kept by its transfer
/// table. Never 0, which a step's cache starts at.
pub(super) struct Edits(AtomicU64);

impl Edits {
    pub(super) fn new() -> Edits {
        Edits(AtomicU64::new(1))
    }

    #[inline]
    pub(super) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// A handle in its slot.
pub(super) struct Held {
    easy: Box<Easy>,
}

impl Held {
    /// `easy`, held: a handle put in place changes what its slot holds.
    pub(super) fn new(easy: Box<Easy>, edits: &Edits) -> Held {
        edits.bump();
        Held { easy }
    }

    /// The handle, given back as its transfer leaves.
    pub(super) fn into_inner(self) -> Box<Easy> {
        self.easy
    }

    /// The handle, to change: counted in its table's `edits`.
    pub(super) fn easy_mut(&mut self, edits: &Edits) -> &mut Easy {
        edits.bump();
        &mut self.easy
    }

    /// What the transfer reports, changed as it runs: no option is
    /// among it, so it is not counted.
    #[inline]
    pub(crate) fn report_mut(&mut self) -> &mut TransferReport {
        self.easy.report_mut()
    }
}

impl Deref for Held {
    type Target = Easy;

    fn deref(&self) -> &Easy {
        &self.easy
    }
}
