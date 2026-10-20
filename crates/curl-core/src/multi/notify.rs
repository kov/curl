//! Notifications: what the multi tells the application about its transfers
//! at the end of a pass (`lib/multi_ntfy.c`).

use curl_alloc::{OutOfMemory, TryVec};

use super::TransferId;

/// A kind of notification the application can ask for
/// (`CURLMNOTIFY_*`). All are off until enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyKind {
    /// Messages wait to be read.
    InfoRead,
    /// A transfer is done, before its message is posted.
    EasyDone,
}

impl NotifyKind {
    fn bit(self) -> u8 {
        match self {
            NotifyKind::InfoRead => 1,
            NotifyKind::EasyDone => 2,
        }
    }
}

/// One notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    /// The first message of a batch was posted: none was unread before it
    /// (`CURLMNOTIFY_INFO_READ`).
    InfoRead,
    /// The transfer is done (`CURLMNOTIFY_EASY_DONE`).
    EasyDone(TransferId),
}

impl Notification {
    pub fn kind(self) -> NotifyKind {
        match self {
            Notification::InfoRead => NotifyKind::InfoRead,
            Notification::EasyDone(_) => NotifyKind::EasyDone,
        }
    }
}

/// The notifications of a pass, in the order they happened.
///
/// Room is reserved when a transfer is added: a pass queues at most one
/// `EasyDone` per transfer and one `InfoRead`, and the queue is empty
/// between passes, so queueing never allocates.
#[derive(Debug, Default)]
pub(crate) struct NotifyQueue {
    entries: Vec<Notification>,
    enabled: u8,
}

impl NotifyQueue {
    /// Make room for the notifications of transfers in `rows` rows.
    pub(crate) fn reserve(&mut self, rows: u32) -> Result<(), OutOfMemory> {
        let room = (rows as usize).saturating_mul(2);
        if self.entries.capacity() < room {
            self.entries.try_reserve_exact(room - self.entries.len())?;
        }
        Ok(())
    }

    pub(crate) fn set(&mut self, kind: NotifyKind, on: bool) {
        if on {
            self.enabled |= kind.bit();
        } else {
            self.enabled &= !kind.bit();
        }
    }

    pub(crate) fn is_enabled(&self, kind: NotifyKind) -> bool {
        self.enabled & kind.bit() != 0
    }

    /// Queue `n` if its kind is enabled (`Curl_mntfy_add`).
    pub(crate) fn push(&mut self, n: Notification) {
        if self.is_enabled(n.kind()) {
            assert!(
                self.entries.len() < self.entries.capacity(),
                "notification room is reserved at add"
            );
            self.entries
                .try_push(n)
                .expect("within the reserved capacity");
        }
    }

    pub(crate) fn get(&self, i: usize) -> Option<Notification> {
        self.entries.get(i).copied()
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}
