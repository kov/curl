//! What the socket callback was told (`lib/multi_ev.c`): for each socket
//! a transfer waits on, the transfers waiting on it and for what, what the
//! application last heard, and the value it assigned to the socket.
//!
//! Each socket's entry is the one record of who waits on it: a transfer
//! keeps no copy, and finds its sockets by asking the table.

use curl_alloc::{OutOfMemory, TryVec as _};

use super::TransferId;
use crate::conn::io::{Events, SocketKey};

/// What the socket callback is told of a socket (`CURL_POLL_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketWhat {
    In,
    Out,
    InOut,
    /// No transfer waits on it any more, or it is closing.
    Remove,
}

impl SocketWhat {
    fn of(events: Events) -> SocketWhat {
        match (events.contains(Events::IN), events.contains(Events::OUT)) {
            (true, true) => SocketWhat::InOut,
            (true, false) => SocketWhat::In,
            (false, true) => SocketWhat::Out,
            (false, false) => unreachable!("a socket waited on is waited on for something"),
        }
    }
}

/// Something the application is to hear of a socket, in the order it is
/// to hear it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Change<S> {
    pub(crate) key: SocketKey,
    pub(crate) what: SocketWhat,
    /// The value assigned to a socket being removed, which the table no
    /// longer holds; an update reads it from the table when told.
    pub(crate) removed_with: Option<S>,
}

#[derive(Debug)]
struct Entry<S> {
    key: SocketKey,
    /// The transfers waiting on the socket, and for what.
    users: Vec<(TransferId, Events)>,
    /// What the application was last told, if anything.
    told: Option<Events>,
    assigned: Option<S>,
}

impl<S> Entry<S> {
    /// What the socket is waited on for, by all its users together.
    fn wanted(&self) -> Events {
        self.users.iter().fold(Events::NONE, |all, &(_, e)| all | e)
    }
}

/// The table of sockets the application was asked to watch.
#[derive(Debug)]
pub(crate) struct SocketTable<S> {
    entries: Vec<Entry<S>>,
}

impl<S: Copy> SocketTable<S> {
    pub(crate) fn new() -> SocketTable<S> {
        SocketTable {
            entries: Vec::new(),
        }
    }

    /// Transfer `id` now waits on `wants` (`mev_pollset_diff`): record it,
    /// and add to `changes` what the application is to hear, the sockets
    /// waited on first in `wants`'s order, then those given up.
    pub(crate) fn assess(
        &mut self,
        id: TransferId,
        wants: &[(SocketKey, Events)],
        changes: &mut Vec<Change<S>>,
    ) -> Result<(), OutOfMemory> {
        for &(key, events) in wants {
            let row = match self.row(key) {
                Some(row) => row,
                None => {
                    self.entries.try_push(Entry {
                        key,
                        users: Vec::new(),
                        told: None,
                        assigned: None,
                    })?;
                    self.entries.len() - 1
                }
            };
            let entry = &mut self.entries[row];
            match entry.users.iter_mut().find(|(user, _)| *user == id) {
                Some((_, had)) => *had = events,
                None => entry.users.try_push((id, events))?,
            }
            if let Some(change) = update(entry) {
                changes.try_push(change)?;
            }
        }
        let mut row = 0;
        while row < self.entries.len() {
            let entry = &mut self.entries[row];
            let given_up = !wants.iter().any(|&(key, _)| key == entry.key)
                && entry.users.iter().any(|&(user, _)| user == id);
            if given_up {
                entry.users.retain(|&(user, _)| user != id);
                if entry.users.is_empty() {
                    // The last user is gone (`mev_forget_socket`).
                    if let Some(change) = self.forget_row(row) {
                        changes.try_push(change)?;
                    }
                    continue;
                }
                if let Some(change) = update(entry) {
                    changes.try_push(change)?;
                }
            }
            row += 1;
        }
        Ok(())
    }

    /// The socket `key` is closing (`Curl_multi_will_close`): forget it,
    /// and say so if the application was told of it.
    pub(crate) fn forget(&mut self, key: SocketKey) -> Option<Change<S>> {
        self.row(key).and_then(|row| self.forget_row(row))
    }

    fn forget_row(&mut self, row: usize) -> Option<Change<S>> {
        let entry = self.entries.swap_remove(row);
        entry.told.map(|_| Change {
            key: entry.key,
            what: SocketWhat::Remove,
            removed_with: entry.assigned,
        })
    }

    /// The application was told `what` of `key`.
    pub(crate) fn told(&mut self, key: SocketKey, what: SocketWhat) {
        if what == SocketWhat::Remove {
            return;
        }
        if let Some(row) = self.row(key) {
            let entry = &mut self.entries[row];
            entry.told = Some(entry.wanted());
        }
    }

    /// The transfers waiting on `key`, in the order they began to.
    pub(crate) fn users(&self, key: SocketKey) -> impl Iterator<Item = TransferId> + '_ {
        self.row(key)
            .into_iter()
            .flat_map(|row| self.entries[row].users.iter().map(|&(id, _)| id))
    }

    /// Tag the socket `key` with the application's value
    /// (`curl_multi_assign`); a socket no transfer waits on has none.
    pub(crate) fn assign(&mut self, key: SocketKey, value: Option<S>) -> Result<(), UnknownSocket> {
        let row = self.row(key).ok_or(UnknownSocket)?;
        self.entries[row].assigned = value;
        Ok(())
    }

    pub(crate) fn assigned(&self, key: SocketKey) -> Option<S> {
        self.row(key).and_then(|row| self.entries[row].assigned)
    }

    /// Every transfer waiting on a socket, and the socket.
    #[cfg(debug_assertions)]
    pub(crate) fn each_user(&self, mut f: impl FnMut(TransferId, SocketKey)) {
        for entry in &self.entries {
            for &(id, _) in &entry.users {
                f(id, entry.key);
            }
        }
    }

    fn row(&self, key: SocketKey) -> Option<usize> {
        self.entries.iter().position(|e| e.key == key)
    }
}

/// What a socket's users want, if the application has not heard it
/// (`mev_sh_entry_update`).
fn update<S: Copy>(entry: &Entry<S>) -> Option<Change<S>> {
    let wanted = entry.wanted();
    (entry.told != Some(wanted)).then(|| Change {
        key: entry.key,
        what: SocketWhat::of(wanted),
        removed_with: None,
    })
}

/// A socket the table does not know (`CURLM_BAD_SOCKET`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownSocket;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Arena, ArenaPolicy};

    fn ids() -> (TransferId, TransferId) {
        let mut arena: Arena<(), super::super::Transfer> =
            Arena::new(ArenaPolicy::new(4, 0).unwrap()).unwrap();
        (
            arena.reserve().unwrap().fill(()),
            arena.reserve().unwrap().fill(()),
        )
    }

    fn whats(changes: &[Change<u8>]) -> Vec<(i32, SocketWhat, Option<u8>)> {
        changes
            .iter()
            .map(|c| (c.key.get(), c.what, c.removed_with))
            .collect()
    }

    /// What a user waits for replaces what it waited for; the socket is
    /// waited on for what all its users want, told when that changes, and
    /// removed with its value when the last goes.
    #[test]
    fn a_socket_is_waited_on_for_what_its_users_want() {
        let (a, b) = ids();
        let k = SocketKey::new(5);
        let mut t: SocketTable<u8> = SocketTable::new();
        let assess = |t: &mut SocketTable<u8>, id, wants: &[(SocketKey, Events)]| {
            let mut changes = Vec::new();
            t.assess(id, wants, &mut changes).unwrap();
            for c in &changes {
                t.told(c.key, c.what);
            }
            whats(&changes)
        };
        assert_eq!(
            assess(&mut t, a, &[(k, Events::OUT)]),
            [(5, SocketWhat::Out, None)]
        );
        t.assign(k, Some(9)).unwrap();
        assert_eq!(t.assigned(k), Some(9));
        assert_eq!(
            assess(&mut t, a, &[(k, Events::IN)]),
            [(5, SocketWhat::In, None)]
        );
        assert_eq!(
            assess(&mut t, b, &[(k, Events::OUT)]),
            [(5, SocketWhat::InOut, None)]
        );
        assert_eq!(t.users(k).collect::<Vec<_>>(), [a, b]);
        assert_eq!(assess(&mut t, a, &[]), [(5, SocketWhat::Out, None)]);
        assert_eq!(assess(&mut t, b, &[]), [(5, SocketWhat::Remove, Some(9))]);
        assert_eq!(t.assign(k, None), Err(UnknownSocket));
    }
}
