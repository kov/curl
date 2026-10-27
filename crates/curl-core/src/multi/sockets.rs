//! What the socket callback was told (`lib/multi_ev.c`): for each socket
//! a transfer waits on, the transfers waiting on it and for what, what the
//! application last heard, and the value it assigned to the socket.
//!
//! Each socket's entry is the one record of who waits on it: a transfer
//! keeps no copy, and finds its sockets by asking the table.

use curl_alloc::{OutOfMemory, TryVec as _};

use super::TransferId;
use crate::conn::io::{Events, Socket, SocketKey};
use crate::conn::shutdown::ClosingId;

/// Who waits on a socket: a transfer, or a connection shutting down in
/// the multi's set, which owns its socket once no transfer has it (C's
/// `mev_sh_entry`, its transfers and its connection).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketOwner {
    Transfer(TransferId),
    Conn(ClosingId),
    /// The resolver's wake, which the multi listens on while a transfer
    /// is alive (C's admin handle and `wakeup_internal`).
    Resolver,
}

/// Whom the socket callback is told a socket is for: a transfer, or the
/// multi's own work, a connection shutting down (C passes its internal
/// handle).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketFor {
    Transfer(TransferId),
    Multi,
}

/// The sockets a pollset holds in place: as many as a connection setup's
/// race of addresses runs at once and a resolver's own. More go on the
/// heap, as C's `easy_pollset` grows past its inline sockets.
const POLLSET_INLINE: usize = 8;

/// Items held in place up to `POLLSET_INLINE`, then on the heap.
#[derive(Clone, Debug)]
enum Store<T> {
    Inline {
        len: usize,
        /// Unused past `len`.
        items: [T; POLLSET_INLINE],
    },
    Heap(Vec<T>),
}

impl<T: Copy> Store<T> {
    /// None, the room in place filled with `fill`.
    const fn new(fill: T) -> Store<T> {
        Store::Inline {
            len: 0,
            items: [fill; POLLSET_INLINE],
        }
    }

    fn as_slice(&self) -> &[T] {
        match self {
            Store::Inline { len, items } => &items[..*len],
            Store::Heap(items) => items,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            Store::Inline { len, items } => &mut items[..*len],
            Store::Heap(items) => items,
        }
    }

    /// `item` after the others, moved to the heap once the room in place
    /// is full.
    fn push(&mut self, item: T) -> Result<(), OutOfMemory> {
        match self {
            Store::Inline { len, items } if *len < POLLSET_INLINE => {
                items[*len] = item;
                *len += 1;
            }
            Store::Inline { items, .. } => {
                let mut heap = Vec::new();
                heap.try_extend_from_slice(items)?;
                heap.try_push(item)?;
                *self = Store::Heap(heap);
            }
            Store::Heap(items) => items.try_push(item)?,
        }
        Ok(())
    }
}

/// The sockets a transfer waits on, and for what (C's `easy_pollset`),
/// held without allocating while they fit in place. A socket added twice
/// waits for both.
pub(crate) struct Pollset<'p> {
    sockets: Store<Option<&'p dyn Socket>>,
    wants: Wants,
}

/// A pollset's sockets by key, apart from the sockets themselves.
#[derive(Clone, Debug)]
pub(crate) struct Wants(Store<(SocketKey, Events)>);

impl Wants {
    /// No socket.
    pub(crate) const NONE: Wants = Wants(Store::new((SocketKey::BAD, Events::NONE)));

    pub(crate) fn as_slice(&self) -> &[(SocketKey, Events)] {
        self.0.as_slice()
    }
}

impl<'p> Pollset<'p> {
    /// Waiting on nothing.
    pub(crate) fn new() -> Pollset<'p> {
        Pollset {
            sockets: Store::new(None),
            wants: Wants::NONE,
        }
    }

    /// Wait on `socket` for `events` too; nothing, for none.
    pub(crate) fn add(
        &mut self,
        socket: &'p dyn Socket,
        events: Events,
    ) -> Result<(), OutOfMemory> {
        if events.is_empty() {
            return Ok(());
        }
        let key = socket.key();
        let wants = self.wants.0.as_mut_slice();
        if let Some((_, had)) = wants.iter_mut().find(|(k, _)| *k == key) {
            *had = *had | events;
            return Ok(());
        }
        self.sockets.push(Some(socket))?;
        self.wants.0.push((key, events))
    }

    /// Each socket, and what it is waited on for.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'p dyn Socket, Events)> + '_ {
        self.sockets
            .as_slice()
            .iter()
            .zip(self.wants.as_slice())
            .map(|(s, &(_, events))| (s.expect("added"), events))
    }

    /// The sockets by key.
    pub(crate) fn into_wants(self) -> Wants {
        self.wants
    }
}

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
    /// Who waits on the socket, and for what.
    users: Vec<(SocketOwner, Events)>,
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

    /// `id` now waits on `wants` (`mev_pollset_diff`): record it, and add
    /// to `changes` what the application is to hear, the sockets waited on
    /// first in `wants`'s order, then those given up.
    pub(crate) fn assess(
        &mut self,
        id: SocketOwner,
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

    /// Who waits on `key`, in the order they began to.
    pub(crate) fn users(&self, key: SocketKey) -> impl Iterator<Item = SocketOwner> + '_ {
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

    /// Whether a connection shutting down waits on `key`: its socket is
    /// the multi's own then, whoever closes it.
    pub(crate) fn has_conn(&self, key: SocketKey) -> bool {
        self.users(key).any(|u| matches!(u, SocketOwner::Conn(_)))
    }

    /// Everyone waiting on a socket, and the socket.
    #[cfg(debug_assertions)]
    pub(crate) fn each_user(&self, mut f: impl FnMut(SocketOwner, SocketKey)) {
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
    use crate::conn::MAX_ATTEMPTS;
    use crate::conn::io::{Readiness, Recv, Sent};
    use crate::id::{Arena, ArenaPolicy};

    /// A socket known by its key alone.
    #[derive(Debug)]
    struct Keyed(i32);

    impl Socket for Keyed {
        fn key(&self) -> SocketKey {
            SocketKey::new(self.0)
        }
        fn readiness(&self) -> Readiness<'_> {
            unreachable!()
        }
        fn take_error(&self) -> std::io::Result<Option<std::io::Error>> {
            unreachable!()
        }
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            unreachable!()
        }
        fn set(&self, _: crate::conn::io::SocketOption) -> std::io::Result<()> {
            unreachable!()
        }
        fn set_nonblocking(&self) -> std::io::Result<()> {
            unreachable!()
        }
        fn bind(&self, _: std::net::SocketAddr) -> std::io::Result<()> {
            unreachable!()
        }
        fn bind_to_device(&self, _: &[u8]) -> std::io::Result<()> {
            unreachable!()
        }
        fn connect(
            &self,
            _: &crate::conn::io::Remote,
        ) -> std::io::Result<crate::conn::io::Connect> {
            unreachable!()
        }
        fn recv(&self, _: &mut [u8]) -> std::io::Result<Recv> {
            unreachable!()
        }
        fn send(&self, _: &[u8]) -> std::io::Result<Sent> {
            unreachable!()
        }
        fn release(self: Box<Self>) -> SocketKey {
            unreachable!()
        }
    }

    /// A socket added again waits for both; one added for nothing is not
    /// waited on.
    #[test]
    fn a_pollset_holds_each_socket_once() {
        let (a, b, c) = (Keyed(3), Keyed(4), Keyed(5));
        let mut set = Pollset::new();
        set.add(&a, Events::IN).unwrap();
        set.add(&b, Events::OUT).unwrap();
        set.add(&a, Events::OUT).unwrap();
        set.add(&c, Events::NONE).unwrap();
        let keys = [SocketKey::new(3), SocketKey::new(4)];
        let want = [(keys[0], Events::IN | Events::OUT), (keys[1], Events::OUT)];
        let got: Vec<_> = set.iter().map(|(s, e)| (s.key(), e)).collect();
        assert_eq!(got, want);
        assert_eq!(set.into_wants().as_slice(), want);
        assert_eq!(Wants::NONE.as_slice(), []);
    }

    /// A pollset holds more sockets than it has room for in place, two
    /// races of addresses among them, each socket still once.
    #[test]
    fn a_pollset_grows_past_its_room_in_place() {
        let sockets: Vec<_> = (0..2 * MAX_ATTEMPTS as i32)
            .map(|fd| Keyed(10 + fd))
            .collect();
        assert!(sockets.len() > POLLSET_INLINE);
        let mut set = Pollset::new();
        for s in &sockets {
            set.add(s, Events::OUT).unwrap();
        }
        // Added again past the room in place, it waits for both.
        set.add(&sockets[0], Events::IN).unwrap();
        set.add(&sockets[POLLSET_INLINE], Events::IN).unwrap();
        let want: Vec<_> = (0..sockets.len())
            .map(|i| {
                let events = match i {
                    0 | POLLSET_INLINE => Events::IN | Events::OUT,
                    _ => Events::OUT,
                };
                (SocketKey::new(10 + i as i32), events)
            })
            .collect();
        let got: Vec<_> = set.iter().map(|(s, e)| (s.key(), e)).collect();
        assert_eq!(got, want);
        assert_eq!(set.into_wants().as_slice(), want);
    }

    fn ids() -> (SocketOwner, SocketOwner) {
        let mut arena: Arena<(), super::super::Transfer> =
            Arena::new(ArenaPolicy::new(4, 0).unwrap()).unwrap();
        (
            SocketOwner::Transfer(arena.reserve().unwrap().fill(())),
            SocketOwner::Transfer(arena.reserve().unwrap().fill(())),
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
