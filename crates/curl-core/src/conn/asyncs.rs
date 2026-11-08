//! What C keeps of each resolve a transfer started that did not answer at
//! once (`struct Curl_resolv_async`, linked on `data->state.async`): its
//! number, drawn from its multi's (`last_resolv_id`), and the DNS filter it
//! is for. The engine's resolves end as their answers come; C's records of
//! them outlive that, until the filter that asked connects, the transfer
//! is done, or the handle is reset or let go, and each says so as it goes
//! (`[N] shutdown async`, `[N] destroy async`). These are those records,
//! kept on the handle, the newest last, for the lines, and for the name's
//! timer a library's answered resolve arms until its record goes.

use crate::multi::state::ConnRank;
use curl_alloc::{OutOfMemory, TryVec, try_box};

/// The DNS filter a resolve is for (`cf_dns_ctx->resolv_id`), or none for
/// a blocking resolve, which goes as its wait ends (`Curl_resolv_blocking`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Holder {
    /// The origin's HTTPS record's, at the top of the chain.
    Record,
    /// The first hop's addresses', on the transfer's connection or its
    /// second (FTP's data connection).
    Addresses(ConnRank),
    /// The SOCKS proxy's target's, resolved here, below the others.
    Target,
    /// A blocking resolve's.
    Blocking,
}

/// One kept record.
#[derive(Clone, Copy, Debug)]
struct Kept {
    id: ResolveNumber,
    holder: Holder,
    /// A resolver library answered it, its channel left open until the
    /// record goes: C's pollset arms the name's timer from it each time,
    /// for the resolve's time left (`Curl_async_pollset`).
    arms: bool,
}

/// A transfer's records, the oldest first: made as the first is kept and
/// gone with the last, so a handle with none costs a pointer.
#[derive(Debug, Default)]
pub(crate) struct Asyncs(Option<Box<Records>>);

/// How many records are kept in the list's own allocation: the most a
/// request keeps at once but for a second connection's, so that keeping
/// them allocates once, where C allocates once for each
/// (`hostip_async_new`).
const INLINE: usize = 4;

/// The records, the oldest first: the first `INLINE` in place, any more
/// after them.
#[derive(Debug, Default)]
struct Records {
    first: [Option<Kept>; INLINE],
    /// How many of `first` are kept, the rest `None`; all of them before
    /// any is in `more`.
    n: usize,
    more: Vec<Kept>,
}

impl Records {
    fn len(&self) -> usize {
        self.n + self.more.len()
    }

    /// The `at`th, counting from the oldest at 0.
    fn get(&self, at: usize) -> Kept {
        if at < self.n {
            self.first[at].expect("the first `n` are kept")
        } else {
            self.more[at - INLINE]
        }
    }

    fn get_mut(&mut self, at: usize) -> &mut Kept {
        if at < self.n {
            self.first[at].as_mut().expect("the first `n` are kept")
        } else {
            &mut self.more[at - INLINE]
        }
    }

    fn push(&mut self, kept: Kept) -> Result<(), OutOfMemory> {
        if self.n < INLINE {
            self.first[self.n] = Some(kept);
            self.n += 1;
            return Ok(());
        }
        self.more.try_push(kept)
    }

    /// The `at`th let go of, those after it moving up.
    fn remove(&mut self, at: usize) -> Kept {
        if at >= self.n {
            return self.more.remove(at - INLINE);
        }
        let gone = self.get(at);
        self.first.copy_within(at + 1..self.n, at);
        if self.more.is_empty() {
            self.n -= 1;
            self.first[self.n] = None;
        } else {
            self.first[INLINE - 1] = Some(self.more.remove(0));
        }
        gone
    }

    fn pop(&mut self) -> Option<Kept> {
        if let Some(kept) = self.more.pop() {
            return Some(kept);
        }
        let at = self.n.checked_sub(1)?;
        Some(self.remove(at))
    }
}

impl Asyncs {
    /// A record kept for `holder`, numbered `id`.
    pub(crate) fn keep(&mut self, id: ResolveNumber, holder: Holder) -> Result<(), OutOfMemory> {
        let kept = match &mut self.0 {
            Some(kept) => kept,
            none => none.insert(try_box(Records::default())?),
        };
        kept.push(Kept {
            id,
            holder,
            arms: false,
        })
    }

    /// The newest of `holder`'s, if one is kept, answered by a resolver
    /// library, whose channel is still open: it arms the name's timer from
    /// now on, until it goes.
    pub(crate) fn answered_by_library(&mut self, holder: Holder) {
        let Some(kept) = self.0.as_deref_mut() else {
            return;
        };
        let newest = (0..kept.len())
            .rev()
            .find(|&at| kept.get(at).holder == holder);
        if let Some(at) = newest {
            kept.get_mut(at).arms = true;
        }
    }

    /// Whether a record kept arms the name's timer: one a library
    /// answered.
    pub(crate) fn arms(&self) -> bool {
        (0..).map_while(|n| self.newest_nth(n)).any(|k| k.arms)
    }

    /// The `n`th, counting from the newest at 0.
    fn newest_nth(&self, n: usize) -> Option<Kept> {
        let kept = self.0.as_deref()?;
        let len = kept.len();
        (n < len).then(|| kept.get(len - 1 - n))
    }

    /// The newest of `holder`'s, if one is kept.
    pub(crate) fn newest(&self, holder: Holder) -> Option<ResolveNumber> {
        (0..)
            .map_while(|n| self.newest_nth(n))
            .find(|k| k.holder == holder)
            .map(|k| k.id)
    }

    /// The newest of `holder`'s, let go of, if one is kept
    /// (`Curl_resolv_destroy`).
    pub(crate) fn take(&mut self, holder: Holder) -> Option<ResolveNumber> {
        let kept = self.0.as_mut()?;
        let at = (0..kept.len())
            .rev()
            .find(|&at| kept.get(at).holder == holder)?;
        let id = kept.remove(at).id;
        self.forget_empty();
        Some(id)
    }

    /// The newest, let go of, if any: one by one, each is
    /// (`Curl_resolv_destroy_all`).
    pub(crate) fn pop_newest(&mut self) -> Option<ResolveNumber> {
        let id = self.0.as_mut()?.pop().map(|k| k.id);
        self.forget_empty();
        id
    }

    /// The `n`th, counting from the newest at 0.
    pub(crate) fn nth_newest(&self, n: usize) -> Option<ResolveNumber> {
        self.newest_nth(n).map(|k| k.id)
    }

    /// The list let go of once nothing is in it.
    fn forget_empty(&mut self) {
        if self.0.as_ref().is_some_and(|kept| kept.len() == 0) {
            self.0 = None;
        }
    }
}

/// The number of a resolve's record, as its lines show it: drawn from
/// its multi's, in 32 bits from 1, past the last back to 1
/// (`last_resolv_id`). A resolve would have to wait out four billion
/// others to meet its number again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolveNumber(std::num::NonZeroU32);

impl ResolveNumber {
    /// The first a multi gives.
    pub(crate) const FIRST: ResolveNumber = ResolveNumber(std::num::NonZeroU32::MIN);

    /// Its number, as traces show it.
    pub(crate) fn get(self) -> u32 {
        self.0.get()
    }

    /// The one after it.
    fn next(self) -> ResolveNumber {
        ResolveNumber(self.0.checked_add(1).unwrap_or(std::num::NonZeroU32::MIN))
    }
}

/// The multi's numbering of its transfers' resolves: from 1, past the
/// last back to 1, never 0 (`last_resolv_id`).
#[derive(Debug, Default)]
pub(crate) struct ResolveCount(Option<ResolveNumber>);

impl ResolveCount {
    /// The next number.
    pub(crate) fn next(&mut self) -> ResolveNumber {
        let id = self.0.map_or(ResolveNumber::FIRST, ResolveNumber::next);
        self.0 = Some(id);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolves are numbered as C's multi numbers them: from 1, and after
    /// `UINT32_MAX` from 1 again, never 0 (`last_resolv_id`).
    #[test]
    fn resolve_numbers_count_as_c_s() {
        assert_eq!(ResolveNumber::FIRST.get(), 1);
        assert_eq!(ResolveNumber::FIRST.next().get(), 2);
        let last = ResolveNumber(std::num::NonZeroU32::MAX);
        assert_eq!(last.next(), ResolveNumber::FIRST);
    }

    #[test]
    fn records_are_walked_newest_first_and_taken_by_holder() {
        let mut count = ResolveCount::default();
        let mut kept = Asyncs::default();
        let record = count.next();
        let addresses = count.next();
        assert_eq!((record.get(), addresses.get()), (1, 2));
        kept.keep(record, Holder::Record).unwrap();
        kept.keep(addresses, Holder::Addresses(ConnRank::First))
            .unwrap();
        // C's list is walked from its head, the newest.
        let walked: Vec<u32> = (0..3)
            .map_while(|n| kept.nth_newest(n))
            .map(ResolveNumber::get)
            .collect();
        assert_eq!(walked, [2, 1]);
        assert_eq!(kept.newest(Holder::Record), Some(record));
        assert_eq!(kept.take(Holder::Addresses(ConnRank::Second)), None);
        assert_eq!(
            kept.take(Holder::Addresses(ConnRank::First)),
            Some(addresses)
        );
        assert_eq!(kept.take(Holder::Addresses(ConnRank::First)), None);
        assert_eq!(kept.pop_newest(), Some(record));
        assert!(kept.0.is_none(), "the last let go of takes the list");
        assert_eq!(kept.pop_newest(), None);
    }

    /// A record a library answered arms the name's timer until it goes; one
    /// of another holder's does not.
    #[test]
    fn a_record_a_library_answered_arms_until_it_goes() {
        let mut count = ResolveCount::default();
        let mut kept = Asyncs::default();
        kept.answered_by_library(Holder::Record);
        assert!(!kept.arms(), "none is kept");
        kept.keep(count.next(), Holder::Record).unwrap();
        kept.keep(count.next(), Holder::Addresses(ConnRank::First))
            .unwrap();
        assert!(!kept.arms());
        kept.answered_by_library(Holder::Target);
        assert!(!kept.arms(), "no record of the target's");
        kept.answered_by_library(Holder::Addresses(ConnRank::First));
        assert!(kept.arms());
        kept.take(Holder::Record);
        assert!(kept.arms(), "the addresses' still kept");
        kept.take(Holder::Addresses(ConnRank::First));
        assert!(!kept.arms());
    }

    /// A record past those kept in place is marked as a library answered
    /// it, and arms until it goes, the records beside it left as they are.
    #[test]
    fn a_record_past_those_in_place_arms_once_answered() {
        let mut count = ResolveCount::default();
        let mut kept = Asyncs::default();
        let holders = [
            Holder::Record,
            Holder::Addresses(ConnRank::First),
            Holder::Target,
            Holder::Blocking,
            Holder::Addresses(ConnRank::Second),
            Holder::Target,
        ];
        assert_eq!(holders.len(), INLINE + 2, "two past those in place");
        for holder in holders {
            kept.keep(count.next(), holder).unwrap();
        }
        kept.answered_by_library(Holder::Addresses(ConnRank::Second));
        assert!(kept.arms());
        kept.take(Holder::Addresses(ConnRank::Second));
        assert!(!kept.arms(), "only the one answered armed");
    }

    /// Past the records kept in place, the rest follow them, in order
    /// however they go.
    #[test]
    fn records_past_those_kept_in_place_keep_their_order() {
        let mut count = ResolveCount::default();
        let mut kept = Asyncs::default();
        let ids: Vec<ResolveNumber> = (0..7).map(|_| count.next()).collect();
        let holders = [
            Holder::Record,
            Holder::Addresses(ConnRank::First),
            Holder::Target,
            Holder::Blocking,
            Holder::Addresses(ConnRank::Second),
            Holder::Record,
            Holder::Target,
        ];
        for (&id, &holder) in ids.iter().zip(&holders) {
            kept.keep(id, holder).unwrap();
        }
        let walked = |kept: &Asyncs| -> Vec<u32> {
            (0..)
                .map_while(|n| kept.nth_newest(n))
                .map(ResolveNumber::get)
                .collect()
        };
        assert_eq!(walked(&kept), [7, 6, 5, 4, 3, 2, 1]);
        // The newest of a holder's, in place or after.
        assert_eq!(kept.take(Holder::Target), Some(ids[6]));
        assert_eq!(kept.take(Holder::Target), Some(ids[2]));
        assert_eq!(walked(&kept), [6, 5, 4, 2, 1]);
        assert_eq!(kept.newest(Holder::Record), Some(ids[5]));
        assert_eq!(kept.take(Holder::Record), Some(ids[5]));
        assert_eq!(kept.take(Holder::Record), Some(ids[0]));
        assert_eq!(walked(&kept), [5, 4, 2]);
        let popped: Vec<u32> = std::iter::from_fn(|| kept.pop_newest())
            .map(ResolveNumber::get)
            .collect();
        assert_eq!(popped, [5, 4, 2]);
        assert!(kept.0.is_none());
    }
}
