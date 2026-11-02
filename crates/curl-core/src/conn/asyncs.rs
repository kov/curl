//! What C keeps of each resolve a transfer started that did not answer at
//! once (`struct Curl_resolv_async`, linked on `data->state.async`): its
//! number, drawn from its multi's (`last_resolv_id`), and the DNS filter it
//! is for. The engine's resolves end as their answers come; C's records of
//! them outlive that, until the filter that asked connects, the transfer
//! is done, or the handle is reset or let go, and each says so as it goes
//! (`[N] shutdown async`, `[N] destroy async`). These are those records,
//! kept on the handle, the newest last, for the lines alone.

use crate::conn::io::ResolveId;
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
    id: ResolveId,
    holder: Holder,
}

/// A transfer's records, the oldest first: made as the first is kept and
/// gone with the last, so a handle with none costs a pointer.
#[derive(Debug, Default)]
#[expect(
    clippy::box_collection,
    reason = "a pointer on every handle, where a vector would be three"
)]
pub(crate) struct Asyncs(Option<Box<Vec<Kept>>>);

impl Asyncs {
    /// A record kept for `holder`, numbered `id`.
    pub(crate) fn keep(&mut self, id: ResolveId, holder: Holder) -> Result<(), OutOfMemory> {
        let kept = match &mut self.0 {
            Some(kept) => kept,
            none => none.insert(try_box(Vec::new())?),
        };
        kept.try_push(Kept { id, holder })
    }

    /// The records, the oldest first.
    fn all(&self) -> &[Kept] {
        self.0.as_deref().map_or(&[], Vec::as_slice)
    }

    /// The newest of `holder`'s, if one is kept.
    pub(crate) fn newest(&self, holder: Holder) -> Option<ResolveId> {
        self.all()
            .iter()
            .rev()
            .find(|k| k.holder == holder)
            .map(|k| k.id)
    }

    /// The newest of `holder`'s, let go of, if one is kept
    /// (`Curl_resolv_destroy`).
    pub(crate) fn take(&mut self, holder: Holder) -> Option<ResolveId> {
        let kept = self.0.as_mut()?;
        let at = kept.iter().rposition(|k| k.holder == holder)?;
        let id = kept.remove(at).id;
        self.forget_empty();
        Some(id)
    }

    /// The newest, let go of, if any: one by one, each is
    /// (`Curl_resolv_destroy_all`).
    pub(crate) fn pop_newest(&mut self) -> Option<ResolveId> {
        let id = self.0.as_mut()?.pop().map(|k| k.id);
        self.forget_empty();
        id
    }

    /// The `n`th, counting from the newest at 0.
    pub(crate) fn nth_newest(&self, n: usize) -> Option<ResolveId> {
        self.all().iter().rev().nth(n).map(|k| k.id)
    }

    /// The list let go of once nothing is in it.
    fn forget_empty(&mut self) {
        if self.0.as_ref().is_some_and(|kept| kept.is_empty()) {
            self.0 = None;
        }
    }
}

/// The multi's numbering of its transfers' resolves: from 1, past the
/// last back to 1, never 0 (`last_resolv_id`).
#[derive(Debug, Default)]
pub(crate) struct ResolveCount(Option<ResolveId>);

impl ResolveCount {
    /// The next number.
    pub(crate) fn next(&mut self) -> ResolveId {
        let id = self.0.map_or(ResolveId::FIRST, ResolveId::next);
        self.0 = Some(id);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .map(ResolveId::get)
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
}
