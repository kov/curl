//! The addresses names were found to have, kept for the transfers after
//! (`lib/vdns/dnscache.c`), and the entries an application gives for them
//! (`CURLOPT_RESOLVE`, `Curl_loadhostpairs`).

use crate::conn::asyncs::Holder;
use crate::multi::state::ConnRank;
use crate::share::{Kind, Share, ShareLock, watched};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::doh::HttpsRecord;
use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use crate::conn::io::Family;
use crate::time::Instant;

/// The addresses a name stands for, in the order they were found (C's
/// `Curl_dns_entry`); none for a name the resolver said does not exist.
#[derive(Debug)]
pub(crate) struct Answer {
    /// The name as it was resolved, or given: an address, a host, or `*`
    /// for any.
    name: Vec<u8>,
    addrs: Vec<IpAddr>,
    /// The addresses asked for (`dns_queries`): an answer for one family
    /// answers no lookup for both.
    family: Family,
    /// Its addresses were shuffled as it was made, which the trace says
    /// with the resolve's other lines, said after it is kept.
    shuffled: bool,
}

impl Answer {
    /// The addresses of either family `name` stands for.
    pub(crate) fn new(name: &[u8], addrs: Vec<IpAddr>) -> Result<Answer, OutOfMemory> {
        Answer::of(name, addrs, Family::Any)
    }

    /// What a resolver answered for `name`, asked for `family`.
    pub(crate) fn of(
        name: &[u8],
        addrs: Vec<IpAddr>,
        family: Family,
    ) -> Result<Answer, OutOfMemory> {
        let mut owned = Vec::new();
        owned.try_extend_from_slice(name)?;
        Ok(Answer {
            name: owned,
            addrs,
            family,
            shuffled: false,
        })
    }

    pub(crate) fn name(&self) -> &[u8] {
        &self.name
    }

    pub(crate) fn addrs(&self) -> &[IpAddr] {
        &self.addrs
    }

    /// Its addresses are `addrs` shuffled ([`shuffle`]), which the trace
    /// says later.
    pub(crate) fn mark_shuffled(&mut self) {
        self.shuffled = true;
    }

    /// Whether its addresses were shuffled as it was made, for a trace
    /// said after it is kept.
    pub(crate) fn shuffled(&self) -> bool {
        self.shuffled
    }

    /// The addresses, to be put in another order.
    pub(crate) fn addrs_mut(&mut self) -> &mut [IpAddr] {
        &mut self.addrs
    }

    /// Whether the name was resolved, rather than an address itself
    /// (`Curl_host_is_ipnum`).
    pub(crate) fn resolved(&self) -> bool {
        address(&self.name).is_none()
    }
}

/// Put `addrs` in a random order, as `CURLOPT_DNS_SHUFFLE_ADDRESSES`
/// asks (`dns_shuffle_addr`): a Fisher-Yates shuffle, each place drawn
/// with four of `random`'s bytes. Random bytes that cannot be had leave
/// the order as it is, as C leaves it. Whether there were two addresses
/// or more to shuffle.
pub(crate) fn shuffle(
    addrs: &mut [IpAddr],
    random: &mut dyn FnMut(&mut [u8]) -> bool,
) -> Result<bool, OutOfMemory> {
    let n = addrs.len();
    if n < 2 {
        return Ok(false);
    }
    let mut drawn = curl_alloc::try_zeroed(n * 4)?;
    if !random(&mut drawn) {
        return Ok(true);
    }
    for i in (1..n).rev() {
        let place = u32::from_ne_bytes(drawn[i * 4..i * 4 + 4].try_into().expect("four bytes"));
        let places = u32::try_from(i + 1).expect("fewer addresses than a u32 counts");
        let j = usize::try_from(place % places).expect("a place among them");
        addrs.swap(i, j);
    }
    Ok(true)
}

/// The most entries kept (`MAX_DNS_CACHE_SIZE`).
const MAX_ENTRIES: usize = 29999;

/// The answers of a multi, by name, in any case, port and what is kept of
/// the name (C's hash on `name:port`).
#[derive(Debug, Default)]
pub(crate) struct DnsCache {
    entries: HashMap<Key, Entry>,
}

/// The answers a transfer looks up and keeps: its multi's, at the step's
/// time, or its share's, at the share's time, each use of those under the
/// share's lock with the application told around it.
pub(crate) enum Names<'a> {
    Own {
        cache: &'a mut DnsCache,
        now: Instant,
    },
    Shared {
        share: &'a Share,
        watch: Option<&'a dyn ShareLock>,
    },
}

impl Names<'_> {
    /// Run `f` on the answers, as one use of them, at the time of their
    /// keeper's time: the share's are stamped and aged at the share's
    /// (`Share::now`), read as the use begins, never at a time the multi
    /// passes in.
    pub(crate) fn section<R>(&mut self, f: impl FnOnce(&mut Dated<'_>) -> R) -> R {
        match self {
            Names::Own { cache, now } => f(&mut Dated { cache, now: *now }),
            Names::Shared { share, watch } => {
                let now = share.now();
                watched(*watch, share, Kind::Names, || {
                    f(&mut Dated {
                        cache: &mut share.dns(),
                        now,
                    })
                })
            }
        }
    }

    /// Tell the application of the use C makes as a DNS filter lets go of
    /// the entry it holds (`Curl_dns_entry_unlink`, `Holds`): here the
    /// answer is counted, and nothing of the share is used.
    pub(crate) fn release(&mut self) {
        self.section(|_| ());
    }
}

/// Which of a transfer's DNS filters hold an entry of the cache, one each
/// at most (C's `cf_dns_ctx.dns`, the entry's count of users raised). A
/// filter holds one from the moment its resolve answers, the setup keeping
/// the addresses themselves, until the filter is destroyed: as its chain
/// is connected (`Curl_conn_remove_setup_filters`), as the second chain
/// is set up again (`Curl_conn_cf_discard_all`), or as the transfer is
/// done with the setup unfinished (`CF_CTRL_DATA_DONE`). The filter goes
/// with the setup's chain, not with the machine an attempt is driven by:
/// a failed attempt, or a race's two attempts below the one filter, leave
/// it as it is. Letting one go is a use of the cache, which a share's lock
/// callbacks see (`Curl_dns_entry_unlink`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Holds(u8);

impl Holds {
    /// The bit of the filter `holder` names on `rank`'s chain: the first
    /// hop's addresses' or the SOCKS proxy's target's. The record's filter
    /// holds no entry of addresses, and a blocking resolve has no filter.
    fn bit(holder: Holder, rank: ConnRank) -> u8 {
        let (rank, at) = match holder {
            Holder::Addresses(rank) => (rank, 0),
            Holder::Target => (rank, 1),
            Holder::Record | Holder::Blocking => unreachable!("{holder:?} holds no entry"),
        };
        match rank {
            ConnRank::First => 1 << at,
            ConnRank::Second => 1 << (at + 2),
        }
    }

    /// `holder`'s filter on `rank`'s chain has its entry. One it holds
    /// already stays its one: a setup dialed again resolves the SOCKS
    /// proxy's target again, which C's filter, above the setup's, does not.
    pub(crate) fn hold(&mut self, holder: Holder, rank: ConnRank) {
        self.0 |= Holds::bit(holder, rank);
    }

    /// `holder`'s filter on `rank`'s chain goes: whether it held an entry.
    pub(crate) fn take(&mut self, holder: Holder, rank: ConnRank) -> bool {
        let bit = Holds::bit(holder, rank);
        let held = self.0 & bit != 0;
        self.0 &= !bit;
        held
    }

    /// The filters of `rank`'s chain go, or of every chain with none:
    /// how many entries they held.
    pub(crate) fn take_all(&mut self, rank: Option<ConnRank>) -> u32 {
        let mask = match rank {
            Some(ConnRank::First) => 0b0011,
            Some(ConnRank::Second) => 0b1100,
            None => 0b1111,
        };
        let held = (self.0 & mask).count_ones();
        self.0 &= !mask;
        held
    }
}

/// One use of a cache, at its keeper's time: what is kept is kept from
/// then, and what was is aged to then.
pub(crate) struct Dated<'a> {
    cache: &'a mut DnsCache,
    now: Instant,
}

impl Dated<'_> {
    /// What is kept for `name` and `port`, as `DnsCache::lookup` says.
    pub(crate) fn lookup(
        &mut self,
        key: (&[u8], u16),
        family: Family,
        wildcard: bool,
        max_age: Option<Duration>,
    ) -> Lookup {
        self.cache.lookup(key, family, wildcard, max_age, self.now)
    }

    /// Keep `answer` for its name and `port` from now, as `DnsCache::put`.
    pub(crate) fn put(
        &mut self,
        answer: TryArc<Answer>,
        port: u16,
        permanent: bool,
    ) -> Result<bool, OutOfMemory> {
        self.cache.put(answer, port, self.now, permanent)
    }

    /// Forget the addresses kept for `name` and `port`; whether some were.
    pub(crate) fn remove(&mut self, name: &[u8], port: u16) -> bool {
        self.cache.remove(name, port)
    }

    /// What is kept of an HTTPS record, as `DnsCache::lookup_https`.
    pub(crate) fn lookup_https(
        &mut self,
        key: (&[u8], u16),
        max_age: Option<Duration>,
    ) -> HttpsLookup {
        self.cache.lookup_https(key, max_age, self.now)
    }

    /// Keep what a name has of an HTTPS record from now, as
    /// `DnsCache::put_https`.
    pub(crate) fn put_https(
        &mut self,
        name: &[u8],
        port: u16,
        record: Option<TryArc<HttpsRecord>>,
        negative: bool,
    ) -> Result<(), OutOfMemory> {
        self.cache.put_https(name, port, record, negative, self.now)
    }

    /// Drop the entries older than `max_age` by now, as `DnsCache::prune`.
    pub(crate) fn prune(&mut self, max_age: Option<Duration>) {
        self.cache.prune(self.now, max_age);
    }
}

/// What an entry keeps of its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Keeps {
    Addresses,
    /// What the name has of an HTTPS record (HTTPS-RR): an entry of its
    /// own, as C keeps both (`CURL_DNST_HTTPS`).
    Https,
}

/// What names an entry: a name, in any case, a port, and what is kept.
/// The keys kept and the ones looked for are hashed and compared as one,
/// so that a lookup needs no key of its own made.
trait Named {
    fn named(&self) -> (&[u8], u16, Keeps);
}

impl Hash for dyn Named + '_ {
    fn hash<S: Hasher>(&self, state: &mut S) {
        let (name, port, keeps) = self.named();
        state.write_usize(name.len());
        let mut folded = [0u8; 64];
        for chunk in name.chunks(folded.len()) {
            let folded = &mut folded[..chunk.len()];
            folded.copy_from_slice(chunk);
            folded.make_ascii_lowercase();
            state.write(folded);
        }
        port.hash(state);
        keeps.hash(state);
    }
}

impl PartialEq for dyn Named + '_ {
    fn eq(&self, other: &Self) -> bool {
        let (name, port, keeps) = self.named();
        let (other_name, other_port, other_keeps) = other.named();
        port == other_port && keeps == other_keeps && name.eq_ignore_ascii_case(other_name)
    }
}

impl Eq for dyn Named + '_ {}

/// An entry's key: the answer it is of, whose name it is kept under, the
/// port, and what is kept.
#[derive(Debug)]
struct Key {
    /// The name's addresses; or, for its HTTPS record, the name, which
    /// is the addresses' answer when it has one.
    answer: TryArc<Answer>,
    port: u16,
    keeps: Keeps,
}

impl Named for Key {
    fn named(&self) -> (&[u8], u16, Keeps) {
        (&self.answer.name, self.port, self.keeps)
    }
}

impl Hash for Key {
    fn hash<S: Hasher>(&self, state: &mut S) {
        <dyn Named>::hash(self, state);
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Key) -> bool {
        <dyn Named as PartialEq>::eq(self, other)
    }
}

impl Eq for Key {}

impl<'a> Borrow<dyn Named + 'a> for Key {
    fn borrow(&self) -> &(dyn Named + 'a) {
        self
    }
}

/// A name, port and what is kept of the name, looked for.
struct Probe<'a>(&'a [u8], u16, Keeps);

impl Named for Probe<'_> {
    fn named(&self) -> (&[u8], u16, Keeps) {
        (self.0, self.1, self.2)
    }
}

impl Probe<'_> {
    fn key(&self) -> &dyn Named {
        self
    }
}

#[derive(Debug)]
struct Entry {
    added: Instant,
    /// Given by the application without `+`: it never goes stale.
    permanent: bool,
    /// The record, for an entry that says the name has one.
    record: Option<TryArc<HttpsRecord>>,
    /// It says the name does not exist, or has no HTTPS record: it ages
    /// twice as fast.
    says_no: bool,
}

/// What the cache had of a name's HTTPS record.
#[derive(Clone, Debug)]
pub(crate) enum HttpsLookup {
    /// What it has: a record or, as far as was asked, none.
    Found(Option<TryArc<HttpsRecord>>),
    /// It had gone stale, and is gone.
    Stale,
    Missing,
}

#[cfg(test)]
impl PartialEq for HttpsLookup {
    fn eq(&self, other: &HttpsLookup) -> bool {
        matches!(
            (self, other),
            (HttpsLookup::Found(None), HttpsLookup::Found(None))
                | (HttpsLookup::Stale, HttpsLookup::Stale)
                | (HttpsLookup::Missing, HttpsLookup::Missing)
        )
    }
}

/// What the cache had for a name.
#[derive(Debug)]
pub(crate) enum Lookup {
    Found(TryArc<Answer>),
    /// The name was found not to exist.
    Negative,
    /// It had gone stale, and is gone.
    Stale,
    Missing,
}

impl DnsCache {
    /// What is kept for `name` and `port`, or for any name on the port if
    /// `wildcard` (`fetch_entry`), if it answers for `family`: an entry
    /// older than `max_age` is dropped, none for ever.
    fn lookup(
        &mut self,
        (name, port): (&[u8], u16),
        family: Family,
        wildcard: bool,
        max_age: Option<Duration>,
        now: Instant,
    ) -> Lookup {
        let mut probe = Probe(name, port, Keeps::Addresses);
        let mut found = self.entries.get_key_value(probe.key());
        if found.is_none() && wildcard {
            probe.0 = b"*";
            found = self.entries.get_key_value(probe.key());
        }
        let Some((key, entry)) = found else {
            return Lookup::Missing;
        };
        if let Some(max_age) = max_age
            && entry.stale_at(now, max_age)
        {
            self.entries.remove(probe.key());
            return Lookup::Stale;
        }
        let answer = &key.answer;
        if answer.family != Family::Any && answer.family != family {
            return Lookup::Missing;
        }
        if answer.addrs.is_empty() {
            return Lookup::Negative;
        }
        Lookup::Found(answer.clone())
    }

    /// The addresses kept for `name` and `port`, as they are kept, and
    /// whether for good, without aging them; for the tests that look in
    /// a multi's cache as C's look in its hash.
    #[cfg(test)]
    pub(crate) fn kept(&self, name: &[u8], port: u16) -> Option<(&[IpAddr], bool)> {
        let probe = Probe(name, port, Keeps::Addresses);
        let (key, entry) = self.entries.get_key_value(probe.key())?;
        Some((&key.answer.addrs, entry.permanent))
    }

    /// Keep `entry` under `key`, a key equal to it gone first.
    fn keep(&mut self, key: Key, entry: Entry) -> Result<(), OutOfMemory> {
        self.entries.try_reserve(1)?;
        // Room was made above: it does not grow.
        #[allow(clippy::disallowed_methods)]
        let replaced = self.entries.insert(key, entry);
        assert!(replaced.is_none(), "the key's entry was taken out first");
        Ok(())
    }

    /// Keep `answer` for its name and `port` from `now`, in place of what
    /// was kept for them; whether something was.
    fn put(
        &mut self,
        answer: TryArc<Answer>,
        port: u16,
        now: Instant,
        permanent: bool,
    ) -> Result<bool, OutOfMemory> {
        let replaced = self.remove(&answer.name, port);
        let says_no = answer.addrs.is_empty();
        let key = Key {
            answer,
            port,
            keeps: Keeps::Addresses,
        };
        self.keep(
            key,
            Entry {
                added: now,
                permanent,
                record: None,
                says_no,
            },
        )?;
        Ok(replaced)
    }

    /// Forget the addresses kept for `name` and `port`; whether some
    /// were.
    fn remove(&mut self, name: &[u8], port: u16) -> bool {
        let probe = Probe(name, port, Keeps::Addresses);
        self.entries.remove(probe.key()).is_some()
    }

    /// What is kept of the HTTPS record of `name` and `port`: an entry
    /// older than `max_age` is dropped, none for ever.
    fn lookup_https(
        &mut self,
        (name, port): (&[u8], u16),
        max_age: Option<Duration>,
        now: Instant,
    ) -> HttpsLookup {
        let probe = Probe(name, port, Keeps::Https);
        let Some(entry) = self.entries.get(probe.key()) else {
            return HttpsLookup::Missing;
        };
        if let Some(max_age) = max_age
            && entry.stale_at(now, max_age)
        {
            self.entries.remove(probe.key());
            return HttpsLookup::Stale;
        }
        HttpsLookup::Found(entry.record.clone())
    }

    /// Keep what `name` has of an HTTPS record on `port`, from `now`, in
    /// place of what was kept of it. The name is the answer of its
    /// addresses when they are kept, so the entry costs no more than its
    /// row.
    fn put_https(
        &mut self,
        name: &[u8],
        port: u16,
        record: Option<TryArc<HttpsRecord>>,
        negative: bool,
        now: Instant,
    ) -> Result<(), OutOfMemory> {
        let addresses = Probe(name, port, Keeps::Addresses);
        let answer = match self.entries.get_key_value(addresses.key()) {
            Some((key, _)) => key.answer.clone(),
            None => TryArc::try_new(Answer::new(name, Vec::new())?)?,
        };
        self.entries.remove(Probe(name, port, Keeps::Https).key());
        let key = Key {
            answer,
            port,
            keeps: Keeps::Https,
        };
        self.keep(
            key,
            Entry {
                added: now,
                permanent: false,
                record,
                says_no: negative,
            },
        )
    }

    /// Drop the entries older than `max_age` by `now`
    /// (`Curl_dnscache_prune`); while over the most kept, those over half
    /// the oldest's age. None keeps them for ever. Each entry's age is its
    /// own: the order they came in decides nothing.
    fn prune(&mut self, now: Instant, max_age: Option<Duration>) {
        self.prune_to(now, max_age, MAX_ENTRIES);
    }

    fn prune_to(&mut self, now: Instant, max_age: Option<Duration>, most: usize) {
        let Some(mut max_age) = max_age else {
            return;
        };
        loop {
            self.entries.retain(|_, e| !e.stale_at(now, max_age));
            if self.entries.len() <= most {
                return;
            }
            let oldest = self
                .entries
                .values()
                .filter(|e| !e.permanent)
                .map(|e| e.age_ms(now))
                .max()
                .unwrap_or_default();
            max_age = Duration::from_millis((oldest / 2).max(0).unsigned_abs());
            if max_age.is_zero() {
                return;
            }
        }
    }
}

impl Entry {
    fn stale_at(&self, now: Instant, max_age: Duration) -> bool {
        !self.permanent && self.age_ms(now) >= crate::time::millis(max_age)
    }

    /// How old the entry is by `now`, in milliseconds as C counts them:
    /// one saying the name does not exist, or has no HTTPS record, ages
    /// twice as fast (`dnscache_entry_is_stale`).
    fn age_ms(&self, now: Instant) -> i64 {
        let age = now.ms_since(self.added);
        if self.says_no {
            age.saturating_mul(2)
        } else {
            age
        }
    }
}

/// An entry of `CURLOPT_RESOLVE`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListEntry<'a> {
    /// `-NAME:PORT`: forget what is kept for them.
    Remove { name: &'a [u8], port: u16 },
    /// `[+]NAME:PORT:ADDRESS[,ADDRESS]...`: keep the addresses for them,
    /// for good unless `+` asks for the cache's timeout.
    Add {
        name: &'a [u8],
        port: u16,
        addrs: Vec<IpAddr>,
        permanent: bool,
        /// The addresses as given, as the trace shows them.
        given: &'a [u8],
    },
}

/// Why an entry of `CURLOPT_RESOLVE` was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BadEntry<'a> {
    /// It is not an entry; `illegal` is an address in it that is not one.
    Syntax {
        illegal: Option<&'a [u8]>,
    },
    OutOfMemory,
}

/// The longest address in brackets (`MAX_IPADR_LEN`).
const MAX_BRACKETED: usize = 46;

/// Read `line` as `Curl_loadhostpairs` reads it: an entry, or none for
/// one it passes over in silence.
pub(crate) fn parse_entry(line: &[u8]) -> Result<Option<ListEntry<'_>>, BadEntry<'_>> {
    let syntax = Err(BadEntry::Syntax { illegal: None });
    let mut s = Cursor(line);
    if s.single(b'-') {
        let name = if s.single(b'[') {
            match s.until(MAX_BRACKETED, b']') {
                Some(name) if s.single(b']') && s.single(b':') => name,
                _ => return Ok(None),
            }
        } else {
            match s.until(4096, b':') {
                Some(name) if s.single(b':') => name,
                _ => return Ok(None),
            }
        };
        return Ok(s.number().map(|port| ListEntry::Remove { name, port }));
    }
    let permanent = !s.single(b'+');
    let name = if s.single(b'[') {
        match s.until(MAX_BRACKETED, b']') {
            Some(name) if s.single(b']') => name,
            _ => return Ok(None),
        }
    } else {
        match s.until(4096, b':') {
            Some(name) => name,
            None => return Ok(None),
        }
    };
    let port = match (s.single(b':'), s.number(), s.single(b':')) {
        (true, Some(port), true) => port,
        _ => return syntax,
    };
    let given = s.0;
    let mut addrs = Vec::new();
    while !s.0.is_empty() {
        let target = if s.single(b'[') {
            match s.until(MAX_BRACKETED, b']') {
                Some(target) if s.single(b']') => target,
                _ => return syntax,
            }
        } else {
            match s.until(4096, b',') {
                Some(target) => target,
                // Nothing but a comma is passed over.
                None if s.single(b',') => continue,
                None => return syntax,
            }
        };
        if target.len() >= 64 {
            return syntax;
        }
        let Some(ip) = address(target) else {
            return Err(BadEntry::Syntax {
                illegal: Some(target),
            });
        };
        addrs
            .try_push(ip)
            .map_err(|OutOfMemory| BadEntry::OutOfMemory)?;
        if !s.single(b',') {
            break;
        }
    }
    if addrs.is_empty() {
        return syntax;
    }
    Ok(Some(ListEntry::Add {
        name,
        port,
        addrs,
        permanent,
        given,
    }))
}

/// `text` as an address, IPv4 dotted or IPv6 without brackets
/// (`Curl_str2addr`).
pub(crate) fn address(text: &[u8]) -> Option<IpAddr> {
    let text = std::str::from_utf8(text).ok()?;
    if let Ok(v4) = text.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    text.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

/// The rest of an entry, read as C's `curlx_str_*` read it.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    /// Past `b`, if it is next.
    fn single(&mut self, b: u8) -> bool {
        match self.0.split_first() {
            Some((&first, rest)) if first == b => {
                self.0 = rest;
                true
            }
            _ => false,
        }
    }

    /// The bytes up to `delim` or the end, at least one and at most
    /// `max`.
    fn until(&mut self, max: usize, delim: u8) -> Option<&'a [u8]> {
        let len = self
            .0
            .iter()
            .position(|&b| b == delim)
            .unwrap_or(self.0.len());
        if len == 0 || len > max {
            return None;
        }
        let (word, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(word)
    }

    /// A port: decimal digits, leading zeroes and all.
    fn number(&mut self) -> Option<u16> {
        let len = self.0.iter().take_while(|b| b.is_ascii_digit()).count();
        if len == 0 {
            return None;
        }
        let mut n: u32 = 0;
        for &d in &self.0[..len] {
            n = n * 10 + u32::from(d - b'0');
            if n > 0xffff {
                return None;
            }
        }
        self.0 = &self.0[len..];
        Some(u16::try_from(n).expect("at most 0xffff"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::{Clock as _, ManualClock};

    const MAX_AGE: Option<Duration> = Some(Duration::from_secs(60));

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// unit1608: eight addresses shuffled with the system's random bytes
    /// are put in another order within ten tries, as `dns_shuffle_addr`
    /// relinks C's list.
    #[test]
    fn unit1608_shuffle_reorders() {
        let given: Vec<IpAddr> = (1..=8).map(|n| ip(&format!("10.0.0.{n}"))).collect();
        let mut addrs = given.clone();
        let libraries = crate::libraries::Libraries::NONE;
        for _ in 0..10 {
            assert!(shuffle(&mut addrs, &mut |b| libraries.random(b).is_ok()).unwrap());
            if addrs != given {
                break;
            }
        }
        assert_ne!(addrs, given, "the addresses are not reordered");
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(sorted, given, "the same addresses");
    }

    /// The shuffle is C's Fisher-Yates: from the last place down, place
    /// `i` swapped with the one its own four random bytes pick among the
    /// first `i + 1`. Random bytes that cannot be had leave the order; a
    /// single address asks for none.
    #[test]
    fn a_shuffle_draws_each_place_as_c_does() {
        let (a, b, c) = (ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3"));
        let mut addrs = [a, b, c];
        let drawn: Vec<u8> = [7u32, 0, 4].iter().flat_map(|n| n.to_ne_bytes()).collect();
        let mut fill = |out: &mut [u8]| {
            out.copy_from_slice(&drawn);
            true
        };
        assert!(shuffle(&mut addrs, &mut fill).unwrap());
        // Place 2 with 4 % 3 = 1, then place 1 with 0 % 2 = 0.
        assert_eq!(addrs, [c, a, b]);
        assert!(shuffle(&mut addrs, &mut |_| false).unwrap());
        assert_eq!(addrs, [c, a, b], "no random bytes, no change");
        assert!(!shuffle(&mut [a], &mut |_| panic!("none drawn")).unwrap());
    }

    /// unit3271's names past what C's key holds: a name is found under
    /// the whole of it, in any case, never under a longer or shorter
    /// one that begins the same.
    #[test]
    fn unit3271_long_names_match_whole() {
        let now = ManualClock::new().unwrap().now();
        let long = vec![b'a'; 257];
        let mut cache = DnsCache::default();
        let answer = |name: &[u8]| TryArc::try_new(Answer::new(name, vec![ip("1.2.3.4")]).unwrap());
        cache
            .put(answer(&long[..255]).unwrap(), 80, now, false)
            .unwrap();
        let found = |cache: &mut DnsCache, name: &[u8]| {
            matches!(
                cache.lookup((name, 80), Family::Any, false, None, now),
                Lookup::Found(_)
            )
        };
        assert!(
            !found(&mut cache, &long),
            "a longer name is not a shorter one's"
        );
        let mut cache = DnsCache::default();
        cache.put(answer(&long).unwrap(), 80, now, false).unwrap();
        assert!(found(&mut cache, &long), "the whole long name");
        let mut upper = long.clone();
        upper[0] = b'A';
        assert!(found(&mut cache, &upper), "in any case");
        assert!(
            !found(&mut cache, &long[..255]),
            "a shorter name is not a longer one's"
        );
    }

    fn add<'a>(
        name: &'a [u8],
        port: u16,
        addrs: &[&str],
        permanent: bool,
        given: &'a [u8],
    ) -> ListEntry<'a> {
        ListEntry::Add {
            name,
            port,
            addrs: addrs.iter().map(|a| ip(a)).collect(),
            permanent,
            given,
        }
    }

    /// Entries read as `Curl_loadhostpairs` reads them.
    #[test]
    fn entries_parse_as_c_parses_them() {
        let ok = |line: &'static [u8]| parse_entry(line).unwrap().unwrap();
        assert_eq!(
            ok(b"example.com:80:127.0.0.1"),
            add(b"example.com", 80, &["127.0.0.1"], true, b"127.0.0.1")
        );
        assert_eq!(
            ok(b"+a:0080:[::1],,127.0.0.2"),
            add(b"a", 80, &["::1", "127.0.0.2"], false, b"[::1],,127.0.0.2")
        );
        assert_eq!(
            ok(b"[::1]:443:::1"),
            add(b"::1", 443, &["::1"], true, b"::1")
        );
        assert_eq!(
            ok(b"*:1:127.0.0.1"),
            add(b"*", 1, &["127.0.0.1"], true, b"127.0.0.1")
        );
        // What follows an address without a comma is not read.
        assert_eq!(ok(b"a:1:[::1]x"), add(b"a", 1, &["::1"], true, b"[::1]x"));
        assert_eq!(
            ok(b"-example.com:80"),
            ListEntry::Remove {
                name: b"example.com",
                port: 80
            }
        );
        assert_eq!(
            ok(b"-[::1]:8"),
            ListEntry::Remove {
                name: b"::1",
                port: 8
            }
        );
        // Passed over in silence.
        for skipped in [
            &b"-a:x"[..],
            b"-a",
            b":1:127.0.0.1",
            b"[::1:1:127.0.0.1",
            b"",
        ] {
            assert_eq!(parse_entry(skipped), Ok(None), "{skipped:?}");
        }
        // Refused.
        let syntax = Err(BadEntry::Syntax { illegal: None });
        for bad in [
            &b"a"[..],
            b"a:1",
            b"a:1:",
            b"a:65536:127.0.0.1",
            b"a:1:[::1",
            b"a:x:1.2.3.4",
        ] {
            assert_eq!(parse_entry(bad), syntax, "{bad:?}");
        }
        // The longest name and the highest port are read.
        let long = [&[b'a'; 4096][..], b":65535:127.0.0.1"].concat();
        assert!(matches!(
            parse_entry(&long),
            Ok(Some(ListEntry::Add { name, port: 65535, .. })) if name.len() == 4096
        ));
        let longer = [&[b'a'; 4097][..], b":1:127.0.0.1"].concat();
        assert_eq!(parse_entry(&longer), Ok(None));
        assert_eq!(
            parse_entry(b"a:1:127.0.0.1,example.com"),
            Err(BadEntry::Syntax {
                illegal: Some(b"example.com")
            })
        );
    }

    /// The cache's timeout may keep answers for ever, or not past the
    /// moment they were found; an answer that a name does not exist ages
    /// twice as fast (`dnscache_entry_is_stale`).
    #[test]
    fn the_cache_s_timeout_decides_what_is_stale() {
        let clock = ManualClock::new().unwrap();
        let now = clock.now();
        let answer = |name: &[u8], addrs: Vec<IpAddr>| {
            TryArc::try_new(Answer::new(name, addrs).unwrap()).unwrap()
        };
        let mut cache = DnsCache::default();
        cache
            .put(answer(b"a", vec![ip("1.2.3.4")]), 1, now, false)
            .unwrap();
        cache
            .put(answer(b"none", Vec::new()), 1, now, false)
            .unwrap();
        let mut look =
            |name: &[u8], max_age, at| cache.lookup((name, 1), Family::Any, false, max_age, at);
        let half = now.after(Duration::from_secs(30));
        assert!(matches!(look(b"a", MAX_AGE, half), Lookup::Found(_)));
        assert!(matches!(look(b"none", MAX_AGE, half), Lookup::Stale));
        let years = now.after(Duration::from_secs(1 << 30));
        assert!(matches!(look(b"a", None, years), Lookup::Found(_)));
        assert!(matches!(
            look(b"a", Some(Duration::ZERO), now),
            Lookup::Stale
        ));
        cache
            .put(answer(b"a", vec![ip("1.2.3.4")]), 1, now, false)
            .unwrap();
        cache.prune(years, None);
        assert!(matches!(
            cache.lookup((b"a", 1), Family::Any, false, MAX_AGE, now),
            Lookup::Found(_)
        ));
        cache.prune(now, Some(Duration::ZERO));
        assert!(matches!(
            cache.lookup((b"a", 1), Family::Any, false, MAX_AGE, now),
            Lookup::Missing
        ));
    }

    /// Over the most kept, the entries over half the oldest's age go, the
    /// permanent ones neither counted nor dropped.
    #[test]
    fn a_full_cache_drops_its_oldest_half() {
        let clock = ManualClock::new().unwrap();
        let start = clock.now();
        let answer =
            |name: &[u8]| TryArc::try_new(Answer::new(name, vec![ip("1.2.3.4")]).unwrap()).unwrap();
        let mut cache = DnsCache::default();
        let at = |s| start.after(Duration::from_secs(s));
        cache.put(answer(b"p"), 1, at(0), true).unwrap();
        cache.put(answer(b"a"), 1, at(60), false).unwrap();
        cache.put(answer(b"b"), 1, at(80), false).unwrap();
        cache.put(answer(b"c"), 1, at(90), false).unwrap();
        cache.prune_to(at(100), MAX_AGE, 2);
        let mut kept = |name: &[u8]| {
            matches!(
                cache.lookup((name, 1), Family::Any, false, None, at(100)),
                Lookup::Found(_)
            )
        };
        assert_eq!(
            [kept(b"p"), kept(b"a"), kept(b"b"), kept(b"c")],
            [true, false, false, true]
        );
    }

    /// A name's HTTPS record is kept apart from its addresses, by name,
    /// in any case, and port, and goes stale in half the cache's timeout,
    /// as an answer that says no does; it names the host with the
    /// addresses' answer when they are kept, and leaves them as they
    /// are.
    #[test]
    fn a_name_s_https_record_is_kept_apart_from_its_addresses() {
        let clock = ManualClock::new().unwrap();
        let now = clock.now();
        let mut cache = DnsCache::default();
        let addrs = TryArc::try_new(Answer::new(b"a.test", vec![ip("1.2.3.4")]).unwrap()).unwrap();
        cache.put(addrs.clone(), 443, now, false).unwrap();
        let https = |cache: &mut DnsCache, name: &[u8], port, at| {
            cache.lookup_https((name, port), MAX_AGE, at)
        };
        assert!(matches!(
            https(&mut cache, b"a.test", 443, now),
            HttpsLookup::Missing
        ));
        cache.put_https(b"a.test", 443, None, true, now).unwrap();
        assert_eq!(TryArc::count(&addrs), 3, "the addresses' answer");
        assert_eq!(
            https(&mut cache, b"A.TEST", 443, now),
            HttpsLookup::Found(None)
        );
        assert_eq!(https(&mut cache, b"a.test", 80, now), HttpsLookup::Missing);
        match cache.lookup((b"a.test", 443), Family::Any, false, MAX_AGE, now) {
            Lookup::Found(found) => assert_eq!(found.addrs(), [ip("1.2.3.4")]),
            _ => panic!("the addresses stay"),
        }
        // Kept again, it replaces what was kept.
        cache.put_https(b"a.test", 443, None, true, now).unwrap();
        assert_eq!(TryArc::count(&addrs), 3);
        let half = now.after(Duration::from_secs(30));
        assert_eq!(https(&mut cache, b"a.test", 443, half), HttpsLookup::Stale);
        assert_eq!(
            https(&mut cache, b"a.test", 443, half),
            HttpsLookup::Missing
        );
        assert!(matches!(
            cache.lookup((b"a.test", 443), Family::Any, false, MAX_AGE, half),
            Lookup::Found(_)
        ));
        // A name with no addresses kept has its record kept alone, and
        // forgetting addresses leaves it.
        cache.put_https(b"b.test", 443, None, true, now).unwrap();
        assert!(!cache.remove(b"b.test", 443));
        assert_eq!(
            https(&mut cache, b"b.test", 443, now),
            HttpsLookup::Found(None)
        );
        assert!(matches!(
            cache.lookup((b"b.test", 443), Family::Any, false, MAX_AGE, now),
            Lookup::Missing
        ));
    }

    /// The cache keeps an answer by name, in any case, and port; a
    /// wildcard answers for any name; an entry not given for good goes
    /// stale after the cache's timeout.
    #[test]
    fn the_cache_keeps_answers_until_they_go_stale() {
        let clock = ManualClock::new().unwrap();
        let now = clock.now();
        let answer =
            |name: &[u8]| TryArc::try_new(Answer::new(name, vec![ip("1.2.3.4")]).unwrap()).unwrap();
        let mut cache = DnsCache::default();
        assert!(!cache.put(answer(b"Example.com"), 80, now, false).unwrap());
        assert!(matches!(
            cache.lookup((b"example.COM", 80), Family::Any, false, MAX_AGE, now),
            Lookup::Found(_)
        ));
        assert!(matches!(
            cache.lookup((b"example.com", 81), Family::Any, false, MAX_AGE, now),
            Lookup::Missing
        ));
        assert!(
            cache.put(answer(b"example.com"), 80, now, false).unwrap(),
            "replaced"
        );
        assert!(!cache.put(answer(b"*"), 81, now, true).unwrap());
        assert!(matches!(
            cache.lookup((b"other", 81), Family::Any, false, MAX_AGE, now),
            Lookup::Missing
        ));
        let Lookup::Found(any) = cache.lookup((b"other", 81), Family::Any, true, MAX_AGE, now)
        else {
            panic!("the wildcard");
        };
        assert_eq!(any.name(), b"*");
        let later = now.after(MAX_AGE.unwrap());
        assert!(matches!(
            cache.lookup((b"example.com", 80), Family::Any, false, MAX_AGE, later),
            Lookup::Stale
        ));
        assert!(matches!(
            cache.lookup((b"example.com", 80), Family::Any, false, MAX_AGE, later),
            Lookup::Missing
        ));
        assert!(
            matches!(
                cache.lookup((b"*", 81), Family::Any, false, MAX_AGE, later),
                Lookup::Found(_)
            ),
            "for good"
        );
        assert!(cache.put(answer(b"a"), 1, now, false).is_ok());
        cache.prune(later, MAX_AGE);
        assert!(
            matches!(
                cache.lookup((b"a", 1), Family::Any, false, MAX_AGE, now),
                Lookup::Missing
            ),
            "pruned"
        );
        assert!(cache.remove(b"*", 81));
        assert!(!cache.remove(b"*", 81));
    }

    /// A wildcard answers only what no entry of the name's own does: an
    /// entry of the name, even one not for the family asked, goes first;
    /// it is the port's alone; a stale one goes as it is looked at; and
    /// an HTTPS record is never the wildcard's.
    #[test]
    fn a_wildcard_answers_only_for_names_without_an_entry() {
        let clock = ManualClock::new().unwrap();
        let now = clock.now();
        let answer = |name: &[u8], ip_: &str, family| {
            TryArc::try_new(Answer::of(name, vec![ip(ip_)], family).unwrap()).unwrap()
        };
        let mut cache = DnsCache::default();
        cache
            .put(answer(b"*", "1.1.1.1", Family::Any), 80, now, false)
            .unwrap();
        cache
            .put(answer(b"Own.test", "2.2.2.2", Family::Any), 80, now, false)
            .unwrap();
        cache
            .put(answer(b"v6.test", "::1", Family::V6), 80, now, false)
            .unwrap();
        let mut look = |name: &[u8], port, family, at| match cache.lookup(
            (name, port),
            family,
            true,
            MAX_AGE,
            at,
        ) {
            Lookup::Found(a) => Some(a.addrs()[0]),
            Lookup::Missing => None,
            other => panic!("{other:?}"),
        };
        assert_eq!(look(b"OWN.test", 80, Family::Any, now), Some(ip("2.2.2.2")));
        assert_eq!(look(b"other", 80, Family::Any, now), Some(ip("1.1.1.1")));
        assert_eq!(look(b"other", 81, Family::Any, now), None, "the port's");
        assert_eq!(
            look(b"v6.test", 80, Family::V4, now),
            None,
            "its own entry, not the wildcard"
        );
        cache.put_https(b"*", 80, None, false, now).unwrap();
        assert_eq!(
            cache.lookup_https((b"other", 80), MAX_AGE, now),
            HttpsLookup::Missing
        );
        let later = now.after(MAX_AGE.unwrap());
        assert!(matches!(
            cache.lookup((b"other", 80), Family::Any, true, MAX_AGE, later),
            Lookup::Stale
        ));
        assert!(!cache.remove(b"*", 80), "gone as it went stale");
        assert!(cache.remove(b"own.TEST", 80));
    }

    #[test]
    fn answers_of_addresses_are_not_resolved() {
        let answer = |name: &[u8]| Answer::new(name, vec![ip("::1")]).unwrap();
        assert!(!answer(b"::1").resolved() && !answer(b"127.0.0.1").resolved());
        assert!(answer(b"localhost").resolved() && answer(b"*").resolved());
    }

    const WORDS: &[&[u8]] = &[
        b"-",
        b"+",
        b"[",
        b"]",
        b":",
        b",",
        b"host",
        b"example.com",
        b"80",
        b"65535",
        b"65536",
        b"1.2.3.4",
        b"::1",
        b"fe80::1%eth0",
        b"127.0.0.1",
        b"999.1.1.1",
        b" ",
    ];
    const ENTRIES: &[&[u8]] = &[
        b"host:80:1.2.3.4,[::1],5.6.7.8",
        b"+[::1]:443:::1",
        b"-host:80",
        b"-[::1]:443",
        b"example.com:8080:,,1.2.3.4",
    ];

    proptest::proptest! {
        #![proptest_config(crate::untrusted::config(512))]

        /// Any line is an entry, none, or refused; an entry keeps a
        /// name C's buffers hold, and at least one address.
        #[test]
        fn any_line_is_an_entry_or_refused(line in crate::untrusted::input(WORDS, ENTRIES, 12)) {
            match parse_entry(&line) {
                Ok(Some(ListEntry::Add { name, addrs, .. })) => {
                    proptest::prop_assert!(!name.is_empty() && name.len() <= 4096);
                    proptest::prop_assert!(!addrs.is_empty());
                }
                Ok(Some(ListEntry::Remove { name, .. })) => {
                    proptest::prop_assert!(!name.is_empty() && name.len() <= 4096);
                }
                Ok(None) | Err(BadEntry::Syntax { .. }) => {}
                Err(BadEntry::OutOfMemory) => proptest::prop_assert!(false, "no allocation fails"),
            }
        }
    }
}
