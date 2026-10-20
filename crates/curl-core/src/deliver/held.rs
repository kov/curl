//! Output held while a write handler has paused the transfer, kept in the
//! order it came and replayed in that order (`cw_out_append`).

use std::ops::Range;

use curl_alloc::TryVec;

use crate::error::ErrorKind;
use crate::handler::HeaderOrigin;

/// The most output held at once (`DYN_PAUSE_BUFFER`).
pub(crate) const MAX_HELD: usize = 64 * 1024 * 1024;

/// What a held entry goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutKind {
    /// The write handler: body, and header lines included in it.
    Body,
    /// The header handler, one line per entry.
    Header(HeaderOrigin),
}

/// Held output: ranges into one buffer, each run of body one entry, each
/// header line its own, so appending is O(1).
#[derive(Debug, Default)]
pub(crate) struct HeldOutput {
    bytes: Vec<u8>,
    entries: Vec<Entry>,
    /// The first entry not yet delivered.
    first: usize,
    /// Bytes not yet delivered.
    held: usize,
}

#[derive(Debug)]
struct Entry {
    kind: OutKind,
    range: Range<usize>,
}

impl HeldOutput {
    /// Hold `data` after what is held; body joins body held just before
    /// it. Past `MAX_HELD` is TooLarge ("pause buffer not large enough").
    pub(crate) fn append(&mut self, kind: OutKind, data: &[u8]) -> Result<(), ErrorKind> {
        if self.held + data.len() > MAX_HELD {
            return Err(ErrorKind::TooLarge);
        }
        let start = self.bytes.len();
        let joins = kind == OutKind::Body
            && self.entries[self.first..]
                .last()
                .is_some_and(|e| e.kind == OutKind::Body);
        if !joins {
            self.entries
                .try_reserve(1)
                .map_err(|_| ErrorKind::OutOfMemory)?;
        }
        self.bytes
            .try_extend_from_slice(data)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let end = self.bytes.len();
        match self.entries.last_mut() {
            Some(last) if joins => last.range.end = end,
            _ => self
                .entries
                .try_push(Entry {
                    kind,
                    range: start..end,
                })
                .expect("reserved"),
        }
        self.held += data.len();
        Ok(())
    }

    /// The entry to deliver next.
    pub(crate) fn front(&self) -> Option<(OutKind, &[u8])> {
        let e = self.entries.get(self.first)?;
        Some((e.kind, &self.bytes[e.range.clone()]))
    }

    /// `n` bytes of the front entry were delivered.
    pub(crate) fn consume(&mut self, n: usize) {
        let e = &mut self.entries[self.first];
        assert!(n <= e.range.len(), "consumed no more than the entry");
        e.range.start += n;
        self.held -= n;
        if e.range.is_empty() {
            self.first += 1;
        }
        if self.first == self.entries.len() {
            self.bytes.clear();
            self.entries.clear();
            self.first = 0;
        } else if self.entries[self.first].range.start > MAX_HELD {
            self.compact();
        }
    }

    /// Drop what was delivered, so a buffer that never empties stays
    /// bounded. Moves, never allocates.
    fn compact(&mut self) {
        let dead = self.entries[self.first].range.start;
        self.bytes.copy_within(dead.., 0);
        self.bytes.truncate(self.bytes.len() - dead);
        self.entries.drain(..self.first);
        self.first = 0;
        for e in &mut self.entries {
            e.range.start -= dead;
            e.range.end -= dead;
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.held == 0
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: OutKind = OutKind::Header(HeaderOrigin::Header);

    fn drain(h: &mut HeldOutput) -> Vec<(OutKind, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some((kind, bytes)) = h.front() {
            let bytes = bytes.to_vec();
            h.consume(bytes.len());
            out.push((kind, bytes));
        }
        out
    }

    #[test]
    fn body_joins_body_and_each_header_line_stands_alone() {
        let mut h = HeldOutput::default();
        h.append(OutKind::Body, b"ab").unwrap();
        h.append(OutKind::Body, b"cd").unwrap();
        h.append(H, b"x: 1\r\n").unwrap();
        h.append(H, b"y: 2\r\n").unwrap();
        h.append(OutKind::Body, b"ef").unwrap();
        assert_eq!(
            drain(&mut h),
            [
                (OutKind::Body, b"abcd".to_vec()),
                (H, b"x: 1\r\n".to_vec()),
                (H, b"y: 2\r\n".to_vec()),
                (OutKind::Body, b"ef".to_vec()),
            ]
        );
        assert!(h.is_empty());
    }

    #[test]
    fn a_partly_delivered_entry_goes_on_from_where_it_stopped() {
        let mut h = HeldOutput::default();
        h.append(OutKind::Body, b"abcdef").unwrap();
        h.consume(2);
        assert_eq!(h.front(), Some((OutKind::Body, &b"cdef"[..])));
        assert_eq!(h.held(), 4);
        h.append(OutKind::Body, b"gh").unwrap();
        assert_eq!(h.front(), Some((OutKind::Body, &b"cdefgh"[..])));
    }

    #[test]
    fn at_most_64_mib_is_held_counting_what_is_left() {
        let mut h = HeldOutput::default();
        let big = vec![0u8; MAX_HELD - 10];
        h.append(OutKind::Body, &big).unwrap();
        assert_eq!(h.append(H, &[0; 11]), Err(ErrorKind::TooLarge));
        h.append(H, &[0; 10]).unwrap();
        h.consume(100);
        h.append(OutKind::Body, &[0; 100]).unwrap();
        assert_eq!(h.append(OutKind::Body, &[0; 1]), Err(ErrorKind::TooLarge));
    }

    /// Delivered bytes stay put until more than the cap has gone, so a
    /// replay does not move what is left at every entry.
    #[test]
    fn delivered_bytes_are_dropped_only_past_the_cap() {
        let mut h = HeldOutput::default();
        h.append(H, b"x: 1\r\n").unwrap();
        h.append(OutKind::Body, b"abc").unwrap();
        h.consume(6);
        assert_eq!((h.first, h.entries.len(), h.bytes.len()), (1, 2, 9));
    }

    /// Output that never empties stays bounded: what was delivered goes.
    #[test]
    fn what_was_delivered_does_not_pile_up() {
        let mut h = HeldOutput::default();
        let chunk = vec![7u8; 1 << 20];
        h.append(H, b"x: 1\r\n").unwrap();
        h.consume(6);
        h.append(OutKind::Body, &chunk).unwrap();
        for _ in 0..200 {
            h.append(H, b"y: 2\r\n").unwrap();
            h.append(OutKind::Body, &chunk).unwrap();
            let (_, front) = h.front().unwrap();
            let n = front.len();
            h.consume(n);
            let (_, front) = h.front().unwrap();
            let n = front.len();
            h.consume(n);
            assert!(h.bytes.len() <= 2 * MAX_HELD + (2 << 20));
        }
        assert_eq!(h.held(), 1 << 20);
        assert_eq!(h.front(), Some((OutKind::Body, &chunk[..])));
    }
}
