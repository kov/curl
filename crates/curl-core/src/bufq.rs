//! Buffers cut into chunks as C's `bufq` cuts them (`lib/bufq.c`): what
//! one look at the front gives is what is left of its chunk, a chunk
//! begins afresh once the queue is empty, and the queue is full once its
//! chunks are. A write always fits (`BUFQ_OPT_SOFT_LIMIT`), as a
//! WebSocket's buffers take it; a fill takes only what the chunks have
//! room for (`BUFQ_OPT_NONE`), as HTTP/2's do. C sends and hands on what
//! it buffers a chunk at a time, so the chunks decide the sizes of the
//! sends and of the writes the application sees.

use std::num::NonZeroUsize;

use curl_alloc::{OutOfMemory, TryVec as _};

/// What a queue's bytes were passed on to took of them (`Curl_bufq_writer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Passed<E> {
    /// This many, from the first.
    Bytes(NonZeroUsize),
    /// None now (`CURLE_AGAIN`).
    Blocked,
    Failed(E),
}

/// What a queue passes its bytes on to.
pub(crate) type PassTo<'a, E> = dyn FnMut(&[u8]) -> Passed<E> + 'a;

/// Bytes held in chunks of `chunk` bytes, full at `max` of them.
#[derive(Debug)]
pub(crate) struct ChunkQueue {
    /// What is held, from `taken` on: what is taken is let go once it is
    /// at least as much as what is left, each byte moved at most once
    /// for every byte taken.
    bytes: Vec<u8>,
    taken: usize,
    /// Where the first byte held is in its chunk.
    at: usize,
    chunk: usize,
    max: usize,
}

impl ChunkQueue {
    /// Empty, with chunks of `chunk` bytes, full at `max` of them; a
    /// chunk is at least a byte.
    pub(crate) fn new(chunk: usize, max: usize) -> ChunkQueue {
        ChunkQueue {
            bytes: Vec::new(),
            taken: 0,
            at: 0,
            chunk: chunk.max(1),
            max,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len() - self.taken
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn held(&self) -> &[u8] {
        &self.bytes[self.taken..]
    }

    /// The size of its chunks.
    pub(crate) fn chunk_size(&self) -> usize {
        self.chunk
    }

    /// Whether its chunks are all in use and the last is full
    /// (`Curl_bufq_is_full`).
    pub(crate) fn is_full(&self) -> bool {
        !self.is_empty() && self.at + self.len() >= self.chunk.saturating_mul(self.max)
    }

    /// What is left of the first chunk (`Curl_bufq_peek`).
    pub(crate) fn peek(&self) -> &[u8] {
        let n = self.len().min(self.chunk - self.at);
        &self.held()[..n]
    }

    /// The first `n` bytes held are taken (`Curl_bufq_skip`).
    pub(crate) fn skip(&mut self, n: usize) {
        assert!(n <= self.len(), "only what is held is taken");
        self.taken += n;
        if self.is_empty() {
            self.reset();
        } else {
            self.at = (self.at + n) % self.chunk;
            if self.taken >= self.len() {
                self.bytes.drain(..self.taken);
                self.taken = 0;
            }
        }
    }

    /// Everything held is let go (`Curl_bufq_reset`).
    pub(crate) fn reset(&mut self) {
        self.bytes.clear();
        self.taken = 0;
        self.at = 0;
    }

    /// `more` put after what is held, all of it.
    pub(crate) fn write(&mut self, more: &[u8]) -> Result<(), OutOfMemory> {
        self.bytes.try_extend_from_slice(more)
    }

    /// What of `more` the chunks have room for put after what is held,
    /// the rest left (`Curl_bufq_write` with a hard limit): how much. A
    /// chunk read from is not written to again until it is empty.
    pub(crate) fn fill(&mut self, more: &[u8]) -> Result<usize, OutOfMemory> {
        let n = more.len().min(self.room());
        self.bytes.try_extend_from_slice(&more[..n])?;
        Ok(n)
    }

    /// The bytes the chunks have room for: all of them once the queue is
    /// empty, else what the first's read part and what is held leave.
    pub(crate) fn room(&self) -> usize {
        let all = self.chunk.saturating_mul(self.max);
        if self.is_empty() {
            all
        } else {
            all.saturating_sub(self.at + self.len())
        }
    }

    /// One byte put after what is held.
    pub(crate) fn push(&mut self, byte: u8) -> Result<(), OutOfMemory> {
        self.bytes.try_push(byte)
    }

    /// The room left in the last chunk, or a whole chunk's if it is full
    /// or there is none: what one read into the queue may fill
    /// (`Curl_bufq_sipn`).
    pub(crate) fn tail_room(&self) -> usize {
        match (self.at + self.len()) % self.chunk {
            0 => self.chunk,
            used => self.chunk - used,
        }
    }

    /// Up to `buf`'s length taken out into it (`Curl_bufq_read`): how many.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.len());
        buf[..n].copy_from_slice(&self.held()[..n]);
        self.skip(n);
        n
    }

    /// What it holds passed on to `to`, the rest of its first chunk each
    /// time, until it is empty or `to` takes none now (`Curl_bufq_pass`):
    /// how much went, none if `to` would block at once.
    pub(crate) fn pass<E>(&mut self, to: &mut PassTo<'_, E>) -> Result<usize, E> {
        let mut went = 0;
        while !self.is_empty() {
            match to(self.peek()) {
                Passed::Bytes(n) => {
                    self.skip(n.get());
                    went += n.get();
                }
                Passed::Blocked => break,
                Passed::Failed(e) => return Err(e),
            }
        }
        Ok(went)
    }

    /// What of `more` its chunks have room for put after what is held,
    /// its chunks passed on to `to` each time they are full and more is to
    /// go, as far as `to` takes them (`Curl_bufq_write_pass`); with no
    /// `to`, as far as there is room (`Curl_bufq_write`). How much of
    /// `more` went in, none if `to` would block at once.
    pub(crate) fn write_pass<E: From<OutOfMemory>>(
        &mut self,
        mut more: &[u8],
        mut to: Option<&mut PassTo<'_, E>>,
    ) -> Result<usize, E> {
        let mut n = 0;
        while !more.is_empty() {
            if self.is_full() {
                let Some(to) = to.as_deref_mut() else {
                    break;
                };
                if self.pass(to)? == 0 {
                    break;
                }
            }
            let k = self.fill(more)?;
            if k == 0 {
                break;
            }
            more = &more[k..];
            n += k;
        }
        Ok(n)
    }

    /// The bytes it keeps room for, held or not.
    #[cfg(test)]
    pub(crate) fn stored(&self) -> usize {
        self.bytes.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A look at the front stops at its chunk's end, and a chunk starts
    /// afresh once the queue is empty.
    #[test]
    fn a_peek_ends_with_its_chunk() {
        let mut q = ChunkQueue::new(4, 2);
        q.write(b"abcdef").unwrap();
        assert_eq!(q.peek(), b"abcd");
        q.skip(3);
        assert_eq!(q.peek(), b"d");
        q.skip(1);
        assert_eq!(q.peek(), b"ef");
        q.write(b"ghij").unwrap();
        assert_eq!(q.peek(), b"efgh");
        q.skip(6);
        assert!(q.is_empty());
        q.write(b"klmnop").unwrap();
        assert_eq!(q.peek(), b"klmn");
    }

    /// Full once its chunks are in use and the last is full; a write
    /// still fits.
    #[test]
    fn full_at_its_chunks() {
        let mut q = ChunkQueue::new(4, 2);
        assert!(!q.is_full());
        q.write(b"abcdefg").unwrap();
        assert!(!q.is_full());
        assert_eq!(q.tail_room(), 1);
        q.push(b'h').unwrap();
        assert!(q.is_full());
        assert_eq!(q.tail_room(), 4);
        q.write(b"ij").unwrap();
        assert!(q.is_full());
        q.skip(4);
        assert!(!q.is_full());
        let mut out = [0u8; 3];
        assert_eq!(q.read(&mut out), 3);
        assert_eq!(&out, b"efg");
        q.reset();
        assert!(q.is_empty());
        assert_eq!(q.tail_room(), 4);
        q.push(b'a').unwrap();
        assert_eq!(q.tail_room(), 3, "what the last chunk has left");
    }

    /// A fill takes what its chunks have room for and no more; a chunk
    /// read from takes nothing again until it is empty, as C's chunk
    /// takes nothing past its end however much of it was read.
    #[test]
    fn a_fill_takes_what_the_chunks_have_room_for() {
        let mut q = ChunkQueue::new(4, 2);
        assert_eq!(q.room(), 8);
        assert_eq!(q.fill(b"abcdefghij").unwrap(), 8);
        assert_eq!(q.room(), 0);
        assert_eq!(q.fill(b"k").unwrap(), 0);
        let mut out = [0u8; 3];
        assert_eq!(q.read(&mut out), 3);
        assert_eq!(q.room(), 0, "the first chunk is not written again");
        assert_eq!(q.read(&mut out[..1]), 1);
        assert_eq!(q.room(), 4, "the first chunk, emptied, is free");
        assert_eq!(q.fill(b"klmnop").unwrap(), 4);
        assert_eq!(q.peek(), b"efgh");
        let mut all = [0u8; 8];
        assert_eq!(q.read(&mut all), 8);
        assert_eq!(&all, b"efghklmn");
        assert_eq!(q.room(), 8, "an empty queue starts afresh");
        assert_eq!(q.fill(b"ab").unwrap(), 2);
        assert_eq!(q.read(&mut out[..1]), 1);
        assert_eq!(
            q.room(),
            6,
            "a part read of the last chunk is not taken again"
        );
    }

    /// unit2601: an empty queue gives nothing to a read, and for each of
    /// `check_bufq`'s queues, a queue with a hard limit takes writes until
    /// it holds its chunks' worth exactly and gives all of it back to
    /// reads; writes and reads in turn keep what is held what went in less
    /// what came out; and a queue with a soft limit takes every write
    /// whole, full or not, and gives back what went in.
    ///
    /// C's spare chunks, its chunk pool (`pool_spares`) and
    /// `BUFQ_OPT_NO_SPARES` have no counterpart: the queue holds its bytes
    /// in one buffer, not in chunks it allocates and keeps, so each call's
    /// queue is checked the same whatever its spares. So have C's head,
    /// tail and spare pointers, checked after init and once emptied: an
    /// emptied queue starts afresh (`a_peek_ends_with_its_chunk`).
    #[test]
    fn unit2601_bufq() {
        const FILE: &str = "tests/unit/unit2601.c";
        let num = |v: &crate::c_source::Value| {
            usize::try_from(crate::c_source::constant(FILE, v.word())).unwrap()
        };
        let mut buf = [0u8; 16 * 1024];
        let mut q = ChunkQueue::new(8 * 1024, 12);
        assert_eq!(q.read(&mut buf[..128]), 0, "read empty");

        let calls = crate::c_source::calls(FILE, "check_bufq");
        assert_eq!(calls.len(), 13);
        // The data written, numbered so that what comes out is checked
        // to be what went in, in order.
        let data: Vec<u8> = (0..32 * 1024usize)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        for call in &calls {
            let [_spares, chunk, max, wsize, rsize, _opts] = &call[..] else {
                panic!("check_bufq's arguments: {call:?}");
            };
            let (chunk, max, wsize, rsize) = (num(chunk), num(max), num(wsize), num(rsize));
            let what = format!("chunk {chunk}, max {max}, write {wsize}, read {rsize}");
            let max_len = chunk * max;
            let mut q = ChunkQueue::new(chunk, max);
            assert_eq!(q.chunk_size(), chunk);
            assert!(q.is_empty(), "{what}");
            assert!(q.fill(&data[..wsize]).unwrap() <= wsize, "{what}");

            // Write the emptied queue full.
            q.reset();
            let mut written = Vec::new();
            while !q.is_full() {
                let n = q.fill(&data[..wsize]).unwrap();
                assert_ne!(n, 0, "{what}: no room before full");
                written.extend_from_slice(&data[..n]);
            }
            assert_eq!(written.len(), max_len, "{what}: full but written wrong");
            // Read it empty.
            let mut read = Vec::new();
            while !q.is_empty() {
                let n = q.read(&mut buf[..rsize]);
                read.extend_from_slice(&buf[..n]);
            }
            assert_eq!(read, written, "{what}: emptied but read wrong");

            let (mut put, mut got) = (0, 0);
            for _ in 0..1000 {
                put += q.fill(&data[..wsize]).unwrap();
                got += q.read(&mut buf[..rsize]);
                assert_eq!(q.len(), put - got, "{what}: write and read in turn");
                assert!(q.len() <= max_len, "{what}: past the hard limit");
            }

            // BUFQ_OPT_SOFT_LIMIT: every write is taken whole.
            let mut q = ChunkQueue::new(chunk, max);
            let mut written = Vec::new();
            while !q.is_full() {
                q.write(&data[..wsize]).unwrap();
                written.extend_from_slice(&data[..wsize]);
            }
            assert!(written.len() >= max_len, "{what}: full but written wrong");
            q.write(&data[..wsize]).unwrap();
            written.extend_from_slice(&data[..wsize]);
            let mut read = Vec::new();
            while !q.is_empty() {
                let n = q.read(&mut buf[..rsize]);
                assert_ne!(n, 0, "{what}");
                read.extend_from_slice(&buf[..n]);
            }
            assert_eq!(read, written, "{what}: not the same out as in");
        }
    }
}
