//! The buffers a WebSocket reads frames from and writes them into, cut
//! into chunks as C's `bufq` cuts them (`lib/bufq.c`): what one look at
//! the front gives is what is left of its chunk, a chunk begins afresh
//! once the queue is empty, and the queue is full once its chunks are,
//! though a write always fits (`BUFQ_OPT_SOFT_LIMIT`). C sends a frame's
//! bytes and hands a frame's payload on a chunk at a time, so the chunks
//! decide the sizes of the sends and of the writes the application sees.

use curl_alloc::{OutOfMemory, TryVec as _};

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
}
