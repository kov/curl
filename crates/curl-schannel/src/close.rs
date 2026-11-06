//! The goodbye's record on its way (`schannel_shutdown`'s
//! `shutdown_token`): kept, with how much of it went, until it is sent
//! whole or its send fails, and released once, by its owner, whatever
//! ends it. Nothing of Windows is in it, so it is tested everywhere.

/// What a record to send is made of.
pub(crate) trait Record {
    fn bytes(&self) -> &[u8];
}

/// A record being sent: its bytes, and how many of them went.
#[derive(Debug)]
pub(crate) struct Pending<T> {
    record: T,
    sent: usize,
}

/// Where a send of the rest of a record left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flushed {
    /// All of it went.
    Done,
    /// Some or none of it went: the rest waits for the connection to take
    /// more.
    Waiting,
    /// The send failed.
    Failed,
}

impl<T: Record> Pending<T> {
    pub(crate) fn new(record: T) -> Pending<T> {
        Pending { record, sent: 0 }
    }

    /// Send what is left of the record, from where the last send stopped:
    /// `send` takes the bytes and says how many it took, `None` for none
    /// as the connection would block, or that it failed.
    pub(crate) fn flush<E>(
        &mut self,
        send: impl FnOnce(&[u8]) -> Result<Option<usize>, E>,
    ) -> Flushed {
        let left = &self.record.bytes()[self.sent..];
        if left.is_empty() {
            return Flushed::Done;
        }
        match send(left) {
            Ok(Some(n)) if n < left.len() => {
                self.sent += n;
                Flushed::Waiting
            }
            Ok(Some(n)) => {
                assert_eq!(n, left.len(), "a send takes no more than it is given");
                self.sent += n;
                Flushed::Done
            }
            Ok(None) => Flushed::Waiting,
            Err(_) => Flushed::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    /// C's token, counting its releases.
    struct Token<'a>(&'a Cell<u32>);

    const TOKEN: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    impl Record for Token<'_> {
        fn bytes(&self) -> &[u8] {
            &TOKEN
        }
    }

    impl Drop for Token<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    /// C's lower filter: blocks as often as told, takes `first` bytes of
    /// its first write that takes any, then all; or fails. Each send must
    /// start where the last stopped.
    struct Lower {
        accepted: Rc<Cell<usize>>,
        blocks: u32,
        first: Option<usize>,
        fail: bool,
        sends: u32,
    }

    impl Lower {
        fn send(&mut self, b: &[u8]) -> Result<Option<usize>, ()> {
            self.sends += 1;
            let at = self.accepted.get();
            assert_eq!(b, &TOKEN[at..], "a retry begins at the unsent offset");
            if self.blocks > 0 {
                self.blocks -= 1;
                return Ok(None);
            }
            if self.fail {
                return Err(());
            }
            let n = self.first.take().unwrap_or(b.len());
            self.accepted.set(at + n);
            Ok(Some(n))
        }
    }

    /// unit4782: a goodbye whose send blocks twice (0), takes one byte
    /// (1), or blocks and is then closed (2) waits with its token kept,
    /// sends the rest from where it stopped, the record delivered once;
    /// a send that fails (3, 4) ends it. The token is released exactly
    /// once each way, when its owner drops it. C's choices after a
    /// failed send (none if the peer had closed, 4) or a token that
    /// could not be made (5) are the session's, on Windows alone.
    #[test]
    fn unit4782_goodbye_resent_from_its_offset() {
        for scenario in 0..5 {
            let freed = Cell::new(0);
            let accepted = Rc::new(Cell::new(0));
            let mut lower = Lower {
                accepted: accepted.clone(),
                blocks: if matches!(scenario, 0 | 2) { 2 } else { 0 },
                first: (scenario == 1).then_some(1),
                fail: matches!(scenario, 3 | 4),
                sends: 0,
            };
            let mut pending = Some(Pending::new(Token(&freed)));
            let first = pending.as_mut().unwrap().flush(|b| lower.send(b));
            if scenario < 3 {
                assert_eq!(first, Flushed::Waiting, "scenario {scenario}");
                assert_eq!(freed.get(), 0, "the pending token is kept");
                if scenario != 2 {
                    let mut last = first;
                    for _ in 0..3 {
                        if last == Flushed::Done {
                            break;
                        }
                        last = pending.as_mut().unwrap().flush(|b| lower.send(b));
                    }
                    assert_eq!(last, Flushed::Done, "scenario {scenario}");
                    assert_eq!(accepted.get(), TOKEN.len(), "delivered once");
                    pending = None;
                    assert_eq!(freed.get(), 1, "released once it went");
                }
            } else {
                assert_eq!(first, Flushed::Failed, "scenario {scenario}");
                assert_eq!(lower.sends, 1, "no retry");
            }
            drop(pending);
            assert_eq!(freed.get(), 1, "closed, the token is released once");
        }
    }
}
