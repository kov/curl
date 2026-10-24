//! Whether a transfer's directions are paused (`curl_easy_pause`,
//! `CURL_WRITEFUNC_PAUSE`, `CURL_READFUNC_PAUSE`).

/// What the application wants paused: every direction not named runs
/// (`CURLPAUSE_*`, which set the state rather than change it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PauseRequest {
    pub recv: bool,
    pub send: bool,
}

impl PauseRequest {
    /// Nothing paused (`CURLPAUSE_CONT`).
    pub const CONT: PauseRequest = PauseRequest {
        recv: false,
        send: false,
    };
    pub const RECV: PauseRequest = PauseRequest {
        recv: true,
        send: false,
    };
    pub const SEND: PauseRequest = PauseRequest {
        recv: false,
        send: true,
    };
    pub const ALL: PauseRequest = PauseRequest {
        recv: true,
        send: true,
    };
}

/// A transfer's pause, one value per direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pause {
    pub(crate) recv: RecvPause,
    pub(crate) send: SendPause,
    /// How many times a pause a read handler asked for was lifted.
    lifts: Lifts,
}

/// A count of the lifts of a transfer's asked-for send pauses: a reader
/// that keeps such a pause keeps the count it was asked at, and the pause
/// holds while the count is the same (`mime_unpause`). A lift needs no
/// reader to hear of it, so none can miss it. The count wraps: a kept
/// pause is checked by the next read, and the next asked-for pause comes
/// from a read, so at most one lift falls between the keeping and the
/// check. Kept small, as every transfer carries it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Lifts(u16);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum RecvPause {
    #[default]
    Running,
    /// Paused by the application from outside a write: nothing more is
    /// read, but what is being delivered still is.
    Stopped,
    /// A write handler asked for a pause: delivery stops at once and the
    /// output is held.
    Held,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SendPause {
    #[default]
    Running,
    /// Paused by the application from outside a read.
    Paused,
    /// A read handler asked for a pause (`CURL_READFUNC_PAUSE`): until it
    /// is lifted the reader is paused too (`Curl_creader_is_paused`), and
    /// an application pause changes nothing.
    Asked,
}

impl Pause {
    /// Set what `req` asks for. A receive pause asked for while output is
    /// held keeps it held.
    pub(crate) fn apply(&mut self, req: PauseRequest) {
        self.recv = match (req.recv, self.recv) {
            (false, _) => RecvPause::Running,
            (true, RecvPause::Held) => RecvPause::Held,
            (true, _) => RecvPause::Stopped,
        };
        self.send = match (req.send, self.send) {
            (false, SendPause::Asked) => {
                self.lifts.0 = self.lifts.0.wrapping_add(1);
                SendPause::Running
            }
            (false, _) => SendPause::Running,
            (true, SendPause::Asked) => SendPause::Asked,
            (true, _) => SendPause::Paused,
        };
    }

    /// Receiving stops, as a layer of the transfer's asks
    /// (`Curl_xfer_pause_recv`), until the application unpauses it;
    /// output held stays held.
    pub(crate) fn stop_recv(&mut self) {
        if self.recv == RecvPause::Running {
            self.recv = RecvPause::Stopped;
        }
    }

    /// A read handler asked for a pause.
    pub(crate) fn ask_send(&mut self) {
        self.send = SendPause::Asked;
    }

    /// The lifts so far of the pauses read handlers asked for.
    pub(crate) fn lifts(&self) -> Lifts {
        self.lifts
    }

    pub(crate) fn recv_paused(&self) -> bool {
        self.recv != RecvPause::Running
    }

    pub(crate) fn send_paused(&self) -> bool {
        self.send != SendPause::Running
    }

    /// Whether the pause stops a request moving bytes the ways it does
    /// (`Curl_xfer_is_blocked`): every way, or receiving when it only
    /// receives, or sending when it only sends. One that moves none is
    /// never blocked.
    pub(crate) fn blocks(&self, ways: Directions) -> bool {
        match (ways.recv, ways.send) {
            (false, false) => false,
            (true, false) => self.recv_paused(),
            (false, true) => self.send_paused(),
            (true, true) => self.recv_paused() && self.send_paused(),
        }
    }
}

/// The ways a request moves bytes, once it is made (C's `REQ_IO_RECV`
/// and `REQ_IO_SEND`): none before, and each until it is done.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Directions {
    pub(crate) recv: bool,
    pub(crate) send: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_sets_each_direction() {
        let mut p = Pause::default();
        p.apply(PauseRequest::RECV);
        assert_eq!((p.recv, p.send), (RecvPause::Stopped, SendPause::Running));
        p.apply(PauseRequest::SEND);
        assert_eq!((p.recv, p.send), (RecvPause::Running, SendPause::Paused));
        p.apply(PauseRequest::ALL);
        assert_eq!((p.recv, p.send), (RecvPause::Stopped, SendPause::Paused));
        p.apply(PauseRequest::CONT);
        assert_eq!(p, Pause::default());
    }

    /// A pause a handler asked for stays so under the application's pause,
    /// and counts a lift when it ends; the application's own does not.
    #[test]
    fn a_lift_counts_the_end_of_an_asked_pause() {
        let mut p = Pause::default();
        p.apply(PauseRequest::SEND);
        p.apply(PauseRequest::CONT);
        assert_eq!(p.lifts(), Lifts(0));
        p.ask_send();
        assert!(p.send_paused());
        p.apply(PauseRequest::SEND);
        assert_eq!((p.send, p.lifts()), (SendPause::Asked, Lifts(0)));
        p.apply(PauseRequest::RECV);
        assert_eq!((p.send, p.lifts()), (SendPause::Running, Lifts(1)));
        p.apply(PauseRequest::CONT);
        assert_eq!(p.lifts(), Lifts(1));
    }

    #[test]
    fn held_output_stays_held_under_a_receive_pause() {
        let mut p = Pause {
            recv: RecvPause::Held,
            ..Pause::default()
        };
        p.apply(PauseRequest::RECV);
        assert_eq!(p.recv, RecvPause::Held);
        p.apply(PauseRequest::ALL);
        assert_eq!((p.recv, p.send), (RecvPause::Held, SendPause::Paused));
        p.apply(PauseRequest::CONT);
        assert_eq!(p.recv, RecvPause::Running);
    }
}
