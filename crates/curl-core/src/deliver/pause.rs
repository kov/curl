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
}

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
    Paused,
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
        self.send = if req.send {
            SendPause::Paused
        } else {
            SendPause::Running
        };
    }

    pub(crate) fn recv_paused(&self) -> bool {
        self.recv != RecvPause::Running
    }
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

    #[test]
    fn held_output_stays_held_under_a_receive_pause() {
        let mut p = Pause {
            recv: RecvPause::Held,
            send: SendPause::Running,
        };
        p.apply(PauseRequest::RECV);
        assert_eq!(p.recv, RecvPause::Held);
        p.apply(PauseRequest::ALL);
        assert_eq!((p.recv, p.send), (RecvPause::Held, SendPause::Paused));
        p.apply(PauseRequest::CONT);
        assert_eq!(p.recv, RecvPause::Running);
    }
}
