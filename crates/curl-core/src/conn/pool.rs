//! The connection pool: the connections kept idle for the transfers after
//! the one that used them, and the only issuer and consumer of leases
//! (`lib/conncache.c`). A leased connection is its lease's, so the
//! transfer holding it uses it without the pool; the pool keeps its place
//! and number, and counts it against its limits.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use super::chain::SetupPoint;
use super::connect::{ConnCx, ConnectError, ConnectMachine, Dialed, Drove, Made, Progress, Setup};
use super::dns::Answer;
use super::io::{Closer, Events, Socket, SocketKey};
use super::layer::{Alive, LayerAnswer, LayerQuery, Silent};
use super::shutdown::{ConnSettings, Exits, discard};
use super::{Conn, ConnId, ConnNumber, ConnSlot, Peer, Route, TransferNumber, Transport, Use};
use crate::id::{Arena, ArenaPolicy};
use crate::proto::http::negotiate::Wants;
use crate::share::Share;
use crate::time::Instant;

/// A transfer's hold on a connection, and the connection, being set up or
/// up. Only the pool makes one, and only `Pool::release` takes one back,
/// that pool being the one `home` names; dropping one is a bug, and aborts.
///
/// A lease on a connection that multiplexes is a key: the connection
/// lives in its pool place, shared by the transfers attached to it, and
/// is out with a lease only for the step of the transfer holding it
/// (`Pool::check_out`, `Pool::check_in`).
#[must_use]
#[derive(Debug)]
pub(crate) struct ConnLease {
    id: ConnId,
    /// None only as the pool takes it back, and, for a key, while the
    /// connection is in its place: whether the lease is a key, its pool's
    /// place says.
    conn: Option<ConnSlot>,
    /// The pool it is from, and goes back to.
    home: Home,
}

/// The pool a lease is from: the multi's own, or a share's. Ids alone
/// cannot tell, as a share's table and a multi's hand out equal ones. A
/// multi's pool is not told from another multi's: a lease never leaves
/// the multi that holds it, but a share's lease is run by any multi.
#[derive(Clone, Debug)]
pub(crate) enum Home {
    Multi,
    Share(Share),
}

impl Home {
    /// Whether the two name the same pool: a share by its identity.
    fn is(&self, other: &Home) -> bool {
        match (self, other) {
            (Home::Multi, Home::Multi) => true,
            (Home::Share(a), Home::Share(b)) => a.is(b),
            (Home::Multi | Home::Share(_), Home::Multi | Home::Share(_)) => false,
        }
    }
}

impl ConnLease {
    /// Its place in its pool: what a transfer keeps of the connection it
    /// had last, and what the tests tell leases apart by.
    pub(crate) fn id(&self) -> ConnId {
        self.id
    }

    /// The connection, as the lease holds it: always, but for a key's
    /// outside its transfer's step.
    pub(crate) fn held(&self) -> &ConnSlot {
        self.slot()
    }

    /// The connection, if the lease has it: a key has it only while its
    /// transfer's step has it out.
    pub(crate) fn holding(&self) -> Option<&ConnSlot> {
        self.conn.as_ref()
    }

    /// Move the connection's setup on by one event. A connection already
    /// up says so.
    pub(crate) fn connect(
        &mut self,
        cx: &mut dyn ConnCx,
        setup: Setup,
    ) -> Result<Connected, ConnectError> {
        let number = self.number();
        let (slot, connected) = match std::mem::replace(self.slot_mut(), ConnSlot::Failed(number)) {
            ConnSlot::Connecting(machine) => match machine.drive(cx, setup) {
                Ok(Drove::Connecting(m, progress)) => {
                    (ConnSlot::Connecting(m), Ok(Connected::Connecting(progress)))
                }
                Ok(Drove::Established(conn)) => {
                    let up = Connected::Established {
                        remote: conn.remote.clone().expect("set up over the network"),
                        local: conn.local(),
                        at: conn.connected_at,
                    };
                    (ConnSlot::Open(conn), Ok(up))
                }
                Err(e) => (ConnSlot::Failed(number), Err(e)),
            },
            ConnSlot::Open(conn) => {
                let up = Connected::AlreadyUp {
                    remote: conn.remote.clone(),
                    local: conn.local(),
                };
                (ConnSlot::Open(conn), Ok(up))
            }
            ConnSlot::Failed(_) => unreachable!("a failed setup is not driven again"),
        };
        *self.slot_mut() = slot;
        connected
    }

    /// How far its setup got, while it is set up.
    pub(crate) fn reached(&self) -> Option<SetupPoint> {
        match self.slot() {
            ConnSlot::Connecting(machine) => Some(machine.reached()),
            ConnSlot::Open(_) | ConnSlot::Failed(_) => None,
        }
    }

    /// The PROXY protocol's line is sent over the connection to the first
    /// hop, as was decided once the proxies' handshakes were made; false
    /// before, and once set up.
    pub(crate) fn sends_preface(&self) -> bool {
        match self.slot() {
            ConnSlot::Connecting(machine) => machine.sends_preface(),
            ConnSlot::Open(_) | ConnSlot::Failed(_) => false,
        }
    }

    /// The proxy's handshake `which` is made over the connection to the
    /// first hop; `haproxy` is read once the route's are all made
    /// (`ConnectMachine::proxied`).
    pub(crate) fn proxied(&mut self, which: Made, haproxy: impl FnOnce() -> bool) {
        let id = self.id;
        match self.slot_mut() {
            ConnSlot::Connecting(machine) => machine.proxied(which, haproxy),
            _ => panic!("{id:?} is not setting up"),
        }
    }

    /// What a failing setup keeps of its connection to the first hop
    /// (`ConnectMachine::partly_made`); nothing once it is not setting up.
    pub(crate) fn partly_made(
        &self,
    ) -> Option<(
        super::io::Remote,
        Option<std::net::SocketAddr>,
        crate::time::Instant,
    )> {
        match self.slot() {
            ConnSlot::Connecting(machine) => machine.partly_made(),
            ConnSlot::Open(_) | ConnSlot::Failed(_) => None,
        }
    }

    /// The connection to the first hop, while its handshakes are made.
    pub(crate) fn dialed(&mut self) -> &mut Dialed {
        let id = self.id;
        match self.slot_mut() {
            ConnSlot::Connecting(machine) => machine.dialed(),
            _ => panic!("{id:?} is not setting up"),
        }
    }

    /// What the handshake under way over the connection to the first
    /// hop waits for, as its layers say: TLS's.
    pub(crate) fn handshake_pollset(&self, wanted: Events) -> Events {
        match self.slot() {
            ConnSlot::Connecting(machine) => machine.handshake_pollset(wanted),
            _ => panic!("{:?} is not setting up", self.id),
        }
    }

    /// The setup's handshakes are made: the connection is up.
    pub(crate) fn handshaken(&mut self) -> Connected {
        let number = self.number();
        let ConnSlot::Connecting(machine) =
            std::mem::replace(self.slot_mut(), ConnSlot::Failed(number))
        else {
            panic!("{:?} is not setting up", self.id);
        };
        let conn = machine.handshaken();
        let up = Connected::Established {
            remote: conn.remote.clone().expect("set up over the network"),
            local: conn.local(),
            at: conn.connected_at,
        };
        *self.slot_mut() = ConnSlot::Open(conn);
        up
    }

    /// Start the setup over, as its proxy closed the connection; false if
    /// it was started over too often.
    pub(crate) fn redial(&mut self, cx: &mut dyn ConnCx) -> bool {
        let id = self.id;
        match self.slot_mut() {
            ConnSlot::Connecting(machine) => machine.redial(cx),
            _ => panic!("{id:?} is not setting up"),
        }
    }

    /// The connection, once up.
    pub(crate) fn conn(&self) -> &Conn {
        match self.slot() {
            ConnSlot::Open(conn) => conn,
            _ => panic!("{:?} is not up", self.id),
        }
    }

    /// The connection is up: set up already, as one reused is.
    pub(crate) fn is_up(&self) -> bool {
        matches!(self.slot(), ConnSlot::Open(_))
    }

    /// The connection is up and to close after its request
    /// (`bits.close`).
    pub(crate) fn closes(&self) -> bool {
        matches!(self.slot(), ConnSlot::Open(conn) if conn.close)
    }

    /// Whether the connection is up and speaks HTTP/2.
    pub(crate) fn is_h2(&self) -> bool {
        matches!(self.slot(), ConnSlot::Open(conn) if conn.is_h2())
    }

    /// The connection, once up, to use.
    pub(crate) fn get(&mut self) -> &mut Conn {
        let id = self.id;
        match self.slot_mut() {
            ConnSlot::Open(conn) => conn,
            _ => panic!("{id:?} is not up"),
        }
    }

    /// What the name of a connection being set up resolved to, once it
    /// has.
    pub(crate) fn answer(&self) -> Option<TryArc<Answer>> {
        match self.slot() {
            ConnSlot::Connecting(m) => m.answer().cloned(),
            ConnSlot::Open(_) | ConnSlot::Failed(_) => None,
        }
    }

    /// The connection's sockets: its attempts' while it is set up, none
    /// without a network.
    pub(crate) fn sockets(&self) -> impl Iterator<Item = &dyn Socket> {
        self.slot().sockets()
    }

    /// What the connection's layers answer `q` (`ConnSlot::query`).
    pub(crate) fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        self.slot().query(q)
    }

    pub(crate) fn number(&self) -> ConnNumber {
        match self.slot() {
            ConnSlot::Connecting(m) => m.number(),
            ConnSlot::Open(conn) => conn.number,
            ConnSlot::Failed(number) => *number,
        }
    }
}

/// What can be read of a connection wherever it is, with its lease or in
/// its place: what a transfer waits on it for, outside its step.
impl ConnSlot {
    /// The connection's sockets: its attempts' while it is set up, none
    /// without a network.
    pub(crate) fn sockets(&self) -> impl Iterator<Item = &dyn Socket> {
        let (setup, open) = match self {
            ConnSlot::Connecting(m) => (Some(m), None),
            ConnSlot::Open(Conn {
                transport: Transport::Tcp(stream),
                ..
            }) => (None, Some(stream.socket())),
            ConnSlot::Open(_) | ConnSlot::Failed(_) => (None, None),
        };
        setup
            .into_iter()
            .flat_map(ConnectMachine::sockets)
            .chain(open)
    }

    /// What a transfer is to wait for on the connection, given what it
    /// wants: its layers' say, once it is up. A transfer wanting nothing
    /// is not asked about, as its layers' sockets would then be ready
    /// forever (`Curl_conn_adjust_pollset`).
    pub(crate) fn adjust_pollset(&self, wanted: Events) -> Events {
        match self {
            ConnSlot::Open(Conn {
                transport: Transport::Tcp(stream),
                ..
            }) if !wanted.is_empty() => stream.adjust_pollset(wanted),
            ConnSlot::Open(_) | ConnSlot::Connecting(_) | ConnSlot::Failed(_) => wanted,
        }
    }

    /// What the connection's layers answer `q`, the topmost that does,
    /// while it is set up and once it is up.
    pub(crate) fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        match self {
            ConnSlot::Connecting(m) => m.query(q),
            ConnSlot::Open(Conn {
                transport: Transport::Tcp(stream),
                ..
            }) => stream.query(q),
            ConnSlot::Open(_) | ConnSlot::Failed(_) => None,
        }
    }

    /// The connection, once up.
    pub(crate) fn open(&self) -> Option<&Conn> {
        match self {
            ConnSlot::Open(conn) => Some(conn),
            ConnSlot::Connecting(_) | ConnSlot::Failed(_) => None,
        }
    }
}

impl ConnLease {
    /// The lease taken apart, as only the pool does.
    fn into_parts(mut self) -> (ConnId, Option<ConnSlot>, Home) {
        let conn = self.conn.take();
        let home = std::mem::replace(&mut self.home, Home::Multi);
        let id = self.id;
        // Taken apart, not dropped: it held nothing more.
        std::mem::forget(self);
        (id, conn, home)
    }

    /// The pool the lease is from, and is given back to.
    pub(crate) fn home(&self) -> &Home {
        &self.home
    }

    fn slot(&self) -> &ConnSlot {
        self.conn
            .as_ref()
            .expect("held until given back, and out of its place")
    }

    fn slot_mut(&mut self) -> &mut ConnSlot {
        self.conn
            .as_mut()
            .expect("held until given back, and out of its place")
    }
}

impl Drop for Pool {
    /// A share's connection lent to a multi goes back with the last of
    /// its keys, which the multi gives back before its pool goes.
    fn drop(&mut self) {
        assert!(
            std::thread::panicking() || self.lent.is_empty(),
            "a pool dropped with a share's connection lent to it"
        );
    }
}

impl Drop for ConnLease {
    fn drop(&mut self) {
        assert!(
            std::thread::panicking(),
            "the lease on {:?} was dropped, not released",
            self.id
        );
    }
}

/// What a transfer looking for a connection wants of one: the route it
/// serves, and how it authenticated, as far as that binds it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Wanted<'w> {
    pub(crate) route: &'w Route,
    pub(crate) auth: Wants<'w>,
    /// The connection the transfer used last, tried first, so that a
    /// transfer sticks to its connection (`state.last_conn_id`). An id
    /// of a connection gone, or of another pool, finds nothing or an
    /// unrelated connection judged as any other, so it needs no clearing.
    pub(crate) last: Option<ConnId>,
    /// The HTTP versions the transfer may speak: a connection that speaks
    /// another is passed over (`url_match_http_version`).
    pub(crate) versions: crate::proto::http::Versions,
    /// The transfer may share a connection that multiplexes, with at most
    /// this many transfers on it (`xfer_may_multiplex`,
    /// `Curl_multi_max_concurrent_streams`).
    pub(crate) multiplex: Option<NonZeroU32>,
    /// The transfer would rather wait for a connection being set up to
    /// say it multiplexes than make its own (`CURLOPT_PIPEWAIT`).
    pub(crate) pipewait: bool,
    /// For a share's pool: what the searching multi has of the share's
    /// connections lent to it.
    pub(crate) lending: Lending<'w>,
}

/// How long the transfer looking for a connection lets one be idle, and
/// live (`CURLOPT_MAXAGE_CONN`, `CURLOPT_MAXLIFETIME_CONN`); none for no
/// limit, as 0 is for either in C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReuseRules {
    pub(crate) max_idle: Option<Duration>,
    pub(crate) max_age: Option<Duration>,
    /// No idle connection is to be reused (`reuse_fresh`).
    pub(crate) fresh: bool,
}

/// How the transfer holding a lease finished with the connection
/// (`multi_done`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Finish {
    /// The transfer stopped before its request was complete, so the
    /// connection's state is unknown.
    pub(crate) premature: bool,
    /// The application forbade the connection's reuse
    /// (`CURLOPT_FORBID_REUSE`).
    pub(crate) forbid_reuse: bool,
    /// The transfer only connected (`CURLOPT_CONNECT_ONLY`): the
    /// connection is kept for its handle to send and receive on.
    pub(crate) reserve: bool,
}

/// What the pool did with a connection given back (`multi_done_locked`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Released {
    /// Kept for another transfer; the pool was `full`, if it was, and
    /// closed another.
    Idle {
        number: ConnNumber,
        full: Option<Full>,
    },
    /// Kept, then closed at once: the pool was full, and it was the
    /// oldest idle connection.
    Evicted(Full),
    /// Closed, gracefully where the connection has a way to.
    Closed(ConnNumber),
    /// Closed at once: the transfer ended prematurely.
    Terminated(ConnNumber),
    /// Kept for the transfers still attached to it, this many.
    InUse(NonZeroU32),
}

/// The pool had more connections than it keeps when one went idle, and
/// closed the idle one longest unused, if any was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Full {
    /// Connections in the pool, busy or idle, before the close.
    pub(crate) conns: u32,
    /// How many it keeps.
    pub(crate) max: u32,
}

/// The limits a new connection is added under
/// (`CURLMOPT_MAX_HOST_CONNECTIONS`, `CURLMOPT_MAX_TOTAL_CONNECTIONS`);
/// none for no limit.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AddLimits {
    pub(crate) max_host: Option<NonZeroU32>,
    pub(crate) max_total: Option<NonZeroU32>,
}

/// Why a transfer waits for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitReason {
    /// As many to its destination as allowed.
    HostLimit,
    /// As many in all as allowed: this many.
    TotalLimit(NonZeroU32),
    /// A connection being set up may take it (`CURLOPT_PIPEWAIT`).
    Multiplex,
}

/// A connection for a transfer.
#[derive(Debug)]
pub(crate) enum Acquired {
    /// A new one, to set up.
    New(ConnLease),
    /// An idle one, up already.
    Reused(ConnLease),
    /// None: a new one would pass a limit.
    Wait(WaitReason),
}

/// Something the search for a connection did, for the transfer to trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PoolNote {
    /// A match idle for too long (`cpool_conn_too_old`). One alive too
    /// long is passed over before its health is checked, so says nothing.
    IdleTooLong { idle_ms: u64, max_ms: u64 },
    /// A match not healthy (`url_match_conn`).
    Dead(ConnNumber),
    /// A connection that multiplexes, and serves the transfer, has as many
    /// on it as the multi lets it, or as its server takes if `peer`
    /// (`url_match_multiplex_limits`).
    Full {
        number: ConnNumber,
        users: u32,
        peer: bool,
    },
    /// A connection that multiplexes was joined.
    Multiplexed,
    /// A connection that serves the transfer, which may multiplex, is
    /// not up, or not known to multiplex (`url_match_fully_connected`).
    NotOpenEnough(ConnNumber),
    /// The transfer waits for such a one (`url_match_result`).
    PendingCandidate,
    /// A connection closed, gracefully.
    Closed(ConnNumber),
}

/// What a step of a connection's setup came to.
#[derive(Debug)]
pub(crate) enum Connected {
    /// Still setting up.
    Connecting(Progress),
    /// Up, from `local` to `remote`, found so at `at`: as the race is
    /// won, or at the end of a proxy's handshake.
    Established {
        remote: super::io::Remote,
        local: Option<SocketAddr>,
        at: Instant,
    },
    /// Up before this step: a reused connection, from `local` to
    /// `remote`.
    AlreadyUp {
        remote: Option<super::io::Remote>,
        local: Option<SocketAddr>,
    },
}

/// Where a connection of the pool is.
enum Place {
    /// Kept for another transfer; always open.
    Idle(ConnSlot),
    /// Leased: its lease has it.
    Leased(Leased),
    /// Kept for the handle whose transfer only connected
    /// (`CURLOPT_CONNECT_ONLY`), which sends and receives on it: never
    /// reused, pruned or closed to make room, but counted toward the
    /// limits (`bits.connect_only`); always open.
    Reserved(ConnSlot),
    /// Multiplexing, leased by the transfers attached to it, whose leases
    /// are keys; always open. Its count of them is the connection's
    /// `Use::Leased`.
    Attached(Shared),
}

/// What the pool knows of a connection leased: enough to count it, and
/// to tell a transfer that may multiplex whether to wait for it.
struct Leased {
    route: Route,
    number: ConnNumber,
    verdict: Verdict,
    /// A share's connection found to multiplex, lent to a multi while it
    /// does: the multi it is lent to has it among those lent to it.
    lent: bool,
}

/// Whether a leased connection may yet take more transfers, as its
/// lease's step last left it (`url_match_fully_connected`,
/// `url_match_multiplex_needs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Being set up, or not yet known to speak HTTP/2 or not.
    Pending,
    /// Up, and takes one request at a time.
    Single,
}

impl Verdict {
    /// A connection's, `settled` if its transfer found what it speaks.
    fn of(conn: Option<&Conn>, settled: bool) -> Verdict {
        match conn {
            Some(conn) if settled && !conn.is_h2() => Verdict::Single,
            _ => Verdict::Pending,
        }
    }
}

/// What the search saw of the connections to the transfer's route that
/// it could not use (`url_conn_match`'s `seen_*`).
#[derive(Clone, Copy, Debug, Default)]
struct Seen {
    pending: bool,
    single: bool,
    multiplex: bool,
}

/// What the search found.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "returned by the search and taken apart at once, never kept; a box would \
              allocate on every search"
)]
pub(crate) enum Found {
    Lease(ConnLease),
    /// The share's connection `id`, lent to the searching multi, which
    /// takes the transfer: the multi's pool has it.
    Lent(ConnId),
    /// Nothing to use, nor to wait for.
    Nothing,
    /// Nothing to use yet, but a connection being set up may take the
    /// transfer once it is known to multiplex (`wait_pipe`).
    Wait,
}

#[cfg(test)]
impl Found {
    /// The lease found, if one was.
    pub(crate) fn lease(self) -> Option<ConnLease> {
        match self {
            Found::Lease(lease) => Some(lease),
            Found::Lent(_) | Found::Nothing | Found::Wait => None,
        }
    }
}

/// A connection that multiplexes, in its place.
struct Shared {
    /// None while the step of one of its transfers has it out.
    slot: Option<ConnSlot>,
    route: Route,
}

impl Shared {
    fn conn(&self) -> &Conn {
        match &self.slot {
            Some(ConnSlot::Open(conn)) => conn,
            Some(_) => unreachable!("an attached connection is open"),
            None => panic!("an attached connection is out with a step"),
        }
    }

    fn conn_mut(&mut self) -> &mut Conn {
        match &mut self.slot {
            Some(ConnSlot::Open(conn)) => conn,
            Some(_) => unreachable!("an attached connection is open"),
            None => panic!("an attached connection is out with a step"),
        }
    }
}

/// A share's connection that multiplexes for the multi, kept by the
/// multi's pool while it does; its keys are the share's leases, naming
/// it by its place there, which says it is lent.
struct Lent {
    shared: Shared,
    share: Share,
    id: ConnId,
}

/// What a connection that multiplexes would make of a transfer looking
/// for one (`url_match_multiplex_needs`, `url_match_multiplex_limits`).
#[derive(Clone, Copy, Debug)]
enum JoinVerdict {
    /// Closing, or to another route: not seen.
    Passed,
    /// Seen, but it cannot take the transfer.
    Seen,
    /// Seen, with as many transfers on it as it takes.
    Full {
        number: ConnNumber,
        users: u32,
        peer: bool,
    },
    Join,
}

/// What the multi searching a share's pool has of the share's
/// connections lent to it: what each would make of the transfer, by its
/// place in the share's pool.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Lending<'w> {
    lent: &'w [(ConnId, JoinVerdict)],
}

impl Lending<'_> {
    pub(crate) const NONE: Lending<'static> = Lending { lent: &[] };
}

/// The multi's side of a search of a share's pool, `Pool::lending`.
pub(crate) struct LentCandidates {
    lent: Vec<(ConnId, JoinVerdict)>,
}

impl LentCandidates {
    pub(crate) fn lending(&self) -> Lending<'_> {
        Lending { lent: &self.lent }
    }
}

/// What a connection the search tried came to.
#[expect(
    clippy::large_enum_variant,
    reason = "as `Found`, which it becomes at once"
)]
enum Took {
    Lease(ConnLease),
    Lent(ConnId),
}

/// What `release_lent` gave back.
#[expect(
    clippy::large_enum_variant,
    reason = "taken apart by the release that asked, never kept"
)]
pub(crate) enum LentBack {
    /// Others are still on it, this many.
    InUse(NonZeroU32),
    /// The last is done: the share's lease, for the share's pool to take
    /// back.
    Last(ConnLease),
}

impl Place {
    /// The idle connection, if this is one.
    fn idle(&self) -> Option<&Conn> {
        match self {
            Place::Idle(slot) => match slot {
                ConnSlot::Open(conn) => Some(conn),
                _ => unreachable!("an idle connection is open"),
            },
            Place::Leased(_) | Place::Reserved(_) | Place::Attached(_) => None,
        }
    }

    fn idle_mut(&mut self) -> Option<&mut Conn> {
        match self {
            Place::Idle(slot) => match slot {
                ConnSlot::Open(conn) => Some(conn),
                _ => unreachable!("an idle connection is open"),
            },
            Place::Leased(_) | Place::Reserved(_) | Place::Attached(_) => None,
        }
    }

    /// The connection, if the pool holds it: idle or reserved.
    fn held(&self) -> Option<&Conn> {
        match self {
            Place::Idle(ConnSlot::Open(conn)) | Place::Reserved(ConnSlot::Open(conn)) => Some(conn),
            Place::Idle(_) | Place::Reserved(_) => unreachable!("a connection held is open"),
            Place::Leased(_) | Place::Attached(_) => None,
        }
    }

    /// The peer the connection goes to, if over a network.
    fn destination(&self) -> Option<&Peer> {
        match self {
            Place::Idle(slot) | Place::Reserved(slot) => slot.destination(),
            Place::Leased(Leased {
                route: Route::Tcp(tcp),
                ..
            })
            | Place::Attached(Shared {
                route: Route::Tcp(tcp),
                ..
            }) => Some(tcp.destination()),
            Place::Leased(_) | Place::Attached(_) => None,
        }
    }
}

/// Every connection of a multi (or of a share): those idle here, and
/// where those leased were.
pub(crate) struct Pool {
    conns: Arena<Place, ConnSlot>,
    /// A multi's: the share's connections lent to it.
    lent: Vec<Lent>,
    next_number: u64,
    /// Connections numbered below this were made before the network last
    /// changed (`CURLMNWC_CLEAR_CONNS`): none is reused, and the prune
    /// closes each once it is idle, as C marks every one `no_reuse`.
    stale_below: u64,
    /// When the search last pruned dead connections (`last_cleanup`).
    last_prune: Option<Instant>,
    /// The number the next transfer to join the pool is given
    /// (`next_easy_id`).
    next_transfer: u64,
}

impl Pool {
    pub(crate) fn new() -> Result<Pool, OutOfMemory> {
        Ok(Pool {
            conns: Arena::new(ArenaPolicy::DOUBLING)?,
            lent: Vec::new(),
            next_number: 0,
            stale_below: 0,
            last_prune: None,
            next_transfer: 0,
        })
    }

    /// A number for a transfer joining the pool: one more than the last
    /// one's, from 0, back to 0 short of the largest `curl_off_t`
    /// (`Curl_cpool_xfer_init`).
    pub(crate) fn join(&mut self) -> TransferNumber {
        let number = TransferNumber(self.next_transfer);
        self.next_transfer += 1;
        if self.next_transfer == i64::MAX as u64 {
            self.next_transfer = 0;
        }
        number
    }

    /// A connection for `route`, leased to the caller: an idle one whose
    /// route is equal, healthy and young enough, or a new one within
    /// `limits`, open at once without a network and set up by
    /// `ConnLease::connect` over one; or none, for want of room. What the
    /// search did is added to `notes`. A pool others share is searched,
    /// and added to, one under its lock at a time, as C does.
    #[cfg(test)]
    #[expect(clippy::too_many_arguments, reason = "what `find` and `add` take")]
    pub(crate) fn acquire(
        &mut self,
        here: &Home,
        route: Route,
        rules: ReuseRules,
        limits: AddLimits,
        exits: &mut dyn Exits,
        now: Instant,
        notes: &mut Vec<PoolNote>,
    ) -> Result<Acquired, OutOfMemory> {
        if searches(&route, rules)
            && let Some(lease) = self
                .find(
                    here,
                    Wanted {
                        route: &route,
                        auth: Wants::NONE,
                        last: None,
                        versions: crate::proto::http::Versions::ALL,
                        multiplex: None,
                        pipewait: false,
                        lending: Lending::NONE,
                    },
                    rules,
                    exits,
                    now,
                    notes,
                )?
                .lease()
        {
            return Ok(Acquired::Reused(lease));
        }
        let settings = ConnSettings::DEFAULT;
        self.add(here, route, Closer::System, settings, limits, exits, now)
    }

    /// A new connection for `route`, within `limits`, or none, for want
    /// of room (`Curl_cpool_add`); its lease is from `here`, the pool this
    /// is. It closes its sockets with `closer` and keeps `settings`, its
    /// creating transfer's, whoever closes it.
    #[expect(
        clippy::too_many_arguments,
        reason = "C's `Curl_cpool_add` and what it captures"
    )]
    pub(crate) fn add(
        &mut self,
        here: &Home,
        route: Route,
        closer: Closer,
        settings: ConnSettings,
        limits: AddLimits,
        exits: &mut dyn Exits,
        now: Instant,
    ) -> Result<Acquired, OutOfMemory> {
        // A connection without a network is added with no limits
        // (`Curl_cpool_add(data, needle, 0, 0)`).
        if let Route::Tcp(tcp) = &route {
            let evicted = Evicted::of(here);
            let to = tcp.destination();
            if let Some(reason) = make_room(&mut self.conns, to, limits, evicted, exits, now) {
                return Ok(Acquired::Wait(reason));
            }
        }
        let number = ConnNumber(self.next_number);
        let leased = Leased {
            route: route.clone(),
            number,
            verdict: Verdict::of(None, false),
            lent: false,
        };
        let slot = match route {
            Route::Local => ConnSlot::Open(Conn {
                number,
                route,
                transport: Transport::Local,
                remote: None,
                created: now,
                connected_at: now,
                use_: Use::Leased(NonZeroU32::MIN),
                served: false,
                socks5_authenticated: false,
                seen_version: None,
                close: false,
                settings,
                negotiate: None,
                h2: None,
            }),
            Route::Tcp(tcp) => {
                ConnSlot::Connecting(ConnectMachine::new(number, tcp, now, closer, settings))
            }
        };
        let id = self.conns.reserve()?.fill(Place::Leased(leased));
        self.next_number += 1;
        Ok(Acquired::New(ConnLease {
            id,
            conn: Some(slot),
            home: here.clone(),
        }))
    }

    /// The search for an idle connection to reuse (`Curl_cpool_find`,
    /// `url_match_conn`): a prune of the dead ones at most once a second,
    /// then the first match in the table's order. A match too old or not
    /// healthy is closed and the search goes on. The lease is from
    /// `here`, the pool this is. A match serves the route `wanted`
    /// names, and what authenticated over it suits what the transfer
    /// wants.
    pub(crate) fn find(
        &mut self,
        here: &Home,
        wanted: Wanted<'_>,
        rules: ReuseRules,
        exits: &mut dyn Exits,
        now: Instant,
        notes: &mut Vec<PoolNote>,
    ) -> Result<Found, OutOfMemory> {
        if self
            .last_prune
            .is_none_or(|at| now.since(at) >= Duration::from_secs(1))
        {
            self.last_prune = Some(now);
            prune(&mut self.conns, self.stale_below, rules, exits, now);
        }
        // The transfer's last connection first, then the others in the
        // table's order (`Curl_cpool_find`).
        let mut seen = Seen::default();
        let found = |took| match took {
            Took::Lease(lease) => Found::Lease(lease),
            Took::Lent(id) => Found::Lent(id),
        };
        if let Some(last) = wanted.last
            && let Some(took) =
                self.take(last, here, &wanted, rules, exits, now, notes, &mut seen)?
        {
            return Ok(found(took));
        }
        let mut cursor = None;
        while let Some(id) = self.conns.next_after(cursor) {
            cursor = Some(id);
            if Some(id) == wanted.last {
                continue;
            }
            if let Some(took) = self.take(id, here, &wanted, rules, exits, now, notes, &mut seen)? {
                return Ok(found(took));
            }
        }
        // A connection that takes one request at a time, with none seen
        // that takes more, says the server does not multiplex: none is
        // waited for (`url_match_result`).
        if seen.single && !seen.multiplex {
            return Ok(Found::Nothing);
        }
        if seen.pending && wanted.pipewait {
            notes.try_push(PoolNote::PendingCandidate)?;
            return Ok(Found::Wait);
        }
        Ok(Found::Nothing)
    }

    /// The connection `id`, leased from `here` if it is idle, matches
    /// `wanted` and is young and healthy enough; one too old or not
    /// healthy is closed, and its notes said.
    /// A leased one that serves the transfer is told in `seen`.
    #[expect(
        clippy::too_many_arguments,
        reason = "what `find` takes, the id, and what it saw"
    )]
    fn take(
        &mut self,
        id: ConnId,
        here: &Home,
        wanted: &Wanted<'_>,
        rules: ReuseRules,
        exits: &mut dyn Exits,
        now: Instant,
        notes: &mut Vec<PoolNote>,
        seen: &mut Seen,
    ) -> Result<Option<Took>, OutOfMemory> {
        match self.conns.get(id) {
            Some(Place::Attached(_)) => {
                return Ok(self
                    .join_if(id, here, wanted, notes, seen)?
                    .map(Took::Lease));
            }
            // Lent to the searching multi, it takes the transfer as its
            // pool says; lent to another, it is seen and passed over
            // (`url_match_multi`).
            Some(Place::Leased(Leased {
                lent: true, route, ..
            })) => {
                let verdict = wanted.lending.lent.iter().find(|(lent, _)| *lent == id);
                return match verdict {
                    Some(&(_, verdict)) => {
                        Ok(judged(verdict, notes, seen)?.then_some(Took::Lent(id)))
                    }
                    None => {
                        if route.serves(wanted.route) {
                            seen.multiplex = true;
                        }
                        Ok(None)
                    }
                };
            }
            Some(Place::Leased(leased)) => {
                if leased.route.serves(wanted.route) {
                    match leased.verdict {
                        Verdict::Pending if wanted.multiplex.is_some() => {
                            seen.pending = true;
                            notes.try_push(PoolNote::NotOpenEnough(leased.number))?;
                        }
                        Verdict::Pending => {}
                        Verdict::Single => seen.single = true,
                    }
                }
                return Ok(None);
            }
            _ => {}
        }
        let Some(conn) = self.conns.get_mut(id).and_then(Place::idle_mut) else {
            return Ok(None);
        };
        let Use::Idle { since, .. } = conn.use_ else {
            unreachable!("an idle connection is idle");
        };
        if conn.number.get() < self.stale_below
            || !conn.serves(wanted.route)
            || !conn.serves_auth(&wanted.auth)
        {
            return Ok(None);
        }
        let speaks = if conn.is_h2() {
            wanted.versions.h2
        } else {
            wanted.versions.h1
        };
        if !speaks {
            return Ok(None);
        }
        let number = conn.number;
        // One that lived too long is passed over for a younger one
        // (`CPOOL_MATCH_TOO_OLD`); one not healthy is reported.
        let verdict = if rules
            .max_age
            .is_some_and(|max| past(now.since(conn.created), max))
        {
            Err(None)
        } else {
            health(conn, since, rules, now).map_err(Some)
        };
        match verdict {
            Ok(()) => {
                let leased = Leased {
                    route: conn.route.clone(),
                    number: conn.number,
                    // An idle one carried a request, which found it.
                    verdict: Verdict::of(Some(conn), true),
                    lent: false,
                };
                let Some(Place::Idle(mut slot)) = self
                    .conns
                    .replace_with(id, |place| (Place::Leased(leased), place))
                else {
                    unreachable!("just found idle");
                };
                let ConnSlot::Open(conn) = &mut slot else {
                    unreachable!("an idle connection is open");
                };
                conn.use_ = Use::Leased(NonZeroU32::MIN);
                return Ok(Some(Took::Lease(ConnLease {
                    id,
                    conn: Some(slot),
                    home: here.clone(),
                })));
            }
            Err(sick) => {
                if let Some(why) = sick {
                    if let Some(old) = why {
                        notes.try_push(old)?;
                    }
                    notes.try_push(PoolNote::Dead(number))?;
                }
                notes.try_push(PoolNote::Closed(number))?;
                close(&mut self.conns, id, Evicted::Linger, exits, now);
            }
        }
        Ok(None)
    }

    /// A key to the attached connection `id`, from `here`, if the transfer
    /// may share it and it takes one more (`url_match_multiplex_needs`,
    /// `url_match_multiplex_limits`).
    fn join_if(
        &mut self,
        id: ConnId,
        here: &Home,
        wanted: &Wanted<'_>,
        notes: &mut Vec<PoolNote>,
        seen: &mut Seen,
    ) -> Result<Option<ConnLease>, OutOfMemory> {
        let Some(Place::Attached(shared)) = self.conns.get(id) else {
            unreachable!("just found attached");
        };
        // Not looked at, as C's `url_match_connect_config` comes first.
        if shared.conn().number.get() < self.stale_below {
            return Ok(None);
        }
        if !judged(join_verdict(shared.conn(), wanted), notes, seen)? {
            return Ok(None);
        }
        Ok(Some(self.join_attached(id, here)))
    }

    /// What each of `share`'s connections lent to this multi would make
    /// of the transfer `wanted` describes, for the search of the share's
    /// pool to judge them by in its order.
    pub(crate) fn lending(
        &self,
        share: &Share,
        wanted: &Wanted<'_>,
    ) -> Result<LentCandidates, OutOfMemory> {
        let mut lent = Vec::new();
        for l in self.lent.iter().filter(|l| l.share.is(share)) {
            lent.try_push((l.id, join_verdict(l.shared.conn(), wanted)))?;
        }
        Ok(LentCandidates { lent })
    }

    /// A key to `share`'s connection `id`, lent to this multi, for one
    /// more transfer, the search of the share's pool having found it takes
    /// the transfer.
    pub(crate) fn join_lent(&mut self, share: &Share, id: ConnId) -> ConnLease {
        let l = self.lent_mut(share, id).expect("found lent");
        let conn = l.shared.conn_mut();
        let Use::Leased(n) = conn.use_ else {
            unreachable!("a lent connection is leased");
        };
        conn.use_ = Use::Leased(n.checked_add(1).expect("a count of transfers fits"));
        conn.served = true;
        ConnLease {
            id,
            conn: l.shared.slot.take(),
            home: Home::Share(share.clone()),
        }
    }

    /// The connection `share`'s `id` names, if it is lent here.
    fn lent_mut(&mut self, share: &Share, id: ConnId) -> Option<&mut Lent> {
        self.lent
            .iter_mut()
            .find(|l| l.id == id && l.share.is(share))
    }

    /// The lent connection `lease`, a share's, is a key to, if it is one.
    fn lent_of(&self, lease: &ConnLease) -> Option<&Lent> {
        self.lent_at(lease).map(|at| &self.lent[at])
    }

    /// Where among those lent here the connection `lease` is a key to is.
    fn lent_at(&self, lease: &ConnLease) -> Option<usize> {
        let Home::Share(share) = &lease.home else {
            return None;
        };
        self.lent
            .iter()
            .position(|l| l.id == lease.id && l.share.is(share))
    }

    /// The share's connection `lease` holds, up and leased by it alone,
    /// found to multiplex: kept here while it does, the lease a key to it
    /// from now on, naming it as before. Its place in the share's pool is
    /// to say it is lent (`Pool::lend`).
    pub(crate) fn borrow(&mut self, lease: &mut ConnLease) -> Result<(), OutOfMemory> {
        let Home::Share(share) = &lease.home else {
            panic!("{:?} is not a share's", lease.id);
        };
        let ConnSlot::Open(conn) = lease.slot() else {
            panic!("{:?} is not up", lease.id);
        };
        assert_eq!(conn.use_, Use::Leased(NonZeroU32::MIN), "one lease");
        let route = conn.route.clone();
        let share = share.clone();
        self.lent.try_reserve(1)?;
        let slot = lease.conn.take().expect("held until given back");
        // Room made first: the slot is not lost to a refusal.
        let pushed = self.lent.try_push(Lent {
            shared: Shared {
                slot: Some(slot),
                route,
            },
            share,
            id: lease.id,
        });
        pushed.expect("room was made");
        Ok(())
    }

    /// The connection `id`, leased from this share's pool, is lent to a
    /// multi: transfers of that multi alone join it.
    pub(crate) fn lend(&mut self, id: ConnId) {
        let Some(Place::Leased(leased)) = self.conns.get_mut(id) else {
            panic!("{id:?} is not leased");
        };
        assert!(!leased.lent, "{id:?} is lent already");
        leased.lent = true;
    }

    /// A key to a share's connection lent here given back: one transfer
    /// less on it, and if it was the last, the connection leased as any
    /// by the lease the share's pool takes back, out of its place here.
    /// A lease not lent here is the share's to take back as it is.
    pub(crate) fn release_lent(&mut self, lease: ConnLease) -> LentBack {
        let Some(at) = self.lent_at(&lease) else {
            return LentBack::Last(lease);
        };
        let (id, slot, home) = lease.into_parts();
        assert!(slot.is_none(), "a key's connection is in its place");
        let conn = self.lent[at].shared.conn_mut();
        let Use::Leased(n) = conn.use_ else {
            unreachable!("a lent connection is leased");
        };
        if let Some(fewer) = NonZeroU32::new(n.get() - 1) {
            conn.use_ = Use::Leased(fewer);
            return LentBack::InUse(fewer);
        }
        let l = self.lent.swap_remove(at);
        LentBack::Last(ConnLease {
            id,
            conn: l.shared.slot,
            home,
        })
    }

    /// The network changed (`Curl_cpool_nw_changed`): no connection
    /// made before is reused, and each no transfer uses is closed now,
    /// as C closes those it can; one reserved for its handle stays.
    pub(crate) fn network_changed(&mut self, exits: &mut dyn Exits, now: Instant) {
        self.stale_below = self.next_number;
        let mut cursor = None;
        while let Some(id) = self.conns.next_after(cursor) {
            cursor = Some(id);
            if let Some(Place::Idle(_)) = self.conns.get(id) {
                close(&mut self.conns, id, Evicted::Linger, exits, now);
            }
        }
    }

    /// Discard every connection no one leases (`Curl_cpool_destroy`):
    /// each shut down once, and kept by the multi's set behind `exits`
    /// if that does not finish; one reserved for its handle is closed at
    /// once.
    pub(crate) fn close_idle(&mut self, exits: &mut dyn Exits, now: Instant) {
        let mut cursor = None;
        while let Some(id) = self.conns.next_after(cursor) {
            cursor = Some(id);
            match self.conns.get(id) {
                Some(Place::Idle(_)) => close(&mut self.conns, id, Evicted::Linger, exits, now),
                Some(Place::Reserved(_)) => {
                    self.close_reserved(id, exits, now);
                }
                Some(Place::Leased(_) | Place::Attached(_)) | None => {}
            }
        }
    }

    /// The connection `id`, reserved for its handle, if the pool still
    /// has it there.
    pub(crate) fn reserved_mut(&mut self, id: ConnId) -> Option<&mut Conn> {
        match self.conns.get_mut(id)? {
            Place::Reserved(ConnSlot::Open(conn)) => Some(conn),
            Place::Reserved(_) => unreachable!("a reserved connection is open"),
            Place::Idle(_) | Place::Leased(_) | Place::Attached(_) => None,
        }
    }

    /// Close the connection `id` reserved for its handle, at once, as C
    /// closes one whose use it cannot know (`Curl_conn_close`, aborted):
    /// its number, if the pool still had it there.
    pub(crate) fn close_reserved(
        &mut self,
        id: ConnId,
        exits: &mut dyn Exits,
        now: Instant,
    ) -> Option<ConnNumber> {
        if !matches!(self.conns.get(id), Some(Place::Reserved(_))) {
            return None;
        }
        let Some(Place::Reserved(ConnSlot::Open(conn))) = self.conns.remove(id) else {
            unreachable!("a reserved connection is open");
        };
        let number = conn.number;
        let left = self.conns.len();
        discard(conn, true, false, left, exits, now);
        Some(number)
    }

    /// The socket of the connection `id`, if the pool holds it, idle or
    /// reserved (`Curl_getconnectinfo`).
    pub(crate) fn socket(&self, id: ConnId) -> Option<SocketKey> {
        match &self.conns.get(id)?.held()?.transport {
            Transport::Tcp(stream) => Some(stream.socket().key()),
            Transport::Local => None,
        }
    }

    /// Take a lease back and decide the connection's fate as
    /// `multi_done_locked` does: kept idle if its protocol allows reuse
    /// and the transfer finished with it, else closed. A connection kept
    /// may leave the pool over its limit (`cpool_conn_now_idle`). The
    /// lease must be from `here`, the pool this is.
    pub(crate) fn release(
        &mut self,
        here: &Home,
        lease: ConnLease,
        finish: Finish,
        limit: Limit,
        exits: &mut dyn Exits,
        now: Instant,
    ) -> Released {
        let (id, slot, home) = lease.into_parts();
        assert!(
            home.is(here),
            "a lease on {id:?} from {home:?} given back to {here:?}"
        );
        let mut slot = match slot {
            Some(slot) => {
                assert!(
                    matches!(self.conns.get(id), Some(Place::Leased(_))),
                    "a lease on {id:?}, which the pool no longer has"
                );
                slot
            }
            // A key: the connection is in its place. Another's still
            // there, it stays (`CONN_INUSE`); the last decides its fate.
            None => match self.detach(id) {
                Some(slot) => slot,
                None => {
                    let Some(Place::Attached(shared)) = self.conns.get(id) else {
                        unreachable!("just detached from");
                    };
                    let Use::Leased(in_use) = shared.conn().use_ else {
                        unreachable!("an attached connection is leased");
                    };
                    return Released::InUse(in_use);
                }
            },
        };
        if let ConnSlot::Open(conn) = &mut slot
            && let Route::Tcp(tcp) = &conn.route
            // One only connected is the handle's, whatever its protocol.
            && (tcp.origin.scheme().reuse || finish.reserve)
            // An HTTP/2 connection outlives a stream cut short
            // (`Curl_conn_is_multiplex`).
            && (!finish.premature || conn.is_h2())
            // Forbidden its reuse, it is kept all the same for the request
            // Negotiate's handshake makes again on it.
            && (!finish.forbid_reuse || conn.negotiating())
            && !conn.close
        {
            assert_eq!(conn.use_, Use::Leased(NonZeroU32::MIN), "one lease");
            conn.use_ = Use::Idle {
                since: now,
                checked_ms: ms_since_made(conn, now),
            };
            conn.served = true;
            let number = conn.number;
            *self.conns.get_mut(id).expect("checked above") = match finish.reserve {
                true => Place::Reserved(slot),
                false => Place::Idle(slot),
            };
            return match over_limit(&mut self.conns, limit, Evicted::of(here), exits, now) {
                Some((full, closed)) if closed == Some(id) => Released::Evicted(full),
                full => Released::Idle {
                    number,
                    full: full.map(|(full, _)| full),
                },
            };
        }
        self.conns.remove(id);
        let number = match slot {
            ConnSlot::Connecting(m) => {
                let number = m.number();
                m.close(exits.parts().0);
                number
            }
            ConnSlot::Open(conn) => {
                // An aborted transfer's connection is not shut down
                // (`cpool_discard_conn`).
                let number = conn.number;
                let left = self.conns.len();
                discard(conn, finish.premature, true, left, exits, now);
                number
            }
            ConnSlot::Failed(number) => number,
        };
        if finish.premature {
            Released::Terminated(number)
        } else {
            Released::Closed(number)
        }
    }

    /// Make the connection `lease` holds, up and leased by it alone, one
    /// that multiplexes: it goes to its place, and the lease becomes a
    /// key to it, as C attaches a transfer to a connection others may
    /// join.
    pub(crate) fn attach(&mut self, lease: &mut ConnLease) {
        let id = lease.id;
        assert!(!self.is_attached(lease), "{id:?} is attached already");
        let slot = lease.conn.take().expect("held until given back");
        let ConnSlot::Open(conn) = &slot else {
            panic!("{id:?} is not up");
        };
        assert_eq!(conn.use_, Use::Leased(NonZeroU32::MIN), "one lease");
        let route = conn.route.clone();
        let place = self.conns.get_mut(id).expect("leased from this pool");
        assert!(matches!(place, Place::Leased(_)), "{id:?} is not leased");
        *place = Place::Attached(Shared {
            slot: Some(slot),
            route,
        });
    }

    /// Keep what a lease's step left its connection as, for others'
    /// searches: whether it is up and takes one request at a time, its
    /// transfer having found what it speaks if `settled`. Whether it was
    /// found to, just now: a transfer waiting for it to multiplex waits
    /// no more (`Curl_multi_connchanged`).
    /// The lease must be from `here`, the pool this is.
    pub(crate) fn settle(&mut self, here: &Home, lease: &ConnLease, settled: bool) -> bool {
        assert!(
            lease.home.is(here),
            "{:?} settled in another pool",
            lease.id
        );
        let Some(Place::Leased(leased)) = self.conns.get_mut(lease.id) else {
            return false;
        };
        let conn = lease.conn.as_ref().and_then(ConnSlot::open);
        let verdict = Verdict::of(conn, settled);
        let single = verdict == Verdict::Single && leased.verdict == Verdict::Pending;
        leased.verdict = verdict;
        single
    }

    /// Whether `lease` is a key to a connection in its place here, one
    /// that multiplexes: only the multi's own pool has them, its own and
    /// those lent to it.
    pub(crate) fn is_attached(&self, lease: &ConnLease) -> bool {
        match lease.home {
            Home::Multi => matches!(self.conns.get(lease.id), Some(Place::Attached(_))),
            Home::Share(_) => self.lent_of(lease).is_some(),
        }
    }

    /// The place a key's connection is in here, its own or a lent one.
    fn shared_mut(&mut self, lease: &ConnLease) -> &mut Shared {
        let id = lease.id;
        match &lease.home {
            Home::Share(share) => {
                &mut self
                    .lent_mut(share, id)
                    .expect("a key to a lent connection")
                    .shared
            }
            Home::Multi => match self.conns.get_mut(id) {
                Some(Place::Attached(shared)) => shared,
                _ => panic!("a key to {id:?}, which is not attached"),
            },
        }
    }

    /// A key to the connection `id`, attached, for one more transfer, from
    /// `here`, the pool this is: the connection out with the key, for the
    /// joining transfer's step.
    fn join_attached(&mut self, id: ConnId, here: &Home) -> ConnLease {
        let Some(Place::Attached(shared)) = self.conns.get_mut(id) else {
            panic!("{id:?} is not attached");
        };
        let conn = shared.conn_mut();
        let Use::Leased(n) = conn.use_ else {
            unreachable!("an attached connection is leased");
        };
        conn.use_ = Use::Leased(n.checked_add(1).expect("a count of transfers fits"));
        // Another's request is on it: the joining one reuses it.
        conn.served = true;
        // Out with the step that joined it.
        ConnLease {
            id,
            conn: shared.slot.take(),
            home: here.clone(),
        }
    }

    /// One transfer less on the attached connection `id`: the connection,
    /// leased as any by the lease going back, if that was its last, out
    /// of its place.
    fn detach(&mut self, id: ConnId) -> Option<ConnSlot> {
        let Some(Place::Attached(shared)) = self.conns.get_mut(id) else {
            panic!("a key to {id:?}, which is not attached");
        };
        let conn = shared.conn_mut();
        let Use::Leased(n) = conn.use_ else {
            unreachable!("an attached connection is leased");
        };
        if let Some(fewer) = NonZeroU32::new(n.get() - 1) {
            conn.use_ = Use::Leased(fewer);
            return None;
        }
        let Some(Place::Attached(shared)) = self.conns.replace_with(id, |place| {
            let Place::Attached(shared) = &place else {
                unreachable!("just found attached");
            };
            let leased = Leased {
                route: shared.route.clone(),
                number: shared.conn().number,
                verdict: Verdict::Pending,
                lent: false,
            };
            (Place::Leased(leased), place)
        }) else {
            unreachable!("just found attached");
        };
        shared.slot
    }

    /// Take the connection a key names out of its place, for its
    /// transfer's step or its release, unless it has it out already; a
    /// lease that holds its connection holds it already. Another step
    /// having it out is a bug.
    pub(crate) fn check_out(&mut self, lease: &mut ConnLease) {
        if lease.conn.is_some() || !self.is_attached(lease) {
            return;
        }
        let slot = self.shared_mut(lease).slot.take();
        lease.conn = Some(slot.expect("out with another step"));
    }

    /// A key to the connection `lease` has out in its step, for a
    /// transfer the server pushes on it: one more user, found by no search
    /// (`Curl_multi_add_perform`'s `Curl_attach_connection`). A connection
    /// of the multi's own not attached yet is from now, and stays out with
    /// the step; a share's is not pushed on, as push is offered on the
    /// multi's own alone.
    pub(crate) fn pushed(&mut self, lease: &mut ConnLease) -> ConnLease {
        assert!(
            !matches!(lease.home, Home::Share(_)),
            "a share's connection is not pushed on"
        );
        if !self.is_attached(lease) {
            self.attach(lease);
            self.check_out(lease);
        }
        let conn = lease.get();
        let Use::Leased(n) = conn.use_ else {
            unreachable!("an attached connection is leased");
        };
        conn.use_ = Use::Leased(n.checked_add(1).expect("a count of transfers fits"));
        ConnLease {
            id: lease.id,
            conn: None,
            home: lease.home.clone(),
        }
    }

    /// Put the connection a key's step had out back in its place, if it
    /// had it out.
    pub(crate) fn check_in(&mut self, lease: &mut ConnLease) {
        if !self.is_attached(lease) {
            return;
        }
        let id = lease.id;
        // Given back outside a step, as an abandoned transfer's is, a key
        // has nothing out.
        let Some(slot) = lease.conn.take() else {
            return;
        };
        let shared = self.shared_mut(lease);
        assert!(shared.slot.is_none(), "{id:?} is in its place already");
        shared.slot = Some(slot);
    }

    /// The connection a lease names, wherever it is: with the lease, or,
    /// for a key, in its place; none while another transfer's step has it
    /// out, as a sibling the stepping transfer delivers to asks.
    pub(crate) fn slot_of<'a>(&'a self, lease: &'a ConnLease) -> Option<&'a ConnSlot> {
        if let Some(slot) = &lease.conn {
            return Some(slot);
        }
        if let Home::Share(_) = lease.home {
            let lent = self.lent_of(lease).expect("a key to a lent connection");
            return lent.shared.slot.as_ref();
        }
        let Some(Place::Attached(shared)) = self.conns.get(lease.id) else {
            panic!("a key to {:?}, which is not attached", lease.id);
        };
        shared.slot.as_ref()
    }

    /// Connections in the pool, busy or idle.
    pub(crate) fn len(&self) -> u32 {
        self.conns.len()
    }

    /// Leases out, between steps: one for each connection leased, and
    /// one for each transfer on a connection attached.
    #[cfg(debug_assertions)]
    pub(crate) fn leased(&self) -> usize {
        let mut leased = 0;
        let mut cursor = None;
        while let Some(id) = self.conns.next_after(cursor) {
            cursor = Some(id);
            leased += match self.conns.get(id) {
                Some(Place::Leased(_)) => 1,
                Some(Place::Attached(shared)) => match shared.conn().use_ {
                    Use::Leased(n) => n.get() as usize,
                    Use::Idle { .. } => unreachable!("an attached connection is leased"),
                },
                _ => 0,
            };
        }
        leased
    }
}

/// What the connection `conn`, which multiplexes, makes of the transfer
/// `wanted` describes (`url_match_multiplex_needs`,
/// `url_match_multiplex_limits`).
fn join_verdict(conn: &Conn, wanted: &Wanted<'_>) -> JoinVerdict {
    if conn.close || !conn.serves(wanted.route) {
        return JoinVerdict::Passed;
    }
    let Some(max) = wanted.multiplex else {
        return JoinVerdict::Seen;
    };
    if !conn.serves_auth(&wanted.auth) || !wanted.versions.h2 {
        return JoinVerdict::Seen;
    }
    let Use::Leased(users) = conn.use_ else {
        unreachable!("a connection that multiplexes is leased");
    };
    let peer_max = conn.h2().map_or(u32::MAX, |h2| h2.max_concurrent());
    if users >= max || users.get() >= peer_max {
        return JoinVerdict::Full {
            number: conn.number,
            users: users.get(),
            peer: users < max,
        };
    }
    JoinVerdict::Join
}

/// Whether the transfer joins a connection that made `verdict` of it,
/// what the search saw of it in `seen` and its notes said.
fn judged(
    verdict: JoinVerdict,
    notes: &mut Vec<PoolNote>,
    seen: &mut Seen,
) -> Result<bool, OutOfMemory> {
    match verdict {
        JoinVerdict::Passed => Ok(false),
        JoinVerdict::Seen => {
            seen.multiplex = true;
            Ok(false)
        }
        JoinVerdict::Full {
            number,
            users,
            peer,
        } => {
            seen.multiplex = true;
            notes.try_push(PoolNote::Full {
                number,
                users,
                peer,
            })?;
            Ok(false)
        }
        JoinVerdict::Join => {
            seen.multiplex = true;
            notes.try_push(PoolNote::Multiplexed)?;
            Ok(true)
        }
    }
}

/// Whether a transfer on `route` looks for an idle connection to reuse:
/// only over a network, and only unless it must have a fresh one.
pub(crate) fn searches(route: &Route, rules: ReuseRules) -> bool {
    matches!(route, Route::Tcp(..)) && !rules.fresh
}

/// How many connections a pool keeps once one goes idle
/// (`CURLMOPT_MAXCONNECTS`); with none set, a guess from the transfers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limit {
    pub(crate) max: Option<NonZeroU32>,
    /// The transfers in the multi (`Curl_multi_xfers_attached`).
    pub(crate) attached: u32,
}

/// With more connections than `limit` keeps, close the idle one longest
/// unused (`cpool_conn_now_idle`, `cpool_get_oldest_idle`). Without a
/// limit set, the pool keeps twice the transfers, and closes only a
/// connection idle for a second.
fn over_limit(
    conns: &mut Arena<Place, ConnSlot>,
    limit: Limit,
    evicted: Evicted,
    exits: &mut dyn Exits,
    now: Instant,
) -> Option<(Full, Option<ConnId>)> {
    let (max, min_idle_ms) = match limit.max {
        Some(max) => (max.get(), 0),
        None => (limit.attached.saturating_mul(2), 1000),
    };
    if max == 0 || max == u32::MAX {
        return None;
    }
    let mut count = 0;
    let mut oldest = None;
    let mut cursor = None;
    while let Some(id) = conns.next_after(cursor) {
        cursor = Some(id);
        let Some(place) = conns.get(id) else {
            continue;
        };
        if let Some(Conn {
            use_: Use::Idle { since, .. },
            ..
        }) = place.idle()
        {
            // In C's milliseconds: of two as old, the first.
            let idle_ms = now.since(*since).as_millis();
            if idle_ms >= min_idle_ms && oldest.is_none_or(|(_, ms)| idle_ms > ms) {
                oldest = Some((id, idle_ms));
            }
        }
        count += 1;
    }
    if count <= max {
        return None;
    }
    let closed = oldest.map(|(id, _)| id);
    if let Some(id) = closed {
        close(conns, id, evicted, exits, now);
    }
    Some((Full { conns: count, max }, closed))
}

/// Make room for a connection to `to` within `limits`
/// (`cpool_check_limits`): past either limit, close the idle connections
/// longest unused, first among those to the same destination, then the
/// oldest shutting down in the multi's set, which count toward both; why
/// there is none, if there is not. The closes trace nowhere, as C's go to
/// its internal handle.
fn make_room(
    conns: &mut Arena<Place, ConnSlot>,
    to: &Peer,
    limits: AddLimits,
    evicted: Evicted,
    exits: &mut dyn Exits,
    now: Instant,
) -> Option<WaitReason> {
    let to_host = |place: &Place| place.destination().is_some_and(|d| d.same_bundle(to));
    if let Some(max) = limits.max_host {
        let max = max.get();
        let mut live = count(conns, to_host);
        if live >= max {
            for _ in max..=live {
                let Some(id) = oldest_idle(conns, to_host, now) else {
                    break;
                };
                close(conns, id, evicted, exits, now);
            }
            live = count(conns, to_host);
        }
        let shutdowns = shutdowns_over(exits, Some(to), live, max);
        if live + shutdowns >= max {
            return Some(WaitReason::HostLimit);
        }
    }
    if let Some(max) = limits.max_total {
        let any = |_: &Place| true;
        let live = count(conns, any);
        for _ in max.get()..=live {
            let Some(id) = oldest_idle(conns, any, now) else {
                break;
            };
            close(conns, id, evicted, exits, now);
        }
        let live = count(conns, any);
        let shutdowns = shutdowns_over(exits, None, live, max.get());
        if live + shutdowns >= max.get() {
            return Some(WaitReason::TotalLimit(max));
        }
    }
    None
}

/// The connections shutting down in the multi's set (to `to`, if given)
/// that are left once those past `max`, with the `live` ones, are closed,
/// oldest first (`Curl_cshutdn_dest_count`, `Curl_cshutdn_count`,
/// `Curl_cshutdn_close_oldest`).
fn shutdowns_over(exits: &mut dyn Exits, to: Option<&Peer>, live: u32, max: u32) -> u32 {
    let (net, linger) = exits.parts();
    let Some(linger) = linger else {
        return 0;
    };
    let set = linger.set;
    let mut shutdowns = match to {
        Some(to) => set.count_to(to),
        None => u32::try_from(set.len()).expect("a set's size fits"),
    };
    if shutdowns > 0 && live + shutdowns >= max {
        let over = live + shutdowns - max + 1;
        shutdowns -= set.close_oldest(to, over, net);
    }
    shutdowns
}

/// The connections `which` picks, busy, idle or being set up. A failed
/// setup is counted until its lease is given back, as C counts a
/// connection until its transfer is done.
fn count(conns: &Arena<Place, ConnSlot>, which: impl Fn(&Place) -> bool) -> u32 {
    let mut n = 0;
    let mut cursor = None;
    while let Some(id) = conns.next_after(cursor) {
        cursor = Some(id);
        if conns.get(id).is_some_and(&which) {
            n += 1;
        }
    }
    n
}

/// The idle connection `which` picks that has been unused longest; of
/// two as old in C's milliseconds, the first (`cpool_get_oldest_idle`,
/// `cpool_bundle_get_oldest_idle`).
fn oldest_idle(
    conns: &Arena<Place, ConnSlot>,
    which: impl Fn(&Place) -> bool,
    now: Instant,
) -> Option<ConnId> {
    let mut oldest: Option<(ConnId, u128)> = None;
    let mut cursor = None;
    while let Some(id) = conns.next_after(cursor) {
        cursor = Some(id);
        if let Some(place) = conns.get(id)
            && let Some(Conn {
                use_: Use::Idle { since, .. },
                ..
            }) = place.idle()
            && which(place)
        {
            let idle_ms = now.since(*since).as_millis();
            if oldest.is_none_or(|(_, ms)| idle_ms > ms) {
                oldest = Some((id, idle_ms));
            }
        }
    }
    oldest.map(|(id, _)| id)
}

/// Close the idle connections that are not healthy, saying nothing: C's
/// prune traces to its internal handle (`cpool_prune_dead`).
fn prune(
    conns: &mut Arena<Place, ConnSlot>,
    stale_below: u64,
    rules: ReuseRules,
    exits: &mut dyn Exits,
    now: Instant,
) {
    let mut cursor = None;
    while let Some(id) = conns.next_after(cursor) {
        cursor = Some(id);
        if let Some(conn) = conns.get_mut(id).and_then(Place::idle_mut)
            && let Use::Idle { since, .. } = conn.use_
            && (conn.number.get() < stale_below || health(conn, since, rules, now).is_err())
        {
            close(conns, id, Evicted::Linger, exits, now);
        }
    }
}

/// What becomes of an idle connection a pool evicts to make room
/// (`cpool_evict_conn`): a multi's goes as any it closes, into the
/// multi's set if it shuts down slowly; a share's pool, which no multi
/// owns, closes it after one try of its shutdown.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Evicted {
    Linger,
    Closed,
}

impl Evicted {
    fn of(here: &Home) -> Evicted {
        match here {
            Home::Multi => Evicted::Linger,
            Home::Share(_) => Evicted::Closed,
        }
    }
}

/// Discard the idle connection `id` names (`cpool_conn_close`, or
/// `cpool_evict_conn` as `evicted` says).
fn close(
    conns: &mut Arena<Place, ConnSlot>,
    id: ConnId,
    evicted: Evicted,
    exits: &mut dyn Exits,
    now: Instant,
) {
    match conns.remove(id) {
        Some(Place::Idle(slot)) => match slot {
            ConnSlot::Open(conn) => {
                let left = conns.len();
                discard(conn, false, evicted == Evicted::Linger, left, exits, now);
            }
            _ => unreachable!("an idle connection is open"),
        },
        Some(Place::Leased(_)) => panic!("{id:?} is leased"),
        Some(Place::Reserved(_)) => panic!("{id:?} is reserved"),
        Some(Place::Attached(_)) => panic!("{id:?} is attached"),
        None => unreachable!("closing {id:?}, which the pool no longer has"),
    }
}

/// Whether an idle connection may be reused
/// (`Curl_cpool_conn_seems_healthy`): not idle or alive too long, and with
/// nothing to read, as an idle HTTP/1 connection must not have (RFC 9112,
/// section 9.2) and a closed one has.
fn health(
    conn: &mut Conn,
    idle_since: Instant,
    rules: ReuseRules,
    now: Instant,
) -> Result<(), Option<PoolNote>> {
    let idle = now.since(idle_since);
    if let Some(max) = rules.max_idle
        && past(idle, max)
    {
        return Err(Some(PoolNote::IdleTooLong {
            idle_ms: whole_ms(idle),
            max_ms: whole_ms(max),
        }));
    }
    // Only the prune meets one alive too long here, and says nothing.
    if rules
        .max_age
        .is_some_and(|max| past(now.since(conn.created), max))
    {
        return Err(None);
    }
    // A multiplexed one is looked at once a second at most, healthy
    // meanwhile; an HTTP/1 one's input is polled at every reuse
    // (`Curl_cpool_conn_seems_healthy`), each in whole milliseconds since
    // the connection was made, as C counts them.
    if let Use::Idle { checked_ms, .. } = conn.use_
        && conn.is_h2()
        && whole_ms(now.since(conn.created)).saturating_sub(checked_ms.into()) < 1000
    {
        return Ok(());
    }
    let healthy = alive(conn, now);
    let made_ms = ms_since_made(conn, now);
    if healthy.is_ok()
        && let Use::Idle { checked_ms, .. } = &mut conn.use_
    {
        *checked_ms = made_ms;
    }
    healthy
}

/// The whole milliseconds from `conn`'s making to `now`, as C keeps its
/// times of use; `u32::MAX` past its range.
fn ms_since_made(conn: &Conn, now: Instant) -> u32 {
    u32::try_from(whole_ms(now.since(conn.created))).unwrap_or(u32::MAX)
}

/// Whether `conn`'s socket is alive and has no input it should not.
fn alive(conn: &mut Conn, now: Instant) -> Result<(), Option<PoolNote>> {
    let Transport::Tcp(stream) = &mut conn.transport else {
        return Ok(());
    };
    // Input waiting is unhealthy too, on an idle HTTP/1 connection; on
    // an HTTP/2 one it is the peer's frames, which its session reads
    // (`http2_connisalive`).
    match stream.is_alive(&mut Silent(now)) {
        Alive::Alive {
            input_pending: false,
        } => Ok(()),
        Alive::Alive {
            input_pending: true,
        } if conn.is_h2() => {
            if conn.h2_stray_input(&mut Silent(now)) {
                Ok(())
            } else {
                Err(None)
            }
        }
        Alive::Alive {
            input_pending: true,
        }
        | Alive::Dead => Err(None),
    }
}

/// Whether `elapsed` is past the limit `max`, counted in whole
/// milliseconds as C counts them (`age_ms > conn_max_idle_ms`).
fn past(elapsed: Duration, max: Duration) -> bool {
    whole_ms(elapsed) > whole_ms(max)
}

fn whole_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
