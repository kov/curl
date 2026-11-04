//! What a step works with: the transfer, its handle and the engine's rest,
//! and what the connection's layers ask of them.

use super::*;
use crate::conn::io::SocketsClosed;

/// A layer working for the stepping transfer traces as it does, keeps
/// its failures and reports to it, and a QUIC connection receives in the
/// multi's room and sets the transfer's timer. No stream is the step's
/// own to hear of: a request's call on its connection hears them
/// (`H3Step`).
impl<H: Host> LayerCx for StepCx<'_, H> {
    fn now(&self) -> Instant {
        self.rest.now
    }

    fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
        Some(self)
    }

    fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
        Some(self)
    }

    fn transfer(&mut self) -> Option<&mut dyn crate::conn::layer::ForTransfer> {
        Some(self)
    }

    /// A multi always has one.
    fn tls_sessions(&mut self) -> Option<&mut dyn crate::conn::layer::TlsSessions> {
        Some(self)
    }

    fn early_data(&mut self) -> Option<&mut dyn crate::conn::layer::EarlyData> {
        Some(self)
    }

    fn quic_timer(&mut self) -> Option<&mut dyn crate::conn::layer::QuicTimer> {
        Some(self)
    }

    fn h3_streams(&mut self) -> Option<&mut dyn crate::conn::layer::H3Streams> {
        None
    }

    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
        Some(&mut *self.rest.sockbuf)
    }
}

impl<H: Host> crate::conn::layer::Trace for StepCx<'_, H> {
    fn line(&mut self, component: Component, line: std::fmt::Arguments<'_>) {
        trace::of(self, component, line);
    }

    fn line_with(&mut self, component: Component, parts: &[&[u8]]) {
        trace::of_with(self, component, parts);
    }

    fn info_line(&mut self, line: std::fmt::Arguments<'_>) {
        trace::info(self, line);
    }

    fn info_line_with(&mut self, parts: &[&[u8]]) {
        trace::info_with(self, parts);
    }

    fn says_info(&self) -> bool {
        self.easy().options().output.verbose
    }

    fn traces(&self, component: Component) -> bool {
        trace::traces(self, component)
    }
}

impl<H: Host> crate::conn::layer::Failures for StepCx<'_, H> {
    fn keep(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
        trace::fail(self, kind, why)
    }

    fn keep_with(&mut self, kind: ErrorKind, parts: &[&[u8]]) -> ErrorKind {
        trace::fail_with(self, kind, parts)
    }

    fn keep_errno(&mut self, e: &std::io::Error) {
        self.report_mut().socket_failed(e);
    }
}

impl<H: Host> crate::conn::layer::ForTransfer for StepCx<'_, H> {
    fn debug_bytes(&mut self, kind: crate::handler::DebugKind, bytes: &[u8]) {
        trace::bytes(self, kind, bytes);
    }

    fn has_debug_handler(&self) -> bool {
        let options = self.easy().options();
        options.callbacks.debug.is_some() && options.output.verbose
    }

    fn certinfo_report(&mut self) -> Option<&mut TransferReport> {
        let asked = self.easy().options().tls.certinfo;
        asked.then(|| self.report_mut())
    }

    fn peer_verified(&mut self, filter: Component, result: i64) {
        if matches!(filter, Component::SslProxy | Component::H3Proxy) {
            self.report_mut().set_proxy_verify_result(result);
        } else {
            self.report_mut().set_verify_result(result);
        }
    }

    fn has_tls_handler(&self) -> bool {
        self.easy().options().tls.options.context.is_some()
    }

    /// The handler is given the context, which the transfer's handlers
    /// reach meanwhile as its connection's (`CURLINFO_TLS_SESSION`).
    fn hand_tls_context(&mut self, native: TlsNative) -> Result<(), ErrorKind> {
        let Some(handler) = self.easy().options().tls.options.context.clone() else {
            return Ok(());
        };
        let lent = self.lent.replace(native);
        let configured = handler.configure(&mut TransferCx::new(self), native);
        self.lent = lent;
        configured
    }

    fn stop_recv(&mut self) {
        let slot = self.rest.tell.slots.get_mut(self.me);
        slot.expect("the stepping transfer").pause.stop_recv();
    }

    fn seconds_since_1970(&self) -> i64 {
        self.rest.clock.unix_time()
    }
}

impl<H: Host> crate::conn::layer::EarlyData for StepCx<'_, H> {
    fn early_sent(&mut self, sent: i64) {
        self.report_mut().set_earlydata_sent(sent);
    }

    fn connected_late(&mut self) {
        let now = self.now();
        let marked = self.report_mut().timings_mut().mark(Timer::AppConnect, now);
        mstate::marked(self, Timer::AppConnect, marked);
    }
}

impl<H: Host> StepCx<'_, H> {
    /// The server has `left` to answer, in whole milliseconds, from now:
    /// the `SERVER_RESPONSE` timer is armed for it as the step ends, and
    /// said to be now (`Curl_expire`, as `Curl_pp_statemach` drives
    /// without blocking).
    pub(crate) fn server_response_in(&mut self, left: Duration) {
        let ms = left.as_millis();
        let at = self
            .now()
            .after(Duration::from_millis(u64::try_from(ms).unwrap_or(u64::MAX)));
        self.server_response_at = Some(at);
        if trace::traces(self, Component::Timer) {
            let us = ms.saturating_mul(1000);
            trace_timer(
                self,
                TimerKind::ServerResponse,
                format_args!("set for {us}us"),
            );
        }
    }
}

impl<H: Host> crate::conn::layer::QuicTimer for StepCx<'_, H> {
    fn due_in(&mut self, wait: Duration) {
        let at = self.rest.clock.now().after(wait);
        self.quic_at = Some(at);
        trace_set(self, TimerKind::Quic, at);
    }
}

impl<H: Host> crate::conn::layer::TlsSessions for StepCx<'_, H> {
    /// The share's if it keeps them (`cf_ssl_scache_get`), what it says
    /// held until its lock is let go, as nothing is called out from inside
    /// a share's lock; else the multi's, lent out of the multi for the
    /// call, so the context traces through while `f` holds it.
    fn with_cache(
        &mut self,
        f: &mut dyn FnMut(&mut crate::tls::SessionCache, &mut dyn crate::conn::layer::SessionSays),
    ) {
        use crate::share::watched;
        if let Some(kept) = self.rest.kept(self.me, Kind::SslSessions) {
            let mut held = HeldSays {
                traces: trace::traces(self, Component::Ssls),
                lines: Vec::new(),
                failure: None,
            };
            watched(kept.watch(), &kept.share, Kind::SslSessions, || {
                // Gone since it was chosen, it is no cache.
                if let Some(cache) = kept.share.sessions().as_mut() {
                    f(cache, &mut held);
                }
            });
            for line in &held.lines {
                trace::of_with(self, Component::Ssls, &[line]);
            }
            if let Some((kind, why)) = held.failure {
                trace::fail_with(self, kind, &[&why]);
            }
            return;
        }
        let none = crate::tls::SessionCache::new(0);
        let mut own = std::mem::replace(&mut self.rest.caches.sessions, none);
        f(&mut own, self);
        self.rest.caches.sessions = own;
    }
}

/// The context of a use of a share's TLS sessions under its lock: what
/// the use traces and fails with is held, to be said once the lock is let
/// go. A line it has no memory to hold is not said.
pub(in crate::multi) struct HeldSays {
    /// The transfer traces the cache's lines (`ssls`).
    pub(in crate::multi) traces: bool,
    pub(in crate::multi) lines: Vec<Vec<u8>>,
    pub(in crate::multi) failure: Option<(ErrorKind, Vec<u8>)>,
}

impl crate::conn::layer::SessionSays for HeldSays {
    fn say_line(&mut self, component: Component, line: std::fmt::Arguments<'_>) {
        if self.traces
            && component == Component::Ssls
            && let Ok(line) = curl_alloc::try_format(line)
        {
            // Without memory to hold it, the line is not said, as a line
            // too long for the trace is cut.
            let _ = self.lines.try_push(line.into_bytes());
        }
    }

    fn say_failure(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
        if self.failure.is_none()
            && let Ok(why) = curl_alloc::try_format(why)
        {
            self.failure = Some((kind, why.into_bytes()));
        }
        kind
    }
}

/// What a step needs: the transfer it steps, whose `Run` is out of its
/// slot, and the rest of the multi.
pub(crate) struct StepCx<'a, H: Host> {
    pub(crate) me: TransferId,
    pub(in crate::multi) rest: EngineRest<'a, H>,
    /// The TLS library's objects of the connection the transfer holds,
    /// lent for the step, whose run is out of reach of its handlers
    /// (`TransferCx::tls_native`).
    pub(super) lent: Option<TlsNative>,
    /// When the QUIC library asked the step to call it again, the
    /// transfer's `QUIC` timer once the step is over.
    pub(crate) quic_at: Option<Instant>,
    /// When the server's time to answer runs out, as the step's line
    /// protocol last drove its back and forth: the transfer's
    /// `SERVER_RESPONSE` timer once the step is over.
    pub(crate) server_response_at: Option<Instant>,
    /// What a second connection's setup, as the step last moved it on,
    /// asks of the transfer's timers once the step is over.
    pub(crate) side_due: SideDue,
    /// The chain of the connection the step is working on, which its
    /// filters' lines name (`cf->sockindex`).
    pub(super) rank: ConnRank,
    /// The connection a WebSocket's transfer holds, lent while its
    /// output is delivered and its upload read: its handlers send frames
    /// on it, and its frames' state is read and kept there. The one
    /// exception to decision 9 (ENGINE.md): what reaches it is only
    /// `TransferCx`'s WebSocket calls.
    ws: Option<crate::conn::WsLend<'a>>,
}

impl<H: Host> StepCx<'_, H> {
    /// The chain the lines said now belong to.
    pub(crate) fn rank(&self) -> ConnRank {
        self.rank
    }

    /// How many of the multi's transfers are added and not yet completed,
    /// this one among them (`xfers_alive`).
    pub(crate) fn running(&self) -> u32 {
        self.rest.tell.counts.get().running
    }

    /// Run `f`, its work the connection's second chain's: its filters'
    /// lines name it, and no others do.
    pub(crate) fn as_second<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let was = std::mem::replace(&mut self.rank, ConnRank::Second);
        let r = f(self);
        self.rank = was;
        r
    }
}

impl<'a, H: Host> StepCx<'a, H> {
    /// The connection's TLS objects as the step changed them, lent for
    /// the rest of it.
    pub(in crate::multi) fn lend(&mut self, native: Option<TlsNative>) {
        self.lent = native;
    }

    pub(crate) fn new(me: TransferId, rest: EngineRest<'a, H>) -> StepCx<'a, H> {
        StepCx {
            me,
            rest,
            lent: None,
            quic_at: None,
            server_response_at: None,
            side_due: SideDue::default(),
            rank: ConnRank::First,
            ws: None,
        }
    }
}

impl<H: Host> StepCx<'_, H> {
    /// Run `f` with transfer `id`'s step context and its HTTP request, its
    /// run out of its slot meanwhile, as the stepping transfer hands it
    /// what the connection they share did for it (ENGINE.md 4.4); the
    /// connection's TLS objects, the same, are lent to it, and it is
    /// marked dirty, to run when its turn next comes, as C marks it
    /// (`Curl_multi_mark_dirty`). None if it is gone or makes no HTTP
    /// request.
    pub(crate) fn with_sibling<R>(
        &mut self,
        id: TransferId,
        f: impl FnOnce(&mut StepCx<'_, H>, &mut crate::proto::http::Request) -> R,
    ) -> Option<R> {
        let slot = self.rest.tell.slots.get_mut(id)?;
        // Only the stepping transfer's run is out while a connection is
        // read or written.
        let mut run = slot.run.take().expect("a sibling's run is in its slot");
        let lent = self.lent;
        let r = match run.state.attached_mut().map(|x| &mut x.proto) {
            Some(ProtoState::Http(req)) => {
                let mut cx = StepCx::new(id, self.rest.reborrow());
                cx.lent = lent;
                Some(f(&mut cx, req))
            }
            _ => None,
        };
        super::super::put_back(self.rest.tell.slots, self.rest.dirty, id, run);
        self.rest.dirty.insert(id.index());
        r
    }

    /// Run `f` with a WebSocket's connection lent to the step, for its
    /// handlers to send frames on and its output to be decoded with.
    pub(crate) fn lending_ws<R>(
        &mut self,
        conn: crate::conn::WsLend<'_>,
        f: impl FnOnce(&mut StepCx<'_, H>) -> R,
    ) -> R {
        assert!(self.ws.is_none(), "one connection lent at a time");
        let mut cx = StepCx {
            me: self.me,
            rest: self.rest.reborrow(),
            lent: self.lent,
            quic_at: self.quic_at,
            server_response_at: self.server_response_at,
            side_due: self.side_due,
            rank: self.rank,
            ws: Some(conn),
        };
        let r = f(&mut cx);
        let (quic_at, server_response_at) = (cx.quic_at, cx.server_response_at);
        self.quic_at = quic_at;
        self.server_response_at = server_response_at;
        self.side_due = cx.side_due;
        r
    }

    /// The WebSocket of the connection lent to the step, if one is.
    pub(crate) fn lent_ws(&mut self) -> Option<&mut crate::proto::ws::WsConn> {
        self.ws.as_mut().map(|l| l.parts().0)
    }

    /// Run `f` with the WebSocket's connection lent to the step, taken
    /// out of it meanwhile, so that `f` has the step too; none if no
    /// connection is lent.
    pub(crate) fn with_ws_conn<R>(
        &mut self,
        f: impl FnOnce(&mut StepCx<'_, H>, &mut crate::conn::WsLend<'_>) -> R,
    ) -> Option<R> {
        let mut conn = self.ws.take()?;
        let r = f(self, &mut conn);
        self.ws = Some(conn);
        Some(r)
    }

    /// Whether the application takes the responses servers push
    /// (`push_cb`).
    pub(crate) fn wants_push(&self) -> bool {
        self.rest.events.wants_push()
    }

    /// Offer the application a response the server promised beside the
    /// stepping transfer's request (`push_promise`): `easy`, made for it,
    /// its URL set. Taken, it is a transfer of the multi's from now, its
    /// run begun by `start` in its own context, as
    /// `Curl_multi_add_perform` takes it to PERFORMING at once.
    pub(crate) fn offer_push(
        &mut self,
        fields: &PushFields,
        easy: Box<Easy>,
        start: impl FnOnce(&mut StepCx<'_, H>, &mut Run) -> Result<(), ErrorKind>,
    ) -> Offered {
        // A multi a callback stopped takes nothing more.
        if *self.rest.tell.life == Life::Dead {
            return Offered::Denied;
        }
        let offer = PushOffer {
            parent: self.me,
            fields,
        };
        let t = &mut self.rest.tell;
        let mut ecx = EventCx {
            alive: &*t.alive,
            slots: &mut *t.slots,
            limits: &mut *t.limits,
            notify: &mut *t.notify,
            counts: t.counts.get(),
            sockets: &mut *t.sockets,
            // The pool is the step's, apart from the multi meanwhile.
            pool: None,
        };
        let (easy, owner) = match self.rest.events.push(&mut ecx, &offer, easy) {
            Pushed::Accepted { easy, owner } => (easy, owner),
            Pushed::Denied => return Offered::Denied,
            Pushed::Failed => return Offered::Failed,
        };
        let rest = &mut self.rest;
        let rows = Rows {
            slots: &mut *rest.tell.slots,
            timers: &mut *rest.timers,
            dirty: &mut *rest.dirty,
            notify: &mut *rest.tell.notify,
        };
        let inserted = super::super::insert(
            rows,
            &mut *rest.tell.counts,
            &mut rest.caches.pool,
            easy,
            super::super::Owner::App(owner),
        );
        let id = match inserted {
            Ok(id) => id,
            Err((refused, owner)) => {
                if let super::super::Owner::App(owner) = owner {
                    rest.events.unpushed(refused.easy, owner);
                }
                trace::info(self, format_args!("failed to add handle to multi"));
                return Offered::Denied;
            }
        };
        rest.dirty.insert(id.index());
        let slot = rest.tell.slots.get(id).expect("just added");
        rest.events
            .added(id, slot.owner.host().expect("the application's own"));
        let slot = rest.tell.slots.get_mut(id).expect("just added");
        let mut run = slot.run.take().expect("a new run in its slot");
        let lent = self.lent;
        let mut cx = StepCx::new(id, self.rest.reborrow());
        // On the stepping transfer's connection.
        cx.lent = lent;
        super::super::trace_membership(&mut cx, "added to");
        let started = start(&mut cx, &mut run);
        super::super::put_back(self.rest.tell.slots, self.rest.dirty, id, run);
        match started {
            Ok(()) => Offered::Added(id),
            // One that could not begin is taken out as the step ends, as
            // it was, its handle closed (`discard_newhandle`), and its
            // stream is refused.
            Err(kind) => {
                let slot = self.rest.tell.slots.get_mut(id).expect("just put back");
                slot.discard = true;
                *self.rest.discards = true;
                // Said by the transfer that heard the promise
                // (`http2_data_setup`'s failure).
                let code = trace::Code(Err(kind));
                trace::fail(self, kind, format_args!("error setting up stream: {code}"));
                Offered::Denied
            }
        }
    }

    /// A key to the connection the stepping transfer's `lease` has out,
    /// for a transfer the server pushes on it. A share's not lent to the
    /// multi yet is lent now, as the step would lend it once done: the
    /// pushed transfer is the multi's, and joins it as C attaches it
    /// (`attached_multi`), unlocked as C sets the connection's field.
    pub(crate) fn pushed_lease(&mut self, lease: &mut ConnLease) -> Result<ConnLease, OutOfMemory> {
        let pool = &mut self.rest.caches.pool;
        if let Home::Share(share) = lease.home()
            && !pool.is_attached(lease)
        {
            let share = share.clone();
            pool.borrow(lease)?;
            share.pool().lend(lease.id());
        }
        Ok(pool.pushed(lease))
    }

    /// Step transfer `id` again in the pass: something it waits on, a
    /// connection it shares, changed.
    pub(crate) fn wake(&mut self, id: TransferId) {
        if self.rest.tell.slots.get(id).is_some() {
            self.rest.dirty.insert(id.index());
        }
    }

    pub(crate) fn easy(&self) -> &Easy {
        &self
            .rest
            .tell
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .easy
    }

    /// The URL the host keeps for the stepping transfer, shared for the
    /// caller's read (`Host::start_url`).
    pub(crate) fn host_start_url(&self) -> Option<crate::url::SharedUrl> {
        let slot = self
            .rest
            .tell
            .slots
            .get(self.me)
            .expect("the stepping transfer");
        slot.owner.host().and_then(H::start_url)
    }
}

impl<H: Host> StepCx<'_, H> {
    pub(crate) fn report_mut(&mut self) -> &mut TransferReport {
        self.rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .easy
            .report_mut()
    }

    /// The streams the multi lets a server open at once on an HTTP/2
    /// connection (`Curl_multi_max_concurrent_streams`).
    pub(crate) fn max_streams(&self) -> u32 {
        self.rest.tell.limits.max_streams.get()
    }

    pub(crate) fn pause(&self) -> Pause {
        self.rest
            .tell
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .pause
    }

    /// The readers C would stack for the request's body.
    pub(crate) fn readers_mut(&mut self) -> &mut Option<Readers> {
        &mut self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .readers
    }

    pub(crate) fn pause_mut(&mut self) -> &mut Pause {
        &mut self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .pause
    }

    pub(crate) fn now(&self) -> Instant {
        self.rest.now
    }

    /// The transfer's time is up, as of the step's start
    /// (`Curl_timeleft_ms` below zero).
    pub(crate) fn time_up(&self) -> bool {
        let limits = self.easy().options().limits;
        let left = Deadlines::new(limits.total, limits.connect).time_left(
            starts(self),
            self.now(),
            Phase::Transferring,
        );
        matches!(left, TimeLeft::Expired(_))
    }

    /// The sockets the transfer's libraries closed: each said, and nothing
    /// waits on it from here on (`Curl_multi_will_close`).
    pub(crate) fn libraries_closed(&mut self) {
        let me = self.me;
        let slot = self.rest.tell.slots.get(me).expect("the stepping transfer");
        let Some(closed) = slot.closed.as_ref().map(SocketsClosed::take) else {
            return;
        };
        for key in closed {
            let fd = key.get();
            mstate::trace(self, format_args!("Curl_multi_will_close fd={fd}"));
            self.rest.announcing(me).will_close(key);
        }
    }

    /// Where the transfer's libraries tell the sockets they close, made
    /// the first time it is asked for.
    pub(crate) fn closed_sockets(&mut self) -> Result<SocketsClosed, OutOfMemory> {
        let me = self.me;
        let slot = self
            .rest
            .tell
            .slots
            .get_mut(me)
            .expect("the stepping transfer");
        if let Some(closed) = &slot.closed {
            return Ok(closed.clone());
        }
        let closed = SocketsClosed::new()?;
        slot.closed = Some(closed.clone());
        Ok(closed)
    }

    /// What is left of the transfer's time, as of the step's start: its
    /// connect limit counts before DO (`Curl_timeleft_ms`).
    pub(crate) fn time_left(&self) -> TimeLeft {
        self.time_left_at(self.now())
    }

    /// What is left of the transfer's time at `now`.
    pub(crate) fn time_left_at(&self, now: Instant) -> TimeLeft {
        let limits = self.easy().options().limits;
        let phase = if self.mstate() < MState::Do {
            Phase::Connecting
        } else {
            Phase::Transferring
        };
        Deadlines::new(limits.total, limits.connect).time_left(starts(self), now, phase)
    }

    /// The calendar time, read now (`time(NULL)`).
    pub(crate) fn unix_time(&self) -> i64 {
        self.rest.clock.unix_time()
    }

    /// Which of the transfer's setups' DNS filters hold an entry of the
    /// cache (`Holds`).
    pub(crate) fn holds_mut(&mut self) -> &mut crate::conn::Holds {
        &mut self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .holds
    }

    pub(crate) fn easy_mut(&mut self) -> &mut Easy {
        &mut self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .easy
    }

    /// The transfer's handle, and the use it makes of the public suffix
    /// list, kept by its share or its multi, if the build has one.
    pub(crate) fn easy_and_suffixes(&mut self) -> (&mut Easy, Option<crate::psl::PslUse<'_>>) {
        let now = self.rest.now;
        let clock = self.rest.clock;
        let multi = &self.rest.caches.psl;
        let easy = &mut *self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .easy;
        let check = easy.libraries().psl.map(|library| {
            let watch = easy.share_watch.as_ref();
            let share = easy.shared(Kind::Psl);
            if let Some(share) = share {
                share.used_under(clock);
            }
            crate::psl::PslUse::new(share, watch, multi, library, now)
        });
        (easy, check)
    }

    pub(crate) fn speedometer_mut(&mut self) -> &mut Speedometer {
        &mut self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .speedometer
    }

    /// The speedometer and the report it writes to.
    pub(crate) fn progress_parts(&mut self) -> (&mut Speedometer, &mut TransferReport) {
        let slot = self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer");
        (&mut slot.speedometer, slot.easy.report_mut())
    }

    /// The speed limits' buckets, with the limits and the pause they are
    /// read with.
    fn rate_parts(&mut self) -> (&mut RateLimits, &Flow, Pause, Instant) {
        let now = self.rest.now;
        let slot = self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer");
        (&mut slot.rate, &slot.easy.options().flow, slot.pause, now)
    }

    /// How many bytes `way` may move now, if it is limited
    /// (`Curl_rlimit_avail`); none while it is paused.
    pub(crate) fn rate_allowance(&mut self, way: Way) -> Option<i64> {
        let (rate, limits, pause, now) = self.rate_parts();
        rate.allowance(way, limits, pause, now)
    }

    /// `n` bytes moved `way`: the limit takes them (`Curl_rlimit_drain`).
    pub(crate) fn rate_drain(&mut self, way: Way, n: usize) {
        let (rate, limits, pause, now) = self.rate_parts();
        rate.drain(way, limits, pause, n, now);
    }

    /// The limit on `way` starts afresh, tuned for `total` bytes if known
    /// (`Curl_rlimit_start`).
    pub(crate) fn rate_start(&mut self, way: Way, total: Option<u64>) {
        let (rate, limits, _, now) = self.rate_parts();
        rate.start(way, limits, now, total);
    }

    /// Whether the limits make the transfer wait (`mspeed_check`).
    pub(super) fn rate_verdict(&mut self) -> Verdict {
        let (rate, limits, pause, now) = self.rate_parts();
        rate.verdict(limits, pause, now)
    }

    pub(crate) fn mark(&mut self, timer: Timer) {
        let now = self.rest.now;
        let marked = self.report_mut().timings_mut().mark(timer, now);
        mstate::marked(self, timer, marked);
    }

    /// As `mark`, at the clock's time now rather than the pass's: C reads
    /// the clock for each mark (`Curl_pgrs_now`), and the queue time is
    /// what passed between two marks of one step.
    pub(crate) fn mark_now(&mut self, timer: Timer) {
        let now = self.rest.clock.now();
        let marked = self.report_mut().timings_mut().mark(timer, now);
        mstate::marked(self, timer, marked);
    }

    /// Where the transfer is in C's states.
    pub(crate) fn mstate(&self) -> MState {
        self.rest
            .tell
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .mstate
    }

    pub(in crate::multi) fn set_mstate(&mut self, state: MState) {
        let slot = self.rest.tell.slots.get_mut(self.me);
        slot.expect("the stepping transfer").mstate = state;
    }
}

impl<H: Host> TransferCalls for StepCx<'_, H> {
    fn me(&self) -> TransferId {
        self.me
    }

    fn own(&self) -> Option<&Easy> {
        Some(self.easy())
    }

    fn census(&self) -> Census {
        let tell = &self.rest.tell;
        super::super::census_of(tell.slots, tell.counts.get())
    }

    fn easy(&self, id: TransferId) -> Option<&Easy> {
        self.rest.tell.slots.app(id).map(|s| &*s.easy)
    }

    fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy> {
        self.rest.tell.slots.app_mut(id).map(|s| &mut *s.easy)
    }

    fn pause(&mut self, id: TransferId, req: PauseRequest) -> Result<(), ErrorKind> {
        super::super::pause_transfer(&mut self.rest, id, req)
    }

    fn fail(&mut self, why: &[u8]) {
        // The kind is the verdict's to decide.
        trace::fail_with(self, ErrorKind::WriteError, &[why]);
    }

    fn ws_send(
        &mut self,
        bytes: &[u8],
        asked: &crate::ws::Asked<'_>,
    ) -> Result<crate::ws::Sent, ErrorKind> {
        crate::proto::http::ws::lent_send(self, bytes, asked)
    }

    fn ws_start_frame(&mut self, asked: &crate::ws::Asked<'_>) -> Result<(), ErrorKind> {
        crate::proto::http::ws::lent_start_frame(self, asked)
    }

    fn ws_recv(&mut self, buf: &mut [u8]) -> Result<crate::ws::Received, ErrorKind> {
        crate::proto::http::ws::lent_recv(self, buf)
    }

    fn ws_meta(&self) -> Option<crate::ws::Meta> {
        if self.easy().options().ws.raw {
            return None;
        }
        Some(self.ws.as_ref()?.ws().meta())
    }

    fn tls_native(&self, id: TransferId) -> Option<TlsNative> {
        let slot = self.rest.tell.slots.app(id)?;
        if id == self.me {
            return self.lent;
        }
        slot.run
            .as_ref()?
            .state
            .tls_native(Some(&self.rest.caches.pool))
    }
}

/// The TLS library's objects of the origin's connection, as its layers
/// answered `LayerQuery::TlsNative`.
pub(crate) fn native_of(answer: Option<LayerAnswer>) -> Option<TlsNative> {
    match answer? {
        LayerAnswer::TlsNative(native) => Some(native),
        LayerAnswer::Alpn(..)
        | LayerAnswer::TlsWaits(_)
        | LayerAnswer::TlsDeferred
        | LayerAnswer::Tunnel(_)
        | LayerAnswer::Failure(_) => {
            unreachable!("an answer of another question")
        }
    }
}

/// Ask a connection, from its filter `top`, what was agreed by ALPN
/// (`Curl_conn_cf_get_alpn_negotiated`), its layers having answered
/// `LayerQuery::Alpn` with `answer`: the filter says it is asked, and the
/// TLS session, if one answers, what it answers; the others answer none,
/// or pass the question on, saying nothing.
pub(crate) fn query_alpn<H: Host>(
    cx: &mut StepCx<'_, H>,
    answer: Option<LayerAnswer>,
    top: Component,
) -> Option<crate::tls::Chosen> {
    trace::of(cx, top, format_args!("query ALPN"));
    // An HTTPS proxy's TLS answers only when asked first: a tunnel's
    // filter above it keeps the question (`cf_h1_proxy_query`).
    if let Some(LayerAnswer::Alpn(chosen, filter)) = answer
        && (filter != Component::SslProxy || top == Component::SslProxy)
    {
        // QUIC's filter answers saying nothing (`cf_ngtcp2_query`).
        if filter != Component::Http3 {
            let name = chosen.map_or("(nil)", crate::tls::Chosen::name);
            let line = format_args!("query ALPN: returning '{name}'");
            trace::of(cx, filter, line);
        }
        return chosen;
    }
    None
}
