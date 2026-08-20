//! Gateway-side QUIC boundary: the Retry transaction, the per-gateway
//! connection state machine, and the sockaddr<->path conversions the
//! adapter deliberately does not own.
//!
//! One gateway serves ONE client. The transaction states are
//! `awaiting_initial` → `retry_sent` → `candidate_uncommitted` →
//! `handshaking_committed` (slot committed; ServerHello held or sent;
//! awaiting confirmation) → `established`. Commit happens exactly once,
//! before publication. Pre-commit failure retires the candidate and
//! returns to `retry_sent` with the slot still usable to its absolute
//! expiry; after commit, any fatal error retires and exits — the slot
//! is never reused. No application bytes move over QUIC here: Q3 owns
//! the stream preface and roles, so readable pre-Q3 stream data closes
//! the connection (counted, no frozen error code).
//!
//! Secrets: the PSK is held as the single owned copy, wiped in `deinit`
//! after the transports die. The address-validation token secret is
//! derived locally (frozen salt/info), installed into the policy, and
//! the local original is wiped the moment construction finishes — the
//! policy keeps the sole copy and its `deinit` wipes it. Each issued
//! token uses a fresh random nonce; a matching retransmission reuses
//! the stored Retry and its nonce verbatim.

const std = @import("std");
const quicz = @import("quicz");
const quic_transport = @import("quic_transport.zig");
const udp = @import("udp.zig");
const lib_posix = @import("posix.zig");

const log = std.log.scoped(.quic_gateway);

const Transport = quic_transport.Transport;

/// Retry lifetime and the absolute handshake deadline (frozen).
pub const retry_lifetime_ns: i64 = 10 * std.time.ns_per_s;
pub const handshake_deadline_ns: i64 = 10 * std.time.ns_per_s;
/// One-second QUIC keepalive after confirmation (frozen).
pub const keepalive_interval_ns: i64 = 1 * std.time.ns_per_s;
/// Per-turn bounds: floods defer to the next turn, never starving
/// signals or deadlines.
pub const max_inbound_per_turn: usize = 64;
pub const max_outbound_per_turn: usize = 64;

/// Which pool a send draws from. Ordinary output — including Retry —
/// stops one slot short of the turn budget; the final slot serves
/// deadline-critical output (daemon-close on EOF, otherwise due-PTO
/// and keepalive), so a flood of ordinary output can never starve a
/// due probe or the close frame.
pub const SendClass = enum { ordinary, reserved };

/// The one outbound budget every send site in a loop turn shares.
pub const TurnBudget = struct {
    outbound: usize = max_outbound_per_turn,

    /// One decrement per attempted send, exactly once.
    pub fn take(self: *TurnBudget, class: SendClass) bool {
        const floor: usize = if (class == .ordinary) 1 else 0;
        if (self.outbound <= floor) return false;
        self.outbound -= 1;
        return true;
    }
};

/// Plan Q1: the address-validation token secret is HKDF-SHA256 of the
/// bootstrap secret with salt `zmosh quic token v1`, expanded with
/// info `zmosh-address-validation-v1`. The PRK is wiped by an
/// immediate defer.
pub fn deriveTokenSecret(out: *[32]u8, bootstrap_secret: *const [32]u8) void {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    var prk = HkdfSha256.extract("zmosh quic token v1", bootstrap_secret);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&prk));
    HkdfSha256.expand(out, "zmosh-address-validation-v1", prk);
}

/// Address conversion lives in udp.zig (the network layer's single
/// source of truth); re-exported here for the existing call sites.
pub const sockaddrToUdpAddress = udp.sockaddrToUdpAddress;
pub const udpAddressToSockaddr = udp.udpAddressToSockaddr;

const GatewayRecord = struct {
    transport: *Transport,

    fn connectionOf(record: *GatewayRecord) *quicz.Connection {
        return record.transport.connection();
    }

    fn deinit(record: *GatewayRecord) void {
        record.transport.destroy();
    }
};

const GatewayRegistry = quicz.EndpointConnectionRegistry(
    GatewayRecord,
    GatewayRecord.connectionOf,
    GatewayRecord.deinit,
);

pub const State = enum {
    awaiting_initial,
    retry_sent,
    candidate_uncommitted,
    handshaking_committed,
    established,
    closed,
};

/// Diagnostics: counters and durations only — never session content.
pub const Counters = struct {
    datagrams_received: usize = 0,
    datagrams_sent: usize = 0,
    datagrams_discarded: usize = 0,
    challenges_issued: usize = 0,
    handshakes_confirmed: usize = 0,
};

pub const QuicGateway = struct {
    alloc: std.mem.Allocator,
    /// Randomness interface for SCIDs, nonces, and challenges.
    io: std.Io,
    /// One owned PSK copy, wiped in `deinit` after the transports die.
    psk: [32]u8,
    policy: quicz.endpoint.AddressValidationPolicy,
    slot: quicz.pending_retry_slot.PendingRetrySlot = .{},
    registry: GatewayRegistry,
    /// This gateway's Retry SCID: regenerated only after slot expiry or
    /// a new exchange — never after an authentication rollback, since
    /// the slot stays usable.
    retry_scid: [4]u8,
    /// The pre-generated unpredictable migration challenge, replaced
    /// only after quicz reports it queued.
    challenge: [8]u8,
    /// The first flight's original DCID as this gateway observed it
    /// when issuing the Retry — the candidate's stored exchange needs
    /// it, and the follow-up datagram no longer carries it.
    exchange_odcid: [8]u8,
    state: State = .awaiting_initial,
    /// The stable local socket identity: getsockname on the wildcard
    /// bind yields 0.0.0.0/:: — identical for route registration and
    /// arrival construction, so routing matches. It is NOT the
    /// per-packet destination (no IP_PKTINFO in Q2).
    local: quicz.endpoint.UdpAddress,
    /// Absolute handshake deadline anchor: the moment the success
    /// bootstrap line was emitted. Never extended across retries.
    bootstrap_emitted_ns: i64,
    counters: Counters = .{},
    handshake_duration_ns: i64 = 0,
    /// Advanced ONLY by an actual successful send.
    last_output_ns: i64 = 0,
    /// Set while one keepalive PING is queued and not yet emitted.
    keepalive_queued: bool = false,
    /// The last keepalive ATTEMPT (queued or not): a queued-but-unsent
    /// PING is retried a full second later — never busy-looped, never
    /// duplicated.
    keepalive_attempt_ns: i64 = 0,
    /// Cleared when the owner's loop should exit.
    running: bool = true,

    pub fn init(
        alloc: std.mem.Allocator,
        io: std.Io,
        psk: *const [32]u8,
        token_secret: *const [32]u8,
        local: quicz.endpoint.UdpAddress,
        bootstrap_emitted_ns: i64,
    ) !QuicGateway {
        // The token secret's local original dies with this frame; the
        // policy owns the sole retained copy and its deinit wipes it.
        var policy = quicz.endpoint.AddressValidationPolicy.init(alloc, token_secret.*, .{});
        errdefer policy.deinit();
        var registry = try GatewayRegistry.initWithCapacity(alloc, 1);
        errdefer registry.deinit();
        var retry_scid: [4]u8 = undefined;
        io.random(&retry_scid);
        var challenge: [8]u8 = undefined;
        io.random(&challenge);
        return .{
            .alloc = alloc,
            .io = io,
            .exchange_odcid = .{0} ** 8,
            .psk = psk.*,
            .policy = policy,
            .registry = registry,
            .retry_scid = retry_scid,
            .challenge = challenge,
            .local = local,
            .bootstrap_emitted_ns = bootstrap_emitted_ns,
        };
    }

    /// Exactly-once cleanup: retire the adopted candidate if present
    /// (through the one fail-closed helper — best-effort here, since
    /// teardown cannot propagate), release the registry and the policy
    /// (whose deinit wipes its token secret), then wipe the owned PSK.
    pub fn deinit(self: *QuicGateway) void {
        if (self.hasCandidate()) {
            self.retireCandidate() catch {};
        }
        self.registry.deinit();
        self.policy.deinit();
        std.crypto.secureZero(u8, &self.psk);
    }

    fn candidate(self: *QuicGateway) *GatewayRecord {
        return self.registry.records.get(1).?;
    }

    fn hasCandidate(self: *const QuicGateway) bool {
        return self.state == .candidate_uncommitted or
            self.state == .handshaking_committed or
            self.state == .established;
    }

    /// Receive up to `max_inbound_per_turn` datagrams and dispatch by
    /// transaction state. Returns false when the gateway should exit.
    pub fn receive(self: *QuicGateway, sock: *udp.UdpSocket, now: i64, budget: *TurnBudget) !bool {
        var received: usize = 0;
        while (received < max_inbound_per_turn) : (received += 1) {
            var buf: [quic_transport.max_udp_payload]u8 = undefined;
            const r = sock.recvFrom(&buf) catch |err| switch (err) {
                error.WouldBlock => return self.running,
                else => return err,
            };
            self.counters.datagrams_received += 1;
            const remote = sockaddrToUdpAddress(r.addr) orelse {
                self.counters.datagrams_discarded += 1;
                continue;
            };
            const arrival = quicz.endpoint.UdpTuple{ .local = self.local, .remote = remote };
            try self.dispatch(sock, arrival, r.addr, buf[0..r.len], now, budget);
            if (!self.running) return false;
        }
        return self.running;
    }

    fn dispatch(
        self: *QuicGateway,
        sock: *udp.UdpSocket,
        arrival: quicz.endpoint.UdpTuple,
        src: lib_posix.Address,
        data: []const u8,
        now: i64,
        budget: *TurnBudget,
    ) !void {
        switch (self.state) {
            .awaiting_initial, .retry_sent => try self.handleInitial(sock, arrival, src, data, now, budget),
            .candidate_uncommitted, .handshaking_committed, .established => {
                const transport = self.candidate().transport;
                if (try transport.handleDatagram(arrival, now, data, &self.challenge)) {
                    self.io.random(&self.challenge);
                    self.counters.challenges_issued += 1;
                }
                try self.drainCandidate(sock, now, budget);
                if (!self.running) return;
                if (self.state != .established and transport.handshakeConfirmed()) {
                    self.handshake_duration_ns = now - self.bootstrap_emitted_ns;
                    self.counters.handshakes_confirmed += 1;
                    self.state = .established;
                    // HANDSHAKE_DONE lets the client confirm too. The
                    // output stamp is NOT advanced here: only a
                    // successful send stamps it, so this queued frame
                    // and the keepalive schedule stay honest until it
                    // actually leaves.
                    try transport.connection().sendHandshakeDone();
                    log.info("quic handshake confirmed duration_ns={d}", .{self.handshake_duration_ns});
                }
                // Established application streams are dispatched by the
                // QuicSession (serve.Gateway-owned), not here.
            },
            .closed => self.counters.datagrams_discarded += 1,
        }
    }

    fn handleInitial(
        self: *QuicGateway,
        sock: *udp.UdpSocket,
        arrival: quicz.endpoint.UdpTuple,
        src: lib_posix.Address,
        data: []const u8,
        now: i64,
        budget: *TurnBudget,
    ) !void {
        const supported = [_]quicz.packet.Version{.v1};
        const accept = (quicz.endpoint.peekInitialAcceptDatagram(arrival, data, &supported) catch {
            self.counters.datagrams_discarded += 1;
            return;
        }) orelse {
            self.counters.datagrams_discarded += 1;
            return;
        };
        // The frozen v1 client CID shapes this gateway accepts: the
        // client SCID is 4 bytes on every Initial; a tokenless first
        // flight carries the 8-byte original DCID, while the
        // token-bearing follow-up's DCID IS the 4-byte Retry SCID.
        if (accept.source_connection_id.len != 4 or
            (accept.token.len == 0 and accept.original_destination_connection_id.len != 8))
        {
            self.counters.datagrams_discarded += 1;
            return;
        }
        const decision = self.slot.classify(
            &self.policy,
            now,
            arrival,
            accept.version,
            accept.original_destination_connection_id,
            accept.source_connection_id,
            &self.retry_scid,
            accept.token,
            data.len,
            true,
        ) catch |err| switch (err) {
            error.RetryExpired => {
                // Empty or expired slot with a tokenless Initial: a
                // fresh exchange. Invalid traffic never resets state.
                if (accept.token.len != 0) {
                    self.counters.datagrams_discarded += 1;
                    return;
                }
                return self.openExchange(sock, arrival, src, accept, now, budget);
            },
            // classify never allocates: every other failure is
            // network-data-driven.
            else => {
                self.counters.datagrams_discarded += 1;
                return;
            },
        };
        switch (decision) {
            // Matching retransmission: the STORED Retry and its nonce
            // are reused verbatim without extending the expiry.
            .send_retry => |view| _ = try self.sendRetryView(sock, view, src, budget),
            .validated => try self.adoptValidated(sock, arrival, accept, data, now, budget),
        }
    }

    fn openExchange(
        self: *QuicGateway,
        sock: *udp.UdpSocket,
        arrival: quicz.endpoint.UdpTuple,
        src: lib_posix.Address,
        accept: anytype,
        now: i64,
        budget: *TurnBudget,
    ) !void {
        // A fresh random nonce for every newly issued token.
        var nonce: quicz.address_validation_token.Nonce = undefined;
        self.io.random(&nonce);
        const token = try self.policy.issueTokenForPath(
            self.alloc,
            .retry,
            now,
            @intCast(retry_lifetime_ns),
            arrival,
            nonce,
        );
        // The slot stores its own copy; the issued allocation dies here.
        defer self.alloc.free(token);
        const view = self.slot.open(
            self.alloc,
            now,
            retry_lifetime_ns,
            arrival,
            accept.version,
            accept.original_destination_connection_id,
            accept.source_connection_id,
            &self.retry_scid,
            token,
        ) catch {
            self.counters.datagrams_discarded += 1;
            return;
        };
        self.exchange_odcid = accept.original_destination_connection_id[0..8].*;
        _ = try self.sendRetryView(sock, view, src, budget);
        self.state = .retry_sent;
    }

    fn adoptValidated(
        self: *QuicGateway,
        sock: *udp.UdpSocket,
        arrival: quicz.endpoint.UdpTuple,
        accept: anytype,
        data: []const u8,
        now: i64,
        budget: *TurnBudget,
    ) !void {
        // The candidate's token comes from the expiry-aware slot
        // accessor — a fixed owned source, never the reusable receive
        // buffer.
        const token = self.slot.storedToken(now) orelse {
            self.counters.datagrams_discarded += 1;
            return;
        };
        const transport = try Transport.createServerCandidate(self.alloc, .{
            .psk = &self.psk,
            .retry_scid = self.retry_scid,
            .original_dcid = self.exchange_odcid,
            .client_scid = accept.source_connection_id[0..4].*,
            .token = token,
            .now_nanos = now,
        });
        // From a successful registry.adopt onward the REGISTRY owns
        // the record and the transport; these errdefers are disarmed
        // so no post-adoption failure can free what the registry
        // holds (the round-3 `ex_owned` pattern).
        var adopted = false;
        errdefer if (!adopted) transport.destroy();
        try transport.registerRoute(arrival.local, arrival.remote);
        const record = try self.alloc.create(GatewayRecord);
        errdefer if (!adopted) self.alloc.destroy(record);
        record.* = .{ .transport = transport };
        self.registry.adopt(1, record) catch {
            self.alloc.destroy(record);
            transport.destroy();
            self.counters.datagrams_discarded += 1;
            return;
        };
        adopted = true;
        self.state = .candidate_uncommitted;

        // Authenticate the follow-up Initial. A failure (wrong PSK,
        // binder mismatch) rolls back THROUGH THE REGISTRY; the slot
        // remains usable to its absolute expiry and the Retry SCID is
        // unchanged.
        _ = transport.handleDatagram(arrival, now, data, &self.challenge) catch {
            try self.rollbackCandidate();
            return;
        };
        transport.driveCrypto(.initial, now) catch {
            try self.rollbackCandidate();
            return;
        };

        // Hold the ServerHello, commit the slot exactly once, then
        // publish it. After commit the slot cannot be reused: a lost
        // ServerHello recovers through QUIC PTO, and any later fatal
        // error retires and exits.
        const sh = (transport.pollOutbound(now) catch {
            try self.rollbackCandidate();
            return;
        }) orelse {
            try self.rollbackCandidate();
            return;
        };
        self.slot.commit(&self.policy, now, token) catch {
            self.alloc.free(sh);
            try self.rollbackCandidate();
            return;
        };
        self.state = .handshaking_committed;
        const sh_sent = self.sendOwned(sock, sh, arrival.remote, budget, .ordinary) catch {
            // Post-commit fatal: retire and exit — never retry_sent.
            try self.retireCandidate();
            self.state = .closed;
            self.running = false;
            log.err("post-commit ServerHello send failed; gateway exiting", .{});
            return;
        };
        if (sh_sent) self.last_output_ns = now;
    }

    /// Retire the adopted candidate through the registry. On failure
    /// the record's ownership is uncertain: fail CLOSED — stop the
    /// gateway and propagate; `retry_sent` is never entered.
    fn retireCandidate(self: *QuicGateway) !void {
        _ = self.registry.retire(self.candidate().transport.lifecycle, 1) catch {
            self.state = .closed;
            self.running = false;
            log.err("candidate retirement failed; failing closed", .{});
            return error.RetireFailed;
        };
    }

    /// Pre-commit rollback: successful retirement returns to
    /// `retry_sent` with the slot and Retry SCID still live for this
    /// exchange.
    fn rollbackCandidate(self: *QuicGateway) !void {
        try self.retireCandidate();
        self.state = .retry_sent;
        self.counters.datagrams_discarded += 1;
    }

    /// The owned-send core, generic over a sendTo-compatible sender
    /// (tests drive the WouldBlock branch with a fake). The budget is
    /// consulted FIRST — an unsendable class never reaches the socket
    /// — and the datagram is freed after every attempt. WouldBlock
    /// drops the bytes and QUIC recovery retransmits; the counter
    /// counts real sends only.
    fn sendOwnedVia(
        self: *QuicGateway,
        sender: anytype,
        dg: []u8,
        remote: quicz.endpoint.UdpAddress,
        budget: *TurnBudget,
        class: SendClass,
    ) !bool {
        defer self.alloc.free(dg);
        if (!budget.take(class)) return false;
        // Any sender-specific non-WouldBlock failure propagates —
        // never silently swallowed.
        sender.sendTo(dg, udpAddressToSockaddr(remote)) catch |err| {
            if (err == error.WouldBlock) return false;
            return err;
        };
        self.counters.datagrams_sent += 1;
        return true;
    }

    fn sendOwned(
        self: *QuicGateway,
        sock: *udp.UdpSocket,
        dg: []u8,
        remote: quicz.endpoint.UdpAddress,
        budget: *TurnBudget,
        class: SendClass,
    ) !bool {
        return self.sendOwnedVia(sock, dg, remote, budget, class);
    }

    /// The Retry datagram is a BORROWED slot view: never freed; on
    /// WouldBlock the slot retains it and a matching retransmission
    /// reissues the same bytes. Ordinary class — a Retry flood stops
    /// one slot short like every other ordinary send.
    fn sendRetryView(
        self: *QuicGateway,
        sock: *udp.UdpSocket,
        view: []const u8,
        src: lib_posix.Address,
        budget: *TurnBudget,
    ) !bool {
        if (!budget.take(.ordinary)) return false;
        sock.sendTo(view, src) catch |err| switch (err) {
            error.WouldBlock => return false,
            else => return err,
        };
        self.counters.datagrams_sent += 1;
        return true;
    }

    /// Bounded outbound drain, ordinary class only: the loop guard
    /// checks the budget BEFORE each poll (an unsendable emission is
    /// never even built), and each datagram is path-tagged by the
    /// atomic egress API. `last_output_ns` advances and the pending
    /// keepalive flag clears ONLY on actual sends — the flag clears
    /// exactly when a sent datagram reported `emitted_ping`.
    fn drainCandidate(self: *QuicGateway, sock: *udp.UdpSocket, now: i64, budget: *TurnBudget) !void {
        if (!self.hasCandidate()) return;
        const transport = self.candidate().transport;
        try transport.driveCrypto(.initial, now);
        try transport.driveCrypto(.handshake, now);
        while (budget.outbound > 1) {
            const tagged = (try transport.pollOutboundPath(now)) orelse break;
            if (try self.sendOwned(sock, tagged.dg, tagged.dst.remote, budget, .ordinary)) {
                self.last_output_ns = now;
                if (tagged.emitted_ping) self.keepalive_queued = false;
            }
        }
    }

    /// The borrowed established transport, or null outside the
    /// established state. The registry owns its lifetime: the session
    /// consuming it must treat it as borrowed and stop at `running ==
    /// false` or state changes. This gateway stays CONNECTION LIFECYCLE
    /// ONLY — application stream dispatch lives in quic_session.zig,
    /// driven by serve.Gateway.
    pub fn establishedTransport(self: *QuicGateway) ?*quic_transport.Transport {
        if (self.state != .established) return null;
        return self.candidate().transport;
    }

    /// Bounded egress drain for the session's stream output: whatever
    /// the application queued into quicz leaves in THIS turn, without
    /// waiting for the next inbound datagram or a PTO.
    pub fn drainEgress(self: *QuicGateway, sock: *udp.UdpSocket, now: i64, budget: *TurnBudget) !void {
        return self.drainCandidate(sock, now, budget);
    }

    /// ONE reserved-class emission: deadline-critical output — here a
    /// queued keepalive PING ordinary output could not send — may take
    /// the final slot of the turn budget.
    fn drainOneReserved(self: *QuicGateway, sock: *udp.UdpSocket, now: i64, budget: *TurnBudget) !void {
        if (!self.hasCandidate() or budget.outbound == 0) return;
        const tagged = (try self.candidate().transport.pollOutboundPath(now)) orelse return;
        if (try self.sendOwned(sock, tagged.dg, tagged.dst.remote, budget, .reserved)) {
            self.last_output_ns = now;
            if (tagged.emitted_ping) self.keepalive_queued = false;
        }
    }

    /// Daemon EOF: queue a CONNECTION_CLOSE and attempt it through
    /// the RESERVED class — ordinary output stopped one slot short,
    /// so no prior flood can consume the slot the close needs — then
    /// terminate. Total output this turn stays within the budget.
    pub fn closeForDaemonExit(self: *QuicGateway, sock: *udp.UdpSocket, now: i64, budget: *TurnBudget) !void {
        defer {
            self.state = .closed;
            self.running = false;
        }
        if (!self.hasCandidate()) return;
        const transport = self.candidate().transport;
        transport.shutdown(0, "daemon closed") catch return;
        transport.driveCrypto(.initial, now) catch return;
        transport.driveCrypto(.handshake, now) catch return;
        while (budget.outbound > 0) {
            const tagged = (try transport.pollOutboundPath(now)) orelse break;
            _ = try self.sendOwned(sock, tagged.dg, tagged.dst.remote, budget, .reserved);
        }
    }

    /// Service due QUIC work with no fd readable. Returns false when
    /// the gateway should exit.
    pub fn serviceDue(self: *QuicGateway, sock: *udp.UdpSocket, now: i64, budget: *TurnBudget) !bool {
        if (self.hasCandidate()) {
            const transport = self.candidate().transport;
            switch (try transport.serviceDueDeadline(now)) {
                .datagram => |tagged| {
                    // Deadline-critical output: the reserved class can
                    // take the final slot.
                    if (try self.sendOwned(sock, tagged.dg, tagged.dst.remote, budget, .reserved)) {
                        self.last_output_ns = now;
                        if (tagged.emitted_ping) self.keepalive_queued = false;
                    }
                },
                .idle_retired, .close_retired => {
                    // The lifecycle already retired the routes: DROP
                    // the record (remove, not retire) and terminate.
                    self.registry.remove(1) catch {};
                    self.state = .closed;
                    self.running = false;
                },
                .no_output => {},
            }
        }
        // Slot expiry: the next tokenless Initial is a fresh exchange
        // with a new Retry SCID.
        if (self.state == .retry_sent and self.slot.occupied and now >= self.slot.expires_nanos) {
            self.state = .awaiting_initial;
            self.io.random(&self.retry_scid);
        }
        // The absolute handshake deadline, anchored at bootstrap
        // emission and never extended. Retirement goes through the
        // one fail-closed helper.
        if (self.state != .established and self.state != .closed and
            now - self.bootstrap_emitted_ns >= handshake_deadline_ns)
        {
            if (self.hasCandidate()) try self.retireCandidate();
            self.state = .closed;
            self.running = false;
            log.info("quic handshake deadline exceeded; gateway exiting", .{});
        }
        // One-second keepalive. A new PING is queued only when none is
        // pending AND capacity exists — an unsendable PING is never
        // queued — and the queued PING may take the FINAL slot through
        // the reserved class when ordinary output has stopped one
        // short.
        if (self.state == .established and self.running) {
            const due_from = if (self.keepalive_queued) self.keepalive_attempt_ns else self.last_output_ns;
            if (now - due_from >= keepalive_interval_ns) {
                if (!self.keepalive_queued and budget.outbound > 0) {
                    self.candidate().transport.connection().sendPing() catch |e| switch (e) {
                        // The application session already closed the
                        // connection: there is nothing left to keep
                        // alive and no PING to queue.
                        error.ConnectionClosed => {},
                        else => return e,
                    };
                    self.keepalive_queued = true;
                }
                self.keepalive_attempt_ns = now;
                try self.drainCandidate(sock, now, budget);
                if (self.keepalive_queued and budget.outbound == 1) {
                    try self.drainOneReserved(sock, now, budget);
                }
            }
        }
        return self.running;
    }

    /// The earliest QUIC deadline: transport recovery/idle/close, slot
    /// expiry, the absolute handshake deadline, and the keepalive
    /// schedule once established (`last_output_ns + 1s`, or
    /// `keepalive_attempt_ns + 1s` while a PING is queued and unsent).
    pub fn nextDeadline(self: *const QuicGateway) ?i64 {
        var next: ?i64 = null;
        if (self.hasCandidate()) next = self.candidateConst().transport.nextDeadlineNanos();
        if (self.state == .retry_sent and self.slot.occupied) {
            next = minDeadline(next, self.slot.expires_nanos);
        }
        if (self.state != .established and self.state != .closed) {
            next = minDeadline(next, self.bootstrap_emitted_ns + handshake_deadline_ns);
        }
        if (self.state == .established) {
            const due_from = if (self.keepalive_queued) self.keepalive_attempt_ns else self.last_output_ns;
            next = minDeadline(next, due_from + keepalive_interval_ns);
        }
        return next;
    }

    fn candidateConst(self: *const QuicGateway) *GatewayRecord {
        return self.registry.records.get(1).?;
    }

    fn minDeadline(a: ?i64, b: i64) ?i64 {
        return if (a) |x| @min(x, b) else b;
    }
};

// ─── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

/// A sendTo-compatible sender whose socket never accepts a datagram.
const WouldBlockSender = struct {
    fn sendTo(_: @This(), _: []const u8, _: lib_posix.Address) !void {
        return error.WouldBlock;
    }
};

test "sendOwnedVia on WouldBlock: freed, uncounted, budget decremented once" {
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);
    var token_secret: [32]u8 = undefined;
    deriveTokenSecret(&token_secret, &psk);
    defer std.crypto.secureZero(u8, &token_secret);

    var gw = try QuicGateway.init(
        testing.allocator,
        testing.io,
        &psk,
        &token_secret,
        quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, 60000),
        0,
    );
    defer gw.deinit();

    // The datagram is freed on the drop (the testing allocator fails
    // the test on any leak), the counter never moves, and the budget
    // is decremented exactly once.
    var budget = TurnBudget{};
    const dg = try testing.allocator.alloc(u8, 64);
    try testing.expect(!try gw.sendOwnedVia(
        WouldBlockSender{},
        dg,
        quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, 60001),
        &budget,
        .reserved,
    ));
    try testing.expectEqual(@as(usize, max_outbound_per_turn - 1), budget.outbound);
    try testing.expectEqual(@as(usize, 0), gw.counters.datagrams_sent);

    // The refused class never reaches the sender: an ordinary send at
    // the floor keeps the reserved slot intact.
    const floor = try testing.allocator.alloc(u8, 64);
    var at_floor = TurnBudget{ .outbound = 1 };
    try testing.expect(!try gw.sendOwnedVia(
        WouldBlockSender{},
        floor,
        quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, 60001),
        &at_floor,
        .ordinary,
    ));
    try testing.expectEqual(@as(usize, 1), at_floor.outbound);
}
