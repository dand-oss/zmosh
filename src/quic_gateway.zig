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

/// Convert one kernel sockaddr into the quicz address form. Returns
/// null for non-INET families.
pub fn sockaddrToUdpAddress(addr: lib_posix.Address) ?quicz.endpoint.UdpAddress {
    return switch (addr.any.family) {
        lib_posix.AF.INET => quicz.endpoint.UdpAddress.init4(
            @bitCast(addr.in.addr),
            std.mem.bigToNative(u16, addr.in.port),
        ),
        lib_posix.AF.INET6 => quicz.endpoint.UdpAddress.init6Scoped(
            addr.in6.addr,
            std.mem.bigToNative(u16, addr.in6.port),
            addr.in6.scope_id,
        ),
        else => null,
    };
}

/// Convert one quicz address back into a kernel sockaddr for sendto.
pub fn udpAddressToSockaddr(a: quicz.endpoint.UdpAddress) lib_posix.Address {
    if (a.family == .ipv4) {
        return lib_posix.Address.initIp4(a.v4, a.port);
    }
    return lib_posix.Address.initIp6(a.v6, a.port, 0, a.scope_id);
}

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
    last_output_ns: i64 = 0,
    /// Set while one keepalive PING is queued and not yet emitted.
    keepalive_queued: bool = false,
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

    /// Exactly-once cleanup: retire the adopted candidate if present,
    /// release the registry and the policy (whose deinit wipes its
    /// token secret), then wipe the owned PSK.
    pub fn deinit(self: *QuicGateway) void {
        if (self.hasCandidate()) {
            _ = self.registry.retire(self.candidate().transport.lifecycle, 1) catch {};
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
    pub fn receive(self: *QuicGateway, sock: *udp.UdpSocket, now: i64) !bool {
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
            try self.dispatch(sock, arrival, r.addr, buf[0..r.len], now);
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
    ) !void {
        switch (self.state) {
            .awaiting_initial, .retry_sent => try self.handleInitial(sock, arrival, src, data, now),
            .candidate_uncommitted, .handshaking_committed, .established => {
                const transport = self.candidate().transport;
                if (try transport.handleDatagram(arrival, now, data, &self.challenge)) {
                    self.io.random(&self.challenge);
                    self.counters.challenges_issued += 1;
                }
                try self.drainCandidate(sock, now);
                if (!self.running) return;
                if (self.state != .established and transport.handshakeConfirmed()) {
                    self.handshake_duration_ns = now - self.bootstrap_emitted_ns;
                    self.counters.handshakes_confirmed += 1;
                    self.state = .established;
                    self.last_output_ns = now;
                    // HANDSHAKE_DONE lets the client confirm too.
                    try transport.connection().sendHandshakeDone();
                    log.info("quic handshake confirmed duration_ns={d}", .{self.handshake_duration_ns});
                }
                if (self.state == .established) try self.rejectPreQ3StreamData(sock, now);
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
                return self.openExchange(sock, arrival, src, accept, now);
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
            .send_retry => |view| try self.sendRetryView(sock, view, src),
            .validated => try self.adoptValidated(sock, arrival, accept, data, now),
        }
    }

    fn openExchange(
        self: *QuicGateway,
        sock: *udp.UdpSocket,
        arrival: quicz.endpoint.UdpTuple,
        src: lib_posix.Address,
        accept: anytype,
        now: i64,
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
        try self.sendRetryView(sock, view, src);
        self.state = .retry_sent;
    }

    fn adoptValidated(
        self: *QuicGateway,
        sock: *udp.UdpSocket,
        arrival: quicz.endpoint.UdpTuple,
        accept: anytype,
        data: []const u8,
        now: i64,
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
        errdefer transport.destroy();
        try transport.registerRoute(arrival.local, arrival.remote);
        const record = try self.alloc.create(GatewayRecord);
        errdefer self.alloc.destroy(record);
        record.* = .{ .transport = transport };
        self.registry.adopt(1, record) catch {
            self.alloc.destroy(record);
            transport.destroy();
            self.counters.datagrams_discarded += 1;
            return;
        };
        self.state = .candidate_uncommitted;

        // Authenticate the follow-up Initial. A failure (wrong PSK,
        // binder mismatch) retires the candidate WITHOUT committing;
        // the slot remains usable to its absolute expiry and the Retry
        // SCID is unchanged.
        _ = try transport.handleDatagram(arrival, now, data, &self.challenge);
        transport.driveCrypto(.initial, now) catch {
            self.rollbackCandidate();
            return;
        };

        // Hold the ServerHello, commit the slot exactly once, then
        // publish it. After commit the slot cannot be reused: a lost
        // ServerHello recovers through QUIC PTO, and any later fatal
        // error retires and exits.
        const sh = (transport.pollOutbound(now) catch {
            self.rollbackCandidate();
            return;
        }) orelse {
            self.rollbackCandidate();
            return;
        };
        self.slot.commit(&self.policy, now, token) catch {
            self.alloc.free(sh);
            self.rollbackCandidate();
            return;
        };
        self.state = .handshaking_committed;
        try self.sendOwned(sock, sh, arrival.remote);
        self.last_output_ns = now;
    }

    /// Pre-commit rollback: retire the candidate, keep the slot and
    /// Retry SCID for the still-live exchange.
    fn rollbackCandidate(self: *QuicGateway) void {
        _ = self.registry.retire(self.candidate().transport.lifecycle, 1) catch {};
        self.state = .retry_sent;
        self.counters.datagrams_discarded += 1;
    }

    /// Owned quicz output: ALWAYS freed after the send attempt —
    /// WouldBlock drops the bytes and QUIC recovery retransmits.
    fn sendOwned(self: *QuicGateway, sock: *udp.UdpSocket, dg: []u8, remote: quicz.endpoint.UdpAddress) !void {
        defer self.alloc.free(dg);
        sock.sendTo(dg, udpAddressToSockaddr(remote)) catch |err| switch (err) {
            error.WouldBlock => {},
            else => return err,
        };
        self.counters.datagrams_sent += 1;
    }

    /// The Retry datagram is a BORROWED slot view: never freed; on
    /// WouldBlock the slot retains it and a matching retransmission
    /// reissues the same bytes.
    fn sendRetryView(self: *QuicGateway, sock: *udp.UdpSocket, view: []const u8, src: lib_posix.Address) !void {
        sock.sendTo(view, src) catch |err| switch (err) {
            error.WouldBlock => {},
            else => return err,
        };
        self.counters.datagrams_sent += 1;
    }

    /// Bounded outbound drain: at most `max_outbound_per_turn` owned
    /// datagrams per turn, each path-tagged by the atomic egress API.
    /// Crypto is driven first in every non-discarded space, so
    /// handshake flights progress on arrival activity.
    fn drainCandidate(self: *QuicGateway, sock: *udp.UdpSocket, now: i64) !void {
        if (!self.hasCandidate()) return;
        const transport = self.candidate().transport;
        try transport.driveCrypto(.initial, now);
        try transport.driveCrypto(.handshake, now);
        var sent: usize = 0;
        while (sent < max_outbound_per_turn) : (sent += 1) {
            const tagged = (try transport.pollOutboundPath(now)) orelse break;
            try self.sendOwned(sock, tagged.dg, tagged.dst.remote);
        }
        // Any authenticated output satisfies the keepalive interval.
        self.last_output_ns = now;
    }

    /// Pre-Q3 application stream data is rejected: the connection
    /// closes (counted, no Q2-frozen error code — Q3 owns stable wire
    /// codes) and the gateway exits; post-commit fatal errors never
    /// return to `retry_sent`.
    fn rejectPreQ3StreamData(self: *QuicGateway, sock: *udp.UdpSocket, now: i64) !void {
        const conn = self.candidate().transport.connection();
        for (conn.recv_streams.items) |stream| {
            if (stream.data.items.len > stream.read_offset) {
                try self.candidate().transport.shutdown(1, "pre-q3 stream data");
                try self.drainCandidate(sock, now);
                self.state = .closed;
                self.running = false;
                return;
            }
        }
    }

    /// Service due QUIC work with no fd readable. Returns false when
    /// the gateway should exit.
    pub fn serviceDue(self: *QuicGateway, sock: *udp.UdpSocket, now: i64) !bool {
        if (self.hasCandidate()) {
            const transport = self.candidate().transport;
            switch (try transport.serviceDueDeadline(now)) {
                .datagram => |tagged| try self.sendOwned(sock, tagged.dg, tagged.dst.remote),
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
        // emission and never extended.
        if (self.state != .established and self.state != .closed and
            now - self.bootstrap_emitted_ns >= handshake_deadline_ns)
        {
            if (self.hasCandidate()) _ = self.registry.retire(self.candidate().transport.lifecycle, 1) catch {};
            self.state = .closed;
            self.running = false;
            log.info("quic handshake deadline exceeded; gateway exiting", .{});
        }
        // One-second keepalive: at most one queued; any authenticated
        // output also satisfies the interval.
        if (self.state == .established and self.running and
            now - self.last_output_ns >= keepalive_interval_ns and !self.keepalive_queued)
        {
            try self.candidate().transport.connection().sendPing();
            self.keepalive_queued = true;
            try self.drainCandidate(sock, now);
            self.keepalive_queued = false;
            self.last_output_ns = now;
        }
        return self.running;
    }

    /// The earliest QUIC deadline: transport recovery/idle/close, slot
    /// expiry, the absolute handshake deadline, and the keepalive
    /// interval once established.
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
            next = minDeadline(next, self.last_output_ns + keepalive_interval_ns);
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
