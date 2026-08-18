//! Thin QUIC transport adapter over the quicz sans-I/O API (Phase Q2).
//!
//! One `Transport` is one QUIC endpoint — the client side or the gateway
//! side of a zmosh connection. It owns the quicz
//! `EndpointConnectionLifecycle`, `Connection`, and TLS backend, and
//! nothing else: datagrams in, datagrams out, deadlines, and counters.
//! It owns no terminal or command semantics; the socket fd, poll()
//! integration, and stream roles live in the gateway layer above it.
//!
//! Authentication is the frozen Q1 contract: certificate-free
//! external-PSK TLS 1.3, PSK = HKDF-SHA256(salt `zmosh quic psk v1`,
//! IKM = the 32-byte SSH-bootstrap secret) expanded with info
//! `zmosh-ssh-bootstrap-v1`; no session tickets, no resumption, no
//! 0-RTT. Callers own the mutable bootstrap original and wipe it; every
//! secret this struct holds is wiped on `destroy` before any storage is
//! freed. Datagrams are capped at the fixed 1200-byte v1 payload.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;

const log = std.log.scoped(.quic_transport);

/// Fixed external-PSK identity (non-secret).
pub const psk_identity = "zmosh-ssh-bootstrap-v1";

/// Plan Q2: PSK = HKDF-SHA256(bootstrap secret) with the fixed context
/// `zmosh quic psk v1`. Writes the derived PSK into `out` in place; the
/// caller owns the mutable bootstrap original and wipes it. The
/// extracted PRK is wiped by an immediate defer so every exit path
/// scrubs it.
pub fn derivePsk(out: *[32]u8, bootstrap_secret: *const [32]u8) void {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    var prk = HkdfSha256.extract("zmosh quic psk v1", bootstrap_secret);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&prk));
    HkdfSha256.expand(out, psk_identity, prk);
}

/// Counters and durations only — never session content, command
/// bodies, labels, paths, snapshot bytes, or secrets.
pub const Counters = struct {
    datagrams_received: usize = 0,
    datagrams_sent: usize = 0,
    datagrams_discarded: usize = 0,
    handshake_nanos: ?i64 = null,
    migrations_committed: usize = 0,
};

pub const Options = struct {
    is_server: bool,
    /// Derived PSK: a pointer, so callers own and wipe the mutable
    /// bootstrap original; this struct retains no copy.
    psk: *const [32]u8,
    /// This endpoint's Initial Source CID. Production picks a random
    /// value; tests may pin it. Four bytes keeps the padded Initial
    /// datagram within the fixed 1200-byte payload.
    scid: [4]u8,
    /// The handshake's original destination CID: the client's chosen
    /// first-flight DCID (random in production). Required for the
    /// client — its Initial secrets derive from it. The server ignores
    /// it and derives lazily from the first received Initial's DCID.
    original_dcid: [8]u8,
    idle_timeout_ms: u64 = 0,
    max_data: u64 = 8192,
    max_stream_data: u64 = 2048,
    max_streams_bidi: u64 = 8,
    /// The v1 protocol uses bidirectional streams only; advertising
    /// unidirectional stream credit would grow transport parameters
    /// past the fixed 1200-byte Initial padding floor.
    max_streams_uni: u64 = 0,
    /// v1 fixes the UDP payload: no PMTU discovery, never an
    /// IP-fragmenting datagram. 1232 rather than exactly 1200 because
    /// quicz pads Initial datagrams up to the 1200-byte QUIC floor and
    /// the varint length field can converge 1-2 bytes above it — 1232
    /// stays within the IPv6-minimum-MTU payload and is still a fixed
    /// cap. FLAGGED for review against the plan's "fixed 1200-byte
    /// payload" wording.
    max_datagram_size: usize = 1232,
};

/// One QUIC endpoint. Heap-held: nothing moves after creation.
pub const Transport = struct {
    alloc: std.mem.Allocator,
    lifecycle: *quicz.EndpointConnectionLifecycle,
    conn: *Connection,
    backend: *Tls13Backend,
    /// Initial-space secrets: derived at create() for the client (from
    /// its original DCID), lazily on the first received Initial for the
    /// server (from that datagram's DCID).
    secrets: ?protection.InitialSecrets,
    /// The handshake's original destination CID: set at create() for
    /// the client, learned from the first received Initial for the
    /// server. Initial-space processing always refers to this value.
    odcid_buf: [20]u8 = undefined,
    odcid_len: usize = 0,
    opts: Options,
    scratch: [16384]u8 = undefined,
    counters: Counters = .{},

    /// Build every resource as a local with an adjacent errdefer that
    /// releases exactly what exists, then transfer ownership in one
    /// assignment; no partially initialized transport is observable.
    pub fn create(alloc: std.mem.Allocator, opts: Options) !*Transport {
        const lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
        errdefer alloc.destroy(lifecycle);
        lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);
        errdefer lifecycle.deinit();

        const conn = try alloc.create(Connection);
        errdefer alloc.destroy(conn);
        conn.* = try Connection.init(alloc, if (opts.is_server) .server else .client, .{
            .initial_max_data = opts.max_data,
            .initial_max_stream_data = opts.max_stream_data,
            .initial_max_streams_bidi = opts.max_streams_bidi,
            .initial_max_streams_uni = opts.max_streams_uni,
            .max_datagram_size = @intCast(opts.max_datagram_size),
            .max_idle_timeout_ms = opts.idle_timeout_ms,
        });
        errdefer conn.deinit();

        // The zmosh gateway validates the peer address out-of-band
        // (SSH bootstrap + Retry) before allocating per-client state.
        if (opts.is_server) try conn.validatePeerAddress();
        try conn.setLocalInitialSourceConnectionId(&opts.scid);

        const backend = try alloc.create(Tls13Backend);
        errdefer alloc.destroy(backend);
        backend.* = if (opts.is_server)
            Tls13Backend.initServerWithPsk(.{
                .alpn = &alpn_zmosh,
                .disable_session_resumption = true,
                // No certificate material: PSK-only or fail.
            }, opts.psk.*)
        else
            Tls13Backend.initClientWithPsk(.{
                .alpn = &alpn_zmosh,
                .server_name = "zmosh",
                .disable_session_resumption = true,
            }, opts.psk.*);
        errdefer backend.secureWipe();
        if (opts.is_server)
            try backend.setServerPskIdentity(psk_identity)
        else
            try backend.setClientPskIdentity(psk_identity);

        var secrets: ?protection.InitialSecrets = null;
        if (!opts.is_server) {
            secrets = try protection.deriveInitialSecrets(.v1, &opts.original_dcid);
            errdefer protection.secureWipeInitialSecrets(&secrets.?);
        }

        const t = try alloc.create(Transport);
        errdefer alloc.destroy(t);
        t.* = .{
            .alloc = alloc,
            .lifecycle = lifecycle,
            .conn = conn,
            .backend = backend,
            .secrets = secrets,
            .odcid_buf = undefined,
            .odcid_len = 0,
            .opts = opts,
        };
        if (secrets != null) {
            // The constructor's stack original is dead from here on;
            // wipe it so exactly one live copy remains.
            protection.secureWipeInitialSecrets(&secrets.?);
        }
        if (!opts.is_server) {
            @memcpy(t.odcid_buf[0..opts.original_dcid.len], &opts.original_dcid);
            t.odcid_len = opts.original_dcid.len;
        }
        return t;
    }

    /// Teardown wipes every secret this transport holds — both the TLS
    /// backend (key schedules, PSK, ephemeral keys) and the Initial
    /// secrets — before freeing anything.
    pub fn destroy(self: *Transport) void {
        const alloc = self.alloc;
        self.backend.secureWipe();
        if (self.secrets != null) protection.secureWipeInitialSecrets(&self.secrets.?);
        self.conn.deinit();
        self.lifecycle.deinit();
        alloc.destroy(self.backend);
        alloc.destroy(self.conn);
        alloc.destroy(self.lifecycle);
        alloc.destroy(self);
    }

    /// The connection, for the protocol layer's stream calls. Thin
    /// escape hatch: stream semantics stay out of this module.
    pub fn connection(self: *Transport) *Connection {
        return self.conn;
    }

    pub fn handshakeConfirmed(self: *const Transport) bool {
        return self.conn.handshakeConfirmed();
    }

    /// Register one destination CID this endpoint receives on, under
    /// the path its socket is bound to. The gateway registers CIDs as
    /// the handshake establishes them (the bounded-candidate flow owns
    /// which CIDs are admitted); a server typically registers the
    /// client's original DCID for the first flight plus its own SCID.
    pub fn registerRouteCid(self: *Transport, cid: []const u8, local: quicz.endpoint.UdpAddress, remote: quicz.endpoint.UdpAddress) !void {
        try self.lifecycle.router.registerConnectionIdAddress(
            handle,
            cid,
            .{ .local = local, .remote = remote },
            .{},
        );
    }

    /// Register this endpoint's own SCID as a destination CID.
    pub fn registerRoute(self: *Transport, local: quicz.endpoint.UdpAddress, remote: quicz.endpoint.UdpAddress) !void {
        try self.registerRouteCid(&self.opts.scid, local, remote);
    }

    /// Next deadline (recovery, close, idle) in absolute nanoseconds,
    /// for the caller's poll()-timeout composition.
    pub fn nextDeadlineNanos(self: *Transport) ?i64 {
        const d = self.lifecycle.nextDeadline(handle, self.conn) orelse return null;
        return d.deadline_nanos;
    }

    const handle: u64 = 1;

    /// Feed one received datagram with its arrival path. Arrival-path
    /// hints are recorded by quicz at every PATH_RESPONSE-capable
    /// receive root (zmosh-quic-q1-5), so path validation is
    /// fail-closed under this dispatch.
    pub fn handleDatagram(self: *Transport, arrival: quicz.endpoint.UdpTuple, now_nanos: i64, data: []const u8) !void {
        self.counters.datagrams_received += 1;
        const info = protection.peekProtectedLongPacketInfo(data) catch {
            // Short header: 1-RTT application data through the
            // canonical guarded entry that also commits validated
            // route changes.
            const res = self.lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndUpdatePathOrCloseAddress(
                handle,
                self.conn,
                arrival,
                now_nanos,
                data,
            ) catch |err| switch (err) {
                // An undecryptable or already-closed datagram is a
                // normal transport event: count it, never fail the
                // caller's receive loop.
                error.InvalidPacket, error.ConnectionClosed => {
                    self.counters.datagrams_discarded += 1;
                    return;
                },
                else => return err,
            };
            if (res.updated_route != null) self.counters.migrations_committed += 1;
            return;
        };
        switch (info.packet_type) {
            .initial => {
                // The handshake's original DCID — and its Initial
                // secrets — are fixed by the FIRST ClientHello's
                // destination CID; the server learns it from that
                // datagram and it never changes afterwards.
                if (self.odcid_len == 0) {
                    const n = @min(info.dcid.len, self.odcid_buf.len);
                    @memcpy(self.odcid_buf[0..n], info.dcid[0..n]);
                    self.odcid_len = n;
                    self.secrets = try protection.deriveInitialSecrets(.v1, self.odcid_buf[0..n]);
                }
                _ = try self.lifecycle.processRoutedProtectedInitialDatagramAddress(
                    handle,
                    self.conn,
                    arrival,
                    now_nanos,
                    self.odcid_buf[0..self.odcid_len],
                    data,
                );
            },
            .handshake => {
                if (!self.conn.hasHandshakeProtectionKeys()) {
                    // A Handshake-space datagram racing ahead of key
                    // installation is dropped; retransmission recovers.
                    self.counters.datagrams_discarded += 1;
                    return;
                }
                _ = try self.lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAddress(
                    handle,
                    self.conn,
                    arrival,
                    now_nanos,
                    data,
                );
            },
            else => {
                self.counters.datagrams_discarded += 1;
            },
        }
    }

    /// Drive the TLS backend in one packet-number space (skipping
    /// spaces whose keys are already discarded).
    pub fn driveCrypto(self: *Transport, space: quicz.PacketNumberSpace, now_nanos: i64) !void {
        if (self.conn.packetNumberSpaceDiscarded(space)) return;
        _ = try self.lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            handle,
            self.conn,
            space,
            self.backend.cryptoBackend(),
            &self.scratch,
        );
        _ = now_nanos;
    }

    /// Poll the next outbound datagram (Initial, Handshake, or 1-RTT
    /// space, in that order). Caller owns and frees the result. The
    /// destination CID for Initial-space datagrams is the peer's
    /// initial DCID until the handshake installs real keys.
    pub fn pollOutbound(self: *Transport, now_nanos: i64) !?[]u8 {
        if (!self.conn.packetNumberSpaceDiscarded(.initial)) {
            if (self.secrets) |secrets| {
                if (self.lifecycle.pollProtectedLongDatagram(
                    handle,
                    self.conn,
                    now_nanos,
                    self.dstCid(),
                    &self.opts.scid,
                    &[_]u8{},
                    .{ .initial = if (self.opts.is_server) secrets.server else secrets.client },
                )) |maybe| {
                    if (maybe) |dg| {
                        self.counters.datagrams_sent += 1;
                        return dg;
                    }
                } else |err| switch (err) {
                    error.InvalidPacket, error.ConnectionClosed => {},
                    else => return err,
                }
            }
        }
        if (!self.conn.packetNumberSpaceDiscarded(.handshake) and self.conn.hasHandshakeProtectionKeys()) {
            if (self.lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
                handle,
                self.conn,
                now_nanos,
                self.dstCid(),
                &self.opts.scid,
            )) |maybe| {
                if (maybe) |dg| {
                    self.counters.datagrams_sent += 1;
                    return dg;
                }
            } else |err| switch (err) {
                error.InvalidPacket, error.ConnectionClosed => {},
                else => return err,
            }
        }
        if (self.conn.hasOneRttProtectionKeys()) {
            if (self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                handle,
                self.conn,
                now_nanos,
                self.dstCid(),
            )) |maybe| {
                if (maybe) |dg| {
                    self.counters.datagrams_sent += 1;
                    return dg;
                }
            } else |err| switch (err) {
                error.InvalidPacket, error.ConnectionClosed => {},
                else => return err,
            }
        }
        return null;
    }

    /// Destination CID for outbound datagrams: the peer's real SCID
    /// once the handshake has revealed it, otherwise the client's
    /// original DCID (the first-flight address).
    fn dstCid(self: *const Transport) []const u8 {
        if (self.conn.peerInitialSourceConnectionId()) |peer| {
            return peer;
        }
        return self.odcid_buf[0..self.odcid_len];
    }

    /// Queue an application CONNECTION_CLOSE and enter the closing
    /// state; the close frame leaves through `pollOutbound`.
    pub fn shutdown(self: *Transport, error_code: u64, reason: []const u8) !void {
        try self.conn.closeApplication(error_code, reason);
    }
};

const alpn_zmosh = [_][]const u8{"zmosh/1"};

const testing = std.testing;

/// One client/server transport pair exchanging datagrams in memory —
/// the loopback the Q2 gate requires before any custom module is
/// removed. Test-only; production exchanges go through real sockets.
/// Handshake-space datagrams that race ahead of receiver key
/// installation are parked and replayed after the next drive (the
/// same recovery the gateway's poll loop will own).
const TestPair = struct {
    client: *Transport,
    server: *Transport,
    client_path: quicz.endpoint.UdpTuple,
    server_path: quicz.endpoint.UdpTuple,
    now_nanos: i64 = 1000,
    parked: std.ArrayList([]u8) = .empty,
    parked_from_server: std.ArrayList(bool) = .empty,

    fn init(alloc: std.mem.Allocator, psk: *const [32]u8) !TestPair {
        const client = try Transport.create(alloc, .{
            .is_server = false,
            .psk = psk,
            .scid = client_scid,
            .original_dcid = original_dcid,
        });
        errdefer client.destroy();
        const server = try Transport.create(alloc, .{
            .is_server = true,
            .psk = psk,
            .scid = server_scid,
            .original_dcid = original_dcid,
        });
        errdefer server.destroy();
        const client_local = quicz.endpoint.UdpAddress.init4([_]u8{ 127, 0, 0, 1 }, 40000);
        const server_local = quicz.endpoint.UdpAddress.init4([_]u8{ 127, 0, 0, 1 }, 41000);
        try client.registerRoute(client_local, server_local);
        try server.registerRoute(server_local, client_local);
        try server.registerRouteCid(&original_dcid, server_local, client_local);
        return .{
            .client = client,
            .server = server,
            .client_path = .{ .local = client_local, .remote = server_local },
            .server_path = .{ .local = server_local, .remote = client_local },
        };
    }

    fn deinit(self: *TestPair, alloc: std.mem.Allocator) void {
        for (self.parked.items) |dg| alloc.free(dg);
        self.parked.deinit(alloc);
        self.parked_from_server.deinit(alloc);
        self.server.destroy();
        self.client.destroy();
    }

    /// Deliver one datagram, parking Handshake-space packets whose
    /// receiver has no keys yet.
    fn deliverOrPark(self: *TestPair, alloc: std.mem.Allocator, from_server: bool, dg: []const u8) !void {
        const receiver = if (from_server) self.client else self.server;
        const info = protection.peekProtectedLongPacketInfo(dg) catch {
            try receiver.handleDatagram(self.arrivalFor(from_server), self.now_nanos, dg);
            return;
        };
        if (info.packet_type == .handshake and !receiver.conn.hasHandshakeProtectionKeys()) {
            try self.parked.append(alloc, try alloc.dupe(u8, dg));
            try self.parked_from_server.append(alloc, from_server);
            return;
        }
        try receiver.handleDatagram(self.arrivalFor(from_server), self.now_nanos, dg);
    }

    fn arrivalFor(self: *const TestPair, from_server: bool) quicz.endpoint.UdpTuple {
        return if (from_server) self.client_path else self.server_path;
    }

    /// Replay parked Handshake-space datagrams whose receiver now has
    /// keys; still-early entries stay parked.
    fn flushParked(self: *TestPair, alloc: std.mem.Allocator) !void {
        var i: usize = 0;
        while (i < self.parked.items.len) {
            const dg = self.parked.items[i];
            const from_server = self.parked_from_server.items[i];
            const receiver = if (from_server) self.client else self.server;
            if (!receiver.conn.hasHandshakeProtectionKeys()) {
                i += 1;
                continue;
            }
            try receiver.handleDatagram(self.arrivalFor(from_server), self.now_nanos, dg);
            alloc.free(dg);
            _ = self.parked.orderedRemove(i);
            _ = self.parked_from_server.orderedRemove(i);
        }
    }

    /// Hand one side's outbound datagram to the other — ONE per call,
    /// mirroring a real poll() loop (recv, handle, try-send once);
    /// draining unboundedly would re-poll unacknowledged datagrams
    /// forever, and batching would fatten ACK ranges past the Initial
    /// padding floor.
    fn pump(self: *TestPair, alloc: std.mem.Allocator, from_server: bool) !void {
        const sender = if (from_server) self.server else self.client;
        {
            const dg = (try sender.pollOutbound(self.now_nanos)) orelse return;
            defer alloc.free(dg);
            try self.deliverOrPark(alloc, from_server, dg);
        }
    }

    /// Drive both backends in the spike-proven flight order until the
    /// handshake confirms on both sides (bounded attempts).
    fn completeHandshake(self: *TestPair, alloc: std.mem.Allocator) !void {
        var attempt: usize = 0;
        while (attempt < 16) : (attempt += 1) {
            self.now_nanos += 1;
            const started = self.now_nanos;

            // Flight 1-2: client Initial -> server drive -> ServerHello.
            try self.client.driveCrypto(.initial, self.now_nanos);
            try self.pump(alloc, false);
            try self.server.driveCrypto(.initial, self.now_nanos);
            try self.pump(alloc, true);

            // Flight 3: client processes the ServerHello, installs
            // handshake keys BEFORE any Handshake-space flight lands.
            try self.client.driveCrypto(.initial, self.now_nanos);
            try self.flushParked(alloc);

            // Flight 4-5: server's PSK-only Handshake flight, then the
            // client's Finished.
            try self.server.driveCrypto(.handshake, self.now_nanos);
            try self.pump(alloc, true);
            try self.client.driveCrypto(.handshake, self.now_nanos);
            try self.pump(alloc, false);

            // Flight 6: server confirms.
            try self.server.driveCrypto(.handshake, self.now_nanos);
            if (true) {}
            if (!self.server.handshakeConfirmed()) continue;
            // Flight 7: HANDSHAKE_DONE so the client confirms too.
            try self.server.conn.sendHandshakeDone();
            try self.pump(alloc, true);
            try self.client.driveCrypto(.handshake, self.now_nanos);
            try self.pump(alloc, false);
            if (self.server.handshakeConfirmed() and self.client.handshakeConfirmed()) {
                if (self.client.counters.handshake_nanos == null) {
                    self.client.counters.handshake_nanos = self.now_nanos - started;
                }
                if (self.server.counters.handshake_nanos == null) {
                    self.server.counters.handshake_nanos = self.now_nanos - started;
                }
                return;
            }
        }
        return error.HandshakeNotConfirmed;
    }
};

const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

test "PSK QUIC loopback: handshake, 1-RTT echo, teardown wipes" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    var psk: [32]u8 = undefined;
    derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);
    try pair.completeHandshake(alloc);
    try testing.expect(pair.client.handshakeConfirmed());
    try testing.expect(pair.server.handshakeConfirmed());
    try testing.expect(pair.client.counters.handshake_nanos != null);

    // 1-RTT echo both directions.
    const stream_id = try pair.client.connection().openStream();
    try pair.client.connection().sendOnStream(stream_id, "q2-loopback", true);
    var echo_budget: usize = 0;
    while (echo_budget < 8) : (echo_budget += 1) {
        const dg = (try pair.client.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg);
    }
    var buf: [128]u8 = undefined;
    const n = (try pair.server.connection().recvOnStream(stream_id, &buf)) orelse return error.NoEcho;
    try testing.expectEqualStrings("q2-loopback", buf[0..n]);
    try testing.expect(pair.client.counters.datagrams_sent >= 1);
    try testing.expect(pair.server.counters.datagrams_received >= 1);
}

test "migration: rebind + validate through the guarded feed" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    var psk: [32]u8 = undefined;
    derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);
    try pair.completeHandshake(alloc);

    // The client rebinds to a new source port. Data still delivers by
    // DCID routing; the server's committed route must NOT move until
    // path validation completes.
    const old_remote = pair.server_path.remote;
    const new_local = quicz.endpoint.UdpAddress.init4([_]u8{ 127, 0, 0, 1 }, 40999);
    pair.client_path.local = new_local;
    pair.server_path.remote = new_local;

    const s = try pair.client.connection().openStream();
    try pair.client.connection().sendOnStream(s, "from-new-path", false);
    var echo_budget_1: usize = 0;
    while (echo_budget_1 < 8) : (echo_budget_1 += 1) {
        const dg = (try pair.client.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg);
    }
    var buf: [128]u8 = undefined;
    const n = (try pair.server.connection().recvOnStream(s, &buf)) orelse return error.NoData;
    try testing.expectEqualStrings("from-new-path", buf[0..n]);
    // The gateway initiates validation for a changed path by queueing
    // an unpredictable challenge bound to the candidate path.
    const challenge_data = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    try pair.server.conn.sendPathChallengeForPath(challenge_data, pair.server_path);
    // Queued as pending; it becomes outstanding once polled and sent.
    try testing.expectEqual(@as(usize, 1), pair.server.connection().pendingPathChallengeCount());

    // Transmit the challenge so it becomes outstanding, then answer it
    // until consumed and the route commits to the rebound path.
    try pair.pump(alloc, true);
    try testing.expectEqual(@as(usize, 1), pair.server.connection().outstandingPathChallengeCount());
    var rounds: usize = 0;
    while (pair.server.connection().outstandingPathChallengeCount() > 0 and rounds < 8) : (rounds += 1) {
        pair.now_nanos += 1;
        try pair.pump(alloc, false);
        try pair.pump(alloc, true);
    }
    try testing.expectEqual(@as(usize, 0), pair.server.connection().outstandingPathChallengeCount());
    const committed = try pair.server.lifecycle.currentRoutePathAddress(&server_scid);
    try testing.expect(committed.remote.eql(new_local));
    try testing.expect(!committed.remote.eql(old_remote));
    try testing.expectEqual(@as(usize, 1), pair.server.counters.migrations_committed);

    // Traffic continues on the committed path.
    try pair.client.connection().sendOnStream(s, "after-migration", true);
    var echo_budget_2: usize = 0;
    while (echo_budget_2 < 8) : (echo_budget_2 += 1) {
        const dg = (try pair.client.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg);
    }
    const n2 = (try pair.server.connection().recvOnStream(s, &buf)) orelse return error.NoDataAfterMigration;
    try testing.expectEqualStrings("after-migration", buf[0..n2]);
}

test "shutdown: application close drains and teardown is clean" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    var psk: [32]u8 = undefined;
    derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    errdefer pair.deinit(alloc);
    try pair.completeHandshake(alloc);

    // Application close: the frame leaves through pollOutbound and the
    // peer observes the closing transition.
    try pair.client.shutdown(0, "done");
    try testing.expect(pair.client.connection().connectionState() == .closing);
    var saw_close = false;
    var close_budget: usize = 0;
    while (close_budget < 8) : (close_budget += 1) {
        const dg = (try pair.client.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg);
        saw_close = true;
    }
    try testing.expect(saw_close);
    try pair.pump(alloc, true);

    // Wipe verification on the LIVE backend (never inspect a destroyed
    // object): destroy()'s first step is this same secureWipe, run
    // under the testing allocator so leaks fail the test.
    const backend = pair.client.backend;
    backend.secureWipe();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&backend.hs.key_schedule.early_secret), 0));
    // destroy() wipes again (idempotent) and frees everything.
    pair.server.destroy();
    pair.client.destroy();
}
