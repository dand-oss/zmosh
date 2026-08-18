//! Shared sans-I/O harness for the Q1 spike proofs.
//!
//! One PSK-authenticated client/server pair driven over
//! `EndpointConnectionLifecycle` with caller-owned datagram exchange, plus
//! a deterministic impairment wire (drop / duplicate / reorder / corrupt /
//! blackout) between them — the in-process datagram layer the plan's fault
//! matrix requires. Everything uses the same public quicz APIs and the
//! same certificate-free external-PSK configuration proven by
//! `quic_psk_gate.zig`.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;

pub const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
pub const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
pub const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
pub const client_handle: u64 = 1;
pub const server_handle: u64 = 2;

pub const alpn_zmosh = [_][]const u8{"zmosh/1"};
pub const psk_identity = "zmosh-ssh-bootstrap-v1";

/// Plan Q1: PSK = HKDF-SHA256(bootstrap secret) with the fixed context
/// `zmosh quic psk v1`. Writes the derived PSK into `out` in place; the
/// caller owns the mutable bootstrap original and wipes it (the backend's
/// retained copy is wiped by its secureWipe; quicz's by-value PSK
/// constructors still make a transient ABI copy we do not claim to
/// eliminate).
pub fn derivePsk(out: *[32]u8, bootstrap_secret: *const [32]u8) void {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    const prk = HkdfSha256.extract("zmosh quic psk v1", bootstrap_secret);
    HkdfSha256.expand(out, psk_identity, prk);
}

/// Deterministic impairment applied on the client->server and
/// server->client paths. Counters apply to datagrams presented for
/// delivery, in order.
pub const Wire = struct {
    /// Drop the first N client->server datagrams (handshake loss tests).
    drop_first_client: usize = 0,
    /// Drop the first N server->client datagrams.
    drop_first_server: usize = 0,
    /// After the first-N window, drop every Nth client datagram (1 = all).
    drop_every_client: usize = 0,
    /// Duplicate every datagram that is delivered.
    duplicate: bool = false,
    /// Hold the next client datagram, then deliver the following one
    /// BEFORE it (one adjacent swap: deterministic reordering).
    reorder_swap_once: bool = false,
    /// Corrupt one byte of the next delivered datagram, once.
    corrupt_once: bool = false,
    /// Drop everything while now_nanos < blackout_until.
    blackout_until_nanos: i64 = 0,
    /// Delay each client datagram by N pump cycles before delivery.
    delay_client_cycles: usize = 0,
    /// Datagrams held for later delivery (delay injection).
    held_late: std.ArrayList([]u8) = .empty,
    held_late_remaining: std.ArrayList(usize) = .empty,
    delayed: usize = 0,
    /// Largest datagram size observed passing the wire (MTU cap proofs).
    max_datagram_seen: usize = 0,
    /// Datagrams discarded on delivery (AEAD/routing failures).
    undeliverable: usize = 0,
    /// Verbose per-datagram tracing (debugging only).
    trace: bool = false,
    now_nanos: *i64,

    client_sent: usize = 0,
    server_sent: usize = 0,
    held_client: ?[]u8 = null,
    dropped: usize = 0,
    duplicated: usize = 0,
    reordered: usize = 0,
    corrupted: usize = 0,

    /// Apply policy; returns action for one presented datagram.
    fn classify(self: *Wire, from_client: bool, alloc: std.mem.Allocator, data: []const u8) enum { deliver, drop, hold, deliver_new_then_held } {
        if (self.now_nanos.* < self.blackout_until_nanos) {
            self.dropped += 1;
            return .drop;
        }
        if (from_client) {
            self.client_sent += 1;
            if (self.drop_first_client > 0 and self.client_sent <= self.drop_first_client) {
                self.dropped += 1;
                return .drop;
            }
            if (self.drop_every_client > 0 and (self.client_sent - @min(self.client_sent, self.drop_first_client)) % self.drop_every_client == 0) {
                self.dropped += 1;
                return .drop;
            }
            if (self.reorder_swap_once) {
                if (self.held_client == null) {
                    self.held_client = alloc.dupe(u8, data) catch unreachable;
                    return .hold;
                }
                // The new datagram overtakes the held one.
                self.reorder_swap_once = false;
                self.reordered += 1;
                return .deliver_new_then_held;
            }
        } else {
            self.server_sent += 1;
            if (self.drop_first_server > 0 and self.server_sent <= self.drop_first_server) {
                self.dropped += 1;
                return .drop;
            }
        }
        return .deliver;
    }

    pub fn deinit(self: *Wire, alloc: std.mem.Allocator) void {
        if (self.held_client) |h| alloc.free(h);
        self.held_client = null;
        for (self.held_late.items) |h| alloc.free(h);
        self.held_late.deinit(alloc);
        self.held_late_remaining.deinit(alloc);
    }
};

pub const PairOptions = struct {
    /// Local max_idle_timeout transport parameter, milliseconds.
    idle_timeout_ms: u64 = 0,
    /// Connection flow-control credit (initial_max_data), bytes.
    max_data: u64 = 8192,
    max_stream_data: u64 = 2048,
    max_streams_bidi: u64 = 8,
    max_streams_uni: u64 = 8,
    /// Disable active migration in transport parameters.
    migration_disabled: bool = true,
    /// Wrong PSK / wrong identity / wrong ALPN failure variants.
    /// Pointers: callers own the mutable originals and wipe them; the
    /// Pair retains no redundant PSK copies.
    client_psk: *const [32]u8,
    server_psk: *const [32]u8,
    server_identity: ?[]const u8 = psk_identity,
    server_alpn: []const []const u8 = &alpn_zmosh,
};

/// One heap-held client/server pair sharing one manual clock and wire.
pub const Pair = struct {
    alloc: std.mem.Allocator,
    now_nanos: i64 = 1000,
    wire: Wire,
    client_lifecycle: *quicz.EndpointConnectionLifecycle,
    server_lifecycle: *quicz.EndpointConnectionLifecycle,
    client: *Connection,
    server: *Connection,
    client_backend: *Tls13Backend,
    server_backend: *Tls13Backend,
    client_path: quicz.endpoint.Udp4Tuple,
    server_path: quicz.endpoint.Udp4Tuple,
    secrets: protection.InitialSecrets,
    scratch: [16384]u8 = undefined,
    pkt: u64 = 10,
    /// Handshake-space datagrams that arrived before the receiver had
    /// keys to decrypt them; replayed after each drive step.
    pending_handshake: std.ArrayList([]u8) = .empty,
    /// Sender flag for each parked datagram.
    pending_from: std.ArrayList(bool) = .empty,

    /// Create on the heap: the wire's clock pointer must reference this
    /// pair's own field, so the pair may never be moved by value.
    pub fn create(alloc: std.mem.Allocator, opts: PairOptions) !*Pair {
        const p = try alloc.create(Pair);
        errdefer alloc.destroy(p);
        try Pair.initInto(p, alloc, opts);
        return p;
    }

    pub fn destroy(self: *Pair) void {
        const alloc = self.alloc;
        // Teardown wipes every secret this pair holds: both TLS backends
        // (key schedules, PSKs, ephemeral keys) and the Initial secrets.
        // Derived-PSK copies are wiped by the caller that created them.
        self.client_backend.secureWipe();
        self.server_backend.secureWipe();
        protection.secureWipeInitialSecrets(&self.secrets);
        self.deinit();
        alloc.destroy(self);
    }

    /// Build every resource as a local with an adjacent errdefer that
    /// releases exactly what exists at that point (LIFO), then transfer
    /// ownership into the pair in ONE assignment on success. No partially
    /// initialized pair is ever observable, and every failure path wipes
    /// or deinits precisely the resources already constructed.
    fn initInto(p: *Pair, alloc: std.mem.Allocator, opts: PairOptions) !void {
        const client_path = quicz.endpoint.Udp4Tuple{
            .local = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 40000),
            .remote = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 41000),
        };
        const server_path = quicz.endpoint.Udp4Tuple{
            .local = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 41000),
            .remote = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 40000),
        };

        const client_lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
        errdefer alloc.destroy(client_lifecycle);
        client_lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);
        errdefer client_lifecycle.deinit();

        const server_lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
        errdefer alloc.destroy(server_lifecycle);
        server_lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);
        errdefer server_lifecycle.deinit();

        try client_lifecycle.registerConnectionId(client_handle, &client_scid, client_path, .{ .active_migration_disabled = opts.migration_disabled });
        try server_lifecycle.registerConnectionId(server_handle, &original_dcid, server_path, .{ .active_migration_disabled = opts.migration_disabled });
        try server_lifecycle.registerConnectionId(server_handle, &server_scid, server_path, .{ .active_migration_disabled = opts.migration_disabled });

        const conn_cfg = quicz.Config{
            .initial_max_data = opts.max_data,
            .initial_max_stream_data = opts.max_stream_data,
            .initial_max_streams_bidi = opts.max_streams_bidi,
            .initial_max_streams_uni = opts.max_streams_uni,
            .max_datagram_size = 8192,
            .max_idle_timeout_ms = opts.idle_timeout_ms,
        };
        const client = try alloc.create(Connection);
        errdefer alloc.destroy(client);
        client.* = try Connection.init(alloc, .client, conn_cfg);
        errdefer client.deinit();

        const server = try alloc.create(Connection);
        errdefer alloc.destroy(server);
        server.* = try Connection.init(alloc, .server, conn_cfg);
        errdefer server.deinit();

        // The zmosh gateway validates the peer address out-of-band (SSH
        // bootstrap + Retry) before allocating per-client state.
        try server.validatePeerAddress();
        try client.setLocalInitialSourceConnectionId(&client_scid);
        try server.setLocalInitialSourceConnectionId(&server_scid);

        const client_backend = try alloc.create(Tls13Backend);
        errdefer alloc.destroy(client_backend);
        client_backend.* = Tls13Backend.initClientWithPsk(.{
            .alpn = &alpn_zmosh,
            .server_name = "zmosh",
            .disable_session_resumption = true,
        }, opts.client_psk.*);
        errdefer client_backend.secureWipe();
        try client_backend.setClientPskIdentity(psk_identity);

        const server_backend = try alloc.create(Tls13Backend);
        errdefer alloc.destroy(server_backend);
        server_backend.* = Tls13Backend.initServerWithPsk(.{
            .alpn = opts.server_alpn,
            .disable_session_resumption = true,
            // No certificate material: PSK-only or fail.
        }, opts.server_psk.*);
        errdefer server_backend.secureWipe();
        if (opts.server_identity) |identity| try server_backend.setServerPskIdentity(identity);

        var secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);
        errdefer protection.secureWipeInitialSecrets(&secrets);

        // All steps succeeded: ownership transfers in one assignment. The
        // constructor's stack original of the Initial secrets is dead from
        // here on — wipe it so exactly one live copy remains (the pair's,
        // wiped again in destroy()).
        p.* = .{
            .alloc = alloc,
            .wire = .{ .now_nanos = &p.now_nanos },
            .client_lifecycle = client_lifecycle,
            .server_lifecycle = server_lifecycle,
            .client = client,
            .server = server,
            .client_backend = client_backend,
            .server_backend = server_backend,
            .client_path = client_path,
            .server_path = server_path,
            .secrets = secrets,
        };
        protection.secureWipeInitialSecrets(&secrets);
    }

    pub fn deinit(self: *Pair) void {
        for (self.pending_handshake.items) |dg| self.alloc.free(dg);
        self.pending_handshake.deinit(self.alloc);
        self.pending_from.deinit(self.alloc);
        self.wire.deinit(self.alloc);
        self.client.deinit();
        self.server.deinit();
        self.client_lifecycle.deinit();
        self.server_lifecycle.deinit();
        self.alloc.destroy(self.client_backend);
        self.alloc.destroy(self.server_backend);
        self.alloc.destroy(self.client);
        self.alloc.destroy(self.server);
        self.alloc.destroy(self.client_lifecycle);
        self.alloc.destroy(self.server_lifecycle);
    }

    pub fn nextPkt(self: *Pair) i64 {
        self.pkt += 1;
        return @intCast(self.pkt);
    }

    /// Derive this side's 1-RTT send keys from the TLS backend's public
    /// key schedule, for the dedicated application-space recovery bridge
    /// (which takes explicit keys; the connection keeps its own copies).
    fn oneRttSendKeys(self: *Pair, client_side: bool) ?protection.Aes128PacketProtectionKeys {
        const backend = if (client_side) self.client_backend else self.server_backend;
        const ks = &backend.hs.key_schedule;
        if (!ks.app_secret_derived) return null;
        const secret = if (client_side)
            ks.client_app_traffic_secret
        else
            ks.server_app_traffic_secret;
        const cipher: protection.CipherSuite = switch (backend.hs.negotiatedCipherSuite()) {
            0x1303 => .chacha20_poly1305,
            else => .aes_128_gcm,
        };
        return protection.deriveForCipher(secret, .v1, cipher);
    }

    /// Destination CID for client Initial-space datagrams: the original
    /// DCID for the very first ClientHello, the server's Initial SCID
    /// afterwards (quicz validates this on every client Initial build).
    fn clientInitialDst(self: *const Pair) []const u8 {
        return if (self.client.peerInitialSourceConnectionId() != null)
            &server_scid
        else
            &original_dcid;
    }

    /// Drive one backend space, skipping spaces whose packet-number space
    /// is already discarded (quicz errors on those).
    fn driveClient(self: *Pair, space: quicz.PacketNumberSpace) !void {
        if (self.client.packetNumberSpaceDiscarded(space)) return;
        _ = try self.client_lifecycle.driveCryptoBackendInSpaceAndArmConnection(client_handle, self.client, space, self.client_backend.cryptoBackend(), &self.scratch);
    }

    fn driveServer(self: *Pair, space: quicz.PacketNumberSpace) !void {
        if (self.server.packetNumberSpaceDiscarded(space)) return;
        _ = try self.server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(server_handle, self.server, space, self.server_backend.cryptoBackend(), &self.scratch);
    }

    /// Present one datagram to the wire; deliver surviving bytes to the
    /// destination in the appropriate packet space.
    pub fn deliver(self: *Pair, from_client: bool, data: []const u8) !void {
        const alloc = self.alloc;
        if (self.wire.trace) std.debug.print("WIRE {s} len={d}\n", .{ if (from_client) "c->s" else "s->c", data.len });
        var bytes = data;
        var owned: ?[]u8 = null;
        defer if (owned) |o| alloc.free(o);

        if (data.len > self.wire.max_datagram_seen) self.wire.max_datagram_seen = data.len;
        if (from_client and self.wire.delay_client_cycles > 0) {
            // Delayed datagram: hold for N pump cycles (drop if the delay
            // slot already holds data; the harness pumps one at a time).
            if (self.wire.held_late.items.len == 0) {
                try self.wire.held_late.append(alloc, try alloc.dupe(u8, data));
                try self.wire.held_late_remaining.append(alloc, self.wire.delay_client_cycles + 1);
                self.wire.delayed += 1;
                return;
            }
        }
        try self.flushAged();
        switch (self.wire.classify(from_client, alloc, bytes)) {
            .drop => return,
            .hold => return,
            .deliver_new_then_held => {
                // Reordering: the newer datagram overtakes the held one.
                try self.deliverDirect(from_client, bytes);
                const held = self.wire.held_client.?;
                self.wire.held_client = null;
                try self.deliverDirect(from_client, held);
                alloc.free(held);
                if (self.wire.duplicate) {
                    self.wire.duplicated += 1;
                    try self.deliverDirect(from_client, bytes);
                }
                return;
            },
            .deliver => {},
        }
        if (self.wire.corrupt_once and bytes.len > 0) {
            self.wire.corrupt_once = false;
            owned = alloc.dupe(u8, bytes) catch unreachable;
            owned.?[owned.?.len - 1] ^= 0xAA;
            self.wire.corrupted += 1;
            bytes = owned.?;
        }
        try self.deliverDirect(from_client, bytes);
        if (self.wire.duplicate) {
            self.wire.duplicated += 1;
            try self.deliverDirect(from_client, bytes);
        }
    }

    fn deliverDirect(self: *Pair, from_client: bool, data: []const u8) !void {
        const lifecycle = if (from_client) self.server_lifecycle else self.client_lifecycle;
        const conn = if (from_client) self.server else self.client;
        const path = if (from_client) self.server_path else self.client_path;
        const handle = if (from_client) server_handle else client_handle;

        const info = protection.peekProtectedLongPacketInfo(data) catch {
            // Short header: 1-RTT application data. A datagram that fails
            // authentication (corruption injection) is discarded, per QUIC.
            _ = lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndUpdatePathOrClose(
                handle,
                conn,
                path,
                self.now_nanos,
                data,
            ) catch |err| {
                if (self.wire.trace) std.debug.print("WIRE {s} process err={}\n", .{ if (from_client) "c->s" else "s->c", err });
                switch (err) {
                    // Delivery to an already-closed peer or an
                    // undecryptable datagram is a normal harness event:
                    // count it, never fail the pump.
                    error.InvalidPacket, error.ConnectionClosed => self.wire.undeliverable += 1,
                    else => return err,
                }
            };
            return;
        };
        switch (info.packet_type) {
            .initial => _ = try lifecycle.processRoutedProtectedInitialDatagram(
                handle,
                conn,
                path,
                self.now_nanos,
                &original_dcid,
                data,
            ),
            .handshake => {
                // A Handshake-space datagram may legitimately arrive
                // before the receiver processed the ServerHello and
                // installed keys (retransmission racing the flight order).
                // Park it and replay after the next drive.
                if (!conn.hasHandshakeProtectionKeys()) {
                    try self.pending_handshake.append(self.alloc, try self.alloc.dupe(u8, data));
                    try self.pending_from.append(self.alloc, from_client);
                    return;
                }
                _ = try lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
                    handle,
                    conn,
                    path,
                    self.now_nanos,
                    data,
                );
            },
            else => _ = try lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
                handle,
                conn,
                path,
                self.now_nanos,
                data,
            ),
        }
    }

    /// Deliver delayed datagrams whose hold has elapsed.
    pub fn flushAged(self: *Pair) !void {
        var i: usize = 0;
        while (i < self.wire.held_late_remaining.items.len) {
            if (self.wire.held_late_remaining.items[i] > 1) {
                self.wire.held_late_remaining.items[i] -= 1;
                i += 1;
                continue;
            }
            const dg = self.wire.held_late.orderedRemove(i);
            _ = self.wire.held_late_remaining.orderedRemove(i);
            defer self.alloc.free(dg);
            try self.deliverDirect(true, dg);
        }
    }

    /// Replay parked Handshake-space datagrams whose receiver now has
    /// keys. Entries that are still early stay parked.
    pub fn flushPendingHandshake(self: *Pair) !void {
        var i: usize = 0;
        while (i < self.pending_handshake.items.len) {
            const dg = self.pending_handshake.items[i];
            // Peek the destination: the first byte's two high bits + CID
            // handling differ per side; store the sender alongside instead.
            const from_client = self.pending_from.items[i];
            const conn = if (from_client) self.server else self.client;
            if (!conn.hasHandshakeProtectionKeys()) {
                i += 1;
                continue;
            }
            try self.deliverDirect(from_client, dg);
            self.alloc.free(dg);
            _ = self.pending_handshake.orderedRemove(i);
            _ = self.pending_from.orderedRemove(i);
        }
    }

    /// Poll and deliver every pending client 1-RTT datagram.
    pub fn flushClientShort(self: *Pair) !void {
        while (try self.client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            client_handle,
            self.client,
            self.now_nanos,
            &server_scid,
        )) |dgram| {
            defer self.alloc.free(dgram);
            try self.deliver(true, dgram);
        }
    }

    /// Poll and deliver every pending server 1-RTT datagram.
    pub fn flushServerShort(self: *Pair) !void {
        while (try self.server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            server_handle,
            self.server,
            self.now_nanos,
            &client_scid,
        )) |dgram| {
            defer self.alloc.free(dgram);
            try self.deliver(false, dgram);
        }
    }

    /// Advance the manual clock past PTO and retransmit the client's
    /// Initial through the wire (handshake loss recovery).
    pub fn clientRetransmitInitial(self: *Pair) !void {
        self.now_nanos += 200 * std.time.ns_per_ms;
        _ = try self.client_lifecycle.serviceRecoveryTimer(client_handle, self.client, self.now_nanos);
        if (try self.client_lifecycle.processDueDeadlineAndPollDatagram(
            client_handle,
            self.client,
            self.now_nanos,
            &original_dcid,
            &client_scid,
        )) |result| {
            if (result.datagram) |dg| {
                defer self.alloc.free(dg);
                try self.deliver(true, dg);
            }
        }
    }

    /// One full recovery cycle: advance the clock exactly past the
    /// earliest due deadline (loss/PTO or otherwise), retransmit each
    /// side's due datagrams, then drive and pump both backends so
    /// delivered bytes are consumed and answered.
    pub fn recoverBoth(self: *Pair) !void {
        self.now_nanos += 200 * std.time.ns_per_ms;
        // Jump exactly to a due RECOVERY deadline (loss/PTO) when one is
        // pending sooner than the fixed step; never jump past idle or
        // close deadlines, which would retire an otherwise live pair.
        if (self.client_lifecycle.nextDeadline(client_handle, self.client)) |d| {
            if (d.kind == .recovery and d.deadline_nanos > self.now_nanos) {
                self.now_nanos = d.deadline_nanos;
            }
        }
        if (self.server_lifecycle.nextDeadline(server_handle, self.server)) |d| {
            if (d.kind == .recovery and d.deadline_nanos > self.now_nanos) {
                self.now_nanos = d.deadline_nanos;
            }
        }
        try self.flushAged();
        try self.flushPendingHandshake();
        try self.retransmitDue(true);
        try self.retransmitDue(false);
        try self.pumpServer();
        try self.pumpClient();
        try self.flushAged();
        try self.flushPendingHandshake();
    }

    /// Poll one side's due retransmission datagrams and deliver them.
    fn retransmitDue(self: *Pair, client_side: bool) !void {
        const lifecycle = if (client_side) self.client_lifecycle else self.server_lifecycle;
        const conn = if (client_side) self.client else self.server;
        const handle = if (client_side) client_handle else server_handle;

        if (lifecycle.serviceRecoveryTimerAndPollProtectedLongDatagram(
            handle,
            conn,
            self.now_nanos,
            if (client_side) self.clientInitialDst() else &client_scid,
            if (client_side) &client_scid else &server_scid,
            &[_]u8{},
            .{ .initial = if (client_side) self.secrets.client else self.secrets.server },
        )) |result| {
            if (result.datagram) |dg| {
                defer self.alloc.free(dg);
                try self.deliver(client_side, dg);
            }
        } else |err| switch (err) {
            error.InvalidPacket => {},
            else => return err,
        }

        if (conn.hasHandshakeProtectionKeys()) {
            if (lifecycle.serviceRecoveryTimerAndPollProtectedHandshakeDatagramWithInstalledKeys(
                handle,
                conn,
                self.now_nanos,
                if (client_side) &server_scid else &client_scid,
                if (client_side) &client_scid else &server_scid,
            )) |result| {
                if (result.datagram) |dg| {
                    defer self.alloc.free(dg);
                    try self.deliver(client_side, dg);
                }
            } else |err| switch (err) {
                error.InvalidPacket => {},
                else => return err,
            }
        }

        // Application-space loss recovery: arm the endpoint recovery
        // timer from the connection's own loss/PTO state, then service a
        // due deadline and poll the probe/retransmission datagram.
        if (conn.handshakeConfirmed() and conn.hasOneRttProtectionKeys()) {
            try lifecycle.armRecoveryTimerFromConnection(handle, conn);
            if (self.wire.trace) std.debug.print("LOSS {s}: loss_dl={any} pto_dl={any} now={d}\n", .{ if (client_side) "client" else "server", conn.lossDetectionDeadline(.application), conn.ptoDeadline(.application), self.now_nanos });
            const keys = self.oneRttSendKeys(client_side) orelse return;
            if (lifecycle.serviceRecoveryTimerAndPollProtectedShortDatagram(
                handle,
                conn,
                self.now_nanos,
                if (client_side) &server_scid else &client_scid,
                keys,
            )) |result| {
                if (self.wire.trace) std.debug.print("BRIDGE {s}: serviced={any} dgram={any}\n", .{ if (client_side) "client" else "server", result.serviced != null, if (result.datagram) |dg| dg.len else @as(?usize, null) });
                if (result.datagram) |dg| {
                    defer self.alloc.free(dg);
                    try self.deliver(client_side, dg);
                }
            } else |err| switch (err) {
                error.InvalidPacket => {},
                else => return err,
            }
        }
    }

    /// Opportunistic Initial-space poll that tolerates the connection not
    /// being ready for that space (recovery probing across states).
    fn pollLongTolerant(self: *Pair, client_side: bool) !?[]u8 {
        const lifecycle = if (client_side) self.client_lifecycle else self.server_lifecycle;
        const conn = if (client_side) self.client else self.server;
        const handle = if (client_side) client_handle else server_handle;
        if (conn.packetNumberSpaceDiscarded(.initial)) return null;
        return lifecycle.pollProtectedLongDatagram(
            handle,
            conn,
            self.now_nanos,
            if (client_side) self.clientInitialDst() else &client_scid,
            if (client_side) &client_scid else &server_scid,
            &[_]u8{},
            .{ .initial = if (client_side) self.secrets.client else self.secrets.server },
        ) catch |err| switch (err) {
            error.InvalidPacket => null,
            else => return err,
        };
    }

    /// 1-RTT send keys for the given side (test crafting of protected
    /// PATH_RESPONSE datagrams). Null before the key schedule derives
    /// application secrets.
    pub fn serverKeyForTest(self: *Pair) protection.Aes128PacketProtectionKeys {
        return self.oneRttSendKeys(false) orelse @panic("no server 1-RTT keys");
    }

    /// Peer (client) send keys as seen by the server.
    pub fn clientKeyForTest(self: *Pair) protection.Aes128PacketProtectionKeys {
        return self.peerKeyForTest() orelse @panic("no client 1-RTT keys");
    }

    fn peerKeyForTest(self: *Pair) ?protection.Aes128PacketProtectionKeys {
        const backend = self.client_backend;
        const ks = &backend.hs.key_schedule;
        if (!ks.app_secret_derived) return null;
        // The server decrypts client packets with the client's app
        // traffic secret (its peer key).
        return protection.deriveForCipher(ks.client_app_traffic_secret, .v1, .aes_128_gcm);
    }

    /// Poll one short datagram from the given side without delivering it.
    pub fn pollShortTolerantForTest(self: *Pair, client_side: bool) !?[]u8 {
        return self.pollShortTolerant(client_side);
    }

    /// Deliver one protected short datagram through the canonical
    /// address-neutral validated feed for the given path; returns the
    /// committed route result (null when no commit happened). Errors
    /// from frame processing propagate.
    pub fn deliverViaUpdatePathForTest(
        self: *Pair,
        from_client: bool,
        path: quicz.endpoint.Udp4Tuple,
        data: []const u8,
    ) !?quicz.endpoint.RouteResult {
        const lifecycle = if (from_client) self.server_lifecycle else self.client_lifecycle;
        const conn = if (from_client) self.server else self.client;
        const handle = if (from_client) server_handle else client_handle;
        const res = try lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndUpdatePathOrCloseAddress(
            handle,
            conn,
            path.toUdp(),
            self.now_nanos,
            data,
        );
        return res.updated_route;
    }

    /// Drive decoded frame bytes directly on a connection with NO
    /// arrival hint (fail-closed null-hint proof).
    pub fn driveDecodedFramesNoHint(
        self: *Pair,
        server_side: bool,
        data: [8]u8,
    ) !void {
        const conn = if (server_side) self.server else self.client;
        var frame_buf: [64]u8 = undefined;
        var w = std.Io.Writer.fixed(&frame_buf);
        try quicz.frame.encodeFrame(&w, .{ .path_response = .{ .data = data } });
        conn.setReceivePathHint(null);
        try conn.processDecodedFramesForTest(w.buffered());
    }

    /// Opportunistic 1-RTT short-datagram poll with the same tolerance.
    fn pollShortTolerant(self: *Pair, client_side: bool) !?[]u8 {
        const lifecycle = if (client_side) self.client_lifecycle else self.server_lifecycle;
        const conn = if (client_side) self.client else self.server;
        const handle = if (client_side) client_handle else server_handle;
        if (!conn.hasOneRttProtectionKeys()) return null;
        return lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            handle,
            conn,
            self.now_nanos,
            if (client_side) &server_scid else &client_scid,
        ) catch |err| switch (err) {
            error.InvalidPacket => null,
            else => return err,
        };
    }

    /// Opportunistic Handshake-space poll with the same tolerance.
    fn pollHandshakeTolerant(self: *Pair, client_side: bool) !?[]u8 {
        const lifecycle = if (client_side) self.client_lifecycle else self.server_lifecycle;
        const conn = if (client_side) self.client else self.server;
        const handle = if (client_side) client_handle else server_handle;
        if (conn.packetNumberSpaceDiscarded(.handshake)) return null;
        return lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
            handle,
            conn,
            self.now_nanos,
            if (client_side) &server_scid else &client_scid,
            if (client_side) &client_scid else &server_scid,
        ) catch |err| switch (err) {
            error.InvalidPacket => null,
            else => return err,
        };
    }

    /// Drive the server backend across spaces and pump any produced
    /// datagrams to the client (who then drives itself).
    fn pumpServer(self: *Pair) !void {
        try self.driveServer(.initial);
        try self.flushPendingHandshake();
        if (try self.pollLongTolerant(false)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(false, dg);
        }
        try self.driveServer(.handshake);
        if (try self.pollHandshakeTolerant(false)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(false, dg);
        }
        // 1-RTT retransmissions and ACKs flow on both sides.
        if (try self.pollShortTolerant(false)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(false, dg);
        }
        // The client consumes whatever arrived and answers.
        try self.driveClient(.initial);
        try self.driveClient(.handshake);
        if (try self.pollHandshakeTolerant(true)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(true, dg);
        }
        if (try self.pollShortTolerant(true)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(true, dg);
        }
    }

    /// Drive the client backend across spaces and pump its answers to the
    /// server (who then drives itself).
    fn pumpClient(self: *Pair) !void {
        try self.driveClient(.initial);
        try self.flushPendingHandshake();
        if (try self.pollLongTolerant(true)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(true, dg);
        }
        try self.driveClient(.handshake);
        if (try self.pollHandshakeTolerant(true)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(true, dg);
        }
        if (try self.pollShortTolerant(true)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(true, dg);
        }
        // The server consumes whatever arrived and answers.
        try self.driveServer(.initial);
        try self.driveServer(.handshake);
        if (try self.pollHandshakeTolerant(false)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(false, dg);
        }
        if (try self.pollShortTolerant(false)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(false, dg);
        }
        // The client consumes the server's answer.
        try self.driveClient(.initial);
        try self.driveClient(.handshake);
    }

    /// completeHandshake with bounded PTO recovery: any flight that fails
    /// to land (dropped datagrams) is retried after a recovery cycle.
    pub fn completeHandshakeWithRecovery(self: *Pair) !void {
        var attempt: usize = 0;
        while (attempt < 10) : (attempt += 1) {
            if (self.completeHandshake()) |_| return else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {},
            }
            try self.recoverBoth();
            if (self.server.handshakeConfirmed() and self.client.handshakeConfirmed()) return;
        }
        return error.HandshakeNotConfirmed;
    }

    /// Drive the complete certificate-free PSK handshake through the
    /// impaired wire. Mirrors the flight order proven in quic_psk_gate:
    /// the client installs handshake keys from the ServerHello before the
    /// server's Handshake-space flight is delivered to it.
    pub fn completeHandshake(self: *Pair) !void {
        const alloc = self.alloc;

        // Flight 1: client Initial.
        try self.driveClient(.initial);
        if (try self.client_lifecycle.pollProtectedLongDatagram(client_handle, self.client, self.now_nanos, self.clientInitialDst(), &client_scid, &[_]u8{}, .{ .initial = self.secrets.client })) |ch| {
            defer alloc.free(ch);
            try self.deliver(true, ch);
        }

        // Flight 2: server processes the Initial, installs handshake keys,
        // answers with the ServerHello.
        try self.driveServer(.initial);
        if (try self.server_lifecycle.pollProtectedLongDatagram(server_handle, self.server, self.now_nanos, &client_scid, &server_scid, &[_]u8{}, .{ .initial = self.secrets.server })) |sh| {
            defer alloc.free(sh);
            try self.deliver(false, sh);
        }

        // Flight 3: client processes the ServerHello (delivered above) and
        // installs its handshake keys BEFORE any Handshake-space datagram
        // can reach it.
        try self.driveClient(.initial);

        // Flight 4: server's PSK-only Handshake flight (EE + Finished).
        // Guarded: a dropped Initial means the server never processed a
        // ClientHello and has no handshake keys to seal with yet — bail to
        // the recovery loop instead.
        if (!self.server.hasHandshakeProtectionKeys()) return error.HandshakeNeedsRecovery;
        try self.driveServer(.handshake);
        if (try self.server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(server_handle, self.server, self.now_nanos, &client_scid, &server_scid)) |flight| {
            defer alloc.free(flight);
            try self.deliver(false, flight);
        }

        // Flight 5: client drives Handshake, answers with its Finished.
        // Guarded the same way: without the ServerHello the client cannot
        // seal Handshake-space datagrams yet.
        if (!self.client.hasHandshakeProtectionKeys()) return error.HandshakeNeedsRecovery;
        try self.driveClient(.handshake);
        if (try self.client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(client_handle, self.client, self.now_nanos, &server_scid, &client_scid)) |fin| {
            defer alloc.free(fin);
            try self.deliver(true, fin);
        }

        // Flight 6: server confirms.
        try self.driveServer(.handshake);
        if (!self.server.handshakeConfirmed()) return error.HandshakeNotConfirmed;

        // Flight 7: the server sends HANDSHAKE_DONE so the client
        // confirms too; without client confirmation, application-space
        // recovery stays gated server-side only.
        try self.server.sendHandshakeDone();
        if (try self.pollShortTolerant(false)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(false, dg);
        }
        try self.driveClient(.handshake);
        if (try self.pollShortTolerant(true)) |dg| {
            defer self.alloc.free(dg);
            try self.deliver(true, dg);
        }
        try self.driveServer(.handshake);
        if (!self.client.handshakeConfirmed()) return error.ClientNotConfirmed;
    }

    /// Send application bytes on one stream client->server; returns what
    /// the server received (null if nothing arrived).
    pub fn clientToServer(self: *Pair, stream_id: u64, bytes: []const u8, fin: bool) !?[]u8 {
        const alloc = self.alloc;
        try self.client.sendOnStream(stream_id, bytes, fin);
        var delivered: ?[]u8 = null;
        var attempts: usize = 0;
        while (attempts < 8) : (attempts += 1) {
            if (try self.client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(client_handle, self.client, self.now_nanos, &server_scid)) |dgram| {
                defer alloc.free(dgram);
                try self.deliver(true, dgram);
            } else break;
            var buf: [4096]u8 = undefined;
            if (try self.server.recvOnStream(stream_id, &buf)) |n| {
                delivered = try alloc.dupe(u8, buf[0..n]);
                break;
            }
        }
        return delivered;
    }

    /// Send application bytes server->client; returns what the client
    /// received.
    pub fn serverToClient(self: *Pair, stream_id: u64, bytes: []const u8, fin: bool) !?[]u8 {
        const alloc = self.alloc;
        try self.server.sendOnStream(stream_id, bytes, fin);
        var delivered: ?[]u8 = null;
        var attempts: usize = 0;
        while (attempts < 8) : (attempts += 1) {
            if (try self.server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(server_handle, self.server, self.now_nanos, &client_scid)) |dgram| {
                defer alloc.free(dgram);
                try self.deliver(false, dgram);
            } else break;
            var buf: [4096]u8 = undefined;
            if (try self.client.recvOnStream(stream_id, &buf)) |n| {
                delivered = try alloc.dupe(u8, buf[0..n]);
                break;
            }
        }
        return delivered;
    }
};
